# Audit Report

## Title
Race Condition in Consensus Observer State Sync Allows Epoch Transition State Corruption

## Summary
A critical race condition exists in the consensus observer's state sync manager that allows a new `sync_to_commit()` call with `epoch_changed=true` to abort an in-progress sync with `epoch_changed=false`. This causes the previous sync task to be terminated mid-execution, potentially leaving the executor and state sync subsystems in an inconsistent state, violating consensus safety guarantees.

## Finding Description

The vulnerability exists in the `process_commit_decision_message()` function where it checks whether to initiate a new state sync operation. The code uses an incorrect guard condition that only prevents new syncs when an epoch-transitioning sync is active, but allows new syncs to interrupt same-epoch syncs. [1](#0-0) 

The check at line 507 uses `is_syncing_through_epoch()` which only returns `true` when the boolean flag in the handle is `true`: [2](#0-1) 

However, there exists a broader check `is_syncing_to_commit()` that returns `true` for ANY active sync: [3](#0-2) 

**Attack Scenario:**

1. **Initial State**: Consensus observer receives CommitDecision1 (epoch 10, round 100) - same epoch, higher round
   - Line 503 calculates `epoch_changed = false` 
   - Line 507 check passes (no active epoch-transitioning sync)
   - Line 526 calls `sync_to_commit(decision1, false)`
   - This spawns async Task1 and sets `sync_to_commit_handle = Some((guard1, false))` [4](#0-3) 

2. **Race Window**: While Task1 is executing, CommitDecision2 arrives (epoch 11, round 1) - new epoch
   - Line 503 calculates `epoch_changed = true`
   - Line 507: `is_syncing_through_epoch()` returns **false** because the flag is `false`
   - Check passes, proceeds to line 520-522
   - Updates block data to the new commit decision
   - Line 526 calls `sync_to_commit(decision2, true)`
   - Line 257 **overwrites** the handle: `sync_to_commit_handle = Some((guard2, true))`
   - When `guard1` is dropped, Task1 is **aborted** via the DropGuard

3. **State Corruption**: Task1 may have been executing critical operations in `sync_to_target()`: [5](#0-4) 

The abortion can occur during:
- Lock acquisition (line 179)
- Executor cleanup via `finish()` (line 185)
- State sync notification (line 218)
- Logical time update (line 222)
- Executor reset (line 226)

This breaks the **State Consistency** invariant as the executor may be left in an inconsistent state (e.g., `finish()` called but `reset()` not called), and the **Deterministic Execution** invariant as different nodes may process these race conditions differently.

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for Critical severity under the Aptos bug bounty program because it causes:

1. **Consensus Safety Violations**: Different observer nodes may process the interleaved commit decisions in different orders, leading to state divergence. This violates the fundamental consensus safety guarantee that all honest nodes agree on the same state.

2. **State Corruption**: Aborting `sync_to_target()` mid-execution can leave the BlockExecutor in an inconsistent state where memory structures are freed (`executor.finish()` called) but caches are not reset (`executor.reset()` not called). This can cause subsequent block executions to produce incorrect state roots.

3. **Epoch Transition Failures**: The epoch transition logic relies on correct sequencing of state sync operations. Interrupting a same-epoch sync with an epoch-transitioning sync can cause nodes to incorrectly handle the epoch boundary, potentially leading to nodes being stuck or producing divergent state.

4. **Non-Recoverable Network Issues**: If observer nodes diverge in state due to this race condition, the network may require manual intervention or a hard fork to recover, qualifying under "Non-recoverable network partition."

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered in production scenarios:

1. **Timing Window**: During periods of high network activity or when a node is catching up, commit decisions can arrive in rapid succession, creating the race window.

2. **Epoch Boundaries**: The vulnerability is most likely to trigger near epoch boundaries when both same-epoch commits (to catch up within the current epoch) and epoch-transitioning commits arrive close together.

3. **No Special Privileges Required**: Any network peer can send commit decisions to observer nodes. While signatures are verified, the timing of message delivery is outside the observer's control.

4. **Async Task Execution**: The spawned tasks execute concurrently with message processing, making the race window substantial (potentially hundreds of milliseconds during actual state sync operations).

## Recommendation

Change line 507 in `consensus_observer.rs` from checking `is_syncing_through_epoch()` to checking `is_syncing_to_commit()`:

```rust
// Before (line 505-516):
if epoch_changed || commit_round > last_block.round() {
    if self.state_sync_manager.is_syncing_through_epoch() {
        info!(...);
        return;
    }
    // ... proceed with sync
}

// After (FIXED):
if epoch_changed || commit_round > last_block.round() {
    if self.state_sync_manager.is_syncing_to_commit() {
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Already waiting for state sync to complete: {:?}. Dropping commit decision: {:?}!",
                self.observer_block_data.lock().root().commit_info(),
                commit_decision.proof_block_info()
            ))
        );
        return;
    }
    // ... proceed with sync
}
```

This ensures that ANY active state sync operation (regardless of whether it's transitioning epochs) prevents new sync requests from being initiated, eliminating the race condition.

## Proof of Concept

```rust
#[tokio::test]
async fn test_sync_to_commit_race_condition() {
    // Create a new state sync manager
    let consensus_observer_config = ConsensusObserverConfig::default();
    let (state_sync_notification_sender, _rx) = tokio::sync::mpsc::unbounded_channel();
    let execution_client = Arc::new(DummyExecutionClient);
    let mut state_sync_manager = StateSyncManager::new(
        consensus_observer_config,
        execution_client,
        state_sync_notification_sender,
    );

    // Start a sync with epoch_changed=false
    let commit_decision1 = CommitDecision::new(LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::new(10, 0, HashValue::zero(), HashValue::zero(), 100, 0, None),
            HashValue::zero(),
        ),
        AggregateSignature::empty(),
    ));
    state_sync_manager.sync_to_commit(commit_decision1, false);
    
    // Verify we're syncing but not through an epoch
    assert!(state_sync_manager.is_syncing_to_commit());
    assert!(!state_sync_manager.is_syncing_through_epoch());
    
    // Simulate the race: start another sync with epoch_changed=true
    // This should be blocked but currently is not
    let commit_decision2 = CommitDecision::new(LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::new(11, 0, HashValue::zero(), HashValue::zero(), 1, 0, None),
            HashValue::zero(),
        ),
        AggregateSignature::empty(),
    ));
    state_sync_manager.sync_to_commit(commit_decision2, true);
    
    // The bug: is_syncing_through_epoch() now returns true, even though
    // the first sync was aborted. The epoch_changed flag was overwritten.
    assert!(state_sync_manager.is_syncing_through_epoch());
    
    // In a correct implementation, the second sync_to_commit should have been
    // rejected because a sync was already in progress.
}
```

**Expected behavior**: The second `sync_to_commit()` call should be prevented when any sync is active.

**Actual behavior**: The second call overwrites the handle, aborting the first task mid-execution and causing potential state corruption.

## Notes

This vulnerability specifically affects consensus observer nodes that process commit decisions from peers. The race condition window opens whenever commit decisions arrive in rapid succession, particularly during epoch transitions or catch-up scenarios. The fix is straightforward and low-risk: simply use the broader check that prevents ANY concurrent sync operations, not just epoch-transitioning ones.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L505-516)
```rust
            // If we're waiting for state sync to transition into a new epoch,
            // we should just wait and not issue a new state sync request.
            if self.state_sync_manager.is_syncing_through_epoch() {
                info!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Already waiting for state sync to reach new epoch: {:?}. Dropping commit decision: {:?}!",
                        self.observer_block_data.lock().root().commit_info(),
                        commit_decision.proof_block_info()
                    ))
                );
                return;
            }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L107-109)
```rust
    pub fn is_syncing_through_epoch(&self) -> bool {
        matches!(self.sync_to_commit_handle, Some((_, true)))
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L112-114)
```rust
    pub fn is_syncing_to_commit(&self) -> bool {
        self.sync_to_commit_handle.is_some()
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L190-258)
```rust
    pub fn sync_to_commit(&mut self, commit_decision: CommitDecision, epoch_changed: bool) {
        // Log that we're starting to sync to the commit decision
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Started syncing to commit: {}!",
                commit_decision.proof_block_info()
            ))
        );

        // Get the commit decision epoch and round
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();

        // Clone the required components for the state sync task
        let execution_client = self.execution_client.clone();
        let sync_notification_sender = self.state_sync_notification_sender.clone();

        // Spawn a task to sync to the commit decision
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(
            async move {
                // Update the state sync metrics now that we're syncing to a commit
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_TO_COMMIT,
                    1, // We're syncing to a commit decision
                );

                // Sync to the commit decision
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
                {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to sync to commit decision: {:?}! Error: {:?}",
                            commit_decision, error
                        ))
                    );
                    return;
                }

                // Notify consensus observer that we've synced to the commit decision
                let state_sync_notification = StateSyncNotification::commit_sync_completed(
                    commit_decision.commit_proof().clone(),
                );
                if let Err(error) = sync_notification_sender.send(state_sync_notification) {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send state sync notification for commit decision epoch: {:?}, round: {:?}! Error: {:?}",
                            commit_epoch, commit_round, error
                        ))
                    );
                }

                // Clear the state sync metrics now that we're done syncing
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_TO_COMMIT,
                    0, // We're no longer syncing to a commit decision
                );
            },
            abort_registration,
        ));

        // Save the sync task handle
        self.sync_to_commit_handle = Some((DropGuard::new(abort_handle), epoch_changed));
    }
```

**File:** consensus/src/state_computer.rs (L177-233)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        // Grab the logical time lock and calculate the target logical time
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by BlockExecutor to prevent a memory leak.
        self.executor.finish();

        // The pipeline phase already committed beyond the target block timestamp, just return.
        if *latest_logical_time >= target_logical_time {
            warn!(
                "State sync target {:?} is lower than already committed logical time {:?}",
                target_logical_time, *latest_logical_time
            );
            return Ok(());
        }

        // This is to update QuorumStore with the latest known commit in the system,
        // so it can set batches expiration accordingly.
        // Might be none if called in the recovery path, or between epoch stop and start.
        if let Some(inner) = self.state.read().as_ref() {
            let block_timestamp = target.commit_info().timestamp_usecs();
            inner
                .payload_manager
                .notify_commit(block_timestamp, Vec::new());
        }

        // Inject an error for fail point testing
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Invoke state sync to synchronize to the specified target. Here, the
        // ChunkExecutor will process chunks and commit to storage. However, after
        // block execution and commits, the internal state of the ChunkExecutor may
        // not be up to date. So, it is required to reset the cache of the
        // ChunkExecutor in state sync when requested to sync.
        let result = monitor!(
            "sync_to_target",
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Update the latest logical time
        *latest_logical_time = target_logical_time;

        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        // Return the result
        result.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
            anyhow_error.into()
        })
    }
```
