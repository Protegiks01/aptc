# Audit Report

## Title
State Corruption in `sync_to_target()` Due to Premature Logical Time Update on Failure

## Summary
The `sync_to_target()` function in `ExecutionProxy` unconditionally updates the internal logical time tracking before verifying that state synchronization succeeded. When state sync fails after partial work (e.g., downloaded chunks but commit failed), the node's logical time is advanced while the actual storage remains at the old version. This creates a permanent state inconsistency where the node believes it has synced to the target but hasn't, causing consensus divergence and violating the documented guarantee that failed syncs leave storage unchanged.

## Finding Description

The `StateComputer` trait documents a critical invariant for `sync_to_target()`: [1](#0-0) 

However, the implementation in `ExecutionProxy::sync_to_target()` violates this guarantee. The function updates the logical time **unconditionally** before checking the sync result: [2](#0-1) 

The critical bug occurs at line 222 where `*latest_logical_time = target_logical_time` executes **before** checking the `result` value. This means that even when state sync fails with an error, the logical time has already been modified.

**Attack Scenario:**

1. Consensus calls `sync_to_target()` with target at epoch 1, round 100 (version 200)
2. Node's current state: epoch 1, round 50 (version 100)
3. State sync begins downloading transaction chunks from remote peers
4. Chunks for versions 100-150 are downloaded and enqueued for commit
5. During commit via `save_transactions()`, a failure occurs:
   - Disk I/O error (disk full, timeout, corruption)
   - Validation error in `pre_commit_validation()`
   - State store buffer update failure [3](#0-2) 

6. The error propagates back: `commit_chunk` → storage synchronizer → state sync driver → consensus notification callback
7. **Line 222 executes anyway**: `latest_logical_time` is set to `(epoch: 1, round: 100)`
8. Error is returned to consensus, but damage is done

**Permanent State Corruption:**

When consensus attempts recovery by calling `sync_to_target()` again with the same target, the early-return check triggers: [4](#0-3) 

The function returns `Ok(())` without actually syncing because `latest_logical_time >= target_logical_time` is now true. The node permanently believes it's at round 100 while storage is actually at ~version 100-150 (partially synced with potentially uncommitted data).

## Impact Explanation

**Severity: CRITICAL** (Consensus/Safety violations, State corruption)

This vulnerability causes:

1. **Consensus Safety Violation**: Node diverges from the network by computing state roots based on incomplete/incorrect storage while believing it's synced to a specific round
2. **State Inconsistency**: Internal logical time doesn't match actual committed storage version, violating the core state consistency invariant
3. **Non-Recoverable Failure**: The node cannot automatically recover because the logical time check prevents re-syncing to the target. Requires manual intervention (node restart)
4. **Potential Chain Split**: If multiple validators experience this during epoch transitions or network partitions, they may form different views of the ledger
5. **Violates Documented Guarantee**: The trait explicitly promises that failed syncs leave storage unchanged, but the logical time tracking (used for consensus decisions) is modified

This meets the Critical Severity criteria: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)" if widespread.

## Likelihood Explanation

**Likelihood: HIGH**

This bug can be triggered by common operational failures without any attacker involvement:

1. **Disk Space Exhaustion**: Node runs out of disk space during chunk commit
2. **I/O Errors**: Hardware failures, disk timeouts, or filesystem corruption during `save_transactions()`
3. **Network Interruption**: Connection drops while downloading chunks, causing partial state
4. **Resource Exhaustion**: OOM conditions during commit processing
5. **Validation Failures**: Data corruption or byzantine peer providing invalid data that passes initial checks but fails during commit validation

These are realistic production scenarios that any validator may encounter. The error handling in the commit path explicitly acknowledges these failures: [5](#0-4) 

Note the TODO comment at line 273: "no practical strategy to recover from this error" - yet the logical time is still corrupted in the caller, making recovery impossible.

## Recommendation

**Fix: Move the logical time update AFTER verifying sync success**

The logical time should only be updated when `result` is `Ok(())`:

```rust
// Invoke state sync to synchronize to the specified target
let result = monitor!(
    "sync_to_target",
    self.state_sync_notifier.sync_to_target(target).await
);

// Only update logical time if sync succeeded
if result.is_ok() {
    *latest_logical_time = target_logical_time;
}

// Reset the BlockExecutor cache
self.executor.reset()?;

// Return the result
result.map_err(|error| {
    let anyhow_error: anyhow::Error = error.into();
    anyhow_error.into()
})
```

This ensures the documented invariant is maintained: on failure, no internal state is modified, and subsequent sync attempts will correctly retry the synchronization.

**Additional Hardening:**

Consider adding explicit validation that storage actually reached the target version before updating logical time:

```rust
if result.is_ok() {
    // Verify storage actually synced to target
    let actual_version = self.executor.committed_block_id().version();
    let target_version = target.ledger_info().version();
    
    if actual_version == target_version {
        *latest_logical_time = target_logical_time;
    } else {
        return Err(StateSyncError::from(anyhow::anyhow!(
            "Storage version {} doesn't match sync target {}",
            actual_version, target_version
        )));
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_sync_to_target_logical_time_corruption_on_failure() {
    use consensus::state_computer::ExecutionProxy;
    use aptos_consensus_notifications::*;
    use aptos_types::ledger_info::LedgerInfoWithSignatures;
    use std::sync::Arc;
    
    // Setup: Create ExecutionProxy with mock components
    let executor = Arc::new(MockBlockExecutor::new());
    let txn_notifier = Arc::new(MockTxnNotifier::new());
    
    // Create a state sync notifier that will FAIL after being called
    let (notifier, mut listener) = new_consensus_notifier_listener_pair(5000);
    let notifier_clone = notifier.clone();
    
    // Spawn handler that simulates state sync failure
    tokio::spawn(async move {
        if let Some(ConsensusNotification::SyncToTarget(sync_notif)) = listener.next().await {
            // Simulate partial sync work happening, then failure
            tokio::time::sleep(Duration::from_millis(100)).await;
            
            // Respond with ERROR (simulating commit failure)
            let _ = listener.respond_to_sync_target_notification(
                sync_notif,
                Err(Error::UnexpectedErrorEncountered(
                    "Simulated commit failure during partial sync".into()
                ))
            );
        }
    });
    
    let state_sync_notifier = Arc::new(notifier_clone);
    let execution_proxy = ExecutionProxy::new(
        executor,
        txn_notifier,
        state_sync_notifier,
        BlockTransactionFilterConfig::default(),
        false,
        None,
    );
    
    // Create target at epoch 1, round 100, version 200
    let target = create_ledger_info_with_sigs(1, 100, 200);
    
    // First sync attempt - should FAIL
    let result1 = execution_proxy.sync_to_target(target.clone()).await;
    assert!(result1.is_err(), "First sync should fail");
    
    // BUG: Logical time is now corrupted (advanced to round 100)
    // Second sync attempt with same target - should retry but WON'T due to bug
    let result2 = execution_proxy.sync_to_target(target.clone()).await;
    
    // BUG MANIFESTATION: Second call returns Ok() without actually syncing
    // because logical time check on line 188 prevents actual sync
    assert!(result2.is_ok(), "Bug: Second sync returns Ok without syncing");
    
    // Verify storage is still at old version, proving state corruption
    let actual_version = executor.committed_version();
    assert_ne!(actual_version, 200, "Storage should not be at target version");
    
    println!("BUG CONFIRMED: Logical time advanced to round 100, but storage at version {}",
             actual_version);
}
```

**Notes:**
- This vulnerability can be triggered by any I/O error, validation failure, or resource exhaustion during the commit phase of state synchronization
- The bug creates a permanent divergence between the node's internal logical time tracking and its actual committed storage state
- Recovery requires manual node restart to reset the corrupted logical time
- The issue violates the documented guarantee that failed sync operations leave the node's state unchanged
- This is particularly dangerous during epoch transitions or network partitions when multiple validators may experience sync failures simultaneously

### Citations

**File:** consensus/src/state_replication.rs (L33-37)
```rust
    /// Best effort state synchronization to the given target LedgerInfo.
    /// In case of success (`Result::Ok`) the LI of storage is at the given target.
    /// In case of failure (`Result::Error`) the LI of storage remains unchanged, and the validator
    /// can assume there were no modifications to the storage made.
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError>;
```

**File:** consensus/src/state_computer.rs (L187-194)
```rust
        // The pipeline phase already committed beyond the target block timestamp, just return.
        if *latest_logical_time >= target_logical_time {
            warn!(
                "State sync target {:?} is lower than already committed logical time {:?}",
                target_logical_time, *latest_logical_time
            );
            return Ok(());
        }
```

**File:** consensus/src/state_computer.rs (L216-232)
```rust
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
```

**File:** storage/storage-interface/src/lib.rs (L607-628)
```rust
    /// Persist transactions. Called by state sync to save verified transactions to the DB.
    fn save_transactions(
        &self,
        chunk: ChunkToCommit,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        sync_commit: bool,
    ) -> Result<()> {
        // For reconfig suffix.
        if ledger_info_with_sigs.is_none() && chunk.is_empty() {
            return Ok(());
        }

        if !chunk.is_empty() {
            self.pre_commit_ledger(chunk.clone(), sync_commit)?;
        }
        let version_to_commit = if let Some(ledger_info_with_sigs) = ledger_info_with_sigs {
            ledger_info_with_sigs.ledger_info().version()
        } else {
            chunk.expect_last_version()
        };
        self.commit_ledger(version_to_commit, ledger_info_with_sigs, Some(chunk))
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L261-288)
```rust
    fn commit_chunk_impl(&self) -> Result<ExecutedChunk> {
        let _timer = CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk_impl__total"]);
        let chunk = {
            let _timer =
                CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk_impl__next_chunk_to_commit"]);
            self.commit_queue.lock().next_chunk_to_commit()?
        };

        let output = chunk.output.expect_complete_result();
        let num_txns = output.num_transactions_to_commit();
        if chunk.ledger_info_opt.is_some() || num_txns != 0 {
            let _timer = CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk_impl__save_txns"]);
            // TODO(aldenhu): remove since there's no practical strategy to recover from this error.
            fail_point!("executor::commit_chunk", |_| {
                Err(anyhow::anyhow!("Injected error in commit_chunk"))
            });
            self.db.writer.save_transactions(
                output.as_chunk_to_commit(),
                chunk.ledger_info_opt.as_ref(),
                false, // sync_commit
            )?;
        }

        let _timer = CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk_impl__dequeue_and_return"]);
        self.commit_queue.lock().dequeue_committed()?;

        Ok(chunk)
    }
```
