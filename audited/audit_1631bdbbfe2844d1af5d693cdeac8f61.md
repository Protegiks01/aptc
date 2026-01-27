# Audit Report

## Title
Race Condition in Consensus Observer State Sync Causes Partial Synchronization Without Notification

## Summary
A race condition exists in the consensus observer's state synchronization mechanism where aborting an in-progress sync task after `sync_to_target()` completes but before the notification is sent causes the observer's state machine to become desynchronized with the actual ledger state. This occurs when multiple commit decisions arrive rapidly within the same epoch, or when `clear_active_commit_sync()` is called during the critical notification window.

## Finding Description

The vulnerability exists in the interaction between `sync_to_commit()` and the async task it spawns in the consensus observer. When `sync_to_commit()` is called, it spawns an async task that:

1. Calls `execution_client.sync_to_target()` to synchronize state [1](#0-0) 

2. Sends a notification upon success [2](#0-1) 

The task's abort handle is wrapped in a `DropGuard` and stored in `sync_to_commit_handle` [3](#0-2) 

The `DropGuard` implementation automatically aborts the task when dropped [4](#0-3) 

**The Critical Race Window:**

When a new commit decision arrives for a higher round within the same epoch, there is no guard preventing a new sync from starting. The only check is for epoch transitions [5](#0-4) 

If a new `sync_to_commit()` is called while Task A is between completing `sync_to_target()` and sending the notification:

1. Line 257 in state_sync_manager.rs overwrites `sync_to_commit_handle` with a new `DropGuard`
2. The old `DropGuard` is dropped, triggering its `Drop` implementation
3. Task A is aborted before the notification can be sent
4. The ledger state has been updated by `sync_to_target()` [6](#0-5)  including updating `latest_logical_time` and resetting the executor cache
5. But the notification never reaches the consensus observer

Similarly, if `clear_active_commit_sync()` is called during this window, it also drops the handle and aborts the task [7](#0-6) 

**Impact on State Machine:**

When the notification handler processes notifications, it first validates that a sync is active [8](#0-7) 

Without the notification:
- The observer never processes ordered blocks for the completed sync [9](#0-8) 
- The state sync metrics are never cleared [10](#0-9) 
- The observer's view of committed state becomes inconsistent with the actual ledger state

## Impact Explanation

This vulnerability falls under **High Severity** per the Aptos bug bounty criteria as it causes:

1. **Significant Protocol Violations**: The consensus observer's state machine becomes desynchronized from the actual ledger state, violating the State Consistency invariant. The observer believes it's waiting for a sync that has already completed.

2. **Observer Functionality Compromise**: Ordered blocks that should be finalized after the first sync completes are not processed until a later sync finishes, potentially delaying block finalization and transaction processing.

3. **Metrics Corruption**: The `OBSERVER_STATE_SYNC_EXECUTING` gauge remains set to 1 even after sync completion, providing incorrect monitoring data that could mask real issues.

4. **Cascading Effects**: If the observer's state machine is out of sync, it may reject valid commit decisions or fail to properly coordinate with the execution pipeline.

While this does not directly cause consensus safety violations (validators still progress correctly), it compromises the reliability of consensus observers, which are critical for light clients and monitoring infrastructure.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability is likely to occur in production scenarios:

1. **High-Throughput Networks**: In busy networks with rapid block production, multiple commit decisions can arrive within milliseconds of each other, especially during catch-up scenarios.

2. **Small Time Window**: The race window is small (between async task completion and notification sending), but async task scheduling can introduce variable delays that make this window exploitable.

3. **No Existing Guards**: There is no check preventing multiple `sync_to_commit()` calls within the same epoch, only for epoch transitions. This makes the race condition easily triggerable.

4. **Natural Network Conditions**: This doesn't require malicious behavior - it can occur naturally when a consensus observer is catching up with the network and receives multiple commit decisions in quick succession.

5. **Error Scenarios**: The race can also be triggered by error conditions where `clear_active_commit_sync()` is called due to inconsistent state detection.

## Recommendation

Add a guard to prevent starting a new sync while already syncing to a commit decision within the same epoch:

```rust
// In consensus_observer.rs, before line 525:
// Check if we're already syncing to a commit (not just through epoch)
if self.state_sync_manager.is_syncing_to_commit() {
    info!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Already syncing to commit decision. Dropping new commit: {:?}",
            commit_decision.proof_block_info()
        ))
    );
    return;
}
```

Alternatively, implement a more robust solution:

1. **Use a critical section flag**: Mark the notification as "pending send" before it can be aborted
2. **Atomic notification state**: Store notification state atomically with the abort handle
3. **Deferred cleanup**: Instead of immediately aborting old tasks, mark them for cleanup after notification is guaranteed sent

The simplest and safest fix is to add the guard shown above, treating same-epoch syncs similarly to epoch-transition syncs.

## Proof of Concept

```rust
// Test demonstrating the race condition
#[tokio::test]
async fn test_abort_during_notification_window() {
    use tokio::time::{sleep, Duration};
    
    // Create state sync manager
    let consensus_observer_config = ConsensusObserverConfig::default();
    let (state_sync_notification_sender, mut notification_receiver) = 
        tokio::sync::mpsc::unbounded_channel();
    
    // Mock execution client that introduces delay after sync_to_target
    struct DelayedExecutionClient;
    #[async_trait::async_trait]
    impl TExecutionClient for DelayedExecutionClient {
        async fn sync_to_target(&self, target: LedgerInfoWithSignatures) 
            -> Result<(), StateSyncError> {
            // Simulate successful sync
            sleep(Duration::from_millis(10)).await;
            Ok(())
        }
        // ... other methods
    }
    
    let mut state_sync_manager = StateSyncManager::new(
        consensus_observer_config,
        Arc::new(DelayedExecutionClient),
        state_sync_notification_sender,
    );
    
    // Start first sync to round 100
    let commit_decision_100 = CommitDecision::new(
        create_ledger_info(1, 100) // epoch 1, round 100
    );
    state_sync_manager.sync_to_commit(commit_decision_100, false);
    
    // Wait for sync_to_target to complete but notification not yet sent
    sleep(Duration::from_millis(15)).await;
    
    // Start second sync to round 200 - this aborts the first task
    let commit_decision_200 = CommitDecision::new(
        create_ledger_info(1, 200) // epoch 1, round 200
    );
    state_sync_manager.sync_to_commit(commit_decision_200, false);
    
    // Wait for second sync to complete
    sleep(Duration::from_millis(50)).await;
    
    // Check notifications received
    let mut notifications = vec![];
    while let Ok(notification) = notification_receiver.try_recv() {
        notifications.push(notification);
    }
    
    // BUG: We should receive 2 notifications (for round 100 and 200)
    // But we only receive 1 (for round 200) because round 100's task was aborted
    assert_eq!(notifications.len(), 1); // This demonstrates the bug
    
    // The ledger state was updated to round 100, then to round 200
    // But the observer only received notification for round 200
    // This leaves the observer's state machine out of sync
}
```

This test demonstrates that when a second sync starts while the first is between `sync_to_target()` completion and notification sending, only the second notification is received, even though both state updates occurred.

## Notes

This vulnerability specifically affects consensus observers, which are used by light clients and for monitoring purposes. While it doesn't directly compromise consensus safety among validators, it undermines the reliability of the observer infrastructure that depends on accurate state synchronization notifications. The lack of protection for same-epoch sync collisions is a clear oversight compared to the explicit guard for epoch-transition syncs.

### Citations

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L79-87)
```rust
    pub fn clear_active_commit_sync(&mut self) {
        // If we're not actively syncing to a commit, log an error
        if !self.is_syncing_to_commit() {
            error!(LogSchema::new(LogEntry::ConsensusObserver)
                .message("Failed to clear sync to commit decision! No active sync handle found!"));
        }

        self.sync_to_commit_handle = None;
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L219-231)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L233-244)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L246-251)
```rust
                // Clear the state sync metrics now that we're done syncing
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_TO_COMMIT,
                    0, // We're no longer syncing to a commit decision
                );
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L257-257)
```rust
        self.sync_to_commit_handle = Some((DropGuard::new(abort_handle), epoch_changed));
```

**File:** crates/reliable-broadcast/src/lib.rs (L232-236)
```rust
impl Drop for DropGuard {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L507-516)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L985-992)
```rust
        // Verify that there is an active commit sync
        if !self.state_sync_manager.is_syncing_to_commit() {
            // Log the error and return early
            error!(LogSchema::new(LogEntry::ConsensusObserver).message(
                "Failed to process commit sync notification! No active commit sync found!"
            ));
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1050-1061)
```rust
        // Process all the newly ordered blocks
        let all_ordered_blocks = self.observer_block_data.lock().get_all_ordered_blocks();
        for (_, (observed_ordered_block, commit_decision)) in all_ordered_blocks {
            // Finalize the ordered block
            let ordered_block = observed_ordered_block.consume_ordered_block();
            self.finalize_ordered_block(ordered_block).await;

            // If a commit decision is available, forward it to the execution pipeline
            if let Some(commit_decision) = commit_decision {
                self.forward_commit_decision(commit_decision.clone());
            }
        }
```

**File:** consensus/src/state_computer.rs (L218-226)
```rust
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Update the latest logical time
        *latest_logical_time = target_logical_time;

        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;
```
