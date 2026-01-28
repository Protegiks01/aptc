# Audit Report

## Title
Consensus Observer State Sync Deadlock on Permanent Failures

## Summary
The Consensus Observer's state sync manager does not properly handle permanent state sync failures, causing validators to enter an unrecoverable deadlock state where they indefinitely wait for sync operations that have already failed and will never complete.

## Finding Description

The vulnerability occurs in the interaction between `StateSyncManager` and `ConsensusObserver` when handling state sync failures.

The `StateSyncError` type is a transparent wrapper around `anyhow::Error` that does not distinguish between transient and permanent failures: [1](#0-0) 

When state sync operations fail in spawned tasks, the error is logged and the task exits without sending a notification. For fallback sync: [2](#0-1) 

For commit sync: [3](#0-2) 

However, the sync handles remain set because they were initialized when the sync started: [4](#0-3) [5](#0-4) 

These handles are only cleared when success notifications are received: [6](#0-5) [7](#0-6) 

The consensus observer's progress check becomes permanently stuck because when handles remain set, the check methods return early without verifying actual progress: [8](#0-7) [9](#0-8) 

The handle check methods simply verify if handles exist: [10](#0-9) [11](#0-10) 

Permanent failures exist in the state sync driver, such as `OldSyncRequest`: [12](#0-11) 

This error is returned when the sync target is already committed: [13](#0-12) 

The progress check runs on a regular interval: [14](#0-13) [15](#0-14) 

However, it cannot detect the stuck state due to the early returns. The critical issue is that when handles remain set, the fallback manager's `check_syncing_progress()` at line 191 is never reached, preventing automatic entry into fallback mode that would recover the validator.

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" under the Aptos bug bounty criteria:

- **Validator Liveness Failure**: Affected validators cannot participate in consensus, reducing network security margins
- **Requires Manual Intervention**: Only a node restart can recover from this state
- **Cascading Failures**: If multiple validators encounter the same permanent failures simultaneously, network liveness degrades
- **No Consensus Safety Impact**: Does not cause chain splits or double-spending
- **Resource Consumption**: Validator remains in stuck state consuming resources without contributing to consensus

This is a liveness issue, not a safety violation, which aligns with Medium severity as it requires manual intervention but does not compromise consensus integrity.

## Likelihood Explanation

**High Likelihood**:

- **Natural Occurrence**: Can be triggered by legitimate network conditions (validators falling behind, blocks being pruned, network partitions)
- **No Malicious Intent Required**: Happens without attacker action when permanent sync failures occur
- **Common Scenarios**: 
  - Validator receives sync target for already-committed version (OldSyncRequest error)
  - Missing blocks that peers cannot provide
  - Database corruption or storage errors during sync
- **Detection Difficulty**: Validator operators may not immediately notice the stuck state as the node appears to be "syncing"

## Recommendation

The spawned state sync tasks should always send notifications, regardless of success or failure. Modify the error handling to send a failure notification:

**For fallback sync (state_sync_manager.rs lines 156-160):**
```rust
Err(error) => {
    error!(LogSchema::new(LogEntry::ConsensusObserver)
        .message(&format!("Failed to sync for fallback! Error: {:?}", error)));
    // Send failure notification to allow handle cleanup and retry
    let _ = sync_notification_sender.send(
        StateSyncNotification::FallbackSyncFailed(error)
    );
    return;
}
```

**For commit sync (state_sync_manager.rs lines 219-231):**
```rust
if let Err(error) = execution_client.clone().sync_to_target(...).await {
    error!(LogSchema::new(LogEntry::ConsensusObserver)
        .message(&format!("Failed to sync to commit decision: {:?}! Error: {:?}", ...)));
    // Send failure notification to allow handle cleanup and retry
    let _ = sync_notification_sender.send(
        StateSyncNotification::CommitSyncFailed(commit_decision.commit_proof().clone(), error)
    );
    return;
}
```

Additionally, add a timeout mechanism in `check_progress()` to detect handles that have been set for too long without completion, and force entry into fallback mode.

## Proof of Concept

The vulnerability can be demonstrated by triggering an `OldSyncRequest` error scenario:

1. Start a consensus observer node
2. Allow it to sync to a specific version (e.g., version 1000)
3. Send a commit decision targeting an older version (e.g., version 500) that's already committed
4. The state sync driver returns `OldSyncRequest` error
5. The sync task logs the error and exits without notification
6. The `sync_to_commit_handle` remains set indefinitely
7. Progress checks continuously return early at line 187
8. The validator remains stuck, unable to process new blocks or enter fallback mode
9. Only a node restart recovers the validator

While a full executable PoC requires complex test infrastructure setup, the logical flow is directly verifiable in the cited code paths.

### Citations

**File:** consensus/src/error.rs (L20-25)
```rust
#[derive(Debug, Error)]
#[error(transparent)]
pub struct StateSyncError {
    #[from]
    inner: anyhow::Error,
}
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L101-103)
```rust
    pub fn in_fallback_mode(&self) -> bool {
        self.fallback_sync_handle.is_some()
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L112-114)
```rust
    pub fn is_syncing_to_commit(&self) -> bool {
        self.sync_to_commit_handle.is_some()
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L156-160)
```rust
                    Err(error) => {
                        error!(LogSchema::new(LogEntry::ConsensusObserver)
                            .message(&format!("Failed to sync for fallback! Error: {:?}", error)));
                        return;
                    },
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L186-186)
```rust
        self.fallback_sync_handle = Some(DropGuard::new(abort_handle));
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

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L257-257)
```rust
        self.sync_to_commit_handle = Some((DropGuard::new(abort_handle), epoch_changed));
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L173-177)
```rust
        if self.state_sync_manager.in_fallback_mode() {
            info!(LogSchema::new(LogEntry::ConsensusObserver)
                .message("Waiting for state sync to complete fallback syncing!",));
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L180-188)
```rust
        if self.state_sync_manager.is_syncing_to_commit() {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Waiting for state sync to reach commit decision: {:?}!",
                    self.observer_block_data.lock().root().commit_info()
                ))
            );
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L964-964)
```rust
        self.state_sync_manager.clear_active_fallback_sync();
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1048-1048)
```rust
        self.state_sync_manager.clear_active_commit_sync();
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1115-1119)
```rust
        // Create a progress check ticker
        let mut progress_check_interval = IntervalStream::new(interval(Duration::from_millis(
            consensus_observer_config.progress_check_interval_ms,
        )))
        .fuse();
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1135-1137)
```rust
                _ = progress_check_interval.select_next_some() => {
                    self.check_progress().await;
                }
```

**File:** state-sync/state-sync-driver/src/error.rs (L39-40)
```rust
    #[error("Received an old sync request for version {0}, but our pre-committed version is: {1} and committed version: {2}")]
    OldSyncRequest(Version, Version, Version),
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L276-285)
```rust
        if sync_target_version < latest_committed_version
            || sync_target_version < latest_pre_committed_version
        {
            let error = Err(Error::OldSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
                latest_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
```
