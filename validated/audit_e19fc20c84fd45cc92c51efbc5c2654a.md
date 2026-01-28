# Audit Report

## Title
Consensus Sync Request State Corruption via Arc Replacement Pattern Causing Lost Callback Responses

## Summary
The state sync driver uses an incorrect Arc replacement pattern when handling new consensus sync requests, causing previous request callbacks to be dropped without responses. This violates the consensus-state sync protocol invariant that every request receives exactly one response, degrading validator synchronization performance.

## Finding Description

The vulnerability exists in the `ConsensusNotificationHandler` which manages consensus sync request state. When a new sync request arrives, the code creates a completely new `Arc<Mutex<Option<ConsensusSyncRequest>>>` instead of updating the contents of the existing Arc. [1](#0-0) [2](#0-1) 

Each consensus sync request contains a oneshot callback channel that must receive exactly one response: [3](#0-2) [4](#0-3) 

**The Bug Flow:**

1. Consensus sends sync request Request_A with callback_A via `sync_to_target()` or `sync_for_duration()`
2. State sync driver receives notification and calls `initialize_sync_target_request()` which creates `Arc_A = Arc::new(Mutex::new(Some(Request_A)))` and assigns it to `self.consensus_sync_request`
3. The handler returns immediately without responding to the callback - the response will be sent later when the sync completes
4. State sync driver begins working on Request_A asynchronously in its event loop
5. Before Request_A completes, consensus sends Request_B with callback_B (during epoch transitions or consensus observer operations)
6. State sync driver receives notification_B and calls `initialize_sync_target_request()` again
7. **BUG**: This creates `Arc_B = Arc::new(Mutex::new(Some(Request_B)))` and replaces `self.consensus_sync_request = Arc_B`
8. If no other component holds long-lived Arc_A references, Arc_A is dropped when all temporary references expire
9. When Arc_A is dropped, Request_A's `ConsensusSyncTargetNotification` is dropped, which drops the `oneshot::Sender<ConsensusNotificationResponse>` callback
10. Consensus awaiting callback_A receives `RecvError` from the oneshot channel [5](#0-4) 

The notification handlers do not check for existing active requests before creating new ones - they immediately create a new Arc and replace the field. [6](#0-5) 

The issue is compounded by the state checking logic in `check_sync_request_progress()` which retrieves the current Arc at one point but then later calls `handle_satisfied_sync_request()` that locks `self.consensus_sync_request` - which may now point to a different Arc if replacement occurred between the check and response: [7](#0-6) 

When the oneshot sender is dropped, the receiver gets an error that is converted to `Error::UnexpectedErrorEncountered`: [8](#0-7) [9](#0-8) 

## Impact Explanation

**High Severity** - This qualifies as "Validator Node Slowdowns" under the Aptos bug bounty program:

1. **Protocol Violation**: Violates the fundamental consensus-state sync contract that every request receives exactly one proper response. Consensus receives unexpected `Error::UnexpectedErrorEncountered` instead of proper sync completion responses or explicit cancellation notifications.

2. **Consensus Coordination Failure**: Breaks the synchronization mechanism between consensus and state sync. When consensus receives unexpected errors instead of completion confirmations, it may retry operations or enter degraded operation modes, not knowing that its request was superseded.

3. **Validator Performance Impact**: Can cause validators to fail proper sync coordination, leading to slowdowns and degraded block production performance. The unexpected errors may trigger retry logic or fallback paths that weren't designed for this scenario.

4. **Cascading Failures**: If multiple validators experience this issue during critical periods (epoch transitions, network partitions), it could amplify consensus delays and reduce network throughput.

While this doesn't cause permanent fund loss or consensus safety violations (different state roots), it significantly degrades network performance and validator operation, qualifying as High severity per the bug bounty program.

## Likelihood Explanation

**Medium Likelihood** during specific operational scenarios:

1. **Epoch Transitions**: During epoch changes, consensus adjusts sync targets as the validator set changes, potentially issuing new sync requests before previous ones complete. [10](#0-9) 

2. **Consensus Observer Operations**: The consensus observer spawns independent tasks for both fallback syncing and commit syncing, creating potential for overlapping requests: [11](#0-10) [12](#0-11) 

3. **Fast-Forward Syncing**: Block storage sync manager can trigger sync operations during recovery: [13](#0-12) 

The vulnerability requires notifications to arrive faster than sync operations complete - not the common case during normal operation, but plausible during network stress, state transitions, or epoch changes when sync targets may be updated before previous syncs finish.

## Recommendation

Replace the Arc replacement pattern with content update pattern. Instead of creating a new Arc:

```rust
// INCORRECT (current code):
self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));
```

Use content mutation of the existing Arc:

```rust
// CORRECT:
let mut sync_request_lock = self.consensus_sync_request.lock();

// Check if there's an existing request and handle its callback
if let Some(old_request) = sync_request_lock.take() {
    // Respond to the old request with cancellation before replacing it
    match old_request {
        ConsensusSyncRequest::SyncTarget(old_notification) => {
            let _ = self.respond_to_sync_target_notification(
                old_notification,
                Err(Error::SyncRequestSuperseded)
            );
        },
        ConsensusSyncRequest::SyncDuration(_, old_notification) => {
            let _ = self.respond_to_sync_duration_notification(
                old_notification,
                Err(Error::SyncRequestSuperseded),
                None
            );
        },
    }
}

// Now set the new request
*sync_request_lock = Some(consensus_sync_request);
```

This ensures:
1. The same Arc is always used (preventing reference confusion)
2. Old callbacks are explicitly responded to before being replaced
3. Consensus receives proper cancellation notifications instead of unexpected errors

## Proof of Concept

A complete PoC would require setting up the full consensus and state sync infrastructure. The vulnerability can be demonstrated by:

1. Starting a validator node
2. Triggering a sync_to_target request with a distant target that will take time to complete
3. Before completion, triggering another sync request (e.g., via epoch transition or consensus observer mode change)
4. Observing that the first request's callback receives RecvError converted to UnexpectedErrorEncountered

The code evidence clearly shows the Arc replacement pattern and the absence of callback handling before replacement, making this vulnerability evident from static analysis.

## Notes

This is a protocol-level bug affecting the consensus-state sync interface, not a network DoS attack. The vulnerability violates the API contract between consensus and state sync, where every request should receive exactly one response. The Arc replacement pattern is a fundamental design flaw that can cause dropped callbacks during legitimate operational scenarios like epoch transitions and consensus observer mode switches.

### Citations

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L256-256)
```rust
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L262-318)
```rust
    pub async fn initialize_sync_target_request(
        &mut self,
        sync_target_notification: ConsensusSyncTargetNotification,
        latest_pre_committed_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        // Get the target sync version and latest committed version
        let sync_target_version = sync_target_notification
            .get_target()
            .ledger_info()
            .version();
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();

        // If the target version is old, return an error to consensus (something is wrong!)
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
        }

        // If the committed version is at the target, return successfully
        if sync_target_version == latest_committed_version {
            info!(
                LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                    "We're already at the requested sync target version: {} \
                (pre-committed version: {}, committed version: {})!",
                    sync_target_version, latest_pre_committed_version, latest_committed_version
                ))
            );
            let result = Ok(());
            self.respond_to_sync_target_notification(sync_target_notification, result.clone())?;
            return result;
        }

        // If the pre-committed version is already at the target, something has else gone wrong
        if sync_target_version == latest_pre_committed_version {
            let error = Err(Error::InvalidSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // Save the request so we can notify consensus once we've hit the target
        let consensus_sync_request =
            ConsensusSyncRequest::new_with_target(sync_target_notification);
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));

        Ok(())
    }
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L162-178)
```rust
        match callback_receiver.await {
            Ok(response) => match response.get_result() {
                Ok(_) => response.get_latest_synced_ledger_info().ok_or_else(|| {
                    Error::UnexpectedErrorEncountered(
                        "Sync for duration returned an empty latest synced ledger info!".into(),
                    )
                }),
                Err(error) => Err(Error::UnexpectedErrorEncountered(format!(
                    "Sync for duration returned an error: {:?}",
                    error
                ))),
            },
            Err(error) => Err(Error::UnexpectedErrorEncountered(format!(
                "Sync for duration failure: {:?}",
                error
            ))),
        }
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L200-206)
```rust
        match callback_receiver.await {
            Ok(response) => response.get_result(),
            Err(error) => Err(Error::UnexpectedErrorEncountered(format!(
                "Sync to target failure: {:?}",
                error
            ))),
        }
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L361-379)
```rust
#[derive(Debug)]
pub struct ConsensusSyncDurationNotification {
    duration: Duration,
    callback: oneshot::Sender<ConsensusNotificationResponse>,
}

impl ConsensusSyncDurationNotification {
    pub fn new(duration: Duration) -> (Self, oneshot::Receiver<ConsensusNotificationResponse>) {
        let (callback, callback_receiver) = oneshot::channel();
        let notification = ConsensusSyncDurationNotification { duration, callback };

        (notification, callback_receiver)
    }

    /// Returns the duration of the notification
    pub fn get_duration(&self) -> Duration {
        self.duration
    }
}
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L381-402)
```rust
/// A notification for state sync to synchronize to the given target
#[derive(Debug)]
pub struct ConsensusSyncTargetNotification {
    target: LedgerInfoWithSignatures,
    callback: oneshot::Sender<ConsensusNotificationResponse>,
}

impl ConsensusSyncTargetNotification {
    pub fn new(
        target: LedgerInfoWithSignatures,
    ) -> (Self, oneshot::Receiver<ConsensusNotificationResponse>) {
        let (callback, callback_receiver) = oneshot::channel();
        let notification = ConsensusSyncTargetNotification { target, callback };

        (notification, callback_receiver)
    }

    /// Returns a reference to the target of the notification
    pub fn get_target(&self) -> &LedgerInfoWithSignatures {
        &self.target
    }
}
```

**File:** state-sync/state-sync-driver/src/driver.rs (L408-442)
```rust
    async fn handle_consensus_sync_target_notification(
        &mut self,
        sync_target_notification: ConsensusSyncTargetNotification,
    ) -> Result<(), Error> {
        // Fetch the pre-committed and committed versions
        let latest_pre_committed_version =
            utils::fetch_pre_committed_version(self.storage.clone())?;
        let latest_synced_ledger_info =
            utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();

        // Update the sync target notification logs and metrics
        info!(
            LogSchema::new(LogEntry::ConsensusNotification).message(&format!(
                "Received a consensus sync target notification! Target: {:?}. \
                Latest pre-committed version: {}. Latest committed version: {}.",
                sync_target_notification.get_target(),
                latest_pre_committed_version,
                latest_committed_version,
            ))
        );
        metrics::increment_counter(
            &metrics::DRIVER_COUNTERS,
            metrics::DRIVER_CONSENSUS_SYNC_TARGET_NOTIFICATION,
        );

        // Initialize a new sync request
        self.consensus_notification_handler
            .initialize_sync_target_request(
                sync_target_notification,
                latest_pre_committed_version,
                latest_synced_ledger_info,
            )
            .await
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L536-609)
```rust
    async fn check_sync_request_progress(&mut self) -> Result<(), Error> {
        // Check if the sync request has been satisfied
        let consensus_sync_request = self.consensus_notification_handler.get_sync_request();
        match consensus_sync_request.lock().as_ref() {
            Some(consensus_sync_request) => {
                let latest_synced_ledger_info =
                    utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
                if !consensus_sync_request
                    .sync_request_satisfied(&latest_synced_ledger_info, self.time_service.clone())
                {
                    return Ok(()); // The sync request hasn't been satisfied yet
                }
            },
            None => {
                return Ok(()); // There's no active sync request
            },
        }

        // The sync request has been satisfied. Wait for the storage synchronizer
        // to drain. This prevents notifying consensus prematurely.
        while self.storage_synchronizer.pending_storage_data() {
            sample!(
                SampleRate::Duration(Duration::from_secs(PENDING_DATA_LOG_FREQ_SECS)),
                info!("Waiting for the storage synchronizer to handle pending data!")
            );

            // Yield to avoid starving the storage synchronizer threads.
            yield_now().await;
        }

        // If the request was to sync for a specified duration, we should only
        // stop syncing when the synced version and synced ledger info version match.
        // Otherwise, the DB will be left in an inconsistent state on handover.
        if let Some(sync_request) = consensus_sync_request.lock().as_ref() {
            if sync_request.is_sync_duration_request() {
                // Get the latest synced version and ledger info version
                let latest_synced_version =
                    utils::fetch_pre_committed_version(self.storage.clone())?;
                let latest_synced_ledger_info =
                    utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
                let latest_ledger_info_version = latest_synced_ledger_info.ledger_info().version();

                // Check if the latest synced version matches the latest ledger info version
                if latest_synced_version != latest_ledger_info_version {
                    sample!(
                        SampleRate::Duration(Duration::from_secs(DRIVER_INFO_LOG_FREQ_SECS)),
                        info!(
                            "Waiting for state sync to sync to a ledger info! \
                            Latest synced version: {:?}, latest ledger info version: {:?}",
                            latest_synced_version, latest_ledger_info_version
                        )
                    );

                    return Ok(()); // State sync should continue to run
                }
            }
        }

        // Handle the satisfied sync request
        let latest_synced_ledger_info =
            utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
        self.consensus_notification_handler
            .handle_satisfied_sync_request(latest_synced_ledger_info)
            .await?;

        // If the sync request was successfully handled, reset the continuous syncer
        // so that in the event another sync request occurs, we have fresh state.
        if !self.active_sync_request() {
            self.continuous_syncer.reset_active_stream(None).await?;
            self.storage_synchronizer.finish_chunk_executor(); // Consensus or consensus observer is now in control
        }

        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L545-569)
```rust
        let ledger_info = proof
            .verify(self.epoch_state())
            .context("[EpochManager] Invalid EpochChangeProof")?;
        info!(
            LogSchema::new(LogEvent::NewEpoch).epoch(ledger_info.ledger_info().next_block_epoch()),
            "Received verified epoch change",
        );

        // shutdown existing processor first to avoid race condition with state sync.
        self.shutdown_current_processor().await;
        *self.pending_blocks.lock() = PendingBlocks::new();
        // make sure storage is on this ledger_info too, it should be no-op if it's already committed
        // panic if this doesn't succeed since the current processors are already shutdown.
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
            .context(format!(
                "[EpochManager] State sync to new epoch {}",
                ledger_info
            ))
            .expect("Failed to sync to new epoch");

        monitor!("reconfig", self.await_reconfig_notification().await);
        Ok(())
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L140-187)
```rust
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_FOR_FALLBACK,
                    1, // We're syncing for the fallback
                );

                // Get the fallback duration
                let fallback_duration =
                    Duration::from_millis(consensus_observer_config.observer_fallback_duration_ms);

                // Sync for the fallback duration
                let latest_synced_ledger_info = match execution_client
                    .clone()
                    .sync_for_duration(fallback_duration)
                    .await
                {
                    Ok(latest_synced_ledger_info) => latest_synced_ledger_info,
                    Err(error) => {
                        error!(LogSchema::new(LogEntry::ConsensusObserver)
                            .message(&format!("Failed to sync for fallback! Error: {:?}", error)));
                        return;
                    },
                };

                // Notify consensus observer that we've synced for the fallback
                let state_sync_notification =
                    StateSyncNotification::fallback_sync_completed(latest_synced_ledger_info);
                if let Err(error) = sync_notification_sender.send(state_sync_notification) {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send state sync notification for fallback! Error: {:?}",
                            error
                        ))
                    );
                }

                // Clear the state sync metrics now that we're done syncing
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_FOR_FALLBACK,
                    0, // We're no longer syncing for the fallback
                );
            },
            abort_registration,
        ));

        // Save the sync task handle
        self.fallback_sync_handle = Some(DropGuard::new(abort_handle));
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L189-230)
```rust
    /// Invokes state sync to synchronize to a new commit decision
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
```

**File:** consensus/src/block_storage/sync_manager.rs (L500-525)
```rust
                )
            })?;

        storage.save_tree(blocks.clone(), quorum_certs.clone())?;
        // abort any pending executor tasks before entering state sync
        // with zaptos, things can run before hitting buffer manager
        if let Some(block_store) = maybe_block_store {
            monitor!(
                "abort_pipeline_for_state_sync",
                block_store.abort_pipeline_for_state_sync().await
            );
        }
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;

        // we do not need to update block_tree.highest_commit_decision_ledger_info here
        // because the block_tree is going to rebuild itself.

        let recovery_data = match storage.start(order_vote_enabled, window_size) {
            LivenessStorageData::FullRecoveryData(recovery_data) => recovery_data,
            _ => panic!("Failed to construct recovery data after fast forward sync"),
        };

        Ok(recovery_data)
    }
```
