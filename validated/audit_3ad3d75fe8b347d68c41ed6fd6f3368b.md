# Audit Report

## Title
State Sync Request Overwrite Vulnerability Causing Lost Consensus Observer Notifications

## Summary
The state sync notification handler unconditionally replaces active sync requests without responding to pending callbacks, causing consensus observers to receive channel cancellation errors and potentially become stuck in fallback mode.

## Finding Description

The vulnerability exists in the state sync driver's notification handler where sync requests are stored. When a consensus observer initiates a sync operation, it creates a oneshot channel and awaits the response. [1](#0-0) 

The critical flaw occurs in `initialize_sync_duration_request()` which unconditionally creates a new `Arc<Mutex<Option<ConsensusSyncRequest>>>` and replaces the existing field: [2](#0-1) 

The same vulnerability exists in `initialize_sync_target_request()`: [3](#0-2) 

When the old Arc is dropped, it drops the oneshot sender without invoking it. The awaiting receiver then receives a cancellation error: [4](#0-3) 

**Triggerable Scenario:**

The consensus observer's `StateSyncManager` maintains separate handles for different sync types: [5](#0-4) 

When the observer enters fallback mode, it calls `sync_for_fallback()`: [6](#0-5) 

This spawns an async task that initiates a duration-based sync: [7](#0-6) 

While in fallback mode, the observer continues processing network messages: [8](#0-7) 

If a commit decision for a future epoch/round arrives, it triggers `sync_to_commit()`: [9](#0-8) 

This second sync request overwrites the first at the state sync driver level, dropping the fallback sync's callback. The fallback sync task receives an error and exits without sending the completion notification: [10](#0-9) 

This leaves the observer stuck in fallback mode. The `check_progress()` function returns early whenever `in_fallback_mode()` returns true: [11](#0-10) 

The observer cannot resume normal operation until restarted.

## Impact Explanation

This qualifies as **MEDIUM to HIGH Severity**:

- **Protocol Contract Violation**: Breaks the request-response contract where all consensus notifications must receive responses
- **Consensus Observer Unavailability**: Affected fullnodes (VFNs/PFNs) become stuck in fallback mode and cannot process new blocks
- **Infrastructure Impact**: VFNs provide critical API services and relay blocks to downstream nodes; their failure degrades network accessibility

**Note:** This primarily affects consensus observers used by fullnodes (VFNs and PFNs), not validators directly: [12](#0-11) 

While validators run only the publisher component, VFNs are critical infrastructure supporting validator operations and user access. A stuck VFN requires manual restart to recover.

## Likelihood Explanation

**MODERATE likelihood** during network stress:

1. **Requires fallback mode entry**: Occurs when observer falls behind (network partitions, high latency)
2. **Requires overlapping sync operations**: Must receive commit decision for future epoch/round while fallback sync is active
3. **No mutual exclusion**: The architecture allows both sync types to be initiated independently with no synchronization between consensus observer and state sync driver layers

The vulnerability can trigger naturally during legitimate network conditions without malicious behavior, making it a realistic protocol-level race condition.

## Recommendation

Add mutual exclusion to prevent concurrent sync requests:

```rust
pub async fn initialize_sync_duration_request(
    &mut self,
    sync_duration_notification: ConsensusSyncDurationNotification,
) -> Result<(), Error> {
    // Check if there's an active sync request
    if let Some(existing_request) = self.consensus_sync_request.lock().as_ref() {
        // Respond to the new request with an error
        self.respond_to_sync_duration_notification(
            sync_duration_notification,
            Err(Error::ActiveSyncRequestExists),
            None,
        )?;
        return Err(Error::ActiveSyncRequestExists);
    }
    
    // Proceed with initialization...
}
```

Alternatively, before overwriting, properly respond to any existing sync request with a cancellation notification.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Starting a consensus observer node
2. Triggering fallback mode by disconnecting it from peers temporarily
3. While fallback sync is in progress, sending a commit decision message for a future round
4. Observing that the fallback sync fails with channel cancellation error
5. Verifying the observer remains stuck with `in_fallback_mode()` returning true
6. Confirming that `check_progress()` continuously returns early without processing blocks

**Notes**

This is a valid protocol-level vulnerability affecting consensus observer infrastructure. While it impacts fullnodes rather than core validators, VFNs are critical components that provide APIs and relay consensus decisions. The technical flaw is real and triggerable during network stress, though the severity depends on whether fullnode availability issues qualify as "Validator Node Slowdowns" under the bug bounty program.

### Citations

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L162-177)
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
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L364-364)
```rust
    callback: oneshot::Sender<ConsensusNotificationResponse>,
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L254-256)
```rust
        let consensus_sync_request =
            ConsensusSyncRequest::new_with_duration(start_time, sync_duration_notification);
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L313-315)
```rust
        let consensus_sync_request =
            ConsensusSyncRequest::new_with_target(sync_target_notification);
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L53-60)
```rust
    // The active fallback sync handle. If this is set, it means that
    // we've fallen back to state sync, and we should wait for it to complete.
    fallback_sync_handle: Option<DropGuard>,

    // The active sync to commit handle. If this is set, it means that
    // we're waiting for state sync to synchronize to a known commit decision.
    // The flag indicates if the commit will transition us to a new epoch.
    sync_to_commit_handle: Option<(DropGuard, bool)>,
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L117-153)
```rust
    pub fn sync_for_fallback(&mut self) {
        // Log that we're starting to sync in fallback mode
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Started syncing in fallback mode! Syncing duration: {:?} ms!",
                self.consensus_observer_config.observer_fallback_duration_ms
            ))
        );

        // Update the state sync fallback counter
        metrics::increment_counter_without_labels(&metrics::OBSERVER_STATE_SYNC_FALLBACK_COUNTER);

        // Clone the required components for the state sync task
        let consensus_observer_config = self.consensus_observer_config;
        let execution_client = self.execution_client.clone();
        let sync_notification_sender = self.state_sync_notification_sender.clone();

        // Spawn a task to sync for the fallback
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(
            async move {
                // Update the state sync metrics now that we're syncing for the fallback
                metrics::set_gauge_with_label(
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
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L154-160)
```rust
                {
                    Ok(latest_synced_ledger_info) => latest_synced_ledger_info,
                    Err(error) => {
                        error!(LogSchema::new(LogEntry::ConsensusObserver)
                            .message(&format!("Failed to sync for fallback! Error: {:?}", error)));
                        return;
                    },
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L173-177)
```rust
        if self.state_sync_manager.in_fallback_mode() {
            info!(LogSchema::new(LogEntry::ConsensusObserver)
                .message("Waiting for state sync to complete fallback syncing!",));
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L237-245)
```rust
    async fn enter_fallback_mode(&mut self) {
        // Terminate all active subscriptions (to ensure we don't process any more messages)
        self.subscription_manager.terminate_all_subscriptions();

        // Clear all the pending block state
        self.clear_pending_block_state().await;

        // Start syncing for the fallback
        self.state_sync_manager.sync_for_fallback();
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L500-527)
```rust
        // Otherwise, we failed to process the commit decision. If the commit
        // is for a future epoch or round, we need to state sync.
        let last_block = self.observer_block_data.lock().get_last_ordered_block();
        let epoch_changed = commit_epoch > last_block.epoch();
        if epoch_changed || commit_round > last_block.round() {
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

            // Otherwise, we should start the state sync process for the commit.
            // Update the block data (to the commit decision).
            self.observer_block_data
                .lock()
                .update_blocks_for_state_sync_commit(&commit_decision);

            // Start state syncing to the commit decision
            self.state_sync_manager
                .sync_to_commit(commit_decision, epoch_changed);
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1128-1130)
```rust
            tokio::select! {
                Some(network_message) = consensus_observer_message_receiver.next() => {
                    self.process_network_message(network_message).await;
```

**File:** config/src/config/consensus_observer_config.rs (L12-14)
```rust
const ENABLE_ON_VALIDATORS: bool = true;
const ENABLE_ON_VALIDATOR_FULLNODES: bool = true;
const ENABLE_ON_PUBLIC_FULLNODES: bool = false;
```
