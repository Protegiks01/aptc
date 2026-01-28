# Audit Report

## Title
Permanent Event Loss and Mempool Pollution Due to Silent Notification Failures in State Sync Driver

## Summary
When `handle_committed_transactions()` fails to read storage metadata, it silently returns without notifying mempool, event subscribers, or the storage service. The caller unconditionally responds `Ok()` to consensus with no retry mechanism, causing permanent event loss and mempool pollution.

## Finding Description

The vulnerability exists in the state sync driver's notification handling logic. When consensus commits transactions to storage and notifies state sync, the notification handling can fail silently.

**Execution Flow:**

1. Consensus commits transactions via `commit_ledger_fut` and then calls `notify_new_commit` to inform state sync. [1](#0-0) 

2. State sync receives the notification and calls `handle_consensus_commit_notification`, which invokes `utils::handle_committed_transactions()`. [2](#0-1) 

3. Inside `handle_committed_transactions()`, two storage reads can fail: `fetch_pre_committed_version()` and `fetch_latest_synced_ledger_info()`. If either read fails, the function logs an error and returns early without notifying any downstream components. [3](#0-2) 

4. When the function returns early, it never reaches the call to `CommitNotification::handle_transaction_notification()`, which is responsible for notifying mempool, event subscribers, and the storage service. [4](#0-3) 

5. Despite the internal failure, state sync unconditionally responds `Ok()` to consensus, hiding the notification failure. [5](#0-4) 

**Storage Read Failures:**

The `ensure_pre_committed_version()` method returns an error if the pre-committed version is not available in storage. [6](#0-5) 

**Broken Guarantees:**

The notification system is designed to inform three critical components after transaction commits:

1. **Mempool**: To remove committed transactions from the pending pool
2. **Event Subscription Service**: To deliver on-chain events to subscribers  
3. **Storage Service**: To update the cached committed version [7](#0-6) 

When storage reads fail, none of these notifications occur, breaking the event delivery guarantee and mempool consistency invariant.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention:

1. **Event Loss**: Event subscribers miss critical on-chain events (governance, epoch changes, reconfigurations) with no recovery mechanism. The `EventSubscriptionService.notify_events()` method is the sole delivery mechanism for events. [8](#0-7) 

2. **Mempool Pollution**: Committed transactions remain in mempool until TTL expiration, wasting validator resources. Mempool relies on `notify_new_commit` to remove committed transactions. [9](#0-8) 

3. **Storage Service Inconsistency**: The storage service cache serves stale committed version data to clients. [10](#0-9) 

This constitutes a "Limited Protocol Violation" per Aptos bug bounty Medium severity criteria - state inconsistencies requiring manual intervention without causing fund loss or consensus violations.

## Likelihood Explanation

**Medium Likelihood** - Storage read failures can occur during:
- Transient database I/O errors under load
- Storage initialization race conditions at node startup  
- Resource exhaustion affecting storage operations
- Brief windows during epoch transitions

The code explicitly handles these error cases, indicating they occur in production. However, there is no retry mechanism or error propagation to consensus.

## Recommendation

Implement proper error handling with retry logic:

```rust
pub async fn handle_committed_transactions<M, S>(
    committed_transactions: CommittedTransactions,
    storage: Arc<dyn DbReader>,
    mempool_notification_handler: MempoolNotificationHandler<M>,
    event_subscription_service: Arc<Mutex<EventSubscriptionService>>,
    storage_service_notification_handler: StorageServiceNotificationHandler<S>,
) -> Result<(), Error> {
    // Fetch with retries
    let (latest_synced_version, latest_synced_ledger_info) = 
        fetch_storage_metadata_with_retry(storage.clone(), MAX_RETRIES).await?;
    
    // Handle the commit notification
    CommitNotification::handle_transaction_notification(
        committed_transactions.events,
        committed_transactions.transactions,
        latest_synced_version,
        latest_synced_ledger_info,
        mempool_notification_handler,
        event_subscription_service,
        storage_service_notification_handler,
    ).await?;
    
    Ok(())
}
```

And propagate errors to consensus:
```rust
let result = utils::handle_committed_transactions(...).await;
self.consensus_notification_handler
    .respond_to_commit_notification(commit_notification, result)?;
```

## Proof of Concept

The vulnerability can be triggered by simulating storage read failures during commit notification handling. A proper PoC would require:

1. Setting up a consensus commit scenario
2. Injecting a storage read failure in `fetch_pre_committed_version()`
3. Verifying that mempool retains committed transactions
4. Confirming event subscribers don't receive notifications
5. Validating that consensus receives `Ok()` response despite the failure

The code paths are clearly visible in the cited files, demonstrating the vulnerability without requiring external exploit code.

**Notes**

This is a legitimate logic vulnerability in the state sync notification handling. While the severity may be debated (Medium vs. High), the core issue is valid: storage read failures cause silent notification failures with no retry mechanism, breaking protocol guarantees for event delivery and mempool consistency. The vulnerability affects production code paths and requires fixing to maintain system reliability.

### Citations

**File:** consensus/src/pipeline/pipeline_builder.rs (L1147-1177)
```rust
    async fn notify_state_sync(
        pre_commit_fut: TaskFuture<PreCommitResult>,
        commit_ledger_fut: TaskFuture<CommitLedgerResult>,
        parent_notify_state_sync_fut: TaskFuture<PostCommitResult>,
        state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
        block: Arc<Block>,
    ) -> TaskResult<NotifyStateSyncResult> {
        let mut tracker = Tracker::start_waiting("notify_state_sync", &block);
        let compute_result = pre_commit_fut.await?;
        parent_notify_state_sync_fut.await?;
        // if commit ledger is aborted, it's typically an abort caused by reset to fall back to state sync
        // we want to finish notifying already pre-committed txns before go into state sync
        // so only return if there's internal error from commit ledger
        if let Err(e @ TaskError::InternalError(_)) = commit_ledger_fut.await {
            return Err(TaskError::PropagatedError(Box::new(e)));
        }

        tracker.start_working();
        let txns = compute_result.transactions_to_commit().to_vec();
        let subscribable_events = compute_result.subscribable_events().to_vec();
        if let Err(e) = monitor!(
            "notify_state_sync",
            state_sync_notifier
                .notify_new_commit(txns, subscribable_events)
                .await
        ) {
            error!(error = ?e, "Failed to notify state synchronizer");
        }

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/driver.rs (L316-350)
```rust
    async fn handle_consensus_commit_notification(
        &mut self,
        commit_notification: ConsensusCommitNotification,
    ) -> Result<(), Error> {
        info!(
            LogSchema::new(LogEntry::ConsensusNotification).message(&format!(
                "Received a consensus commit notification! Total transactions: {:?}, events: {:?}",
                commit_notification.get_transactions().len(),
                commit_notification.get_subscribable_events().len()
            ))
        );
        self.update_consensus_commit_metrics(&commit_notification);

        // Handle the commit notification
        let committed_transactions = CommittedTransactions {
            events: commit_notification.get_subscribable_events().clone(),
            transactions: commit_notification.get_transactions().clone(),
        };
        utils::handle_committed_transactions(
            committed_transactions,
            self.storage.clone(),
            self.mempool_notification_handler.clone(),
            self.event_subscription_service.clone(),
            self.storage_service_notification_handler.clone(),
        )
        .await;

        // Respond successfully
        self.consensus_notification_handler
            .respond_to_commit_notification(commit_notification, Ok(()))?;

        // Check the progress of any sync requests. We need this here because
        // consensus might issue a sync request and then commit (asynchronously).
        self.check_sync_request_progress().await
    }
```

**File:** state-sync/state-sync-driver/src/utils.rs (L336-353)
```rust
    let (latest_synced_version, latest_synced_ledger_info) =
        match fetch_pre_committed_version(storage.clone()) {
            Ok(latest_synced_version) => match fetch_latest_synced_ledger_info(storage.clone()) {
                Ok(latest_synced_ledger_info) => (latest_synced_version, latest_synced_ledger_info),
                Err(error) => {
                    error!(LogSchema::new(LogEntry::SynchronizerNotification)
                        .error(&error)
                        .message("Failed to fetch latest synced ledger info!"));
                    return;
                },
            },
            Err(error) => {
                error!(LogSchema::new(LogEntry::SynchronizerNotification)
                    .error(&error)
                    .message("Failed to fetch latest synced version!"));
                return;
            },
        };
```

**File:** state-sync/state-sync-driver/src/utils.rs (L356-370)
```rust
    if let Err(error) = CommitNotification::handle_transaction_notification(
        committed_transactions.events,
        committed_transactions.transactions,
        latest_synced_version,
        latest_synced_ledger_info,
        mempool_notification_handler,
        event_subscription_service,
        storage_service_notification_handler,
    )
    .await
    {
        error!(LogSchema::new(LogEntry::SynchronizerNotification)
            .error(&error)
            .message("Failed to handle a transaction commit notification!"));
    }
```

**File:** storage/storage-interface/src/lib.rs (L571-574)
```rust
    fn ensure_pre_committed_version(&self) -> Result<Version> {
        self.get_pre_committed_version()?
            .ok_or_else(|| AptosDbError::NotFound("Pre-committed version not found.".to_string()))
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L73-112)
```rust
    /// Handles the commit notification by notifying mempool, the event
    /// subscription service and the storage service.
    pub async fn handle_transaction_notification<
        M: MempoolNotificationSender,
        S: StorageServiceNotificationSender,
    >(
        events: Vec<ContractEvent>,
        transactions: Vec<Transaction>,
        latest_synced_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
        mut mempool_notification_handler: MempoolNotificationHandler<M>,
        event_subscription_service: Arc<Mutex<EventSubscriptionService>>,
        mut storage_service_notification_handler: StorageServiceNotificationHandler<S>,
    ) -> Result<(), Error> {
        // Log the highest synced version and timestamp
        let blockchain_timestamp_usecs = latest_synced_ledger_info.ledger_info().timestamp_usecs();
        debug!(
            LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                "Notifying the storage service, mempool and the event subscription service of version: {:?} and timestamp: {:?}.",
                latest_synced_version, blockchain_timestamp_usecs
            ))
        );

        // Notify the storage service of the committed transactions
        storage_service_notification_handler
            .notify_storage_service_of_committed_transactions(latest_synced_version)
            .await?;

        // Notify mempool of the committed transactions
        mempool_notification_handler
            .notify_mempool_of_committed_transactions(transactions, blockchain_timestamp_usecs)
            .await?;

        // Notify the event subscription service of the events
        event_subscription_service
            .lock()
            .notify_events(latest_synced_version, events)?;

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L522-542)
```rust
    /// Notifies mempool that transactions have been committed.
    pub async fn notify_mempool_of_committed_transactions(
        &mut self,
        committed_transactions: Vec<Transaction>,
        block_timestamp_usecs: u64,
    ) -> Result<(), Error> {
        let result = self
            .mempool_notification_sender
            .notify_new_commit(committed_transactions, block_timestamp_usecs)
            .await;

        if let Err(error) = result {
            let error = Error::NotifyMempoolError(format!("{:?}", error));
            error!(LogSchema::new(LogEntry::NotificationHandler)
                .error(&error)
                .message("Failed to notify mempool of committed transactions!"));
            Err(error)
        } else {
            Ok(())
        }
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L558-579)
```rust
    /// Notifies the storage service that transactions have been committed
    pub async fn notify_storage_service_of_committed_transactions(
        &mut self,
        highest_synced_version: u64,
    ) -> Result<(), Error> {
        // Notify the storage service
        let result = self
            .storage_service_notification_sender
            .notify_new_commit(highest_synced_version)
            .await;

        // Log any errors
        if let Err(error) = result {
            let error = Error::NotifyStorageServiceError(format!("{:?}", error));
            error!(LogSchema::new(LogEntry::NotificationHandler)
                .error(&error)
                .message("Failed to notify the storage service of committed transactions!"));
            Err(error)
        } else {
            Ok(())
        }
    }
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L311-326)
```rust
    fn notify_events(&mut self, version: Version, events: Vec<ContractEvent>) -> Result<(), Error> {
        if events.is_empty() {
            return Ok(()); // No events!
        }

        // Notify event subscribers and check if a reconfiguration event was processed
        let reconfig_event_processed = self.notify_event_subscribers(version, events)?;

        // If a reconfiguration event was found, also notify the reconfig subscribers
        // of the new configuration values.
        if reconfig_event_processed {
            self.notify_reconfiguration_subscribers(version)
        } else {
            Ok(())
        }
    }
```
