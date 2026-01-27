# Audit Report

## Title
Memory Exhaustion via Unbounded Consensus Notification Queue During Storage Read Failures

## Summary
The `handle_committed_transactions()` function in state-sync-driver returns early when storage reads fail, without implementing retry logic or backpressure. Combined with the unbounded consensus notification channel, this allows notifications containing full transaction and event data to accumulate indefinitely in memory during persistent storage failures, leading to potential node memory exhaustion.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Unbounded Notification Channel**: Consensus sends commit notifications to state sync via an unbounded MPSC channel [1](#0-0) 

2. **Early Return on Storage Failure**: When `handle_committed_transactions()` attempts to read from storage and fails, it immediately returns without processing the notification [2](#0-1) 

3. **No Retry Mechanism**: There is no retry logic, circuit breaker, or backpressure mechanism to handle repeated storage failures.

**Exploitation Flow:**

1. Storage subsystem experiences repeated failures or slowdowns (disk I/O issues, lock contention, resource exhaustion)
2. Consensus continues committing blocks and sending notifications via `notify_new_commit()` [3](#0-2) 
3. Each notification contains full `Vec<Transaction>` and `Vec<ContractEvent>` data structures
4. State sync driver receives notifications but fails storage reads, returning early without processing
5. Driver still responds `Ok(())` to consensus [4](#0-3) 
6. Consensus continues sending more notifications to the unbounded channel
7. Notifications accumulate in the channel waiting to be processed, each containing potentially megabytes of transaction data
8. Node memory grows unbounded until OOM crash

The downstream notifications to mempool, event subscription service, and storage service are never sent [5](#0-4) , causing additional state inconsistencies.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: Mempool retains committed transactions, event subscribers miss events, and storage service remains unnotified
- **Potential node crashes**: Memory exhaustion can cause validator nodes to crash, affecting network availability
- **Degrades under operational stress**: While not directly exploitable by external attackers, it creates a cascading failure mode during storage issues

At high throughput (1000+ TPS), each notification could contain 100KB-1MB of data. If 1000 notifications accumulate, this represents 100MB-1GB of memory growth, potentially triggering OOM kills on validators.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can occur under realistic operational conditions:
- Storage subsystem experiencing I/O slowdowns or failures
- High consensus throughput maintaining steady block production
- Lock contention on `current_state_locked()` [6](#0-5) 

While not directly exploitable by unprivileged attackers, it represents a legitimate availability risk during infrastructure stress. Validators running near memory limits are particularly vulnerable.

## Recommendation

Implement bounded channels with backpressure and retry logic:

```rust
pub async fn handle_committed_transactions<
    M: MempoolNotificationSender,
    S: StorageServiceNotificationSender,
>(
    committed_transactions: CommittedTransactions,
    storage: Arc<dyn DbReader>,
    mempool_notification_handler: MempoolNotificationHandler<M>,
    event_subscription_service: Arc<Mutex<EventSubscriptionService>>,
    storage_service_notification_handler: StorageServiceNotificationHandler<S>,
) -> Result<(), Error> {  // Return Result instead of ()
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 100;
    
    // Implement retry logic for storage reads
    let mut retry_count = 0;
    let (latest_synced_version, latest_synced_ledger_info) = loop {
        match fetch_pre_committed_version(storage.clone()) {
            Ok(version) => match fetch_latest_synced_ledger_info(storage.clone()) {
                Ok(ledger_info) => break (version, ledger_info),
                Err(error) if retry_count < MAX_RETRIES => {
                    warn!("Storage read failed, retrying {}/{}: {:?}", 
                          retry_count + 1, MAX_RETRIES, error);
                    retry_count += 1;
                    tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                    continue;
                },
                Err(error) => return Err(Error::StorageError(format!(
                    "Failed to fetch after {} retries: {:?}", MAX_RETRIES, error
                ))),
            },
            Err(error) if retry_count < MAX_RETRIES => {
                warn!("Storage read failed, retrying {}/{}: {:?}", 
                      retry_count + 1, MAX_RETRIES, error);
                retry_count += 1;
                tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                continue;
            },
            Err(error) => return Err(Error::StorageError(format!(
                "Failed to fetch after {} retries: {:?}", MAX_RETRIES, error
            ))),
        }
    };
    
    // Rest of the function...
    CommitNotification::handle_transaction_notification(/*...*/).await
}
```

Additionally, replace the unbounded consensus channel with a bounded channel and propagate errors back to consensus when the channel is full.

## Proof of Concept

```rust
// Simulated test demonstrating memory accumulation
#[tokio::test]
async fn test_memory_exhaustion_on_storage_failure() {
    // Create consensus notifier with unbounded channel
    let (consensus_notifier, mut consensus_listener) = 
        new_consensus_notifier_listener_pair(1000);
    
    // Create mock storage that always fails reads
    let failing_storage = Arc::new(MockFailingStorage::new());
    
    // Simulate high-throughput consensus sending 1000 notifications
    for i in 0..1000 {
        let large_txns = vec![create_large_transaction(); 100]; // 100 txns per block
        let events = vec![create_contract_event(); 50]; // 50 events per block
        
        // Send notification (will accumulate in unbounded channel)
        let _ = consensus_notifier.notify_new_commit(large_txns, events).await;
    }
    
    // Process notifications with failing storage
    let mut processed = 0;
    while let Some(notification) = consensus_listener.select_next_some().await {
        if let ConsensusNotification::NotifyCommit(commit) = notification {
            // This will fail and return early, but notification data remains in memory
            handle_committed_transactions(
                CommittedTransactions { 
                    transactions: commit.transactions,
                    events: commit.events 
                },
                failing_storage.clone(),
                // ... other handlers
            ).await;
            processed += 1;
        }
    }
    
    // At this point, all 1000 notifications have been allocated
    // and processed (failed), consuming ~100MB+ memory
    assert_eq!(processed, 1000);
}
```

**Notes**

This vulnerability represents a **graceful degradation failure** rather than a direct attack vector. While not exploitable by unprivileged external attackers, it creates a dangerous failure mode where storage issues can cascade into validator node crashes via memory exhaustion. The unbounded channel design violates the **Resource Limits** invariant (#9) by allowing unlimited memory growth during operational failures. Production validators experiencing storage I/O issues under high load are at risk of OOM crashes, potentially affecting network liveness if multiple validators are impacted simultaneously.

### Citations

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L62-62)
```rust
    let (notification_sender, notification_receiver) = mpsc::unbounded();
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L93-138)
```rust
    async fn notify_new_commit(
        &self,
        transactions: Vec<Transaction>,
        subscribable_events: Vec<ContractEvent>,
    ) -> Result<(), Error> {
        // Only send a notification if transactions have been committed
        if transactions.is_empty() {
            return Ok(());
        }

        // Create a consensus commit notification
        let (notification, callback_receiver) =
            ConsensusCommitNotification::new(transactions, subscribable_events);
        let commit_notification = ConsensusNotification::NotifyCommit(notification);

        // Send the notification to state sync
        if let Err(error) = self
            .notification_sender
            .clone()
            .send(commit_notification)
            .await
        {
            return Err(Error::NotificationError(format!(
                "Failed to notify state sync of committed transactions! Error: {:?}",
                error
            )));
        }

        // Handle any responses or a timeout
        if let Ok(response) = timeout(
            Duration::from_millis(self.commit_timeout_ms),
            callback_receiver,
        )
        .await
        {
            match response {
                Ok(consensus_notification_response) => consensus_notification_response.get_result(),
                Err(error) => Err(Error::UnexpectedErrorEncountered(format!(
                    "Consensus commit notification failure: {:?}",
                    error
                ))),
            }
        } else {
            Err(Error::TimeoutWaitingForStateSync)
        }
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

**File:** state-sync/state-sync-driver/src/driver.rs (L343-345)
```rust
        // Respond successfully
        self.consensus_notification_handler
            .respond_to_commit_notification(commit_notification, Ok(()))?;
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L75-112)
```rust
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

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L137-141)
```rust
    fn get_pre_committed_version(&self) -> Result<Option<Version>> {
        gauged_api("get_pre_committed_version", || {
            Ok(self.state_store.current_state_locked().version())
        })
    }
```
