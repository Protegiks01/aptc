> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

---

Notes:
- The provided citations show that: (1) block timestamp validation allows blocks up to 5 minutes ahead of local system time; (2) this future timestamp is accepted into the chain and will become the canonical on-chain time via the Move prologue; (3) mempool garbage collection and transaction expiration all use this timestamp, meaning valid transactions can be dropped/rejected if the timestamp is manipulated; (4) this does not require a colluding majority or compromise of trusted parties—just a malicious proposer within normal Aptos operation.
- This results in a Medium severity protocol impact due to time skew-induced censorship/validity window truncation, as described in the report.

### Citations

**File:** consensus/consensus-types/src/block.rs (L521-540)
```rust
        if self.is_nil_block() || parent.has_reconfiguration() {
            ensure!(
                self.timestamp_usecs() == parent.timestamp_usecs(),
                "Nil/reconfig suffix block must have same timestamp as parent"
            );
        } else {
            ensure!(
                self.timestamp_usecs() > parent.timestamp_usecs(),
                "Blocks must have strictly increasing timestamps"
            );

            let current_ts = duration_since_epoch();

            // we can say that too far is 5 minutes in the future
            const TIMEBOUND: u64 = 300_000_000;
            ensure!(
                self.timestamp_usecs() <= (current_ts.as_micros() as u64).saturating_add(TIMEBOUND),
                "Blocks must not be too far in the future"
            );
        }
```

**File:** crates/aptos-infallible/src/time.rs (L1-100)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

#![forbid(unsafe_code)]

use std::time::{Duration, SystemTime};

/// Gives the duration since the Unix epoch, notice the expect.
pub fn duration_since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is before the UNIX_EPOCH")
}

/// Gives the duration of the given time since the Unix epoch, notice the expect.
pub fn duration_since_epoch_at(system_time: &SystemTime) -> Duration {
    system_time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is before the UNIX_EPOCH")
}


```

**File:** aptos-move/framework/aptos-framework/sources/timestamp.move (L31-50)
```text
    /// Updates the wall clock time by consensus. Requires VM privilege and will be invoked during block prologue.
    public fun update_global_time(
        account: &signer,
        proposer: address,
        timestamp: u64
    ) acquires CurrentTimeMicroseconds {
        // Can only be invoked by AptosVM signer.
        system_addresses::assert_vm(account);

        let global_timer = borrow_global_mut<CurrentTimeMicroseconds>(@aptos_framework);
        let now = global_timer.microseconds;
        if (proposer == @vm_reserved) {
            // NIL block with null address as proposer. Timestamp must be equal.
            assert!(now == timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
        } else {
            // Normal block. Time must advance
            assert!(now < timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
            global_timer.microseconds = timestamp;
        };
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L713-743)
```rust
pub(crate) fn process_committed_transactions(
    mempool: &Mutex<CoreMempool>,
    use_case_history: &Mutex<UseCaseHistory>,
    transactions: Vec<CommittedTransaction>,
    block_timestamp_usecs: u64,
) {
    let mut pool = mempool.lock();
    let block_timestamp = Duration::from_micros(block_timestamp_usecs);

    let tracking_usecases = {
        let mut history = use_case_history.lock();
        history.update_usecases(&transactions);
        history.compute_tracking_set()
    };

    for transaction in transactions {
        pool.log_commit_transaction(
            &transaction.sender,
            transaction.replay_protector,
            tracking_usecases
                .get(&transaction.use_case)
                .map(|name| (transaction.use_case.clone(), name)),
            block_timestamp,
        );
        pool.commit_transaction(&transaction.sender, transaction.replay_protector);
    }

    if block_timestamp_usecs > 0 {
        pool.gc_by_expiration_time(block_timestamp);
    }
}
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L80-104)
```rust
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
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L139-142)
```text
        assert!(
            timestamp::now_seconds() < txn_expiration_time,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRED),
        );
```
