# Audit Report

## Title
Transaction Loss During Validator Node Bootstrapping Due to Historical Commit Notifications

## Summary
BCS transactions submitted via the REST API during validator node synchronization can be permanently lost without error notification when the node processes historical blocks containing transactions with the same sender and sequence number, causing mempool to incorrectly remove the newly submitted transaction.

## Finding Description

During validator node bootstrapping, the REST API accepts transaction submissions while state sync simultaneously processes historical blocks. This creates a race condition where newly submitted transactions can be permanently lost.

**Validated Execution Path:**

1. **API Accepts Transactions Without Bootstrap Validation**: The REST API transaction submission endpoints only check the `transaction_submission_enabled` flag before accepting transactions. [1](#0-0) [2](#0-1)  No validation exists to check if the node has completed bootstrapping before accepting user transactions.

2. **Transaction Submission Enabled By Default**: The `transaction_submission_enabled` configuration flag defaults to `true` in the node configuration. [3](#0-2) [4](#0-3) 

3. **Mempool Starts Before Bootstrap Completes**: The node initialization sequence demonstrates that mempool runtime is started before waiting for state sync bootstrap completion. [5](#0-4)  The state sync initialization wait only occurs after mempool is already active and processing transactions. [6](#0-5) 

4. **State Sync Notifies Mempool of All Commits**: During bootstrapping, the storage synchronizer spawns a commit post-processor that handles commit notifications. [7](#0-6)  This processor notifies mempool of all committed transactions, including historical ones processed during synchronization. [8](#0-7) [9](#0-8) 

5. **Mempool Updates Sequence Numbers and Removes Transactions**: When mempool receives a commit notification for a sequence-number transaction, it updates the account sequence number to `max(current, txn_sequence_number + 1)` and calls the cleanup method. [10](#0-9) [11](#0-10) 

6. **Cleanup Logic Removes All Transactions Below Sequence**: The `clean_committed_transactions_below_account_seq_num` method removes all transactions with sequence numbers below the provided threshold. [12](#0-11)  It uses `seq_num_split_off` which keeps only transactions with sequence numbers >= the threshold. [13](#0-12) 

7. **Bootstrap Check Exists But Is Not Used**: The `is_bootstrapped()` method exists in the bootstrapper. [14](#0-13)  However, this check is not used by the API transaction submission endpoints to gate transaction acceptance.

**Attack Scenario:**

1. Validator node restarts and begins bootstrapping from version 1000 to version 2000
2. At version 1000, account A has on-chain sequence number 50
3. User submits NEW transaction A:50 via `/transactions` API endpoint
4. Mempool validates against state at version 1000, sees sequence 50 is valid, returns HTTP 202 Accepted
5. Transaction A:50 is added to mempool
6. State sync processes historical block at version 1500 containing a DIFFERENT historical transaction A:50 (already on blockchain)
7. Storage synchronizer sends commit notification for historical transaction A:50
8. Mempool's `commit_transaction` updates account A's sequence to 51 (50+1) and calls `clean_committed_transactions_below_account_seq_num(51)`
9. This removes ALL transactions with sequence < 51, including the user's newly submitted transaction A:50
10. User's transaction is permanently lost, never broadcast to consensus, never executed

The critical flaw is that mempool tracks transactions only by (address, sequence_number) pairs and cannot distinguish between a newly submitted transaction and a historical transaction with the same sequence number.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria:

**Why Medium:**
- **Limited funds loss or manipulation**: Users submitting transactions during bootstrapping windows may lose transactions entirely, causing failed transfers they believe succeeded
- **State inconsistencies requiring manual intervention**: Mempool state becomes inconsistent with user expectations, requiring manual detection and resubmission
- **Silent failure**: Users receive HTTP 202 Accepted but transaction never executes, with no notification mechanism
- **Affects real user funds**: Can lead to actual financial impact when transactions carrying value are lost

**Why Not Critical:**
- Only affects transactions during temporary bootstrapping windows
- Does not compromise consensus safety or network-wide state
- Impact limited to individual users, not entire network
- Does not enable direct theft or unlimited minting

**Why Not Low:**
- Causes actual transaction loss with financial implications
- Occurs during normal operations (restarts, new validators, recovery)
- No user notification or recovery mechanism
- Can affect any transaction during multi-hour bootstrapping windows

## Likelihood Explanation

**High Likelihood:**

1. **Frequent Occurrence**: Validator nodes bootstrap regularly during node restarts for maintenance or upgrades, new validators joining the network, recovery from crashes or network issues, and catching up after falling behind

2. **Default Configuration Enables Vulnerability**: The `transaction_submission_enabled` flag defaults to `true` and is not automatically disabled during bootstrapping

3. **No Bootstrap State Validation**: Neither the API nor mempool checks bootstrap completion before accepting transactions

4. **Wide Vulnerability Window**: The vulnerability window spans the entire bootstrapping period, which can range from minutes to hours depending on how far behind the node is

5. **Difficult to Detect**: Users have no indication their transaction was lost unless they actively monitor transaction status, as the initial response is HTTP 202 Accepted

## Recommendation

Implement bootstrap state validation before accepting transactions:

1. **Add Bootstrap Check to API**: Modify the transaction submission endpoints to check `is_bootstrapped()` before accepting transactions
2. **Reject During Bootstrap**: Return HTTP 503 Service Unavailable with a clear error message when the node is still bootstrapping
3. **Configuration Option**: Add a configuration flag to control whether to accept transactions during bootstrap (defaulting to false for safety)
4. **Alternative: Separate Mempool State**: Maintain separate tracking for user-submitted vs. historical transactions during bootstrap to prevent incorrect removal

## Proof of Concept

A proof of concept would require:

1. Setting up a validator node that is behind the network by several thousand versions
2. Submitting a transaction via the REST API immediately after node startup
3. Monitoring the mempool to observe the transaction being removed when state sync processes the corresponding historical block
4. Verifying the transaction never reaches consensus despite receiving HTTP 202 Accepted

The vulnerability is demonstrated through the code path analysis showing that all components are in place for this race condition to occur during normal operations.

## Notes

This vulnerability represents a design flaw in the interaction between API availability, mempool transaction tracking, and state sync commit notifications. The issue is particularly insidious because it provides false confirmation to users (HTTP 202 Accepted) while silently discarding their transactions. The fix requires coordination between the API layer, state sync bootstrap tracking, and mempool transaction acceptance policies.

### Citations

**File:** api/src/transactions.rs (L490-492)
```rust
        if !self.context.node_config.api.transaction_submission_enabled {
            return Err(api_disabled("Submit transaction"));
        }
```

**File:** api/src/transactions.rs (L543-545)
```rust
        if !self.context.node_config.api.transaction_submission_enabled {
            return Err(api_disabled("Submit batch transaction"));
        }
```

**File:** config/src/config/api_config.rs (L104-106)
```rust
fn default_enabled() -> bool {
    true
}
```

**File:** config/src/config/api_config.rs (L127-127)
```rust
            transaction_submission_enabled: default_enabled(),
```

**File:** aptos-node/src/lib.rs (L801-810)
```rust
    let (mempool_runtime, consensus_to_mempool_sender) =
        services::start_mempool_runtime_and_get_consensus_sender(
            &mut node_config,
            &db_rw,
            mempool_reconfig_subscription,
            mempool_network_interfaces,
            mempool_listener,
            mempool_client_receiver,
            peers_and_metadata,
        );
```

**File:** aptos-node/src/lib.rs (L824-827)
```rust
    // Wait until state sync has been initialized
    debug!("Waiting until state sync is initialized!");
    state_sync_runtimes.block_until_initialized();
    debug!("State sync initialization complete.");
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L783-824)
```rust
/// Spawns a dedicated commit post-processor that handles commit notifications
fn spawn_commit_post_processor<
    MempoolNotifier: MempoolNotificationSender,
    StorageServiceNotifier: StorageServiceNotificationSender,
>(
    mut commit_post_processor_listener: mpsc::Receiver<ChunkCommitNotification>,
    event_subscription_service: Arc<Mutex<EventSubscriptionService>>,
    mempool_notification_handler: MempoolNotificationHandler<MempoolNotifier>,
    storage_service_notification_handler: StorageServiceNotificationHandler<StorageServiceNotifier>,
    pending_data_chunks: Arc<AtomicU64>,
    runtime: Option<Handle>,
    storage: Arc<dyn DbReader>,
) -> JoinHandle<()> {
    // Create a commit post-processor
    let commit_post_processor = async move {
        while let Some(notification) = commit_post_processor_listener.next().await {
            // Start the commit post-process timer
            let _timer = metrics::start_timer(
                &metrics::STORAGE_SYNCHRONIZER_LATENCIES,
                metrics::STORAGE_SYNCHRONIZER_COMMIT_POST_PROCESS,
            );

            // Handle the committed transaction notification (e.g., notify mempool)
            let committed_transactions = CommittedTransactions {
                events: notification.subscribable_events,
                transactions: notification.committed_transactions,
            };
            utils::handle_committed_transactions(
                committed_transactions,
                storage.clone(),
                mempool_notification_handler.clone(),
                event_subscription_service.clone(),
                storage_service_notification_handler.clone(),
            )
            .await;
            decrement_pending_data_chunks(pending_data_chunks.clone());
        }
    };

    // Spawn the commit post-processor
    spawn(runtime, commit_post_processor)
}
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L101-104)
```rust
        // Notify mempool of the committed transactions
        mempool_notification_handler
            .notify_mempool_of_committed_transactions(transactions, blockchain_timestamp_usecs)
            .await?;
```

**File:** mempool/src/shared_mempool/coordinator.rs (L252-257)
```rust
    process_committed_transactions(
        mempool,
        use_case_history,
        msg.transactions,
        msg.block_timestamp_usecs,
    );
```

**File:** mempool/src/core_mempool/transaction_store.rs (L635-665)
```rust
    fn clean_committed_transactions_below_account_seq_num(
        &mut self,
        address: &AccountAddress,
        account_sequence_number: u64,
    ) {
        // Remove all previous seq number transactions for this account.
        // This can happen if transactions are sent to multiple nodes and one of the
        // nodes has sent the transaction to consensus but this node still has the
        // transaction sitting in mempool.
        if let Some(txns) = self.transactions.get_mut(address) {
            let mut active = txns.seq_num_split_off(account_sequence_number);
            let txns_for_removal = txns.clone();
            txns.clear();
            txns.append(&mut active);

            let mut rm_txns = match aptos_logger::enabled!(Level::Trace) {
                true => TxnsLog::new(),
                false => TxnsLog::new_with_max(10),
            };
            for transaction in txns_for_removal.values() {
                rm_txns.add(transaction.get_sender(), transaction.get_replay_protector());
                self.index_remove(transaction);
            }
            trace!(
                LogSchema::new(LogEntry::CleanCommittedTxn).txns(rm_txns),
                "txns cleaned with committing tx {}:{}",
                address,
                account_sequence_number
            );
        }
    }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L671-688)
```rust
    pub fn commit_transaction(
        &mut self,
        account: &AccountAddress,
        replay_protector: ReplayProtector,
    ) {
        match replay_protector {
            ReplayProtector::SequenceNumber(txn_sequence_number) => {
                let current_account_seq_number =
                    self.get_account_sequence_number(account).map_or(0, |v| *v);
                let new_account_seq_number =
                    max(current_account_seq_number, txn_sequence_number + 1);
                self.account_sequence_numbers
                    .insert(*account, new_account_seq_number);
                self.clean_committed_transactions_below_account_seq_num(
                    account,
                    new_account_seq_number,
                );
                self.process_ready_seq_num_based_transactions(account, new_account_seq_number);
```

**File:** mempool/src/shared_mempool/tasks.rs (L737-737)
```rust
        pool.commit_transaction(&transaction.sender, transaction.replay_protector);
```

**File:** mempool/src/core_mempool/index.rs (L90-97)
```rust
    pub(crate) fn seq_num_split_off(&mut self, sequence_number: u64) -> Self {
        AccountTransactions {
            sequence_number_transactions: self
                .sequence_number_transactions
                .split_off(&sequence_number),
            nonce_transactions: mem::take(&mut self.nonce_transactions),
        }
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L368-370)
```rust
    pub fn is_bootstrapped(&self) -> bool {
        self.bootstrapped
    }
```
