# Audit Report

## Title
Unbounded Memory Growth in Mempool Due to Account Sequence Number Map Leak

## Summary
The `account_sequence_numbers` HashMap in mempool's `TransactionStore` grows unbounded as entries are inserted for every committed transaction but only removed when the last transaction for an account is removed from the mempool. This causes a memory leak affecting all validator nodes during normal blockchain operation.

## Finding Description

The vulnerability exists in the cleanup logic for the `account_sequence_numbers` HashMap. This HashMap tracks sequence numbers for accounts with transactions in the mempool.

**The problematic flow:**

When a transaction commits on the blockchain, state sync notifies mempool through `MempoolCommitNotification`, which triggers `process_committed_transactions()` to call `commit_transaction()` for ALL committed transactions. [1](#0-0) 

In `commit_transaction()`, for sequence-number-based transactions, the function unconditionally inserts the account's new sequence number into `account_sequence_numbers`: [2](#0-1) 

The ONLY place where entries are removed from `account_sequence_numbers` is in `index_remove()`, which executes cleanup only when the account has zero transactions remaining: [3](#0-2) 

**The critical issue:** The cleanup at line 760 checks `if let Some(txns) = self.transactions.get(address)`. If an account never had transactions in this node's mempool, this check returns `None`, the cleanup code never executes, and the `account_sequence_numbers` entry remains forever.

**Execution Flow:**
1. ALL validators receive commit notifications for ALL blockchain transactions via state sync [4](#0-3) 
2. Each validator's mempool processes these commits [5](#0-4) 
3. For accounts that submitted transactions through OTHER validators, the transaction was never in THIS validator's mempool
4. The unconditional insert adds an entry that will never be cleaned up

The `clean_committed_transactions_below_account_seq_num()` function only operates on accounts in the `transactions` map and doesn't clean up `account_sequence_numbers`: [6](#0-5) 

## Impact Explanation

This is **HIGH severity** per Aptos bug bounty criteria: "Validator Node Slowdowns (High): Significant performance degradation affecting consensus, DoS through resource exhaustion."

**Memory impact:**
- Each entry: ~40-50 bytes (32-byte `AccountAddress` + 8-byte `u64` + HashMap overhead)
- Over time, millions of unique accounts accumulate across the network
- Result: Hundreds of MB to GB of leaked memory per validator
- Eventually leads to: Node performance degradation, memory pressure, potential OOM crashes

**Network impact:**
- ALL validator nodes affected equally during normal operation
- Gradual degradation over weeks/months
- Can impact consensus performance as nodes experience memory pressure
- May require node restarts to clear accumulated state

This is NOT a network DoS attack (which is out of scope). This is a code bug causing resource exhaustion through normal blockchain operation, explicitly covered under "Validator Node Slowdowns (High)."

## Likelihood Explanation

**Likelihood: HIGH** - This occurs naturally during normal blockchain operation.

**Factors:**
1. **Guaranteed to occur:** Every unique account that commits a transaction adds an entry to ALL validators' mempools
2. **No attacker needed:** Organic user growth naturally triggers this
3. **Accelerated by design:** Aptos's high throughput means more unique accounts processed daily
4. **No mitigation:** No configuration, gas limits, or operational procedures prevent this

**Timeline:**
- Mainnet with millions of active accounts accumulates entries continuously
- High-activity periods (airdrops, NFT mints) with many new accounts accelerate growth
- Growth is monotonic - entries never decrease without node restart

## Recommendation

Modify the cleanup logic in `index_remove()` to also check and clean up `account_sequence_numbers` entries even when the account has no transactions in the mempool:

```rust
// Remove account datastructures if there are no more transactions for the account.
let address = &txn.get_sender();
if let Some(txns) = self.transactions.get(address) {
    if txns.len() == 0 {
        self.transactions.remove(address);
        self.account_sequence_numbers.remove(address);
    }
}
// Also remove orphaned sequence number entries
else {
    self.account_sequence_numbers.remove(address);
}
```

Alternatively, add a periodic cleanup mechanism or only insert into `account_sequence_numbers` when the account exists in `transactions`.

## Proof of Concept

```rust
#[test]
fn test_account_sequence_numbers_leak() {
    use crate::core_mempool::CoreMempool;
    use aptos_types::account_address::AccountAddress;
    use aptos_types::transaction::ReplayProtector;
    
    let mut mempool = CoreMempool::new(&Default::default());
    
    // Simulate commit notification for account that never had transactions in this mempool
    let account = AccountAddress::random();
    let initial_size = mempool.transactions.account_sequence_numbers.len();
    
    // Call commit_transaction for sequence number txn (simulates receiving commit notification)
    mempool.transactions.commit_transaction(&account, ReplayProtector::SequenceNumber(0));
    
    // Verify entry was added
    assert_eq!(mempool.transactions.account_sequence_numbers.len(), initial_size + 1);
    assert!(mempool.transactions.account_sequence_numbers.contains_key(&account));
    
    // Verify account has no transactions in mempool
    assert!(!mempool.transactions.transactions.contains_key(&account));
    
    // Attempt any cleanup operation - entry persists
    mempool.transactions.gc_by_system_ttl(Duration::from_secs(u64::MAX));
    
    // Entry still exists - memory leak confirmed
    assert!(mempool.transactions.account_sequence_numbers.contains_key(&account));
    
    // Simulate 1 million unique accounts committing transactions (normal mainnet operation)
    for _ in 0..1_000_000 {
        let random_account = AccountAddress::random();
        mempool.transactions.commit_transaction(&random_account, ReplayProtector::SequenceNumber(0));
    }
    
    // Verify unbounded growth
    assert!(mempool.transactions.account_sequence_numbers.len() > 1_000_000);
}
```

### Citations

**File:** mempool/src/shared_mempool/tasks.rs (L737-737)
```rust
        pool.commit_transaction(&transaction.sender, transaction.replay_protector);
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

**File:** mempool/src/core_mempool/transaction_store.rs (L677-683)
```rust
            ReplayProtector::SequenceNumber(txn_sequence_number) => {
                let current_account_seq_number =
                    self.get_account_sequence_number(account).map_or(0, |v| *v);
                let new_account_seq_number =
                    max(current_account_seq_number, txn_sequence_number + 1);
                self.account_sequence_numbers
                    .insert(*account, new_account_seq_number);
```

**File:** mempool/src/core_mempool/transaction_store.rs (L758-765)
```rust
        // Remove account datastructures if there are no more transactions for the account.
        let address = &txn.get_sender();
        if let Some(txns) = self.transactions.get(address) {
            if txns.len() == 0 {
                self.transactions.remove(address);
                self.account_sequence_numbers.remove(address);
            }
        }
```

**File:** state-sync/inter-component/mempool-notifications/src/lib.rs (L77-100)
```rust
    async fn notify_new_commit(
        &self,
        transactions: Vec<Transaction>,
        block_timestamp_usecs: u64,
    ) -> Result<(), Error> {
        // Get only user transactions from committed transactions
        let user_transactions: Vec<CommittedTransaction> = transactions
            .iter()
            .filter_map(|transaction| match transaction {
                Transaction::UserTransaction(signed_txn) => Some(CommittedTransaction {
                    sender: signed_txn.sender(),
                    replay_protector: signed_txn.replay_protector(),
                    use_case: signed_txn.parse_use_case(),
                }),
                _ => None,
            })
            .collect();

        // Mempool needs to be notified about all transactions (user and non-user transactions).
        // See https://github.com/aptos-labs/aptos-core/issues/1882 for more details.
        let commit_notification = MempoolCommitNotification {
            transactions: user_transactions,
            block_timestamp_usecs,
        };
```

**File:** mempool/src/shared_mempool/coordinator.rs (L229-257)
```rust
fn handle_commit_notification<TransactionValidator>(
    mempool: &Arc<Mutex<CoreMempool>>,
    mempool_validator: &Arc<RwLock<TransactionValidator>>,
    use_case_history: &Arc<Mutex<UseCaseHistory>>,
    msg: MempoolCommitNotification,
    num_committed_txns_received_since_peers_updated: &Arc<AtomicU64>,
) where
    TransactionValidator: TransactionValidation,
{
    debug!(
        block_timestamp_usecs = msg.block_timestamp_usecs,
        num_committed_txns = msg.transactions.len(),
        LogSchema::event_log(LogEntry::StateSyncCommit, LogEvent::Received),
    );

    // Process and time committed user transactions.
    let start_time = Instant::now();
    counters::mempool_service_transactions(
        counters::COMMIT_STATE_SYNC_LABEL,
        msg.transactions.len(),
    );
    num_committed_txns_received_since_peers_updated
        .fetch_add(msg.transactions.len() as u64, Ordering::Relaxed);
    process_committed_transactions(
        mempool,
        use_case_history,
        msg.transactions,
        msg.block_timestamp_usecs,
    );
```
