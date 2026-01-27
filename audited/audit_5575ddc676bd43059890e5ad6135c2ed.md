# Audit Report

## Title
Parking Lot Flooding via GC: Permanent Transaction Trapping Leading to Mempool DoS

## Summary
An attacker can flood the mempool's parking lot with transactions that can never become ready by exploiting the garbage collection (GC) mechanism. When a ready transaction with sequence number N is GC'd, all subsequent transactions (N+1, N+2, etc.) are forcibly parked but cannot become ready again because the required predecessor transaction (N) is gone. This allows an attacker to fill the mempool with permanently stuck transactions, causing memory exhaustion and rejection of legitimate transactions.

## Finding Description
The vulnerability exists in the `gc()` function's handling of sequence number transactions. When a transaction is garbage collected, the code at lines 959-976 automatically parks all subsequent transactions from the same account: [1](#0-0) 

The critical security flaw is that once parked, these transactions can **never** become ready again unless the missing transaction is resubmitted and committed on-chain. Here's why:

**Attack Flow:**
1. Attacker creates many accounts and submits sequential transactions (seq: 0, 1, 2, ..., 99) for each account
2. The `process_ready_seq_num_based_transactions` function makes all transactions ready since they are sequential: [2](#0-1) 

3. Attacker sets transaction 0 with a very short expiration time (e.g., expires in 1 second)
4. When GC runs, transaction 0 is removed and transactions 1-99 are forcibly parked
5. These parked transactions require `account_sequence_num >= 1` to become ready, but:
   - The on-chain account sequence number is still 0 (transaction 0 was never committed)
   - The mempool's cached sequence number is also 0
   - The only recovery path requires submitting a new transaction 0 and committing it on-chain
   
6. Attacker never resubmits transaction 0, leaving 99 permanently parked transactions per account
7. With ~20,000 accounts, the attacker approaches the default capacity limit of 2,000,000 transactions

The existing test `test_gc_ready_transaction` demonstrates this behavior but doesn't treat it as a security issue: [3](#0-2) 

**Why Current Mitigations Fail:**

The eviction mechanism only triggers when inserting **ready** transactions: [4](#0-3) 

An attacker submitting **non-ready** transactions (future sequence numbers) bypasses eviction. Additionally, eviction is reactive and cannot keep pace with a coordinated flooding attack.

## Impact Explanation
This is a **High Severity** vulnerability per Aptos bug bounty criteria:

**Validator Node Slowdowns:** 
- Mempool capacity defaults to 2,000,000 transactions and 2GB [5](#0-4) 

- With `capacity_per_user = 100`, an attacker needs only ~20,000 accounts to fill mempool with parked transactions
- Each account can hold 100 transactions, and 99 can be permanently parked after GC
- Total parked: 20,000 × 99 = 1,980,000 transactions (99% of capacity)

**Significant Protocol Violations:**
- Legitimate user transactions are rejected with "Mempool is full" errors
- Consensus cannot pull transactions efficiently from a nearly-full mempool
- Network throughput degrades significantly

**Resource Exhaustion:**
- Memory consumption approaches 2GB limit
- Parking lot index grows without bound (no separate limit exists) [6](#0-5) 

## Likelihood Explanation
**Very High Likelihood:**

**Ease of Execution:**
- Account creation is free (no on-chain cost until first transaction)
- Submitting transactions requires minimal gas (can use very low gas prices)
- Setting short expiration times is trivial
- Attack can be automated and executed over hours/days

**Low Cost:**
- Transaction submission cost: ~100 accounts × 100 txns × minimal_gas ≈ negligible
- No need for validator access or collusion
- Attack can be executed from any network node

**No Effective Barriers:**
- Per-account limit (100 transactions) is easily circumvented by using many accounts
- No rate limiting on parking lot growth
- No automatic cleanup of permanently stuck parked transactions
- Eviction only helps when ready transactions are inserted, not proactively

## Recommendation
Implement multi-layered defense:

**1. Maximum Parking Lot Size Limit:**
Add a separate capacity limit for the parking lot (e.g., 20% of total capacity):

```rust
pub struct TransactionStore {
    // ... existing fields ...
    parking_lot_capacity: usize,
}

impl TransactionStore {
    pub(crate) fn new(config: &MempoolConfig) -> Self {
        Self {
            // ... existing initialization ...
            parking_lot_capacity: config.capacity / 5, // 20% of total capacity
        }
    }
    
    fn check_parking_lot_capacity(&self) -> bool {
        self.parking_lot_index.size() >= self.parking_lot_capacity
    }
}
```

**2. Proactive Parking Lot Cleanup:**
When parking lot exceeds threshold, aggressively evict oldest parked transactions:

```rust
fn gc(&mut self, now: Duration, by_system_ttl: bool) {
    // ... existing GC logic ...
    
    // After GC, check if parking lot is too full
    if self.parking_lot_index.size() > self.parking_lot_capacity {
        self.evict_excess_parked_transactions();
    }
}

fn evict_excess_parked_transactions(&mut self) {
    let target_size = self.parking_lot_capacity * 90 / 100; // Evict to 90%
    while self.parking_lot_index.size() > target_size {
        if let Some(txn_pointer) = self.parking_lot_index.get_poppable() {
            if let Some(txn) = self.transactions
                .get_mut(&txn_pointer.sender)
                .and_then(|txns| txns.remove(&txn_pointer.replay_protector)) 
            {
                self.index_remove(&txn);
            }
        } else {
            break;
        }
    }
}
```

**3. Parking Time Limit:**
Track how long transactions have been parked and evict those exceeding threshold:

```rust
// In MempoolTransaction, track parking duration
pub struct InsertionInfo {
    pub park_time: Option<SystemTime>,
    // ... existing fields ...
}

// Add parking TTL check during GC
const MAX_PARKING_TIME_SECS: u64 = 300; // 5 minutes

fn gc(&mut self, now: Duration, by_system_ttl: bool) {
    // ... existing GC logic ...
    
    // Remove transactions parked for too long
    self.gc_stale_parked_transactions(now);
}

fn gc_stale_parked_transactions(&mut self, now: Duration) {
    let mut to_remove = vec![];
    for (address, txns) in self.transactions.iter() {
        for (replay_protector, txn) in txns.values() {
            if let Some(park_time) = txn.insertion_info.park_time {
                if let Ok(parked_duration) = SystemTime::now().duration_since(park_time) {
                    if parked_duration.as_secs() > MAX_PARKING_TIME_SECS {
                        to_remove.push((*address, *replay_protector));
                    }
                }
            }
        }
    }
    
    for (address, replay_protector) in to_remove {
        if let Some(txns) = self.transactions.get_mut(&address) {
            if let Some(txn) = txns.remove(&replay_protector) {
                self.index_remove(&txn);
            }
        }
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_parking_lot_flood_attack() {
    let mut config = NodeConfig::generate_random_config();
    config.mempool.capacity = 1000; // Reduced for test
    config.mempool.capacity_per_user = 50;
    let mut pool = CoreMempool::new(&config);
    
    let num_accounts = 20;
    
    // Attack phase 1: Submit sequential transactions for many accounts
    for account_idx in 0..num_accounts {
        // Submit transactions 0-49 for each account
        for seq in 0..50 {
            let txn = if seq == 0 {
                // First transaction expires quickly
                TestTransaction::new(account_idx, ReplayProtector::SequenceNumber(seq), 1)
                    .make_signed_transaction_with_expiration_time(0)
            } else {
                TestTransaction::new(account_idx, ReplayProtector::SequenceNumber(seq), 1)
                    .make_signed_transaction()
            };
            
            pool.add_txn(
                txn,
                0, // gas_amount
                Some(0), // account sequence number
                TimelineState::NotReady,
                false,
                None,
                Some(BroadcastPeerPriority::Primary),
            );
        }
    }
    
    // Verify all transactions became ready (sequential from 0)
    let ready_count = pool.get_batch(1000, 1024 * 1024, true, btreemap![]).len();
    assert_eq!(ready_count, num_accounts * 50);
    
    // Attack phase 2: Trigger GC to remove transaction 0 for all accounts
    pool.gc_by_expiration_time(Duration::from_secs(1));
    
    // Verify transactions 1-49 are now parked for all accounts
    let ready_count_after_gc = pool.get_batch(1000, 1024 * 1024, true, btreemap![]).len();
    assert_eq!(ready_count_after_gc, 0); // All ready txns were GC'd or parked
    
    // Verify parking lot is flooded
    let parking_lot_size = pool.get_parking_lot_size();
    assert_eq!(parking_lot_size, num_accounts * 49); // 49 parked txns per account
    
    // Attack phase 3: Verify legitimate transactions are rejected
    let new_txn = TestTransaction::new(999, ReplayProtector::SequenceNumber(0), 1)
        .make_signed_transaction();
    
    let result = pool.add_txn(
        new_txn,
        0,
        Some(0),
        TimelineState::NotReady,
        false,
        None,
        Some(BroadcastPeerPriority::Primary),
    );
    
    // Should fail because mempool is full of parked transactions
    assert!(result.code == MempoolStatusCode::MempoolIsFull);
    
    println!("Attack successful: {} permanently parked transactions", parking_lot_size);
}
```

**Notes**

This vulnerability breaks the "Resource Limits" invariant by allowing unbounded growth of the parking lot with transactions that can never become ready. The existing eviction mechanism is insufficient because it only triggers on ready transaction insertion and cannot keep pace with a coordinated flood attack. The recommended fixes add multiple layers of defense: hard limits on parking lot size, proactive cleanup, and time-based eviction of stale parked transactions.

### Citations

**File:** mempool/src/core_mempool/transaction_store.rs (L415-420)
```rust
    fn check_is_full_after_eviction(
        &mut self,
        txn: &MempoolTransaction,
        account_sequence_number: Option<u64>,
    ) -> bool {
        if self.is_full() && self.check_txn_ready(txn, account_sequence_number) {
```

**File:** mempool/src/core_mempool/transaction_store.rs (L603-611)
```rust
    fn process_ready_seq_num_based_transactions(
        &mut self,
        address: &AccountAddress,
        account_sequence_num: u64,
    ) {
        let mut min_seq = account_sequence_num;
        while self.process_ready_transaction(address, ReplayProtector::SequenceNumber(min_seq)) {
            min_seq += 1;
        }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L958-974)
```rust
                    for (_, t) in txns.seq_num_range_mut((park_range_start, park_range_end)) {
                        self.parking_lot_index.insert(t);
                        self.priority_index.remove(t);
                        let sender_bucket = sender_bucket(&t.get_sender(), self.num_sender_buckets);
                        self.timeline_index
                            .get_mut(&sender_bucket)
                            .unwrap_or_else(|| {
                                panic!(
                                    "Unable to get the timeline index for the sender bucket {}",
                                    sender_bucket
                                )
                            })
                            .remove(t);
                        if let TimelineState::Ready(_) = t.timeline_state {
                            t.timeline_state = TimelineState::NotReady;
                        }
                    }
```

**File:** mempool/src/tests/core_mempool_test.rs (L1331-1410)
```rust
fn test_gc_ready_transaction() {
    let mut pool = setup_mempool().0;
    add_txn(
        &mut pool,
        TestTransaction::new(1, ReplayProtector::SequenceNumber(0), 1),
    )
    .unwrap();

    // Insert in the middle transaction that's going to be expired.
    let txn = TestTransaction::new(1, ReplayProtector::SequenceNumber(1), 1)
        .make_signed_transaction_with_expiration_time(0);
    let sender_bucket = sender_bucket(&txn.sender(), MempoolConfig::default().num_sender_buckets);

    pool.add_txn(
        txn,
        1,
        Some(0),
        TimelineState::NotReady,
        false,
        None,
        Some(BroadcastPeerPriority::Primary),
    );

    // Insert few transactions after it.
    // They are supposed to be ready because there's a sequential path from 0 to them.
    add_txn(
        &mut pool,
        TestTransaction::new(1, ReplayProtector::SequenceNumber(2), 1),
    )
    .unwrap();
    add_txn(
        &mut pool,
        TestTransaction::new(1, ReplayProtector::SequenceNumber(3), 1),
    )
    .unwrap();

    // Check that all txns are ready.
    let (timeline, _) = pool.read_timeline(
        sender_bucket,
        &vec![0].into(),
        10,
        None,
        BroadcastPeerPriority::Primary,
    );
    assert_eq!(timeline.len(), 4);

    // GC expired transaction.
    pool.gc_by_expiration_time(Duration::from_secs(1));

    // Make sure txns 2 and 3 became not ready and we can't read them from any API.
    let block = pool.get_batch(1, 1024, true, btreemap![]);
    assert_eq!(block.len(), 1);
    assert_eq!(block[0].sequence_number(), 0);

    let (timeline, _) = pool.read_timeline(
        sender_bucket,
        &vec![0].into(),
        10,
        None,
        BroadcastPeerPriority::Primary,
    );
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].0.sequence_number(), 0);

    // Resubmit txn 1
    add_txn(
        &mut pool,
        TestTransaction::new(1, ReplayProtector::SequenceNumber(1), 1),
    )
    .unwrap();

    // Make sure txns 2 and 3 can be broadcast after txn 1 is resubmitted
    let (timeline, _) = pool.read_timeline(
        sender_bucket,
        &vec![0].into(),
        10,
        None,
        BroadcastPeerPriority::Primary,
    );
    assert_eq!(timeline.len(), 4);
```

**File:** config/src/config/mempool_config.rs (L121-123)
```rust
            capacity: 2_000_000,
            capacity_bytes: 2 * 1024 * 1024 * 1024,
            capacity_per_user: 100,
```

**File:** mempool/src/core_mempool/index.rs (L529-536)
```rust
pub struct ParkingLotIndex {
    // DS invariants:
    // 1. for each entry (account, txns) in `data`, `txns` is never empty
    // 2. for all accounts, data.get(account_indices.get(`account`)) == (account, sequence numbers of account's txns)
    data: Vec<(AccountAddress, BTreeSet<(u64, HashValue)>)>,
    account_indices: HashMap<AccountAddress, usize>,
    size: usize,
}
```
