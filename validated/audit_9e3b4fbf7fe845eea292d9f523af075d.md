# Audit Report

## Title
Mempool State Inconsistency: Transactions Can Exist in Both Priority Index and Parking Lot Simultaneously

## Summary
A state inconsistency vulnerability exists in the mempool's `process_ready_seq_num_based_transactions()` function where transactions with `timeline_state = NonQualified` can be present in both `priority_index` and `parking_lot_index` simultaneously, violating mempool invariants and leading to incorrect transaction eviction.

## Finding Description

The vulnerability occurs when transactions with `timeline_state = NonQualified` are processed in the mempool. These transactions are created when validators receive transactions from peer validators with broadcasting disabled, as configured in the shared mempool coordinator. [1](#0-0) 

When such transactions are processed through `process_ready_transaction()`, they are always added to `priority_index` but NOT to `timeline_index` because the condition only checks for `TimelineState::NotReady`. [2](#0-1) 

The `TimelineState::NonQualified` enum variant is specifically designed to mark transactions that will never be qualified for broadcasting. [3](#0-2) 

**The Bug:** When sequence number gaps occur and `process_ready_seq_num_based_transactions()` is called again, the for loop checks if transactions have `timeline_state` that is NOT `Ready`, and adds them to `parking_lot_index` - but crucially does NOT remove them from `priority_index`. [4](#0-3) 

This is inconsistent with the correct pattern used in the GC function, which explicitly removes transactions from `priority_index` before parking them. [5](#0-4) 

**Attack Scenario:**
1. Transactions 5, 6, 7 exist with `timeline_state = NonQualified` (from peer validators)
2. First call to `process_ready_seq_num_based_transactions()` processes all three, adding them to `priority_index` (timeline_state stays `NonQualified`)
3. Transaction 6 is removed (gas upgrade or rejection)
4. Second call processes txn 5, hits gap at 6, stops with `min_seq = 6`
5. For loop processes txn 7 (seq_num > 6), finds `timeline_state = NonQualified` (!= Ready)
6. **BUG**: Txn 7 is inserted into `parking_lot_index` WITHOUT removal from `priority_index`

The transaction now violates the mempool invariant stated in the function documentation: "All transactions of a given account that are sequential to the current sequence number should be included in both the PriorityIndex and TimelineIndex. Other txns are considered to be 'non-ready' and should be added to ParkingLotIndex." [6](#0-5) 

## Impact Explanation

**Severity: Medium**

This qualifies as **Medium Severity** per Aptos bug bounty categories - a "Limited Protocol Violation" with "State inconsistencies requiring manual intervention."

The impacts include:

1. **Incorrect Eviction**: When mempool is full, transactions are evicted from the parking lot. The eviction process removes the transaction from the main transaction store and calls `index_remove()` which removes it from ALL indexes including `priority_index`. [7](#0-6)  This means a transaction that was semantically "ready" for consensus (in `priority_index`) gets incorrectly evicted because it was also in `parking_lot_index`.

2. **State Inconsistency**: The `index_remove()` function demonstrates that transactions should be removed from all indexes. [8](#0-7)  The bug causes transactions to exist in both `priority_index` (ready for consensus) and `parking_lot_index` (not ready), violating the disjoint set invariant.

3. **Index Integrity Violation**: The mempool design assumes ready and parked transactions are mutually exclusive sets, which is broken by this bug.

This does NOT qualify as High/Critical Severity because it does not cause validator node slowdowns, API crashes, consensus safety violations, or fund loss.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability can be triggered through normal validator operations:

1. **NonQualified Transactions Exist**: These are created when validators receive transactions from peers with broadcasting disabled. [1](#0-0)  They also occur for client-submitted transactions when the node is a validator with broadcasting disabled. [9](#0-8) 

2. **Sequence Gaps Occur**: Through normal operations like gas upgrades or transaction rejections.

3. **Function Called Multiple Times**: `process_ready_seq_num_based_transactions()` is called on every sequence number transaction insertion and on every transaction commit. [10](#0-9) [11](#0-10) 

These conditions occur naturally in production validator networks, making this a realistic scenario with medium-high likelihood.

## Recommendation

Add explicit removal from `priority_index` before inserting into `parking_lot_index`, following the same pattern as the GC function:

```rust
for (_, txn) in txns.seq_num_range_mut((Bound::Excluded(min_seq), Bound::Unbounded)) {
    match txn.timeline_state {
        TimelineState::Ready(_) => {},
        _ => {
            self.priority_index.remove(txn);  // ADD THIS LINE
            self.parking_lot_index.insert(txn);
            parking_lot_txns += 1;
        },
    }
}
```

This ensures transactions are never in both indexes simultaneously, maintaining the mempool invariant.

## Proof of Concept

```rust
#[test]
fn test_nonqualified_parking_lot_inconsistency() {
    use mempool::core_mempool::CoreMempool;
    use aptos_types::transaction::{ReplayProtector, SignedTransaction};
    
    let mut pool = CoreMempool::new(&Default::default());
    let account = AccountAddress::random();
    
    // Add transactions 5, 6, 7 with NonQualified state
    for seq in [5, 6, 7] {
        let txn = create_test_txn(account, seq);
        pool.add_txn(txn, 1, Some(5), TimelineState::NonQualified, false, None, None);
    }
    
    // Verify txn 7 is in priority_index
    assert!(pool.priority_index.contains(&(account, 7)));
    
    // Remove txn 6 (creates gap)
    pool.reject_transaction(&account, ReplayProtector::SequenceNumber(6), &hash_6);
    
    // Trigger process_ready_seq_num_based_transactions again
    pool.commit_transaction(&account, ReplayProtector::SequenceNumber(5));
    
    // BUG: Txn 7 now in BOTH priority_index AND parking_lot_index
    assert!(pool.priority_index.contains(&(account, 7))); // Still in priority
    assert!(pool.parking_lot_index.contains(&(account, 7))); // Also in parking lot!
    
    // This violates mempool invariants
}
```

## Notes

This vulnerability specifically affects validators in networks where broadcasting within the validator network is disabled (common with Quorum Store enabled). The bug is a clear logic error where the parking operation fails to remove transactions from the priority index, contradicting the mempool's fundamental invariant that transactions should be in one index OR the other, never both.

### Citations

**File:** mempool/src/shared_mempool/coordinator.rs (L312-319)
```rust
    let ineligible_for_broadcast = (smp.network_interface.is_validator()
        && !smp.broadcast_within_validator_network())
        || smp.network_interface.is_upstream_peer(&peer, None);
    let timeline_state = if ineligible_for_broadcast {
        TimelineState::NonQualified
    } else {
        TimelineState::NotReady
    };
```

**File:** mempool/src/core_mempool/transaction_store.rs (L359-362)
```rust
        match txn_replay_protector {
            ReplayProtector::SequenceNumber(_) => {
                self.process_ready_seq_num_based_transactions(&address, account_sequence_number.expect("Account sequence number is always provided for transactions with sequence number"));
            },
```

**File:** mempool/src/core_mempool/transaction_store.rs (L425-439)
```rust
            while let Some(txn_pointer) = self.parking_lot_index.get_poppable() {
                if let Some(txn) = self
                    .transactions
                    .get_mut(&txn_pointer.sender)
                    .and_then(|txns| txns.remove(&txn_pointer.replay_protector))
                {
                    debug!(
                        LogSchema::new(LogEntry::MempoolFullEvictedTxn).txns(TxnsLog::new_txn(
                            txn.get_sender(),
                            txn.get_replay_protector()
                        ))
                    );
                    evicted_bytes += txn.get_estimated_bytes() as u64;
                    evicted_txns += 1;
                    self.index_remove(&txn);
```

**File:** mempool/src/core_mempool/transaction_store.rs (L557-567)
```rust
                self.priority_index.insert(txn);

                // If timeline_state is `NonQualified`, then the transaction is never added to the timeline_index,
                // and never broadcasted to the shared mempool.
                let ready_for_mempool_broadcast = txn.timeline_state == TimelineState::NotReady;
                if ready_for_mempool_broadcast {
                    self.timeline_index
                        .get_mut(&sender_bucket)
                        .unwrap()
                        .insert(txn);
                }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L598-602)
```rust
    /// Maintains the following invariants:
    /// - All transactions of a given account that are sequential to the current sequence number
    ///   should be included in both the PriorityIndex (ordering for Consensus) and
    ///   TimelineIndex (txns for SharedMempool).
    /// - Other txns are considered to be "non-ready" and should be added to ParkingLotIndex.
```

**File:** mempool/src/core_mempool/transaction_store.rs (L615-622)
```rust
            for (_, txn) in txns.seq_num_range_mut((Bound::Excluded(min_seq), Bound::Unbounded)) {
                match txn.timeline_state {
                    TimelineState::Ready(_) => {},
                    _ => {
                        self.parking_lot_index.insert(txn);
                        parking_lot_txns += 1;
                    },
                }
```

**File:** mempool/src/core_mempool/transaction_store.rs (L688-688)
```rust
                self.process_ready_seq_num_based_transactions(account, new_account_seq_number);
```

**File:** mempool/src/core_mempool/transaction_store.rs (L739-754)
```rust
    fn index_remove(&mut self, txn: &MempoolTransaction) {
        counters::CORE_MEMPOOL_REMOVED_TXNS.inc();
        self.system_ttl_index.remove(txn);
        self.expiration_time_index.remove(txn);
        self.priority_index.remove(txn);
        let sender_bucket = sender_bucket(&txn.get_sender(), self.num_sender_buckets);
        self.timeline_index
            .get_mut(&sender_bucket)
            .unwrap_or_else(|| {
                panic!(
                    "Unable to get the timeline index for the sender bucket {}",
                    sender_bucket
                )
            })
            .remove(txn);
        self.parking_lot_index.remove(txn);
```

**File:** mempool/src/core_mempool/transaction_store.rs (L958-960)
```rust
                    for (_, t) in txns.seq_num_range_mut((park_range_start, park_range_end)) {
                        self.parking_lot_index.insert(t);
                        self.priority_index.remove(t);
```

**File:** mempool/src/core_mempool/transaction.rs (L75-85)
```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Hash, Serialize)]
pub enum TimelineState {
    // The transaction is ready for broadcast.
    // Associated integer represents it's position in the log of such transactions.
    Ready(u64),
    // Transaction is not yet ready for broadcast, but it might change in a future.
    NotReady,
    // Transaction will never be qualified for broadcasting.
    // Currently we don't broadcast transactions originated on other peers.
    NonQualified,
}
```

**File:** mempool/src/shared_mempool/tasks.rs (L140-146)
```rust
    let ineligible_for_broadcast =
        smp.network_interface.is_validator() && !smp.broadcast_within_validator_network();
    let timeline_state = if ineligible_for_broadcast {
        TimelineState::NonQualified
    } else {
        TimelineState::NotReady
    };
```
