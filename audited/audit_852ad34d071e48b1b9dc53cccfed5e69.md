# Audit Report

## Title
Mempool State Inconsistency: Transactions Can Exist in Both Priority Index and Parking Lot Simultaneously

## Summary
A state inconsistency vulnerability exists in the mempool's `process_ready_seq_num_based_transactions()` function where transactions with `timeline_state = NonQualified` can be present in both `priority_index` and `parking_lot_index` simultaneously, violating mempool invariants.

## Finding Description

The vulnerability occurs when transactions with `timeline_state = NonQualified` are processed in `process_ready_seq_num_based_transactions()`. These transactions are created when validators receive transactions from peer validators with broadcasting disabled. [1](#0-0) 

When such transactions are processed through `process_ready_transaction()`, they are added to `priority_index` but NOT to `timeline_index` because the condition only checks for `TimelineState::NotReady`: [2](#0-1) 

Critically, since these transactions are never inserted into `timeline_index`, their `timeline_state` never changes to `Ready` (which would normally happen during timeline insertion): [3](#0-2) 

**The Bug:** When sequence number gaps occur and `process_ready_seq_num_based_transactions()` is called again, the for loop at lines 615-622 checks if transactions have `timeline_state` that is NOT `Ready`, and adds them to `parking_lot_index` - but crucially does NOT remove them from `priority_index`: [4](#0-3) 

This is inconsistent with the correct pattern used in the GC function, which explicitly removes transactions from `priority_index` before parking them: [5](#0-4) 

**Attack Scenario:**
1. Transactions 5, 6, 7 exist with `timeline_state = NonQualified` (from peer validators)
2. First call processes all three, adding them to `priority_index` (timeline_state stays `NonQualified`)
3. Transaction 6 is removed (gas upgrade or rejection)
4. Second call processes txn 5, hits gap at 6, stops with `min_seq = 6`
5. For loop processes txn 7 (seq_num > 6), finds `timeline_state = NonQualified` (!= Ready)
6. **BUG**: Txn 7 is inserted into `parking_lot_index` WITHOUT removal from `priority_index`

The transaction now violates the mempool invariant of being in one index OR the other, never both.

## Impact Explanation

**Severity: Medium**

This violates mempool invariants and causes state inconsistency. Per Aptos bug bounty categories, this qualifies as **Medium Severity** - a "Limited Protocol Violation" with "State inconsistencies requiring manual intervention."

The impacts include:

1. **Incorrect Eviction**: When mempool is full, the transaction can be evicted from parking lot (removing it from all indices including priority_index) despite being semantically "ready" for consensus

2. **State Inconsistency**: The transaction exists in two mutually exclusive states - both "ready" (in priority_index) and "not ready" (in parking_lot_index)

3. **Index Integrity Violation**: Breaks the fundamental assumption that ready and parked transactions are disjoint sets

This does NOT qualify as High Severity because it does not cause:
- Validator node slowdowns or performance degradation
- API crashes or service disruption
- Consensus safety violations
- Fund loss or theft

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability can be triggered through normal validator operations:

1. **NonQualified Transactions Exist**: Created when validators receive transactions from peer validators with broadcasting disabled [6](#0-5) 

2. **Sequence Gaps Occur**: Through normal operations like gas upgrades or transaction rejections

3. **Function Called Multiple Times**: `process_ready_seq_num_based_transactions()` is called on every transaction insertion and commit [7](#0-6) 

These conditions occur naturally in production, making this a realistic scenario.

## Recommendation

Add explicit removal from `priority_index` before inserting into `parking_lot_index` in lines 615-622, matching the pattern used in the GC function:

```rust
for (_, txn) in txns.seq_num_range_mut((Bound::Excluded(min_seq), Bound::Unbounded)) {
    match txn.timeline_state {
        TimelineState::Ready(_) => {},
        _ => {
            self.priority_index.remove(txn); // ADD THIS LINE
            self.parking_lot_index.insert(txn);
            parking_lot_txns += 1;
        },
    }
}
```

## Proof of Concept

A Rust test demonstrating the vulnerability would create transactions with `NonQualified` timeline state, process them through `process_ready_seq_num_based_transactions()`, remove a middle transaction, then call the function again to observe the dual-index presence. The test would verify that a transaction exists in both `priority_index.contains()` and `parking_lot_index` simultaneously, violating mempool invariants.

## Notes

While the technical vulnerability is valid and the scenario is realistic, the severity assessment has been corrected from High to Medium to align with Aptos bug bounty categories. The issue represents a protocol violation with state inconsistency but does not directly impact consensus safety, validator performance, or network liveness.

### Citations

**File:** mempool/src/shared_mempool/coordinator.rs (L312-318)
```rust
    let ineligible_for_broadcast = (smp.network_interface.is_validator()
        && !smp.broadcast_within_validator_network())
        || smp.network_interface.is_upstream_peer(&peer, None);
    let timeline_state = if ineligible_for_broadcast {
        TimelineState::NonQualified
    } else {
        TimelineState::NotReady
```

**File:** mempool/src/core_mempool/transaction_store.rs (L361-361)
```rust
                self.process_ready_seq_num_based_transactions(&address, account_sequence_number.expect("Account sequence number is always provided for transactions with sequence number"));
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

**File:** mempool/src/core_mempool/transaction_store.rs (L959-960)
```rust
                        self.parking_lot_index.insert(t);
                        self.priority_index.remove(t);
```

**File:** mempool/src/core_mempool/index.rs (L371-378)
```rust
    pub(crate) fn insert(&mut self, txn: &mut MempoolTransaction) {
        self.timeline.insert(
            self.next_timeline_id,
            (txn.get_sender(), txn.get_replay_protector(), Instant::now()),
        );
        txn.timeline_state = TimelineState::Ready(self.next_timeline_id);
        self.next_timeline_id += 1;
    }
```
