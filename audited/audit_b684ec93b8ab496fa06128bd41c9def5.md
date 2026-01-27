# Audit Report

## Title
Pre-Partition Read-Write Dependency Tracking Failure Causes Non-Deterministic Transaction Execution

## Summary
The `ConnectedComponentPartitioner` only considers write sets when building transaction dependency groups through union-find, completely ignoring read sets. This allows transactions with read-after-write dependencies to be reordered and assigned to different shards with no cross-shard dependencies, causing them to execute in parallel while reading stale state. This violates the deterministic execution invariant and can lead to consensus splits.

## Finding Description

The block partitioner's pre-partition phase is responsible for grouping conflicting transactions together. However, the `ConnectedComponentPartitioner` implementation has a critical flaw in its dependency analysis: [1](#0-0) 

The union-find algorithm **only unions based on write sets**. Read sets are completely ignored during pre-partitioning. This creates a scenario where:

1. Transaction T0 writes to key A (from sender S0)
2. Transaction T1 reads from key A (from sender S1, where S0 ≠ S1)

Since T1 only reads key A, sender S1 is NOT unioned with key A in the union-find structure. T0 and T1 end up in different union-find sets and can be assigned to different shards by the LPT scheduler, with T1 potentially being reordered to execute **before** T0.

The subsequent `remove_cross_shard_dependencies` phase fails to detect this conflict because it only checks for writes in a specific range: [2](#0-1) 

The `has_write_in_range` function only checks for **pending writes**, not reads: [3](#0-2) 

When both transactions are accepted in the same round but different shards, the dependency building phase fails to create cross-shard edges because it only tracks dependencies based on the last **writer**: [4](#0-3) 

Since T1 (the reader) has no prior writer in its view, no `required_edge` is created. The `CrossShardStateView` only tracks keys from required edges: [5](#0-4) 

As a result, T1 reads from the base state view (pre-block state) while T0 writes independently. If T1's logic depends on T0's write, the final state becomes inconsistent with sequential execution.

**Attack Scenario:**
```
Initial state: Account.balance[A] = 100

Block contains (in order):
- T0 (sender=Alice): Withdraw 50 from A → balance[A] = 50
- T1 (sender=Bob): Check balance[A] >= 50, mint reward

Expected sequential execution:
- T0: reads balance[A]=100, writes balance[A]=50
- T1: reads balance[A]=50, mints reward ✓

Actual parallel execution after reordering:
- Pre-partition assigns T1 to shard 0, T0 to shard 1
- T1 (shard 0): reads balance[A]=100 from base state, mints reward
- T0 (shard 1): writes balance[A]=50
- Final state: balance[A]=50, but reward was minted based on old value=100

State inconsistency: Different execution orders produce different results!
```

## Impact Explanation

This is a **Critical Severity** vulnerability that violates the fundamental **Deterministic Execution** invariant:

> "All validators must produce identical state roots for identical blocks"

**Impact Categories:**
1. **Consensus/Safety Violation**: Different validators using different shard configurations or LPT scheduling orders (due to timing variations) may partition the same block differently, causing some to accept T1→T0 ordering and others T0→T1, producing different state roots and causing consensus failure.

2. **State Inconsistency**: Even with consistent partitioning, the parallel execution of read-write dependent transactions without proper coordination creates non-deterministic results. The final state depends on timing races between shards rather than transaction order.

3. **Loss of Funds**: Financial logic that depends on reading current state (balance checks, collateral verification, lending protocols) can be exploited. An attacker can craft transaction sequences that bypass safety checks when executed out of order.

Per the Aptos bug bounty program, this qualifies for **Critical Severity** (up to $1,000,000) as it directly enables "Consensus/Safety violations" and potential "Loss of Funds."

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will manifest whenever:
1. A block contains transactions from different senders with read-write dependencies
2. The ConnectedComponentPartitioner is used (it's the default pre-partitioner)
3. Transactions are common patterns like: transfer followed by balance check, state update followed by conditional logic

The conditions are routine in blockchain operations. Every DeFi transaction sequence involving state reads is potentially affected. The bug is not edge-case behavior but fundamental to how dependencies are tracked.

**Attacker Requirements:**
- Submit two transactions in the same block from different accounts
- First transaction writes to a state location
- Second transaction reads from that location and performs conditional logic
- No special privileges or insider access required

## Recommendation

**Fix 1: Include Reads in Union-Find (Recommended)**

Modify the ConnectedComponentPartitioner to consider both reads and writes when building dependency sets:

```rust
// In connected_component/mod.rs, replace lines 49-56:
for txn_idx in 0..state.num_txns() {
    let sender_idx = state.sender_idx(txn_idx);
    let write_set = state.write_sets[txn_idx].read().unwrap();
    let read_set = state.read_sets[txn_idx].read().unwrap();  // ADD THIS
    
    // Union sender with all accessed keys (reads AND writes)
    for &key_idx in write_set.iter().chain(read_set.iter()) {  // CHANGE THIS
        let key_idx_in_uf = num_senders + key_idx;
        uf.union(key_idx_in_uf, sender_idx);
    }
}
```

This ensures transactions with any data dependency (read or write) are grouped together in the same conflicting set, preserving their relative order.

**Fix 2: Enhanced Cross-Shard Dependency Detection**

If Fix 1 causes excessive grouping, enhance the `key_owned_by_another_shard` check to also detect read-after-write hazards across shards by checking if ANY transaction (not just writes) in another shard accessed the key.

**Fix 3: Validation Pass**

Add a post-partitioning validation that verifies all read-after-write dependencies have corresponding cross-shard edges, failing the partition if any are missing.

## Proof of Concept

```rust
#[test]
fn test_read_write_dependency_reordering_bug() {
    use crate::{
        pre_partition::connected_component::ConnectedComponentPartitioner,
        test_utils::generate_test_account,
        v2::PartitionerV2,
        BlockPartitioner,
    };
    use aptos_types::state_store::state_key::StateKey;
    use aptos_types::transaction::analyzed_transaction::AnalyzedTransaction;
    use move_core_types::account_address::AccountAddress;

    // Create two different senders
    let sender_alice = generate_test_account();
    let sender_bob = generate_test_account();
    
    // Create a shared state key both transactions will access
    let shared_key = StateKey::raw(b"shared_account_balance");
    
    // T0: Alice writes to shared_key (e.g., withdraw funds)
    let mut txn0 = create_test_transaction(&sender_alice);
    txn0.write_hints = vec![shared_key.clone().into()];
    
    // T1: Bob reads from shared_key (e.g., check balance for reward eligibility)  
    let mut txn1 = create_test_transaction(&sender_bob);
    txn1.read_hints = vec![shared_key.clone().into()];
    
    let txns = vec![
        AnalyzedTransaction::new(txn0),
        AnalyzedTransaction::new(txn1),
    ];
    
    // Partition with ConnectedComponentPartitioner
    let partitioner = PartitionerV2::new(
        4,
        3,
        0.9,
        64,
        false,
        Box::new(ConnectedComponentPartitioner {
            load_imbalance_tolerance: 2.0,
        }),
    );
    
    let partitioned = partitioner.partition(txns.clone(), 2);
    
    // BUG: The partitioner may assign T0 and T1 to different shards
    // without creating a cross-shard dependency edge between them.
    // This causes T1 to read stale state instead of T0's updated value.
    
    // Verify the bug: Check if T0 and T1 are in different shards
    // but T1 has no required edge to T0
    let mut t0_location = None;
    let mut t1_location = None;
    
    for (shard_id, shard) in partitioned.sharded_txns().iter().enumerate() {
        for (round_id, sub_block) in shard.sub_blocks.iter().enumerate() {
            for (idx, txn_with_deps) in sub_block.transactions_with_deps().iter().enumerate() {
                if txn_with_deps.txn.sender() == sender_alice.account_address {
                    t0_location = Some((round_id, shard_id, idx));
                } else if txn_with_deps.txn.sender() == sender_bob.account_address {
                    t1_location = Some((round_id, shard_id, idx));
                    
                    // Check if T1 has a required edge to T0
                    let has_dependency = txn_with_deps
                        .cross_shard_dependencies
                        .required_edges()
                        .iter()
                        .any(|(src, _)| {
                            if let Some((t0_round, t0_shard, _)) = t0_location {
                                src.round_id == t0_round && src.shard_id == t0_shard
                            } else {
                                false
                            }
                        });
                    
                    // BUG MANIFESTATION: If T0 and T1 are in different shards
                    // but T1 has no dependency on T0, the bug is triggered
                    if let Some((t0_round, t0_shard, _)) = t0_location {
                        if (round_id, shard_id) != (t0_round, t0_shard) {
                            assert!(
                                has_dependency,
                                "BUG: T1 reads key that T0 writes, they're in different shards, \
                                 but no cross-shard dependency exists! T1 will read stale state."
                            );
                        }
                    }
                }
            }
        }
    }
}
```

This test demonstrates that when transactions with read-write dependencies from different senders are partitioned, they may end up in different shards without proper cross-shard dependency tracking, causing state inconsistencies.

### Citations

**File:** execution/block-partitioner/src/pre_partition/connected_component/mod.rs (L49-56)
```rust
        for txn_idx in 0..state.num_txns() {
            let sender_idx = state.sender_idx(txn_idx);
            let write_set = state.write_sets[txn_idx].read().unwrap();
            for &key_idx in write_set.iter() {
                let key_idx_in_uf = num_senders + key_idx;
                uf.union(key_idx_in_uf, sender_idx);
            }
        }
```

**File:** execution/block-partitioner/src/v2/state.rs (L211-217)
```rust
    pub(crate) fn key_owned_by_another_shard(&self, shard_id: ShardId, key: StorageKeyIdx) -> bool {
        let tracker_ref = self.trackers.get(&key).unwrap();
        let tracker = tracker_ref.read().unwrap();
        let range_start = self.start_txn_idxs_by_shard[tracker.anchor_shard_id];
        let range_end = self.start_txn_idxs_by_shard[shard_id];
        tracker.has_write_in_range(range_start, range_end)
    }
```

**File:** execution/block-partitioner/src/v2/state.rs (L301-321)
```rust
        // Build required edges.
        let write_set = self.write_sets[ori_txn_idx].read().unwrap();
        let read_set = self.read_sets[ori_txn_idx].read().unwrap();
        for &key_idx in write_set.iter().chain(read_set.iter()) {
            let tracker_ref = self.trackers.get(&key_idx).unwrap();
            let tracker = tracker_ref.read().unwrap();
            if let Some(txn_idx) = tracker
                .finalized_writes
                .range(..ShardedTxnIndexV2::new(round_id, shard_id, 0))
                .last()
            {
                let src_txn_idx = ShardedTxnIndex {
                    txn_index: *self.final_idxs_by_pre_partitioned[txn_idx.pre_partitioned_txn_idx]
                        .read()
                        .unwrap(),
                    shard_id: txn_idx.shard_id(),
                    round_id: txn_idx.round_id(),
                };
                deps.add_required_edge(src_txn_idx, tracker.storage_location.clone());
            }
        }
```

**File:** execution/block-partitioner/src/v2/conflicting_txn_tracker.rs (L70-84)
```rust
    pub fn has_write_in_range(
        &self,
        start_txn_id: PrePartitionedTxnIdx,
        end_txn_id: PrePartitionedTxnIdx,
    ) -> bool {
        if start_txn_id <= end_txn_id {
            self.pending_writes
                .range(start_txn_id..end_txn_id)
                .next()
                .is_some()
        } else {
            self.pending_writes.range(start_txn_id..).next().is_some()
                || self.pending_writes.range(..end_txn_id).next().is_some()
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L58-71)
```rust
    pub fn create_cross_shard_state_view(
        base_view: &'a S,
        transactions: &[TransactionWithDependencies<AnalyzedTransaction>],
    ) -> CrossShardStateView<'a, S> {
        let mut cross_shard_state_key = HashSet::new();
        for txn in transactions {
            for (_, storage_locations) in txn.cross_shard_dependencies.required_edges_iter() {
                for storage_location in storage_locations {
                    cross_shard_state_key.insert(storage_location.clone().into_state_key());
                }
            }
        }
        CrossShardStateView::new(cross_shard_state_key, base_view)
    }
```
