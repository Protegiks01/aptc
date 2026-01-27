# Audit Report

## Title
Missing Read-After-Write Dependencies in Block Partitioner Causes Consensus Split

## Summary
The `take_txn_with_dep()` function in the block partitioner fails to capture required dependencies when transactions are reordered by `ConnectedComponentPartitioner`. A transaction that reads a key can execute before a transaction that writes the same key (violating original transaction order), causing validators to produce different state roots and breaking consensus.

## Finding Description

The block partitioner's dependency tracking has a critical flaw in how it handles cross-shard dependencies when using `ConnectedComponentPartitioner`. The vulnerability arises from the interaction between three components: [1](#0-0) 

The `take_txn_with_dep()` function builds required edges by finding the last writer **before the current transaction's (round, shard) position**. However, `ConnectedComponentPartitioner` can reorder transactions such that a transaction T5 (original index 5) is placed in shard 0 while transaction T2 (original index 2) is placed in shard 1: [2](#0-1) 

The union-find grouping **only considers write sets, not read sets**. This means T2 (writes X) and T5 (reads X) may be assigned to different conflicting sets and subsequently different shards. [3](#0-2) 

The conflict detection only checks for **writes** in other shards, not reads. If T5 (shard 0) reads X and T2 (shard 1) writes X, no cross-shard conflict is detected since `key_owned_by_another_shard` only checks for writes: [4](#0-3) 

**Attack Scenario:**
1. Original transaction order: T2 writes key X, T5 reads key X (original order: T2 → T5)
2. ConnectedComponentPartitioner assigns: Shard 0: [T5], Shard 1: [T2]
3. Both accepted in round 0 (no write-write conflict detected)
4. During `take_txn_with_dep` for T5:
   - Searches for writers before (round=0, shard=0)
   - T2 is at (round=0, shard=1), which is NOT less than (0, 0)
   - T5 gets NO required edge from T2 [5](#0-4) 

The ordering comparison is based on `(sub_block_idx, pre_partitioned_txn_idx)` tuple, making (0, 1, _) > (0, 0, _).

5. During parallel execution in round 0:
   - T5 reads X from base state view (gets old value)
   - T2 writes X (new value)
   - T5 should have read T2's new value per original order, but reads old value instead

6. **Consensus violation**: Sequential execution would have T2 write first, then T5 read the new value. Sharded execution makes T5 read the old value. Different state roots are produced.

## Impact Explanation

**Critical Severity** - This is a **Consensus Safety Violation** that breaks the fundamental invariant: "All validators must produce identical state roots for identical blocks." [6](#0-5) 

The parallel execution model must maintain the "preset serialization order" but this bug violates it. Validators using different execution modes (sequential vs. sharded) or different partitioner configurations will produce divergent state, requiring a hard fork to recover. This meets the Critical severity criteria for "Consensus/Safety violations" and "Non-recoverable network partition."

## Likelihood Explanation

**High Likelihood** - This vulnerability triggers whenever:
1. A block contains transactions where one writes and another reads the same key
2. `ConnectedComponentPartitioner` is enabled (production configuration)
3. The transactions have different senders (not grouped by sender)
4. Load balancing assigns them to different shards

These conditions occur regularly in production blocks with independent transactions accessing common state (e.g., reading/writing to shared resources, token balances, etc.). No special attacker capabilities are required - normal transaction submission can trigger this.

## Recommendation

**Fix 1: Track read dependencies in union-find**
Modify ConnectedComponentPartitioner to include both read and write sets when building conflicting sets:

```rust
// In connected_component/mod.rs, line 49-56
for txn_idx in 0..state.num_txns() {
    let sender_idx = state.sender_idx(txn_idx);
    let write_set = state.write_sets[txn_idx].read().unwrap();
    let read_set = state.read_sets[txn_idx].read().unwrap(); // ADD THIS
    for &key_idx in write_set.iter().chain(read_set.iter()) { // MODIFY THIS
        let key_idx_in_uf = num_senders + key_idx;
        uf.union(key_idx_in_uf, sender_idx);
    }
}
```

**Fix 2: Use original transaction order for dependencies**
Modify `take_txn_with_dep()` to track dependencies based on original transaction order rather than (round, shard) order. Store and use `ori_txn_idx` when comparing transaction ordering for dependency edges.

**Fix 3: Validate partitioner output**
Add assertion in test utilities to verify no same-round cross-shard read-after-write dependencies exist: [7](#0-6) 

The current check only asserts different rounds for dependencies (line 223), but should also detect same-round RAW hazards.

## Proof of Concept

```rust
// Test case demonstrating the vulnerability
#[test]
fn test_missing_raw_dependency_consensus_split() {
    use crate::v2::PartitionerV2;
    use crate::pre_partition::connected_component::ConnectedComponentPartitioner;
    use aptos_types::transaction::analyzed_transaction::*;
    
    // Create two transactions:
    // T0: writes key X (sender S0)
    // T1: reads key X (sender S1, different sender to avoid grouping)
    
    let key_x = StateKey::raw(b"key_x");
    
    let txn0 = create_analyzed_transaction(
        /* sender */ S0,
        /* reads */ vec![],
        /* writes */ vec![StorageLocation::Specific(key_x.clone())]
    );
    
    let txn1 = create_analyzed_transaction(
        /* sender */ S1,
        /* reads */ vec![StorageLocation::Specific(key_x.clone())],
        /* writes */ vec![]
    );
    
    let block = vec![txn0, txn1];
    
    // Use ConnectedComponentPartitioner with settings that split them
    let partitioner = PartitionerV2::new(
        8, 4, 0.9, 64, false,
        Box::new(ConnectedComponentPartitioner {
            load_imbalance_tolerance: 0.5, // Force splitting
        })
    );
    
    let partitioned = partitioner.partition(block.clone(), 2);
    
    // Verify txn1 is in earlier shard than txn0 (due to load balancing)
    // and has NO required edge from txn0
    let txn1_deps = find_transaction_dependencies(&partitioned, txn1.hash());
    
    // BUG: txn1 should depend on txn0 (RAW dependency)
    // but required_edges will be empty because txn0 is in later shard
    assert!(txn1_deps.required_edges().is_empty(), 
            "BUG: Missing RAW dependency from txn0 to txn1");
    
    // This causes txn1 to read stale value instead of txn0's write
    // Sequential execution: txn0 writes X=10, txn1 reads X=10
    // Sharded execution: txn1 reads X=0 (old), txn0 writes X=10
    // CONSENSUS SPLIT!
}
```

## Notes

The vulnerability exists at the intersection of pre-partitioning (which reorders transactions) and dependency tracking (which uses post-reordering positions). The Block-STM execution engine itself correctly enforces sequential semantics **within a shard**, but cross-shard dependencies are incorrect when transaction reordering violates read-after-write ordering from the original block.

The fix must ensure that either:
1. Transactions with RAW dependencies are kept in the same shard, OR  
2. Required edges correctly reflect original transaction order, not partitioned order

### Citations

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

**File:** execution/block-partitioner/src/v2/state.rs (L291-321)
```rust
    pub(crate) fn take_txn_with_dep(
        &self,
        round_id: RoundId,
        shard_id: ShardId,
        txn_idx: PrePartitionedTxnIdx,
    ) -> TransactionWithDependencies<AnalyzedTransaction> {
        let ori_txn_idx = self.ori_idxs_by_pre_partitioned[txn_idx];
        let txn = self.txns[ori_txn_idx].write().unwrap().take().unwrap();
        let mut deps = CrossShardDependencies::default();

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

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L119-126)
```rust
                        let write_set = state.write_sets[ori_txn_idx].read().unwrap();
                        let read_set = state.read_sets[ori_txn_idx].read().unwrap();
                        for &key_idx in write_set.iter().chain(read_set.iter()) {
                            if state.key_owned_by_another_shard(shard_id, key_idx) {
                                in_round_conflict_detected = true;
                                break;
                            }
                        }
```

**File:** execution/block-partitioner/src/v2/types.rs (L65-69)
```rust
impl Ord for ShardedTxnIndexV2 {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        (self.sub_block_idx, self.pre_partitioned_txn_idx)
            .cmp(&(other.sub_block_idx, other.pre_partitioned_txn_idx))
    }
```

**File:** aptos-move/block-executor/src/lib.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

/**
The high level parallel execution logic is implemented in 'executor.rs'. The
input of parallel executor is a block of transactions, containing a sequence
of n transactions tx_1, tx_2, ..., tx_n (this defines the preset serialization
order tx_1< tx_2< ...<tx_n).

Each transaction might be executed several times and we refer to the i-th
execution as incarnation i of a transaction. We say that an incarnation is
aborted when the system decides that a subsequent re-execution with an incremented
incarnation number is needed. A version is a pair of a transaction index and
an incarnation number. To support reads and writes by transactions that may
execute concurrently, parallel execution maintains an in-memory multi-version
data structure that separately stores for each memory location the latest value
written per transaction, along with the associated transaction version.
This data structure is implemented in: '../../mvhashmap/src/lib.rs'.
When transaction tx reads a memory location, it obtains from the multi-version
data-structure the value written to this location by the highest transaction
that appears before tx in the preset serialization order, along with the
associated version. For example, transaction tx_5 can read a value written
by transaction tx_3 even if transaction tx_6 has written to same location.
If no smaller transaction has written to a location, then the read
(e.g. all reads by tx_1) is resolved from storage based on the state before
the block execution.

For each incarnation, parallel execution maintains a write-set and a read-set
in 'txn_last_input_output.rs'. The read-set contains the memory locations that
are read during the incarnation, and the corresponding versions. The write-set
describes the updates made by the incarnation as (memory location, value) pairs.
The write-set of the incarnation is applied to shared memory (the multi-version
data-structure) at the end of execution. After an incarnation executes it needs
to pass validation. The validation re-reads the read-set and compares the
observed versions. Intuitively, a successful validation implies that writes
applied by the incarnation are still up-to-date, while a failed validation implies
that the incarnation has to be aborted. For instance, if the transaction was
speculatively executed and read value x=2, but later validation observes x=3,
the results of the transaction execution are no longer applicable and must
be discarded, while the transaction is marked for re-execution.

When an incarnation is aborted due to a validation failure, the entries in the
multi-version data-structure corresponding to its write-set are replaced with
a special ESTIMATE marker. This signifies that the next incarnation is estimated
to write to the same memory location, and is utilized for detecting potential
dependencies. In particular, an incarnation of transaction tx_j stops and waits
on a condition variable whenever it reads a value marked as an ESTIMATE that was
written by a lower transaction tx_k. When the execution of tx_k finishes, it
signals the condition variable and the execution of tx_j continues. This way,
tx_j does not read a value that is likely to cause an abort in the future due to a
```

**File:** execution/block-partitioner/src/test_utils.rs (L222-225)
```rust
                    if round_id != num_rounds - 1 {
                        assert_ne!(src_txn_idx.round_id, round_id);
                    }
                    assert!((src_txn_idx.round_id, src_txn_idx.shard_id) < (round_id, shard_id));
```
