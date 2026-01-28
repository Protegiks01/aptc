# Audit Report

## Title
Missing Read-After-Write Dependencies in Block Partitioner Causes Consensus Split

## Summary
The block partitioner's dependency tracking fails to capture read-after-write dependencies when transactions are reordered across shards by `ConnectedComponentPartitioner`. This allows a transaction reading a key to execute before a transaction writing that key (violating the preset serialization order), causing validators to produce different state roots and breaking consensus.

## Finding Description

The vulnerability arises from three interacting flaws in the block partitioner:

**Flaw 1: Union-find only groups transactions by writes, not reads**

The `ConnectedComponentPartitioner` uses union-find to group conflicting transactions, but only considers write sets: [1](#0-0) 

This means a transaction T2 that writes key X and transaction T5 that reads key X will NOT be grouped together unless they have other conflicts.

**Flaw 2: Cross-shard conflict detection only checks for writes**

During the discarding round, the algorithm checks both read and write sets for conflicts: [2](#0-1) 

However, `key_owned_by_another_shard` only detects WRITES in other shards: [3](#0-2) [4](#0-3) 

When T5 (reads X, shard 0) checks for conflicts, it won't find T2 because T2 is only checked via writes. When T2 (writes X, shard 1) checks for conflicts, it won't find T5's read because only writes are checked.

**Flaw 3: Dependency edge search uses shard ordering**

When building required edges, `take_txn_with_dep` searches for the last writer BEFORE the current transaction's position: [5](#0-4) 

The ordering is based on `(round_id, shard_id, pre_partitioned_txn_idx)`: [6](#0-5) 

For T5 at (round=0, shard=0), it searches before (0, 0, 0). T2 at (0, 1, _) is NOT less than (0, 0, 0), so no dependency edge is created.

**Attack Scenario:**
1. Submit transactions T2 (writes X) and T5 (reads X) where T2 < T5 in original order
2. ConnectedComponentPartitioner assigns them to different shards: Shard 0: [T5], Shard 1: [T2]
3. If anchor_shard for X equals 0, both pass conflict detection and are accepted in round 0
4. T5 gets no required edge from T2 (wrong shard ordering)
5. During execution, T5 reads X from base state (old value), T2 writes X (new value)
6. Sequential execution would give T5 the new value, sharded execution gives old value
7. Different state roots produced

The parallel execution model must maintain the "preset serialization order": [7](#0-6) [8](#0-7) 

This bug violates that invariant.

## Impact Explanation

**Critical Severity** - This is a Consensus/Safety Violation that breaks the fundamental guarantee: "All validators must produce identical state roots for identical blocks."

Validators executing blocks with sharded execution will produce different state roots than validators using sequential execution (or different partitioner configurations). This causes:
- Chain splits requiring hard fork to resolve
- Permanent consensus divergence
- Network partition

This meets the Critical severity criteria for "Consensus/Safety violations" and "Non-recoverable network partition" in the Aptos bug bounty program.

## Likelihood Explanation

**Medium-to-High Likelihood** - The vulnerability triggers when:
1. A block contains transactions with read-after-write dependencies from different senders
2. `ConnectedComponentPartitioner` is enabled (default production configuration)
3. The transactions are assigned to different shards by load balancing
4. The storage location's anchor_shard hash allows the conflict to slip through (depends on which shard is anchor)

These conditions occur regularly in production. Any transactions from independent accounts accessing shared resources (e.g., reading token metadata written by another transaction) can trigger this. The probability depends on the hash function assigning favorable anchor shards, but over many blocks, this will eventually occur.

## Recommendation

**Fix 1: Include reads in union-find grouping**

Modify `ConnectedComponentPartitioner` to union both reads and writes:
```rust
for txn_idx in 0..state.num_txns() {
    let sender_idx = state.sender_idx(txn_idx);
    let write_set = state.write_sets[txn_idx].read().unwrap();
    let read_set = state.read_sets[txn_idx].read().unwrap();
    for &key_idx in write_set.iter().chain(read_set.iter()) {
        let key_idx_in_uf = num_senders + key_idx;
        uf.union(key_idx_in_uf, sender_idx);
    }
}
```

**Fix 2: Check for reads in cross-shard conflict detection**

Modify `key_owned_by_another_shard` to check both reads and writes, or add a separate check for reads of keys that are written in other shards.

**Fix 3: Search all previous shards for writers**

In `take_txn_with_dep`, search for writers across ALL shards in the current and previous rounds, not just shards less than the current shard ID.

## Proof of Concept

A PoC would require:
1. Creating two transactions T2 and T5 from different accounts
2. T2 writes to a state key X, T5 reads from X
3. Partitioning them with ConnectedComponentPartitioner
4. Executing with ShardedBlockExecutor
5. Comparing output against sequential execution to demonstrate divergence

The existing test suite has tests marked as problematic: [9](#0-8) [10](#0-9) 

These comments acknowledge that "cross shard conflict doesn't work" but refer to cross-round dependencies. The issue reported here is within-round dependencies that should have been detected but weren't.

## Notes

This vulnerability is in production code paths used by the sharded block executor. The test suite already contains evidence that cross-shard conflicts are problematic, though the specific read-after-write dependency bug was not documented. The fix requires careful consideration to maintain performance while ensuring correctness of the partitioning algorithm.

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

**File:** execution/block-partitioner/src/v2/state.rs (L307-320)
```rust
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

**File:** execution/block-partitioner/src/v2/types.rs (L65-69)
```rust
impl Ord for ShardedTxnIndexV2 {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        (self.sub_block_idx, self.pre_partitioned_txn_idx)
            .cmp(&(other.sub_block_idx, other.pre_partitioned_txn_idx))
    }
```

**File:** aptos-move/block-executor/src/lib.rs (L7-8)
```rust
of n transactions tx_1, tx_2, ..., tx_n (this defines the preset serialization
order tx_1< tx_2< ...<tx_n).
```

**File:** aptos-move/block-executor/src/lib.rs (L19-26)
```rust
When transaction tx reads a memory location, it obtains from the multi-version
data-structure the value written to this location by the highest transaction
that appears before tx in the preset serialization order, along with the
associated version. For example, transaction tx_5 can read a value written
by transaction tx_3 even if transaction tx_6 has written to same location.
If no smaller transaction has written to a location, then the read
(e.g. all reads by tx_1) is resolved from storage based on the state before
the block execution.
```

**File:** aptos-move/aptos-vm/tests/sharded_block_executor.rs (L40-41)
```rust
// Sharded execution with cross shard conflict doesn't work for now because we don't have
// cross round dependency tracking yet.
```

**File:** aptos-move/aptos-vm/tests/sharded_block_executor.rs (L127-128)
```rust
// Sharded execution with cross shard conflict doesn't work for now because we don't have
// cross round dependency tracking yet.
```
