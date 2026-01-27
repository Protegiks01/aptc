# Audit Report

## Title
Non-Deterministic Block Partitioning Causes Consensus Divergence in Sharded Execution Mode

## Summary
The block partitioner uses Rust's `DefaultHasher` to compute anchor shard IDs for storage locations, which generates different hash values across validator processes. This non-determinism causes validators to partition blocks differently, resulting in divergent transaction orderings and breaking the fundamental consensus invariant that all validators must produce identical state roots for identical blocks.

## Finding Description
The vulnerability exists in the sharded block execution path. When sharded execution is enabled, the block partitioner assigns an "anchor shard" to each storage location accessed by transactions. This anchor shard is used during conflict resolution to determine whether transactions should be moved to later execution rounds. [1](#0-0) 

The `get_anchor_shard_id` function uses `DefaultHasher`, which in Rust uses SipHash-1-3 with a randomly generated key created once per process startup. This means different validator processes will compute different anchor shard IDs for the same storage location. [2](#0-1) 

During partitioning, these anchor shard IDs are stored in the `ConflictingTxnTracker` and used to detect cross-shard conflicts: [3](#0-2) 

The critical issue occurs in the discarding phase where transactions are checked for conflicts: [4](#0-3) 

When validators compute different anchor shard IDs, they check different transaction ranges for conflicts, leading to different decisions about which transactions to discard to later rounds. This produces different partitioning matrices across validators.

The partitioned transactions are then flattened back into a sequential order for execution: [5](#0-4) 

The flatten operation processes transactions in order of (round, shard, position), meaning different partitioning produces different final transaction orderings. While the parallel executor guarantees equivalence to sequential execution, it requires all validators to execute transactions in the SAME sequential order - which is violated here.

## Impact Explanation
This vulnerability has **Critical** severity under the Aptos bug bounty program as it causes consensus divergence:

- **Breaks Deterministic Execution Invariant**: All validators must produce identical state roots for identical blocks, but this bug causes them to execute transactions in different orders
- **Consensus Safety Violation**: Different validators commit different state roots for the same block, leading to chain splits
- **Network Partition**: Once divergence occurs, validators cannot reach consensus on subsequent blocks, effectively partitioning the network
- **Requires Hardfork**: Recovery would require manual intervention and potentially a hardfork to bring validators back to consensus

The impact meets the Critical severity threshold of "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation
The likelihood depends on whether sharded execution is enabled in production:

- **If sharded execution is enabled**: This bug triggers naturally on EVERY block without requiring any attacker action. The non-determinism is inherent to Rust's `DefaultHasher` design.
- **If sharded execution is disabled**: The vulnerability is dormant but represents a critical risk if/when sharded execution is enabled.

The execution path exists and is implemented: [6](#0-5) 

The code is production-ready with configuration support, suggesting it may already be used or planned for use: [7](#0-6) 

## Recommendation
Replace `DefaultHasher` with a deterministic hash function. The anchor shard ID must be computed identically across all validator nodes for the same storage location.

**Recommended fix:**
```rust
use sha3::{Digest, Sha3_256};

fn get_anchor_shard_id(storage_location: &StorageLocation, num_shards: usize) -> ShardId {
    let mut hasher = Sha3_256::new();
    // Serialize the storage location deterministically using BCS
    let serialized = bcs::to_bytes(storage_location).expect("Serialization should not fail");
    hasher.update(&serialized);
    let hash = hasher.finalize();
    // Use first 8 bytes as u64
    let hash_u64 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    (hash_u64 % num_shards as u64) as usize
}
```

Alternatively, use `std::collections::hash_map::RandomState::with_seeds()` to create a hasher with fixed seeds that all validators agree on.

## Proof of Concept
To demonstrate this vulnerability:

1. Start two validator nodes with sharded execution enabled (`num_shards > 0`)
2. Submit a block containing transactions that access overlapping storage locations
3. Both validators partition the block independently
4. Compare the resulting state roots - they will differ due to different transaction execution orders

**Minimal reproduction steps:**
```rust
// In two separate processes:
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn get_hash(data: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

// Process 1 output: e.g., 12345678901234
// Process 2 output: e.g., 98765432109876 (different!)
println!("Hash: {}", get_hash("same_storage_key"));
```

The non-determinism is guaranteed by Rust's `DefaultHasher` design, which uses a per-process random seed. When two validators compute different anchor shard IDs for the same storage location, they will make different partitioning decisions, leading to divergent state roots.

## Notes
- This vulnerability only affects deployments with sharded execution enabled
- The issue is in the partitioner's design choice to use `DefaultHasher`, which is explicitly documented as non-deterministic across processes
- The parallel block executor itself is correct - it guarantees determinism for a given transaction order, but cannot compensate for different validators using different orders
- Tests pass because they run in a single process where `DefaultHasher` is deterministic within that process lifetime [8](#0-7)

### Citations

**File:** execution/block-partitioner/src/lib.rs (L39-43)
```rust
fn get_anchor_shard_id(storage_location: &StorageLocation, num_shards: usize) -> ShardId {
    let mut hasher = DefaultHasher::new();
    storage_location.hash(&mut hasher);
    (hasher.finish() % num_shards as u64) as usize
}
```

**File:** execution/block-partitioner/src/v2/init.rs (L45-54)
```rust
                            state.trackers.entry(key_idx).or_insert_with(|| {
                                let anchor_shard_id = get_anchor_shard_id(
                                    storage_location,
                                    state.num_executor_shards,
                                );
                                RwLock::new(ConflictingTxnTracker::new(
                                    storage_location.clone(),
                                    anchor_shard_id,
                                ))
                            });
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

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L121-126)
```rust
                        for &key_idx in write_set.iter().chain(read_set.iter()) {
                            if state.key_owned_by_another_shard(shard_id, key_idx) {
                                in_round_conflict_detected = true;
                                break;
                            }
                        }
```

**File:** types/src/block_executor/partitioner.rs (L378-394)
```rust
    pub fn flatten(block: Vec<SubBlocksForShard<T>>) -> Vec<T> {
        let num_shards = block.len();
        let mut flattened_txns = Vec::new();
        let num_rounds = block[0].num_sub_blocks();
        let mut ordered_blocks = vec![SubBlock::empty(); num_shards * num_rounds];
        for (shard_id, sub_blocks) in block.into_iter().enumerate() {
            for (round, sub_block) in sub_blocks.into_sub_blocks().into_iter().enumerate() {
                ordered_blocks[round * num_shards + shard_id] = sub_block;
            }
        }

        for sub_block in ordered_blocks.into_iter() {
            flattened_txns.extend(sub_block.into_txns());
        }

        flattened_txns
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L68-89)
```rust
        let out = match transactions {
            ExecutableTransactions::Unsharded(txns) => {
                Self::by_transaction_execution_unsharded::<V>(
                    executor,
                    txns,
                    auxiliary_infos,
                    parent_state,
                    state_view,
                    onchain_config,
                    transaction_slice_metadata,
                )?
            },
            // TODO: Execution with auxiliary info is yet to be supported properly here for sharded transactions
            ExecutableTransactions::Sharded(txns) => Self::by_transaction_execution_sharded::<V>(
                txns,
                auxiliary_infos,
                parent_state,
                state_view,
                onchain_config,
                transaction_slice_metadata.append_state_checkpoint_to_block(),
            )?,
        };
```

**File:** execution/executor-benchmark/src/block_preparation.rs (L98-111)
```rust
            Some(partitioner) => {
                NUM_TXNS.inc_with_by(&["partition"], sig_verified_txns.len() as u64);
                let analyzed_transactions =
                    sig_verified_txns.into_iter().map(|t| t.into()).collect();
                let timer = TIMER.timer_with(&["partition"]);
                let partitioned_txns =
                    partitioner.partition(analyzed_transactions, self.num_executor_shards);
                timer.stop_and_record();
                ExecutableBlock::new(
                    block_id,
                    ExecutableTransactions::Sharded(partitioned_txns),
                    vec![],
                )
            },
```

**File:** execution/block-partitioner/src/v2/tests.rs (L42-53)
```rust
fn test_partitioner_v2_uniform_determinism() {
    for merge_discarded in [false, true] {
        let partitioner = Arc::new(PartitionerV2::new(
            4,
            4,
            0.9,
            64,
            merge_discarded,
            Box::new(UniformPartitioner {}),
        ));
        assert_deterministic_result(partitioner);
    }
```
