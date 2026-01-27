# Audit Report

## Title
Adversarial Read/Write Sets Force Sequential Execution via Cross-Shard Conflict Maximization

## Summary
An attacker can craft transactions with read/write sets designed to maximize cross-shard conflicts in the block partitioner, causing all transactions to be discarded during partitioning rounds and merged into sequential execution in a single shard. This reduces parallel execution throughput by a factor equal to the number of shards (e.g., 75% reduction with 4 shards).

## Finding Description

The PartitionerV2 implementation uses an anchor-shard-based conflict detection mechanism to avoid cross-shard dependencies. Each storage key is assigned an "anchor shard" via deterministic hashing [1](#0-0) , and transactions are checked for conflicts using the `key_owned_by_another_shard` function [2](#0-1) .

The vulnerability lies in the discarding round logic [3](#0-2) . A transaction in shard S accessing a key with anchor shard A will be flagged as having a cross-shard conflict if there are any writes to that key in the range [A, S) (or wrapped range if A > S). 

**Attack Vector:**
1. Attacker submits N transactions from different senders (to avoid pre-partitioning grouping)
2. Each transaction writes to K storage keys (where K = number of executor shards)
3. The K keys are chosen such that their anchor shards are distributed across all shards (e.g., for 4 shards: K0→shard 0, K1→shard 1, K2→shard 2, K3→shard 3)

**Exploitation Flow:**
- **Pre-partitioning**: Since all transactions write to the same K keys, they form one conflicting set via union-find [4](#0-3) . This set is split into groups and distributed across all shards.

- **Discarding Rounds**: In each round, every transaction in shard S will access at least K-1 keys whose anchor shards are not S. For each such key K_i with anchor A ≠ S, the conflict check will find writes in the range [A, S), causing the transaction to be discarded [5](#0-4) .

- **Result**: ALL transactions in ALL shards are discarded in every round until `max_partitioning_rounds - 1` iterations complete.

- **Final Merge**: With default config `partition_last_round: false` [6](#0-5) , all remaining transactions are merged into the last shard for sequential execution [7](#0-6) .

## Impact Explanation

This qualifies as **Medium Severity** per the Aptos bug bounty criteria for "Validator node slowdowns" (up to $10,000). The attack causes:

1. **Performance Degradation**: Block execution time increases by a factor of `num_shards` (e.g., 4x slowdown with 4 shards, 8x with 8 shards)
2. **Throughput Reduction**: Parallel execution capability is completely nullified, reducing TPS proportionally
3. **Griefing Attack Surface**: Attacker pays normal gas fees but forces degraded performance on all other transactions in the block
4. **No Validator Access Required**: Any transaction sender can perform this attack

The vulnerability does not directly cause consensus violations or fund loss, but significantly impacts network performance and availability, making it a clear DoS vector against the parallel execution system.

## Likelihood Explanation

This attack is **highly likely** to occur because:

1. **Low Barrier to Entry**: Any user can submit transactions with arbitrary read/write sets via Move entry functions
2. **Easy Key Discovery**: Finding storage keys that hash to specific anchor shards requires minimal computation (simple brute force over account addresses or resource types)
3. **No Economic Disincentive**: Attack cost is only the gas fees for the attacker's transactions, which execute normally (albeit slowly)
4. **Deterministic Hashing**: The anchor shard assignment is deterministic [8](#0-7) , allowing attackers to reliably construct adversarial key sets
5. **No Detection/Mitigation**: The partitioner has no defense mechanism to detect or throttle such adversarial patterns

## Recommendation

**Short-term Fix**: Implement a fallback partitioning strategy when excessive discarding is detected:

```rust
// In remove_cross_shard_dependencies, after the discarding loop:
let acceptance_rate = (state.num_txns() - num_remaining_txns) as f32 / state.num_txns() as f32;

// If almost all transactions were discarded, switch to uniform partitioning
if acceptance_rate < 0.1 && state.partition_last_round == false {
    // Distribute remaining txns uniformly instead of merging to one shard
    let chunk_size = (num_remaining_txns + state.num_executor_shards - 1) / state.num_executor_shards;
    let mut new_remaining = vec![vec![]; state.num_executor_shards];
    let all_remaining: Vec<_> = remaining_txns.into_iter().flatten().collect();
    for (i, txn_idx) in all_remaining.into_iter().enumerate() {
        new_remaining[i / chunk_size].push(txn_idx);
    }
    remaining_txns = new_remaining;
}
```

**Long-term Fix**: Redesign the conflict detection to be anchor-shard-agnostic or implement adaptive anchor reassignment based on observed conflict patterns.

## Proof of Concept

```rust
#[test]
fn test_adversarial_read_write_sets_force_sequential_execution() {
    use aptos_types::transaction::analyzed_transaction::{AnalyzedTransaction, StorageLocation};
    use aptos_types::state_store::state_key::StateKey;
    use aptos_types::account_address::AccountAddress;
    use move_core_types::language_storage::StructTag;
    use std::str::FromStr;
    
    let num_shards = 4;
    let num_txns = 100;
    
    // Find 4 keys with anchor shards 0, 1, 2, 3
    let mut keys_by_anchor = vec![vec![]; num_shards];
    let mut counter = 0u64;
    while keys_by_anchor.iter().any(|v| v.is_empty()) {
        let addr = AccountAddress::from_hex_literal(&format!("0x{:x}", counter)).unwrap();
        let state_key = StateKey::resource(&addr, &StructTag::from_str("0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>").unwrap()).unwrap();
        let storage_location = StorageLocation::Specific(state_key);
        let anchor = get_anchor_shard_id(&storage_location, num_shards);
        if keys_by_anchor[anchor].is_empty() {
            keys_by_anchor[anchor].push(storage_location);
        }
        counter += 1;
    }
    
    // Create 100 transactions, each writing to all 4 keys
    let mut transactions = vec![];
    for i in 0..num_txns {
        let sender = AccountAddress::from_hex_literal(&format!("0x{:x}", 1000 + i)).unwrap();
        let mut write_hints = vec![];
        for anchor in 0..num_shards {
            write_hints.push(keys_by_anchor[anchor][0].clone());
        }
        // Create mock AnalyzedTransaction with these write hints
        // (actual implementation would need proper SignatureVerifiedTransaction)
        transactions.push(create_mock_analyzed_txn(sender, write_hints));
    }
    
    // Partition the block
    let partitioner = PartitionerV2::new(
        8, 4, 0.9, 64, false, // partition_last_round = false
        Box::new(ConnectedComponentPartitioner { load_imbalance_tolerance: 2.0 })
    );
    let result = partitioner.partition(transactions, num_shards);
    
    // Verify that all transactions ended up in the last shard (sequential execution)
    let mut txns_in_last_shard = 0;
    for (round_id, round) in result.rounds().enumerate() {
        for (shard_id, sub_block) in round.iter().enumerate() {
            if round_id == result.rounds().len() - 1 && shard_id == num_shards - 1 {
                txns_in_last_shard = sub_block.len();
            }
        }
    }
    
    // Assert that most/all transactions are in the last shard due to conflict maximization
    assert!(txns_in_last_shard > num_txns * 9 / 10, 
            "Expected >90% of transactions in last shard, found {}/{}", 
            txns_in_last_shard, num_txns);
}
```

**Notes:**
- The vulnerability stems from the fundamental design of anchor-shard-based conflict resolution combined with the aggressive discarding strategy
- The wrapped range check logic [9](#0-8)  correctly implements the intended semantics, but the semantics themselves are exploitable
- The default configuration [10](#0-9)  amplifies the impact by merging all discarded transactions into one shard
- This attack does not affect consensus safety or determinism, only performance and liveness under load

### Citations

**File:** execution/block-partitioner/src/lib.rs (L39-43)
```rust
fn get_anchor_shard_id(storage_location: &StorageLocation, num_shards: usize) -> ShardId {
    let mut hasher = DefaultHasher::new();
    storage_location.hash(&mut hasher);
    (hasher.finish() % num_shards as u64) as usize
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

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L52-58)
```rust
        if !state.partition_last_round {
            trace!("Merging txns after discarding stopped.");
            let last_round_txns: Vec<PrePartitionedTxnIdx> =
                remaining_txns.into_iter().flatten().collect();
            remaining_txns = vec![vec![]; state.num_executor_shards];
            remaining_txns[state.num_executor_shards - 1] = last_round_txns;
        }
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L116-126)
```rust
                    txn_idxs.into_par_iter().for_each(|txn_idx| {
                        let ori_txn_idx = state.ori_idxs_by_pre_partitioned[txn_idx];
                        let mut in_round_conflict_detected = false;
                        let write_set = state.write_sets[ori_txn_idx].read().unwrap();
                        let read_set = state.read_sets[ori_txn_idx].read().unwrap();
                        for &key_idx in write_set.iter().chain(read_set.iter()) {
                            if state.key_owned_by_another_shard(shard_id, key_idx) {
                                in_round_conflict_detected = true;
                                break;
                            }
                        }
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L128-134)
```rust
                        if in_round_conflict_detected {
                            let sender = state.sender_idx(ori_txn_idx);
                            min_discard_table
                                .entry(sender)
                                .or_insert_with(|| AtomicUsize::new(usize::MAX))
                                .fetch_min(txn_idx, Ordering::SeqCst);
                            discarded[shard_id].write().unwrap().push(txn_idx);
```

**File:** execution/block-partitioner/src/pre_partition/connected_component/mod.rs (L43-56)
```rust
        // Union-find.
        // Each sender/state key initially in its own set.
        // For every declared storage access to key `k` by a txn from sender `s`, merge the set of `k` and that of `s`.
        let num_senders = state.num_senders();
        let num_keys = state.num_keys();
        let mut uf = UnionFind::new(num_senders + num_keys);
        for txn_idx in 0..state.num_txns() {
            let sender_idx = state.sender_idx(txn_idx);
            let write_set = state.write_sets[txn_idx].read().unwrap();
            for &key_idx in write_set.iter() {
                let key_idx_in_uf = num_senders + key_idx;
                uf.union(key_idx_in_uf, sender_idx);
            }
        }
```

**File:** execution/block-partitioner/src/v2/config.rs (L54-64)
```rust
impl Default for PartitionerV2Config {
    fn default() -> Self {
        Self {
            num_threads: 8,
            max_partitioning_rounds: 4,
            cross_shard_dep_avoid_threshold: 0.9,
            dashmap_num_shards: 64,
            partition_last_round: false,
            pre_partitioner_config: Box::<ConnectedComponentPartitionerConfig>::default(),
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
