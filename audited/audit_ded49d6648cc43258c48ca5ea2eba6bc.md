# Audit Report

## Title
Shard Starvation in Block Partitioner Due to Unbalanced Round Distribution After Cross-Shard Dependency Removal

## Summary
The block partitioner's pre-partitioning phase achieves load balance through LPT scheduling, but the subsequent `remove_cross_shard_dependencies` phase can redistribute transactions across rounds in an unbalanced manner, causing some execution shards to remain idle while others are overloaded, degrading overall throughput.

## Finding Description

The Aptos sharded block executor uses a two-phase partitioning approach: 

**Phase 1: Pre-partitioning** [1](#0-0) 

The `ConnectedComponentPartitioner` calculates a `group_size_limit` based on `load_imbalance_tolerance` (default 2.0) and uses Longest-Processing-Time-First (LPT) scheduling to distribute transaction groups across shards. [2](#0-1) 

This guarantees initial load balance: no shard receives more than `(block_size * load_imbalance_tolerance) / num_shards` transactions.

**Phase 2: Cross-shard dependency removal** [3](#0-2) 

The `remove_cross_shard_dependencies` function iteratively creates rounds by calling `discarding_round`, which checks each transaction for cross-shard conflicts and moves conflicting transactions to the next round. [4](#0-3) 

**Critical issue:** The discarding logic performs NO load balancing. It only checks whether a transaction conflicts with keys "owned by another shard". Transactions without conflicts remain in the current round; those with conflicts are moved to the next round, regardless of resulting shard balance.

**Execution model** [5](#0-4) 

Each shard processes its sub-blocks sequentially by round. [6](#0-5) 

The coordinator waits for ALL shards to complete before aggregating results. [7](#0-6) 

**Attack scenario:**
1. Attacker crafts transactions with specific read/write patterns that create cross-shard conflicts for certain shards
2. Transactions on Shard A access only keys unique to Shard A → no conflicts → all stay in round 0
3. Transactions on Shard B access keys from other shards → conflicts → most moved to later rounds
4. Result: Round 0 has Shard A with 30 txns, Shard B with 2 txns
5. Shard B finishes round 0 quickly and idles while Shard A continues processing
6. Overall throughput is limited by the slowest shard (Shard A)

## Impact Explanation

This issue causes **validator node slowdowns**, which the Aptos bug bounty classifies as **High Severity** (up to $50,000). However, the security question explicitly labels this as **(Low)** severity, suggesting it's a known performance trade-off rather than a critical vulnerability.

The impact is throughput degradation, not a safety or correctness violation. All critical invariants remain intact:
- Deterministic execution is preserved
- No consensus safety violations occur
- State consistency is maintained
- The system functions correctly, just slower than optimal

## Likelihood Explanation

**Moderate likelihood** under normal operation - the imbalance naturally occurs when transactions have uneven cross-shard conflict patterns.

**Low exploitation likelihood** - An attacker attempting to intentionally maximize imbalance would need to:
1. Understand the internal union-find partitioning algorithm
2. Know which storage keys map to which shards (non-deterministic, changes per block)
3. Craft transactions with precise read/write patterns to create targeted conflicts
4. This requires deep system knowledge and is highly complex

The system already includes monitoring via metrics [8](#0-7)  that track execution time and transaction count per shard per round, allowing detection of imbalance.

## Recommendation

**Option 1: Add post-round load balancing**
After `remove_cross_shard_dependencies` creates rounds, redistribute transactions within each round to balance shard load, while maintaining the constraint that within-round transactions have no cross-shard conflicts.

**Option 2: Make load balancing adaptive**
Track actual execution times per shard and dynamically adjust future partitioning decisions based on observed imbalance.

**Option 3: Configure for specific workloads**
Tune `load_imbalance_tolerance`, `max_partitioning_rounds`, and `cross_shard_dep_avoid_threshold` [9](#0-8)  based on observed transaction patterns to minimize post-round imbalance.

## Proof of Concept

Due to the complexity of the sharded execution environment, a full PoC would require:
1. Setting up a multi-shard executor with configurable number of shards
2. Crafting a block of transactions with specific conflict patterns
3. Measuring per-shard execution times across rounds
4. Demonstrating significant imbalance (e.g., >2x difference in shard workload)

This would be implemented as an integration test in `execution/block-partitioner/src/v2/tests.rs`, measuring the delta between fastest and slowest shard completion times and asserting it exceeds acceptable thresholds.

---

## Notes

This is classified as a **Low severity performance issue** rather than a critical security vulnerability because:
1. No safety or correctness invariants are violated
2. The imbalance is a natural trade-off in the conflict avoidance design
3. Existing metrics monitor for this condition
4. Exploitation requires sophisticated knowledge and offers limited attacker benefit
5. The system includes partial mitigations (global executor for highly conflicting txns)

The issue represents a performance optimization opportunity rather than an exploitable security flaw requiring urgent remediation.

### Citations

**File:** execution/block-partitioner/src/pre_partition/connected_component/mod.rs (L88-91)
```rust
        // Calculate txn group size limit.
        let group_size_limit = ((state.num_txns() as f32) * self.load_imbalance_tolerance
            / (state.num_executor_shards as f32))
            .ceil() as usize;
```

**File:** execution/block-partitioner/src/pre_partition/connected_component/mod.rs (L108-114)
```rust
        // Assign groups to shards using longest-processing-time first scheduling.
        let tasks: Vec<u64> = group_metadata
            .iter()
            .map(|(_, size)| (*size) as u64)
            .collect();
        let (_longest_pole, shards_by_group) =
            longest_processing_time_first(&tasks, state.num_executor_shards);
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L30-48)
```rust
    pub(crate) fn remove_cross_shard_dependencies(state: &mut PartitionState) {
        let _timer = MISC_TIMERS_SECONDS.timer_with(&["remove_cross_shard_dependencies"]);

        let mut remaining_txns = mem::take(&mut state.pre_partitioned);
        assert_eq!(state.num_executor_shards, remaining_txns.len());

        let mut num_remaining_txns: usize;
        for round_id in 0..(state.num_rounds_limit - 1) {
            let (accepted, discarded) = Self::discarding_round(state, round_id, remaining_txns);
            state.finalized_txn_matrix.push(accepted);
            remaining_txns = discarded;
            num_remaining_txns = remaining_txns.iter().map(|ts| ts.len()).sum();

            if num_remaining_txns
                < ((1.0 - state.cross_shard_dep_avoid_threshold) * state.num_txns() as f32) as usize
            {
                break;
            }
        }
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L116-142)
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

                        if in_round_conflict_detected {
                            let sender = state.sender_idx(ori_txn_idx);
                            min_discard_table
                                .entry(sender)
                                .or_insert_with(|| AtomicUsize::new(usize::MAX))
                                .fetch_min(txn_idx, Ordering::SeqCst);
                            discarded[shard_id].write().unwrap().push(txn_idx);
                        } else {
                            tentatively_accepted[shard_id]
                                .write()
                                .unwrap()
                                .push(txn_idx);
                        }
                    });
                });
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L185-213)
```rust
    fn execute_block(
        &self,
        transactions: SubBlocksForShard<AnalyzedTransaction>,
        state_view: &S,
        config: BlockExecutorConfig,
    ) -> Result<Vec<Vec<TransactionOutput>>, VMStatus> {
        let mut result = vec![];
        for (round, sub_block) in transactions.into_sub_blocks().into_iter().enumerate() {
            let _timer = SHARDED_BLOCK_EXECUTION_BY_ROUNDS_SECONDS
                .timer_with(&[&self.shard_id.to_string(), &round.to_string()]);
            SHARDED_BLOCK_EXECUTOR_TXN_COUNT.observe_with(
                &[&self.shard_id.to_string(), &round.to_string()],
                sub_block.transactions.len() as f64,
            );
            info!(
                "executing sub block for shard {} and round {}, number of txns {}",
                self.shard_id,
                round,
                sub_block.transactions.len()
            );
            result.push(self.execute_sub_block(sub_block, round, state_view, config.clone())?);
            trace!(
                "Finished executing sub block for shard {} and round {}",
                self.shard_id,
                round
            );
        }
        Ok(result)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L164-175)
```rust
    fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
        let _timer = WAIT_FOR_SHARDED_OUTPUT_SECONDS.start_timer();
        trace!("LocalExecutorClient Waiting for results");
        let mut results = vec![];
        for (i, rx) in self.result_rxs.iter().enumerate() {
            results.push(
                rx.recv()
                    .unwrap_or_else(|_| panic!("Did not receive output from shard {}", i))?,
            );
        }
        Ok(results)
    }
```

**File:** aptos-move/aptos-vm/src/sharded-block-executor/mod.rs (L98-110)
```rust

```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/counters.rs (L42-59)
```rust
pub static SHARDED_BLOCK_EXECUTION_BY_ROUNDS_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "sharded_block_execution_by_rounds_seconds",
        "Time to execute a sub block in sharded execution in seconds",
        &["shard_id", "round_id"]
    )
    .unwrap()
});

/// Count of the committed transactions since last restart.
pub static SHARDED_BLOCK_EXECUTOR_TXN_COUNT: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "sharded_block_executor_txn_count",
        "Count of number of transactions per shard per round in sharded execution",
        &["shard_id", "round_id"]
    )
    .unwrap()
});
```

**File:** execution/block-partitioner/src/v2/config.rs (L54-65)
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
}
```
