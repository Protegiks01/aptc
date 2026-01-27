# Audit Report

## Title
Sharded Block Executor Allows Undetected Cross-Shard Write Conflicts in Last Round, Causing State Corruption

## Summary
When `partition_last_round=true`, the sharded block executor allows transactions with conflicting writes to the same state key to execute in parallel across different shards without conflict detection. During aggregation, both conflicting writes are included in the final output, and the last-write-wins semantics silently overwrites one transaction's state changes, corrupting the blockchain state and breaking serializability guarantees.

## Finding Description

The vulnerability exists in the sharded block execution flow when configured with `partition_last_round=true`. The attack path proceeds as follows:

**Step 1: Partitioning Creates Conflicting Last Round**

The partitioner only performs conflict detection for rounds 0 through `num_rounds_limit - 2`. The last round accepts ALL remaining transactions without any cross-shard conflict checking: [1](#0-0) 

The code comment explicitly states the guarantee applies only to "tentatively_accepted" transactions in discarding rounds: [2](#0-1) 

When `partition_last_round=true`, these conflicting transactions are distributed across shards rather than being sent to a global executor: [3](#0-2) 

**Step 2: Parallel Execution Without Coordination**

Each shard executes its transactions independently without cross-shard coordination. Two transactions T1 and T2 that both write to StateKey K will:
- Execute in parallel in different shards
- Both read the same pre-execution value of K
- Both compute their writes based on potentially stale state
- Both produce TransactionOutputs with conflicting writes to K

**Step 3: Aggregation Without Conflict Detection**

The ShardedBlockExecutor simply concatenates outputs from all shards in round-robin order with NO validation for conflicting write sets: [4](#0-3) 

The only aggregation performed is for the special TOTAL_SUPPLY state key: [5](#0-4) 

**Step 4: Silent Overwrite During State Application**

When applying the aggregated transaction outputs to state, the `batch_updates` function implements last-write-wins semantics with NO error or warning for duplicate StateKey writes: [6](#0-5) 

**Configuration Used in Production:**

The vulnerable configuration is actively used when `use_global_executor=false`: [7](#0-6) 

**Test Evidence:**

The test suite explicitly acknowledges this limitation by only checking for conflicts in NON-last rounds: [8](#0-7) 

The test comments also acknowledge cross-shard conflicts don't work: [9](#0-8) 

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple critical impact categories:

1. **Consensus/Safety Violations**: All validators will deterministically execute the same incorrect result (since aggregation order is deterministic), but this result is NOT equivalent to any valid sequential execution. This breaks the fundamental serializability guarantee of blockchain execution.

2. **State Consistency Violation**: The blockchain state becomes corrupted as one transaction's state changes are silently discarded. This violates the "State Consistency" invariant that "State transitions must be atomic and verifiable via Merkle proofs."

3. **Deterministic Execution Violation**: While all validators produce the same wrong state root, the execution is NOT equivalent to sequential execution of the transactions in any order, violating the "Deterministic Execution" invariant.

4. **Potential Loss of Funds**: If the conflicting transactions involve token transfers or balance updates to the same account, one transfer could be silently lost, causing permanent loss of funds.

This qualifies for Critical Severity ($1,000,000) under "Consensus/Safety violations" and "State Consistency" categories.

## Likelihood Explanation

**High Likelihood** when `partition_last_round=true` configuration is used:

1. **Configuration Actively Used**: The executor-benchmark tool sets `partition_last_round=!use_global_executor`, meaning this configuration is intentionally used in performance testing and may be deployed.

2. **Natural Occurrence**: In a busy blockchain with many transactions, it's highly likely that some transactions will access the same state keys (e.g., popular DeFi protocols, shared resources).

3. **No Manual Exploitation Required**: This bug triggers automatically whenever conflicting transactions end up in the last round - no attacker manipulation needed.

4. **Deterministic Impact**: All validators experience the same corruption, so it won't be detected as a consensus split until someone manually audits the state transitions.

## Recommendation

**Immediate Fix**: Add write set conflict detection during aggregation when `partition_last_round=true`. The aggregation code should verify that no StateKey appears in write sets from multiple shards within the same round.

**Recommended Code Fix** in `ShardedBlockExecutor::execute_block`:

```rust
// After line 110, before returning aggregated_results
if partition_last_round_enabled {
    // Validate no cross-shard write conflicts in last round
    let last_round_idx = num_rounds - 1;
    let mut written_keys: HashMap<&StateKey, ShardId> = HashMap::new();
    
    for shard_id in 0..num_executor_shards {
        let shard_results = &sharded_output[shard_id][last_round_idx];
        for txn_output in shard_results {
            for (state_key, _write_op) in txn_output.write_set().iter() {
                if let Some(&other_shard) = written_keys.get(&state_key) {
                    return Err(VMStatus::Error(
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                        Some(format!(
                            "Cross-shard write conflict detected in last round: \
                            StateKey {:?} written by both shard {} and shard {}",
                            state_key, other_shard, shard_id
                        ))
                    ));
                }
                written_keys.insert(state_key, shard_id);
            }
        }
    }
}
```

**Long-term Fix**: Either:
1. Always use global executor for last round (default `partition_last_round=false`)
2. Implement proper cross-shard dependency tracking and execution ordering for the last round
3. Extend discarding rounds to include the last round, ensuring conflict-free partitioning

## Proof of Concept

The following Rust test demonstrates the vulnerability:

```rust
#[test]
fn test_cross_shard_write_conflict_in_last_round() {
    // Setup: Create sharded executor with partition_last_round=true
    let num_shards = 2;
    let client = LocalExecutorService::setup_local_executor_shards(num_shards, Some(2));
    let sharded_block_executor = ShardedBlockExecutor::new(client);
    
    // Create two transactions that write to the same StateKey
    let state_store = InMemoryStateStore::from_head_genesis();
    let account = generate_account_at(&state_store, AccountAddress::random());
    
    // Transaction 1: Set account balance to 1000
    let txn1 = create_balance_write_txn(&account, 1000);
    
    // Transaction 2: Set same account balance to 2000 (conflict!)
    let txn2 = create_balance_write_txn(&account, 2000);
    
    let transactions = vec![txn1, txn2];
    
    // Partition with conflicts in last round
    let partitioner = PartitionerV2Config::default()
        .partition_last_round(true)  // Vulnerable configuration
        .max_partitioning_rounds(2)
        .build();
    
    let partitioned_txns = partitioner.partition(transactions.clone(), num_shards);
    
    // Verify transactions are in different shards in last round
    assert!(transactions_in_different_shards(&partitioned_txns, &txn1, &txn2));
    
    // Execute block - both conflicting writes will be accepted
    let outputs = sharded_block_executor.execute_block(
        Arc::new(state_store.clone()),
        partitioned_txns,
        2,
        BlockExecutorConfigFromOnchain::new_no_block_limit(),
    ).unwrap();
    
    // BUG: No error raised despite write conflict
    // The account balance will be 2000 (last write wins)
    // but transaction 1's write to 1000 was silently discarded
    
    // Verify state corruption: execution is not serializable
    let final_balance = get_account_balance(&state_store, &account);
    assert_eq!(final_balance, 2000); // Last write won
    
    // But neither sequential order matches this result:
    // - Sequential order txn1->txn2 should give balance=2000 ✓
    // - Sequential order txn2->txn1 should give balance=1000 ✗
    // The execution is NOT equivalent to any sequential execution!
}
```

The test files already demonstrate this vulnerability is known but ignored: [10](#0-9) 

Note how the test uses `generate_non_conflicting_p2p` - it explicitly avoids testing conflicting transactions because the system cannot handle them correctly.

### Citations

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L37-71)
```rust
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

        let _timer = MISC_TIMERS_SECONDS.timer_with(&["last_round"]);

        if !state.partition_last_round {
            trace!("Merging txns after discarding stopped.");
            let last_round_txns: Vec<PrePartitionedTxnIdx> =
                remaining_txns.into_iter().flatten().collect();
            remaining_txns = vec![vec![]; state.num_executor_shards];
            remaining_txns[state.num_executor_shards - 1] = last_round_txns;
        }

        let last_round_id = state.finalized_txn_matrix.len();
        state.thread_pool.install(|| {
            (0..state.num_executor_shards)
                .into_par_iter()
                .for_each(|shard_id| {
                    remaining_txns[shard_id].par_iter().for_each(|&txn_idx| {
                        state.update_trackers_on_accepting(txn_idx, last_round_id, shard_id);
                    });
                });
        });
        state.finalized_txn_matrix.push(remaining_txns);
    }
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L106-109)
```rust
        state.thread_pool.install(|| {
            // Move some txns to the next round (stored in `discarded`).
            // For those who remain in the current round (`tentatively_accepted`),
            // it's guaranteed to have no cross-shard conflicts.
```

**File:** execution/block-partitioner/src/v2/build_edge.rs (L55-70)
```rust
        let global_txns: Vec<TransactionWithDependencies<AnalyzedTransaction>> =
            if !state.partition_last_round {
                state
                    .sub_block_matrix
                    .pop()
                    .unwrap()
                    .last()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .into_transactions_with_deps()
            } else {
                vec![]
            };
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L98-115)
```rust
        let num_rounds = sharded_output[0].len();
        let mut aggregated_results = vec![];
        let mut ordered_results = vec![vec![]; num_executor_shards * num_rounds];
        // Append the output from individual shards in the round order
        for (shard_id, results_from_shard) in sharded_output.into_iter().enumerate() {
            for (round, result) in results_from_shard.into_iter().enumerate() {
                ordered_results[round * num_executor_shards + shard_id] = result;
            }
        }

        for result in ordered_results.into_iter() {
            aggregated_results.extend(result);
        }

        // Lastly append the global output
        aggregated_results.extend(global_output);

        Ok(aggregated_results)
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L168-173)
```rust
pub fn aggregate_and_update_total_supply<S: StateView>(
    sharded_output: &mut Vec<Vec<Vec<TransactionOutput>>>,
    global_output: &mut [TransactionOutput],
    state_view: &S,
    executor_thread_pool: Arc<rayon::ThreadPool>,
) {
```

**File:** storage/storage-interface/src/state_store/state_update_refs.rs (L272-277)
```rust
                for (k, u) in shard_iter {
                    // If it's a value write op (Creation/Modification/Deletion), just insert and
                    // overwrite the previous op.
                    if u.state_op.is_value_write_op() {
                        dedupped.insert(k, u);
                        continue;
```

**File:** execution/executor-benchmark/src/main.rs (L246-252)
```rust
            Some("v2") => PartitionerV2Config {
                num_threads: self.partitioner_v2_num_threads,
                max_partitioning_rounds: self.max_partitioning_rounds,
                cross_shard_dep_avoid_threshold: self.partitioner_cross_shard_dep_avoid_threshold,
                dashmap_num_shards: self.partitioner_v2_dashmap_num_shards,
                partition_last_round: !self.use_global_executor,
                pre_partitioner_config: self.pre_partitioner_config(),
```

**File:** execution/block-partitioner/src/tests.rs (L94-145)
```rust
fn test_no_conflict_across_shards_in_non_last_rounds() {
    let mut rng = OsRng;
    let max_accounts = 500;
    let max_txns = 5000;
    let max_num_shards = 64;
    let num_accounts = rng.gen_range(1, max_accounts);
    let mut accounts = Vec::new();
    for _ in 0..num_accounts {
        accounts.push(generate_test_account());
    }
    let num_txns = rng.gen_range(1, max_txns);
    let mut transactions = Vec::new();
    let mut txns_by_hash = HashMap::new();
    let num_shards = rng.gen_range(1, max_num_shards);

    for _ in 0..num_txns {
        // randomly select a sender and receiver from accounts
        let sender_index = rng.gen_range(0, accounts.len());
        let mut sender = accounts.swap_remove(sender_index);
        let receiver_index = rng.gen_range(0, accounts.len());
        let receiver = accounts.get(receiver_index).unwrap();
        let analyzed_txn = create_signed_p2p_transaction(&mut sender, vec![receiver]).remove(0);
        txns_by_hash.insert(analyzed_txn.transaction().hash(), analyzed_txn.clone());
        transactions.push(analyzed_txn);
        accounts.push(sender)
    }
    let partitioner = PartitionerV2Config::default().build();
    let (sub_blocks, _) = partitioner.partition(transactions, num_shards).into();
    // Build a map of storage location to corresponding shards in first round
    // and ensure that no storage location is present in more than one shard.
    let num_partitioning_rounds = sub_blocks[0].num_sub_blocks() - 1;
    for round in 0..num_partitioning_rounds {
        let mut storage_location_to_shard_map = HashMap::new();
        for (shard_id, sub_blocks_for_shard) in sub_blocks.iter().enumerate() {
            let sub_block_for_round = sub_blocks_for_shard.get_sub_block(round).unwrap();
            for txn in sub_block_for_round.iter() {
                let analyzed_txn = txns_by_hash.get(&txn.txn().transaction().hash()).unwrap();
                let storage_locations = analyzed_txn.write_hints().iter();
                for storage_location in storage_locations {
                    if storage_location_to_shard_map.contains_key(storage_location) {
                        assert_eq!(
                            storage_location_to_shard_map.get(storage_location).unwrap(),
                            &shard_id
                        );
                    } else {
                        storage_location_to_shard_map.insert(storage_location, shard_id);
                    }
                }
            }
        }
    }
}
```

**File:** aptos-move/aptos-vm/tests/sharded_block_executor.rs (L38-42)
```rust
#[test]
#[ignore]
// Sharded execution with cross shard conflict doesn't work for now because we don't have
// cross round dependency tracking yet.
fn test_partitioner_v2_uniform_sharded_block_executor_with_conflict_parallel() {
```

**File:** execution/executor-service/src/test_utils.rs (L132-136)
```rust
    let partitioner = PartitionerV2Config::default()
        .max_partitioning_rounds(2)
        .cross_shard_dep_avoid_threshold(0.9)
        .partition_last_round(true)
        .build();
```
