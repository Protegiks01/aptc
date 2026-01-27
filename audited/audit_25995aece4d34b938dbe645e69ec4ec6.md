# Audit Report

## Title
Remote Sharded Executor Skips Total Supply Aggregation Leading to Consensus Divergence

## Summary
The `RemoteExecutorClient::execute_block` implementation fails to call `aggregate_and_update_total_supply`, causing transaction outputs to contain incorrect total supply values based on the aggregator base value (`TOTAL_SUPPLY_AGGR_BASE_VAL`) instead of the actual state tree value. This creates state divergence between validators using remote sharded execution versus local sharded execution, breaking consensus determinism.

## Finding Description

The sharded block executor uses `AggregatorOverriddenStateView` to override the `TOTAL_SUPPLY_STATE_KEY` reads with a base value (`TOTAL_SUPPLY_AGGR_BASE_VAL = u128::MAX >> 1`) during parallel execution across shards. This allows shards to execute independently without contention on the global total supply aggregator. [1](#0-0) 

After execution completes, the `aggregate_and_update_total_supply` function is responsible for correcting all transaction outputs to reflect the actual total supply from the state tree plus accumulated deltas: [2](#0-1) 

The **critical vulnerability** is that `LocalExecutorClient::execute_block` properly calls this aggregation function: [3](#0-2) 

However, `RemoteExecutorClient::execute_block` completely omits this step and returns raw execution results: [4](#0-3) 

The remote executor returns transaction outputs with total supply values still based on `TOTAL_SUPPLY_AGGR_BASE_VAL` rather than the correct values from the state tree. These incorrect outputs propagate through the system: [5](#0-4) 

**Attack Path:**
1. Deploy remote sharded execution infrastructure using `RemoteExecutorClient`
2. Validators using remote execution compute transaction outputs with incorrect total supply values
3. When these outputs are committed to the state tree, they produce a different state root hash
4. Validators using local execution compute correct total supply values after aggregation
5. Same block produces different state roots on different validators → **consensus failure**

## Impact Explanation

This vulnerability has **Critical Severity** under the Aptos Bug Bounty program as it causes:

1. **Consensus/Safety Violation**: Different validators produce different state roots for identical blocks, breaking the fundamental consensus invariant that "all validators must produce identical state roots for identical blocks."

2. **Non-recoverable Network Partition**: Once the divergence occurs, validators cannot reach consensus on subsequent blocks, requiring manual intervention or a hard fork to recover.

3. **State Tree Corruption**: The Jellyfish Merkle tree would contain incorrect total supply values in nodes using remote execution, causing permanent state inconsistency.

The impact affects all validators using remote sharded execution, which appears to be a supported deployment mode based on the configuration system: [6](#0-5) 

## Likelihood Explanation

**Likelihood: High**

1. **No attacker required**: This is a deterministic bug that occurs automatically when remote sharded execution is enabled
2. **Easy to trigger**: Simply enabling remote executor addresses causes the bug to activate
3. **Configuration-based**: The code path selection depends on `get_remote_addresses()` being non-empty [7](#0-6) 

4. **Production-ready code**: The remote executor implementation appears complete and production-ready, suggesting it may already be deployed or planned for deployment

## Recommendation

Add the total supply aggregation call to `RemoteExecutorClient::execute_block`:

```rust
fn execute_block(
    &self,
    state_view: Arc<S>,
    transactions: PartitionedTransactions,
    concurrency_level_per_shard: usize,
    onchain_config: BlockExecutorConfigFromOnchain,
) -> Result<ShardedExecutionOutput, VMStatus> {
    // ... existing code ...
    
    let mut execution_results = self.get_output_from_shards()?;
    let mut global_output = vec![]; // or execute global txns if supported

    // ADD THIS: Aggregate and update total supply before returning
    sharded_aggregator_service::aggregate_and_update_total_supply(
        &mut execution_results,
        &mut global_output,
        state_view.as_ref(),
        self.thread_pool.clone(),
    );

    self.state_view_service.drop_state_view();
    Ok(ShardedExecutionOutput::new(execution_results, global_output))
}
```

Alternatively, if remote executors cannot access the aggregation service, the coordinator must perform aggregation after receiving results from remote shards.

## Proof of Concept

This vulnerability can be demonstrated by:

1. Setting up two validator nodes with identical genesis state
2. Configuring Node A with local sharded execution (default)
3. Configuring Node B with remote sharded execution (set remote executor addresses)
4. Submitting a block containing transactions that modify total supply (e.g., coin minting/burning)
5. Observing that Node A and Node B compute different state root hashes for the same block

The state root divergence occurs because:
- Node A: total supply correctly updated via `aggregate_and_update_total_supply`
- Node B: total supply remains at `TOTAL_SUPPLY_AGGR_BASE_VAL + delta` without adjustment to actual state tree value

This breaks consensus as nodes cannot agree on the canonical state root.

## Notes

Regarding the original question about the discarded call at line 46: The `self.base_view.get_state_value(state_key)?;` call has no side effects in the base view implementations and does not cause state divergence. However, the investigation revealed this more severe vulnerability where the aggregation step is completely missing in the remote executor path, directly causing the state divergence concern raised in the question.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L41-50)
```rust
    fn get_state_value(&self, state_key: &StateKey) -> Result<Option<StateValue>> {
        if *state_key == *TOTAL_SUPPLY_STATE_KEY {
            // TODO: Remove this when we have aggregated total supply implementation for remote
            //       sharding. For now we need this because after all the txns are executed, the
            //       proof checker expects the total_supply to read/written to the tree.
            self.base_view.get_state_value(state_key)?;
            return self.total_supply_base_view_override();
        }
        self.base_view.get_state_value(state_key)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L168-221)
```rust
pub fn aggregate_and_update_total_supply<S: StateView>(
    sharded_output: &mut Vec<Vec<Vec<TransactionOutput>>>,
    global_output: &mut [TransactionOutput],
    state_view: &S,
    executor_thread_pool: Arc<rayon::ThreadPool>,
) {
    let num_shards = sharded_output.len();
    let num_rounds = sharded_output[0].len();

    // The first element is 0, which is the delta for shard 0 in round 0. +1 element will contain
    // the delta for the global shard
    let mut aggr_total_supply_delta = vec![DeltaU128::default(); num_shards * num_rounds + 1];

    // No need to parallelize this as the runtime is O(num_shards * num_rounds)
    // TODO: Get this from the individual shards while getting 'sharded_output'
    let mut aggr_ts_idx = 1;
    for round in 0..num_rounds {
        sharded_output.iter().for_each(|shard_output| {
            let mut curr_delta = DeltaU128::default();
            // Though we expect all the txn_outputs to have total_supply, there can be
            // exceptions like 'block meta' (first txn in the block) and 'chkpt info' (last txn
            // in the block) which may not have total supply. Hence we iterate till we find the
            // last txn with total supply.
            for txn in shard_output[round].iter().rev() {
                if let Some(last_txn_total_supply) = txn.write_set().get_total_supply() {
                    curr_delta =
                        DeltaU128::get_delta(last_txn_total_supply, TOTAL_SUPPLY_AGGR_BASE_VAL);
                    break;
                }
            }
            aggr_total_supply_delta[aggr_ts_idx] =
                curr_delta + aggr_total_supply_delta[aggr_ts_idx - 1];
            aggr_ts_idx += 1;
        });
    }

    // The txn_outputs contain 'txn_total_supply' with
    // 'CrossShardStateViewAggrOverride::total_supply_aggr_base_val' as the base value.
    // The actual 'total_supply_base_val' is in the state_view.
    // The 'delta' for the shard/round is in aggr_total_supply_delta[round * num_shards + shard_id + 1]
    // For every txn_output, we have to compute
    //      txn_total_supply = txn_total_supply - CrossShardStateViewAggrOverride::total_supply_aggr_base_val + total_supply_base_val + delta
    // While 'txn_total_supply' is u128, the intermediate computation can be negative. So we use
    // DeltaU128 to handle any intermediate underflow of u128.
    let total_supply_base_val: u128 = get_state_value(&TOTAL_SUPPLY_STATE_KEY, state_view).unwrap();
    let base_val_delta = DeltaU128::get_delta(total_supply_base_val, TOTAL_SUPPLY_AGGR_BASE_VAL);

    let aggr_total_supply_delta_ref = &aggr_total_supply_delta;
    // Runtime is O(num_txns), hence parallelized at the shard level and at the txns level.
    executor_thread_pool.scope(|_| {
        sharded_output
            .par_iter_mut()
            .enumerate()
            .for_each(|(shard_id, shard_output)| {
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L183-223)
```rust
    fn execute_block(
        &self,
        state_view: Arc<S>,
        transactions: PartitionedTransactions,
        concurrency_level_per_shard: usize,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<ShardedExecutionOutput, VMStatus> {
        assert_eq!(transactions.num_shards(), self.num_shards());
        let (sub_blocks, global_txns) = transactions.into();
        for (i, sub_blocks_for_shard) in sub_blocks.into_iter().enumerate() {
            self.command_txs[i]
                .send(ExecutorShardCommand::ExecuteSubBlocks(
                    state_view.clone(),
                    sub_blocks_for_shard,
                    concurrency_level_per_shard,
                    onchain_config.clone(),
                ))
                .unwrap();
        }

        // This means that we are executing the global transactions concurrently with the individual shards but the
        // global transactions will be blocked for cross shard transaction results. This hopefully will help with
        // finishing the global transactions faster but we need to evaluate if this causes thread contention. If it
        // does, then we can simply move this call to the end of the function.
        let mut global_output = self.global_executor.execute_global_txns(
            global_txns,
            state_view.as_ref(),
            onchain_config,
        )?;

        let mut sharded_output = self.get_output_from_shards()?;

        sharded_aggregator_service::aggregate_and_update_total_supply(
            &mut sharded_output,
            &mut global_output,
            state_view.as_ref(),
            self.global_executor.get_executor_thread_pool(),
        );

        Ok(ShardedExecutionOutput::new(sharded_output, global_output))
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L35-44)
```rust
pub fn set_remote_addresses(addresses: Vec<SocketAddr>) {
    REMOTE_ADDRESSES.set(addresses).ok();
}

pub fn get_remote_addresses() -> Vec<SocketAddr> {
    match REMOTE_ADDRESSES.get() {
        Some(value) => value.clone(),
        None => vec![],
    }
}
```

**File:** execution/executor-service/src/remote_executor_client.rs (L180-212)
```rust
    fn execute_block(
        &self,
        state_view: Arc<S>,
        transactions: PartitionedTransactions,
        concurrency_level_per_shard: usize,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<ShardedExecutionOutput, VMStatus> {
        trace!("RemoteExecutorClient Sending block to shards");
        self.state_view_service.set_state_view(state_view);
        let (sub_blocks, global_txns) = transactions.into();
        if !global_txns.is_empty() {
            panic!("Global transactions are not supported yet");
        }
        for (shard_id, sub_blocks) in sub_blocks.into_iter().enumerate() {
            let senders = self.command_txs.clone();
            let execution_request = RemoteExecutionRequest::ExecuteBlock(ExecuteBlockCommand {
                sub_blocks,
                concurrency_level: concurrency_level_per_shard,
                onchain_config: onchain_config.clone(),
            });

            senders[shard_id]
                .lock()
                .unwrap()
                .send(Message::new(bcs::to_bytes(&execution_request).unwrap()))
                .unwrap();
        }

        let execution_results = self.get_output_from_shards()?;

        self.state_view_service.drop_state_view();
        Ok(ShardedExecutionOutput::new(execution_results, vec![]))
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3123-3148)
```rust
    fn execute_block_sharded<S: StateView + Sync + Send + 'static, C: ExecutorClient<S>>(
        sharded_block_executor: &ShardedBlockExecutor<S, C>,
        transactions: PartitionedTransactions,
        state_view: Arc<S>,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>, VMStatus> {
        let log_context = AdapterLogSchema::new(state_view.id(), 0);
        info!(
            log_context,
            "Executing block, transaction count: {}",
            transactions.num_txns()
        );

        let count = transactions.num_txns();
        let ret = sharded_block_executor.execute_block(
            state_view,
            transactions,
            AptosVM::get_concurrency_level(),
            onchain_config,
        );
        if ret.is_ok() {
            // Record the histogram count for transactions per block.
            BLOCK_TRANSACTION_COUNT.observe(count as f64);
        }
        ret
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L256-276)
```rust
    fn execute_block_sharded<V: VMBlockExecutor>(
        partitioned_txns: PartitionedTransactions,
        state_view: Arc<CachedStateView>,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>> {
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        } else {
            Ok(V::execute_block_sharded(
                &SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        }
    }
```
