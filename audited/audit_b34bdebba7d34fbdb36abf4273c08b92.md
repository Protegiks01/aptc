# Audit Report

## Title
State Root Divergence Between Local and Remote Sharded Execution Due to Missing Total Supply Aggregation

## Summary
The `RemoteExecutorClient` does not perform total supply aggregation after sharded execution, while `LocalExecutorClient` does. This causes validators using different execution modes to compute different state roots for identical blocks, breaking consensus safety.

## Finding Description
The sharded block executor supports two execution modes: local and remote. The critical difference is in their post-execution aggregation logic:

**LocalExecutorClient** performs total supply aggregation: [1](#0-0) 

**RemoteExecutorClient** does NOT perform total supply aggregation: [2](#0-1) 

The aggregation service modifies transaction outputs by computing cumulative total supply deltas across all shards and rounds, then updating each transaction's total supply value: [3](#0-2) 

Validators select between local and remote execution based on configuration: [4](#0-3) 

The total supply value is written to the state through the write set: [5](#0-4) 

**Attack Scenario:**
1. Validator A is configured without remote addresses (uses LocalExecutorClient)
2. Validator B is configured with remote addresses (uses RemoteExecutorClient)
3. Both validators receive the same block with transactions that modify total supply
4. Validator A executes locally and calls `aggregate_and_update_total_supply()`, adjusting all transaction outputs' total supply values based on cumulative deltas
5. Validator B executes remotely and skips aggregation, keeping original unadjusted total supply values
6. Both validators compute state roots from their transaction outputs
7. Result: **Different state roots for the same block** → Consensus failure

This breaks the fundamental invariant: **"All validators must produce identical state roots for identical blocks"**

## Impact Explanation
**Critical Severity** - This is a consensus-breaking vulnerability that causes network partition:

- **Consensus Safety Violation**: Validators cannot agree on the correct state root, breaking Byzantine Fault Tolerance guarantees
- **Network Partition**: The network splits into two groups (local vs. remote executors) that reject each other's blocks
- **Non-Recoverable Without Hardfork**: Requires manual intervention and coordination to resolve the divergence
- **Affects All Transactions**: Any block with transactions touching total supply (which includes most system operations) will trigger the divergence

Per Aptos bug bounty criteria, this qualifies as **Critical Severity** (up to $1,000,000) under "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation
**High Likelihood** if mixed execution modes are deployed:

- The code paths are well-defined and deterministic in producing different outputs
- No special conditions or race conditions required
- Occurs automatically on any block execution if validators use different modes
- Remote execution is a documented feature (though possibly not widely deployed yet)
- The TODO comment in the aggregation code suggests this is known incomplete functionality: [6](#0-5) 

If all validators currently use the same execution mode (all local or all remote), the vulnerability is latent but becomes active upon mixed deployments.

## Recommendation
The `RemoteExecutorClient` must call `aggregate_and_update_total_supply()` before returning results, matching the `LocalExecutorClient` behavior.

**Fix for `remote_executor_client.rs`:**

```rust
fn execute_block(
    &self,
    state_view: Arc<S>,
    transactions: PartitionedTransactions,
    concurrency_level_per_shard: usize,
    onchain_config: BlockExecutorConfigFromOnchain,
) -> Result<ShardedExecutionOutput, VMStatus> {
    trace!("RemoteExecutorClient Sending block to shards");
    self.state_view_service.set_state_view(state_view.clone());
    let (sub_blocks, global_txns) = transactions.into();
    if !global_txns.is_empty() {
        panic!("Global transactions are not supported yet");
    }
    
    // ... send to shards ...
    
    let mut execution_results = self.get_output_from_shards()?;
    let mut global_output = vec![]; // Empty until global txns supported
    
    // ADD THIS: Perform total supply aggregation like LocalExecutorClient
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

Additionally, add integration tests that verify both execution modes produce identical outputs for the same block.

## Proof of Concept
```rust
// Test demonstrating state root divergence
#[test]
fn test_local_vs_remote_execution_divergence() {
    use aptos_vm::sharded_block_executor::{
        local_executor_shard::LocalExecutorClient,
        ShardedBlockExecutor,
    };
    use execution_executor_service::remote_executor_client::RemoteExecutorClient;
    
    // Setup: Create identical state view and transaction block
    let state_view = create_test_state_view();
    let transactions = create_test_partitioned_transactions(); // Contains txns modifying total supply
    let config = BlockExecutorConfigFromOnchain::default();
    
    // Execute with LocalExecutorClient
    let local_executor = LocalExecutorClient::create_local_sharded_block_executor(4, None);
    let local_outputs = local_executor.execute_block(
        Arc::new(state_view.clone()),
        transactions.clone(),
        8,
        config.clone(),
    ).unwrap();
    
    // Execute with RemoteExecutorClient (with remote shards configured)
    let remote_executor = RemoteExecutorClient::create_remote_sharded_block_executor(
        coordinator_address,
        vec![shard1_addr, shard2_addr, shard3_addr, shard4_addr],
        None,
    );
    let remote_outputs = remote_executor.execute_block(
        Arc::new(state_view.clone()),
        transactions,
        8,
        config,
    ).unwrap();
    
    // Compare total supply values in outputs
    for (local_txn, remote_txn) in local_outputs.iter().zip(remote_outputs.iter()) {
        let local_supply = local_txn.write_set().get_total_supply();
        let remote_supply = remote_txn.write_set().get_total_supply();
        
        // BUG: These will be DIFFERENT due to missing aggregation in remote executor
        assert_eq!(local_supply, remote_supply, 
            "State root divergence: local and remote executors produce different total supply values");
    }
    
    // Compute state roots
    let local_state_root = compute_state_root(&local_outputs);
    let remote_state_root = compute_state_root(&remote_outputs);
    
    // VULNERABILITY: Different state roots for identical blocks
    assert_eq!(local_state_root, remote_state_root,
        "CRITICAL: Validators compute different state roots for the same block!");
}
```

**Notes:**
- This vulnerability is present in the current codebase and affects consensus safety
- The remote execution feature may not be widely deployed yet, but the code path exists and could be enabled via configuration
- The fix is straightforward: ensure both execution modes call the same aggregation logic
- Comprehensive testing should verify output equivalence between execution modes before deployment

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L213-222)
```rust
        let mut sharded_output = self.get_output_from_shards()?;

        sharded_aggregator_service::aggregate_and_update_total_supply(
            &mut sharded_output,
            &mut global_output,
            state_view.as_ref(),
            self.global_executor.get_executor_thread_pool(),
        );

        Ok(ShardedExecutionOutput::new(sharded_output, global_output))
```

**File:** execution/executor-service/src/remote_executor_client.rs (L208-211)
```rust
        let execution_results = self.get_output_from_shards()?;

        self.state_view_service.drop_state_view();
        Ok(ShardedExecutionOutput::new(execution_results, vec![]))
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L168-257)
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
                for (round, txn_outputs) in shard_output.iter_mut().enumerate() {
                    let delta_for_round =
                        aggr_total_supply_delta_ref[round * num_shards + shard_id] + base_val_delta;
                    let num_txn_outputs = txn_outputs.len();
                    txn_outputs
                        .par_iter_mut()
                        .with_min_len(optimal_min_len(num_txn_outputs, 32))
                        .for_each(|txn_output| {
                            if let Some(txn_total_supply) =
                                txn_output.write_set().get_total_supply()
                            {
                                txn_output.update_total_supply(
                                    delta_for_round.add_delta(txn_total_supply),
                                );
                            }
                        });
                }
            });
    });

    let delta_for_global_shard = aggr_total_supply_delta[num_shards * num_rounds] + base_val_delta;
    let delta_for_global_shard_ref = &delta_for_global_shard;
    executor_thread_pool.scope(|_| {
        let num_txn_outputs = global_output.len();
        global_output
            .par_iter_mut()
            .with_min_len(optimal_min_len(num_txn_outputs, 32))
            .for_each(|txn_output| {
                if let Some(txn_total_supply) = txn_output.write_set().get_total_supply() {
                    txn_output.update_total_supply(
                        delta_for_global_shard_ref.add_delta(txn_total_supply),
                    );
                }
            });
    });
}
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-275)
```rust
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
```

**File:** types/src/write_set.rs (L730-739)
```rust
    fn update_total_supply(&mut self, value: u128) {
        assert!(self
            .0
            .write_set
            .insert(
                TOTAL_SUPPLY_STATE_KEY.clone(),
                WriteOp::legacy_modification(bcs::to_bytes(&value).unwrap().into())
            )
            .is_some());
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L43-46)
```rust
            // TODO: Remove this when we have aggregated total supply implementation for remote
            //       sharding. For now we need this because after all the txns are executed, the
            //       proof checker expects the total_supply to read/written to the tree.
            self.base_view.get_state_value(state_key)?;
```
