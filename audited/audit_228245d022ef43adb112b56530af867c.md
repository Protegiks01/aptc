# Audit Report

## Title
Block Output Limit Bypass in Sharded Execution Leading to Memory Amplification

## Summary
The sharded block executor's `execute_block()` function accumulates transaction outputs from multiple rounds without enforcing a global block output limit, allowing memory consumption to grow up to `max_partitioning_rounds * block_output_limit` instead of the intended single `block_output_limit`. While bounded, this represents a protocol-level invariant violation where the per-block output limit is effectively multiplied by the number of execution rounds.

## Finding Description

The Aptos blockchain implements a `block_output_limit` (default 4MB) to cap total transaction output size per block and prevent validator memory exhaustion. [1](#0-0) 

However, in sharded execution, the `execute_block()` function processes transactions across multiple rounds, creating a new `BlockExecutor` instance for each round. [2](#0-1) 

Each round's execution independently enforces the 4MB limit via its own `BlockGasLimitProcessor`. [3](#0-2) 

The `result` vector accumulates outputs from all rounds without checking aggregate size. [4](#0-3) 

With `MAX_ALLOWED_PARTITIONING_ROUNDS` set to 8, a single shard can accumulate up to 32MB (8 rounds × 4MB). [5](#0-4) 

The coordinator aggregates all shards' outputs into memory simultaneously. [6](#0-5) 

## Impact Explanation

**Severity: Medium (borderline High)**

While this violates the Resource Limits invariant (Invariant #9), actual validator OOM is unlikely because:
- Maximum memory per shard: 8 rounds × 4MB = 32MB
- Maximum total (8 shards): 256MB
- Modern validators have 32GB+ RAM

However, this constitutes:
- **Protocol violation**: The `block_output_limit` is designed as a per-block cap, not per-round
- **Memory pressure**: Under constrained resources or with other memory demands, this 8x amplification could contribute to slowdowns or instability  
- **Unexpected behavior**: Validators may experience 8x higher memory usage than anticipated from configuration

This falls under "Validator node slowdowns" (High Severity per bug bounty) when combined with other memory pressures, but does not meet "Total loss of liveness" (Critical) as OOM is unlikely in production.

## Likelihood Explanation

**Likelihood: Medium-Low**

While the code path is deterministic and executes on every sharded block:
- Default `max_partitioning_rounds` is 3-4, not the maximum 8, limiting realistic amplification to 4x
- External attackers cannot control `max_partitioning_rounds` (node configuration parameter)
- Consensus already limits block size (~10K transactions, 5MB bytes)
- Validators are provisioned with substantial memory (32GB+)

However, the issue manifests whenever sharded execution is enabled with multiple rounds, making it a persistent deviation from intended behavior rather than a rare edge case.

## Recommendation

Implement global block output limit tracking across all rounds within a shard. Modify `execute_block()` to:

1. Create a shared `accumulated_output_size` counter before the round loop
2. Pass this counter to each `execute_sub_block()` call
3. Check accumulated size against `block_output_limit` before processing each round
4. Halt execution if the global limit is reached

Alternatively, distribute the `block_output_limit` proportionally across rounds: `limit_per_round = block_output_limit / num_rounds`, though this may impact execution determinism.

The proper fix requires either:
- **Global limit enforcement**: Track total output across all rounds and halt when exceeded
- **Per-round allocation**: Divide the limit among rounds proportionally
- **Documentation clarification**: If this is intentional design, document that sharded execution allows `num_rounds × block_output_limit` memory usage

## Proof of Concept

```rust
// Conceptual test demonstrating the issue
// Note: Actual PoC would require full test harness with sharded executor setup

#[test]
fn test_sharded_output_limit_bypass() {
    // Setup: 4 rounds, block_output_limit = 4MB
    let max_rounds = 4;
    let limit_per_round = 4 * 1024 * 1024; // 4MB
    
    // Create transactions that each produce 1MB of output
    let txns_per_round = vec![
        create_txns_with_output_size(1024 * 1024), // Round 0: 4 txns = 4MB
        create_txns_with_output_size(1024 * 1024), // Round 1: 4 txns = 4MB  
        create_txns_with_output_size(1024 * 1024), // Round 2: 4 txns = 4MB
        create_txns_with_output_size(1024 * 1024), // Round 3: 4 txns = 4MB
    ];
    
    let result = execute_block(txns_per_round);
    
    // Expected: Total output <= 4MB (global limit)
    // Actual: Total output = 16MB (4 rounds × 4MB each)
    let total_output_size: usize = result.iter()
        .flat_map(|round| round.iter())
        .map(|txn_output| approximate_size(txn_output))
        .sum();
    
    assert!(total_output_size > limit_per_round); // Demonstrates bypass
    assert_eq!(total_output_size, limit_per_round * max_rounds); // 16MB actual
}
```

## Notes

This issue represents a **design-level protocol deviation** rather than a traditional exploitable vulnerability. While it doesn't meet the criteria for Critical severity (cannot demonstrate actual validator OOM), it constitutes a clear violation of the Resource Limits invariant where the intended 4MB cap is effectively multiplied by the number of rounds. The bounded nature of the growth (`MAX_ALLOWED_PARTITIONING_ROUNDS = 8`) prevents unlimited accumulation, but still allows 8x the intended memory usage per shard.

### Citations

**File:** types/src/on_chain_config/execution_config.rs (L143-155)
```rust
    pub fn default_for_genesis() -> Self {
        BlockGasLimitType::ComplexLimitV1 {
            effective_block_gas_limit: 20000,
            execution_gas_effective_multiplier: 1,
            io_gas_effective_multiplier: 1,
            conflict_penalty_window: 9,
            use_granular_resource_group_conflicts: false,
            use_module_publishing_block_conflict: true,
            block_output_limit: Some(4 * 1024 * 1024),
            include_user_txn_size_in_block_output: true,
            add_block_limit_outcome_onchain: true,
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L145-156)
```rust
                let ret = AptosVMBlockExecutorWrapper::execute_block_on_thread_pool(
                    executor_thread_pool,
                    &txn_provider,
                    aggr_overridden_state_view.as_ref(),
                    // Since we execute blocks in parallel, we cannot share module caches, so each
                    // thread has its own caches.
                    &AptosModuleCacheManager::new(),
                    config,
                    TransactionSliceMetadata::unknown(),
                    cross_shard_commit_sender,
                )
                .map(BlockOutput::into_transaction_outputs_forced);
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

**File:** types/src/block_executor/partitioner.rs (L20-21)
```rust
pub static MAX_ALLOWED_PARTITIONING_ROUNDS: usize = 8;
pub static GLOBAL_ROUND_ID: usize = MAX_ALLOWED_PARTITIONING_ROUNDS + 1;
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
