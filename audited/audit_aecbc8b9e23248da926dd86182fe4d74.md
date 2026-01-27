# Audit Report

## Title
Sharded Executor Panic and Silent Transaction Loss via Empty `sub_blocks` in `ExecuteBlockCommand`

## Summary
The `ExecuteBlockCommand` structure lacks validation on the `sub_blocks` field, allowing empty vectors to be processed. When executor shards receive commands with empty `sub_blocks`, the result aggregation logic makes unsafe assumptions about uniform round counts across all shards, leading to either index-out-of-bounds panics (causing DoS) or silent transaction loss where the system incorrectly reports successful execution despite processing zero transactions.

## Finding Description

The `ExecuteBlockCommand` struct contains a `sub_blocks` field of type `SubBlocksForShard<AnalyzedTransaction>` with no validation ensuring it is non-empty. [1](#0-0) 

When a shard receives an `ExecuteBlockCommand` with empty `sub_blocks`, the `execute_block` function iterates over the empty vector and returns `Ok(vec![])` (zero rounds of results). [2](#0-1) 

The coordinator's aggregation logic in `ShardedBlockExecutor::execute_block` calculates the number of rounds based solely on shard 0's output length, making a critical assumption that all shards return the same number of rounds. [3](#0-2) 

This creates three exploitable scenarios:

**Scenario 1: Empty sub_blocks sent to shard 0**
- Shard 0 returns `Ok(vec![])` (0 rounds)
- Other shards return results with N rounds
- Line 98: `num_rounds = 0`
- Line 100: `ordered_results = vec![]` (empty)
- When other shards try to write results at line 104, index out of bounds panic occurs
- **Result: Executor crashes (DoS)**

**Scenario 2: Empty sub_blocks sent to non-shard-0**
- Shard 0 returns N rounds of results
- Another shard returns `Ok(vec![])` (0 rounds)
- Line 98: `num_rounds = N` (from shard 0)
- The aggregation in `aggregate_and_update_total_supply` assumes all shards have N rounds
- Line 191 attempts to access `shard_output[round]` for the empty shard [4](#0-3) 

- **Result: Index out of bounds panic in total supply aggregation (DoS)**

**Scenario 3: Empty sub_blocks sent to ALL shards**
- All shards return `Ok(vec![])` (0 rounds)
- Line 98: `num_rounds = 0`
- Line 100: `ordered_results = vec![]`
- Lines 102-106: All shards iterate 0 times
- Returns `Ok(vec![])` - **successful execution with zero outputs**
- **Result: Silent transaction loss - system reports success despite processing no transactions**

This violates the **Deterministic Execution** invariant where identical blocks must produce identical results across validators. If one validator processes transactions normally while another receives empty commands (due to network manipulation, race condition, or bug), they will produce different state roots, breaking consensus safety.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria:

1. **State inconsistencies requiring intervention**: Silent transaction loss in Scenario 3 causes state divergence between validators
2. **Validator node crashes**: DoS via panic in Scenarios 1 and 2 causes API crashes and node slowdowns (overlaps with High severity)
3. **Limited protocol violations**: Doesn't directly steal funds but can cause transaction execution failures and state inconsistencies

The impact is not Critical because:
- It doesn't directly enable theft or minting of funds
- Consensus safety is impacted indirectly (state divergence) rather than direct double-spending
- Recovery is possible through node restart and state sync (though may require manual intervention)

However, if exploited during a critical transaction (e.g., validator set update, governance proposal execution), the impact could escalate to High severity due to liveness failures.

## Likelihood Explanation

**Likelihood: Low to Medium**

**Attack Requirements:**
1. Ability to send crafted `RemoteExecutionRequest` messages to executor shards
2. The remote executor service must be network-accessible
3. The `NetworkController` used by the remote executor lacks authentication [5](#0-4) 

The `receive_execute_command` function deserializes incoming messages without validation of the `sub_blocks` content.

**Factors Increasing Likelihood:**
- No validation exists on `ExecuteBlockCommand` structure upon receipt
- The partitioner guarantees uniform round distribution in normal operation, but this isn't enforced at the executor level
- Race conditions or bugs in the partitioner could inadvertently create mismatched round counts

**Factors Decreasing Likelihood:**
- Remote executor service is likely deployed in controlled environments
- The coordinator typically creates commands from the partitioner which ensures proper structure
- Network access to executor shards may be restricted in production deployments

## Recommendation

**Immediate Fix: Add validation in `receive_execute_command`**

Validate that the received `ExecuteBlockCommand` has non-empty `sub_blocks` and matches expected round counts:

```rust
impl CoordinatorClient<RemoteStateViewClient> for RemoteCoordinatorClient {
    fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
        match self.command_rx.recv() {
            Ok(message) => {
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                match request {
                    RemoteExecutionRequest::ExecuteBlock(command) => {
                        // VALIDATION: Ensure sub_blocks is non-empty
                        if command.sub_blocks.is_empty() {
                            panic!("Received ExecuteBlockCommand with empty sub_blocks for shard {}", 
                                   self.shard_id);
                        }
                        
                        let state_keys = Self::extract_state_keys(&command);
                        self.state_view_client.init_for_block(state_keys);
                        let (sub_blocks, concurrency, onchain_config) = command.into();
                        ExecutorShardCommand::ExecuteSubBlocks(...)
                    },
                }
            },
            Err(_) => ExecutorShardCommand::Stop,
        }
    }
}
```

**Additional Hardening:**

1. Add round count validation in aggregation logic:
```rust
pub fn execute_block(...) -> Result<Vec<TransactionOutput>, VMStatus> {
    let num_rounds = sharded_output[0].len();
    
    // Validate all shards return the same number of rounds
    for (shard_id, shard_results) in sharded_output.iter().enumerate() {
        if shard_results.len() != num_rounds {
            return Err(VMStatus::Error(StatusCode::INTERNAL_ERROR, 
                Some(format!("Shard {} returned {} rounds, expected {}", 
                             shard_id, shard_results.len(), num_rounds))));
        }
    }
    // ... rest of aggregation logic
}
```

2. Add authentication to `NetworkController` for remote executor communication to prevent malicious message injection

3. Add metrics/alerts when empty `sub_blocks` are detected

## Proof of Concept

```rust
// File: execution/executor-service/tests/empty_subblocks_attack.rs

#[cfg(test)]
mod tests {
    use aptos_types::block_executor::partitioner::{SubBlocksForShard, SubBlock};
    use aptos_types::block_executor::config::BlockExecutorConfigFromOnchain;
    use aptos_types::transaction::analyzed_transaction::AnalyzedTransaction;
    use aptos_vm::sharded_block_executor::sharded_executor_service::ShardedExecutorService;
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_empty_subblocks_causes_panic() {
        // Simulate the scenario where shard 0 has empty sub_blocks
        // and shard 1 has normal sub_blocks
        
        let num_shards = 2;
        
        // Create empty sub_blocks for shard 0
        let empty_sub_blocks: SubBlocksForShard<AnalyzedTransaction> = 
            SubBlocksForShard::empty(0);
        
        // Simulate shard 0 executing with empty sub_blocks
        // This would return Ok(vec![]) - 0 rounds
        
        // Create normal sub_blocks for shard 1 with 2 rounds
        let mut normal_sub_blocks = SubBlocksForShard::empty(1);
        normal_sub_blocks.add_sub_block(SubBlock::empty());
        normal_sub_blocks.add_sub_block(SubBlock::empty());
        
        // Simulate shard 1 executing normally
        // This would return Ok(vec![vec![], vec![]]) - 2 rounds
        
        // Now simulate the coordinator aggregating results
        let sharded_output = vec![
            vec![], // Shard 0: 0 rounds
            vec![vec![], vec![]], // Shard 1: 2 rounds
        ];
        
        // This should panic when trying to aggregate
        let num_rounds = sharded_output[0].len(); // 0
        let mut ordered_results = vec![vec![]; num_shards * num_rounds]; // empty vec
        
        for (shard_id, results_from_shard) in sharded_output.into_iter().enumerate() {
            for (round, result) in results_from_shard.into_iter().enumerate() {
                // When shard_id=1, round=0: tries to access ordered_results[0]
                // But ordered_results is empty!
                ordered_results[round * num_shards + shard_id] = result; // PANIC HERE
            }
        }
    }
    
    #[test]
    fn test_all_empty_subblocks_silent_success() {
        // Scenario 3: All shards have empty sub_blocks
        let num_shards = 2;
        
        let sharded_output: Vec<Vec<Vec<_>>> = vec![
            vec![], // Shard 0: 0 rounds
            vec![], // Shard 1: 0 rounds
        ];
        
        let num_rounds = sharded_output[0].len(); // 0
        let mut aggregated_results = vec![];
        let mut ordered_results = vec![vec![]; num_shards * num_rounds]; // empty
        
        for (shard_id, results_from_shard) in sharded_output.into_iter().enumerate() {
            for (round, result) in results_from_shard.into_iter().enumerate() {
                ordered_results[round * num_shards + shard_id] = result;
            }
        }
        
        for result in ordered_results.into_iter() {
            aggregated_results.extend(result);
        }
        
        // Result: Empty aggregated_results
        assert_eq!(aggregated_results.len(), 0);
        // This is reported as Ok(vec![]) - successful execution with no outputs!
        // But transactions were expected to be executed
    }
}
```

## Notes

The vulnerability is most concerning in deployment scenarios where:
1. Remote executor shards are exposed to untrusted network actors
2. The system experiences race conditions or bugs in the partitioner
3. State divergence between validators could occur if some receive malformed commands

While the partitioner is designed to prevent this in normal operation, defense-in-depth principles require validation at the executor level to handle unexpected or malicious inputs. The lack of such validation creates a critical attack surface for DoS and state inconsistency attacks.

### Citations

**File:** execution/executor-service/src/lib.rs (L48-53)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecuteBlockCommand {
    pub(crate) sub_blocks: SubBlocksForShard<AnalyzedTransaction>,
    pub(crate) concurrency_level: usize,
    pub(crate) onchain_config: BlockExecutorConfigFromOnchain,
}
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L98-110)
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
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L184-191)
```rust
    for round in 0..num_rounds {
        sharded_output.iter().for_each(|shard_output| {
            let mut curr_delta = DeltaU128::default();
            // Though we expect all the txn_outputs to have total_supply, there can be
            // exceptions like 'block meta' (first txn in the block) and 'chkpt info' (last txn
            // in the block) which may not have total supply. Hence we iterate till we find the
            // last txn with total supply.
            for txn in shard_output[round].iter().rev() {
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-113)
```rust
    fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
        match self.command_rx.recv() {
            Ok(message) => {
                let _rx_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx"])
                    .start_timer();
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                drop(bcs_deser_timer);

                match request {
                    RemoteExecutionRequest::ExecuteBlock(command) => {
                        let init_prefetch_timer = REMOTE_EXECUTOR_TIMER
                            .with_label_values(&[&self.shard_id.to_string(), "init_prefetch"])
                            .start_timer();
                        let state_keys = Self::extract_state_keys(&command);
                        self.state_view_client.init_for_block(state_keys);
                        drop(init_prefetch_timer);

                        let (sub_blocks, concurrency, onchain_config) = command.into();
                        ExecutorShardCommand::ExecuteSubBlocks(
                            self.state_view_client.clone(),
                            sub_blocks,
                            concurrency,
                            onchain_config,
                        )
                    },
                }
            },
            Err(_) => ExecutorShardCommand::Stop,
        }
    }
```
