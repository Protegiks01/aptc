# Audit Report

## Title
Index-Out-of-Bounds Panic in Sharded Execution Result Aggregation Causes Validator Crash

## Summary
The `ShardedBlockExecutor::execute_block` method aggregates execution results from multiple executor shards without validating that all shards returned the same number of rounds. When a malicious or compromised remote executor shard provides mismatched vector dimensions in its `Vec<Vec<TransactionOutput>>` response, the aggregation logic performs an out-of-bounds array access, causing an immediate panic that crashes the validator node.

## Finding Description

The vulnerability exists in the result aggregation logic of the sharded block executor: [1](#0-0) 

The vulnerable code path operates as follows:

1. **Remote executor shards return results**: Each remote shard executes its assigned sub-blocks and returns `Vec<Vec<TransactionOutput>>` where the outer vector represents rounds and inner vectors contain transaction outputs for that round. [2](#0-1) 

2. **No validation on result collection**: The coordinator collects results from all shards without validating dimensional consistency: [3](#0-2) 

3. **Unsafe aggregation assumptions**: The aggregation logic assumes all shards returned the same number of rounds by only checking the first shard's dimension, then creates a fixed-size `ordered_results` vector. When iterating through shards with potentially different round counts, the index calculation `round * num_executor_shards + shard_id` can exceed vector bounds.

**Attack Scenario:**
- The legitimate partitioner ensures all shards receive SubBlocksForShard with identical round counts: [4](#0-3) 

- However, a compromised remote executor shard can ignore the input structure and fabricate results with arbitrary dimensions, as there is no validation: [5](#0-4) 

**Example**: If 4 shards with 2 rounds expected:
- `num_rounds = sharded_output[0].len()` = 2
- `ordered_results` size = 4 × 2 = 8
- If malicious shard[1] returns 3 rounds:
  - Round 2: `ordered_results[2 * 4 + 1]` = `ordered_results[9]` → **PANIC: index out of bounds**

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Crash**: The panic immediately terminates the validator process, causing a complete loss of that validator's participation in consensus.

2. **Network Liveness Impact**: If multiple validators use remote execution infrastructure and a single remote shard is compromised, all connected validators crash when processing blocks assigned to that shard, significantly degrading network liveness.

3. **Deterministic Exploitation**: Unlike consensus attacks requiring stake or coordination, a single compromised remote executor shard can deterministically crash validators with a malformed response.

4. **Defense-in-Depth Violation**: The system fails to validate outputs from remote components, violating the security principle that all external inputs must be validated.

The impact aligns with "Validator node slowdowns" and "Significant protocol violations" (High Severity, up to $50,000), as validator crashes directly impact network availability and violate the **Deterministic Execution** invariant (all validators must successfully process identical blocks).

## Likelihood Explanation

**Moderate to High Likelihood** depending on deployment configuration:

1. **Requires Remote Executor Infrastructure**: The vulnerability only affects validators using remote executor shards (configured via `set_remote_addresses`). Local execution is not vulnerable because all shards run in-process with deterministic behavior.

2. **Single Point of Compromise**: Only ONE remote executor shard needs to be compromised or contain a bug. This is more feasible than multi-party collusion attacks.

3. **No Stake Required**: Unlike Byzantine consensus attacks, the attacker needs no stake in the network—only the ability to compromise or operate a malicious remote executor.

4. **Accidental Triggering**: Even non-malicious bugs in remote executor implementations could trigger this panic if they cause dimensional mismatches.

The likelihood increases if:
- Remote execution is widely adopted for performance optimization
- Remote executor shards are operated by different entities with varying security practices
- Remote executor code has implementation bugs causing non-deterministic result dimensions

## Recommendation

Implement strict validation of result dimensions before aggregation:

```rust
pub fn execute_block(
    &self,
    state_view: Arc<S>,
    transactions: PartitionedTransactions,
    concurrency_level_per_shard: usize,
    onchain_config: BlockExecutorConfigFromOnchain,
) -> Result<Vec<TransactionOutput>, VMStatus> {
    let _timer = SHARDED_BLOCK_EXECUTION_SECONDS.start_timer();
    let num_executor_shards = self.executor_client.num_shards();
    NUM_EXECUTOR_SHARDS.set(num_executor_shards as i64);
    assert_eq!(
        num_executor_shards,
        transactions.num_shards(),
        "Block must be partitioned into {} sub-blocks",
        num_executor_shards
    );
    let (sharded_output, global_output) = self
        .executor_client
        .execute_block(
            state_view,
            transactions,
            concurrency_level_per_shard,
            onchain_config,
        )?
        .into_inner();
    
    // VALIDATION: Ensure all shards returned results
    if sharded_output.is_empty() {
        return Err(VMStatus::Error(StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION));
    }
    
    // VALIDATION: Ensure all shards returned the same number of rounds
    let num_rounds = sharded_output[0].len();
    for (shard_id, results) in sharded_output.iter().enumerate().skip(1) {
        if results.len() != num_rounds {
            return Err(VMStatus::Error(StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION));
        }
    }
    
    info!("ShardedBlockExecutor Received all results");
    let _aggregation_timer = SHARDED_EXECUTION_RESULT_AGGREGATION_SECONDS.start_timer();
    let mut aggregated_results = vec![];
    let mut ordered_results = vec![vec![]; num_executor_shards * num_rounds];
    // ... rest of aggregation logic
```

Additionally, consider adding validation in `RemoteExecutorClient::get_output_from_shards` to fail fast when receiving malformed results from remote shards.

## Proof of Concept

A malicious remote executor shard can trigger this vulnerability by returning extra rounds:

```rust
// In a compromised RemoteCoordinatorClient implementation:
impl CoordinatorClient<RemoteStateViewClient> for MaliciousRemoteCoordinatorClient {
    fn send_execution_result(&self, mut result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
        // Inject an extra round to cause index-out-of-bounds panic
        if let Ok(ref mut rounds) = result {
            // Add a fake extra round with empty transactions
            rounds.push(vec![]);
        }
        
        let remote_execution_result = RemoteExecutionResult::new(result);
        let output_message = bcs::to_bytes(&remote_execution_result).unwrap();
        self.result_tx.send(Message::new(output_message)).unwrap();
    }
}
```

When the coordinator aggregates results with this extra round:
1. Shard 0 returns 2 rounds → `num_rounds = 2`, `ordered_results.len() = 8`
2. Malicious shard 1 returns 3 rounds
3. During iteration: `ordered_results[2 * 4 + 1] = ordered_results[9]` 
4. **Result**: `thread 'main' panicked at 'index out of bounds: the len is 8 but the index is 9'`

**Notes**

While this vulnerability requires compromised remote executor infrastructure, it represents a critical defensive programming failure. The validation present in test utilities confirms the expected invariant but is absent from production code: [6](#0-5) 

The system correctly ensures input consistency during partitioning but fails to validate output consistency during aggregation, creating an exploitable gap when using remote executors. This violates defense-in-depth principles and the system's **Deterministic Execution** invariant, as validators cannot safely process blocks when remote components provide malformed results.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L86-115)
```rust
        let (sharded_output, global_output) = self
            .executor_client
            .execute_block(
                state_view,
                transactions,
                concurrency_level_per_shard,
                onchain_config,
            )?
            .into_inner();
        // wait for all remote executors to send the result back and append them in order by shard id
        info!("ShardedBlockExecutor Received all results");
        let _aggregation_timer = SHARDED_EXECUTION_RESULT_AGGREGATION_SECONDS.start_timer();
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

**File:** execution/executor-service/src/remote_cordinator_client.rs (L115-119)
```rust
    fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
        let remote_execution_result = RemoteExecutionResult::new(result);
        let output_message = bcs::to_bytes(&remote_execution_result).unwrap();
        self.result_tx.send(Message::new(output_message)).unwrap();
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L163-172)
```rust
    fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
        trace!("RemoteExecutorClient Waiting for results");
        let mut results = vec![];
        for rx in self.result_rxs.iter() {
            let received_bytes = rx.recv().unwrap().to_bytes();
            let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes).unwrap();
            results.push(result.inner?);
        }
        Ok(results)
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

**File:** execution/block-partitioner/src/v2/build_edge.rs (L72-88)
```rust
        let final_num_rounds = state.sub_block_matrix.len();
        let sharded_txns = (0..state.num_executor_shards)
            .map(|shard_id| {
                let sub_blocks: Vec<SubBlock<AnalyzedTransaction>> = (0..final_num_rounds)
                    .map(|round_id| {
                        state.sub_block_matrix[round_id][shard_id]
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                    })
                    .collect();
                SubBlocksForShard::new(shard_id, sub_blocks)
            })
            .collect();

        PartitionedTransactions::new(sharded_txns, global_txns)
```

**File:** execution/block-partitioner/src/test_utils.rs (L165-172)
```rust
    let num_rounds = output
        .sharded_txns()
        .first()
        .map(|sbs| sbs.sub_blocks.len())
        .unwrap_or(0);
    for sub_block_list in output.sharded_txns().iter().take(num_shards).skip(1) {
        assert_eq!(num_rounds, sub_block_list.sub_blocks.len());
    }
```
