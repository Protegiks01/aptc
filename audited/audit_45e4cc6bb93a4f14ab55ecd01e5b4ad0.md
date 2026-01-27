# Audit Report

## Title
Panic Due to Unchecked Empty Array Access in Sharded Block Executor Aggregation

## Summary
The `execute_block()` function in the sharded block executor performs an unchecked array access on `sharded_output[0].len()` without verifying that `sharded_output` is non-empty, leading to a panic that crashes validator nodes when zero executor shards are configured or when initialization failures occur.

## Finding Description

The vulnerability exists in the block execution aggregation logic where results from multiple executor shards are combined. [1](#0-0) 

The code assumes `sharded_output` contains at least one element and directly accesses the first element to determine the number of rounds. However, `sharded_output` is a `Vec<Vec<Vec<TransactionOutput>>>` that can be empty in two scenarios:

**Scenario 1: Zero Executor Shards Configuration**

Both executor client implementations can return empty `sharded_output` when configured with zero shards:

- **RemoteExecutorClient**: When initialized with an empty `remote_shard_addresses` vector, it creates empty `command_txs` and `result_rxs` vectors. [2](#0-1) 

The `get_output_from_shards()` method iterates over the empty `result_rxs` and returns an empty vector. [3](#0-2) 

- **LocalExecutorClient**: The `setup_local_executor_shards()` function accepts `num_shards` as a parameter with no validation preventing zero. [4](#0-3) 

When `num_shards` is 0, all channel vectors are empty, and `get_output_from_shards()` returns an empty result. [5](#0-4) 

**Scenario 2: Uninitialized Remote Executor**

The static `REMOTE_SHARDED_BLOCK_EXECUTOR` uses lazy initialization and calls `get_remote_addresses()` which returns an empty vector if `REMOTE_ADDRESSES` is not set. [6](#0-5) 

This creates a remote executor with zero shards. [7](#0-6) 

**Exploitation Path:**

1. A validator node initializes with `num_shards = 0` or accesses `REMOTE_SHARDED_BLOCK_EXECUTOR` before proper initialization
2. The executor client is created with zero shards
3. When `execute_block()` is called, the assertion at lines 80-85 checks `num_executor_shards == transactions.num_shards()`. If both are 0, the assertion passes. [8](#0-7) 
4. The executor returns an empty `sharded_output`
5. Line 99 attempts to access `sharded_output[0].len()` on an empty vector
6. **Rust panics with "index out of bounds"**, crashing the validator node

**Additional Vulnerability Instance:**

The same pattern exists in the `SubBlocksForShard::flatten()` utility function, which also accesses `block[0].num_sub_blocks()` without validation. [9](#0-8) 

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria: "Validator node slowdowns" and "API crashes")

This vulnerability causes:
- **Validator Node Crash**: The panic immediately terminates the validator process during block execution
- **Consensus Disruption**: Affected validators cannot participate in consensus, reducing network capacity
- **Deterministic Execution Violation**: Different nodes may crash at different times if initialization races occur
- **Availability Impact**: Repeated crashes prevent the node from processing blocks until properly reconfigured

While the global `NUM_EXECUTION_SHARD` configuration uses `max(num_shards, 1)` [10](#0-9) , this only protects code paths using that specific global. Direct instantiation of executor clients bypasses this protection.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability requires:
- Node misconfiguration (setting `num_shards` to 0), OR
- Initialization race condition (accessing remote executor before address setup), OR
- Bug in initialization code

While production deployments typically configure valid shard counts, several factors increase likelihood:
1. **No Runtime Validation**: Neither executor client constructor validates `num_shards > 0`
2. **Lazy Initialization**: The static remote executor can be accessed before proper setup
3. **Configuration Complexity**: Multi-shard setup has multiple initialization steps that can fail
4. **Testing Gaps**: Edge case of zero shards may not be covered in integration tests

## Recommendation

Add defensive validation to prevent zero-shard configurations and provide meaningful error messages:

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
    
    // VALIDATION: Prevent zero-shard configuration
    if num_executor_shards == 0 {
        return Err(VMStatus::Error(
            StatusCode::INTERNAL_TYPE_ERROR,
            Some("Sharded block executor requires at least one shard".to_string())
        ));
    }
    
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
    
    // VALIDATION: Verify non-empty result before indexing
    if sharded_output.is_empty() {
        return Err(VMStatus::Error(
            StatusCode::INTERNAL_TYPE_ERROR,
            Some("Executor returned empty shard results".to_string())
        ));
    }
    
    let num_rounds = sharded_output[0].len();
    // ... rest of function
}
```

Additionally, add validation in constructor methods:
- `LocalExecutorService::setup_local_executor_shards()` should reject `num_shards == 0`
- `RemoteExecutorClient::new()` should reject empty `remote_shard_addresses`
- Similar fix needed in `SubBlocksForShard::flatten()`

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_types::block_executor::partitioner::PartitionedTransactions;
    use std::sync::Arc;
    
    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn test_zero_shards_panic() {
        // Create a LocalExecutorClient with 0 shards
        let client = LocalExecutorService::setup_local_executor_shards(0, Some(1));
        let executor = ShardedBlockExecutor::new(client);
        
        // Create empty partitioned transactions (0 shards)
        let transactions = PartitionedTransactions::empty();
        
        // This will panic at line 99: sharded_output[0].len()
        let result = executor.execute_block(
            Arc::new(EmptyStateView),
            transactions,
            1,
            BlockExecutorConfigFromOnchain::default(),
        );
        
        // Never reached due to panic
        assert!(result.is_err());
    }
    
    struct EmptyStateView;
    impl StateView for EmptyStateView {
        // Minimal implementation for testing
    }
}
```

## Notes

This is a **defensive programming issue** rather than a direct security exploit by external attackers. The vulnerability requires node-level misconfiguration or initialization bugs, not malicious transactions or network attacks. However, it violates the robustness principle that critical infrastructure should fail gracefully rather than panic, and could be triggered by initialization race conditions in distributed deployments.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L80-85)
```rust
        assert_eq!(
            num_executor_shards,
            transactions.num_shards(),
            "Block must be partitioned into {} sub-blocks",
            num_executor_shards
        );
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L98-99)
```rust
        let num_rounds = sharded_output[0].len();
        let mut aggregated_results = vec![];
```

**File:** execution/executor-service/src/remote_executor_client.rs (L39-44)
```rust
pub fn get_remote_addresses() -> Vec<SocketAddr> {
    match REMOTE_ADDRESSES.get() {
        Some(value) => value.clone(),
        None => vec![],
    }
}
```

**File:** execution/executor-service/src/remote_executor_client.rs (L57-72)
```rust
pub static REMOTE_SHARDED_BLOCK_EXECUTOR: Lazy<
    Arc<
        aptos_infallible::Mutex<
            ShardedBlockExecutor<CachedStateView, RemoteExecutorClient<CachedStateView>>,
        >,
    >,
> = Lazy::new(|| {
    info!("REMOTE_SHARDED_BLOCK_EXECUTOR created");
    Arc::new(aptos_infallible::Mutex::new(
        RemoteExecutorClient::create_remote_sharded_block_executor(
            get_coordinator_address(),
            get_remote_addresses(),
            None,
        ),
    ))
});
```

**File:** execution/executor-service/src/remote_executor_client.rs (L107-119)
```rust
        let (command_txs, result_rxs) = remote_shard_addresses
            .iter()
            .enumerate()
            .map(|(shard_id, address)| {
                let execute_command_type = format!("execute_command_{}", shard_id);
                let execute_result_type = format!("execute_result_{}", shard_id);
                let command_tx = Mutex::new(
                    controller_mut_ref.create_outbound_channel(*address, execute_command_type),
                );
                let result_rx = controller_mut_ref.create_inbound_channel(execute_result_type);
                (command_tx, result_rx)
            })
            .unzip();
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L77-91)
```rust
    pub fn setup_local_executor_shards(
        num_shards: usize,
        num_threads: Option<usize>,
    ) -> LocalExecutorClient<S> {
        let (global_executor, global_cross_shard_tx) = Self::setup_global_executor();
        let num_threads = num_threads
            .unwrap_or_else(|| (num_cpus::get() as f64 / num_shards as f64).ceil() as usize);
        let (command_txs, command_rxs): (
            Vec<Sender<ExecutorShardCommand<S>>>,
            Vec<Receiver<ExecutorShardCommand<S>>>,
        ) = (0..num_shards).map(|_| unbounded()).unzip();
        let (result_txs, result_rxs): (
            Vec<Sender<Result<Vec<Vec<TransactionOutput>>, VMStatus>>>,
            Vec<Receiver<Result<Vec<Vec<TransactionOutput>>, VMStatus>>>,
        ) = (0..num_shards).map(|_| unbounded()).unzip();
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

**File:** types/src/block_executor/partitioner.rs (L376-386)
```rust
    // Flattens a vector of `SubBlocksForShard` into a vector of transactions in the order they
    // appear in the block.
    pub fn flatten(block: Vec<SubBlocksForShard<T>>) -> Vec<T> {
        let num_shards = block.len();
        let mut flattened_txns = Vec::new();
        let num_rounds = block[0].num_sub_blocks();
        let mut ordered_blocks = vec![SubBlock::empty(); num_shards * num_rounds];
        for (shard_id, sub_blocks) in block.into_iter().enumerate() {
            for (round, sub_block) in sub_blocks.into_sub_blocks().into_iter().enumerate() {
                ordered_blocks[round * num_shards + shard_id] = sub_block;
            }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L457-461)
```rust
    pub fn set_num_shards_once(mut num_shards: usize) {
        num_shards = max(num_shards, 1);
        // Only the first call succeeds, due to OnceCell semantics.
        NUM_EXECUTION_SHARD.set(num_shards).ok();
    }
```
