# Audit Report

## Title
Panic on Block Execution Due to Missing Executor Client Initialization Validation

## Summary
The `ShardedBlockExecutor::new()` function accepts an `ExecutorClient` without validating that it has at least one shard configured. During block execution, the code unsafely accesses `sharded_output[0]` without checking if the vector is empty, causing a panic if the executor client was initialized with zero shards.

## Finding Description

The vulnerability exists in the initialization and execution flow of the sharded block executor: [1](#0-0) 

The `new()` constructor accepts any `ExecutorClient` implementation without validating that `num_shards() > 0`. It only logs the number of shards but performs no validation.

The critical unsafe access occurs in `execute_block()`: [2](#0-1) 

At line 98, the code directly accesses `sharded_output[0].len()` without checking if `sharded_output` is empty. If the executor client has 0 shards, this causes an **index out of bounds panic**.

**Attack Vector:**

The `RemoteExecutorClient` initialization has a critical flaw where remote addresses default to an empty vector: [3](#0-2) 

The `REMOTE_SHARDED_BLOCK_EXECUTOR` static variable uses this function during lazy initialization: [4](#0-3) 

**Exploitation Path:**
1. If `REMOTE_SHARDED_BLOCK_EXECUTOR` is accessed before `set_remote_addresses()` is called
2. `get_remote_addresses()` returns an empty vector (default state)
3. `RemoteExecutorClient::new()` creates a client with 0 shards
4. `ShardedBlockExecutor::new()` accepts this malformed client with no validation
5. When `execute_block()` is later called, it panics at line 98 accessing empty `sharded_output[0]`

This breaks the **Deterministic Execution** and **Resource Limits** invariants, as the node crashes unexpectedly during block execution rather than handling the error gracefully.

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria because it causes:
- **State inconsistency requiring intervention**: Node crash during block execution disrupts consensus participation
- **Validator node availability issue**: Affected validators cannot process blocks, reducing network liveness
- **Undefined behavior**: Panic causes ungraceful shutdown rather than controlled error handling

It does not reach High severity because:
- No funds are lost or stolen
- Does not directly violate consensus safety (though liveness is affected)
- Requires misconfiguration rather than direct attack

## Likelihood Explanation

**Medium to Low Likelihood:**

The vulnerability requires specific initialization ordering:
- Accessing the executor before proper configuration
- Race condition between lazy initialization and configuration setup
- More likely in testing/development environments or deployment errors

However, the likelihood is non-zero because:
- The default behavior is unsafe (empty vec rather than error)
- No compile-time enforcement of initialization order
- Could occur during node startup race conditions

## Recommendation

Implement defensive validation at multiple layers:

**1. Add validation in `ShardedBlockExecutor::new()`:**
```rust
pub fn new(executor_client: C) -> Self {
    let num_shards = executor_client.num_shards();
    assert!(num_shards > 0, "Executor client must have at least one shard configured");
    info!(
        "Creating a new ShardedBlockExecutor with {} shards",
        num_shards
    );
    Self {
        executor_client,
        phantom: PhantomData,
    }
}
```

**2. Add safe access in `execute_block()`:**
```rust
let num_rounds = if sharded_output.is_empty() {
    0
} else {
    sharded_output[0].len()
};
```

**3. Fix `get_remote_addresses()` to error on uninitialized state:**
```rust
pub fn get_remote_addresses() -> Vec<SocketAddr> {
    match REMOTE_ADDRESSES.get() {
        Some(value) => {
            assert!(!value.is_empty(), "Remote addresses must not be empty");
            value.clone()
        },
        None => panic!("Remote addresses not configured - call set_remote_addresses() first"),
    }
}
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_zero_shard_executor_panics() {
    use aptos_types::block_executor::partitioner::PartitionedTransactions;
    use aptos_types::block_executor::config::BlockExecutorConfigFromOnchain;
    use std::sync::Arc;
    
    // Create a mock state view
    let state_view = Arc::new(MockStateView::new());
    
    // Create executor client with 0 shards (empty addresses)
    let executor_client = RemoteExecutorClient::new(
        vec![], // Empty addresses = 0 shards
        NetworkController::new(
            "test-coordinator".to_string(),
            "127.0.0.1:52200".parse().unwrap(),
            5000,
        ),
        None,
    );
    
    // Create sharded block executor - no validation!
    let executor = ShardedBlockExecutor::new(executor_client);
    
    // Create empty partitioned transactions (0 shards)
    let transactions = PartitionedTransactions::empty(0);
    let onchain_config = BlockExecutorConfigFromOnchain::default();
    
    // This will panic at sharded_output[0].len()
    let _ = executor.execute_block(
        state_view,
        transactions,
        1,
        onchain_config,
    );
}
```

## Notes

This vulnerability demonstrates a defensive programming failure where the API accepts invalid inputs without validation. While the normal initialization paths through `AptosVM::get_num_shards()` enforce at least 1 shard, the remote executor path has an unsafe default that can lead to crashes.

The fix should enforce the invariant that **all executor clients must have at least one shard configured** at construction time, preventing the system from ever entering an invalid state rather than failing at usage time.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L53-62)
```rust
    pub fn new(executor_client: C) -> Self {
        info!(
            "Creating a new ShardedBlockExecutor with {} shards",
            executor_client.num_shards()
        );
        Self {
            executor_client,
            phantom: PhantomData,
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L86-98)
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
