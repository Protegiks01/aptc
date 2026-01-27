# Audit Report

## Title
Unvalidated Thread Count Parameter in GlobalExecutor Causes Panic on Downstream Assertion

## Summary
The `GlobalExecutor::new()` function accepts a `num_threads` parameter without validation. If `num_threads` is 0, it causes a panic during subsequent execution when `BlockExecutor::new()` asserts that `concurrency_level > 0`. [1](#0-0) 

## Finding Description
The vulnerability exists in a missing input validation at the API boundary. When `GlobalExecutor::new()` is called with `num_threads = 0`:

1. The value is stored as `concurrency_level` without validation
2. It's used to create a thread pool with `num_threads + 2 = 2` (safe for rayon)
3. When `execute_global_txns()` is later invoked, it passes `concurrency_level: 0` to create a `BlockExecutorConfig` [2](#0-1) 

4. This config flows through `ShardedExecutorService::execute_transactions_with_dependencies()` to `AptosVMBlockExecutorWrapper::execute_block_on_thread_pool()` [3](#0-2) 

5. `BlockExecutor::new()` is instantiated with the config containing `concurrency_level = 0`
6. The constructor immediately panics on its assertion: [4](#0-3) 

This violates the fail-fast principle - validation should occur at construction time (`GlobalExecutor::new()`), not during execution.

## Impact Explanation
**Severity: Not exploitable - Does not meet bounty criteria**

While this causes a panic that could crash the executor thread, it **fails the exploitability requirement**:

- **No attacker control**: The only production call site uses `num_cpus::get().min(32)`, which returns ≥1 on all real systems [5](#0-4) 

- **No external input**: The parameter is not exposed through any API accessible to untrusted actors
- **Unrealistic trigger condition**: Would require `num_cpus::get()` to return 0, which violates system assumptions

This is a **defensive programming issue** (missing precondition check), not a security vulnerability exploitable by attackers, malicious validators, or transaction senders.

## Likelihood Explanation
**Likelihood: Negligible in production**

The bug cannot be triggered without:
1. Modifying internal Aptos code to pass `num_threads = 0`
2. Or running on a hypothetical system where `num_cpus::get()` returns 0 (violates all OS assumptions)

There is no realistic attack path from untrusted actors.

## Recommendation
Add defensive validation in `GlobalExecutor::new()`:

```rust
pub fn new(cross_shard_client: Arc<GlobalCrossShardClient>, num_threads: usize) -> Self {
    assert!(num_threads > 0, "num_threads must be positive, got {}", num_threads);
    // ... existing code
}
```

This provides fail-fast behavior and clearer error messages at the API boundary.

## Proof of Concept
```rust
#[test]
#[should_panic(expected = "num_threads must be positive")]
fn test_global_executor_zero_threads() {
    let (cross_shard_tx, cross_shard_rx) = unbounded();
    let client = Arc::new(GlobalCrossShardClient::new(cross_shard_tx, cross_shard_rx));
    let _executor = GlobalExecutor::<MockStateView>::new(client, 0);
}
```

## Notes

**This finding does NOT meet Aptos bug bounty criteria** because:
- ✗ Not exploitable by unprivileged attackers (Validation Check #2 failed)
- ✗ No realistic attack path exists (Validation Check #3 failed)  
- ✗ Requires internal code modification or impossible system conditions

The issue is a **code quality concern** (defensive programming best practice) rather than a security vulnerability. The missing validation violates design principles but poses no actual security risk in production environments.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/global_executor.rs (L27-42)
```rust
    pub fn new(cross_shard_client: Arc<GlobalCrossShardClient>, num_threads: usize) -> Self {
        let executor_thread_pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                // We need two extra threads for the cross-shard commit receiver and the thread
                // that is blocked on waiting for execute block to finish.
                .num_threads(num_threads + 2)
                .build()
                .unwrap(),
        );
        Self {
            global_cross_shard_client: cross_shard_client,
            executor_thread_pool,
            phantom: std::marker::PhantomData,
            concurrency_level: num_threads,
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/global_executor.rs (L44-69)
```rust
    pub fn execute_global_txns(
        &self,
        transactions: Vec<TransactionWithDependencies<AnalyzedTransaction>>,
        state_view: &S,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>, VMStatus> {
        trace!("executing the last round in global executor",);
        if transactions.is_empty() {
            return Ok(vec![]);
        }
        ShardedExecutorService::execute_transactions_with_dependencies(
            None,
            self.executor_thread_pool.clone(),
            transactions,
            self.global_cross_shard_client.clone(),
            None,
            GLOBAL_ROUND_ID,
            state_view,
            BlockExecutorConfig {
                local: BlockExecutorLocalConfig::default_with_concurrency_level(
                    self.concurrency_level,
                ),
                onchain: onchain_config,
            },
        )
    }
```

**File:** aptos-move/aptos-vm/src/block_executor/mod.rs (L545-550)
```rust
        let executor =
            BlockExecutor::<SignatureVerifiedTransaction, E, S, L, TP, AuxiliaryInfo>::new(
                config,
                executor_thread_pool,
                transaction_commit_listener,
            );
```

**File:** aptos-move/block-executor/src/executor.rs (L127-132)
```rust
        assert!(
            config.local.concurrency_level > 0 && config.local.concurrency_level <= num_cpus,
            "Parallel execution concurrency level {} should be between 1 and number of CPUs ({})",
            config.local.concurrency_level,
            num_cpus,
        );
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L71-74)
```rust
        // Limit the number of global executor threads to 32 as parallel execution doesn't scale well beyond that.
        let executor_threads = num_cpus::get().min(32);
        let global_executor = GlobalExecutor::new(cross_shard_client, executor_threads);
        (global_executor, cross_shard_tx)
```
