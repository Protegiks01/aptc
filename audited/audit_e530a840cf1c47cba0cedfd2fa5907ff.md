# Audit Report

## Title
Async Cancellation Vulnerability in TPS Checker Causes Indefinite Worker Task Execution

## Summary
The TPS checker in the node-checker service spawns independent tokio worker tasks that submit transactions to blockchain nodes. If the checker's async operation is cancelled due to HTTP timeout or other interruption before cleanup code executes, these worker tasks continue running indefinitely, causing resource exhaustion and inconsistent system state.

## Finding Description
The vulnerability exists in the async cancellation handling of the TPS checker. The execution flow is:

1. An HTTP request is made to the node-checker service with a 60-second timeout (default) [1](#0-0) 

2. The server-side API handler invokes the runner without any timeout wrapper [2](#0-1) 

3. The TPS checker calls `emit_transactions_with_cluster()` [3](#0-2) 

4. This spawns independent tokio worker tasks via `tokio::spawn()` [4](#0-3) 

5. Workers run in a loop checking a shared `stop` flag [5](#0-4) 

6. The stop flag is only set when `job.stop_job().await` is explicitly called [6](#0-5) 

**The Critical Flaw**: The `EmitJob` struct has no `Drop` implementation to automatically clean up workers. If the async task is cancelled at any `.await` point before reaching line 946 (such as during the sleep at line 942 or due to HTTP timeout), the worker tasks remain running because:
- They were spawned as independent tokio tasks (not bound to parent task lifecycle)
- The stop flag was never set to true
- No cleanup mechanism exists for premature cancellation

Workers continue submitting transactions indefinitely, consuming network bandwidth, CPU cycles, and potentially causing rate limiting or resource exhaustion on target nodes.

## Impact Explanation
This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention"

The vulnerability causes:
1. **Resource Exhaustion**: Worker tasks continue submitting transactions to blockchain nodes indefinitely after checker cancellation
2. **State Inconsistency**: The node-checker service believes the check has completed/failed, but workers remain active
3. **Cascading Failures**: Multiple cancelled TPS checks result in accumulating background workers, amplifying resource consumption
4. **Incorrect Test Results**: Subsequent checks may be affected by workers from previous runs still submitting transactions

While this doesn't directly compromise blockchain consensus or funds, it violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The uncontrolled worker tasks bypass intended resource management.

## Likelihood Explanation
**HIGH likelihood** - This vulnerability is easily triggered:
- Default HTTP timeout of 60 seconds is frequently exceeded during TPS testing
- No special privileges required - any user calling the node-checker API can trigger it
- Network instability or client cancellation naturally causes premature termination
- The TPS checker is a commonly used feature for node validation

An attacker could deliberately trigger this by:
1. Initiating TPS checks against target nodes
2. Cancelling requests before completion
3. Repeating to accumulate background workers
4. Causing resource exhaustion on both the node-checker service and target nodes

## Recommendation
Implement proper async cancellation safety by adding a `Drop` implementation to `EmitJob` that ensures workers are stopped even if the task is cancelled:

```rust
impl Drop for EmitJob {
    fn drop(&mut self) {
        // Signal all workers to stop
        self.stop.store(true, Ordering::Relaxed);
        // Note: We cannot await join_handles in Drop since it's not async
        // Workers will stop at their next loop iteration
    }
}
```

Additionally, wrap the checker execution with an explicit timeout:

```rust
// In ecosystem/node-checker/src/server/api.rs
use tokio::time::timeout;

let complete_evaluation_result = timeout(
    Duration::from_secs(120), // Explicit server-side timeout
    baseline_configuration.runner.run(&target_node_address)
).await.map_err(|_| anyhow!("Checker execution timeout"))?;
```

For more robust cleanup, consider using structured concurrency patterns or tokio's `CancellationToken` to propagate cancellation to spawned tasks.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_tps_checker_cancellation_leak() {
    use ecosystem_node_checker::checker::tps::TpsChecker;
    use tokio::time::{timeout, Duration};
    
    // Configure TPS checker
    let config = TpsCheckerConfig {
        common: CommonCheckerConfig { required: false },
        emit_config: EmitArgs { duration: 30, ..Default::default() },
        // ... other config
    };
    
    let checker = TpsChecker::new(config).unwrap();
    let providers = setup_test_providers();
    
    // Start checker but cancel it before completion
    let check_future = checker.check(&providers);
    let result = timeout(Duration::from_secs(5), check_future).await;
    
    // Checker was cancelled due to timeout
    assert!(result.is_err());
    
    // Wait a moment
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Verify workers are still running by checking if transactions
    // are still being submitted to the test node
    let ongoing_txns = check_pending_transactions(&test_node).await;
    assert!(ongoing_txns > 0, "Worker tasks leaked - still submitting transactions");
}
```

**Notes**

This vulnerability is specific to the TPS checker due to its use of spawned worker tasks. Other checkers that only use sequential async operations without spawning independent tasks are not affected. The issue stems from a fundamental async safety principle: spawned tasks must have explicit cleanup mechanisms since they don't participate in structured concurrency.

### Citations

**File:** ecosystem/node-checker/fn-check-client/src/check.rs (L62-64)
```rust
        let nhc_client = ReqwestClient::builder()
            .timeout(Duration::from_secs(self.nhc_timeout_secs))
            .build()
```

**File:** ecosystem/node-checker/src/server/api.rs (L89-92)
```rust
        let complete_evaluation_result = baseline_configuration
            .runner
            .run(&target_node_address)
            .await;
```

**File:** ecosystem/node-checker/src/checker/tps.rs (L141-149)
```rust
        let stats = emit_transactions_with_cluster(
            &cluster,
            &self.config.emit_config,
            self.config
                .emit_workload_configs
                .args_to_transaction_mix_per_phase(),
        )
        .await
        .map_err(TpsCheckerError::TransactionEmitterError)?;
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L899-904)
```rust
        let workers = submission_workers
            .into_iter()
            .map(|worker| Worker {
                join_handle: tokio_handle.spawn(worker.run(phase_start).boxed()),
            })
            .collect();
```

**File:** crates/transaction-emitter-lib/src/emitter/mod.rs (L946-946)
```rust
        let stats = job.stop_job().await;
```

**File:** crates/transaction-emitter-lib/src/emitter/submission_worker.rs (L93-93)
```rust
        while !self.stop.load(Ordering::Relaxed) {
```
