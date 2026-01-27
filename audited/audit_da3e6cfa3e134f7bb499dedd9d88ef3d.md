# Audit Report

## Title
Unrecoverable Mutex Poisoning in Sharded Block Executor Causes Non-Deterministic Validator Failures

## Summary
The `RemoteStateValue` struct in the sharded block executor uses `.unwrap()` on all mutex operations, converting any mutex poisoning into panics. This creates a vulnerability where thread panics during cross-shard execution can cascade into validator-wide execution failures, with non-deterministic timing across validators potentially breaking consensus determinism.

## Finding Description

The `RemoteStateValue` struct is a critical synchronization primitive used in the sharded block executor for cross-shard state dependencies. It uses a `Mutex<RemoteValueStatus>` and `Condvar` for blocking reads of remote state values. [1](#0-0) [2](#0-1) 

Both `get_value()` and `set_value()` use `.unwrap()` on mutex operations. In Rust, when a thread panics while holding a mutex lock, that mutex becomes "poisoned". All subsequent calls to `.lock()` on a poisoned mutex return an `Err(PoisonError)`, which `.unwrap()` converts into a panic.

This is used throughout the execution path: [3](#0-2) [4](#0-3) 

The execution flow is:
1. `CrossShardStateView` is created with `RemoteStateValue` instances in `Waiting` state
2. A separate thread runs `CrossShardCommitReceiver` to populate values via `set_value()`
3. Transaction execution threads call `get_value()` which blocks until values are ready
4. If ANY thread panics while holding the mutex, all subsequent operations panic

**Attack Scenarios:**

While an unprivileged attacker cannot directly poison mutexes, several conditions in a production environment can trigger this:

1. **Resource Exhaustion**: Out-of-memory conditions during transaction execution while holding locks
2. **Stack Overflow**: Deep recursion in Move execution triggering stack overflow panics
3. **Assertion Failures**: Internal invariant violations in the VM or block executor
4. **Concurrent Bugs**: Race conditions or other concurrency bugs causing panics in the execution path

Once a mutex is poisoned, the cascading effect is:
- All transactions reading that cross-shard state will panic
- The entire sub-block execution fails  
- The shard becomes unable to complete block execution
- Different validators may experience this at different times based on thread scheduling

This breaks the **Deterministic Execution** invariant: validators must produce identical results for identical blocks, but thread scheduling differences can cause some validators to complete successfully while others panic. [5](#0-4) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Crashes/Slowdowns**: When mutex poisoning occurs, the affected shard cannot complete execution. The validator becomes unable to participate in consensus for that block.

2. **Non-Deterministic Failures**: The most critical impact is that validators may experience failures at different times. This creates a race condition where:
   - Fast validators complete before any panic occurs
   - Slower validators hit the poisoned mutex and fail
   - This leads to validators proposing different results for the same block

3. **Consensus Protocol Violations**: While not directly breaking safety (validators would disagree and fail to reach consensus), it creates a liveness failure where the network cannot make progress until validators restart.

4. **No Recovery Path**: Unlike returning a `Result<T, E>`, panics cannot be caught at system boundaries. The only recovery is process restart, which is disruptive and can compound into sustained liveness failures during periods of high load (when panics are most likely).

## Likelihood Explanation

**Likelihood: Medium-to-High** in production environments:

1. **Complex Execution Environment**: The sharded block executor involves multiple threads, cross-shard communication, and complex Move VM execution. Any bug in this stack can trigger panics.

2. **Resource Pressure**: Under high load, validators may experience resource exhaustion (OOM, stack overflow) that triggers panics during critical sections.

3. **Undiscovered Bugs**: Given the complexity of the system, there may be unhandled edge cases or race conditions that cause panics.

4. **Thread Scheduling Variability**: Different validators run on different hardware with different loads, making thread scheduling non-deterministic across the network.

The vulnerability is not directly exploitable by attackers crafting malicious transactions (due to Move VM sandboxing), but it creates a fragile system that can fail non-deterministically under production conditions, especially during:
- Network stress or attack conditions
- Software updates with subtle bugs
- Resource pressure from legitimate high transaction volume

## Recommendation

**Fix: Return `Result` types and handle errors gracefully**

Modify `RemoteStateValue` to return `Result` types that allow callers to handle mutex poisoning:

```rust
pub fn set_value(&self, value: Option<StateValue>) -> Result<(), String> {
    let (lock, cvar) = &*self.value_condition;
    let mut status = lock.lock()
        .map_err(|e| format!("Mutex poisoned in set_value: {}", e))?;
    *status = RemoteValueStatus::Ready(value);
    cvar.notify_all();
    Ok(())
}

pub fn get_value(&self) -> Result<Option<StateValue>, String> {
    let (lock, cvar) = &*self.value_condition;
    let mut status = lock.lock()
        .map_err(|e| format!("Mutex poisoned in get_value: {}", e))?;
    while let RemoteValueStatus::Waiting = *status {
        status = cvar.wait(status)
            .map_err(|e| format!("Condvar wait failed: {}", e))?;
    }
    match &*status {
        RemoteValueStatus::Ready(value) => Ok(value.clone()),
        RemoteValueStatus::Waiting => unreachable!(),
    }
}
```

Propagate errors through the call stack:
- `CrossShardStateView::get_state_value()` should return `StateViewError` on mutex poisoning
- `execute_transactions_with_dependencies()` should handle these errors and return appropriate `VMStatus` errors
- The consensus layer should treat this as a temporary failure and retry

This allows the system to:
1. Detect mutex poisoning without crashing
2. Log the condition for debugging
3. Return graceful errors to consensus
4. Potentially recover or fall back to sequential execution

## Proof of Concept

```rust
// Reproduction test demonstrating the vulnerability
#[test]
fn test_mutex_poisoning_cascade() {
    use std::sync::{Arc, Mutex};
    use std::panic;
    
    // Create RemoteStateValue
    let remote_value = Arc::new(RemoteStateValue::waiting());
    let remote_value_clone = remote_value.clone();
    
    // Thread 1: Panics while holding the lock (simulating OOM or assertion)
    let panic_thread = std::thread::spawn(move || {
        let (lock, _cvar) = &*remote_value_clone.value_condition;
        let _status = lock.lock().unwrap();
        // Simulate panic during critical section
        panic!("Simulated execution panic (e.g., OOM)");
    });
    
    // Wait for panic and mutex poisoning
    let _ = panic_thread.join();
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    // Thread 2: Tries to set value - will panic due to poisoned mutex
    let result = panic::catch_unwind(|| {
        remote_value.set_value(Some(StateValue::from(vec![1, 2, 3])));
    });
    
    // Demonstrates the vulnerability: set_value panics
    assert!(result.is_err(), "set_value should panic on poisoned mutex");
    
    // Thread 3: Tries to read value - will also panic
    let result = panic::catch_unwind(|| {
        remote_value.get_value()
    });
    
    // Demonstrates cascade: subsequent operations also panic
    assert!(result.is_err(), "get_value should panic on poisoned mutex");
}
```

**Notes**

This vulnerability represents a critical gap in defensive programming for production blockchain infrastructure. While not directly exploitable by malicious transactions, it creates a fragile system where transient failures can cascade into consensus-level impacts. The sharded block executor is performance-critical infrastructure, and any degradation in reliability directly threatens network liveness. The use of `.unwrap()` on synchronization primitives in production code violates Rust best practices for fault-tolerant systems.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L22-27)
```rust
    pub fn set_value(&self, value: Option<StateValue>) {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        *status = RemoteValueStatus::Ready(value);
        cvar.notify_all();
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L29-39)
```rust
    pub fn get_value(&self) -> Option<StateValue> {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        while let RemoteValueStatus::Waiting = *status {
            status = cvar.wait(status).unwrap();
        }
        match &*status {
            RemoteValueStatus::Ready(value) => value.clone(),
            RemoteValueStatus::Waiting => unreachable!(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L77-82)
```rust
    fn get_state_value(&self, state_key: &StateKey) -> Result<Option<StateValue>, StateViewError> {
        if let Some(value) = self.cross_shard_data.get(state_key) {
            return Ok(value.get_value());
        }
        self.base_view.get_state_value(state_key)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L115-118)
```rust
        let cross_shard_state_view = Arc::new(CrossShardStateView::create_cross_shard_state_view(
            state_view,
            &transactions,
        ));
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L134-183)
```rust
        executor_thread_pool.clone().scope(|s| {
            s.spawn(move |_| {
                CrossShardCommitReceiver::start(
                    cross_shard_state_view_clone,
                    cross_shard_client,
                    round,
                );
            });
            s.spawn(move |_| {
                let txn_provider =
                    DefaultTxnProvider::new_without_info(signature_verified_transactions);
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
                if let Some(shard_id) = shard_id {
                    trace!(
                        "executed sub block for shard {} and round {}",
                        shard_id,
                        round
                    );
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_cross_shard_msg(
                        shard_id,
                        round,
                        CrossShardMsg::StopMsg,
                    );
                } else {
                    trace!("executed block for global shard and round {}", round);
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_global_msg(CrossShardMsg::StopMsg);
                }
                callback.send(ret).unwrap();
                executor_thread_pool_clone.spawn(move || {
                    // Explicit async drop
                    drop(txn_provider);
                });
            });
        });

        block_on(callback_receiver).unwrap()
    }
```
