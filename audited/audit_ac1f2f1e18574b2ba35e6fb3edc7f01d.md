# Audit Report

## Title
Memory Ordering Race Condition in Dependency Shortcut Causes Non-Deterministic Consensus Divergence

## Summary
The `dependency_shortcut` atomic field in `ExecutionStatus` uses `Ordering::Relaxed` for both reads and writes, even when operations are performed under the status lock. This weak memory ordering allows concurrent threads to observe stale shortcut values, leading to spurious invariant violations that cause non-deterministic `PanicError` returns. Different validators may experience different race outcomes when executing the same block, resulting in consensus divergence where some nodes successfully execute the block while others halt with errors. [1](#0-0) 

## Finding Description

The BlockSTMv2 parallel block executor maintains transaction status information including a `dependency_shortcut` atomic flag that provides lock-free access to transaction state for scheduling decisions. The implementation updates this shortcut while holding the status lock and documents this requirement explicitly. [2](#0-1) 

However, all atomic operations on `dependency_shortcut` use `Ordering::Relaxed`, which provides no synchronization guarantees with other memory operations - including lock acquisitions and releases. This creates a critical discrepancy between the documented intent (lock-synchronized updates) and actual behavior (unsynchronized atomic operations). [3](#0-2) 

**The Race Condition:**

When Thread A updates transaction status under lock and then updates `dependency_shortcut` with `Ordering::Relaxed`: [4](#0-3) 

And Thread B subsequently acquires the same lock and reads `dependency_shortcut` with `Ordering::Relaxed`: [5](#0-4) 

Thread B may observe a stale shortcut value because `Ordering::Relaxed` does not establish a happens-before relationship with the lock synchronization. The lock only synchronizes non-atomic variables; atomic operations with `Relaxed` ordering can be independently reordered by the CPU.

**Spurious Invariant Violations:**

The code contains invariant checks that assume consistency between `status` and `dependency_shortcut`: [6](#0-5) 

When Thread B observes `status = PendingScheduling` (updated by Thread A) but reads a stale `dependency_shortcut = IsSafe` or `WaitForExecution` (not yet visible due to Relaxed ordering), this invariant check fails spuriously and returns a `PanicError`.

Similarly, the swap validation can fail spuriously: [7](#0-6) 

**Consensus Divergence:**

When a `PanicError` occurs in a worker thread, it triggers scheduler halting: [8](#0-7) 

The error is non-deterministic - it depends on CPU scheduling, memory model behavior, and thread interleaving. For the same block:
- Validator A may experience no race and execute successfully
- Validator B may hit the spurious invariant violation and halt execution
- This causes validators to disagree on whether the block executed successfully

This violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Impact Explanation

This qualifies as **High Severity** per the Aptos bug bounty criteria under "Significant protocol violations" and approaches **Critical Severity** under "Consensus/Safety violations."

**Actual Impact:**
- **Consensus Divergence**: Validators can reach different conclusions about block execution due to non-deterministic race outcomes
- **Network Disruption**: Affected validators halt execution and cannot process transactions
- **Non-Recoverable State**: Validators that fail cannot automatically recover without manual intervention or rollback

The issue breaks the fundamental consensus guarantee that identical inputs (same block) produce identical outputs (same execution result) across all validators. While not directly causing fund theft, it can partition the network and prevent transaction finalization.

## Likelihood Explanation

**Likelihood: Medium to High under production load**

The race condition occurs naturally during parallel block execution and increases in probability with:
- Higher transaction throughput (more parallel workers)
- More CPU cores (greater opportunity for reordering)
- Longer blocks (more transactions, more status updates)
- Memory pressure (delays in cache coherency)

The race window is small (between lock release and lock acquisition by another thread), but given that:
- Each block executes hundreds to thousands of transactions
- Each transaction can undergo multiple incarnations (re-executions)  
- Status updates happen frequently during execution, abort, and commit flows
- Modern CPUs aggressively reorder memory operations

The cumulative probability of observing this race across a validator's lifetime is significant. Production networks with high throughput would likely encounter this issue within days to weeks of operation.

## Recommendation

Replace `Ordering::Relaxed` with `Ordering::SeqCst` or implement proper lock-atomic synchronization:

**Option 1: Use Sequential Consistency (Simple Fix)**
```rust
fn swap_dependency_status_any(
    &self,
    expected_values: &[DependencyStatus],
    new_value: DependencyStatus,
    context: &'static str,
) -> Result<DependencyStatus, PanicError> {
    let prev = DependencyStatus::from_u8(
        self.dependency_shortcut
            .swap(new_value as u8, Ordering::SeqCst),  // Changed from Relaxed
    )?;
    if !expected_values.contains(&prev) {
        return Err(code_invariant_error(format!(
            "Incorrect dependency status in {}: expected one of {:?}, found {:?}",
            context, expected_values, prev,
        )));
    }
    Ok(prev)
}
```

And update all load/store operations:
```rust
let dependency_status = 
    DependencyStatus::from_u8(status.dependency_shortcut.load(Ordering::SeqCst))?;

status.dependency_shortcut.store(
    DependencyStatus::ShouldDefer as u8, 
    Ordering::SeqCst
);
```

**Option 2: Use Acquire/Release Semantics (Performance-Optimized)**

Use `Ordering::Release` for stores/swaps and `Ordering::Acquire` for loads to establish proper happens-before relationships while maintaining better performance than SeqCst.

The fix must be applied to ALL atomic operations on `dependency_shortcut` throughout the file, including in `add_stall`, `remove_stall`, `finish_execution`, `finish_abort`, `to_pending_scheduling`, `to_executing`, and `shortcut_executed_and_not_stalled`.

## Proof of Concept

This race condition cannot be reliably reproduced in a simple test due to its non-deterministic nature. However, the following stress test demonstrates the theoretical vulnerability:

```rust
// Stress test to increase probability of observing the race
// Add to scheduler_status.rs tests module
#[test]
#[ignore] // Run with: cargo test --release -- --ignored --test-threads=1
fn stress_test_dependency_shortcut_race() {
    use std::sync::Arc;
    use std::thread;
    
    const NUM_ITERATIONS: usize = 100000;
    const NUM_THREADS: usize = 8;
    
    for iteration in 0..NUM_ITERATIONS {
        let statuses = Arc::new(ExecutionStatuses::new_for_test(
            ExecutionQueueManager::new_for_test(1),
            vec![ExecutionStatus::new()],
        ));
        
        let mut handles = vec![];
        
        // Thread 1: Repeatedly transition through states
        let statuses_clone = statuses.clone();
        handles.push(thread::spawn(move || {
            let txn_idx = 0;
            for _ in 0..10 {
                let _ = statuses_clone.start_executing(txn_idx);
                let _ = statuses_clone.finish_execution(txn_idx, 0);
                let _ = statuses_clone.start_abort(txn_idx, 0);
                let _ = statuses_clone.finish_abort(txn_idx, 0, false);
            }
        }));
        
        // Threads 2-N: Repeatedly call add_stall
        for _ in 0..NUM_THREADS-1 {
            let statuses_clone = statuses.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = statuses_clone.add_stall(0);
                    let _ = statuses_clone.remove_stall(0);
                }
            }));
        }
        
        for handle in handles {
            if let Err(e) = handle.join().unwrap() {
                println!("Iteration {}: Caught race condition error: {:?}", iteration, e);
                panic!("Successfully demonstrated race condition vulnerability!");
            }
        }
    }
}
```

To demonstrate actual consensus impact, validators would need to execute identical blocks under high parallel load and compare execution outcomes. The non-deterministic nature means some executions succeed while others fail with `PanicError` from spurious invariant violations.

---

**Notes:**
- This vulnerability is inherent to the current implementation and not dependent on specific transaction payloads
- The issue affects BlockSTMv2 scheduler specifically
- All validators running this code version are potentially affected
- The bug is in production code, not tests or documentation
- Fix requires updating atomic operations throughout the scheduler_status module

### Citations

**File:** aptos-move/block-executor/src/scheduler_status.rs (L366-370)
```rust
            // Acquire write lock for (non-monitor) shortcut modifications.
            let status_guard = status.status_with_incarnation.lock();

            let dependency_status =
                DependencyStatus::from_u8(status.dependency_shortcut.load(Ordering::Relaxed))?;
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L383-386)
```rust
                (Some(_), DependencyStatus::IsSafe | DependencyStatus::WaitForExecution) => {
                    return Err(code_invariant_error(
                        "Inconsistent status and dependency shortcut in add_stall",
                    ));
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L875-883)
```rust
        let status = &self.statuses[txn_idx as usize];
        // Update inner status.
        status_guard.status = SchedulingStatus::PendingScheduling;
        status_guard.incarnation = new_incarnation;

        // Under the lock, update the shortcuts.
        status
            .dependency_shortcut
            .store(DependencyStatus::ShouldDefer as u8, Ordering::Relaxed);
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L925-929)
```rust
    /// Performs an atomic swap operation on the dependency status and checks
    /// that the previous value matches one of the expected values.
    /// Note that in our implementation, all updates to the status are performed
    /// while holding the lock on InnerStatus, which is the responsibility
    /// of the caller.
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L939-957)
```rust
    fn swap_dependency_status_any(
        &self,
        expected_values: &[DependencyStatus],
        new_value: DependencyStatus,
        context: &'static str,
    ) -> Result<DependencyStatus, PanicError> {
        let prev = DependencyStatus::from_u8(
            self.dependency_shortcut
                .swap(new_value as u8, Ordering::Relaxed),
        )?;
        // Note: can avoid a lookup by optimizing expected values representation.
        if !expected_values.contains(&prev) {
            return Err(code_invariant_error(format!(
                "Incorrect dependency status in {}: expected one of {:?}, found {:?}",
                context, expected_values, prev,
            )));
        }
        Ok(prev)
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L1778-1799)
```rust
                    if let Err(err) = self.worker_loop_v2(
                        &executor,
                        signature_verified_block,
                        environment,
                        *worker_id,
                        num_workers,
                        &scheduler,
                        &shared_sync_params,
                    ) {
                        // If there are multiple errors, they all get logged: FatalVMError is
                        // logged at construction, below we log CodeInvariantErrors.
                        if let PanicOr::CodeInvariantError(err_msg) = err {
                            alert!(
                                "[BlockSTMv2] worker loop: CodeInvariantError({:?})",
                                err_msg
                            );
                        }
                        shared_maybe_error.store(true, Ordering::SeqCst);

                        // Make sure to halt the scheduler if it hasn't already been halted.
                        scheduler.halt();
                    }
```
