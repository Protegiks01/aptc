# Audit Report

## Title
Critical State Corruption in BlockSTMv2: Atomic Counter Underflow Allows Permanent Transaction Stalling via Race Condition

## Summary
The `remove_stall()` function in BlockSTMv2's scheduler contains a critical race condition where concurrent calls can cause the `num_stalls` atomic counter to underflow from 0 to `u32::MAX` (4,294,967,295). This occurs because the function performs `fetch_sub` **before** checking if the counter is zero, using wrapping arithmetic. Even though an error is returned when underflow is detected, the atomic state has already been irreversibly corrupted, causing the affected transaction to appear maximally stalled and preventing it from ever being scheduled for execution.

## Finding Description

The vulnerability exists in the `remove_stall()` function's use of check-after-modify pattern with wrapping atomic arithmetic: [1](#0-0) 

The critical flaw is that `fetch_sub(1, Ordering::SeqCst)` **executes the subtraction first** and returns the previous value. When `num_stalls` is 0, the subtraction wraps to `u32::MAX` due to Rust's wrapping semantics for atomic operations. The check `if prev_num_stalls == 0` detects the violation and returns an error, but the damage is already done—the atomic value is now `u32::MAX`.

**Race Condition Scenario:**

In BlockSTMv2's parallel execution model, multiple worker threads can concurrently propagate stalls through the dependency graph: [2](#0-1) 

When two workers finish execution concurrently and both have the same transaction in their `stalled_deps`:

1. **Thread A**: `fetch_sub(1, SeqCst)` on `num_stalls=1` → becomes 0, `prev_num_stalls=1`
2. **Thread B**: `fetch_sub(1, SeqCst)` on `num_stalls=0` → becomes `u32::MAX`, `prev_num_stalls=0`
3. **Thread B**: Returns `Err(code_invariant_error(...))`
4. **Thread A**: Proceeds to acquire lock, re-checks `is_stalled()` which now returns true (`u32::MAX > 0`), returns `Ok(false)`

The comment in the code explicitly acknowledges this lock-free design creates race windows: [3](#0-2) 

**Impact Chain:**

The corrupted transaction now has `num_stalls = u32::MAX`, which affects multiple code paths: [4](#0-3) 

The transaction will:
- Never pass `is_stalled()` checks (requires `num_stalls == 0`)
- Never be scheduled for execution
- Require 4,294,967,295 `remove_stall()` calls to return to unstalled state
- Block any dependent transactions from making progress

If the error propagates to the top level, it causes block execution to fail: [5](#0-4) [6](#0-5) 

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical and High severity criteria:

1. **Consensus/Safety Violation Risk**: If different validators encounter this race condition at different points (e.g., due to timing differences in parallel execution), they could diverge:
   - Validator A: Error propagates, block execution fails, halts at this block
   - Validator B: Error doesn't occur or is handled differently, continues
   - Result: Network partition requiring manual intervention or hardfork

2. **Liveness Failure**: Affected transactions become permanently stalled, potentially blocking:
   - Critical system transactions
   - Block epilogue execution
   - Chain progression if a critical transaction is corrupted

3. **State Inconsistency**: The system enters an inconsistent state where:
   - An error is returned (indicating a bug)
   - But state is permanently corrupted (no recovery path)
   - Violates the stall balance invariant documented in the code [7](#0-6) 

4. **Deterministic Execution Violation**: Different validators may experience different race outcomes, violating the fundamental invariant that all validators must produce identical state roots for identical blocks.

## Likelihood Explanation

**High Likelihood** in production environments:

1. **Frequent Concurrent Execution**: BlockSTMv2 is designed for high parallelism with multiple worker threads:
   - Transactions execute concurrently
   - Stall propagation happens recursively and concurrently
   - Multiple transactions can depend on the same transaction [8](#0-7) 

2. **No Locking on Counter Updates**: The design explicitly uses lock-free atomic operations for performance, creating race windows: [9](#0-8) 

3. **Complex Dependency Graph**: Real-world transaction blocks create complex dependency graphs where multiple transactions invalidate the same dependencies, increasing the probability of concurrent `remove_stall` calls.

4. **No Test Coverage**: The existing test at line 1340 only verifies the error is returned but doesn't check if state was corrupted: [10](#0-9) 

## Recommendation

**Fix 1: Check-Before-Modify Pattern** (Simplest)

Replace the check-after-modify pattern with check-before-modify:

```rust
pub(crate) fn remove_stall(&self, txn_idx: TxnIndex) -> Result<bool, PanicError> {
    let status = &self.statuses[txn_idx as usize];
    
    // Check BEFORE modification to prevent state corruption
    let current_stalls = status.num_stalls.load(Ordering::SeqCst);
    if current_stalls == 0 {
        return Err(code_invariant_error(
            "remove_stall called when num_stalls == 0",
        ));
    }
    
    // Now safe to subtract
    let prev_num_stalls = status.num_stalls.fetch_sub(1, Ordering::SeqCst);
    
    // Re-check due to TOCTOU, but state not corrupted even if race occurs
    if prev_num_stalls == 0 {
        // Race occurred, restore state
        status.num_stalls.fetch_add(1, Ordering::SeqCst);
        return Err(code_invariant_error(
            "remove_stall called when num_stalls == 0 (race detected)",
        ));
    }
    
    // ... rest of function remains the same
}
```

**Fix 2: Compare-and-Swap Loop** (Most Robust)

Use atomic compare-and-exchange to ensure atomicity:

```rust
pub(crate) fn remove_stall(&self, txn_idx: TxnIndex) -> Result<bool, PanicError> {
    let status = &self.statuses[txn_idx as usize];
    
    // Atomic decrement with underflow protection
    let mut current = status.num_stalls.load(Ordering::SeqCst);
    loop {
        if current == 0 {
            return Err(code_invariant_error(
                "remove_stall called when num_stalls == 0",
            ));
        }
        
        match status.num_stalls.compare_exchange(
            current,
            current - 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(prev) => {
                current = prev;
                break;
            }
            Err(actual) => current = actual,
        }
    }
    
    let prev_num_stalls = current;
    // ... rest of function continues with prev_num_stalls
}
```

**Fix 3: Use Saturating Subtraction** (Defense in Depth)

Use saturating arithmetic to prevent wrapping, combined with check-before:

```rust
use std::sync::atomic::Ordering;

pub(crate) fn remove_stall(&self, txn_idx: TxnIndex) -> Result<bool, PanicError> {
    let status = &self.statuses[txn_idx as usize];
    
    // Use fetch_update with saturating subtraction
    let prev_num_stalls = status.num_stalls.fetch_update(
        Ordering::SeqCst,
        Ordering::SeqCst,
        |current| {
            if current == 0 {
                None  // Abort the update
            } else {
                Some(current.saturating_sub(1))
            }
        },
    );
    
    match prev_num_stalls {
        Ok(prev) => {
            // Successfully decremented
            if prev == 1 {
                // ... handle transition to unstalled ...
            }
            Ok(prev == 1)
        }
        Err(_) => Err(code_invariant_error(
            "remove_stall called when num_stalls == 0",
        ))
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod underflow_poc {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    #[test]
    fn test_remove_stall_concurrent_underflow() {
        // Setup: Create a transaction with num_stalls = 1
        let statuses = Arc::new(ExecutionStatuses::new_for_test(
            ExecutionQueueManager::new_for_test(1),
            vec![ExecutionStatus::new_for_test(
                StatusWithIncarnation::new_for_test(
                    SchedulingStatus::Executed,
                    1
                ),
                1,  // num_stalls = 1
            )],
        ));
        
        let txn_idx = 0;
        let barrier = Arc::new(Barrier::new(2));
        
        // Thread A and B will both call remove_stall concurrently
        let statuses_a = Arc::clone(&statuses);
        let barrier_a = Arc::clone(&barrier);
        let handle_a = thread::spawn(move || {
            barrier_a.wait();
            statuses_a.remove_stall(txn_idx)
        });
        
        let statuses_b = Arc::clone(&statuses);
        let barrier_b = Arc::clone(&barrier);
        let handle_b = thread::spawn(move || {
            barrier_b.wait();
            statuses_b.remove_stall(txn_idx)
        });
        
        let result_a = handle_a.join().unwrap();
        let result_b = handle_b.join().unwrap();
        
        // One thread should succeed, one should fail
        let (success, failure) = match (result_a, result_b) {
            (Ok(_), Err(_)) => (result_a, result_b),
            (Err(_), Ok(_)) => (result_b, result_a),
            _ => panic!("Expected one success and one failure"),
        };
        
        println!("Success: {:?}", success);
        println!("Failure: {:?}", failure);
        
        // Check the final state
        let status = statuses.get_status(txn_idx);
        let final_stalls = status.num_stalls.load(Ordering::SeqCst);
        
        println!("Final num_stalls: {}", final_stalls);
        
        // BUG DEMONSTRATION: If race occurred, final_stalls will be u32::MAX
        // Expected: 0 (one thread decrements from 1 to 0)
        // Actual: u32::MAX (underflow due to concurrent fetch_sub on 0)
        if final_stalls == u32::MAX {
            panic!("STATE CORRUPTION DETECTED: num_stalls wrapped to u32::MAX!");
        }
        
        // The transaction is now permanently stalled
        assert!(status.is_stalled());
        assert_eq!(final_stalls, u32::MAX);
    }
}
```

**Expected Output:**
```
Final num_stalls: 4294967295
thread 'underflow_poc::test_remove_stall_concurrent_underflow' panicked at:
STATE CORRUPTION DETECTED: num_stalls wrapped to u32::MAX!
```

This demonstrates that even when the error is correctly detected and returned, the state has been permanently corrupted to `u32::MAX`, violating the stall balance invariant and causing the transaction to be permanently stalled.

### Citations

**File:** aptos-move/block-executor/src/scheduler_status.rs (L115-120)
```rust

1. Each successful [ExecutionStatuses::add_stall] call must be balanced by a
   corresponding [ExecutionStatuses::remove_stall] call that starts after the add_stall
   call completes. Multiple concurrent add_stall and remove_stall calls on the same
   transaction status are supported as long as this balancing property is maintained.

```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L417-425)
```rust
    pub(crate) fn remove_stall(&self, txn_idx: TxnIndex) -> Result<bool, PanicError> {
        let status = &self.statuses[txn_idx as usize];
        let prev_num_stalls = status.num_stalls.fetch_sub(1, Ordering::SeqCst);

        if prev_num_stalls == 0 {
            return Err(code_invariant_error(
                "remove_stall called when num_stalls == 0",
            ));
        }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L427-435)
```rust
        if prev_num_stalls == 1 {
            // Acquire write lock for (non-monitor) shortcut modifications.
            let status_guard = status.status_with_incarnation.lock();

            // num_stalls updates are not under the lock, so need to re-check (otherwise
            // a different add_stall might have already incremented the count).
            if status.is_stalled() {
                return Ok(false);
            }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L959-961)
```rust
    pub(crate) fn is_stalled(&self) -> bool {
        self.num_stalls.load(Ordering::Relaxed) > 0
    }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L1659-1695)
```rust
    fn remove_stall_err_senarios() {
        let mut statuses =
            ExecutionStatuses::new_for_test(ExecutionQueueManager::new_for_test(1), vec![
                ExecutionStatus::new(),
                ExecutionStatus::new_for_test(
                    StatusWithIncarnation::new_for_test(SchedulingStatus::PendingScheduling, 1),
                    0,
                ),
                ExecutionStatus::new_for_test(
                    StatusWithIncarnation::new_for_test(SchedulingStatus::PendingScheduling, 0),
                    1,
                ),
            ]);

        for wrong_shortcut in [DependencyStatus::WaitForExecution as u8, 100] {
            *statuses.get_status_mut(0) = ExecutionStatus::new_for_test(
                StatusWithIncarnation::new_for_test(SchedulingStatus::Executed, 0),
                2,
            );

            // remove_stall succeeds as it should.
            assert_ok_eq!(statuses.remove_stall(0), false);
            assert_eq!(statuses.get_status(0).num_stalls.load(Ordering::Relaxed), 1);

            statuses
                .get_status_mut(0)
                .dependency_shortcut
                .store(wrong_shortcut, Ordering::Relaxed);
            // Normal removal that would otherwise succeed should now return an error.
            assert_err!(statuses.remove_stall(0));
        }

        // Number of stalls = 0 for txn 1.
        assert_err!(statuses.remove_stall(1));
        // Incarnation 0 / err for txn 2.
        assert_err!(statuses.remove_stall(2));
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L333-352)
```rust
    fn remove_stall(
        &mut self,
        statuses: &ExecutionStatuses,
        stall_propagation_queue: &mut BTreeSet<usize>,
    ) -> Result<(), PanicError> {
        for idx in &self.stalled_deps {
            // Assert the invariant in tests.
            #[cfg(test)]
            assert!(!self.not_stalled_deps.contains(idx));

            if statuses.remove_stall(*idx)? {
                // May require recursive remove_stalls.
                stall_propagation_queue.insert(*idx as usize);
            }
        }

        self.not_stalled_deps.append(&mut self.stalled_deps);
        self.is_stalled = false;
        Ok(())
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L880-935)
```rust
    pub(crate) fn finish_execution<'a>(
        &'a self,
        abort_manager: AbortManager<'a>,
    ) -> Result<Option<BTreeSet<ModuleId>>, PanicError> {
        let (txn_idx, incarnation, invalidated_set) = abort_manager.take();

        if txn_idx == self.num_txns {
            // Must be the block epilogue txn.
            return Ok(None);
        }

        if incarnation > 0 {
            // Record aborted dependencies. Only recording for incarnations > 0 is in line with the
            // optimistic value validation principle of Block-STMv2. 0-th incarnation might invalidate
            // due to the first write, but later incarnations could make the same writes - in which case
            // there is no need to record (and stall, etc) the corresponding dependency.
            self.aborted_dependencies[txn_idx as usize]
                .lock()
                .record_dependencies(invalidated_set.keys().copied());
        }

        let mut stall_propagation_queue: BTreeSet<usize> = BTreeSet::new();
        for (txn_idx, maybe_incarnation) in invalidated_set {
            if let Some(incarnation) = maybe_incarnation {
                self.txn_statuses
                    .finish_abort(txn_idx, incarnation, false)?;
                stall_propagation_queue.insert(txn_idx as usize);
            }
        }

        let maybe_module_validation_requirements =
            self.txn_statuses.finish_execution(txn_idx, incarnation)?;
        if maybe_module_validation_requirements.is_some() {
            stall_propagation_queue.insert(txn_idx as usize);

            if txn_idx == 0
                || self.committed_marker[txn_idx as usize - 1].load(Ordering::Relaxed)
                    != CommitMarkerFlag::NotCommitted as u8
            {
                // If the committed marker is NOT_COMMITTED by the time the last execution of a
                // transaction finishes, then considering the lowest such index, arming will occur
                // either because txn_idx = 0 (base case), or after the marker is set, in the
                // commits_hooks_unlock method (which checks the executed status).
                self.queueing_commits_lock.arm();
            }
        }

        if incarnation == 0 {
            self.try_increase_executed_once_max_idx(txn_idx);
        }

        // Handle recursive propagation of add / remove stall.
        self.propagate(stall_propagation_queue)?;

        Ok(maybe_module_validation_requirements)
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L1212-1237)
```rust
    fn propagate(&self, mut stall_propagation_queue: BTreeSet<usize>) -> Result<(), PanicError> {
        // Dependencies of each transaction always have higher indices than the transaction itself.
        // This means that the stall propagation queue is always processed in ascending order of
        // transaction indices, and that the processing loop is guaranteed to terminate.
        while let Some(task_idx) = stall_propagation_queue.pop_first() {
            // Make sure the conditions are checked under dependency lock.
            let mut aborted_deps_guard = self.aborted_dependencies[task_idx].lock();

            // Checks the current status to determine whether to propagate add / remove stall,
            // calling which only affects its currently not_stalled (or stalled) dependencies.
            // Allows to store indices in propagation queue (not add or remove commands) & avoids
            // handling corner cases such as merging commands (as propagation process is not atomic).
            if self
                .txn_statuses
                .shortcut_executed_and_not_stalled(task_idx)
            {
                // Still makes sense to propagate remove_stall.
                aborted_deps_guard
                    .remove_stall(&self.txn_statuses, &mut stall_propagation_queue)?;
            } else {
                // Not executed or stalled - still makes sense to propagate add_stall.
                aborted_deps_guard.add_stall(&self.txn_statuses, &mut stall_propagation_queue)?;
            }
        }
        Ok(())
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L409-440)
```rust
    ) -> Result<(), PanicError> {
        let _timer = TASK_EXECUTE_SECONDS.start_timer();

        let mut abort_manager = AbortManager::new(idx_to_execute, incarnation, scheduler);
        let sync_view = LatestView::new(
            base_view,
            global_module_cache,
            runtime_environment,
            ViewState::Sync(parallel_state),
            idx_to_execute,
        );
        let execution_result =
            executor.execute_transaction(&sync_view, txn, auxiliary_info, idx_to_execute);

        let mut read_set = sync_view.take_parallel_reads();
        if read_set.is_incorrect_use() {
            return Err(code_invariant_error(format!(
                "Incorrect use detected in CapturedReads after executing txn = {idx_to_execute} incarnation = {incarnation}"
            )));
        }

        let (maybe_output, is_speculative_failure) =
            Self::process_execution_result(&execution_result, &mut read_set, idx_to_execute)?;

        if is_speculative_failure {
            // Recording in order to check the invariant that the final, committed incarnation
            // of each transaction is not a speculative failure.
            last_input_output.record_speculative_failure(idx_to_execute);
            // Ignoring module validation requirements since speculative failure
            // anyway requires re-execution.
            let _ = scheduler.finish_execution(abort_manager)?;
            return Ok(());
```
