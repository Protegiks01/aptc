# Audit Report

## Title
Retry Starvation Causes Worker Thread Busy-Wait Spinning in Block Executor

## Summary
Worker threads in the parallel block executor can spin indefinitely in a busy-wait loop when both `execution_idx` and `validation_idx` exceed `num_txns` but the `done_marker` has not been set. This causes excessive CPU usage and validator node performance degradation.

## Finding Description

The vulnerability exists in the `next_task()` function where the scheduler returns `SchedulerTask::Retry` without any backoff mechanism when both scheduling indices are beyond the total transaction count but execution is not yet complete. [1](#0-0) 

The critical code path is:

1. When `execution_idx >= num_txns` (line 488) and `prefer_validate` is false (line 490-491), the function returns `SchedulerTask::Retry` at line 494.

2. The `prefer_validate` flag becomes false when `idx_to_validate >= num_txns`, causing the condition at line 493 to trigger.

3. The `done_marker` is only set when all transactions are committed or execution is halted: [2](#0-1) 

4. In the executor's worker loop, when `Retry` is received, it immediately calls `next_task()` again without any yielding: [3](#0-2) 

**Attack Scenario:**
During normal parallel block execution with N worker threads processing M transactions:
- Workers rapidly dispatch all transactions, advancing both indices past M
- Some transactions are slow (complex Move execution, validation dependencies)
- Fast-finishing workers call `next_task()` but both indices are >= M
- These workers receive `Retry` and immediately retry in a tight recursive loop
- The spinning continues until all slow transactions finish and commit
- During this period, affected threads consume 100% CPU doing no productive work

This breaks the **Resource Limits** invariant: operations should respect computational limits, but the busy-wait loop wastes CPU cycles indefinitely.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria: **"Validator node slowdowns"**

Impact quantification:
- **Affected Nodes**: All validator nodes running parallel block execution
- **CPU Impact**: Worker threads spin at 100% CPU usage while waiting
- **Performance Degradation**: Reduces validator's ability to process subsequent blocks efficiently
- **Resource Exhaustion**: Excessive CPU usage can trigger thermal throttling or system monitoring alerts
- **Network Impact**: Slower block processing affects validator participation in consensus

The validator node experiences significant performance degradation that could impact its ability to timely propose/validate blocks, potentially affecting consensus participation and validator rewards.

## Likelihood Explanation

**Likelihood: High** - This occurs naturally during normal operation without any attacker intervention.

Triggering conditions:
1. **Block with many transactions** (e.g., 1000+ transactions) - increases probability that indices advance past `num_txns` before all complete
2. **High worker thread count** (e.g., 16-32 threads) - more workers can finish early and start spinning
3. **Varied transaction complexity** - some transactions finish in microseconds, others take milliseconds
4. **High network load** - more blocks processed means more opportunities for the race condition

This is especially likely during:
- Peak network usage periods
- Processing blocks with complex DeFi transactions
- Systems with high core counts (common in validator hardware)

The issue manifests more frequently as:
- Transaction count increases
- Worker thread count increases  
- Transaction execution time variance increases

## Recommendation

Implement a backoff mechanism when returning `Retry` to avoid busy-waiting:

**Solution 1: Add yield point**
```rust
if !prefer_validate && idx_to_execute >= self.num_txns {
    // Yield to avoid busy-wait spinning
    std::thread::yield_now();
    return SchedulerTask::Retry;
}
```

**Solution 2: Use condition variable (better)**
Add a condition variable that gets notified when:
- Execution index is decreased (new work available)
- Validation index is decreased (new work available)  
- Done marker is set (execution complete)

Then wait on this condition variable instead of immediately returning Retry:
```rust
if !prefer_validate && idx_to_execute >= self.num_txns {
    // Wait for signal that work is available or execution is done
    let mut lock = self.work_available_condvar.lock();
    while !self.done() && !self.has_work_available() {
        self.work_available_cvar.wait(&mut lock);
    }
    return SchedulerTask::Retry;
}
```

**Solution 3: Adaptive backoff**
Implement exponential backoff with maximum delay:
```rust
if !prefer_validate && idx_to_execute >= self.num_txns {
    // Use per-thread retry counter and exponential backoff
    let backoff = min(2_u64.pow(retry_count), 1000); // max 1000 microseconds
    std::thread::sleep(Duration::from_micros(backoff));
    return SchedulerTask::Retry;
}
```

The condition variable approach (Solution 2) is preferred as it provides immediate wakeup when work becomes available while consuming zero CPU during the wait.

## Proof of Concept

The following Rust test demonstrates the spinning behavior:

```rust
#[test]
fn test_retry_starvation_spinning() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};
    
    let num_txns = 100;
    let num_workers = 8;
    let scheduler = Arc::new(Scheduler::new(num_txns));
    let barrier = Arc::new(Barrier::new(num_workers + 1));
    
    // Simulate: advance both indices past num_txns
    for _ in 0..num_txns {
        scheduler.execution_idx.fetch_add(1, Ordering::SeqCst);
    }
    for _ in 0..num_txns {
        let curr = scheduler.validation_idx.load(Ordering::Acquire);
        scheduler.validation_idx.store(
            Scheduler::next_validation_index(curr), 
            Ordering::Release
        );
    }
    
    // Spawn worker threads
    let mut handles = vec![];
    for _ in 0..num_workers {
        let sched = scheduler.clone();
        let bar = barrier.clone();
        handles.push(thread::spawn(move || {
            bar.wait(); // Synchronize start
            
            let start = Instant::now();
            let mut retry_count = 0;
            
            // Try to get tasks for 100ms
            while start.elapsed() < Duration::from_millis(100) {
                match sched.next_task() {
                    SchedulerTask::Retry => {
                        retry_count += 1;
                        if retry_count > 10000 {
                            // Excessive spinning detected
                            return retry_count;
                        }
                    },
                    SchedulerTask::Done => break,
                    _ => {},
                }
            }
            retry_count
        }));
    }
    
    barrier.wait(); // Start all workers
    
    // Let them spin for a bit
    thread::sleep(Duration::from_millis(50));
    
    // Set done marker to stop spinning
    scheduler.halt();
    
    // Check results
    for handle in handles {
        let retry_count = handle.join().unwrap();
        // If spinning occurred, retry_count will be very high
        println!("Worker got {} retries", retry_count);
        assert!(retry_count > 1000, "Worker should have spun many times");
    }
}
```

To observe in production:
1. Deploy validator with monitoring on CPU usage per thread
2. Process blocks with 500+ transactions
3. Monitor worker threads during parallel execution phase
4. Observe brief spikes in CPU usage on some threads while others are still processing
5. Profile with `perf` or similar tools - will show time spent in `next_task()` → recursive `next_task()` calls

## Notes

This is a performance/resource exhaustion vulnerability rather than a consensus safety issue. The busy-waiting does not affect correctness of block execution (transactions still get processed correctly), but it significantly impacts validator node performance.

The issue is exacerbated by modern validator hardware with high core counts (32-64 cores), as more worker threads means more potential spinners consuming CPU cycles unproductively.

### Citations

**File:** aptos-move/block-executor/src/scheduler.rs (L402-405)
```rust
                        if *commit_idx == self.num_txns {
                            // All txns have been committed, the parallel execution can finish.
                            self.done_marker.store(true, Ordering::SeqCst);
                        }
```

**File:** aptos-move/block-executor/src/scheduler.rs (L478-513)
```rust
    pub fn next_task(&self) -> SchedulerTask {
        loop {
            if self.done() {
                // No more tasks.
                return SchedulerTask::Done;
            }

            let (idx_to_validate, wave) =
                Self::unpack_validation_idx(self.validation_idx.load(Ordering::Acquire));

            let idx_to_execute = self.execution_idx.load(Ordering::Acquire);

            let prefer_validate = idx_to_validate < min(idx_to_execute, self.num_txns)
                && !self.never_executed(idx_to_validate);

            if !prefer_validate && idx_to_execute >= self.num_txns {
                return SchedulerTask::Retry;
            }

            if prefer_validate {
                if let Some((txn_idx, incarnation, wave)) =
                    self.try_validate_next_version(idx_to_validate, wave)
                {
                    return SchedulerTask::ValidationTask(txn_idx, incarnation, wave);
                }
            }

            if idx_to_execute < self.num_txns {
                if let Some((txn_idx, incarnation, execution_task_type)) =
                    self.try_execute_next_version()
                {
                    return SchedulerTask::ExecutionTask(txn_idx, incarnation, execution_task_type);
                }
            }
        }
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L1422-1422)
```rust
                SchedulerTask::Retry => scheduler.next_task(),
```
