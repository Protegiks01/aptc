# Audit Report

## Title
Tokio Worker Thread Blocking on Async Drop Queue Exhaustion During StateCheckpointOutput Replacement

## Summary
When the async drop queue reaches capacity (32 concurrent tasks), replacing `StateComputeResult` instances in consensus blocks causes tokio worker threads to block on a condition variable, degrading validator performance. This occurs because `StateCheckpointOutput` uses `DropHelper` which schedules async drops via `DEFAULT_DROPPER`, and the scheduling operation blocks when the queue is full.

## Finding Description

The vulnerability exists in how `StateCheckpointOutput` instances are dropped during consensus execution, spanning multiple components:

**Architecture Overview:**

`StateCheckpointOutput` is wrapped in `Arc<DropHelper<Inner>>` for async dropping. [1](#0-0) 

When `DropHelper` is dropped, it schedules the inner value for async drop using the global `DEFAULT_DROPPER` with a maximum of 32 concurrent tasks. [2](#0-1) 

The `Drop` implementation calls `DEFAULT_DROPPER.schedule_drop()`. [3](#0-2) 

Scheduling a drop calls `num_tasks_tracker.inc()` which contains a blocking while loop when the queue is full. [4](#0-3) 

The blocking occurs via condition variable wait with no timeout. [5](#0-4) 

**Critical Execution Path:**

`PipelinedBlock` stores a `StateComputeResult` in a `Mutex`. [6](#0-5) 

When new execution results arrive, `set_compute_result()` replaces the old `StateComputeResult`, causing it to be dropped. [7](#0-6) 

This occurs in the consensus execution pipeline during `ExecutionSchedulePhase` which runs as a tokio async task. [8](#0-7) 

The `ExecutionSchedulePhase` calls this within its async `process()` method. [9](#0-8) 

**Why Blocking Occurs:**

The async drop queue fills up when block trees are pruned via `BlockTree::prune()`. [10](#0-9) 

Each pruned block contains `PartialStateComputeResult` with `StateCheckpointOutput` instances. [11](#0-10) 

While 32+ drop tasks are processing, if `ExecutionSchedulePhase` tries to replace `StateComputeResult` instances, the tokio worker thread blocks waiting for queue capacity via the condition variable.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program criteria: "Validator node slowdowns" (up to $50,000).

**Validator Impact:**
- Tokio worker threads block during critical consensus execution phases
- Blocking calls in async contexts prevent other tasks from progressing on that worker
- Multiple workers can be blocked simultaneously during high load
- Block execution and voting can be delayed
- Validators may fall behind and miss consensus rounds
- Network liveness degrades during high-throughput periods

**Technical Severity:**
The blocking operation (`std::sync::Condvar::wait`) in an async context is a critical anti-pattern in Rust async programming. When called from a tokio async task, it blocks the entire OS thread, not just the async task, preventing other tasks scheduled on that worker from making progress.

**Triggering Conditions:**
- Occurs naturally during high transaction throughput
- Exacerbated when blocks are large and contain complex state
- Can happen during normal validator operation under load (DeFi activity spikes, protocol upgrades)

The 32-task limit is relatively small compared to potential drop workload when pruning large block trees with multiple `StateCheckpointOutput` instances.

## Likelihood Explanation

**Likelihood: Medium** during periods of high network activity.

The issue occurs when:
1. Block execution rate is high (many new `StateCheckpointOutput` instances created)
2. Block tree pruning happens frequently (filling the 32-task drop queue)
3. `ExecutionSchedulePhase` replaces `StateComputeResult` instances (triggering drops from async context)

All three conditions occur naturally during normal validator operation under load. While not constantly triggered, high-throughput scenarios make this realistic. The queue drains as tasks complete, but sustained high load can maintain the queue at capacity.

## Recommendation

Replace the blocking `std::sync::Condvar` with async-aware synchronization:

1. **Immediate fix**: Use `tokio::sync::Semaphore` instead of `Mutex + Condvar` in `NumTasksTracker` to make the waiting operation async-aware.

2. **Alternative**: Check the queue capacity before scheduling and return an error or use a non-blocking variant when called from async contexts.

3. **Architectural fix**: Detect when `schedule_drop` is called from async contexts and handle differently (e.g., spawn a blocking task).

4. **Increase capacity**: Consider increasing the 32-task limit if memory permits, though this is a temporary mitigation.

## Proof of Concept

A complete PoC would require:
1. Setting up a validator node under high load
2. Monitoring tokio worker thread states
3. Triggering simultaneous block pruning and execution

The vulnerability can be demonstrated by:
```rust
// Simulate the blocking scenario
let dropper = AsyncConcurrentDropper::new("test", 32, 4);
// Fill the queue with 32 slow-drop items
for _ in 0..32 {
    dropper.schedule_drop(SlowDropper);
}
// This will block waiting for queue space
dropper.schedule_drop(SlowDropper); // Blocks on condvar.wait()
```

When called from within a tokio async task (as happens in `ExecutionSchedulePhase`), this blocks the worker thread.

## Notes

The report's description is technically accurate but uses imprecise terminology in places:
- It blocks "tokio worker threads" not "the consensus thread" 
- The blocking waits for queue space, not "indefinitely" (though without timeout)
- Impact depends on how many workers get blocked simultaneously

Despite these terminological issues, the core vulnerability is valid: blocking operations in async contexts during critical consensus execution can degrade validator performance, meeting the High Severity "Validator node slowdowns" criteria.

### Citations

**File:** execution/executor-types/src/state_checkpoint_output.rs (L14-16)
```rust
pub struct StateCheckpointOutput {
    #[deref]
    inner: Arc<DropHelper<Inner>>,
```

**File:** crates/aptos-drop-helper/src/lib.rs (L19-20)
```rust
pub static DEFAULT_DROPPER: Lazy<AsyncConcurrentDropper> =
    Lazy::new(|| AsyncConcurrentDropper::new("default", 32, 8));
```

**File:** crates/aptos-drop-helper/src/lib.rs (L51-55)
```rust
impl<T: Send + 'static> Drop for DropHelper<T> {
    fn drop(&mut self) {
        DEFAULT_DROPPER.schedule_drop(self.inner.take());
    }
}
```

**File:** crates/aptos-drop-helper/src/async_concurrent_dropper.rs (L61-68)
```rust
    fn schedule_drop_impl<V: Send + 'static>(&self, v: V, notif_sender_opt: Option<Sender<()>>) {
        if IN_ANY_DROP_POOL.get() {
            Self::do_drop(v, notif_sender_opt);
            return;
        }

        let _timer = TIMER.timer_with(&[self.name, "enqueue_drop"]);
        self.num_tasks_tracker.inc();
```

**File:** crates/aptos-drop-helper/src/async_concurrent_dropper.rs (L112-119)
```rust
    fn inc(&self) {
        let mut num_tasks = self.lock.lock();
        while *num_tasks >= self.max_tasks {
            num_tasks = self.cvar.wait(num_tasks).expect("lock poisoned.");
        }
        *num_tasks += 1;
        GAUGE.set_with(&[self.name, "num_tasks"], *num_tasks as i64);
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L208-208)
```rust
    state_compute_result: Mutex<StateComputeResult>,
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L307-307)
```rust
        *self.state_compute_result.lock() = state_compute_result;
```

**File:** consensus/src/pipeline/execution_schedule_phase.rs (L51-80)
```rust
    async fn process(&self, req: ExecutionRequest) -> ExecutionWaitRequest {
        let ExecutionRequest { mut ordered_blocks } = req;

        let block_id = match ordered_blocks.last() {
            Some(block) => block.id(),
            None => {
                return ExecutionWaitRequest {
                    block_id: HashValue::zero(),
                    fut: Box::pin(async { Err(aptos_executor_types::ExecutorError::EmptyBlocks) }),
                }
            },
        };

        for b in &ordered_blocks {
            if let Some(tx) = b.pipeline_tx().lock().as_mut() {
                tx.rand_tx.take().map(|tx| tx.send(b.randomness().cloned()));
            }
        }

        let fut = async move {
            for b in ordered_blocks.iter_mut() {
                let (compute_result, execution_time) = b.wait_for_compute_result().await?;
                b.set_compute_result(compute_result, execution_time);
            }
            Ok(ordered_blocks)
        }
        .boxed();

        ExecutionWaitRequest { block_id, fut }
    }
```

**File:** execution/executor/src/block_executor/block_tree/mod.rs (L27-32)
```rust
pub struct Block {
    pub id: HashValue,
    pub output: PartialStateComputeResult,
    children: Mutex<Vec<Arc<Block>>>,
    block_lookup: Arc<BlockLookup>,
}
```

**File:** execution/executor/src/block_executor/block_tree/mod.rs (L264-268)
```rust
        let old_root = std::mem::replace(&mut *self.root.lock(), root);

        // send old root to async task to drop it
        Ok(DEFAULT_DROPPER.schedule_drop_with_waiter(old_root))
    }
```
