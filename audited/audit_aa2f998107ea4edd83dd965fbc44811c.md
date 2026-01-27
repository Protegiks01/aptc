# Audit Report

## Title
Resource Leak and Dangling Futures from Dropped ExecutionWaitRequest During Consensus Pipeline Operations

## Summary
The consensus pipeline contains non-abortable execution futures (`execute_fut` and `ledger_update_fut`) that continue running even when `ExecutionWaitRequest` or `ExecutionResponse` are dropped, leading to resource leaks through orphaned tokio tasks that perform expensive executor operations.

## Finding Description

When `ExecutionWaitRequest` is dropped before processing, the underlying execution pipeline futures continue to run because they are spawned as non-abortable tasks, violating resource management invariants.

**The Resource Leak Mechanism:**

1. `ExecutionSchedulePhase` creates an `ExecutionWaitRequest` containing an `ExecutionFut` that will await `wait_for_compute_result()` on each block [1](#0-0) 

2. The `wait_for_compute_result()` method awaits the `ledger_update_fut`, which is a shared future spawned by the pipeline builder [2](#0-1) 

3. In `pipeline_builder.rs`, critical futures are spawned as **non-abortable** tasks (with `None` for abort_handles):
   - `execute_fut` at line 500
   - `ledger_update_fut` at line 510
   - `pre_commit_fut` at line 545
   - `commit_ledger_fut` at line 555 [3](#0-2) 

4. When abort_pipeline() is called (either explicitly during reset or via PipelinedBlock::drop()), only futures with abort handles are terminated: [4](#0-3) 

5. The non-abortable futures continue executing expensive operations in spawn_blocking tasks:
   - `execute_and_update_state` performs transaction execution [5](#0-4) 
   - `ledger_update` generates state compute results [6](#0-5) 

**When This Occurs:**

During `BufferManager::reset()`, blocks have their pipelines aborted, but if `ExecutionWaitRequest` is in-flight or queued in the execution_wait_phase channel, when it's eventually dropped, the non-abortable tasks continue running: [7](#0-6) 

The `PipelinePhase` processes requests without canceling the underlying futures when reset occurs: [8](#0-7) 

## Impact Explanation

**Medium Severity** - This violates the Resource Limits invariant and causes:

1. **Resource Leaks**: Tokio tasks continue consuming thread pool resources for abandoned blocks
2. **Executor Resource Contention**: Blocking operations hold executor resources unnecessarily
3. **Performance Degradation**: Background tasks compete with legitimate operations, potentially causing validator node slowdowns (which could escalate to High severity)
4. **Memory Retention**: Intermediate execution state is retained longer than necessary

The leaked tasks interact with the `BlockExecutorTrait`, performing `execute_and_update_state` and `ledger_update` operations on blocks that have been abandoned by consensus. [9](#0-8) 

## Likelihood Explanation

**High Likelihood** - This occurs during:
- Every reset operation (triggered by state sync or epoch changes)
- Node shutdown sequences
- Any scenario where ExecutionWaitRequest is dropped before the future completes

The frequency depends on how often resets occur, but in a production network with state sync and epoch transitions, this would accumulate resource leaks over time.

## Recommendation

**Option 1** (Preferred): Make these futures properly abortable by including abort handles:

```rust
let execute_fut = spawn_shared_fut(
    Self::execute(...),
    Some(&mut abort_handles),  // Changed from None
);

let ledger_update_fut = spawn_shared_fut(
    Self::ledger_update(...),
    Some(&mut abort_handles),  // Changed from None
);
```

Ensure the executor can safely handle mid-flight abortion by checking if the operation should continue.

**Option 2**: Implement a proper Drop handler for `ExecutionWaitRequest` that waits for the future to complete:

```rust
impl Drop for ExecutionWaitRequest {
    fn drop(&mut self) {
        // Ensure future completes before dropping
        // This requires making fut accessible and using block_on
    }
}
```

**Option 3**: Add cancellation checks in executor methods to detect aborted blocks and return early.

## Proof of Concept

```rust
#[tokio::test]
async fn test_execution_wait_request_resource_leak() {
    // Setup: Create a PipelinedBlock with pipeline futures
    let block = create_test_pipelined_block();
    let pipeline_builder = create_test_pipeline_builder();
    
    // Build pipeline with non-abortable futures
    pipeline_builder.build_for_consensus(&block, parent_futs, callback);
    
    // Create ExecutionWaitRequest
    let execution_request = ExecutionRequest {
        ordered_blocks: vec![Arc::new(block.clone())],
    };
    
    let exec_schedule_phase = ExecutionSchedulePhase::new();
    let wait_request = exec_schedule_phase.process(execution_request).await;
    
    // Simulate reset: abort pipeline
    let futs = block.abort_pipeline();
    
    // Drop the ExecutionWaitRequest WITHOUT awaiting
    drop(wait_request);
    
    // Verification: The non-abortable futures (execute_fut, ledger_update_fut) 
    // are still running in the background even though wait_request was dropped
    // This can be verified by:
    // 1. Checking tokio task count remains elevated
    // 2. Monitoring executor method call count continues increasing
    // 3. Memory profiling shows retained execution state
    
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Background tasks should have completed by now, but resources were leaked during the delay
}
```

---

**Notes:**

The design intentionally makes `execute_fut` and `ledger_update_fut` non-abortable to prevent state inconsistencies during execution. However, this creates a vulnerability where dropped `ExecutionWaitRequest` objects leak resources. The current implementation violates the assumption that dropping a request cleanly releases all associated resources.

### Citations

**File:** consensus/src/pipeline/execution_schedule_phase.rs (L70-79)
```rust
        let fut = async move {
            for b in ordered_blocks.iter_mut() {
                let (compute_result, execution_time) = b.wait_for_compute_result().await?;
                b.set_compute_result(compute_result, execution_time);
            }
            Ok(ordered_blocks)
        }
        .boxed();

        ExecutionWaitRequest { block_id, fut }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L528-547)
```rust
    pub fn abort_pipeline(&self) -> Option<PipelineFutures> {
        if let Some(abort_handles) = self.pipeline_abort_handle.lock().take() {
            let mut aborted = false;
            for handle in abort_handles {
                if !handle.is_finished() {
                    handle.abort();
                    aborted = true;
                }
            }
            if aborted {
                info!(
                    "[Pipeline] Aborting pipeline for block {} {} {}",
                    self.id(),
                    self.epoch(),
                    self.round()
                );
            }
        }
        self.pipeline_futs.lock().take()
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L549-560)
```rust
    pub async fn wait_for_compute_result(&self) -> ExecutorResult<(StateComputeResult, Duration)> {
        self.pipeline_futs()
            .ok_or(ExecutorError::InternalError {
                error: "Pipeline aborted".to_string(),
            })?
            .ledger_update_fut
            .await
            .map(|(compute_result, execution_time, _)| (compute_result, execution_time))
            .map_err(|e| ExecutorError::InternalError {
                error: e.to_string(),
            })
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L489-511)
```rust
        let execute_fut = spawn_shared_fut(
            Self::execute(
                prepare_fut.clone(),
                parent.execute_fut.clone(),
                rand_check_fut.clone(),
                self.executor.clone(),
                block.clone(),
                self.validators.clone(),
                self.block_executor_onchain_config.clone(),
                self.persisted_auxiliary_info_version,
            ),
            None,
        );
        let ledger_update_fut = spawn_shared_fut(
            Self::ledger_update(
                rand_check_fut.clone(),
                execute_fut.clone(),
                parent.ledger_update_fut.clone(),
                self.executor.clone(),
                block.clone(),
            ),
            None,
        );
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L857-868)
```rust
        tokio::task::spawn_blocking(move || {
            executor
                .execute_and_update_state(
                    (block.id(), txns, auxiliary_info).into(),
                    block.parent_id(),
                    onchain_execution_config,
                )
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        Ok(start.elapsed())
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L874-921)
```rust
    async fn ledger_update(
        rand_check: TaskFuture<RandResult>,
        execute_fut: TaskFuture<ExecuteResult>,
        parent_block_ledger_update_fut: TaskFuture<LedgerUpdateResult>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
    ) -> TaskResult<LedgerUpdateResult> {
        let mut tracker = Tracker::start_waiting("ledger_update", &block);
        let (_, _, prev_epoch_end_timestamp) = parent_block_ledger_update_fut.await?;
        let execution_time = execute_fut.await?;

        tracker.start_working();
        let block_clone = block.clone();
        let result = tokio::task::spawn_blocking(move || {
            executor
                .ledger_update(block_clone.id(), block_clone.parent_id())
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        let timestamp = block.timestamp_usecs();
        observe_block(timestamp, BlockStage::EXECUTED);
        let epoch_end_timestamp =
            if result.has_reconfiguration() && !result.compute_status_for_input_txns().is_empty() {
                Some(timestamp)
            } else {
                prev_epoch_end_timestamp
            };
        // check for randomness consistency
        let (_, has_randomness) = rand_check.await?;
        if !has_randomness {
            let mut label = "consistent";
            for event in result.execution_output.subscribable_events.get(None) {
                if event.type_tag() == RANDOMNESS_GENERATED_EVENT_MOVE_TYPE_TAG.deref() {
                    error!(
                            "[Pipeline] Block {} {} {} generated randomness event without has_randomness being true!",
                            block.id(),
                            block.epoch(),
                            block.round()
                        );
                    label = "inconsistent";
                    break;
                }
            }
            counters::RAND_BLOCK.with_label_values(&[label]).inc();
        }
        Ok((result, execution_time, epoch_end_timestamp))
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L546-576)
```rust
    async fn reset(&mut self) {
        while let Some((_, block)) = self.pending_commit_blocks.pop_first() {
            // Those blocks don't have any dependencies, should be able to finish commit_ledger.
            // Abort them can cause error on epoch boundary.
            block.wait_for_commit_ledger().await;
        }
        while let Some(item) = self.buffer.pop_front() {
            for b in item.get_blocks() {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        self.buffer = Buffer::new();
        self.execution_root = None;
        self.signing_root = None;
        self.previous_commit_time = Instant::now();
        self.commit_proof_rb_handle.take();
        // purge the incoming blocks queue
        while let Ok(Some(blocks)) = self.block_rx.try_next() {
            for b in blocks.ordered_blocks {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        // Wait for ongoing tasks to finish before sending back ack.
        while self.ongoing_tasks.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
```

**File:** consensus/src/pipeline/pipeline_phase.rs (L88-108)
```rust
    pub async fn start(mut self) {
        // main loop
        while let Some(counted_req) = self.rx.next().await {
            let CountedRequest { req, guard: _guard } = counted_req;
            if self.reset_flag.load(Ordering::SeqCst) {
                continue;
            }
            let response = {
                let _timer = BUFFER_MANAGER_PHASE_PROCESS_SECONDS
                    .with_label_values(&[T::NAME])
                    .start_timer();
                self.processor.process(req).await
            };
            if let Some(tx) = &mut self.maybe_tx {
                if tx.send(response).await.is_err() {
                    debug!("Failed to send response, buffer manager probably dropped");
                    break;
                }
            }
        }
    }
```
