# Audit Report

## Title
Critical Liveness Failure: ExecutorError Handling Causes Irrecoverable Validator Deadlock Without Automatic Recovery

## Summary
The consensus pipeline's error handling in `buffer_manager.rs` causes validators to enter an irrecoverable deadlock state when any `ExecutorError` occurs during block execution. The missing retry mechanism for execution errors (unlike signing errors which have retry) causes affected validators to become stuck until epoch change, potentially causing network-wide liveness failure if >1/3 of validators are affected.

## Finding Description

When any `ExecutorError` is returned during block execution, the buffer manager's `process_execution_response` method handles it by logging and immediately returning without advancing the block's state: [1](#0-0) 

This creates a **permanent deadlock** because:

1. **Block remains in "Ordered" state**: The block is never advanced to "Executed" state since the function returns early. The `advance_to_executed_or_aggregated` method at line 661 is never called when an error occurs.

2. **Execution root becomes stuck**: The `advance_execution_root` function is designed to return `Some(block_id)` to signal retry is needed when the execution root doesn't advance: [2](#0-1) 

However, all three call sites in the main event loop **ignore this return value**, meaning no retry is ever scheduled: [3](#0-2) 

3. **Missing retry mechanism**: Compare this to `advance_signing_root`, which **does** implement proper retry logic when signing fails: [4](#0-3) 

The execution phase has no equivalent retry implementation, despite `advance_execution_root` returning a value that suggests retry was intended.

4. **Sequential execution blocks all subsequent blocks**: The execution schedule phase processes blocks sequentially with a `?` operator that fails the entire batch if any block fails: [5](#0-4) 

Since `advance_execution_root` always finds the first "Ordered" block and the failed block stays "Ordered", all subsequent blocks remain blocked.

5. **ExecutorError types that trigger this**: [6](#0-5) 

All variants trigger the deadlock, including:
- `CouldNotGetData` - missing QuorumStore batch data (transient, would succeed with retry)
- `BlockNotFound` - missing speculation result  
- `InternalError` - database errors, VM failures
- `EmptyBlocks` - empty block batch

The error logging function explicitly categorizes errors, showing that `CouldNotGetData` and `BlockNotFound` are expected/handled differently from other "UnexpectedError" cases: [7](#0-6) 

**Breaking Invariant**: This violates the **liveness guarantee** of AptosBFT consensus. While it doesn't violate safety (no chain split occurs), validators become permanently stuck and cannot process new blocks until an epoch change forces a reset.

The only recovery path is through the `reset()` method: [8](#0-7) 

Which is only triggered by epoch changes or explicit reset signals: [9](#0-8) [10](#0-9) 

## Impact Explanation

This qualifies as **Critical Severity** under the "Total loss of liveness/network availability" category:

- **Validator Deadlock**: Individual validators become completely stuck and cannot recover without external intervention (epoch change)
- **Network Liveness Loss**: If >1/3 of validators encounter the error, the network cannot reach consensus quorum and stops processing transactions entirely
- **No Automatic Recovery**: Unlike transient errors that could succeed on retry, this has zero tolerance - a single error causes permanent deadlock with no retry mechanism
- **Cascading Failure Risk**: If the error is triggered by a specific condition (e.g., missing QuorumStore data, database issues), multiple validators could be affected simultaneously

Per Aptos bug bounty criteria, this falls under "Total loss of liveness/network availability" which is Critical Severity.

## Likelihood Explanation

**Moderate to High Likelihood** because:

1. **ExecutorErrors occur in normal operation**: The codebase explicitly handles `CouldNotGetData` and `BlockNotFound` as known error cases, suggesting they occur with some frequency

2. **Transient errors become permanent**: Even errors that would succeed on retry (like `CouldNotGetData` for temporarily unavailable batch data) become permanent deadlocks due to the missing retry mechanism

3. **Zero-tolerance approach**: A single ExecutorError causes permanent deadlock, with no degradation path or fallback

4. **Realistic trigger scenarios**:
   - QuorumStore batch data temporarily unavailable (`CouldNotGetData`)
   - Database errors during execution (`InternalError`)
   - Missing speculation results (`BlockNotFound`)
   - VM execution failures (`InternalError` from VM errors)

5. **Design inconsistency**: The signing phase has retry logic, but the execution phase (which was designed to support retry based on the return type) has the retry mechanism never implemented

## Recommendation

Implement retry logic for execution errors similar to the signing phase:

```rust
async fn advance_execution_root(&mut self) -> Option<HashValue> {
    let cursor = self.execution_root;
    self.execution_root = self
        .buffer
        .find_elem_from(cursor.or_else(|| *self.buffer.head_cursor()), |item| {
            item.is_ordered()
        });
    if self.execution_root.is_some() && cursor == self.execution_root {
        // Return block_id for retry
        self.execution_root
    } else {
        None
    }
}

// In the main event loop, use the return value:
Some(response) = self.execution_wait_phase_rx.next() => {
    monitor!("buffer_manager_process_execution_wait_response", {
        self.process_execution_response(response).await;
        if let Some(retry_block_id) = self.advance_execution_root() {
            // Schedule retry for failed execution
            let item = self.buffer.find_elem_by_key(self.execution_root, retry_block_id);
            if let Some(cursor) = item {
                let ordered_item = self.buffer.get(&cursor);
                if ordered_item.is_ordered() {
                    let blocks = ordered_item.get_blocks().clone();
                    let request = self.create_new_request(ExecutionRequest {
                        ordered_blocks: blocks,
                    });
                    let sender = self.execution_schedule_phase_tx.clone();
                    Self::spawn_retry_request(sender, request, Duration::from_millis(100));
                }
            }
        }
        if self.signing_root.is_none() {
            self.advance_signing_root().await;
        }
    });
}
```

## Proof of Concept

The vulnerability can be demonstrated by triggering any ExecutorError during block execution. The most realistic scenario is `CouldNotGetData` from missing QuorumStore batch data:

1. Validator receives ordered blocks for execution
2. Execution phase calls `wait_for_compute_result()` which requires batch data
3. Batch data is temporarily unavailable (network delay, DB issue)
4. `ExecutorError::CouldNotGetData` is returned
5. `process_execution_response` logs error and returns early (lines 617-626)
6. Block remains in "Ordered" state
7. `advance_execution_root` finds the same "Ordered" block again
8. Returns `Some(block_id)` to signal retry needed
9. Main loop ignores the return value (line 957)
10. No retry is scheduled
11. Validator is permanently stuck until epoch change

The code evidence shows this is a real design flaw where retry functionality was partially implemented (`advance_execution_root` returns retry signal) but never wired up in the main event loop, unlike the signing phase which has complete retry implementation.

## Notes

While the claim specifically mentions `BadNumTxnsToCommit`, this error variant is defined but never actually constructed anywhere in the current codebase. However, the vulnerability applies to **all ExecutorError variants**, including those that are actively used (`CouldNotGetData`, `BlockNotFound`, `InternalError`), making the finding valid despite the specific example being unused.

The asymmetry between signing phase (has retry) and execution phase (missing retry) indicates this was likely an implementation oversight rather than intentional design, as evidenced by the return type of `advance_execution_root` suggesting retry was intended.

### Citations

**File:** consensus/src/pipeline/buffer_manager.rs (L429-451)
```rust
    fn advance_execution_root(&mut self) -> Option<HashValue> {
        let cursor = self.execution_root;
        self.execution_root = self
            .buffer
            .find_elem_from(cursor.or_else(|| *self.buffer.head_cursor()), |item| {
                item.is_ordered()
            });
        if self.execution_root.is_some() && cursor == self.execution_root {
            // Schedule retry.
            self.execution_root
        } else {
            sample!(
                SampleRate::Frequency(2),
                info!(
                    "Advance execution root from {:?} to {:?}",
                    cursor, self.execution_root
                )
            );
            // Otherwise do nothing, because the execution wait phase is driven by the response of
            // the execution schedule phase, which is in turn fed as soon as the ordered blocks
            // come in.
            None
        }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L478-481)
```rust
            if cursor == self.signing_root {
                let sender = self.signing_phase_tx.clone();
                Self::spawn_retry_request(sender, request, Duration::from_millis(100));
            } else {
```

**File:** consensus/src/pipeline/buffer_manager.rs (L530-534)
```rust
                if commit_proof.ledger_info().ends_epoch() {
                    // the epoch ends, reset to avoid executing more blocks, execute after
                    // this persisting request will result in BlockNotFound
                    self.reset().await;
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

**File:** consensus/src/pipeline/buffer_manager.rs (L579-595)
```rust
    async fn process_reset_request(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        info!("Receive reset");

        match signal {
            ResetSignal::Stop => self.stop = true,
            ResetSignal::TargetRound(round) => {
                self.highest_committed_round = round;
                self.latest_round = round;

                let _ = self.drain_pending_commit_proof_till(round);
            },
        }

        self.reset().await;
        let _ = tx.send(ResetAck::default());
        info!("Reset finishes");
```

**File:** consensus/src/pipeline/buffer_manager.rs (L617-626)
```rust
        let executed_blocks = match inner {
            Ok(result) => result,
            Err(e) => {
                log_executor_error_occurred(
                    e,
                    &counters::BUFFER_MANAGER_RECEIVED_EXECUTOR_ERROR_COUNT,
                    block_id,
                );
                return;
            },
```

**File:** consensus/src/pipeline/buffer_manager.rs (L954-960)
```rust
                Some(response) = self.execution_wait_phase_rx.next() => {
                    monitor!("buffer_manager_process_execution_wait_response", {
                    self.process_execution_response(response).await;
                    self.advance_execution_root();
                    if self.signing_root.is_none() {
                        self.advance_signing_root().await;
                    }});
```

**File:** consensus/src/pipeline/execution_schedule_phase.rs (L70-77)
```rust
        let fut = async move {
            for b in ordered_blocks.iter_mut() {
                let (compute_result, execution_time) = b.wait_for_compute_result().await?;
                b.set_compute_result(compute_result, execution_time);
            }
            Ok(ordered_blocks)
        }
        .boxed();
```

**File:** execution/executor-types/src/error.rs (L11-43)
```rust
#[derive(Debug, Deserialize, Error, PartialEq, Eq, Serialize, Clone)]
/// Different reasons for proposal rejection
pub enum ExecutorError {
    #[error("Cannot find speculation result for block id {0}")]
    BlockNotFound(HashValue),

    #[error("Cannot get data for batch id {0}")]
    DataNotFound(HashValue),

    #[error(
        "Bad num_txns_to_commit. first version {}, num to commit: {}, target version: {}",
        first_version,
        to_commit,
        target_version
    )]
    BadNumTxnsToCommit {
        first_version: Version,
        to_commit: usize,
        target_version: Version,
    },

    #[error("Internal error: {:?}", error)]
    InternalError { error: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Received Empty Blocks")]
    EmptyBlocks,

    #[error("request timeout")]
    CouldNotGetData,
}
```

**File:** consensus/src/counters.rs (L1184-1212)
```rust
pub fn log_executor_error_occurred(
    e: ExecutorError,
    counter: &Lazy<IntCounterVec>,
    block_id: HashValue,
) {
    match e {
        ExecutorError::CouldNotGetData => {
            counter.with_label_values(&["CouldNotGetData"]).inc();
            warn!(
                block_id = block_id,
                "Execution error - CouldNotGetData {}", block_id
            );
        },
        ExecutorError::BlockNotFound(block_id) => {
            counter.with_label_values(&["BlockNotFound"]).inc();
            warn!(
                block_id = block_id,
                "Execution error BlockNotFound {}", block_id
            );
        },
        e => {
            counter.with_label_values(&["UnexpectedError"]).inc();
            warn!(
                block_id = block_id,
                "Execution error {:?} for {}", e, block_id
            );
        },
    }
}
```
