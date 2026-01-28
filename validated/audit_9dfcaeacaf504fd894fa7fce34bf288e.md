# Audit Report

## Title
Permanent Consensus Liveness Failure Due to Missing Retry Logic for ExecutorError::CouldNotGetData

## Summary
When block execution fails with `ExecutorError::CouldNotGetData` (a timeout error), the block is permanently stuck in "Ordered" state with no retry mechanism, causing total consensus liveness failure. All subsequent blocks are blocked from execution, halting the entire blockchain until manual intervention or epoch change.

## Finding Description

The consensus pipeline processes blocks sequentially through the BufferManager. When a block requires batch data from the quorum store and that data times out, execution fails with `CouldNotGetData`. [1](#0-0) 

This error is returned when batch requests timeout or when batches expire: [2](#0-1) [3](#0-2) 

When the ExecutionWaitPhase returns this error, the BufferManager's `process_execution_response()` method logs it and returns early without advancing the block's state: [4](#0-3) [5](#0-4) 

The block remains in "Ordered" state. Subsequently, `advance_execution_root()` is called, which finds the same block still unexecuted and returns `Some(block_id)` with a comment "Schedule retry": [6](#0-5) 

**However, this return value is completely ignored** in the main event loop: [7](#0-6) 

Unlike the signing phase which properly implements retry logic using `spawn_retry_request()`: [8](#0-7) [9](#0-8) 

The execution phase has no such mechanism. The Buffer processes blocks sequentially as a linked list: [10](#0-9) 

This means if one block is stuck, all subsequent blocks cannot proceed. The periodic interval tick only updates metrics and rebroadcasts commit votes, it does not retry execution: [11](#0-10) 

## Impact Explanation

This is a **Critical Severity** vulnerability per Aptos bug bounty criteria as it causes **Total Loss of Liveness/Network Availability**. 

When a block fails execution with `CouldNotGetData`:
1. The block remains permanently in "Ordered" state with no automatic recovery
2. All validators that ordered this block (≥2/3 of the network) experience the same failure
3. The sequential buffer processing blocks all subsequent blocks from execution
4. New rounds can propose blocks, but they queue behind the stuck block and cannot execute
5. The entire blockchain halts until either an epoch change occurs or a manual reset signal is sent

The only recovery mechanisms are:
- Epoch changes (which happen automatically but infrequently, typically every few hours)
- Manual intervention via reset signals

This directly violates the liveness guarantee of the consensus protocol.

## Likelihood Explanation

This vulnerability is **highly likely** to occur in production for several reasons:

**Natural Occurrence:**
- Network partitions and timeouts are common in distributed systems
- Batch expiration occurs when the blockchain progresses faster than batch data propagates
- Peer nodes may legitimately not have batch data when requested
- No special attacker capabilities required - can trigger naturally from network conditions

**Intentional Attack Scenario:**
- A malicious validator selected as leader can propose blocks containing batches they never share
- The attacker can selectively withhold batch data from specific validators
- This requires only being selected as leader (probabilistic based on stake), not majority control
- Falls within the <1/3 Byzantine fault tolerance model

## Recommendation

Implement retry logic for execution failures similar to the existing signing phase retry mechanism. Specifically:

1. **Capture the return value from `advance_execution_root()`** in the event loop and handle retry scheduling
2. **Implement execution retry using `spawn_retry_request()`** similar to the signing phase
3. **Add configurable retry limits and backoff** to prevent infinite retries

Suggested fix in `consensus/src/pipeline/buffer_manager.rs`:

```rust
// In the event loop around line 954-960, change:
Some(response) = self.execution_wait_phase_rx.next() => {
    monitor!("buffer_manager_process_execution_wait_response", {
        self.process_execution_response(response).await;
        if let Some(retry_block_id) = self.advance_execution_root() {
            // Handle execution retry
            if let Some(cursor) = self.buffer.find_elem_by_key(self.execution_root, retry_block_id) {
                let item = self.buffer.get(&cursor);
                if let Some(ordered_item) = item.as_ordered() {
                    let request = self.create_new_request(ExecutionRequest {
                        ordered_blocks: ordered_item.ordered_blocks.clone(),
                    });
                    let sender = self.execution_schedule_phase_tx.clone();
                    Self::spawn_retry_request(sender, request, Duration::from_millis(100));
                }
            }
        } else if self.signing_root.is_none() {
            self.advance_signing_root().await;
        }
    });
},
```

## Proof of Concept

The vulnerability can be demonstrated by simulating a batch timeout scenario:

1. Deploy a test environment with multiple validators
2. Have a validator propose a block with batch data
3. Prevent the batch data from being propagated to other validators (network partition simulation or withholding)
4. Observe that validators attempting to execute the block timeout with `CouldNotGetData`
5. Verify that these validators remain stuck with the block in "Ordered" state
6. Confirm that no subsequent blocks can execute despite new rounds continuing
7. Verify that only a reset signal or epoch change can recover the system

The core issue can be verified by examining the code paths:
- `ExecutionWaitPhase` returns `ExecutorError::CouldNotGetData` for timeout
- `process_execution_response()` logs and returns without state advancement
- `advance_execution_root()` returns `Some(block_id)` for retry
- Event loop ignores this return value
- No retry mechanism exists for execution phase

### Citations

**File:** execution/executor-types/src/error.rs (L41-42)
```rust
    #[error("request timeout")]
    CouldNotGetData,
```

**File:** consensus/src/quorum_store/batch_requester.rs (L148-150)
```rust
                                    counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
                                    debug!("QS: batch request expired, digest:{}", digest);
                                    return Err(ExecutorError::CouldNotGetData);
```

**File:** consensus/src/quorum_store/batch_requester.rs (L176-178)
```rust
            counters::RECEIVED_BATCH_REQUEST_TIMEOUT_COUNT.inc();
            debug!("QS: batch request timed out, digest:{}", digest);
            Err(ExecutorError::CouldNotGetData)
```

**File:** consensus/src/pipeline/buffer_manager.rs (L293-306)
```rust
    fn spawn_retry_request<T: Send + 'static>(
        mut sender: Sender<T>,
        request: T,
        duration: Duration,
    ) {
        counters::BUFFER_MANAGER_RETRY_COUNT.inc();
        spawn_named!("retry request", async move {
            tokio::time::sleep(duration).await;
            sender
                .send(request)
                .await
                .expect("Failed to send retry request");
        });
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L429-452)
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
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L478-480)
```rust
            if cursor == self.signing_root {
                let sender = self.signing_phase_tx.clone();
                Self::spawn_retry_request(sender, request, Duration::from_millis(100));
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

**File:** consensus/src/pipeline/buffer_manager.rs (L986-990)
```rust
                _ = interval.tick().fuse() => {
                    monitor!("buffer_manager_process_interval_tick", {
                    self.update_buffer_manager_metrics();
                    self.rebroadcast_commit_votes_if_needed().await
                    });
```

**File:** consensus/src/counters.rs (L1190-1196)
```rust
        ExecutorError::CouldNotGetData => {
            counter.with_label_values(&["CouldNotGetData"]).inc();
            warn!(
                block_id = block_id,
                "Execution error - CouldNotGetData {}", block_id
            );
        },
```

**File:** consensus/src/pipeline/buffer.rs (L18-35)
```rust
/// Buffer implementes an ordered dictionary
/// It supports push_back, pop_front, and lookup by HashValue
pub struct Buffer<T: Hashable> {
    map: HashMap<HashValue, LinkedItem<T>>,
    count: u64,
    head: Cursor,
    tail: Cursor,
}

impl<T: Hashable> Buffer<T> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            count: 0,
            head: None,
            tail: None,
        }
    }
```
