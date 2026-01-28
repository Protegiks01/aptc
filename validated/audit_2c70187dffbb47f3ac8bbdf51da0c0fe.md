# Audit Report

## Title
Missing Retry Mechanism for Execution Failures Causes Permanent Liveness Loss

## Summary
When the execution wait phase returns an `ExecutorError::CouldNotGetData` timeout error, the affected block remains permanently stuck in "Ordered" state and is never re-executed. This causes complete liveness failure for the validator as all subsequent blocks are blocked from processing. Unlike the signing phase which implements retry logic, the execution phase ignores the retry signal, creating an unrecoverable deadlock situation.

## Finding Description
The vulnerability exists in the execution response handling logic within the buffer manager's main event loop. When blocks are ordered and sent for execution, if the execution fails with a `CouldNotGetData` error (commonly triggered by quorum store batch request timeouts), the block processing follows this flawed path:

1. The `ExecutionWaitPhase` awaits compute results and returns an `ExecutionResponse` containing the error result. [1](#0-0) 

2. The buffer manager's `process_execution_response` method receives this error response, logs it via `log_executor_error_occurred`, and returns early without advancing the block from "Ordered" to "Executed" state. [2](#0-1) 

3. The `advance_execution_root` method is designed to detect this stuck situation and return `Some(block_id)` to signal that a retry is needed when the execution root hasn't advanced. [3](#0-2) 

4. However, in the main event loop, this return value is completely ignored and no retry is scheduled. [4](#0-3) 

This is in stark contrast to the signing phase, which properly handles retry scenarios by spawning a delayed retry request when the signing root hasn't advanced. [5](#0-4) 

The `CouldNotGetData` error is defined in the executor error types: [6](#0-5) 

And occurs in realistic scenarios such as batch request timeout after exhausting retry attempts: [7](#0-6) 

Once a block becomes stuck, execution is only triggered when ordered blocks are first received: [8](#0-7) 

There is no mechanism to retry failed executions during normal operation, as confirmed by the interval tick handler which only updates metrics and rebroadcasts commit votes: [9](#0-8) 

## Impact Explanation
This vulnerability qualifies as **CRITICAL Severity** under the Aptos bug bounty program because it causes **Total Loss of Liveness/Network Availability** (Category 4):

**Complete Validator Halt**: When a block gets stuck due to `CouldNotGetData`, the validator completely stops making consensus progress. The buffer manager cannot advance past the stuck block, preventing all subsequent blocks from being executed, signed, or committed. This represents a fundamental protocol violation causing the validator node to become non-functional.

**No Automatic Recovery**: The only recovery mechanisms are epoch boundary reset: [10](#0-9) 

Or manual state synchronization via reset request: [11](#0-10) 

During normal epoch operation, there is no automatic recovery, meaning validators remain stuck until external intervention.

**Network-Wide Impact**: If multiple validators encounter batch timeout issues simultaneously (e.g., during network partitions or storage slowdowns), this can lead to widespread liveness failures across the validator set, potentially preventing the network from reaching consensus and processing transactions.

## Likelihood Explanation
This vulnerability has **HIGH likelihood** of occurring in production:

**Common Trigger Conditions**:
- Network latency or partitions causing batch request timeouts (with retry limit of 10 attempts and 5000ms RPC timeout)
- Storage I/O delays preventing timely batch retrieval
- Quorum store synchronization issues between validators
- High load conditions causing request queue backlogs

**No Special Privileges Required**: This can happen to any validator during normal operations without requiring malicious activity. The batch request timeout mechanism has built-in limits that will eventually return `CouldNotGetData` under adverse network or storage conditions. [12](#0-11) 

**Production Environment Realistic**: Network and storage issues are common in distributed systems, making this a realistic failure mode that could affect mainnet validators during periods of stress or infrastructure degradation.

## Recommendation
Implement retry logic for execution failures similar to the signing phase. In the main event loop, capture the return value from `advance_execution_root()` and spawn a delayed retry request when a block is stuck:

```rust
Some(response) = self.execution_wait_phase_rx.next() => {
    monitor!("buffer_manager_process_execution_wait_response", {
        self.process_execution_response(response).await;
        if let Some(block_id) = self.advance_execution_root() {
            // Spawn retry request for stuck execution
            let sender = self.execution_schedule_phase_tx.clone();
            let request = self.create_new_request(ExecutionRequest {
                ordered_blocks: self.buffer.get(&self.execution_root)
                    .unwrap_ordered_ref()
                    .ordered_blocks.clone(),
            });
            Self::spawn_retry_request(sender, request, Duration::from_millis(100));
        }
        if self.signing_root.is_none() {
            self.advance_signing_root().await;
        }
    });
},
```

## Proof of Concept
The vulnerability can be demonstrated by:

1. Setting up a validator node in a test environment
2. Using fail points or network simulation to cause batch request timeouts that trigger `CouldNotGetData` errors
3. Observing that the affected block remains in "Ordered" state indefinitely
4. Confirming that the validator stops processing all subsequent blocks until epoch boundary or manual reset

The code evidence shows the vulnerability is present in the current codebase, as the retry signal from `advance_execution_root()` is discarded at line 957 of `buffer_manager.rs`, while the signing phase correctly implements retry logic at lines 478-480.

## Notes
This vulnerability represents a genuine consensus liveness issue in the Aptos blockchain. The asymmetry between execution phase error handling (which lacks retry logic) and signing phase error handling (which implements retry logic) indicates an incomplete implementation rather than an intentional design decision. The issue affects normal validator operations and does not require any malicious activity or trusted role compromise to trigger.

### Citations

**File:** consensus/src/pipeline/execution_wait_phase.rs (L49-56)
```rust
    async fn process(&self, req: ExecutionWaitRequest) -> ExecutionResponse {
        let ExecutionWaitRequest { block_id, fut } = req;

        ExecutionResponse {
            block_id,
            inner: fut.await,
        }
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L397-410)
```rust
        let request = self.create_new_request(ExecutionRequest {
            ordered_blocks: ordered_blocks.clone(),
        });
        if let Some(consensus_publisher) = &self.consensus_publisher {
            let message = ConsensusObserverMessage::new_ordered_block_message(
                ordered_blocks.clone(),
                ordered_proof.clone(),
            );
            consensus_publisher.publish_message(message);
        }
        self.execution_schedule_phase_tx
            .send(request)
            .await
            .expect("Failed to send execution schedule request");
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

**File:** consensus/src/pipeline/buffer_manager.rs (L986-991)
```rust
                _ = interval.tick().fuse() => {
                    monitor!("buffer_manager_process_interval_tick", {
                    self.update_buffer_manager_metrics();
                    self.rebroadcast_commit_votes_if_needed().await
                    });
                },
```

**File:** execution/executor-types/src/error.rs (L41-42)
```rust
    #[error("request timeout")]
    CouldNotGetData,
```

**File:** consensus/src/quorum_store/batch_requester.rs (L140-150)
```rust
                            }
                            // Short-circuit if the chain has moved beyond expiration
                            Ok(BatchResponse::NotFound(ledger_info)) => {
                                counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
                                if ledger_info.commit_info().epoch() == epoch
                                    && ledger_info.commit_info().timestamp_usecs() > expiration
                                    && ledger_info.verify_signatures(&validator_verifier).is_ok()
                                {
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

**File:** consensus/src/pipeline/execution_client.rs (L674-709)
```rust
    async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
        let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager) = {
            let handle = self.handle.read();
            (
                handle.reset_tx_to_rand_manager.clone(),
                handle.reset_tx_to_buffer_manager.clone(),
            )
        };

        if let Some(mut reset_tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx: ack_tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::RandResetDropped)?;
            ack_rx.await.map_err(|_| Error::RandResetDropped)?;
        }

        if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
            // reset execution phase and commit phase
            let (tx, rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::ResetDropped)?;
            rx.await.map_err(|_| Error::ResetDropped)?;
        }

        Ok(())
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L711-720)
```rust
    async fn end_epoch(&self) {
        let (
            reset_tx_to_rand_manager,
            reset_tx_to_buffer_manager,
            reset_tx_to_secret_share_manager,
        ) = {
            let mut handle = self.handle.write();
            handle.reset()
        };

```
