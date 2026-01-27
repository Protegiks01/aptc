# Audit Report

## Title
Execution Pipeline Lacks Timeout Protection Against Byzantine Block Execution Delays

## Summary
The consensus execution pipeline phases process blocks sequentially without timeouts, allowing Byzantine validator proposers to craft blocks with computationally expensive (but gas-compliant) transactions that block the execution pipeline for extended periods, preventing honest validators from processing subsequent blocks and causing them to fall behind in consensus rounds.

## Finding Description

The vulnerability exists in the execution pipeline's sequential processing architecture where each phase awaits block execution without timeout protection.

**Core Issue Location:** [1](#0-0) 

The `ExecutionWaitPhase::process()` method awaits the execution future indefinitely without any timeout mechanism. When a block contains transactions that take longer to execute than the round timeout (default 1000ms), the following occurs: [2](#0-1) 

The pipeline phase processes requests sequentially, blocking at line 99 on `self.processor.process(req).await` until completion. While the reset flag check exists at line 92, it only helps if checked before execution starts, not during execution.

**Attack Flow:**

1. Byzantine validator proposer crafts a block with transactions that execute within gas limits but take >1000ms wall-clock time
2. Block is broadcast to honest validators
3. Honest validators begin execution in `ExecutionWaitPhase` [3](#0-2) 

4. Execution happens in `spawn_blocking` which has no timeout: [4](#0-3) 

5. Round timeout fires at 1000ms, validators timeout the round: [5](#0-4) 

6. Validators move to next round via `process_local_timeout`: [6](#0-5) 

7. However, execution pipeline remains blocked - no abort occurs
8. New blocks from subsequent rounds queue up but cannot be processed
9. Validators fall multiple rounds behind, unable to vote on current blocks
10. Byzantine validator (who can skip or fast-track their own malicious block) maintains consensus participation

**Critical Insight:** The `tokio::task::spawn_blocking` tasks cannot be cancelled even when the outer future is aborted: [7](#0-6) 

While abort handles exist, they only cancel the outer async wrapper, not the inner blocking execution task which continues consuming resources.

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria - "Validator node slowdowns"

This attack causes:
1. **Execution Pipeline Starvation**: Honest validators cannot process new blocks while blocked
2. **Consensus Participation Failure**: Validators miss voting windows for multiple rounds  
3. **Liveness Degradation**: If multiple honest validators are affected, overall network throughput drops
4. **Resource Exhaustion**: Abandoned `spawn_blocking` tasks continue consuming CPU even after abort

The target execution time is 90ms: [8](#0-7) 

But blocks could legitimately take up to several seconds under adversarial conditions while staying within gas limits, blocking the pipeline for 10-50x the expected duration.

## Likelihood Explanation

**Likelihood: Medium-to-High**

Requirements:
- Attacker must be a validator proposer (or control one)
- Must craft blocks that execute slowly but remain within gas limits
- Blocks must pass all validation checks

Mitigating factors:
- Gas limits constrain maximum execution time
- Backpressure mechanisms calibrate limits based on recent performance
- Round rotation limits how often a single Byzantine proposer gets to propose
- Reset during epoch boundaries clears pipeline

However, a Byzantine proposer in a typical rotation schedule (1 in 100+ validators) can still disrupt the network periodically, and if multiple Byzantine validators coordinate, the effect compounds.

## Recommendation

**Implement execution timeout at the pipeline phase level:**

```rust
// In pipeline_phase.rs
pub async fn start(mut self) {
    while let Some(counted_req) = self.rx.next().await {
        let CountedRequest { req, guard: _guard } = counted_req;
        if self.reset_flag.load(Ordering::SeqCst) {
            continue;
        }
        
        // Add timeout wrapper
        let timeout_duration = Duration::from_millis(5000); // 5x normal timeout
        let response = match tokio::time::timeout(timeout_duration, self.processor.process(req)).await {
            Ok(response) => response,
            Err(_) => {
                error!("Pipeline phase {} timed out after {:?}", T::NAME, timeout_duration);
                continue; // Skip this block and move to next
            }
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

**Additional hardening:**
1. Track execution time metrics per proposer to detect slow-block attacks
2. Implement dynamic timeout scaling based on block complexity
3. Add circuit breaker for validators repeatedly submitting slow blocks
4. Consider parallel execution pipelines to prevent head-of-line blocking

## Proof of Concept

```rust
#[tokio::test]
async fn test_byzantine_slow_execution_blocks_pipeline() {
    // Setup execution pipeline with short timeout
    let config = ConsensusConfig {
        round_initial_timeout_ms: 1000,
        ..Default::default()
    };
    
    // Create Byzantine block with expensive transactions
    let expensive_block = create_block_with_expensive_transactions(
        /* transactions that take 5000ms to execute but stay within gas limits */
    );
    
    // Send block to execution pipeline
    let start = Instant::now();
    execution_schedule_phase_tx.send(expensive_block).await.unwrap();
    
    // Verify round timeout fires at 1000ms
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(round_timed_out);
    
    // Send next block from subsequent round
    let next_block = create_normal_block(round + 1);
    execution_schedule_phase_tx.send(next_block).await.unwrap();
    
    // Verify next block is NOT processed until expensive block completes
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!next_block_executed); // Still blocked
    
    // Wait for expensive block to complete
    tokio::time::sleep(Duration::from_millis(4000)).await;
    let elapsed = start.elapsed();
    
    // Verify pipeline was blocked for ~5000ms despite 1000ms timeout
    assert!(elapsed > Duration::from_millis(5000));
    assert!(next_block_executed); // Only now processed
}
```

**Notes:**
- The vulnerability requires validator proposer access, placing it at the boundary of the trust model
- While gas limits provide some bounds, wall-clock execution time can still exceed round timeouts significantly
- The impact is proportional to how many validators are affected and how frequently the attack occurs
- This represents a liveness attack rather than a safety violation, but still qualifies as "Validator node slowdowns" per bug bounty criteria

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

**File:** consensus/src/pipeline/pipeline_phase.rs (L88-109)
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
}
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

**File:** consensus/src/pipeline/pipeline_builder.rs (L144-165)
```rust
fn spawn_shared_fut<
    T: Send + Clone + 'static,
    F: Future<Output = TaskResult<T>> + Send + 'static,
>(
    f: F,
    abort_handles: Option<&mut Vec<AbortHandle>>,
) -> TaskFuture<T> {
    let join_handle = tokio::spawn(f);
    if let Some(handles) = abort_handles {
        handles.push(join_handle.abort_handle());
    }
    async move {
        match join_handle.await {
            Ok(Ok(res)) => Ok(res),
            Ok(e @ Err(TaskError::PropagatedError(_))) => e,
            Ok(Err(e @ TaskError::InternalError(_) | e @ TaskError::JoinError(_))) => {
                Err(TaskError::PropagatedError(Box::new(e)))
            },
            Err(e) => Err(TaskError::JoinError(Arc::new(e))),
        }
    }
    .boxed()
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

**File:** config/src/config/consensus_config.rs (L177-183)
```rust
            lookback_config: ExecutionBackpressureLookbackConfig {
                num_blocks_to_look_at: 30,
                min_block_time_ms_to_activate: 10,
                min_blocks_to_activate: 4,
                metric: ExecutionBackpressureMetric::Mean,
                target_block_time_ms: 90,
            },
```

**File:** config/src/config/consensus_config.rs (L235-239)
```rust
            round_initial_timeout_ms: 1000,
            // 1.2^6 ~= 3
            // Timeout goes from initial_timeout to initial_timeout*3 in 6 steps
            round_timeout_backoff_exponent_base: 1.2,
            round_timeout_backoff_max_exponent: 6,
```

**File:** consensus/src/round_manager.rs (L993-1043)
```rust
    pub async fn process_local_timeout(&mut self, round: Round) -> anyhow::Result<()> {
        if !self.round_state.process_local_timeout(round) {
            return Ok(());
        }

        if self.sync_only() {
            self.network
                .broadcast_sync_info(self.block_store.sync_info())
                .await;
            bail!("[RoundManager] sync_only flag is set, broadcasting SyncInfo");
        }

        if self.local_config.enable_round_timeout_msg {
            let timeout = if let Some(timeout) = self.round_state.timeout_sent() {
                timeout
            } else {
                let timeout = TwoChainTimeout::new(
                    self.epoch_state.epoch,
                    round,
                    self.block_store.highest_quorum_cert().as_ref().clone(),
                );
                let signature = self
                    .safety_rules
                    .lock()
                    .sign_timeout_with_qc(
                        &timeout,
                        self.block_store.highest_2chain_timeout_cert().as_deref(),
                    )
                    .context("[RoundManager] SafetyRules signs 2-chain timeout")?;

                let timeout_reason = self.compute_timeout_reason(round);

                RoundTimeout::new(
                    timeout,
                    self.proposal_generator.author(),
                    timeout_reason,
                    signature,
                )
            };

            self.round_state.record_round_timeout(timeout.clone());
            let round_timeout_msg = RoundTimeoutMsg::new(timeout, self.block_store.sync_info());
            self.network
                .broadcast_round_timeout(round_timeout_msg)
                .await;
            warn!(
                round = round,
                remote_peer = self.proposer_election.get_valid_proposer(round),
                event = LogEvent::Timeout,
            );
            bail!("Round {} timeout, broadcast to all peers", round);
```
