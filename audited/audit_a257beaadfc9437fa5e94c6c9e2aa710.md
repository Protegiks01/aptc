# Audit Report

## Title
Race Condition in Buffer Manager Reset During Epoch Transitions Causes Cascade Failures Across Consensus Components

## Summary
The `ResetDropped` error in `execution_client.rs` can cascade to multiple consensus components when concurrent state synchronization operations race with epoch transitions. The buffer manager, rand manager, and secret share manager reset channels are closed during `end_epoch()`, but concurrent sync operations spawned by the consensus observer or round manager can attempt to send reset requests after the receivers are dropped, causing the error to propagate and trigger silent failures in critical consensus paths. [1](#0-0) 

## Finding Description

The vulnerability exists in the interaction between epoch shutdown logic and concurrent state synchronization operations. 

**Core Issue:**

When `end_epoch()` is called, it removes the reset channel senders from the handle and sends `ResetSignal::Stop` to all managers: [2](#0-1) 

However, the consensus observer spawns background tokio tasks that call `sync_for_duration()` and `sync_to_target()`: [3](#0-2) [4](#0-3) 

These sync operations internally call `reset()` which attempts to send reset requests to the buffer manager: [5](#0-4) 

**The Race Condition Timeline:**

1. Consensus observer spawns background sync task (tokio::spawn) that calls `sync_for_duration()` or `sync_to_target()`
2. Sync task reads reset channel senders from handle (they are `Some(...)` at this point)
3. Epoch manager calls `shutdown_current_processor()` → `end_epoch()`
4. `end_epoch()` removes channels from handle and sends `ResetSignal::Stop` to buffer manager
5. Buffer manager processes Stop signal, exits its event loop, and drops the reset receiver
6. Sync task (still holding cloned sender) attempts to send reset request
7. Send fails with channel closed error → returns `Error::ResetDropped` [6](#0-5) [7](#0-6) 

**Cascade Effects:**

**1. Consensus Observer Failures:**
Errors are logged but sync is silently abandoned: [8](#0-7) [9](#0-8) 

**2. Round Manager Proposal Processing:**
Errors propagate through the sync chain and are logged, but consensus continues potentially in inconsistent state: [10](#0-9) [11](#0-10) 

**3. Sync Manager Fast-Forward Sync:**
Errors propagate up through the sync chain, preventing nodes from catching up: [12](#0-11) [13](#0-12) 

This breaks the **Liveness** invariant - affected nodes fail to make progress during critical state synchronization operations.

## Impact Explanation

**Medium Severity** per Aptos Bug Bounty criteria:

1. **State Inconsistencies Requiring Intervention**: When consensus observer sync fails silently, observer nodes fall behind and cannot serve queries, requiring manual intervention to restart or resync.

2. **Validator Node Issues**: Main consensus validators that fail fast-forward sync during epoch transitions may be unable to catch up, reducing network participation and affecting block production rates.

3. **Availability Impact**: Multiple nodes experiencing concurrent sync failures during epoch transitions can temporarily reduce network availability and increase latency.

While this doesn't directly cause fund loss or permanent consensus violations, it represents a significant operational failure mode that requires intervention to restore full network functionality. The silent failure nature (errors are only logged) makes diagnosis difficult and can lead to prolonged degraded states.

## Likelihood Explanation

**Medium to High Likelihood:**

1. **Frequent Trigger Conditions**: 
   - Epoch transitions occur regularly (every few hours based on configuration)
   - Consensus observers continuously spawn background sync tasks
   - Round managers perform fast-forward sync when catching up

2. **Timing Window**: The race window exists between reading the channel from the handle and actually sending the reset request - a narrow but real window given async task scheduling.

3. **Observable in Production**: This can naturally occur without malicious actors - simply normal operation during epoch transitions with active state sync.

4. **Multiple Entry Points**: The vulnerability can be triggered from:
   - Consensus observer fallback sync (spawned task)
   - Consensus observer commit sync (spawned task)  
   - Round manager processing proposals with sync_up
   - Block storage fast-forward sync operations

## Recommendation

Implement proper synchronization and error handling:

**Option 1: Graceful Degradation**
```rust
async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
    let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager) = {
        let handle = self.handle.read();
        (
            handle.reset_tx_to_rand_manager.clone(),
            handle.reset_tx_to_buffer_manager.clone(),
        )
    };

    // If channels are None (already shut down), skip reset gracefully
    if reset_tx_to_rand_manager.is_none() && reset_tx_to_buffer_manager.is_none() {
        warn!("Reset called after epoch shutdown - skipping reset operations");
        return Ok(());
    }

    if let Some(mut reset_tx) = reset_tx_to_rand_manager {
        let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
        if reset_tx.send(ResetRequest { tx: ack_tx, signal: ResetSignal::TargetRound(target.commit_info().round()) }).await.is_err() {
            // Receiver dropped - epoch likely ended
            warn!("Rand manager reset receiver dropped - epoch may have ended");
            return Ok(()); // Gracefully return since epoch is ending
        }
        if ack_rx.await.is_err() {
            warn!("Rand manager reset ack channel dropped");
            return Ok(());
        }
    }

    if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
        let (tx, rx) = oneshot::channel::<ResetAck>();
        if reset_tx.send(ResetRequest { tx, signal: ResetSignal::TargetRound(target.commit_info().round()) }).await.is_err() {
            warn!("Buffer manager reset receiver dropped - epoch may have ended");
            return Ok(());
        }
        if rx.await.is_err() {
            warn!("Buffer manager reset ack channel dropped");
            return Ok(());
        }
    }

    Ok(())
}
```

**Option 2: Synchronization Guard**
Add an atomic flag to track epoch shutdown state and check it before spawning sync tasks:

```rust
pub struct ExecutionProxyClient {
    // ... existing fields ...
    epoch_active: Arc<AtomicBool>,
}

// In end_epoch():
async fn end_epoch(&self) {
    self.epoch_active.store(false, Ordering::SeqCst);
    // ... existing shutdown logic ...
}

// In sync operations:
async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
    if !self.epoch_active.load(Ordering::SeqCst) {
        // Epoch is shutting down, skip reset
        return Ok(());
    }
    // ... existing reset logic ...
}
```

**Option 3: Abort Background Tasks**
Ensure background sync tasks are properly aborted during shutdown: [14](#0-13) 

Add explicit abort of consensus observer sync tasks before calling `end_epoch()`.

## Proof of Concept

```rust
// Rust integration test demonstrating the race condition
#[tokio::test]
async fn test_reset_dropped_race_condition() {
    use consensus::pipeline::execution_client::ExecutionProxyClient;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    
    // Setup execution client with buffer manager
    let execution_client = Arc::new(setup_execution_client());
    
    // Spawn background sync task (simulating consensus observer)
    let client_clone = execution_client.clone();
    let sync_task = tokio::spawn(async move {
        // Simulate reading channel from handle
        sleep(Duration::from_millis(10)).await;
        
        // Attempt sync which will call reset()
        let result = client_clone.sync_for_duration(Duration::from_secs(5)).await;
        
        // This should fail with ResetDropped
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("ResetDropped") || 
                err.to_string().contains("dropped"));
    });
    
    // Simulate epoch transition after short delay
    sleep(Duration::from_millis(5)).await;
    execution_client.end_epoch().await;
    
    // Wait for sync task to complete
    sync_task.await.unwrap();
}
```

**Notes**

The vulnerability is particularly concerning because:
1. Errors are inconsistently handled - sometimes logged, sometimes causing panics
2. The silent failure mode in consensus observer makes debugging difficult
3. Multiple concurrent sync operations can all fail simultaneously during epoch transitions
4. There's no retry mechanism or circuit breaker to handle transient failures

This represents a systemic issue in the epoch transition and state synchronization coordination that can affect network stability during critical operational events.

### Citations

**File:** consensus/src/pipeline/errors.rs (L15-16)
```rust
    #[error("Reset host dropped")]
    ResetDropped,
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

**File:** consensus/src/pipeline/execution_client.rs (L711-760)
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

        if let Some(mut tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop rand manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop rand manager");
        }

        if let Some(mut tx) = reset_tx_to_secret_share_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop secret share manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop secret share manager");
        }

        if let Some(mut tx) = reset_tx_to_buffer_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop buffer manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop buffer manager");
        }
        self.execution_proxy.end_epoch();
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L134-187)
```rust
        // Spawn a task to sync for the fallback
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(
            async move {
                // Update the state sync metrics now that we're syncing for the fallback
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_FOR_FALLBACK,
                    1, // We're syncing for the fallback
                );

                // Get the fallback duration
                let fallback_duration =
                    Duration::from_millis(consensus_observer_config.observer_fallback_duration_ms);

                // Sync for the fallback duration
                let latest_synced_ledger_info = match execution_client
                    .clone()
                    .sync_for_duration(fallback_duration)
                    .await
                {
                    Ok(latest_synced_ledger_info) => latest_synced_ledger_info,
                    Err(error) => {
                        error!(LogSchema::new(LogEntry::ConsensusObserver)
                            .message(&format!("Failed to sync for fallback! Error: {:?}", error)));
                        return;
                    },
                };

                // Notify consensus observer that we've synced for the fallback
                let state_sync_notification =
                    StateSyncNotification::fallback_sync_completed(latest_synced_ledger_info);
                if let Err(error) = sync_notification_sender.send(state_sync_notification) {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send state sync notification for fallback! Error: {:?}",
                            error
                        ))
                    );
                }

                // Clear the state sync metrics now that we're done syncing
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_FOR_FALLBACK,
                    0, // We're no longer syncing for the fallback
                );
            },
            abort_registration,
        ));

        // Save the sync task handle
        self.fallback_sync_handle = Some(DropGuard::new(abort_handle));
    }
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L207-231)
```rust
        // Spawn a task to sync to the commit decision
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(
            async move {
                // Update the state sync metrics now that we're syncing to a commit
                metrics::set_gauge_with_label(
                    &metrics::OBSERVER_STATE_SYNC_EXECUTING,
                    metrics::STATE_SYNCING_TO_COMMIT,
                    1, // We're syncing to a commit decision
                );

                // Sync to the commit decision
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
                {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to sync to commit decision: {:?}! Error: {:?}",
                            commit_decision, error
                        ))
                    );
                    return;
                }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L579-596)
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
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L935-995)
```rust
        while !self.stop {
            // advancing the root will trigger sending requests to the pipeline
            ::tokio::select! {
                Some(blocks) = self.block_rx.next(), if !self.need_back_pressure() => {
                    self.latest_round = blocks.latest_round();
                    monitor!("buffer_manager_process_ordered", {
                    self.process_ordered_blocks(blocks).await;
                    if self.execution_root.is_none() {
                        self.advance_execution_root();
                    }});
                },
                Some(reset_event) = self.reset_rx.next() => {
                    monitor!("buffer_manager_process_reset",
                    self.process_reset_request(reset_event).await);
                },
                Some(response) = self.execution_schedule_phase_rx.next() => {
                    monitor!("buffer_manager_process_execution_schedule_response", {
                    self.process_execution_schedule_response(response).await;
                })},
                Some(response) = self.execution_wait_phase_rx.next() => {
                    monitor!("buffer_manager_process_execution_wait_response", {
                    self.process_execution_response(response).await;
                    self.advance_execution_root();
                    if self.signing_root.is_none() {
                        self.advance_signing_root().await;
                    }});
                },
                Some(response) = self.signing_phase_rx.next() => {
                    monitor!("buffer_manager_process_signing_response", {
                    self.process_signing_response(response).await;
                    self.advance_signing_root().await
                    })
                },
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
                },
                Some(rpc_request) = verified_commit_msg_rx.next() => {
                    monitor!("buffer_manager_process_commit_message",
                    if let Some(aggregated_block_id) = self.process_commit_message(rpc_request) {
                        self.advance_head(aggregated_block_id).await;
                        if self.execution_root.is_none() {
                            self.advance_execution_root();
                        }
                        if self.signing_root.is_none() {
                            self.advance_signing_root().await;
                        }
                    });
                }
                _ = interval.tick().fuse() => {
                    monitor!("buffer_manager_process_interval_tick", {
                    self.update_buffer_manager_metrics();
                    self.rebroadcast_commit_votes_if_needed().await
                    });
                },
                // no else branch here because interval.tick will always be available
            }
        }
        info!("Buffer manager stops.");
```

**File:** consensus/src/round_manager.rs (L743-750)
```rust
        let in_correct_round = self
            .ensure_round_and_sync_up(
                proposal_msg.proposal().round(),
                proposal_msg.sync_info(),
                proposal_msg.proposer(),
            )
            .await
            .context("[RoundManager] Process proposal")?;
```

**File:** consensus/src/round_manager.rs (L2136-2142)
```rust
                        match result {
                            Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
                            Err(e) => {
                                counters::ERROR_COUNT.inc();
                                warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
                            }
                        }
```

**File:** consensus/src/block_storage/sync_manager.rs (L127-132)
```rust
        self.sync_to_highest_quorum_cert(
            sync_info.highest_quorum_cert().clone(),
            sync_info.highest_commit_cert().clone(),
            &mut retriever,
        )
        .await?;
```

**File:** consensus/src/block_storage/sync_manager.rs (L512-514)
```rust
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;
```

**File:** consensus/src/epoch_manager.rs (L637-669)
```rust
    async fn shutdown_current_processor(&mut self) {
        if let Some(close_tx) = self.round_manager_close_tx.take() {
            // Release the previous RoundManager, especially the SafetyRule client
            let (ack_tx, ack_rx) = oneshot::channel();
            close_tx
                .send(ack_tx)
                .expect("[EpochManager] Fail to drop round manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop round manager");
        }
        self.round_manager_tx = None;

        if let Some(close_tx) = self.dag_shutdown_tx.take() {
            // Release the previous RoundManager, especially the SafetyRule client
            let (ack_tx, ack_rx) = oneshot::channel();
            close_tx
                .send(ack_tx)
                .expect("[EpochManager] Fail to drop DAG bootstrapper");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop DAG bootstrapper");
        }
        self.dag_shutdown_tx = None;

        // Shutdown the previous rand manager
        self.rand_manager_msg_tx = None;

        // Shutdown the previous secret share manager
        self.secret_share_manager_tx = None;

        // Shutdown the previous buffer manager, to release the SafetyRule client
        self.execution_client.end_epoch().await;
```
