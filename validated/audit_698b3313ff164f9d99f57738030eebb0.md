# Audit Report

## Title
SecretShareManager Panic During State Sync Due to Missing Pipeline Reset

## Summary
During state sync operations, the `ExecutionProxyClient::reset()` method fails to send reset signals to the `SecretShareManager`, while simultaneously aborting pipeline futures on blocks that are shared between the `BufferManager` and `SecretShareManager`. This creates a race condition where `SecretShareManager` attempts to access pipeline futures that have been removed, causing a panic that terminates this critical consensus component.

## Finding Description

This vulnerability stems from incomplete reset coordination between pipeline managers during state sync operations.

**1. Shared Block References**: When blocks are ordered in consensus, they are sent to both the `SecretShareManager` and `BufferManager` via the coordinator, which clones `OrderedBlocks` structures containing `Vec<Arc<PipelinedBlock>>`. Both managers share references to identical block instances. [1](#0-0) [2](#0-1) 

**2. Incomplete Reset Logic**: During state sync operations (`sync_to_target` and `sync_for_duration`), the `ExecutionProxyClient::reset()` method only extracts and sends reset signals to `rand_manager` and `buffer_manager`, completely omitting the `secret_share_manager`: [3](#0-2) 

Despite the `BufferManagerHandle` structure containing the `reset_tx_to_secret_share_manager` channel: [4](#0-3) 

**3. Pipeline Abortion**: When `BufferManager` receives the reset signal, it calls `reset()` which invokes `abort_pipeline()` on all blocks in its queue: [5](#0-4) 

The `abort_pipeline()` method removes the `PipelineFutures` by calling `.take()` on the mutex: [6](#0-5) 

**4. Panic Condition**: Meanwhile, `SecretShareManager` continues processing blocks from its incoming queue because it never received a reset signal. When it processes a block and attempts to access pipeline futures, it encounters `None` and panics: [7](#0-6) 

**5. Race Condition Window**: The `SecretShareManager` event loop only drains its incoming blocks queue when it receives a reset signal: [8](#0-7) 

However, this reset signal is never sent during `sync_to_target()` or `sync_for_duration()` operations.

**Confirmation via end_epoch()**: The developers clearly understood that all three managers need reset coordination, as evidenced by the `end_epoch()` method which properly extracts and resets all three managers including `SecretShareManager`: [9](#0-8) 

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty "Validator node slowdowns" criteria)

This vulnerability causes:

1. **Task Termination**: The `SecretShareManager` task panics and terminates, completely disabling the secret sharing subsystem.

2. **Consensus Disruption**: When secret sharing is enabled for randomness generation (used in leader election and consensus operations), the failure of this component prevents the validator from properly participating in consensus protocols.

3. **Triggering via Normal Operations**: State sync is triggered during routine validator operations when catching up with the network or during epoch transitions. [10](#0-9) [11](#0-10) 

4. **No Attacker Required**: This is a protocol-level bug requiring no malicious actor—normal state sync operations trigger the vulnerability.

The impact qualifies as High severity because it causes validator component failures that directly disrupt consensus participation, matching the "Validator node slowdowns" criteria in the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to occur because:

1. **Routine Operations**: State sync is performed regularly by validators when syncing with the network, recovering from downtime, or catching up after falling behind.

2. **No Special Conditions**: No Byzantine behavior, malicious actors, or special network conditions are required—the vulnerability exists in the normal protocol flow.

3. **Realistic Timing Window**: The race condition has a genuine timing window. During state sync, blocks continuously flow through both managers asynchronously. When `BufferManager` starts aborting pipelines while `SecretShareManager` processes blocks, the panic condition occurs.

4. **Active When Configured**: When secret sharing is configured for randomness (a production feature), the vulnerable code path is active.

## Recommendation

Modify the `ExecutionProxyClient::reset()` method to extract and send reset signals to all three managers, including `SecretShareManager`:

```rust
async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
    let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager, reset_tx_to_secret_share_manager) = {
        let handle = self.handle.read();
        (
            handle.reset_tx_to_rand_manager.clone(),
            handle.reset_tx_to_buffer_manager.clone(),
            handle.reset_tx_to_secret_share_manager.clone(), // Add this line
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

    // Add reset for SecretShareManager
    if let Some(mut reset_tx) = reset_tx_to_secret_share_manager {
        let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
        reset_tx
            .send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::TargetRound(target.commit_info().round()),
            })
            .await
            .map_err(|_| Error::SecretShareResetDropped)?;
        ack_rx.await.map_err(|_| Error::SecretShareResetDropped)?;
    }

    if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
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

This ensures all managers receive reset coordination signals during state sync operations, preventing the race condition.

## Proof of Concept

The vulnerability can be triggered by:

1. Starting a validator node with secret sharing configured for randomness
2. Allowing blocks to flow through the consensus pipeline
3. Triggering a state sync operation via `sync_to_target()` or `sync_for_duration()`
4. Observing the panic when `SecretShareManager` attempts to access aborted pipeline futures

The panic message would be: "pipeline must exist" from the `.expect()` call in `process_incoming_block()`.

## Notes

This vulnerability demonstrates a coordination failure in the consensus pipeline reset logic. The developers clearly understood the need for coordinating resets across all three managers, as evidenced by the correct implementation in `end_epoch()`. However, the `reset()` method used during state sync operations was not updated to include `SecretShareManager`, creating this critical race condition. The fix is straightforward and follows the existing pattern established in `end_epoch()`.

### Citations

**File:** consensus/src/pipeline/execution_client.rs (L124-131)
```rust
struct BufferManagerHandle {
    pub execute_tx: Option<UnboundedSender<OrderedBlocks>>,
    pub commit_tx:
        Option<aptos_channel::Sender<AccountAddress, (AccountAddress, IncomingCommitRequest)>>,
    pub reset_tx_to_buffer_manager: Option<UnboundedSender<ResetRequest>>,
    pub reset_tx_to_rand_manager: Option<UnboundedSender<ResetRequest>>,
    pub reset_tx_to_secret_share_manager: Option<UnboundedSender<ResetRequest>>,
}
```

**File:** consensus/src/pipeline/execution_client.rs (L335-336)
```rust
                        let _ = rand_manager_input_tx.send(ordered_blocks.clone()).await;
                        let _ = secret_share_manager_input_tx.send(ordered_blocks.clone()).await;
```

**File:** consensus/src/pipeline/execution_client.rs (L642-658)
```rust
    async fn sync_for_duration(
        &self,
        duration: Duration,
    ) -> Result<LedgerInfoWithSignatures, StateSyncError> {
        fail_point!("consensus::sync_for_duration", |_| {
            Err(anyhow::anyhow!("Injected error in sync_for_duration").into())
        });

        // Sync for the specified duration
        let result = self.execution_proxy.sync_for_duration(duration).await;

        // Reset the rand and buffer managers to the new synced round
        if let Ok(latest_synced_ledger_info) = &result {
            self.reset(latest_synced_ledger_info).await?;
        }

        result
```

**File:** consensus/src/pipeline/execution_client.rs (L661-671)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Reset the rand and buffer managers to the target round
        self.reset(&target).await?;

        // TODO: handle the state sync error (e.g., re-push the ordered
        // blocks to the buffer manager when it's reset but sync fails).
        self.execution_proxy.sync_to_target(target).await
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

**File:** consensus/src/pipeline/execution_client.rs (L711-745)
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
```

**File:** consensus/src/pipeline/buffer_manager.rs (L79-83)
```rust
#[derive(Clone)]
pub struct OrderedBlocks {
    pub ordered_blocks: Vec<Arc<PipelinedBlock>>,
    pub ordered_proof: LedgerInfoWithSignatures,
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

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L132-138)
```rust
    async fn process_incoming_block(&self, block: &PipelinedBlock) -> DropGuard {
        let futures = block.pipeline_futs().expect("pipeline must exist");
        let self_secret_share = futures
            .secret_sharing_derive_self_fut
            .await
            .expect("Decryption share computation is expected to succeed")
            .expect("Must not be None");
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L353-361)
```rust
        while !self.stop {
            tokio::select! {
                Some(blocks) = incoming_blocks.next() => {
                    self.process_incoming_blocks(blocks).await;
                }
                Some(reset) = reset_rx.next() => {
                    while matches!(incoming_blocks.try_next(), Ok(Some(_))) {}
                    self.process_reset(reset);
                }
```
