# Audit Report

## Title
SecretShareManager Panic During State Sync Due to Missing Pipeline Reset

## Summary
The `SecretShareManager::process_incoming_block()` function unconditionally expects pipeline futures to exist on blocks via `.expect("pipeline must exist")`. However, during state sync operations, the `BufferManager` aborts pipeline futures on blocks while the `SecretShareManager` is not reset, creating a race condition that causes a panic when the manager tries to access pipeline futures that have been removed. [1](#0-0) 

## Finding Description
The vulnerability occurs due to incomplete reset coordination between the `BufferManager` and `SecretShareManager` during state sync operations. Here's how the attack unfolds:

1. **Shared Block References**: When blocks are ordered, they are sent to both the `SecretShareManager` and `BufferManager` via cloned `OrderedBlocks` structures. Since these contain `Arc<PipelinedBlock>`, both managers share references to the same block instances. [2](#0-1) 

2. **Incomplete Reset Logic**: During state sync, the `ExecutionProxyClient::reset()` function sends reset signals to only the `rand_manager` and `buffer_manager`, but **omits** the `secret_share_manager`: [3](#0-2) 

Note that at lines 675-681, only two reset channels are extracted, despite the `BufferManagerHandle` containing three reset channels including `reset_tx_to_secret_share_manager`: [4](#0-3) 

3. **Pipeline Abortion**: When `BufferManager` receives a reset, it calls `abort_pipeline()` on blocks in its queue, which removes the `PipelineFutures` by calling `.take()`: [5](#0-4) [6](#0-5) 

4. **Panic Condition**: Meanwhile, `SecretShareManager` continues processing blocks from its queue because it was never reset. When it reaches line 133, it calls `pipeline_futs().expect()` on a block whose pipeline was already aborted, receiving `None` and triggering a panic: [7](#0-6) 

5. **Timing Window**: The race condition exists because the `SecretShareManager` event loop continues processing incoming blocks while the `BufferManager` reset is happening in parallel: [8](#0-7) 

The `SecretShareManager` only drains its queue when it receives a reset signal (line 359), but this signal is never sent during `sync_to_target()` operations.

## Impact Explanation
**Severity: High** (per Aptos Bug Bounty criteria for "Validator node slowdowns" and "API crashes")

This vulnerability causes:

1. **Component Failure**: The `SecretShareManager` task panics and terminates, disrupting the secret sharing subsystem critical for randomness generation in consensus.

2. **Consensus Disruption**: When secret sharing is enabled (for randomness in leader election and other consensus operations), the failure of this component can prevent the validator from participating properly in consensus.

3. **State Sync Vulnerability**: The issue is triggered during state sync operations, which are routine operations validators perform when catching up with the network. This makes the vulnerability easily triggerable during normal operations.

4. **No Attacker Required**: This is a protocol-level bug requiring no malicious actor—simply normal state sync operations can trigger the panic.

The impact qualifies as High severity because it causes validator node component failures that disrupt consensus participation, directly matching the "Validator node slowdowns" and "Significant protocol violations" criteria.

## Likelihood Explanation
**Likelihood: High**

This vulnerability is highly likely to occur because:

1. **Normal Operations**: State sync is a routine operation that validators perform regularly when syncing with the network, joining after downtime, or catching up after being behind.

2. **No Special Conditions**: No malicious actor, special network conditions, or Byzantine behavior is required—the vulnerability exists in the normal protocol flow.

3. **Race Condition Window**: The vulnerability has a realistic timing window. During state sync, blocks are continuously flowing through both `BufferManager` and `SecretShareManager`, and the reset coordination flaw creates a direct race.

4. **Enabled by Default**: When secret sharing is configured (for randomness), the vulnerable code path is active.

The likelihood is not "certain" only because it depends on the specific timing of when blocks are being processed by `SecretShareManager` versus when the reset occurs, but given the asynchronous nature of the system, this race will occur regularly in production.

## Recommendation

The fix requires sending reset signals to the `SecretShareManager` during state sync operations. Modify the `ExecutionProxyClient::reset()` function to include the secret share manager reset:

**File: `consensus/src/pipeline/execution_client.rs`**

Change the `reset()` function from: [3](#0-2) 

To include the secret share manager reset channel:

```rust
async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
    let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager, reset_tx_to_secret_share_manager) = {
        let handle = self.handle.read();
        (
            handle.reset_tx_to_rand_manager.clone(),
            handle.reset_tx_to_buffer_manager.clone(),
            handle.reset_tx_to_secret_share_manager.clone(),  // ADD THIS LINE
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

    // ADD THIS BLOCK
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

This ensures that during state sync, the `SecretShareManager` is reset **before** the `BufferManager` aborts pipelines, preventing the race condition.

## Proof of Concept

**Reproduction Steps:**

1. **Setup**: Start a validator node with secret sharing enabled in the consensus configuration.

2. **Trigger State Sync**: Force the node to perform state sync by:
   - Starting the node after being offline for some time
   - Or triggering `sync_to_target()` through state synchronization

3. **Race Condition**: During state sync:
   - Blocks are flowing to both `SecretShareManager` and `BufferManager`
   - The `reset()` function is called (line 667 in execution_client.rs)
   - `BufferManager` receives reset and aborts pipeline futures
   - `SecretShareManager` was not reset and continues processing
   - When `process_incoming_block()` executes line 133, it calls `.expect()` on `None`

4. **Observed Behavior**: The `SecretShareManager` task panics with the error message "pipeline must exist", terminating the secret sharing component.

**Code Path Trace:**
```
ExecutionProxyClient::sync_to_target() (execution_client.rs:643)
  └─> ExecutionProxyClient::reset() (execution_client.rs:674)
      ├─> Sends reset to rand_manager ✓
      ├─> Sends reset to secret_share_manager ✗ (MISSING)
      └─> Sends reset to buffer_manager ✓
          └─> BufferManager::reset() (buffer_manager.rs:546)
              └─> abort_pipeline() on blocks (buffer_manager.rs:567)
                  └─> pipeline_futs set to None (pipelined_block.rs:546)

Concurrently:
SecretShareManager::start() event loop (secret_share_manager.rs:354)
  └─> process_incoming_blocks() (secret_share_manager.rs:112)
      └─> process_incoming_block() (secret_share_manager.rs:132)
          └─> block.pipeline_futs().expect() → PANIC! (line 133)
```

**Notes**

This vulnerability demonstrates a critical oversight in the reset coordination logic between consensus pipeline components. The issue is particularly concerning because:

1. The `end_epoch()` function correctly resets all three components in the proper order, but the `reset()` function (used during state sync) omits the secret share manager.

2. The vulnerability only manifests when secret sharing is enabled, which is required for randomness-based features in Aptos consensus.

3. The fix is straightforward—simply include the secret share manager in the reset coordination—but the impact of not doing so is significant.

### Citations

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

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L354-360)
```rust
            tokio::select! {
                Some(blocks) = incoming_blocks.next() => {
                    self.process_incoming_blocks(blocks).await;
                }
                Some(reset) = reset_rx.next() => {
                    while matches!(incoming_blocks.try_next(), Ok(Some(_))) {}
                    self.process_reset(reset);
```

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

**File:** consensus/src/pipeline/buffer_manager.rs (L565-570)
```rust
        while let Ok(Some(blocks)) = self.block_rx.try_next() {
            for b in blocks.ordered_blocks {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L528-546)
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
```
