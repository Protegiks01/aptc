# Audit Report

## Title
Race Condition in SecretShareManager Causes Validator Panic During State Sync

## Summary
A critical race condition exists in the consensus pipeline where `SecretShareManager` attempts to access pipeline futures on blocks that have been aborted during state synchronization, causing validator nodes to panic and halt. The root cause is that the `reset()` function only notifies `BufferManager` and `RandManager` to abort pipelines, but completely omits `SecretShareManager`.

## Finding Description

During state synchronization operations, the `ExecutionProxyClient::reset()` function is called to reset the consensus pipeline to a target round. However, this function contains a critical omission that leads to a validator panic.

The `reset()` function reads only two of the three manager reset channels from the handle, completely omitting the `SecretShareManager`: [1](#0-0) 

Despite the handle storing the `reset_tx_to_secret_share_manager` channel: [2](#0-1) 

The reset function never reads or uses it. The comment at line 653 explicitly states "Reset the rand and buffer managers" - confirming the omission is in the original design: [3](#0-2) 

When `BufferManager` receives the reset signal, it aborts all pipeline futures for buffered blocks: [4](#0-3) 

The `abort_pipeline()` method sets the `pipeline_futs` field to `None`: [5](#0-4) 

Meanwhile, `SecretShareManager` continues processing blocks and unconditionally expects pipeline futures to exist: [6](#0-5) 

The critical issue is that `OrderedBlocks` contains `Vec<Arc<PipelinedBlock>>`, meaning cloning only increments reference counts - both managers receive references to the SAME block objects: [7](#0-6) 

The coordinator distributes these shared blocks to both managers: [8](#0-7) 

**Attack Scenario:**
1. Validator triggers state sync (common during restarts, network issues, or when falling behind)
2. `sync_for_duration()` or `sync_to_target()` calls `reset()`: [9](#0-8) [10](#0-9) 
3. `reset()` sends reset signal to `BufferManager` and `RandManager` but NOT to `SecretShareManager`: [11](#0-10) 
4. `BufferManager` aborts pipeline futures for all shared `Arc<PipelinedBlock>` objects
5. `SecretShareManager` continues processing blocks from its queue
6. Calls `pipeline_futs().expect("pipeline must exist")` - returns `None`
7. Validator panics with message "pipeline must exist"
8. Validator process crashes and requires manual restart

## Impact Explanation

This vulnerability qualifies for **Critical Severity** under the Aptos bug bounty program as **Total Loss of Liveness/Network Availability**:

- **Immediate Validator Halt**: The panic causes the validator process to crash immediately, stopping all consensus participation
- **Non-recoverable Without Intervention**: Requires manual node restart and does not automatically recover
- **Cascading Failures**: Multiple validators may trigger state sync simultaneously (e.g., during network disruptions), causing coordinated crashes
- **BFT Threshold Risk**: If >1/3 of validators crash simultaneously, the network loses its Byzantine fault tolerance guarantees
- **Deterministic Trigger**: Once the race condition occurs, the panic is guaranteed

The vulnerability breaks the fundamental liveness guarantee that honest validators should remain operational during normal protocol operations like state synchronization.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to occur in production because:

1. **Frequent Trigger**: State synchronization is a common operation triggered by validator restarts, network latency, or temporary disconnections
2. **Wide Race Window**: The time between when blocks enter `SecretShareManager`'s processing queue and when `BufferManager` aborts them provides a substantial window for the race condition
3. **No Safeguards**: There are no defensive checks, timeouts, or graceful degradation mechanisms to prevent the panic
4. **Secret Sharing Enabled**: The vulnerability affects all validators running with secret sharing configuration enabled: [12](#0-11) 
5. **Byzantine Amplification**: Malicious validators can deliberately cause honest validators to lag (via block withholding or network disruption), triggering state sync

## Recommendation

Modify the `ExecutionProxyClient::reset()` function to include reset handling for `SecretShareManager`. The function should extract all three reset channels and send reset signals to all managers:

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

    // Add reset handling for SecretShareManager
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

Also update the comment at line 653 to reflect that all three managers are being reset.

## Proof of Concept

The vulnerability can be demonstrated by triggering a state sync operation while blocks are in the SecretShareManager's queue:

1. Configure a validator with secret sharing enabled
2. Start the validator and allow it to participate in consensus
3. Trigger state sync (either by stopping the validator temporarily or simulating network lag)
4. Observe that the validator panics with "pipeline must exist" when SecretShareManager attempts to process blocks whose pipeline futures were aborted by BufferManager

The panic occurs because:
- `BufferManager::reset()` calls `abort_pipeline()` on shared blocks
- `abort_pipeline()` sets `pipeline_futs` to `None` via `take()`
- `SecretShareManager::process_incoming_block()` calls `pipeline_futs().expect()` which panics on `None`

This can be verified by examining the execution flow during state sync operations and observing the validator crash logs.

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

**File:** consensus/src/pipeline/execution_client.rs (L334-339)
```rust
                    Some(ordered_blocks) = ordered_block_rx.next() => {
                        let _ = rand_manager_input_tx.send(ordered_blocks.clone()).await;
                        let _ = secret_share_manager_input_tx.send(ordered_blocks.clone()).await;
                        let first_block_id = ordered_blocks.ordered_blocks.first().expect("Cannot be empty").id();
                        inflight_block_tracker.insert(first_block_id, (ordered_blocks, false, false));
                        inflight_block_tracker.entry(first_block_id)
```

**File:** consensus/src/pipeline/execution_client.rs (L400-436)
```rust
            (Some(rand_config), Some(secret_sharing_config)) => {
                let (rand_manager_input_tx, rand_ready_block_rx, reset_tx_to_rand_manager) = self
                    .make_rand_manager(
                        &epoch_state,
                        fast_rand_config,
                        rand_msg_rx,
                        highest_committed_round,
                        &network_sender,
                        rand_config,
                        consensus_sk,
                    );

                let (
                    secret_share_manager_input_tx,
                    secret_ready_block_rx,
                    reset_tx_to_secret_share_manager,
                ) = self.make_secret_sharing_manager(
                    &epoch_state,
                    secret_sharing_config,
                    secret_sharing_msg_rx,
                    highest_committed_round,
                    &network_sender,
                );

                let (ordered_block_tx, ready_block_rx) = Self::make_coordinator(
                    rand_manager_input_tx,
                    rand_ready_block_rx,
                    secret_share_manager_input_tx,
                    secret_ready_block_rx,
                );

                (
                    ordered_block_tx,
                    ready_block_rx,
                    Some(reset_tx_to_rand_manager),
                    Some(reset_tx_to_secret_share_manager),
                )
```

**File:** consensus/src/pipeline/execution_client.rs (L653-656)
```rust
        // Reset the rand and buffer managers to the new synced round
        if let Ok(latest_synced_ledger_info) = &result {
            self.reset(latest_synced_ledger_info).await?;
        }
```

**File:** consensus/src/pipeline/execution_client.rs (L666-667)
```rust
        // Reset the rand and buffer managers to the target round
        self.reset(&target).await?;
```

**File:** consensus/src/pipeline/execution_client.rs (L674-681)
```rust
    async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
        let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager) = {
            let handle = self.handle.read();
            (
                handle.reset_tx_to_rand_manager.clone(),
                handle.reset_tx_to_buffer_manager.clone(),
            )
        };
```

**File:** consensus/src/pipeline/execution_client.rs (L695-706)
```rust
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
```

**File:** consensus/src/pipeline/buffer_manager.rs (L79-83)
```rust
#[derive(Clone)]
pub struct OrderedBlocks {
    pub ordered_blocks: Vec<Arc<PipelinedBlock>>,
    pub ordered_proof: LedgerInfoWithSignatures,
}
```

**File:** consensus/src/pipeline/buffer_manager.rs (L546-558)
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
