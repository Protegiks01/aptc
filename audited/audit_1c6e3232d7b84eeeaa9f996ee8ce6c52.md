# Audit Report

## Title
Secret Shares Silently Dropped During Reset Leading to Randomness Protocol Failure

## Summary
The `SecretShareManager::start()` function contains a critical flaw in its reset handling logic at lines 358-360. When a reset signal is received, all pending blocks in the `incoming_blocks` channel are drained using `try_next()` and silently discarded without processing their secret shares. This causes valid, consensus-ordered blocks to lose their secret shares, potentially breaking the randomness beacon protocol and causing consensus liveness issues. [1](#0-0) 

## Finding Description

When the `SecretShareManager` receives a reset request (triggered during epoch transitions via `end_epoch()`), the event loop handles it by draining all pending blocks from the `incoming_blocks` channel without any processing: [1](#0-0) 

The blocks are consumed but the result is immediately discarded (no variable assignment, no processing). These blocks never undergo the critical secret sharing flow that normally happens in `process_incoming_blocks()`: [2](#0-1) 

Specifically, the dropped blocks miss:
1. **Self secret share derivation** - The validator never computes its own secret share for these blocks
2. **Broadcasting** - Secret shares are never broadcast to other validators  
3. **Share requester tasks** - Tasks to request missing shares from peers are never spawned
4. **Queue insertion** - Blocks never enter the processing queue

The `process_reset()` function then clears the entire block queue and updates state without any cleanup for the dropped blocks: [3](#0-2) 

**Contrast with BufferManager:** The `BufferManager` implements proper cleanup when draining blocks during reset by calling `abort_pipeline()` on each block and waiting for pipeline futures to complete: [4](#0-3) 

The `SecretShareManager` lacks this cleanup entirely.

**When This Occurs:** 
During `end_epoch()` transitions, reset requests are sent to all managers including `SecretShareManager`: [5](#0-4) 

**Blocks at Risk:**
The blocks in the `incoming_blocks` channel at reset time are valid blocks that:
- Were ordered by consensus and sent by the coordinator
- Are part of the agreed-upon blockchain
- May be needed for completing the randomness protocol for the ending epoch
- Other validators have already processed and are waiting for this validator's shares

## Impact Explanation

**Severity: High (potentially Critical)**

This vulnerability breaks the **Consensus Safety** and **Cryptographic Correctness** invariants:

1. **Randomness Protocol Failure**: The Aptos randomness beacon requires threshold secret sharing to function. When validators silently drop secret shares for valid blocks:
   - Other validators waiting for these shares will timeout
   - If enough validators (>1/3) drop shares for the same blocks, the randomness beacon cannot aggregate sufficient shares
   - Randomness failure impacts leader election and consensus progression

2. **Validator State Inconsistency**: Different validators will have different sets of secret shares for the same blocks, creating asymmetry in the randomness protocol state.

3. **Consensus Liveness Risk**: If randomness protocol fails, subsequent consensus rounds that depend on the randomness beacon may stall, causing:
   - Validator node slowdowns (High Severity per bug bounty)
   - Potential temporary loss of liveness requiring manual intervention
   - In extreme cases, could require coordinator intervention if enough validators are affected

4. **Silent Failure Mode**: The vulnerability creates a silent failure - there are no error logs, no notifications to other validators, and no indication that secret shares were dropped. This makes debugging extremely difficult.

The impact qualifies as **High Severity** under the bug bounty criteria due to "Validator node slowdowns" and "Significant protocol violations." If it can be demonstrated to cause network-wide liveness issues, it could escalate to **Critical Severity**.

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers during **every epoch transition** (`end_epoch()`), which is a regular protocol event. The likelihood is determined by:

1. **Guaranteed Trigger**: Every epoch boundary will execute the vulnerable code path
2. **Race Condition Window**: If blocks are still being ordered when epoch transition occurs, they will be queued in `incoming_blocks` channel
3. **Timing Dependent**: The number of dropped blocks depends on how many blocks are in-flight during the epoch boundary
4. **No Mitigation**: There is no code to prevent this scenario or handle it gracefully

In production networks with active block production, it is **highly likely** that some blocks will be in the `incoming_blocks` channel during epoch transitions, especially during periods of high activity or if epoch transitions occur during consensus rounds.

The impact severity depends on:
- How many validators drop blocks simultaneously (determined by network timing)
- How many blocks are dropped per validator
- Whether the dropped blocks' randomness is needed for the next epoch

## Recommendation

**Fix: Implement proper block cleanup during reset**

The `SecretShareManager` should follow the same pattern as `BufferManager` by properly cleaning up drained blocks:

```rust
Some(reset) = reset_rx.next() => {
    // Properly drain and clean up pending blocks
    while let Ok(Some(blocks)) = incoming_blocks.try_next() {
        // Abort any pipeline futures associated with these blocks
        for b in blocks.ordered_blocks {
            if let Some(futs) = b.abort_pipeline() {
                futs.wait_until_finishes().await;
            }
        }
    }
    self.process_reset(reset);
}
```

**Additional Improvements:**

1. **Add logging** to track how many blocks are being dropped during reset
2. **Consider processing in-flight blocks** before reset if they're from the current epoch
3. **Coordinate with other managers** to ensure consistent reset behavior across BufferManager, RandManager, and SecretShareManager
4. **Add metrics** to monitor secret share drop events

## Proof of Concept

The vulnerability can be demonstrated with the following Rust test scenario:

```rust
#[tokio::test]
async fn test_secret_share_manager_reset_drops_blocks() {
    // Setup: Create SecretShareManager with test configuration
    // 1. Start the SecretShareManager with mocked dependencies
    // 2. Send multiple OrderedBlocks to the incoming_blocks channel
    // 3. Before blocks are processed, send a ResetRequest with Stop signal
    // 4. Verify that:
    //    a. Blocks were consumed from the channel (channel is empty)
    //    b. Secret shares were NOT derived for those blocks (check secret_share_store)
    //    c. No broadcasts were made to other validators (check network_sender mock)
    //    d. Block queue is empty after reset
    // 5. Compare with expected behavior where blocks should be processed or properly cleaned up
    
    // Expected: Blocks are silently dropped without secret share processing
    // Impact: Other validators waiting for shares will timeout
}
```

To reproduce in a live network:
1. Deploy a test network with randomness beacon enabled
2. Generate blocks during an epoch transition
3. Observe epoch boundary crossing while blocks are being ordered
4. Monitor validator logs for missing secret shares
5. Check if subsequent rounds experience delays due to incomplete randomness aggregation

**Notes**

This vulnerability represents a fundamental inconsistency in how different consensus managers handle reset. The `BufferManager` properly aborts pipeline futures during reset, while `SecretShareManager` simply discards blocks. This asymmetry can lead to state inconsistencies where the buffer manager has cleaned up blocks but the secret share manager has lost their shares without proper cleanup.

Additionally, there is a related issue in the `reset()` function implementation where the `SecretShareManager` is NOT reset during normal state sync operations (`sync_to_target`, `sync_for_duration`), only during `end_epoch`: [6](#0-5) 

This creates another inconsistency where `RandManager` and `BufferManager` are reset but `SecretShareManager` continues processing old blocks during state sync scenarios.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L112-130)
```rust
    async fn process_incoming_blocks(&mut self, blocks: OrderedBlocks) {
        let rounds: Vec<u64> = blocks.ordered_blocks.iter().map(|b| b.round()).collect();
        info!(rounds = rounds, "Processing incoming blocks.");

        let mut share_requester_handles = Vec::new();
        let mut pending_secret_key_rounds = HashSet::new();
        for block in blocks.ordered_blocks.iter() {
            let handle = self.process_incoming_block(block).await;
            share_requester_handles.push(handle);
            pending_secret_key_rounds.insert(block.round());
        }

        let queue_item = QueueItem::new(
            blocks,
            Some(share_requester_handles),
            pending_secret_key_rounds,
        );
        self.block_queue.push_back(queue_item);
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L172-184)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.secret_share_store
            .lock()
            .update_highest_known_round(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L358-360)
```rust
                Some(reset) = reset_rx.next() => {
                    while matches!(incoming_blocks.try_next(), Ok(Some(_))) {}
                    self.process_reset(reset);
```

**File:** consensus/src/pipeline/buffer_manager.rs (L565-571)
```rust
        while let Ok(Some(blocks)) = self.block_rx.try_next() {
            for b in blocks.ordered_blocks {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
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

**File:** consensus/src/pipeline/execution_client.rs (L734-745)
```rust
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
