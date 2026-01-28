# Audit Report

## Title
Silent Failure in Secret Share Aggregation Causes Undetectable Consensus Stall

## Summary
The secret sharing pipeline in Aptos consensus has two critical bugs that combine to create an undetectable consensus stall condition: (1) `unbounded_send()` failures are silently ignored when sending aggregated secret keys, and (2) the `SecretShareManager` is not reset during `sync_to_target()` operations while other pipeline components are reset, creating state desynchronization. When these bugs interact during validator catch-up scenarios, blocks can become permanently stuck waiting for secret keys with no detection or recovery mechanism.

## Finding Description

The vulnerability exists in the consensus secret sharing pipeline, which processes encrypted transaction decryption. The issue involves two distinct but related bugs:

**Bug #1: Silent Send Failure**

In the secret share aggregation path, when enough shares are collected to reconstruct a secret key, the result is sent via an unbounded channel but the send operation's result is completely ignored. [1](#0-0) 

The `unbounded_send()` call returns a `Result<(), SendError>`, but it's discarded with `let _ =`. If the send fails because the receiver is disconnected, the aggregated key is silently lost with no error logging, monitoring, or recovery.

Similarly, when ready blocks are sent downstream: [2](#0-1) 

**Bug #2: Missing Reset of SecretShareManager**

During state synchronization operations, the `reset()` method only extracts and resets two of three available reset senders: [3](#0-2) 

However, the `BufferManagerHandle::reset()` method returns THREE reset senders: [4](#0-3) 

The third sender (`reset_tx_to_secret_share_manager`) is never extracted or used, meaning `SecretShareManager` is never reset during `sync_to_target()` operations, while `RandManager` and `BufferManager` are properly reset.

**Attack Path:**

1. Validator processes blocks normally at rounds 100-110, collecting secret shares
2. Some blocks reach aggregation threshold and spawn background cryptographic tasks
3. A `sync_to_target(round 200)` is triggered when the validator falls behind
4. The `reset()` method resets `rand_manager` and `buffer_manager` to round 200
5. The `secret_share_manager` is NOT reset - it still has blocks 100-110 in its queue
6. New blocks at round 200+ arrive and are added to the queue
7. The `dequeue_ready_prefix()` method only dequeues a contiguous prefix of ready blocks: [5](#0-4) 

Since blocks 100-110 are not ready (awaiting secret shares that will never arrive because the validator moved on), they block all subsequent blocks 200+ from being dequeued and processed.

The `SecretShareManager` has a `process_reset()` method that properly clears the block queue: [6](#0-5) 

However, this method is never invoked during `sync_to_target()` operations because the reset request is never sent.

**No Detection Mechanism:**

The only observable metric tracks queue size but triggers no automated action: [7](#0-6) 

There is no timeout, staleness detection, or recovery mechanism for missing secret keys.

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

1. **Validator Node Slowdowns**: Affected validators cannot process blocks past the stalled point, causing severe performance degradation affecting consensus participation
2. **Significant Protocol Violations**: Breaks the consensus liveness invariant that blocks should eventually be processed
3. **Partial Loss of Network Availability**: Validators experiencing this issue stop contributing to consensus, reducing the effective validator set size

The impact manifests as:
- Individual validators falling permanently out of sync
- Manual intervention (node restart) required for recovery
- Potential cascading failures as more validators fall behind and trigger `sync_to_target()`
- No automated detection or alerting exists
- The `DEC_QUEUE_SIZE` metric provides no actionable information

While not every validator is affected simultaneously, repeated occurrences can significantly degrade network health and reduce effective validator participation.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability occurs during normal network operations:

1. **Trigger Condition**: `sync_to_target()` is called whenever validators fall behind, which happens during:
   - Network partitions or connectivity issues
   - Validator restarts and catch-up periods
   - High load when some validators lag
   - Rapid block production periods

2. **Frequency**: State synchronization is common in production networks, especially during network instability or validator maintenance windows

3. **Race Window**: The window exists between when secret share aggregation begins (spawning blocking cryptographic computation tasks) and when `sync_to_target()` is called - this can span hundreds of milliseconds

4. **No Mitigations**: No safeguards, timeouts, or recovery mechanisms exist to prevent or detect this condition

The combination of frequent trigger conditions during normal operations and absence of defensive mechanisms makes this a realistic threat in production environments.

## Recommendation

**Fix Bug #2** by ensuring `SecretShareManager` is reset during `sync_to_target()`:

In `ExecutionProxyClient::reset()`, extract all three reset senders:

```rust
async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
    let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager, reset_tx_to_secret_share_manager) = {
        let handle = self.handle.read();
        (
            handle.reset_tx_to_rand_manager.clone(),
            handle.reset_tx_to_buffer_manager.clone(),
            handle.reset_tx_to_secret_share_manager.clone(),  // ADD THIS
        )
    };

    // Reset rand_manager...
    
    // Reset secret_share_manager
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

    // Reset buffer_manager...
    
    Ok(())
}
```

**Fix Bug #1** by logging send failures:

```rust
if let Err(e) = decision_tx.unbounded_send(dec_key) {
    warn!("Failed to send aggregated secret key: {}", e);
}
```

## Proof of Concept

While a full runnable PoC would require a complex multi-validator test setup, the vulnerability can be demonstrated through code inspection:

1. The `reset()` method demonstrably omits `reset_tx_to_secret_share_manager` extraction despite it being returned by `BufferManagerHandle::reset()`
2. During `sync_to_target()`, only `rand_manager` and `buffer_manager` receive reset signals
3. The `block_queue.dequeue_ready_prefix()` logic clearly shows contiguous prefix dequeuing
4. Stale blocks without secret keys would block all subsequent blocks indefinitely

The vulnerability is directly observable from the code structure and can be reproduced by triggering `sync_to_target()` on a validator with pending secret share aggregation tasks.

## Notes

This vulnerability represents a state desynchronization bug in the consensus pipeline where component reset operations are incomplete. The missing reset of `SecretShareManager` during validator catch-up creates a permanent liveness failure for affected validators with no automated recovery path. The issue is exacerbated by silent error handling in the aggregation pipeline, making diagnosis difficult for operators.

### Citations

**File:** consensus/src/rand/secret_sharing/secret_share_store.rs (L55-70)
```rust
        tokio::task::spawn_blocking(move || {
            let maybe_key = SecretShare::aggregate(self.shares.values(), &dec_config);
            match maybe_key {
                Ok(key) => {
                    let dec_key = SecretSharedKey::new(metadata, key);
                    let _ = decision_tx.unbounded_send(dec_key);
                },
                Err(e) => {
                    warn!(
                        epoch = metadata.epoch,
                        round = metadata.round,
                        "Aggregation error: {e}"
                    );
                },
            }
        });
```

**File:** consensus/src/rand/secret_sharing/secret_share_manager.rs (L160-170)
```rust
    fn process_ready_blocks(&mut self, ready_blocks: Vec<OrderedBlocks>) {
        let rounds: Vec<u64> = ready_blocks
            .iter()
            .flat_map(|b| b.ordered_blocks.iter().map(|b3| b3.round()))
            .collect();
        info!(rounds = rounds, "Processing secret share ready blocks.");

        for blocks in ready_blocks {
            let _ = self.outgoing_blocks.unbounded_send(blocks);
        }
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

**File:** consensus/src/pipeline/execution_client.rs (L159-176)
```rust
    pub fn reset(
        &mut self,
    ) -> (
        Option<UnboundedSender<ResetRequest>>,
        Option<UnboundedSender<ResetRequest>>,
        Option<UnboundedSender<ResetRequest>>,
    ) {
        let reset_tx_to_rand_manager = self.reset_tx_to_rand_manager.take();
        let reset_tx_to_buffer_manager = self.reset_tx_to_buffer_manager.take();
        let reset_tx_to_secret_share_manager = self.reset_tx_to_secret_share_manager.take();
        self.execute_tx = None;
        self.commit_tx = None;
        (
            reset_tx_to_rand_manager,
            reset_tx_to_buffer_manager,
            reset_tx_to_secret_share_manager,
        )
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

**File:** consensus/src/rand/secret_sharing/block_queue.rs (L112-127)
```rust
    pub fn dequeue_ready_prefix(&mut self) -> Vec<OrderedBlocks> {
        let mut ready_prefix = vec![];
        while let Some((_starting_round, item)) = self.queue.first_key_value() {
            if item.is_fully_secret_shared() {
                let (_, item) = self.queue.pop_first().expect("First key must exist");
                for block in item.blocks() {
                    observe_block(block.timestamp_usecs(), BlockStage::SECRET_SHARING_READY);
                }
                let QueueItem { ordered_blocks, .. } = item;
                ready_prefix.push(ordered_blocks);
            } else {
                break;
            }
        }
        ready_prefix
    }
```

**File:** consensus/src/counters.rs (L1418-1424)
```rust
pub static DEC_QUEUE_SIZE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_consensus_dec_queue_size",
        "Number of decryption-pending blocks."
    )
    .unwrap()
});
```
