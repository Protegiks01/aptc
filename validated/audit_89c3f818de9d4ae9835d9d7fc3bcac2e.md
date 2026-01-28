# Audit Report

## Title
Resource Exhaustion via DropGuard Leak in Randomness Generation Block Queue

## Summary

A resource exhaustion vulnerability exists in the randomness generation pipeline where `QueueItem` instances containing `DropGuard`-wrapped broadcast tasks accumulate indefinitely when randomness aggregation fails to reach threshold. This leads to unbounded memory, task, and network consumption requiring manual intervention to recover.

## Finding Description

The vulnerability occurs in the randomness generation system's block queue management. The `QueueItem` struct holds `DropGuard` instances that wrap abort handles for long-running broadcast tasks. [1](#0-0) 

When blocks arrive, `process_incoming_blocks()` creates broadcast handles via `spawn_aggregate_shares_task()` and wraps them in `QueueItem` instances. [2](#0-1) 

Each broadcast task uses reliable broadcast with infinite retry logic. The exponential backoff iterator is explicitly expected to produce values indefinitely. [3](#0-2) 

The `DropGuard` struct wraps an `AbortHandle` and only aborts the associated task when dropped. [4](#0-3) 

**The Critical Flaw**: Queue items are only removed when all randomness is decided using prefix semantics. [5](#0-4) 

When aggregation logic determines insufficient shares exist (below threshold weight), aggregation never completes. [6](#0-5) 

The `ShareAggregateState::add()` method only returns `Some(())` when `RandStore::add_share()` confirms a decision exists, which only occurs after successful threshold-based aggregation. [7](#0-6) 

If a block at round N fails to receive sufficient shares (< threshold validators respond due to Byzantine behavior, network partition, or validator failures):

1. Round N's `QueueItem` never has `num_undecided() == 0`
2. The dequeue loop breaks, blocking all subsequent rounds (head-of-line blocking)
3. All `QueueItem`s remain in the queue indefinitely
4. Their `DropGuard`s are never dropped
5. Broadcast tasks continue retrying with capped 3-second delays forever

The reset mechanism only triggers during state sync operations. [8](#0-7) [9](#0-8) 

If the node continues processing blocks normally without falling behind, no sync occurs and the queue grows indefinitely. The code only observes queue size via metrics without enforcing limits. [10](#0-9) 

## Impact Explanation

**Severity: Medium (up to $10,000)**

This vulnerability causes resource exhaustion leading to node degradation:

1. **Memory exhaustion**: Unbounded growth of QueueItems containing PipelinedBlocks and task state
2. **Task scheduler exhaustion**: Tokio runtime overwhelmed with active tasks retrying every 3 seconds
3. **Network congestion**: Continuous retry attempts consume bandwidth
4. **Performance degradation**: Node becomes slow and unresponsive
5. **Potential crash**: OOM or task limit exceeded

This aligns with **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention" - the node enters a degraded state requiring manual intervention (restart or triggering state sync reset) to recover.

The impact is limited to individual nodes experiencing the condition, not a network-wide consensus failure. However, if multiple validators are affected simultaneously, it could impact network liveness.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can be triggered by legitimate Byzantine behavior within the < 1/3 assumption:

1. **Byzantine validators**: Insufficient validators provide shares (below threshold)
2. **Network partitions**: Temporary isolation preventing share delivery
3. **Validator failures**: Crashes or restarts during randomness generation windows
4. **Software bugs**: Issues in share generation or transmission code

The trigger does not require an active attacker with special privileges - it can occur naturally under adverse but expected network conditions. The threshold-based cryptography system is designed to tolerate < 1/3 Byzantine validators, but when exactly at the threshold boundary, randomness cannot be computed.

The head-of-line blocking effect amplifies the impact: a single stuck block prevents all subsequent blocks from being processed, causing rapid queue growth with each new block spawning additional broadcast tasks.

## Recommendation

Implement bounded resource management for the randomness generation queue:

1. **Add timeout mechanism**: Set a maximum retry duration per block (e.g., based on epoch duration or round timeouts). After timeout, mark the block as failed and allow queue progression.

2. **Implement queue size limits**: Add a maximum queue size with oldest-item eviction or block skipping policies.

3. **Add cleanup mechanism**: Implement periodic cleanup of stuck items that exceed age thresholds, with proper DropGuard disposal to abort tasks.

4. **Skip mechanism**: Allow the queue to skip blocks that fail to receive randomness after a timeout, rather than blocking all subsequent blocks.

Example fix outline:
```rust
// In QueueItem, add creation timestamp
pub struct QueueItem {
    ordered_blocks: OrderedBlocks,
    offsets_by_round: HashMap<Round, usize>,
    num_undecided_blocks: usize,
    broadcast_handle: Option<Vec<DropGuard>>,
    created_at: Instant,  // Add this
}

// In dequeue_rand_ready_prefix, add timeout check
pub fn dequeue_rand_ready_prefix(&mut self, timeout: Duration) -> Vec<OrderedBlocks> {
    let mut rand_ready_prefix = vec![];
    while let Some((_starting_round, item)) = self.queue.first_key_value() {
        if item.num_undecided() == 0 || item.created_at.elapsed() > timeout {
            // Dequeue either completed or timed-out items
            let (_, item) = self.queue.pop_first().unwrap();
            // ... rest of logic
        } else {
            break;
        }
    }
    rand_ready_prefix
}
```

## Proof of Concept

A theoretical PoC scenario:

1. Deploy a network with 3f+1 validators where threshold = 2f+1
2. Have exactly f+1 validators fail to respond to randomness share requests for block at round N (Byzantine behavior or simulated network partition)
3. Observe that block N never completes randomness aggregation
4. Continue proposing and committing new blocks (consensus can proceed without randomness being immediately available)
5. Monitor metrics showing `RAND_QUEUE_SIZE` growing unbounded
6. Monitor system resources showing increasing task count and memory usage
7. Eventually observe node performance degradation or OOM

Due to the complexity of setting up a full Aptos network with controlled Byzantine behavior, a complete runnable PoC would require significant test infrastructure. However, the vulnerability path is clearly traceable through the code as demonstrated by the citations above.

## Notes

This vulnerability represents a failure to handle an expected Byzantine fault condition gracefully. While the inability to compute randomness under < threshold participation is by design in threshold cryptography, the system should not accumulate unbounded resources. The lack of timeouts, bounds, or cleanup mechanisms transforms an expected protocol limitation into a resource exhaustion vulnerability requiring manual intervention.

### Citations

**File:** consensus/src/rand/rand_gen/block_queue.rs (L17-22)
```rust
pub struct QueueItem {
    ordered_blocks: OrderedBlocks,
    offsets_by_round: HashMap<Round, usize>,
    num_undecided_blocks: usize,
    broadcast_handle: Option<Vec<DropGuard>>,
}
```

**File:** consensus/src/rand/rand_gen/block_queue.rs (L118-137)
```rust
    pub fn dequeue_rand_ready_prefix(&mut self) -> Vec<OrderedBlocks> {
        let mut rand_ready_prefix = vec![];
        while let Some((_starting_round, item)) = self.queue.first_key_value() {
            if item.num_undecided() == 0 {
                let (_, item) = self.queue.pop_first().unwrap();
                for block in item.blocks() {
                    observe_block(block.timestamp_usecs(), BlockStage::RAND_READY);
                }
                let QueueItem { ordered_blocks, .. } = item;
                debug_assert!(ordered_blocks
                    .ordered_blocks
                    .iter()
                    .all(|block| block.has_randomness()));
                rand_ready_prefix.push(ordered_blocks);
            } else {
                break;
            }
        }
        rand_ready_prefix
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L132-143)
```rust
    fn process_incoming_blocks(&mut self, blocks: OrderedBlocks) {
        let rounds: Vec<u64> = blocks.ordered_blocks.iter().map(|b| b.round()).collect();
        info!(rounds = rounds, "Processing incoming blocks.");
        let broadcast_handles: Vec<_> = blocks
            .ordered_blocks
            .iter()
            .map(|block| FullRandMetadata::from(block.block()))
            .map(|metadata| self.process_incoming_metadata(metadata))
            .collect();
        let queue_item = QueueItem::new(blocks, Some(broadcast_handles));
        self.block_queue.push_back(queue_item);
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L184-194)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.rand_store.lock().reset(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L477-480)
```rust
    pub fn observe_queue(&self) {
        let queue = &self.block_queue.queue();
        RAND_QUEUE_SIZE.set(queue.len() as i64);
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L194-200)
```rust
                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
```

**File:** crates/reliable-broadcast/src/lib.rs (L222-236)
```rust
pub struct DropGuard {
    abort_handle: AbortHandle,
}

impl DropGuard {
    pub fn new(abort_handle: AbortHandle) -> Self {
        Self { abort_handle }
    }
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L41-49)
```rust
    pub fn try_aggregate(
        self,
        rand_config: &RandConfig,
        rand_metadata: FullRandMetadata,
        decision_tx: Sender<Randomness>,
    ) -> Either<Self, RandShare<S>> {
        if self.total_weight < rand_config.threshold() {
            return Either::Left(self);
        }
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L131-151)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
        ensure!(
            share.metadata() == &self.rand_metadata,
            "Metadata does not match: local {:?}, received {:?}",
            self.rand_metadata,
            share.metadata()
        );
        share.verify(&self.rand_config)?;
        info!(LogSchema::new(LogEvent::ReceiveReactiveRandShare)
            .epoch(share.epoch())
            .round(share.metadata().round)
            .remote_peer(*share.author()));
        let mut store = self.rand_store.lock();
        let aggregated = if store.add_share(share, PathType::Slow)? {
            Some(())
        } else {
            None
        };
        Ok(aggregated)
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L661-709)
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
    }

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
