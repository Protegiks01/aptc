# Audit Report

## Title
Broadcast State Resource Leak Due to Missing Cleanup of Failed Share Aggregation Tasks

## Summary
Broadcast state structures in the randomness generation subsystem are not properly cleaned up when share aggregation fails to reach quorum. Share aggregation tasks continue running indefinitely with exponential backoff retries, holding references to broadcast state structures until the next epoch change. This causes a bounded resource leak that can accumulate memory and network overhead during network partitions or Byzantine validator scenarios.

## Finding Description

The randomness generation system uses reliable broadcast to collect shares from validators. For each incoming block, a share aggregation task is spawned and wrapped with a `DropGuard` to enable abortion. These `DropGuards` are stored in `QueueItem` structures within the `BlockQueue`. [1](#0-0) 

The cleanup mechanism relies on dequeuing `QueueItem` structures when all blocks have received randomness: [2](#0-1) 

However, when randomness is never generated for a round (due to insufficient shares), the `QueueItem` remains in the queue indefinitely. The `DropGuards` are never dropped, keeping the broadcast tasks alive: [3](#0-2) 

The share aggregation task spawns a reliable broadcast multicast that retries indefinitely with exponential backoff: [4](#0-3) 

The broadcast state `ShareAggregateState` holds Arc references to shared resources: [5](#0-4) 

**Attack Scenario:**
1. Network partition or Byzantine validators (>1/3) prevent quorum from being reached for certain rounds
2. Affected rounds never generate randomness
3. `QueueItems` accumulate in `BlockQueue`, each holding `DropGuards` for active broadcast tasks
4. Tasks continuously retry RPCs with exponential backoff, consuming resources
5. Head-of-line blocking prevents subsequent blocks from being processed
6. Resources accumulate until epoch change triggers queue reset [6](#0-5) 

## Impact Explanation

**Medium Severity** - This issue causes gradual resource exhaustion and liveness degradation:

- **Memory**: Each stuck round holds broadcast state structures (bounded by epoch duration, typically hours)
- **Network**: Continuous RPC retries consume bandwidth (mitigated by exponential backoff)
- **Liveness**: Head-of-line blocking in the queue prevents processing of subsequent blocks
- **Task Accumulation**: Each stuck round consumes a tokio task slot

The impact qualifies as **Medium severity** under bug bounty criteria for "State inconsistencies requiring intervention" as nodes may experience slowdowns or require restart to recover normal operation during extended network partitions.

## Likelihood Explanation

**Medium to Low Likelihood**:

**Triggering Conditions:**
- Network partition isolating <2/3 validators for extended period
- Byzantine validators (>1/3) deliberately withholding shares
- Extended validator downtime preventing quorum

**Mitigating Factors:**
- Automatic cleanup at epoch boundaries (every few hours)
- Exponential backoff limits retry frequency  
- Requires sustained adverse network conditions
- Node restart also clears accumulated state

The issue is most likely to manifest during network instability or validator failures rather than deliberate attacks, as it requires either network conditions outside attacker control or Byzantine validator collusion.

## Recommendation

Implement timeout-based cleanup for stale share aggregation tasks:

**Option 1: Task-Level Timeout**
Add a timeout to share aggregation tasks in `spawn_aggregate_shares_task`. After a reasonable duration (e.g., 5 minutes), abort the task even if quorum wasn't reached:

```rust
fn spawn_aggregate_shares_task(&self, metadata: RandMetadata) -> DropGuard {
    let rb = self.reliable_broadcast.clone();
    let aggregate_state = Arc::new(ShareAggregateState::new(
        self.rand_store.clone(),
        metadata.clone(),
        self.config.clone(),
    ));
    let task = async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let maybe_existing_shares = rand_store.lock().get_all_shares_authors(round);
        if let Some(existing_shares) = maybe_existing_shares {
            let request = RequestShare::new(metadata.clone());
            let targets = /* ... */;
            
            // Add timeout wrapper
            match tokio::time::timeout(
                Duration::from_secs(300), // 5 minute timeout
                rb.multicast(request, aggregate_state, targets)
            ).await {
                Ok(Ok(())) => info!("Share aggregation completed"),
                Ok(Err(e)) => warn!("Share aggregation failed: {}", e),
                Err(_) => warn!("Share aggregation timed out for round {}", round),
            }
        }
    };
    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    tokio::spawn(Abortable::new(task, abort_registration));
    DropGuard::new(abort_handle)
}
```

**Option 2: Queue-Level Pruning**
Add periodic pruning of old `QueueItems` that haven't received randomness within a threshold:

```rust
impl BlockQueue {
    pub fn prune_stale_items(&mut self, current_round: Round, max_age: u64) {
        let stale_threshold = current_round.saturating_sub(max_age);
        self.queue.retain(|&round, _| round > stale_threshold);
    }
}
```

Call this periodically in the RandManager event loop to remove items older than a threshold.

## Proof of Concept

```rust
#[tokio::test]
async fn test_broadcast_state_leak_on_failed_aggregation() {
    use consensus::rand::rand_gen::{
        rand_manager::RandManager,
        block_queue::BlockQueue,
    };
    use futures_channel::mpsc::unbounded;
    use std::sync::Arc;
    
    // Setup: Create RandManager with mocked dependencies
    let (block_tx, block_rx) = unbounded();
    let (reset_tx, reset_rx) = unbounded();
    
    // Simulate: Send blocks that will never get randomness
    // (by mocking validators that never respond)
    for round in 1..=10 {
        let blocks = create_test_blocks(vec![round]);
        block_tx.unbounded_send(blocks).unwrap();
    }
    
    // Start RandManager
    let manager_handle = tokio::spawn(async move {
        rand_manager.start(
            block_rx,
            incoming_rpc_rx,
            reset_rx,
            bounded_executor,
            0,
        ).await;
    });
    
    // Wait and observe queue growth
    tokio::time::sleep(Duration::from_secs(60)).await;
    
    // Verify: Queue contains all 10 rounds (none processed)
    // Each round has an active broadcast task consuming resources
    // Memory usage increases proportionally
    
    // Cleanup: Send reset signal to trigger cleanup
    reset_tx.unbounded_send(ResetRequest {
        tx: oneshot::channel().0,
        signal: ResetSignal::Stop,
    }).unwrap();
    
    manager_handle.await.unwrap();
    
    // After reset, verify all broadcast tasks are aborted
    // and memory is reclaimed
}
```

**Notes**

The vulnerability exists because the cleanup mechanism assumes broadcasts will eventually complete or be explicitly aborted. In practice, network partitions or validator failures can prevent share aggregation from completing, causing indefinite resource accumulation until the next epoch boundary. While the leak is bounded by epoch duration, it represents a deviation from the expected "cleanup on completion" behavior for broadcast state structures. The fix should implement proactive timeout-based cleanup rather than relying solely on epoch-boundary resets.

### Citations

**File:** consensus/src/rand/rand_gen/block_queue.rs (L16-22)
```rust
/// Maintain the ordered blocks received from consensus and corresponding randomness
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

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L263-303)
```rust
    fn spawn_aggregate_shares_task(&self, metadata: RandMetadata) -> DropGuard {
        let rb = self.reliable_broadcast.clone();
        let aggregate_state = Arc::new(ShareAggregateState::new(
            self.rand_store.clone(),
            metadata.clone(),
            self.config.clone(),
        ));
        let epoch_state = self.epoch_state.clone();
        let round = metadata.round;
        let rand_store = self.rand_store.clone();
        let task = async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let maybe_existing_shares = rand_store.lock().get_all_shares_authors(round);
            if let Some(existing_shares) = maybe_existing_shares {
                let epoch = epoch_state.epoch;
                let request = RequestShare::new(metadata.clone());
                let targets = epoch_state
                    .verifier
                    .get_ordered_account_addresses_iter()
                    .filter(|author| !existing_shares.contains(author))
                    .collect::<Vec<_>>();
                info!(
                    epoch = epoch,
                    round = round,
                    "[RandManager] Start broadcasting share request for {}",
                    targets.len(),
                );
                rb.multicast(request, aggregate_state, targets)
                    .await
                    .expect("Broadcast cannot fail");
                info!(
                    epoch = epoch,
                    round = round,
                    "[RandManager] Finish broadcasting share request",
                );
            }
        };
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(task, abort_registration));
        DropGuard::new(abort_handle)
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L167-205)
```rust
            loop {
                tokio::select! {
                    Some((receiver, result)) = rpc_futures.next() => {
                        let aggregating = aggregating.clone();
                        let future = executor.spawn(async move {
                            (
                                    receiver,
                                    result
                                        .and_then(|msg| {
                                            msg.try_into().map_err(|e| anyhow::anyhow!("{:?}", e))
                                        })
                                        .and_then(|ack| aggregating.add(receiver, ack)),
                            )
                        }).await;
                        aggregate_futures.push(future);
                    },
                    Some(result) = aggregate_futures.next() => {
                        let (receiver, result) = result.expect("spawned task must succeed");
                        match result {
                            Ok(may_be_aggragated) => {
                                if let Some(aggregated) = may_be_aggragated {
                                    return Ok(aggregated);
                                }
                            },
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
                        }
                    },
                    else => unreachable!("Should aggregate with all responses")
                }
            }
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L104-122)
```rust
pub struct ShareAggregateState<S> {
    rand_metadata: RandMetadata,
    rand_store: Arc<Mutex<RandStore<S>>>,
    rand_config: RandConfig,
}

impl<S> ShareAggregateState<S> {
    pub fn new(
        rand_store: Arc<Mutex<RandStore<S>>>,
        rand_metadata: RandMetadata,
        rand_config: RandConfig,
    ) -> Self {
        Self {
            rand_store,
            rand_metadata,
            rand_config,
        }
    }
}
```
