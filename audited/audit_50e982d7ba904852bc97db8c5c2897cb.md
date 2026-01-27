# Audit Report

## Title
Resource Exhaustion via DropGuard Leak in Randomness Generation Block Queue

## Summary

The `QueueItem` struct in the randomness generation pipeline holds `DropGuard` instances that wrap abort handles for long-running broadcast tasks. When randomness never arrives for a block (due to insufficient validator shares), the `QueueItem` remains in the queue indefinitely, preventing the `DropGuard`s from being dropped. This causes the associated broadcast tasks to continue retrying forever, leading to unbounded resource consumption. [1](#0-0) 

## Finding Description

The vulnerability occurs in the randomness generation system's block queue management. Each `QueueItem` contains an `Option<Vec<DropGuard>>` field that holds guards for async broadcast tasks spawned to aggregate randomness shares from validators. [2](#0-1) 

When blocks arrive, `process_incoming_blocks()` creates broadcast handles for each block and wraps them in a `QueueItem`. Each broadcast handle is created by `spawn_aggregate_shares_task()`: [3](#0-2) 

These tasks use reliable broadcast with infinite retry logic: [4](#0-3) 

The retry mechanism uses an exponential backoff iterator that is expected to produce values indefinitely (line 197: `expect("should produce value")`). Tasks only complete when aggregation succeeds.

**The Critical Flaw:** Items are only removed from the queue when they have all randomness decided, using prefix semantics: [5](#0-4) 

If any block at round N fails to receive sufficient shares (< threshold validators respond), then:

1. Round N's `QueueItem` never has `num_undecided() == 0`
2. The loop breaks at line 133, blocking all subsequent rounds
3. All `QueueItem`s remain in the queue indefinitely
4. Their `DropGuard`s are never dropped
5. The broadcast tasks continue retrying forever

**Attack Scenario:**

When fewer than the threshold number of validators provide randomness shares (due to Byzantine behavior, network partition, or validator failures), randomness cannot be computed. This is expected under the < 1/3 Byzantine assumption. However, the system fails to handle this gracefully:

- Consensus continues committing new blocks
- Each new block spawns new broadcast tasks
- Old blocks remain stuck without randomness
- All blocks queue up behind the stuck block (head-of-line blocking)
- Tasks accumulate indefinitely, each retrying with exponential backoff
- Memory consumption grows (QueueItems + task state)
- Active tokio task count grows unbounded
- Network bandwidth consumed by continuous retries
- Eventually leads to OOM, task scheduler exhaustion, or severe performance degradation

**Reset Mechanism Insufficient:**

The only cleanup mechanism is reset during state sync: [6](#0-5) 

However, resets only trigger during state sync operations: [7](#0-6) 

If the node continues processing blocks normally (not falling behind), no sync occurs and the queue grows indefinitely.

**Lack of Protections:**

The code only observes queue size via metrics but enforces no limits: [8](#0-7) 

## Impact Explanation

**Severity: Medium (up to $10,000)**

This vulnerability causes resource exhaustion leading to node degradation:

1. **Memory exhaustion**: Unbounded growth of QueueItems and task state
2. **Task scheduler exhaustion**: Tokio runtime overwhelmed with active tasks  
3. **Network congestion**: Continuous retry attempts consume bandwidth
4. **Performance degradation**: Node becomes slow and unresponsive
5. **Potential crash**: OOM or task limit exceeded

This falls under **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention" - the node enters a degraded state requiring manual intervention (restart/reset) to recover. It could also be considered **High Severity**: "Validator node slowdowns" if the performance impact is severe enough.

The impact is limited to individual nodes experiencing the condition, not a network-wide consensus failure. However, if multiple validators are affected simultaneously, it could impact network liveness.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can be triggered by:

1. **Byzantine validators** (within < 1/3 assumption): Legitimate Byzantine behavior where insufficient validators provide shares
2. **Network partitions**: Temporary isolation preventing share delivery
3. **Validator failures**: Crashes or restarts during critical windows
4. **Software bugs**: Issues in share generation/transmission code

The trigger does not require an active attacker with special privileges - it can occur naturally under adverse but expected network conditions. Once triggered, the resource leak is automatic and continuous.

The head-of-line blocking effect amplifies the impact: a single stuck block prevents all subsequent blocks from being processed, causing rapid queue growth.

## Recommendation

Implement multiple defensive measures to prevent unbounded resource accumulation:

### 1. Timeout-based QueueItem removal
Add a maximum age for QueueItems. Remove items older than a threshold (e.g., 60 seconds or configurable based on round time):

```rust
pub struct QueueItem {
    ordered_blocks: OrderedBlocks,
    offsets_by_round: HashMap<Round, usize>,
    num_undecided_blocks: usize,
    broadcast_handle: Option<Vec<DropGuard>>,
    inserted_at: Instant,  // Add timestamp
}

impl BlockQueue {
    pub fn remove_stale_items(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.queue.retain(|_, item| {
            now.duration_since(item.inserted_at) < max_age
        });
    }
}
```

Call `remove_stale_items()` periodically in the main event loop.

### 2. Maximum queue size
Enforce a maximum number of pending QueueItems:

```rust
const MAX_QUEUE_SIZE: usize = 100;

impl BlockQueue {
    pub fn push_back(&mut self, item: QueueItem) -> Result<(), QueueItem> {
        if self.queue.len() >= MAX_QUEUE_SIZE {
            // Remove oldest item when at capacity
            if let Some((_, old_item)) = self.queue.pop_first() {
                warn!("Queue at capacity, dropping oldest item");
            }
        }
        // ... existing logic
    }
}
```

### 3. Task timeout in spawn_aggregate_shares_task
Add a timeout to the broadcast task itself:

```rust
fn spawn_aggregate_shares_task(&self, metadata: RandMetadata) -> DropGuard {
    let task = async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Add timeout wrapper
        tokio::time::timeout(
            Duration::from_secs(30),
            rb.multicast(request, aggregate_state, targets)
        ).await
        .ok(); // Ignore timeout errors
    };
    // ... rest of implementation
}
```

### 4. Bounded retry in ReliableBroadcast
Modify the backoff policy to have a maximum retry count:

```rust
// Use tokio_retry with max_delay and take() to limit retries
let backoff_policy = ExponentialBackoff::from_millis(100)
    .max_delay(Duration::from_secs(10))
    .take(10); // Maximum 10 retries per peer
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_dropguard_leak_on_stalled_randomness() {
    // Setup: Create a RandManager with mocked validators
    let (incoming_blocks_tx, incoming_blocks_rx) = unbounded();
    let (reset_tx, reset_rx) = unbounded();
    
    // Simulate scenario where shares never arrive
    // 1. Send blocks to RandManager
    for round in 1..=100 {
        let blocks = create_test_blocks(vec![round]);
        incoming_blocks_tx.send(blocks).unwrap();
    }
    
    // 2. Don't send any randomness decisions (simulating insufficient shares)
    
    // 3. Let the manager run for some time
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    // 4. Observe metrics
    let queue_size = RAND_QUEUE_SIZE.get();
    assert_eq!(queue_size, 100, "All blocks should be queued");
    
    // 5. Check resource consumption
    // - Memory usage should be high (100 QueueItems)
    // - Active tokio tasks should be high (100+ broadcast tasks)
    // - Network activity should show continuous retry attempts
    
    // Without fix: Queue grows, tasks accumulate, resources exhausted
    // With fix: Old items removed, tasks aborted, resources bounded
}
```

**Steps to reproduce:**

1. Deploy validator node with randomness enabled
2. Configure < threshold validators to respond to share requests
3. Monitor node metrics: `aptos_consensus_rand_queue_size`, memory usage, task count
4. Observe unbounded growth over time as blocks accumulate
5. Node eventually becomes unresponsive or crashes

**Notes:**

The vulnerability is most severe when:
- Network conditions cause intermittent share delivery failures
- Multiple rounds fail to receive randomness consecutively
- Node continues receiving new blocks from consensus while old blocks are stuck

The lack of any bounded resource limits (queue size, task lifetime, retry counts) allows this to escalate from a temporary issue to a catastrophic resource exhaustion.

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

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L477-480)
```rust
    pub fn observe_queue(&self) {
        let queue = &self.block_queue.queue();
        RAND_QUEUE_SIZE.set(queue.len() as i64);
    }
```

**File:** crates/reliable-broadcast/src/lib.rs (L191-200)
```rust
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
```

**File:** consensus/src/pipeline/execution_client.rs (L654-655)
```rust
        if let Ok(latest_synced_ledger_info) = &result {
            self.reset(latest_synced_ledger_info).await?;
```
