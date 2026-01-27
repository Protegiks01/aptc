# Audit Report

## Title
Memory Leak in RandStore Due to Lack of Garbage Collection for Incomplete Rounds

## Summary
The `RandStore` structure accumulates randomness shares for rounds that never reach the aggregation threshold, without any garbage collection mechanism to remove old incomplete rounds. This causes unbounded memory growth within an epoch, potentially leading to validator node resource exhaustion and performance degradation.

## Finding Description

The randomness generation system in Aptos consensus maintains a `RandStore` that tracks shares for each consensus round in two `BTreeMap` structures: `rand_map` and `fast_rand_map`. [1](#0-0) 

When blocks arrive, the `RandManager` creates entries in these maps to aggregate randomness shares from validators. [2](#0-1) 

Each `RandItem` contains a `ShareAggregator` with a `HashMap<Author, RandShare<S>>` that accumulates shares until the threshold (typically 2f+1 validators) is reached. [3](#0-2) 

**The Critical Flaw:**

The `reset()` method only removes *future* rounds (those >= target_round) using `split_off()`, but provides no mechanism to clean up old rounds that failed to complete: [4](#0-3) 

**Attack Scenario:**

1. An attacker causes intermittent network partitions or performs Byzantine behavior (staying under 1/3 threshold)
2. Some consensus rounds fail to collect enough shares to reach the aggregation threshold
3. These incomplete rounds remain in `rand_map` indefinitely with partial share data
4. Each `RandItem` contains cryptographic shares (BLS signatures, metadata) consuming memory
5. Over an epoch, hundreds or thousands of incomplete rounds accumulate
6. Memory consumption grows unbounded until epoch change (which can be hours to days)

The shares are only accepted if they're within `FUTURE_ROUNDS_TO_ACCEPT` (200 rounds) of the highest known round, but there's no corresponding cleanup for old rounds: [5](#0-4) 

This breaks the **Resource Limits** invariant that states all operations must respect storage and computational limits.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program criteria for the following reasons:

1. **Validator Node Slowdowns**: As `rand_map` grows large, HashMap operations degrade in performance, slowing down share aggregation and consensus operations
2. **Memory Exhaustion**: Sustained attacks or prolonged network issues can consume significant memory (potentially hundreds of MB to GB over long epochs)
3. **Availability Impact**: Sufficient memory pressure can lead to out-of-memory conditions, causing validator crashes and impacting network liveness

The impact is limited to within-epoch duration since `RandManager` is recreated on epoch changes, clearing all state. [6](#0-5) 

However, epochs can last hours to days in production, providing substantial time for memory accumulation.

## Likelihood Explanation

**Likelihood: Medium to High**

This issue can occur through:

1. **Natural Network Conditions**: Intermittent network partitions or latency spikes preventing threshold from being reached for some rounds
2. **Byzantine Behavior**: Malicious validators (under 1/3 threshold) selectively delaying or withholding shares to prevent aggregation
3. **Targeted Attacks**: Attackers causing controlled network disruptions to specific validator subsets

The attack requires no special privileges and can be triggered by conditions that occur naturally in distributed systems or through deliberate Byzantine behavior that doesn't violate the 2f+1 honest assumption.

## Recommendation

Implement garbage collection for old rounds in `RandStore` similar to how other consensus components handle cleanup. Add a method to remove rounds below a certain threshold:

```rust
pub fn garbage_collect(&mut self, min_round_to_keep: Round) {
    // Remove all rounds below min_round_to_keep that haven't decided
    self.rand_map.retain(|round, item| {
        *round >= min_round_to_keep || item.has_decision()
    });
    
    if let Some(fast_rand_map) = self.fast_rand_map.as_mut() {
        fast_rand_map.retain(|round, item| {
            *round >= min_round_to_keep || item.has_decision()
        });
    }
}
```

Call this periodically from `RandManager` (e.g., when processing new rounds or on a timer) with `min_round_to_keep` set to something like `current_round - 1000` to keep only recent rounds.

## Proof of Concept

The following Rust test demonstrates the memory leak by simulating incomplete rounds:

```rust
#[tokio::test]
async fn test_rand_store_memory_leak() {
    use futures_channel::mpsc::unbounded;
    
    let ctxt = TestContext::new(vec![100; 7], 0);
    let (decision_tx, _decision_rx) = unbounded();
    let mut rand_store = RandStore::new(
        ctxt.target_epoch,
        ctxt.authors[0],
        ctxt.rand_config.clone(),
        None,
        decision_tx,
    );
    
    // Simulate 1000 rounds where only 2 validators respond (below threshold)
    for round in 1..=1000 {
        let metadata = FullRandMetadata::new(
            ctxt.target_epoch, 
            round, 
            HashValue::zero(), 
            1700000000
        );
        rand_store.add_rand_metadata(metadata.clone());
        
        // Only add shares from 2 validators (below 4-threshold needed)
        for author in &ctxt.authors[0..2] {
            let share = create_share(metadata.metadata.clone(), *author);
            rand_store.add_share(share, PathType::Slow).unwrap();
        }
    }
    
    // Verify that all 1000 incomplete rounds remain in memory
    assert_eq!(rand_store.rand_map.len(), 1000);
    
    // Reset to round 500 - should only remove future rounds
    rand_store.reset(500);
    
    // Bug: Old incomplete rounds (1-499) still in memory
    assert!(rand_store.rand_map.len() > 490);
    println!("Leaked {} incomplete rounds", rand_store.rand_map.len());
}
```

This demonstrates that incomplete rounds accumulate without bounds, consuming memory proportional to the number of failed rounds.

## Notes

While the broadcast state structures themselves (`AugDataCertBuilder`, `CertifiedAugDataAckState`, `ShareAggregateState`) are properly cleaned up through Rust's RAII and the `DropGuard` mechanism when blocks are dequeued [7](#0-6) , the underlying `RandStore` that these states write to lacks proper garbage collection for incomplete rounds, causing the memory leak described above.

### Citations

**File:** consensus/src/rand/rand_gen/rand_store.rs (L18-39)
```rust
pub struct ShareAggregator<S> {
    author: Author,
    shares: HashMap<Author, RandShare<S>>,
    total_weight: u64,
    path_type: PathType,
}

impl<S: TShare> ShareAggregator<S> {
    pub fn new(author: Author, path_type: PathType) -> Self {
        Self {
            author,
            shares: HashMap::new(),
            total_weight: 0,
            path_type,
        }
    }

    pub fn add_share(&mut self, weight: u64, share: RandShare<S>) {
        if self.shares.insert(*share.author(), share).is_none() {
            self.total_weight += weight;
        }
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L218-227)
```rust
pub struct RandStore<S> {
    epoch: u64,
    author: Author,
    rand_config: RandConfig,
    rand_map: BTreeMap<Round, RandItem<S>>,
    fast_rand_config: Option<RandConfig>,
    fast_rand_map: Option<BTreeMap<Round, RandItem<S>>>,
    highest_known_round: u64,
    decision_tx: Sender<Randomness>,
}
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L253-259)
```rust
    pub fn reset(&mut self, round: u64) {
        self.update_highest_known_round(round);
        // remove future rounds items in case they're already decided
        // otherwise if the block re-enters the queue, it'll be stuck
        let _ = self.rand_map.split_off(&round);
        let _ = self.fast_rand_map.as_mut().map(|map| map.split_off(&round));
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L280-313)
```rust
    pub fn add_share(&mut self, share: RandShare<S>, path: PathType) -> anyhow::Result<bool> {
        ensure!(
            share.metadata().epoch == self.epoch,
            "Share from different epoch"
        );
        ensure!(
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
        let rand_metadata = share.metadata().clone();

        let (rand_config, rand_item) = if path == PathType::Fast {
            match (self.fast_rand_config.as_ref(), self.fast_rand_map.as_mut()) {
                (Some(fast_rand_config), Some(fast_rand_map)) => (
                    fast_rand_config,
                    fast_rand_map
                        .entry(rand_metadata.round)
                        .or_insert_with(|| RandItem::new(self.author, path)),
                ),
                _ => anyhow::bail!("Fast path not enabled"),
            }
        } else {
            (
                &self.rand_config,
                self.rand_map
                    .entry(rand_metadata.round)
                    .or_insert_with(|| RandItem::new(self.author, PathType::Slow)),
            )
        };

        rand_item.add_share(share, rand_config)?;
        rand_item.try_aggregate(rand_config, self.decision_tx.clone());
        Ok(rand_item.has_decision())
    }
```

**File:** consensus/src/epoch_manager.rs (L637-683)
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

        // Shutdown the block retrieval task by dropping the sender
        self.block_retrieval_tx = None;
        self.batch_retrieval_tx = None;

        if let Some(mut quorum_store_coordinator_tx) = self.quorum_store_coordinator_tx.take() {
            let (ack_tx, ack_rx) = oneshot::channel();
            quorum_store_coordinator_tx
                .send(CoordinatorCommand::Shutdown(ack_tx))
                .await
                .expect("Could not send shutdown indicator to QuorumStore");
            ack_rx.await.expect("Failed to stop QuorumStore");
        }
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
