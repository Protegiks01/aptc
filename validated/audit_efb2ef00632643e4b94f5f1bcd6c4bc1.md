# Audit Report

## Title
Memory Leak in RandStore Due to Lack of Garbage Collection for Incomplete Rounds

## Summary
The `RandStore` structure in Aptos consensus accumulates randomness shares for rounds that never reach the aggregation threshold without any garbage collection mechanism. This causes unbounded memory growth within an epoch, potentially leading to validator node resource exhaustion, performance degradation, and availability issues.

## Finding Description

The randomness generation system maintains a `RandStore` that tracks shares for each consensus round in two `BTreeMap` structures: `rand_map` and `fast_rand_map`. [1](#0-0) 

When blocks arrive, the `RandManager` processes incoming metadata and creates entries in these maps to aggregate randomness shares from validators. [2](#0-1) 

Each `RandItem` contains a `ShareAggregator` with a `HashMap<Author, RandShare<S>>` that accumulates shares until the threshold is reached. [3](#0-2) 

**The Critical Flaw:**

The `reset()` method only removes *future* rounds (those >= target_round) using `split_off()`, but provides no mechanism to clean up old rounds that failed to complete. [4](#0-3) 

When shares are added, they are only rejected if they exceed `FUTURE_ROUNDS_TO_ACCEPT` (200 rounds) beyond the highest known round. [5](#0-4) [6](#0-5) 

However, there is no corresponding cleanup for *old* incomplete rounds. New entries are created via `entry().or_insert_with()`, and once created, they remain indefinitely until epoch change. [7](#0-6) 

**Attack Scenario:**

1. Byzantine validators (staying under 1/3 threshold) selectively withhold randomness shares for certain rounds
2. These rounds fail to collect enough shares to reach the aggregation threshold
3. Incomplete `RandItem` entries remain in `rand_map` with partial cryptographic data (BLS signatures, metadata)
4. Over an epoch with thousands of rounds, hundreds of incomplete rounds accumulate
5. Memory consumption grows linearly with each incomplete round
6. Validator nodes experience memory pressure, performance degradation, and potentially OOM crashes

Notably, other consensus components implement garbage collection (e.g., `PendingBlocks::gc()` [8](#0-7) ), but `RandStore` lacks this protection, indicating a clear oversight.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: As `rand_map` grows large, BTreeMap operations degrade in performance, affecting share aggregation and consensus operations
2. **Memory Exhaustion**: Sustained Byzantine behavior can consume significant memory (potentially hundreds of MB over long epochs)
3. **Availability Impact**: Sufficient memory pressure can lead to out-of-memory conditions, causing validator crashes and impacting network liveness

The impact is limited to within-epoch duration since `RandManager` is recreated on epoch changes, clearing all state. [9](#0-8)  However, epochs can last hours to days in production, providing substantial time for memory accumulation.

## Likelihood Explanation

**Likelihood: Medium to High**

This issue can occur through:

1. **Byzantine Behavior**: Malicious validators (under 1/3 threshold) selectively withholding shares to prevent aggregation - this is within the Aptos threat model and requires no special privileges
2. **Natural Network Conditions**: Intermittent latency or connectivity issues preventing threshold from being reached for some rounds
3. **No Economic Barriers**: The attack requires no stake beyond validator status and operates within consensus rules

The vulnerability is triggerable by any Byzantine validator subset below the 1/3 threshold, making it realistic and within the established threat model.

## Recommendation

Implement a garbage collection mechanism in `RandStore` to periodically remove old incomplete rounds. This could be done by:

1. Adding a `gc()` method similar to `PendingBlocks::gc()` that removes entries older than a certain round threshold
2. Calling this method periodically (e.g., when processing new blocks or during the reset operation)
3. Maintaining entries only for a sliding window of recent rounds (e.g., last 1000 rounds)

Example implementation:
```rust
pub fn gc(&mut self, min_round_to_keep: Round) {
    self.rand_map.retain(|round, _| *round >= min_round_to_keep);
    if let Some(fast_rand_map) = self.fast_rand_map.as_mut() {
        fast_rand_map.retain(|round, _| *round >= min_round_to_keep);
    }
}
```

This should be called whenever the highest known round advances significantly, ensuring old incomplete rounds are cleaned up.

## Proof of Concept

The vulnerability can be demonstrated by examining the code flow:

1. When blocks arrive, `add_rand_metadata()` creates entries in `rand_map` for each round
2. If Byzantine validators withhold shares, `ShareAggregator::try_aggregate()` never reaches the threshold
3. The `RandItem` remains in `PendingDecision` state indefinitely
4. The `reset()` method only removes future rounds, leaving old incomplete rounds
5. Over thousands of rounds, the `rand_map` grows unbounded until epoch change

This can be validated by instrumenting `RandStore` to track map size and observing growth over an epoch when some validators are non-responsive.

## Notes

This vulnerability represents a resource management oversight in the consensus randomness generation system. While the impact is limited to within-epoch duration (a significant mitigating factor), the lack of garbage collection for incomplete rounds can lead to validator performance degradation and availability issues. The vulnerability is triggerable within the < 1/3 Byzantine threat model and requires no special privileges, making it a valid Medium severity security issue rather than a simple performance optimization.

### Citations

**File:** consensus/src/rand/rand_gen/rand_store.rs (L18-23)
```rust
pub struct ShareAggregator<S> {
    author: Author,
    shares: HashMap<Author, RandShare<S>>,
    total_weight: u64,
    path_type: PathType,
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

**File:** consensus/src/rand/rand_gen/rand_store.rs (L261-278)
```rust
    pub fn add_rand_metadata(&mut self, rand_metadata: FullRandMetadata) {
        let rand_item = self
            .rand_map
            .entry(rand_metadata.round())
            .or_insert_with(|| RandItem::new(self.author, PathType::Slow));
        rand_item.add_metadata(&self.rand_config, rand_metadata.clone());
        rand_item.try_aggregate(&self.rand_config, self.decision_tx.clone());
        // fast path
        if let (Some(fast_rand_map), Some(fast_rand_config)) =
            (self.fast_rand_map.as_mut(), self.fast_rand_config.as_ref())
        {
            let fast_rand_item = fast_rand_map
                .entry(rand_metadata.round())
                .or_insert_with(|| RandItem::new(self.author, PathType::Fast));
            fast_rand_item.add_metadata(fast_rand_config, rand_metadata.clone());
            fast_rand_item.try_aggregate(fast_rand_config, self.decision_tx.clone());
        }
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L285-288)
```rust
        ensure!(
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/block_storage/pending_blocks.rs (L122-133)
```rust
    pub fn gc(&mut self, round: Round) {
        let mut to_remove = vec![];
        for (r, _) in self.blocks_by_round.range(..=round) {
            to_remove.push(*r);
        }
        for r in to_remove {
            self.opt_blocks_by_round.remove(&r);
            if let Some(block) = self.blocks_by_round.remove(&r) {
                self.blocks_by_hash.remove(&block.id());
            }
        }
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L240-259)
```rust
        let rand_manager = RandManager::<Share, AugmentedData>::new(
            self.author,
            epoch_state.clone(),
            signer,
            rand_config,
            fast_rand_config,
            rand_ready_block_tx,
            network_sender.clone(),
            self.rand_storage.clone(),
            self.bounded_executor.clone(),
            &self.consensus_config.rand_rb_config,
        );

        tokio::spawn(rand_manager.start(
            ordered_block_rx,
            rand_msg_rx,
            reset_rand_manager_rx,
            self.bounded_executor.clone(),
            highest_committed_round,
        ));
```
