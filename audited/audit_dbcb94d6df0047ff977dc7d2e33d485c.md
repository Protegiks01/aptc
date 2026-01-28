# Audit Report

## Title
Unbounded Memory Growth in RandStore Leading to Validator Node Memory Exhaustion

## Summary
The `RandStore` component in the randomness generation subsystem lacks a pruning mechanism for old round entries, allowing the `rand_map` and `fast_rand_map` to grow unboundedly throughout an epoch. This enables malicious validators to cause memory exhaustion by submitting valid shares for many different rounds, potentially crashing validator nodes and disrupting consensus liveness.

## Finding Description

The `ShareAggregateState::add()` function adds shares to the `RandStore` without any capacity bounds checking. [1](#0-0) 

The underlying `RandStore` maintains two `BTreeMap` structures (`rand_map` and optionally `fast_rand_map`) that store randomness shares indexed by round number. [2](#0-1) 

When shares are added via `RandStore::add_share()`, the only constraint is that shares must be within the acceptable future window defined by the `FUTURE_ROUNDS_TO_ACCEPT` constant. [3](#0-2) 

The constant defining this window is set to 200 rounds. [4](#0-3) 

**Critical Flaw**: The `reset()` method only removes FUTURE rounds (rounds >= target) using `split_off(&round)`, but never cleans up OLD rounds (rounds < target). [5](#0-4) 

This contrasts with other consensus components like `DagStore`, which properly implement pruning for old rounds by removing entries before `start_round` when `commit_callback()` is triggered. [6](#0-5) 

**Attack Mechanism**:
1. A malicious validator with valid signing keys generates cryptographically valid shares for multiple rounds within the acceptable window
2. Shares are verified via `share.verify()` which checks cryptographic validity [7](#0-6) 
3. Each share is added to `rand_map` via `entry().or_insert_with()` creating new `RandItem` entries [8](#0-7) 
4. As consensus progresses through rounds, old entries accumulate indefinitely throughout the epoch
5. Memory grows linearly: `memory_usage = rounds_processed × validators × share_size`

The `BlockQueue` cleanup mechanism removes processed blocks but does not trigger any cleanup in `RandStore`. [9](#0-8) 

**Memory Impact Calculation**:
- Each `RandShare` contains: Author (32 bytes) + RandMetadata (16 bytes) + ProofShare (~48-96 bytes) ≈ 96-144 bytes
- Per round with 100 validators: ~10-15 KB
- For 10,000 rounds in an epoch: ~100-150 MB (slow path)
- With fast path enabled: ~200-300 MB
- For 86,400 rounds (1 day epoch): ~850 MB - 1.3 GB (slow path) or ~1.7-2.6 GB (with fast path)
- Attack acceleration: Maintaining 200 future pending rounds multiplies memory consumption

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program under the "Validator node slowdowns" category for the following reasons:

**Validator Node Slowdowns**: As memory consumption grows throughout an epoch, nodes experience increased garbage collection pressure, memory swapping, and eventual performance degradation. This directly impacts consensus participation and block processing speed.

**Potential Node Crashes**: When memory exhaustion occurs, the operating system may kill the validator process (OOM killer), causing node crashes and consensus participation failures. Modern validators typically have 16-64 GB RAM, but multi-gigabyte memory leaks over long epochs can cause significant issues when combined with other consensus state.

**Consensus Liveness Impact**: If multiple validators experience simultaneous memory exhaustion and crash, the network could lose consensus liveness if the number of crashed validators exceeds the Byzantine fault tolerance threshold (1/3 of validators).

**Long-Lived Epochs**: The impact severity increases with epoch duration. In production networks where epochs may span thousands to tens of thousands of rounds (potentially hours or days), the memory accumulation becomes significant and can reach multiple gigabytes.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements**:
- Must be a validator with valid cryptographic keys (validators are untrusted actors in the threat model)
- Can send valid shares through normal consensus messaging channels
- No special network position or privileges required beyond validator status
- Does not require collusion with other validators

**Attack Feasibility**:
- Normal operation already accumulates old rounds without malicious activity - this is a latent bug
- Malicious acceleration is trivial: simply broadcast shares for all rounds in the acceptable 200-round window
- No detection mechanisms exist to identify abnormal share patterns
- Attack persists throughout epoch lifetime (potentially hours/days)
- Memory growth is deterministic and predictable based on epoch duration

**Probability of Natural Occurrence**:
Even without malicious intent, normal consensus operation will cause memory growth proportional to epoch length, making this a bug that will eventually manifest in long-running production epochs.

## Recommendation

Implement a pruning mechanism in `RandStore` similar to the one in `DagStore`:

1. Add a `prune()` method that removes entries with rounds below a configurable threshold
2. Call the pruning method periodically or when certain round milestones are reached
3. Consider maintaining a sliding window of rounds (e.g., only keep the most recent N rounds or rounds within a certain distance from the highest known round)

Example fix pattern (following DagStore's approach):
```rust
pub fn prune(&mut self, lowest_round_to_keep: Round) -> BTreeMap<Round, RandItem<S>> {
    let to_keep = self.rand_map.split_off(&lowest_round_to_keep);
    let to_prune = std::mem::replace(&mut self.rand_map, to_keep);
    
    if let Some(fast_map) = self.fast_rand_map.as_mut() {
        let fast_to_keep = fast_map.split_off(&lowest_round_to_keep);
        let _ = std::mem::replace(fast_map, fast_to_keep);
    }
    
    to_prune
}
```

Call this method when blocks are committed or when the highest known round advances significantly beyond old entries.

## Proof of Concept

While a full PoC would require a multi-validator testnet setup, the vulnerability can be demonstrated by code inspection:

1. The `RandStore::new()` creates empty `BTreeMap` structures that persist for the entire epoch [10](#0-9) 
2. Each call to `add_share()` or `add_rand_metadata()` creates entries that are never removed [11](#0-10) 
3. The `reset()` method explicitly only removes future rounds, leaving old rounds intact [5](#0-4) 
4. No other cleanup mechanism exists in the codebase for `RandStore` entries

The memory growth is deterministic: for every round processed in an epoch, entries remain in the maps indefinitely until the epoch ends and a new `RandStore` is created. [12](#0-11)

### Citations

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

**File:** consensus/src/rand/rand_gen/rand_store.rs (L230-246)
```rust
    pub fn new(
        epoch: u64,
        author: Author,
        rand_config: RandConfig,
        fast_rand_config: Option<RandConfig>,
        decision_tx: Sender<Randomness>,
    ) -> Self {
        Self {
            epoch,
            author,
            rand_config,
            rand_map: BTreeMap::new(),
            fast_rand_config: fast_rand_config.clone(),
            fast_rand_map: fast_rand_config.map(|_| BTreeMap::new()),
            highest_known_round: 0,
            decision_tx,
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

**File:** consensus/src/rand/rand_gen/rand_store.rs (L280-288)
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
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L302-308)
```rust
            (
                &self.rand_config,
                self.rand_map
                    .entry(rand_metadata.round)
                    .or_insert_with(|| RandItem::new(self.author, PathType::Slow)),
            )
        };
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/dag/dag_store.rs (L408-429)
```rust
    pub(super) fn prune(&mut self) -> BTreeMap<u64, Vec<Option<NodeStatus>>> {
        let to_keep = self.nodes_by_round.split_off(&self.start_round);
        let to_prune = std::mem::replace(&mut self.nodes_by_round, to_keep);
        debug!(
            "pruning dag. start round {}. pruning from {}",
            self.start_round,
            to_prune.first_key_value().map(|v| v.0).unwrap()
        );
        to_prune
    }

    fn commit_callback(
        &mut self,
        commit_round: Round,
    ) -> Option<BTreeMap<u64, Vec<Option<NodeStatus>>>> {
        let new_start_round = commit_round.saturating_sub(3 * self.window_size);
        if new_start_round > self.start_round {
            self.start_round = new_start_round;
            return Some(self.prune());
        }
        None
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

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L98-104)
```rust
        let rand_store = Arc::new(Mutex::new(RandStore::new(
            epoch_state.epoch,
            author,
            config.clone(),
            fast_config.clone(),
            decision_tx,
        )));
```
