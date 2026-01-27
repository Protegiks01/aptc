# Audit Report

## Title
Byzantine Validator Can Force Exclusive Fast Path Usage by Withholding Regular Shares

## Summary
Byzantine validators can send only `FastShare` messages without corresponding regular `Share` messages, forcing the randomness generation system to rely exclusively on the fast path while preventing the slow path from ever completing. This breaks the intended redundancy mechanism where both paths should be available.

## Finding Description

The Aptos randomness generation system implements two parallel paths for share aggregation:
1. **Slow Path**: Uses regular `Share` messages with lower threshold requirements
2. **Fast Path**: Uses `FastShare` messages as an optimization with higher threshold requirements

The vulnerability exists because there is no cryptographic or protocol-level binding between `FastShare` and regular `Share` messages for the same round.

**Key Code Locations:**

Regular Share broadcast occurs in `rand_manager.rs`: [1](#0-0) 

FastShare broadcast occurs in `round_manager.rs`: [2](#0-1) 

Share verification in `network_messages.rs` validates each share type independently: [3](#0-2) 

The two paths maintain separate aggregation state: [4](#0-3) 

Both paths share the same decision channel, and whichever completes first determines the randomness: [5](#0-4) 

**Attack Scenario:**

1. Byzantine validator modifies their node to skip the regular Share broadcast (line 166-167 in `rand_manager.rs`)
2. Byzantine validator continues voting normally and broadcasts FastShares (line 1356 in `round_manager.rs`)
3. The fast path can reach its threshold with Byzantine FastShares + honest FastShares
4. The slow path cannot reach its threshold due to missing Byzantine regular Shares
5. System relies exclusively on fast path, eliminating the slow path as a fallback

## Impact Explanation

This issue constitutes a **significant protocol violation** under High severity because:

1. **Design Intent Violation**: The system was designed with both slow and fast paths for redundancy. Byzantine validators can eliminate this redundancy.

2. **Fallback Mechanism Removal**: The slow path was intended as the primary mechanism with fast path as optimization. Forcing exclusive fast path usage removes the safety fallback.

3. **System Resilience Reduction**: If the fast path encounters implementation bugs, timing issues, or other problems, the slow path cannot serve as backup.

However, this does NOT reach Critical severity because:
- No consensus safety violation occurs (both paths use valid WVUF cryptography)
- No funds are at risk
- The fast path actually has HIGHER security thresholds than the slow path [6](#0-5) 

## Likelihood Explanation

**Likelihood: High**

1. **Trivial to Execute**: Byzantine validator only needs to modify one line of code to skip regular Share broadcast
2. **No Detection**: There is no mechanism to detect or penalize validators who don't send regular Shares
3. **No Cryptographic Binding**: FastShares are validated independently without checking for corresponding regular Shares
4. **Honest Behavior Pattern**: The condition on line 380 of `rand_manager.rs` shows blocks are only processed when certified augmented data exists, creating natural scenarios where FastShares exist without regular Shares

## Recommendation

Implement cryptographic binding between FastShares and regular Shares:

```rust
// In FastShare verification (network_messages.rs)
RandMessage::FastShare(share) => {
    share.share.verify(fast_rand_config.as_ref().ok_or_else(|| {
        anyhow::anyhow!("[RandMessage] rand config for fast path not found")
    })?)?;
    
    // NEW: Verify that sender has also sent/will send regular Share
    // This could be done by requiring a commitment or proof that
    // the regular Share exists in the sender's outgoing queue
    
    Ok(())
}
```

Alternative approach: Track which validators have sent both share types and only accept FastShares from validators who also participate in slow path:

```rust
// In RandStore
pub struct ShareParticipation {
    slow_path_participants: HashSet<Author>,
    fast_path_participants: HashSet<Author>,
}

// Only accept FastShare if validator also sent regular Share
pub fn add_share(&mut self, share: RandShare<S>, path: PathType) -> anyhow::Result<bool> {
    if path == PathType::Fast {
        ensure!(
            self.participation.slow_path_participants.contains(share.author()),
            "FastShare received from validator who hasn't sent regular Share"
        );
    }
    // ... rest of implementation
}
```

## Proof of Concept

```rust
// Modify Byzantine validator node:
// In consensus/src/rand/rand_gen/rand_manager.rs, line 166-167:
// Comment out or skip the regular Share broadcast:

// self.network_sender
//     .broadcast_without_self(RandMessage::<S, D>::Share(self_share).into_network_message());

// Keep FastShare broadcast in consensus/src/round_manager.rs line 1356 active

// Result: 
// 1. Byzantine validator votes on blocks and sends FastShares
// 2. Byzantine validator does NOT send regular Shares  
// 3. Fast path reaches threshold with: honest FastShares + Byzantine FastShares
// 4. Slow path never reaches threshold due to missing Byzantine regular Shares
// 5. System uses ONLY fast path for randomness generation
// 6. Slow path fallback is eliminated

// To demonstrate in testing:
// - Create test with 4 validators (Byzantine threshold = 1)
// - Make 1 validator send only FastShares
// - Observe fast path completes while slow path does not
// - Verify randomness still generated (via fast path only)
```

## Notes

While this is a valid protocol violation, it's important to note that the fast path has **higher security thresholds** than the slow path, so forcing its exclusive use doesn't inherently weaken cryptographic security. The primary concern is loss of redundancy and architectural intent violation rather than direct consensus or fund security compromise.

### Citations

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L145-169)
```rust
    fn process_incoming_metadata(&self, metadata: FullRandMetadata) -> DropGuard {
        let self_share = S::generate(&self.config, metadata.metadata.clone());
        info!(LogSchema::new(LogEvent::BroadcastRandShare)
            .epoch(self.epoch_state.epoch)
            .author(self.author)
            .round(metadata.round()));
        let mut rand_store = self.rand_store.lock();
        rand_store.update_highest_known_round(metadata.round());
        rand_store
            .add_share(self_share.clone(), PathType::Slow)
            .expect("Add self share should succeed");

        if let Some(fast_config) = &self.fast_config {
            let self_fast_share =
                FastShare::new(S::generate(fast_config, metadata.metadata.clone()));
            rand_store
                .add_share(self_fast_share.rand_share(), PathType::Fast)
                .expect("Add self share for fast path should succeed");
        }

        rand_store.add_rand_metadata(metadata.clone());
        self.network_sender
            .broadcast_without_self(RandMessage::<S, D>::Share(self_share).into_network_message());
        self.spawn_aggregate_shares_task(metadata.metadata)
    }
```

**File:** consensus/src/round_manager.rs (L1339-1361)
```rust
    async fn broadcast_fast_shares(&mut self, block_info: &BlockInfo) {
        // generate and multicast randomness share for the fast path
        if let Some(fast_config) = &self.fast_rand_config {
            if !block_info.is_empty()
                && !self
                    .blocks_with_broadcasted_fast_shares
                    .contains(&block_info.id())
            {
                let metadata = RandMetadata {
                    epoch: block_info.epoch(),
                    round: block_info.round(),
                };
                let self_share = Share::generate(fast_config, metadata);
                let fast_share = FastShare::new(self_share);
                info!(LogSchema::new(LogEvent::BroadcastRandShareFastPath)
                    .epoch(fast_share.epoch())
                    .round(fast_share.round()));
                self.network.broadcast_fast_share(fast_share).await;
                self.blocks_with_broadcasted_fast_shares
                    .put(block_info.id(), ());
            }
        }
    }
```

**File:** consensus/src/rand/rand_gen/network_messages.rs (L36-60)
```rust
    pub fn verify(
        &self,
        epoch_state: &EpochState,
        rand_config: &RandConfig,
        fast_rand_config: &Option<RandConfig>,
        sender: Author,
    ) -> anyhow::Result<()> {
        ensure!(self.epoch() == epoch_state.epoch);
        match self {
            RandMessage::RequestShare(_) => Ok(()),
            RandMessage::Share(share) => share.verify(rand_config),
            RandMessage::AugData(aug_data) => {
                aug_data.verify(rand_config, fast_rand_config, sender)
            },
            RandMessage::CertifiedAugData(certified_aug_data) => {
                certified_aug_data.verify(&epoch_state.verifier)
            },
            RandMessage::FastShare(share) => {
                share.share.verify(fast_rand_config.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("[RandMessage] rand config for fast path not found")
                })?)
            },
            _ => bail!("[RandMessage] unexpected message type"),
        }
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L218-246)
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

impl<S: TShare> RandStore<S> {
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

**File:** types/src/dkg/real_dkg/rounding/mod.rs (L366-373)
```rust
pub static DEFAULT_SECRECY_THRESHOLD: Lazy<U64F64> =
    Lazy::new(|| U64F64::from_num(1) / U64F64::from_num(2));

pub static DEFAULT_RECONSTRUCT_THRESHOLD: Lazy<U64F64> =
    Lazy::new(|| U64F64::from_num(2) / U64F64::from_num(3));

pub static DEFAULT_FAST_PATH_SECRECY_THRESHOLD: Lazy<U64F64> =
    Lazy::new(|| U64F64::from_num(2) / U64F64::from_num(3));
```
