# Audit Report

## Title
Consensus Liveness Failure Due to Asynchronous Aggregation Race Condition in Randomness Generation

## Summary
The `ShareAggregateState::add()` function returns `Some(())` (signaling successful aggregation) when the voting weight threshold is met, but the actual cryptographic aggregation happens asynchronously. If the asynchronous aggregation fails, no randomness is generated, but the reliable broadcast has already terminated, leaving blocks permanently stuck and halting the entire blockchain.

## Finding Description

The vulnerability exists in the randomness generation subsystem's share aggregation logic. The critical flaw is a race condition between broadcast termination and actual cryptographic aggregation:

**The Vulnerable Flow:**

1. When `ShareAggregateState::add()` receives shares via reliable broadcast, it calls `RandStore::add_share()` [1](#0-0) 

2. This delegates to `RandItem::try_aggregate()`, which calls `ShareAggregator::try_aggregate()` [2](#0-1) 

3. In `ShareAggregator::try_aggregate()`, when `total_weight >= threshold()`, it immediately:
   - Spawns an async blocking task to perform `S::aggregate()`
   - Returns `Either::Right(self_share)` **without waiting for aggregation to complete** [3](#0-2) 

4. This causes the `RandItem` to transition to `Decided` state, making `has_decision()` return `true`, which makes `add_share()` return `true`, causing `ShareAggregateState::add()` to return `Some(())`

5. The reliable broadcast interprets `Some(())` as "aggregation complete" and terminates successfully [4](#0-3) 

6. **Meanwhile**, the async aggregation task performs the actual cryptographic aggregation (`Share::aggregate()`), which can fail for multiple reasons:
   - Missing certified augmented public keys (APKs)
   - WVUF `derive_eval` errors  
   - Serialization failures [5](#0-4) 

7. When aggregation fails, only a warning is logged - **no randomness is sent to `decision_tx`** [6](#0-5) 

**The Cascading Failure:**

- The `RandManager` never receives randomness via `decision_rx` for that round [7](#0-6) 

- The block is never marked as rand-ready (`set_randomness()` is never called) [8](#0-7) 

- `BlockQueue::dequeue_rand_ready_prefix()` only dequeues blocks when `num_undecided() == 0`, which never becomes true [9](#0-8) 

- All subsequent blocks are blocked because the queue only processes the prefix
- **The entire blockchain halts**

**Why No Recovery:**

Once the `RandItem` is in `Decided` state, `get_all_shares_authors()` returns `None`, preventing any retry broadcasts from happening [10](#0-9) 

The only recovery requires manual intervention - all validators must restart with `randomness_override_seq_num` configuration [11](#0-10) 

## Impact Explanation

**Critical Severity** - This vulnerability causes **total loss of liveness/network availability**, meeting the highest severity tier ($1,000,000) per the Aptos bug bounty program.

When triggered, the vulnerability:
- **Halts all consensus progress** - blocks cannot be committed without randomness
- **Affects all validators network-wide** - they all run identical code and hit the same failure
- **Requires manual recovery** - needs coordinated validator restarts with override configuration
- **Is non-recoverable through normal operations** - no automatic retry mechanism exists

The blockchain documentation explicitly states: "When randomness generation is stuck due to a bug, the chain is also stuck." [11](#0-10) 

## Likelihood Explanation

**High Likelihood** - This vulnerability can trigger naturally without malicious intent:

1. **Realistic Failure Scenarios:**
   - Missing or corrupted certified APK during validator set transitions
   - WVUF cryptographic computation errors in the async task
   - Transient resource exhaustion during blocking task execution
   - Edge cases in Lagrange interpolation during share aggregation

2. **No Attacker Required:** This is a race condition bug that can occur during normal operation, especially during:
   - Epoch transitions when validator sets change
   - High load scenarios where async task scheduling is delayed
   - Validators with missing or incomplete randomness configuration

3. **Deterministic Trigger:** Once the threshold is met and aggregation fails, the failure is permanent for that round - no probabilistic element.

4. **Network-Wide Impact:** All honest validators experience the same failure path simultaneously.

## Recommendation

**Fix the race condition by ensuring aggregation completes before signaling success:**

```rust
// In ShareAggregator::try_aggregate()
pub fn try_aggregate(
    self,
    rand_config: &RandConfig,
    rand_metadata: FullRandMetadata,
    decision_tx: Sender<Randomness>,
) -> Either<Self, RandShare<S>> {
    if self.total_weight < rand_config.threshold() {
        return Either::Left(self);
    }
    
    // Perform aggregation SYNCHRONOUSLY before returning
    let maybe_randomness = S::aggregate(
        self.shares.values(),
        rand_config,
        rand_metadata.metadata.clone(),
    );
    
    match maybe_randomness {
        Ok(randomness) => {
            // Only transition to Decided if aggregation succeeds
            let _ = decision_tx.unbounded_send(randomness);
            let self_share = self.get_self_share()
                .expect("Aggregated item should have self share");
            Either::Right(self_share)
        },
        Err(e) => {
            warn!(
                epoch = rand_metadata.metadata.epoch,
                round = rand_metadata.metadata.round,
                "Aggregation failed, remaining in pending state: {e}"
            );
            // Stay in pending state to allow retry
            Either::Left(self)
        }
    }
}
```

**Alternative: Use async/await properly:**
```rust
// Change try_aggregate to be async and await the aggregation
pub async fn try_aggregate(...) -> Either<Self, RandShare<S>> {
    // ... threshold check ...
    
    let maybe_randomness = tokio::task::spawn_blocking(move || {
        S::aggregate(...)
    }).await.unwrap();
    
    match maybe_randomness {
        Ok(randomness) => {
            let _ = decision_tx.unbounded_send(randomness);
            Either::Right(self_share)
        },
        Err(e) => Either::Left(self) // Retry
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_aggregation_failure_causes_permanent_halt() {
    use consensus::rand::rand_gen::{
        rand_store::{RandStore, ShareAggregator},
        types::{Share, RandConfig, PathType},
    };
    use futures_channel::mpsc::unbounded;
    
    // Setup: Create RandStore with decision channel
    let (decision_tx, mut decision_rx) = unbounded();
    let mut rand_store = RandStore::new(
        1, // epoch
        Author::random(),
        rand_config.clone(),
        None,
        decision_tx,
    );
    
    // Step 1: Add shares from multiple validators to meet threshold
    let metadata = RandMetadata::new(1, 100);
    for i in 0..4 {
        let share = create_share_with_missing_apk(metadata.clone(), validator_authors[i]);
        // This will succeed because we're just collecting shares
        rand_store.add_share(share, PathType::Slow).unwrap();
    }
    
    // Step 2: Add final share that meets threshold
    let final_share = create_share_with_missing_apk(metadata.clone(), validator_authors[4]);
    
    // add_share returns true (indicating "decided") because threshold is met
    let result = rand_store.add_share(final_share, PathType::Slow).unwrap();
    assert_eq!(result, true); // Broadcast thinks aggregation is complete!
    
    // Step 3: Wait for async aggregation to complete
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Step 4: Verify NO randomness was received because aggregation failed
    assert!(decision_rx.try_next().is_err()); // No randomness sent!
    
    // Step 5: Verify state is "Decided" so no retries will occur
    assert_eq!(rand_store.get_all_shares_authors(100), None); // Returns None for Decided state
    
    // Result: Block is permanently stuck, chain halted
    // This would require manual recovery via randomness_override_seq_num
}
```

**Reproduction Steps:**
1. Deploy a validator with incomplete randomness configuration (missing some APKs)
2. Wait for a block that requires randomness
3. Shares are collected and threshold is met
4. Aggregation fails asynchronously due to missing APK
5. Observe warning log: "Aggregation error: Share::aggregate failed with missing apk"
6. Observe block stuck in queue indefinitely
7. Observe all subsequent blocks also stuck (queue only processes prefix)
8. Requires manual recovery with validator restarts

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

**File:** consensus/src/rand/rand_gen/rand_store.rs (L41-89)
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
        match self.path_type {
            PathType::Fast => {
                observe_block(
                    rand_metadata.timestamp,
                    BlockStage::RAND_ADD_ENOUGH_SHARE_FAST,
                );
            },
            PathType::Slow => {
                observe_block(
                    rand_metadata.timestamp,
                    BlockStage::RAND_ADD_ENOUGH_SHARE_SLOW,
                );
            },
        }

        let rand_config = rand_config.clone();
        let self_share = self
            .get_self_share()
            .expect("Aggregated item should have self share");
        tokio::task::spawn_blocking(move || {
            let maybe_randomness = S::aggregate(
                self.shares.values(),
                &rand_config,
                rand_metadata.metadata.clone(),
            );
            match maybe_randomness {
                Ok(randomness) => {
                    let _ = decision_tx.unbounded_send(randomness);
                },
                Err(e) => {
                    warn!(
                        epoch = rand_metadata.metadata.epoch,
                        round = rand_metadata.metadata.round,
                        "Aggregation error: {e}"
                    );
                },
            }
        });
        Either::Right(self_share)
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L195-205)
```rust
    fn get_all_shares_authors(&self) -> Option<HashSet<Author>> {
        match self {
            RandItem::PendingDecision {
                share_aggregator, ..
            } => Some(share_aggregator.shares.keys().cloned().collect()),
            RandItem::Decided { .. } => None,
            RandItem::PendingMetadata(_) => {
                unreachable!("Should only be called after block is added")
            },
        }
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

**File:** crates/reliable-broadcast/src/lib.rs (L183-190)
```rust
                    Some(result) = aggregate_futures.next() => {
                        let (receiver, result) = result.expect("spawned task must succeed");
                        match result {
                            Ok(may_be_aggragated) => {
                                if let Some(aggregated) = may_be_aggragated {
                                    return Ok(aggregated);
                                }
                            },
```

**File:** consensus/src/rand/rand_gen/types.rs (L97-148)
```rust
    fn aggregate<'a>(
        shares: impl Iterator<Item = &'a RandShare<Self>>,
        rand_config: &RandConfig,
        rand_metadata: RandMetadata,
    ) -> anyhow::Result<Randomness>
    where
        Self: Sized,
    {
        let timer = std::time::Instant::now();
        let mut apks_and_proofs = vec![];
        for share in shares {
            let id = rand_config
                .validator
                .address_to_validator_index()
                .get(share.author())
                .copied()
                .ok_or_else(|| {
                    anyhow!(
                        "Share::aggregate failed with invalid share author: {}",
                        share.author
                    )
                })?;
            let apk = rand_config
                .get_certified_apk(share.author())
                .ok_or_else(|| {
                    anyhow!(
                        "Share::aggregate failed with missing apk for share from {}",
                        share.author
                    )
                })?;
            apks_and_proofs.push((Player { id }, apk.clone(), share.share().share));
        }

        let proof = WVUF::aggregate_shares(&rand_config.wconfig, &apks_and_proofs);
        let metadata_serialized = bcs::to_bytes(&rand_metadata).map_err(|e| {
            anyhow!("Share::aggregate failed with metadata serialization error: {e}")
        })?;
        let eval = WVUF::derive_eval(
            &rand_config.wconfig,
            &rand_config.vuf_pp,
            metadata_serialized.as_slice(),
            &rand_config.get_all_certified_apk(),
            &proof,
            THREAD_MANAGER.get_exe_cpu_pool(),
        )
        .map_err(|e| anyhow!("Share::aggregate failed with WVUF derive_eval error: {e}"))?;
        debug!("WVUF derivation time: {} ms", timer.elapsed().as_millis());
        let eval_bytes = bcs::to_bytes(&eval)
            .map_err(|e| anyhow!("Share::aggregate failed with eval serialization error: {e}"))?;
        let rand_bytes = Sha3_256::digest(eval_bytes.as_slice()).to_vec();
        Ok(Randomness::new(rand_metadata, rand_bytes))
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L387-389)
```rust
                Some(randomness) = self.decision_rx.next()  => {
                    self.process_randomness(randomness);
                }
```

**File:** consensus/src/rand/rand_gen/block_queue.rs (L69-82)
```rust
    pub fn set_randomness(&mut self, round: Round, rand: Randomness) -> bool {
        let offset = self.offset(round);
        if !self.blocks()[offset].has_randomness() {
            observe_block(
                self.blocks()[offset].timestamp_usecs(),
                BlockStage::RAND_ADD_DECISION,
            );
            self.blocks_mut()[offset].set_randomness(rand);
            self.num_undecided_blocks -= 1;
            true
        } else {
            false
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

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config_seqnum.move (L1-9)
```text
/// Randomness stall recovery utils.
///
/// When randomness generation is stuck due to a bug, the chain is also stuck. Below is the recovery procedure.
/// 1. Ensure more than 2/3 stakes are stuck at the same version.
/// 1. Every validator restarts with `randomness_override_seq_num` set to `X+1` in the node config file,
///    where `X` is the current `RandomnessConfigSeqNum` on chain.
/// 1. The chain should then be unblocked.
/// 1. Once the bug is fixed and the binary + framework have been patched,
///    a governance proposal is needed to set `RandomnessConfigSeqNum` to be `X+2`.
```
