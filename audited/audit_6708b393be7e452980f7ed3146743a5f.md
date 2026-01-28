# Audit Report

## Title
Consensus Safety Violation: Non-Deterministic Randomness Selection Between Fast and Slow Paths Causes Chain Splits

## Summary
The Aptos consensus randomness system implements parallel fast and slow paths that use cryptographically distinct augmented key pairs, producing different randomness values for the same block. A non-deterministic race condition between these paths can cause different validators to execute blocks with different randomness, leading to state divergence and consensus failure.

## Finding Description

The Aptos randomness generation system implements two independent paths that can simultaneously produce different randomness values for the same block round.

**Different Cryptographic Keys Produce Different Randomness:**

The fast and slow paths use distinct DKG secret shares during key generation. The slow path uses `sk.main` and `pk.main`, while the fast path uses `sk.fast` and `pk.fast`: [1](#0-0) 

These different keys produce cryptographically different randomness values during VUF evaluation because the augmented public keys differ: [2](#0-1) 

**Independent Aggregation Creates Race Condition:**

Both paths independently aggregate shares and spawn blocking tasks that send to the same `decision_tx` channel: [3](#0-2) 

The slow path aggregates at line 267 and fast path at line 276, both using the same decision channel: [4](#0-3) 

**First-to-Arrive Wins, Second Silently Rejected:**

The `RandManager` processes randomness sequentially without checking return values: [5](#0-4) 

The `QueueItem::set_randomness()` silently rejects the second randomness value by returning false: [6](#0-5) 

**Randomness Used in Block Execution:**

The randomness is incorporated into the block metadata transaction during execution, affecting the final state: [7](#0-6) 

**Attack Scenario:**

Due to network latency variations and CPU scheduling differences, validators can observe different race outcomes:
- Validator A: Slow-path shares arrive faster → aggregates slow → sets `randomness_slow`
- Validator B: Fast-path shares arrive faster → aggregates fast → sets `randomness_fast`
- Both execute with different randomness → different state roots → consensus breaks

## Impact Explanation

**Severity: CRITICAL**

This vulnerability meets the **Consensus/Safety Violations** category from the Aptos Bug Bounty program:

1. **Different State Roots**: Validators execute identical blocks with different randomness values, producing different transaction outputs and state roots.

2. **Consensus Failure**: Validators cannot form quorums because they're voting on different states. This violates the fundamental invariant that all validators must produce identical state for identical blocks.

3. **Network Partition**: The network cannot automatically recover - validators remain diverged until manual intervention or hard fork.

4. **Potential Fund Loss**: If different validators finalize conflicting transactions (e.g., different recipients for randomness-dependent transfers), funds could be lost or double-spent.

The vulnerability affects the entire validator network when ConfigV2 is enabled, which is the default configuration: [8](#0-7) 

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability triggers automatically when:

1. **ConfigV2 Enabled**: Fast randomness is enabled by default in genesis configuration, making this widely applicable: [9](#0-8) 

2. **Network Timing Variations**: Different validators receive shares at different times due to network latency, causing non-deterministic aggregation order.

3. **No Synchronization**: The blocking task spawns have no ordering guarantees, and there's no mechanism to ensure both paths choose the same randomness.

4. **Silent Failure**: No error detection or logging when the second randomness value is rejected, making the issue difficult to detect until state roots diverge.

Fast shares are broadcast after QC formation, adding further timing variability: [10](#0-9) 

## Recommendation

Implement deterministic randomness path selection to ensure all validators use the same path:

1. **Priority-Based Selection**: Always prefer one path (e.g., fast if available, slow as fallback) across all validators
2. **Consensus on Path Selection**: Include path selection in the consensus protocol itself
3. **Error Detection**: Log when multiple randomness values arrive for the same round
4. **Return Value Checking**: Check the return value of `set_randomness()` and raise alerts on rejection

Example fix for `process_randomness()`:

```rust
fn process_randomness(&mut self, randomness: Randomness) {
    if let Some(block) = self.block_queue.item_mut(randomness.round()) {
        if !block.set_randomness(randomness.round(), randomness.clone()) {
            error!("Duplicate randomness for round {}: rejected second value", randomness.round());
            // Raise alert - validators may diverge
        }
    }
}
```

## Proof of Concept

The vulnerability is inherent in the design and can be demonstrated through network simulation showing validators with different timing receiving different randomness values. A full PoC would require:

1. Deploy ConfigV2 configuration
2. Simulate network with varying latencies across validators
3. Inject blocks requiring randomness
4. Observe different validators setting different randomness values (fast vs slow)
5. Verify resulting state root mismatches

The core issue is architectural - the race between independently-computed cryptographically-different randomness values with no ordering guarantee.

### Citations

**File:** consensus/src/epoch_manager.rs (L1104-1113)
```rust
            let augmented_key_pair = WVUF::augment_key_pair(&vuf_pp, sk.main, pk.main, &mut rng);
            let fast_augmented_key_pair = if fast_randomness_is_enabled {
                if let (Some(sk), Some(pk)) = (sk.fast, pk.fast) {
                    Some(WVUF::augment_key_pair(&vuf_pp, sk, pk, &mut rng))
                } else {
                    None
                }
            } else {
                None
            };
```

**File:** consensus/src/rand/rand_gen/types.rs (L130-147)
```rust
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
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L69-87)
```rust
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

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L196-206)
```rust
    fn process_randomness(&mut self, randomness: Randomness) {
        let rand = hex::encode(randomness.randomness());
        info!(
            metadata = randomness.metadata(),
            rand = rand,
            "Processing decisioned randomness."
        );
        if let Some(block) = self.block_queue.item_mut(randomness.round()) {
            block.set_randomness(randomness.round(), randomness);
        }
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

**File:** consensus/src/pipeline/pipeline_builder.rs (L803-811)
```rust
        let (rand_result, _has_randomness) = rand_check.await?;

        tracker.start_working();
        // if randomness is disabled, the metadata skips DKG and triggers immediate reconfiguration
        let metadata_txn = if let Some(maybe_rand) = rand_result {
            block.new_metadata_with_randomness(&validator, maybe_rand)
        } else {
            block.new_block_metadata(&validator).into()
        };
```

**File:** types/src/on_chain_config/randomness_config.rs (L201-203)
```rust
    pub fn default_for_genesis() -> Self {
        OnChainRandomnessConfig::V2(ConfigV2::default())
    }
```

**File:** types/src/on_chain_config/randomness_config.rs (L213-219)
```rust
    pub fn fast_randomness_enabled(&self) -> bool {
        match self {
            OnChainRandomnessConfig::Off => false,
            OnChainRandomnessConfig::V1(_) => false,
            OnChainRandomnessConfig::V2(_) => true,
        }
    }
```

**File:** consensus/src/round_manager.rs (L1813-1813)
```rust
                        self.broadcast_fast_shares(qc.certified_block()).await;
```
