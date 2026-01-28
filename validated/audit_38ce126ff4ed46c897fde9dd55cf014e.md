# Audit Report

## Title
Consensus Divergence via Unvalidated Duplicate Randomness in Fast/Slow Path Race Condition

## Summary
The Aptos consensus randomness system implements parallel fast-path and slow-path randomness generation using cryptographically-distinct augmented key pairs. Due to missing validation in randomness deduplication and decoupled execution, different validators can execute blocks with different randomness values for the same round, causing permanent consensus divergence without requiring any Byzantine actors.

## Finding Description

This vulnerability exists at the intersection of three design elements:

**1. Cryptographically Distinct Fast/Slow Randomness Paths**

The epoch manager generates separate augmented key pairs by calling `WVUF::augment_key_pair()` twice with different base keys (sk.main/pk.main vs sk.fast/pk.fast). [1](#0-0) 

Each call uses `random_nonzero_scalar(rng)` to generate a unique random scalar, producing cryptographically different augmented keys: [2](#0-1) 

These different augmented public keys (APKs) are used during randomness aggregation where `WVUF::derive_eval()` computes the final randomness value. Since the APKs differ between paths, they produce **cryptographically different randomness values** for the same epoch/round: [3](#0-2) 

**2. Missing Validation of Duplicate Randomness**

Both fast and slow paths independently aggregate shares and send randomness through the same `decision_tx` channel: [4](#0-3) 

When `RandManager` receives randomness, `set_randomness()` silently rejects duplicates **without validating the values match**: [5](#0-4) 

This allows a race condition where:
- Validator A: fast path completes first → sets `Randomness_Fast`  
- Validator B: slow path completes first → sets `Randomness_Slow`
- Both validators silently ignore the alternate randomness when it arrives

**3. Decoupled Execution Without State Validation**

Aptos uses "decoupled execution" where validators vote on blocks without validating execution results. In decoupled mode, `gen_vote_data()` uses `vote_data_ordering_only()` which creates votes with a **placeholder hash** instead of actual executed state: [6](#0-5) [7](#0-6) 

This means validators form QCs **without validating they executed to the same state**. The randomness is then included in the `BlockMetadataExt` transaction during execution: [8](#0-7) 

**Exploitation Flow:**

1. Network conditions cause validators to receive fast/slow path shares in different orders
2. Each validator sets the first randomness they receive (fast or slow)  
3. Validators vote and form QCs using placeholder hashes (no state validation)
4. Each validator executes with their different randomness value
5. Different randomness → different `BlockMetadataExt` execution → different state roots
6. **Permanent consensus divergence** across the network

The block ID is computed from `BlockData.hash()` which does NOT include randomness: [9](#0-8) 

Therefore, validators commit the same block ID but execute to different states.

The validation at ledger update only checks if randomness events were generated unexpectedly, NOT if all validators have the same randomness value: [10](#0-9) 

## Impact Explanation

**Critical Severity** - This vulnerability breaks the fundamental blockchain invariant: "All validators must produce identical state for identical inputs."

**Specific Impacts:**

1. **Consensus Safety Violation**: Different validators have divergent state after executing the same block, violating AptosBFT safety guarantees

2. **Non-Recoverable Network Partition**: Once divergence occurs, validators cannot reconcile their states through normal consensus. The network permanently splits into incompatible histories requiring hardfork intervention

3. **Chain Split Risk**: Different validator subsets commit different execution results for on-chain randomness consumers (NFT mints, gaming, lotteries), creating competing chain histories

4. **Unpredictable Application Behavior**: Applications using on-chain randomness receive different values on different validators, breaking application-level invariants

This qualifies as **Critical Severity (up to $1,000,000)** under the Aptos bug bounty program categories "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**High Likelihood** - This vulnerability manifests under normal network operation without requiring malicious actors:

**Natural Triggers:**
- **Network Variance**: Validators have different network latencies, peer connections, and processing speeds
- **Fast Path Design**: The fast path is designed to complete before the slow path, but network jitter can reverse this ordering for individual validators  
- **No Synchronization**: There is no protocol-level agreement on which randomness source validators should use
- **Silent Failure**: The bug occurs silently - `set_randomness()` returns `false` without logging when duplicate randomness is rejected

**Preconditions:**
- Fast randomness must be enabled (ConfigV2 active)
- Network must have non-zero latency variance (always true in distributed systems)
- No Byzantine actors required

**Exploitation Complexity:** LOW
- Occurs naturally due to network timing differences
- Can be deliberately triggered by network adversaries delaying specific messages  
- Probability increases with validator count and network degradation

## Recommendation

Implement one of these fixes:

**Option 1: Validate Randomness Values Match**
```rust
pub fn set_randomness(&mut self, round: Round, rand: Randomness) -> bool {
    let offset = self.offset(round);
    if let Some(existing_rand) = self.blocks()[offset].get_randomness() {
        // Validate new randomness matches existing
        if existing_rand.randomness() != rand.randomness() {
            panic!("Randomness mismatch for round {}: validator consensus divergence detected", round);
        }
        return false;
    }
    // Set randomness as before
    observe_block(self.blocks()[offset].timestamp_usecs(), BlockStage::RAND_ADD_DECISION);
    self.blocks_mut()[offset].set_randomness(rand);
    self.num_undecided_blocks -= 1;
    true
}
```

**Option 2: Protocol-Level Path Selection**
Enforce that all validators use the same randomness path through deterministic selection (e.g., "always prefer fast path if both complete within time window T").

**Option 3: Include Randomness in Block ID**
Include randomness commitment in BlockData hash computation so validators cannot form QCs on blocks with different randomness values.

## Proof of Concept

A full PoC would require running a multi-validator testnet with:
1. Fast randomness enabled (ConfigV2)
2. Network delay injection to create different share arrival orders
3. Monitoring of state root divergence post-execution

The vulnerability can be demonstrated by:
1. Setting up validators with varied network latencies
2. Observing which path (fast/slow) completes first on each validator
3. Verifying different randomness values are set via logging
4. Confirming different state roots post-execution

## Notes

This is a **design-level consensus bug** that affects the core randomness system. The issue stems from the lack of consensus-layer validation that all validators use the same randomness value. The vulnerability is exacerbated by decoupled execution, which allows validators to commit blocks without validating execution results match.

The fix requires careful consideration of the fast/slow path design goals while adding validation to ensure consensus safety.

### Citations

**File:** consensus/src/epoch_manager.rs (L1104-1107)
```rust
            let augmented_key_pair = WVUF::augment_key_pair(&vuf_pp, sk.main, pk.main, &mut rng);
            let fast_augmented_key_pair = if fast_randomness_is_enabled {
                if let (Some(sk), Some(pk)) = (sk.fast, pk.fast) {
                    Some(WVUF::augment_key_pair(&vuf_pp, sk, pk, &mut rng))
```

**File:** crates/aptos-dkg/src/weighted_vuf/pinkas/mod.rs (L89-89)
```rust
        let r = random_nonzero_scalar(rng);
```

**File:** consensus/src/rand/rand_gen/types.rs (L134-142)
```rust
        let eval = WVUF::derive_eval(
            &rand_config.wconfig,
            &rand_config.vuf_pp,
            metadata_serialized.as_slice(),
            &rand_config.get_all_certified_apk(),
            &proof,
            THREAD_MANAGER.get_exe_cpu_pool(),
        )
        .map_err(|e| anyhow!("Share::aggregate failed with WVUF derive_eval error: {e}"))?;
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L267-276)
```rust
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

**File:** consensus/consensus-types/src/vote_proposal.rs (L60-69)
```rust
    fn vote_data_ordering_only(&self) -> VoteData {
        VoteData::new(
            self.block().gen_block_info(
                *ACCUMULATOR_PLACEHOLDER_HASH,
                0,
                self.next_epoch_state().cloned(),
            ),
            self.block().quorum_cert().certified_block().clone(),
        )
    }
```

**File:** consensus/consensus-types/src/vote_proposal.rs (L88-101)
```rust
    pub fn gen_vote_data(&self) -> anyhow::Result<VoteData> {
        if self.decoupled_execution {
            Ok(self.vote_data_ordering_only())
        } else {
            let proposed_block = self.block();
            let new_tree = self.accumulator_extension_proof().verify(
                proposed_block
                    .quorum_cert()
                    .certified_block()
                    .executed_state_id(),
            )?;
            Ok(self.vote_data_with_extension_proof(&new_tree))
        }
    }
```

**File:** types/src/block_metadata_ext.rs (L23-34)
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockMetadataWithRandomness {
    pub id: HashValue,
    pub epoch: u64,
    pub round: u64,
    pub proposer: AccountAddress,
    #[serde(with = "serde_bytes")]
    pub previous_block_votes_bitvec: Vec<u8>,
    pub failed_proposer_indices: Vec<u32>,
    pub timestamp_usecs: u64,
    pub randomness: Option<Randomness>,
}
```

**File:** consensus/consensus-types/src/block_data.rs (L108-133)
```rust
    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::default();
        if self.is_opt_block() {
            #[derive(Serialize)]
            struct OptBlockDataForHash<'a> {
                epoch: u64,
                round: Round,
                timestamp_usecs: u64,
                quorum_cert_vote_data: &'a VoteData,
                block_type: &'a BlockType,
            }

            let opt_block_data_for_hash = OptBlockDataForHash {
                epoch: self.epoch,
                round: self.round,
                timestamp_usecs: self.timestamp_usecs,
                quorum_cert_vote_data: self.quorum_cert.vote_data(),
                block_type: &self.block_type,
            };
            bcs::serialize_into(&mut state, &opt_block_data_for_hash)
                .expect("OptBlockDataForHash must be serializable");
        } else {
            bcs::serialize_into(&mut state, &self).expect("BlockData must be serializable");
        }
        state.finish()
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L902-919)
```rust
        // check for randomness consistency
        let (_, has_randomness) = rand_check.await?;
        if !has_randomness {
            let mut label = "consistent";
            for event in result.execution_output.subscribable_events.get(None) {
                if event.type_tag() == RANDOMNESS_GENERATED_EVENT_MOVE_TYPE_TAG.deref() {
                    error!(
                            "[Pipeline] Block {} {} {} generated randomness event without has_randomness being true!",
                            block.id(),
                            block.epoch(),
                            block.round()
                        );
                    label = "inconsistent";
                    break;
                }
            }
            counters::RAND_BLOCK.with_label_values(&[label]).inc();
        }
```
