# Audit Report

## Title
Last-Revealer Attack: Byzantine Validators Can Bias On-Chain Randomness Through Selective Share Withholding

## Summary
The randomness generation protocol lacks a commit-reveal scheme, allowing Byzantine validators to observe intermediate share aggregation state before deciding whether to reveal their own share. This enables selective censorship of unfavorable randomness values, biasing the distribution of committed randomness over time. The attack exploits the deterministic nature of WVUF shares combined with proactive share broadcasting, where malicious validators can withhold shares after computing the final randomness output.

## Finding Description

The Aptos randomness generation protocol uses Weighted Verifiable Unpredictable Functions (WVUF) with threshold cryptography. When a block is ordered, validators generate and broadcast randomness shares. Once sufficient weight (threshold ≈ 66.67% of stake) is collected, shares are aggregated to produce deterministic randomness.

**The vulnerability chain:**

1. **Deterministic Share Generation**: [1](#0-0) 
   Shares are deterministically generated using WVUF without any commitment phase.

2. **Immediate Proactive Broadcast**: [2](#0-1) 
   Honest validators immediately broadcast their shares upon receiving block metadata. However, this broadcast is not enforced—a Byzantine validator can simply skip this step.

3. **Observable Aggregation State**: [3](#0-2) 
   When shares arrive from other validators, they are added to the local store. The Byzantine validator's node processes these shares and knows the accumulated weight.

4. **Reactive Protocol Without Commitment**: [4](#0-3) 
   After a 300ms timeout, `RequestShare` messages are sent to validators that haven't broadcast. The Byzantine validator can delay until this point.

5. **Predictable Final Output**: [5](#0-4) 
   WVUF aggregation is deterministic. Once the Byzantine validator sees threshold-1 shares, they can locally compute what the final randomness will be if they add their share.

6. **No Penalties for Withholding**: [6](#0-5) 
   The reliable broadcast system retries indefinitely with exponential backoff. There are no slashing penalties or forced deadlines for share revelation.

**Attack Execution:**

1. Byzantine validator modifies their node to skip proactive share broadcast
2. Honest validators broadcast shares within milliseconds of block ordering
3. Byzantine validator receives and stores these shares locally
4. After receiving shares with total weight W, where threshold-1 ≤ W < threshold:
   - Compute own share deterministically: `Share::generate(config, metadata)`
   - Aggregate with received shares: `Share::aggregate([received_shares + own_share], config, metadata)`
   - Obtain predicted randomness value
5. If randomness value is favorable (e.g., for MEV, governance vote manipulation), respond to `RequestShare`
6. If unfavorable, withhold response—reliable broadcast retries indefinitely, causing liveness failure for that round

**Over multiple rounds:** Only randomness values the Byzantine validator approves pass through, creating statistical bias in committed randomness distribution.

## Impact Explanation

**Severity: High (potentially Critical depending on randomness usage)**

This vulnerability breaks the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure." Specifically, the randomness output is no longer cryptographically unbiased when a Byzantine validator can selectively censor values.

**Critical impacts if randomness is used for:**
- **Leader election**: Byzantine validator biases leader selection toward themselves or allies
- **Validator set sampling**: Manipulation of validator rotation
- **On-chain applications**: Any Move contracts relying on `aptos_framework::randomness` module become exploitable
- **MEV extraction**: Predictable randomness enables frontrunning/backrunning strategies

**Guaranteed impacts:**
- **Liveness degradation**: Selective censorship causes rounds to timeout waiting for shares
- **Biased distribution**: Non-uniform randomness distribution over time violates beacon security properties
- **Trust model violation**: System designed to tolerate <33% Byzantine, but single validator can bias outputs

Under the Aptos bug bounty criteria, this qualifies as **High Severity** (significant protocol violation) and potentially **Critical** if it enables consensus manipulation or fund theft through randomness-dependent mechanisms.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attack feasibility:**
- Requires being a validator (barrier: stake requirement)
- Requires node modification (simple: comment out broadcast line)
- Requires favorable network timing (threshold - own_weight < received_weight < threshold)
- No specialized cryptographic knowledge needed

**When attack succeeds:**
- Network asynchrony means validators respond at different times
- Byzantine validator with 5-15% stake can frequently be pivotal
- Even if successful only 10-20% of rounds, creates measurable bias over time

**Detection difficulty:**
- Appears as normal network latency or intermittent failures
- No on-chain evidence distinguishing malicious withholding from connectivity issues
- Requires statistical analysis over many rounds to detect bias

**Mitigation absence:**
- No commit-reveal mechanism
- No slashing for non-responsiveness
- No cryptographic enforcement of timely revelation

The attack is practical for any validator operator willing to modify their node software, with success dependent on network conditions but achievable regularly in production settings.

## Recommendation

Implement a two-phase commit-reveal protocol for randomness share generation:

**Phase 1: Commitment (before block metadata known)**
- Each validator generates and broadcasts a commitment: `H(share || nonce)` where nonce is random
- Collect commitments with threshold weight
- Include commitment QC in block metadata

**Phase 2: Revelation (after commitments finalized)**
- Validators reveal `(share, nonce)` which must match their commitment
- Verify: `H(share || nonce) == commitment`
- Aggregate only shares with valid commitments
- Slash validators who committed but failed to reveal within timeout

**Code modifications needed:**

1. Add commitment phase in `RandManager::process_incoming_metadata()`:
```rust
// Generate commitment: H(share || nonce)
let nonce = rand::random();
let commitment = hash(share, nonce);
// Broadcast commitment first
network_sender.broadcast_without_self(RandMessage::ShareCommitment(commitment));
// Wait for commitment QC before revealing
```

2. Add revelation verification in `ShareAggregateState::add()`:
```rust
// Verify share matches commitment
ensure!(hash(share, nonce) == stored_commitment[peer], "Invalid revelation");
```

3. Add timeout-based slashing for committed but non-revealing validators

**Alternative (simpler):** Use Verifiable Delay Functions (VDF) post-processing: `final_randomness = VDF(aggregated_randomness, delay_parameter)` where delay prevents precomputation, though this adds latency.

## Proof of Concept

```rust
// Simulated Byzantine validator attack
// This demonstrates the attack logic, not a full runnable PoC due to testing infrastructure requirements

use consensus::rand::rand_gen::{
    types::{Share, RandConfig, RandShare},
    rand_store::RandStore,
};

async fn byzantine_validator_attack(
    rand_config: &RandConfig,
    metadata: RandMetadata,
    received_shares: Vec<RandShare<Share>>,
) -> Option<RandShare<Share>> {
    // Step 1: Compute own share deterministically
    let own_share = Share::generate(rand_config, metadata.clone());
    
    // Step 2: Check accumulated weight
    let received_weight: u64 = received_shares
        .iter()
        .map(|s| rand_config.get_peer_weight(s.author()))
        .sum();
    let threshold = rand_config.threshold();
    let own_weight = rand_config.get_peer_weight(&rand_config.author());
    
    // Step 3: If pivotal, compute final randomness with own share
    if received_weight + own_weight >= threshold && received_weight < threshold {
        let all_shares = received_shares.iter().chain(std::iter::once(&own_share));
        let predicted_randomness = Share::aggregate(
            all_shares,
            rand_config,
            metadata.clone(),
        ).expect("Aggregation should succeed");
        
        // Step 4: Decide based on preference (example: prefer even values)
        let rand_bytes = predicted_randomness.randomness();
        let is_favorable = rand_bytes[0] % 2 == 0;
        
        // Step 5: Only reveal if favorable
        if is_favorable {
            println!("Revealing share - favorable outcome");
            return Some(own_share);
        } else {
            println!("Withholding share - unfavorable outcome");
            return None; // Cause liveness failure for this round
        }
    }
    
    // Not pivotal, reveal normally
    Some(own_share)
}

// Over many rounds, only even-valued randomness gets committed,
// creating 50% bias instead of uniform distribution
```

## Notes

This vulnerability represents a fundamental protocol design issue rather than an implementation bug. The WVUF cryptographic primitive is correctly implemented, but the protocol layer fails to enforce a commit-reveal pattern necessary for Byzantine-resistant randomness beacons. This is a well-documented attack class in distributed randomness literature (e.g., "last-revealer" attacks in beacon protocols).

The attack requires validator status but not collusion—a single Byzantine validator with sufficient stake to be occasionally pivotal can measurably bias outputs. The threshold setting (~66.67%) means validators with 10-20% stake can frequently be pivotal when network conditions cause some honest validators to respond slowly.

### Citations

**File:** consensus/src/rand/rand_gen/types.rs (L84-95)
```rust
    fn generate(rand_config: &RandConfig, rand_metadata: RandMetadata) -> RandShare<Self>
    where
        Self: Sized,
    {
        let share = Share {
            share: WVUF::create_share(
                &rand_config.keys.ask,
                bcs::to_bytes(&rand_metadata).unwrap().as_slice(),
            ),
        };
        RandShare::new(rand_config.author(), rand_metadata, share)
    }
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

**File:** crates/reliable-broadcast/src/lib.rs (L191-206)
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
                        }
                    },
                    else => unreachable!("Should aggregate with all responses")
                }
            }
        }
```
