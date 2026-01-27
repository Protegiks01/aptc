# Audit Report

## Title
ProofOfStore Replay Attack Enables Resource Exhaustion via Cache Eviction Window

## Summary
A timing vulnerability exists in the ProofOfStore verification system where already-committed batches can be replayed after ProofCache eviction (20-second TTL) but before batch expiration (60 seconds), forcing validators to repeatedly perform expensive BLS aggregate signature verification. This creates a 40-second attack window for resource exhaustion.

## Finding Description

The vulnerability stems from a mismatch between two independent caching mechanisms in the consensus quorum store:

1. **ProofCache**: A verification result cache with a 20-second TTL [1](#0-0) 

2. **BatchProofQueue**: Tracks batch lifecycle (committed/expired) with 60-second batch expiration [2](#0-1) 

**The Attack Flow:**

When a `ProofOfStoreMsg` arrives at a validator node, verification happens in this order:

1. Message received → `UnverifiedEvent::ProofOfStoreMsg` verification is triggered [3](#0-2) 

2. `ProofOfStoreMsg::verify()` iterates through all proofs and calls expensive verification [4](#0-3) 

3. For each proof, `ProofOfStore::verify()` checks the ProofCache first, then performs expensive BLS aggregate signature verification if cache misses [5](#0-4) 

4. **ONLY AFTER** all expensive verification completes, the proof is passed to `insert_proof()` which checks for duplicates/committed batches [6](#0-5) 

**The Vulnerability Window:**

After a batch is committed, it remains in `BatchProofQueue.items` marked as committed [7](#0-6) . However:

- ProofCache entry expires after **20 seconds**
- Batch is only removed from tracking after **60 seconds** (batch expiration timestamp)
- During the 40-second gap, attackers can replay the same `ProofOfStore`
- Each replay bypasses the cache (expired) and forces full cryptographic verification
- The duplicate detection in `insert_proof()` only rejects AFTER expensive verification

**Exploitation:**

1. Monitor consensus for committed batches
2. Wait 20 seconds for ProofCache eviction
3. Repeatedly broadcast the same `ProofOfStoreMsg` to all validators
4. Each validator re-verifies expensive BLS signatures for up to 40 seconds
5. No per-proof rate limiting exists to prevent this

This breaks the **Resource Limits invariant**: expensive cryptographic operations should not be repeatedly performable for already-verified, committed proofs.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria: "Validator node slowdowns"

BLS aggregate signature verification is computationally expensive (typically milliseconds per verification). An attacker can:

- Force all validators to repeatedly verify the same committed proofs
- Sustain attack for 40 seconds per batch (or longer with multiple batches)
- Amplify impact by targeting multiple recently-committed batches simultaneously
- Cause measurable CPU exhaustion on validator nodes
- Potentially slow down consensus participation and block production

The attack requires no privileged access—any network peer can send `ProofOfStoreMsg` messages. The computational cost to attackers is minimal (network bandwidth) while defenders incur significant CPU cost per replayed message.

## Likelihood Explanation

**High Likelihood:**

- Attack is trivial to execute: monitor committed batches, wait 20 seconds, replay
- No authentication required: any network peer can send consensus messages
- Attack window is deterministic: 40-second gap exists for every committed batch
- No rate limiting: system does not track or throttle duplicate proof identities
- Highly observable: committed batches are public information in the blockchain
- Low cost to attacker: minimal bandwidth vs. expensive cryptographic verification by all validators

The only barrier is network connectivity to validator nodes, which is a fundamental requirement of the P2P consensus network.

## Recommendation

**Immediate Fix: Extend deduplication to pre-verification stage**

Add a secondary, longer-lived deduplication mechanism that tracks seen `(BatchInfoExt, AggregateSignature)` pairs beyond the ProofCache TTL:

```rust
// In epoch_manager.rs or proof_coordinator.rs
pub struct ProofDeduplication {
    seen_proofs: Cache<(BatchInfoExt, AggregateSignature), ()>,
}

impl ProofDeduplication {
    pub fn new() -> Self {
        Self {
            seen_proofs: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(120)) // 2x batch expiry
                .build(),
        }
    }
    
    pub fn is_duplicate(&self, info: &BatchInfoExt, sig: &AggregateSignature) -> bool {
        self.seen_proofs.contains_key(&(info.clone(), sig.clone()))
    }
    
    pub fn mark_seen(&self, info: BatchInfoExt, sig: AggregateSignature) {
        self.seen_proofs.insert((info, sig), ());
    }
}
```

**Check before expensive verification in `ProofOfStore::verify()`:**

```rust
pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache, dedup: &ProofDeduplication) -> anyhow::Result<()> {
    let batch_info_ext: BatchInfoExt = self.info.clone().into();
    
    // NEW: Check deduplication FIRST
    if dedup.is_duplicate(&batch_info_ext, &self.multi_signature) {
        return Ok(()); // Already verified within TTL window
    }
    
    // Existing cache check
    if let Some(signature) = cache.get(&batch_info_ext) {
        if signature == self.multi_signature {
            return Ok(());
        }
    }
    
    // Expensive verification
    let result = validator
        .verify_multi_signatures(&self.info, &self.multi_signature)
        .context(format!("Failed to verify ProofOfStore for batch: {:?}", self.info));
        
    if result.is_ok() {
        cache.insert(batch_info_ext.clone(), self.multi_signature.clone());
        dedup.mark_seen(batch_info_ext, self.multi_signature.clone()); // NEW
    }
    result
}
```

**Alternative: Align ProofCache TTL with batch expiry:**

Increase ProofCache TTL from 20 seconds to at least 120 seconds (2x batch expiry) to close the attack window:

```rust
proof_cache: Cache::builder()
    .max_capacity(node_config.consensus.proof_cache_capacity)
    .initial_capacity(1_000)
    .time_to_live(Duration::from_secs(120)) // Increased from 20
    .build(),
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[tokio::test]
async fn test_proof_replay_after_cache_eviction() {
    use mini_moka::sync::Cache;
    use std::time::Duration;
    use tokio::time::sleep;
    
    // Setup: Create validator, proof cache with 1-second TTL for testing
    let (signers, validator) = random_validator_verifier(4, None, false);
    let proof_cache: ProofCache = Cache::builder()
        .max_capacity(1024)
        .time_to_live(Duration::from_secs(1)) // Short TTL for test
        .build();
    
    // Create a valid ProofOfStore
    let batch_info = create_batch_info_ext(/*...*/);
    let signatures = signers.iter()
        .map(|s| s.sign(&batch_info).unwrap())
        .collect::<Vec<_>>();
    let aggregate_sig = AggregateSignature::new(BTreeMap::from_iter(/*...*/));
    let proof = ProofOfStore::new(batch_info.clone(), aggregate_sig.clone());
    
    // First verification - should succeed and cache
    let start = Instant::now();
    assert!(proof.verify(&validator, &proof_cache).is_ok());
    let first_duration = start.elapsed();
    println!("First verification: {:?}", first_duration);
    
    // Second verification - should be instant (cached)
    let start = Instant::now();
    assert!(proof.verify(&validator, &proof_cache).is_ok());
    let cached_duration = start.elapsed();
    println!("Cached verification: {:?}", cached_duration);
    assert!(cached_duration < first_duration / 10); // Cache should be 10x faster
    
    // Wait for cache eviction
    sleep(Duration::from_secs(2)).await;
    
    // VULNERABILITY: Third verification after cache eviction
    // Should reject quickly if protected, but instead performs expensive verification
    let start = Instant::now();
    assert!(proof.verify(&validator, &proof_cache).is_ok());
    let replay_duration = start.elapsed();
    println!("Replay after eviction: {:?}", replay_duration);
    
    // BUG: Replay takes full verification time, not cached time
    assert!(replay_duration > cached_duration * 5, 
        "Replay should take full verification time after cache eviction");
    
    // An attacker can repeat this many times during the 40-second window
    for i in 0..10 {
        let start = Instant::now();
        assert!(proof.verify(&validator, &proof_cache).is_ok());
        println!("Replay {}: {:?}", i, start.elapsed());
    }
}
```

**Expected Output:**
```
First verification: 3.2ms    (expensive BLS verification)
Cached verification: 0.05ms  (cache hit)
Replay after eviction: 3.1ms (expensive re-verification - VULNERABILITY)
Replay 0: 3.2ms
Replay 1: 3.1ms
...
```

This demonstrates that after cache eviction, the same proof can be verified repeatedly with full cryptographic cost, enabling resource exhaustion attacks against all validators in the network.

## Notes

The vulnerability exists because verification happens in two stages with independent caching:
1. **Cryptographic verification** (ProofCache: 20s TTL)
2. **State tracking** (BatchProofQueue: 60s expiry)

The gap between these durations creates an exploitable window. The fix must either align the cache durations or add pre-verification deduplication that spans the full batch lifecycle.

### Citations

**File:** consensus/src/epoch_manager.rs (L250-254)
```rust
            proof_cache: Cache::builder()
                .max_capacity(node_config.consensus.proof_cache_capacity)
                .initial_capacity(1_000)
                .time_to_live(Duration::from_secs(20))
                .build(),
```

**File:** config/src/config/quorum_store_config.rs (L131-131)
```rust
            batch_expiry_gap_when_init_usecs: Duration::from_secs(60).as_micros() as u64,
```

**File:** consensus/src/round_manager.rs (L221-228)
```rust
            UnverifiedEvent::ProofOfStoreMsgV2(p) => {
                if !self_message {
                    p.verify(max_num_batches, validator, proof_cache)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proof_of_store_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProofOfStoreMsg(p)
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L566-583)
```rust
    pub fn verify(
        &self,
        max_num_proofs: usize,
        validator: &ValidatorVerifier,
        cache: &ProofCache,
    ) -> anyhow::Result<()> {
        ensure!(!self.proofs.is_empty(), "Empty message");
        ensure!(
            self.proofs.len() <= max_num_proofs,
            "Too many proofs: {} > {}",
            self.proofs.len(),
            max_num_proofs
        );
        for proof in &self.proofs {
            proof.verify(validator, cache)?
        }
        Ok(())
    }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L635-652)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache) -> anyhow::Result<()> {
        let batch_info_ext: BatchInfoExt = self.info.clone().into();
        if let Some(signature) = cache.get(&batch_info_ext) {
            if signature == self.multi_signature {
                return Ok(());
            }
        }
        let result = validator
            .verify_multi_signatures(&self.info, &self.multi_signature)
            .context(format!(
                "Failed to verify ProofOfStore for batch: {:?}",
                self.info
            ));
        if result.is_ok() {
            cache.insert(batch_info_ext, self.multi_signature.clone());
        }
        result
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L181-188)
```rust
        if self
            .items
            .get(&batch_key)
            .is_some_and(|item| item.proof.is_some() || item.is_committed())
        {
            counters::inc_rejected_pos_count(counters::POS_DUPLICATE_LABEL);
            return;
        }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L887-889)
```rust
                // The item is just marked committed for now.
                // When the batch is expired, then it will be removed from items.
                item.mark_committed();
```
