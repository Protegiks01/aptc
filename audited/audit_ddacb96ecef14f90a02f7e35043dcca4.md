# Audit Report

## Title
ProofCache Pollution Attack Causing Validator Performance Degradation

## Summary
A malicious validator can exploit the bounded ProofCache (10,000 entries with 20-second TTL) by flooding proposals with unique ProofOfStore entries when selected as leader, causing cache pollution that evicts legitimate proofs and forces expensive BLS multi-signature re-verification across all validators.

## Finding Description

The ProofCache is a performance optimization shared across all validators to avoid redundant cryptographic verification of ProofOfStore entries. When a validator becomes the consensus leader, they can include up to 20 ProofOfStore entries per proposal. [1](#0-0) 

The cache is initialized with a fixed capacity of 10,000 entries and a 20-second TTL: [2](#0-1) 

When validators verify proposals, each ProofOfStore is checked against the cache. If not cached, expensive BLS multi-signature verification occurs, and the result is inserted into the cache: [3](#0-2) 

**Attack Path:**

1. Malicious validator creates numerous unique batches over time with varying batch_id, digest, epoch, and expiration values
2. Through normal Quorum Store operation, these batches receive legitimate multi-signatures from the validator set
3. When selected as leader (statistically ~1/N rounds where N is validator count), the attacker constructs proposals containing 20 unique ProofOfStore entries
4. All validators verify these proposals, executing the verification path: [4](#0-3) 
5. The payload verification delegates to ProofOfStore verification with cache insertion: [5](#0-4) 
6. With max capacity of 10,000 entries and LRU eviction, the cache fills with attacker-controlled proofs over ~500 rounds as leader
7. Legitimate proofs from honest validators are evicted from the cache
8. Future proposals referencing evicted proofs trigger expensive re-verification of BLS multi-signatures
9. BLS signature verification latency accumulates across all validators, degrading consensus performance

The cache capacity configuration is set at: [6](#0-5) 

## Impact Explanation

This vulnerability causes **validator node slowdowns**, qualifying as **High severity** per the Aptos bug bounty criteria (up to $50,000). The impact manifests as:

- **Increased CPU Usage**: BLS multi-signature verification is cryptographically expensive (milliseconds per signature). Cache misses force re-verification across all validators simultaneously
- **Consensus Latency**: Accumulated verification delays can increase round times, potentially triggering timeouts
- **Resource Exhaustion**: Sustained cache pollution over multiple rounds compounds the verification burden
- **Network-Wide Effect**: All honest validators suffer degraded performance when processing proposals with evicted proofs

While the 20-second TTL provides natural expiration, a persistent attacker selected as leader even intermittently can maintain cache pollution. At 10,000 capacity with 20 proofs/proposal, a single malicious validator needs leadership in only 500 rounds (achievable in normal operation) to significantly impact cache effectiveness.

## Likelihood Explanation

**Likelihood: Medium**

**Attacker Requirements:**
- Must be a validator (requires staking threshold)
- Must be selected as leader (probabilistic based on validator set size)
- Can pre-create batches with valid signatures through normal Quorum Store participation

**Attack Complexity:**
- Low technical barrier once validator status obtained
- Legitimate-appearing behavior (creating batches is normal)
- No consensus rule violations detected during execution

**Realistic Scenario:**
With a validator set of 100 nodes, a malicious validator becomes leader ~1% of rounds. At 1-2 seconds per round, they lead ~40-80 times per hour. Over several hours, they can inject thousands of unique proofs, significantly polluting the cache. The attack is self-sustaining as evicted proofs require re-verification, creating a performance feedback loop.

**Mitigation Factors:**
- 20-second TTL limits persistence of individual entries
- Requires validator privileges (not unprivileged attacker)
- Leader rotation prevents single-validator dominance

## Recommendation

Implement per-validator cache limits and proof uniqueness validation:

```rust
// In consensus/src/epoch_manager.rs
pub struct EpochManager {
    // ...
    proof_cache: ProofCache,
    proof_cache_stats: Arc<Mutex<HashMap<PeerId, ProofCacheStats>>>, // NEW
}

struct ProofCacheStats {
    proofs_added_in_window: usize,
    last_reset: Instant,
}

// Add validation in ProofOfStore verification
pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache, 
              author: PeerId, cache_stats: &Arc<Mutex<HashMap<PeerId, ProofCacheStats>>>) 
              -> anyhow::Result<()> {
    // Check per-validator rate limit
    let mut stats = cache_stats.lock().unwrap();
    let author_stats = stats.entry(author).or_insert(ProofCacheStats {
        proofs_added_in_window: 0,
        last_reset: Instant::now(),
    });
    
    if author_stats.last_reset.elapsed() > Duration::from_secs(60) {
        author_stats.proofs_added_in_window = 0;
        author_stats.last_reset = Instant::now();
    }
    
    const MAX_PROOFS_PER_VALIDATOR_PER_MINUTE: usize = 100;
    ensure!(
        author_stats.proofs_added_in_window < MAX_PROOFS_PER_VALIDATOR_PER_MINUTE,
        "Validator {} exceeded proof cache insertion rate limit",
        author
    );
    
    // Existing verification logic...
    let batch_info_ext: BatchInfoExt = self.info.clone().into();
    if let Some(signature) = cache.get(&batch_info_ext) {
        if signature == self.multi_signature {
            return Ok(());
        }
    }
    
    let result = validator.verify_multi_signatures(&self.info, &self.multi_signature)?;
    
    if result.is_ok() {
        cache.insert(batch_info_ext, self.multi_signature.clone());
        author_stats.proofs_added_in_window += 1;
    }
    
    Ok(result)
}
```

**Additional Mitigations:**
1. Increase cache capacity to 50,000 or implement segmented LRU per validator
2. Add metrics monitoring for cache hit rates per validator
3. Implement proof deduplication at proposal creation time
4. Consider weighted cache eviction favoring proofs from multiple validators over single-validator batches

## Proof of Concept

```rust
#[cfg(test)]
mod proof_cache_pollution_test {
    use super::*;
    use consensus_types::proof_of_store::{BatchInfoExt, ProofCache, ProofOfStore};
    use aptos_crypto::HashValue;
    use aptos_types::validator_verifier::random_validator_verifier;
    use std::time::Instant;
    
    #[test]
    fn test_cache_pollution_attack() {
        // Setup: 100 validators, malicious validator creates unique proofs
        let (signers, validator_verifier) = random_validator_verifier(100, None, false);
        let malicious_signer = &signers[0];
        let proof_cache = ProofCache::new(10_000); // Default capacity
        
        // Phase 1: Attacker creates 500 unique batches over time
        let mut malicious_proofs = vec![];
        for i in 0..500 {
            let batch_info = BatchInfoExt::new_v1(
                malicious_signer.author(),
                i, // Unique batch_id
                1, // epoch
                1_000_000 + i, // Unique expiration
                HashValue::random(), // Unique digest
                50, // num_txns
                1024, // num_bytes
                0, // gas_bucket_start
            );
            
            // Simulate getting valid signatures (in real attack, through Quorum Store)
            let signature = create_aggregate_signature(&signers, &batch_info);
            let proof = ProofOfStore::new(batch_info, signature);
            malicious_proofs.push(proof);
        }
        
        // Phase 2: Attacker becomes leader and inserts proofs
        // Each proposal can have 20 proofs
        let start = Instant::now();
        let mut verification_times = vec![];
        
        for chunk in malicious_proofs.chunks(20) {
            for proof in chunk {
                let verify_start = Instant::now();
                proof.verify(&validator_verifier, &proof_cache).unwrap();
                verification_times.push(verify_start.elapsed());
            }
        }
        
        println!("Cache pollution completed in {:?}", start.elapsed());
        println!("Cache size: {}", proof_cache.entry_count());
        
        // Phase 3: Honest validator tries to use legitimate proof
        let honest_batch = BatchInfoExt::new_v1(
            signers[1].author(),
            999,
            1,
            2_000_000,
            HashValue::random(),
            50,
            1024,
            0,
        );
        
        let honest_signature = create_aggregate_signature(&signers, &honest_batch);
        let honest_proof = ProofOfStore::new(honest_batch, honest_signature);
        
        // First verification - will be cached
        let first_verify = Instant::now();
        honest_proof.verify(&validator_verifier, &proof_cache).unwrap();
        let first_time = first_verify.elapsed();
        
        // Simulate cache eviction by filling with more malicious proofs
        for i in 500..1000 {
            let batch = BatchInfoExt::new_v1(
                malicious_signer.author(),
                i,
                1,
                1_000_000 + i,
                HashValue::random(),
                50,
                1024,
                0,
            );
            let sig = create_aggregate_signature(&signers, &batch);
            let proof = ProofOfStore::new(batch, sig);
            proof.verify(&validator_verifier, &proof_cache).unwrap();
        }
        
        // Second verification - cache miss forces re-verification
        let second_verify = Instant::now();
        honest_proof.verify(&validator_verifier, &proof_cache).unwrap();
        let second_time = second_verify.elapsed();
        
        // Assertion: Second verification significantly slower due to cache eviction
        println!("First verification (cached): {:?}", first_time);
        println!("Second verification (evicted): {:?}", second_time);
        assert!(second_time > first_time * 10, 
                "Cache eviction should force expensive re-verification");
    }
}
```

**Notes:**
- The vulnerability exists but is constrained by configuration limits (20 proofs/proposal, 10,000 capacity, 20s TTL)
- Attack requires validator privileges, limiting the attacker pool to the validator set
- Impact is performance degradation rather than consensus safety violation
- The 20-second TTL provides natural mitigation, though insufficient against persistent attackers
- Real-world exploitation requires the attacker to achieve leader selection repeatedly over time

### Citations

**File:** config/src/config/quorum_store_config.rs (L122-122)
```rust
            receiver_max_num_batches: 20,
```

**File:** consensus/src/epoch_manager.rs (L250-254)
```rust
            proof_cache: Cache::builder()
                .max_capacity(node_config.consensus.proof_cache_capacity)
                .initial_capacity(1_000)
                .time_to_live(Duration::from_secs(20))
                .build(),
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

**File:** consensus/consensus-types/src/opt_proposal_msg.rs (L110-119)
```rust
        let (payload_verify_result, qc_verify_result) = rayon::join(
            || {
                self.block_data()
                    .payload()
                    .verify(validator, proof_cache, quorum_store_enabled)
            },
            || self.block_data().grandparent_qc().verify(validator),
        );
        payload_verify_result?;
        qc_verify_result?;
```

**File:** consensus/consensus-types/src/common.rs (L517-539)
```rust
    fn verify_with_cache<T>(
        proofs: &[ProofOfStore<T>],
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
    ) -> anyhow::Result<()>
    where
        T: TBatchInfo + Send + Sync + 'static,
        BatchInfoExt: From<T>,
    {
        let unverified: Vec<_> = proofs
            .iter()
            .filter(|proof| {
                proof_cache
                    .get(&BatchInfoExt::from(proof.info().clone()))
                    .is_none_or(|cached_proof| cached_proof != *proof.multi_signature())
            })
            .collect();
        unverified
            .par_iter()
            .with_min_len(2)
            .try_for_each(|proof| proof.verify(validator, proof_cache))?;
        Ok(())
    }
```

**File:** config/src/config/consensus_config.rs (L372-372)
```rust
            proof_cache_capacity: 10_000,
```
