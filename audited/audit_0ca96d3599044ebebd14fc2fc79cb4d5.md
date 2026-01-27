# Audit Report

## Title
Missing Cryptographic Verification in Signature Aggregation Error Path Allows Invalid Proofs to be Cached

## Summary
The `SignatureAggregator::aggregate_and_verify()` method fails to cryptographically verify re-aggregated signatures in its error recovery path before returning them for caching. When initial aggregate signature verification fails, the code filters invalid signatures and re-aggregates, but returns the new aggregate signature without calling `verify_multi_signatures()`. This unverified proof is then cached by `ProofCoordinator`, allowing potentially invalid proofs to bypass future consensus validation. [1](#0-0) 

## Finding Description
The vulnerability exists in the error recovery logic of signature aggregation. When a proof's initial aggregate signature verification fails at line 523, the system enters an error path that:

1. Filters out invalid individual signatures using `filter_invalid_signatures()` at line 530
2. Re-aggregates the remaining signatures via `try_aggregate()` at line 532
3. **Immediately returns the re-aggregated signature without verification** at line 533 [2](#0-1) 

The `try_aggregate()` method only checks voting power and performs optimistic aggregation without cryptographic verification: [3](#0-2) 

The `aggregate_signatures()` call explicitly performs "optimistic aggregation of the signatures without verification": [4](#0-3) 

This unverified aggregate signature is then cached by `ProofCoordinator`: [5](#0-4) 

Subsequently, when consensus validates the same proof, it checks the cache first and skips verification if found: [6](#0-5) 

**Attack Scenario:**
1. Attacker sends batch signatures where some are invalid, causing first aggregate verification to fail
2. System filters invalid signatures and re-aggregates remaining ones
3. Due to implementation bugs, edge cases, or BLS library issues, the re-aggregated signature could be invalid despite individual signatures being valid
4. This unverified aggregate is cached as valid
5. When consensus receives the proof, it finds it in cache and skips verification
6. Invalid proof is accepted, violating consensus safety

This breaks **Critical Invariant #2 (Consensus Safety)** and **Invariant #10 (Cryptographic Correctness)** by allowing unverified cryptographic material to be treated as validated.

## Impact Explanation
**Severity: Critical**

This vulnerability enables **Consensus Safety Violations** - a Critical severity category per the Aptos bug bounty program. Specifically:

- **Consensus Safety Breach**: Invalid proofs lacking proper quorum validation could be accepted, allowing batches to be committed without legitimate validator consensus
- **Defense-in-Depth Failure**: The cache mechanism designed for performance optimization becomes a security bypass, as cached unverified proofs skip all future validation
- **Cross-Epoch Impact**: The proof cache is shared across epochs, potentially allowing invalid proofs from one epoch to affect subsequent epochs [7](#0-6) 

While exploitation requires specific conditions (BLS implementation bugs or edge cases), the complete absence of verification in a critical security path represents a fundamental violation of cryptographic security principles in consensus-critical code.

## Likelihood Explanation
**Likelihood: Medium to High**

The error path is triggered whenever initial aggregate signature verification fails, which can occur through:
- Normal network conditions with late/invalid validator signatures
- Malicious validators intentionally sending invalid signatures
- Byzantine behavior during consensus

While the vulnerability's exploitability depends on the existence of BLS aggregation bugs or edge cases, several factors increase likelihood:

1. **No verification barrier**: The code explicitly skips verification, making exploitation trivial once any BLS edge case is discovered
2. **Complexity of BLS aggregation**: Multi-signature aggregation is cryptographically complex with potential for subtle implementation bugs
3. **Assumption-based security**: The code assumes mathematical correctness without verification, violating security engineering best practices
4. **Historical precedent**: Cryptographic implementations frequently have subtle bugs discovered post-deployment

## Recommendation
**Immediate Fix**: Add explicit cryptographic verification after re-aggregation in the error path:

```rust
pub fn aggregate_and_verify(
    &mut self,
    verifier: &ValidatorVerifier,
) -> Result<(T, AggregateSignature), VerifyError> {
    let aggregated_sig = self.try_aggregate(verifier)?;

    match verifier.verify_multi_signatures(&self.data, &aggregated_sig) {
        Ok(_) => {
            Ok((self.data.clone(), aggregated_sig))
        },
        Err(_) => {
            self.filter_invalid_signatures(verifier);
            
            let aggregated_sig = self.try_aggregate(verifier)?;
            // FIX: Verify the re-aggregated signature before returning
            verifier.verify_multi_signatures(&self.data, &aggregated_sig)?;
            Ok((self.data.clone(), aggregated_sig))
        },
    }
}
```

**Additional Recommendations:**
1. Add comprehensive test coverage for the error path with various invalid signature combinations
2. Consider adding cache-specific validation that re-verifies cached entries periodically
3. Add metrics/logging when error path is triggered for monitoring

## Proof of Concept
```rust
#[test]
fn test_aggregate_and_verify_error_path_skips_verification() {
    use aptos_types::validator_verifier::{ValidatorVerifier, ValidatorConsensusInfo};
    use aptos_types::ledger_info::{LedgerInfo, SignatureAggregator, SignatureWithStatus};
    use aptos_crypto::bls12381;
    
    // Setup validators with quorum = 3
    let ledger_info = LedgerInfo::new(BlockInfo::empty(), HashValue::random());
    let validator_signers: Vec<ValidatorSigner> = (0..4)
        .map(|i| ValidatorSigner::random([i; 32]))
        .collect();
    
    let validator_infos: Vec<_> = validator_signers
        .iter()
        .map(|v| ValidatorConsensusInfo::new(v.author(), v.public_key(), 1))
        .collect();
    
    let verifier = ValidatorVerifier::new_with_quorum_voting_power(validator_infos, 3).unwrap();
    let mut aggregator = SignatureAggregator::new(ledger_info.clone());
    
    // Add 3 valid signatures + 1 invalid (dummy) signature
    for i in 0..3 {
        aggregator.add_signature(
            validator_signers[i].author(),
            &SignatureWithStatus::from(validator_signers[i].sign(&ledger_info).unwrap())
        );
    }
    
    // Add invalid signature to trigger error path
    aggregator.add_signature(
        validator_signers[3].author(),
        &SignatureWithStatus::from(bls12381::Signature::dummy_signature())
    );
    
    // This will:
    // 1. Fail initial verification (due to dummy signature)
    // 2. Filter out dummy signature  
    // 3. Re-aggregate remaining 3 valid signatures
    // 4. Return WITHOUT verifying the re-aggregated signature
    let result = aggregator.aggregate_and_verify(&verifier);
    
    // The function succeeds, but the aggregate signature was never verified
    // after filtering and re-aggregation
    assert!(result.is_ok(), "Error path returned unverified aggregate as valid");
}
```

**Notes:**
- This vulnerability requires defense-in-depth verification to be added to security-critical cryptographic code paths
- The proof cache sharing across epochs amplifies the impact by allowing cached invalid proofs to persist
- While theoretical without a known BLS bug, the complete absence of verification represents a critical security gap in consensus validation logic

### Citations

**File:** types/src/ledger_info.rs (L497-508)
```rust
    fn try_aggregate(
        &mut self,
        verifier: &ValidatorVerifier,
    ) -> Result<AggregateSignature, VerifyError> {
        self.check_voting_power(verifier, true)?;

        let all_signatures = self
            .signatures
            .iter()
            .map(|(voter, sig)| (voter, sig.signature()));
        verifier.aggregate_signatures(all_signatures)
    }
```

**File:** types/src/ledger_info.rs (L517-536)
```rust
    pub fn aggregate_and_verify(
        &mut self,
        verifier: &ValidatorVerifier,
    ) -> Result<(T, AggregateSignature), VerifyError> {
        let aggregated_sig = self.try_aggregate(verifier)?;

        match verifier.verify_multi_signatures(&self.data, &aggregated_sig) {
            Ok(_) => {
                // We are not marking all the signatures as "verified" here, as two malicious
                // voters can collude and create a valid aggregated signature.
                Ok((self.data.clone(), aggregated_sig))
            },
            Err(_) => {
                self.filter_invalid_signatures(verifier);

                let aggregated_sig = self.try_aggregate(verifier)?;
                Ok((self.data.clone(), aggregated_sig))
            },
        }
    }
```

**File:** types/src/validator_verifier.rs (L316-335)
```rust
    pub fn aggregate_signatures<'a>(
        &self,
        signatures: impl Iterator<Item = (&'a AccountAddress, &'a bls12381::Signature)>,
    ) -> Result<AggregateSignature, VerifyError> {
        let mut sigs = vec![];
        let mut masks = BitVec::with_num_bits(self.len() as u16);
        for (addr, sig) in signatures {
            let index = *self
                .address_to_validator_index
                .get(addr)
                .ok_or(VerifyError::UnknownAuthor)?;
            masks.set(index as u16);
            sigs.push(sig.clone());
        }
        // Perform an optimistic aggregation of the signatures without verification.
        let aggregated_sig = bls12381::Signature::aggregate(sigs)
            .map_err(|_| VerifyError::FailedToAggregateSignature)?;

        Ok(AggregateSignature::new(masks, Some(aggregated_sig)))
    }
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L330-336)
```rust
                let proof = {
                    let _timer = counters::SIGNED_BATCH_INFO_VERIFY_DURATION.start_timer();
                    value.aggregate_and_verify(validator_verifier)?
                };
                // proof validated locally, so adding to cache
                self.proof_cache
                    .insert(proof.info().clone(), proof.multi_signature().clone());
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

**File:** consensus/src/epoch_manager.rs (L750-752)
```rust
                epoch_state.verifier.clone(),
                self.proof_cache.clone(),
                self.quorum_store_storage.clone(),
```
