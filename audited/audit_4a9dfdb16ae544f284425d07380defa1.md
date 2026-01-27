# Audit Report

## Title
BLS Signature Verification DoS via Optimistic Verification Bypass

## Summary
A malicious validator can cause consensus performance degradation by submitting votes with invalid BLS signatures that bypass optimistic verification, forcing all validators to perform expensive individual signature verifications instead of efficient batch verification. This creates a (2f+1)x amplification in cryptographic operations during quorum formation.

## Finding Description

The Aptos consensus protocol implements an optimistic signature verification feature (enabled by default) that defers expensive BLS signature verification until quorum certificate formation. When a validator submits a vote, the signature is not immediately verified if `optimistic_sig_verification` is enabled and the validator is not in the `pessimistic_verify_set`. [1](#0-0) 

When enough votes are collected to form a quorum certificate, all signatures are aggregated and verified in a single batch operation: [2](#0-1) 

The aggregation process explicitly does NOT validate individual signatures before combining them, as documented: [3](#0-2) 

If the batch verification fails (due to any invalid signature), the system falls back to individual verification of ALL signatures: [4](#0-3) 

This fallback uses parallel individual verification which performs a BLS pairing operation for each signature: [5](#0-4) 

**Attack Flow:**
1. Malicious validator crafts a vote with an invalid BLS signature (e.g., random G2 point or malformed signature)
2. Vote passes network authentication (author == sender) and optimistic verification (no cryptographic check)
3. Vote is added to pending votes for quorum formation
4. When 2f+1 votes are collected, batch aggregation and verification occurs
5. Batch verification fails due to invalid signature (1 expensive pairing operation)
6. System individually verifies all 2f+1 signatures (2f+1 expensive pairing operations)
7. Invalid signature is detected, validator added to pessimistic set
8. Repeat attack with different controlled validators

## Impact Explanation

This constitutes **High Severity** impact under the Aptos Bug Bounty criteria: "Validator node slowdowns."

For a validator set of 100 validators requiring 67 signatures for quorum:
- **Normal case**: 1 BLS pairing operation (batch verification)
- **Attack case**: 67 BLS pairing operations (individual verification after batch failure)
- **Amplification**: 67x increase in cryptographic computation

BLS pairing operations are among the most expensive cryptographic operations in consensus. At consensus finality rates of 1-2 seconds per round, this amplification can:
- Delay quorum certificate formation
- Increase round timeout probability
- Degrade overall network throughput
- Cascade to other validators experiencing the same attack

While the attack is self-limiting (attacker added to pessimistic set after first invalid signature), a Byzantine validator controlling multiple validator accounts can repeat this attack, causing sustained performance degradation across multiple rounds.

## Likelihood Explanation

**Likelihood: Medium to High**

**Requirements:**
- Attacker must control at least one validator account (Byzantine validator within < 1/3 threshold)
- Optimistic signature verification must be enabled (default: true) [6](#0-5) 

**Feasibility:**
- Attack is trivial to execute: send valid vote with invalid signature bytes
- No special timing or coordination required
- Attack can be repeated across multiple validator identities
- Detection occurs AFTER the expensive verification amplification

**Mitigation complexity:**
The current design intentionally skips validation for performance. The comment explicitly acknowledges this trade-off but doesn't prevent the DoS vector: [7](#0-6) 

## Recommendation

**Immediate Mitigation:**
Implement early signature subgroup validation before accepting votes into the pending votes pool. While this adds overhead to vote reception, it prevents the amplification attack:

```rust
// In Vote::verify() or VoteMsg::verify(), add:
pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
    // Existing checks...
    
    // Add early signature validation if optimistic verification is enabled
    if validator.optimistic_sig_verification {
        self.signature.subgroup_check()
            .context("Signature failed subgroup check")?;
    }
    
    // Continue with existing optimistic verification...
    validator.optimistic_verify(self.author(), &self.ledger_info, &self.signature)
        .context("Failed to verify Vote")?;
    // ...
}
```

**Long-term Solution:**
Implement a hybrid verification strategy:
1. Perform lightweight subgroup checks on vote reception (cheaper than full verification)
2. Maintain optimistic batch verification for valid-looking signatures
3. Implement reputation-based throttling for validators frequently producing invalid signatures
4. Consider probabilistic sampling: verify random subset of signatures before batch verification

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_invalid_signature_dos_amplification() {
    use aptos_crypto::{bls12381, Uniform};
    use aptos_types::validator_verifier::ValidatorVerifier;
    use consensus_types::vote::Vote;
    use std::time::Instant;
    
    // Setup validator set
    let num_validators = 100;
    let (signers, verifier) = random_validator_verifier(num_validators, None, false);
    
    // Create a valid vote message
    let vote_data = VoteData::new(/* ... */);
    let ledger_info = LedgerInfo::new(/* ... */);
    
    // Collect 66 valid votes
    let mut votes = Vec::new();
    for i in 0..66 {
        let valid_vote = signers[i].sign_vote(&vote_data, &ledger_info);
        votes.push(valid_vote);
    }
    
    // Add 1 INVALID vote from a malicious validator
    let mut malicious_vote = signers[67].sign_vote(&vote_data, &ledger_info);
    // Replace signature with invalid bytes (still valid BLS point, but wrong signature)
    malicious_vote.signature = bls12381::Signature::dummy_signature();
    votes.push(malicious_vote);
    
    // Enable optimistic verification
    verifier.set_optimistic_sig_verification_flag(true);
    
    // Process votes through pending_votes
    let mut pending_votes = PendingVotes::new();
    for vote in &votes {
        pending_votes.insert_vote(vote, &verifier);
    }
    
    // Measure verification time when forming QC
    let start = Instant::now();
    let result = pending_votes.insert_vote(&votes[66], &verifier);
    let elapsed = start.elapsed();
    
    // Verification should take significantly longer due to fallback to individual verification
    // Expected: ~67x longer than batch verification
    println!("Verification time with invalid signature: {:?}", elapsed);
    assert!(elapsed.as_millis() > 100); // Threshold depends on hardware
    
    // Verify that malicious validator was added to pessimistic set
    assert!(verifier.pessimistic_verify_set().contains(&signers[67].author()));
}
```

## Notes

The vulnerability exists because the optimistic verification optimization prioritizes performance over early detection of invalid signatures. The BLS signature scheme's security properties prevent forgery but don't prevent resource exhaustion attacks. The mitigation must balance:
- Early detection overhead (subgroup checks on every vote)
- Batch verification benefits (single pairing for valid quorums)
- DoS resistance (preventing amplification attacks)

The current implementation correctly prevents signature forgery but is vulnerable to targeted performance degradation by Byzantine validators.

### Citations

**File:** types/src/validator_verifier.rs (L269-285)
```rust
    pub fn optimistic_verify<T: Serialize + CryptoHash>(
        &self,
        author: AccountAddress,
        message: &T,
        signature_with_status: &SignatureWithStatus,
    ) -> std::result::Result<(), VerifyError> {
        if self.get_public_key(&author).is_none() {
            return Err(VerifyError::UnknownAuthor);
        }
        if (!self.optimistic_sig_verification || self.pessimistic_verify_set.contains(&author))
            && !signature_with_status.is_verified()
        {
            self.verify(author, message, signature_with_status.signature())?;
            signature_with_status.set_verified();
        }
        Ok(())
    }
```

**File:** types/src/validator_verifier.rs (L287-311)
```rust
    pub fn filter_invalid_signatures<T: Send + Sync + Serialize + CryptoHash>(
        &self,
        message: &T,
        signatures: BTreeMap<AccountAddress, SignatureWithStatus>,
    ) -> BTreeMap<AccountAddress, SignatureWithStatus> {
        signatures
            .into_iter()
            .collect_vec()
            .into_par_iter()
            .with_min_len(4) // At least 4 signatures are verified in each task
            .filter_map(|(account_address, signature)| {
                if signature.is_verified()
                    || self
                        .verify(account_address, message, signature.signature())
                        .is_ok()
                {
                    signature.set_verified();
                    Some((account_address, signature))
                } else {
                    self.add_pessimistic_verify_set(account_address);
                    None
                }
            })
            .collect()
    }
```

**File:** consensus/src/pending_votes.rs (L383-387)
```rust
                            sig_aggregator.aggregate_and_verify(validator_verifier).map(
                                |(ledger_info, aggregated_sig)| {
                                    LedgerInfoWithSignatures::new(ledger_info, aggregated_sig)
                                },
                            )
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_sigs.rs (L64-76)
```rust
    /// Optimistically-aggregate signatures shares into either (1) a multisignature or (2) an aggregate
    /// signature. The individual signature shares could be adversarial. Nonetheless, for performance
    /// reasons, we do not subgroup-check the signature shares here, since the verification of the
    /// returned multi-or-aggregate signature includes such a subgroup check. As a result, adversarial
    /// signature shares cannot lead to forgeries.
    pub fn aggregate(sigs: Vec<Self>) -> Result<Signature> {
        let sigs: Vec<_> = sigs.iter().map(|s| &s.sig).collect();
        let agg_sig = blst::min_pk::AggregateSignature::aggregate(&sigs[..], false)
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(Signature {
            sig: agg_sig.to_signature(),
        })
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

**File:** config/src/config/consensus_config.rs (L382-382)
```rust
            optimistic_sig_verification: true,
```
