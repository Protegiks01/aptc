# Audit Report

## Title
Optimistic Signature Verification Bypass Enables Resource Exhaustion via Invalid SignedBatchInfo Messages

## Summary
The proof_coordinator trusts the `VerifiedEvent` designation from NetworkListener and does not perform cryptographic signature verification when adding signatures to the aggregator. With optimistic signature verification enabled by default, invalid signatures can bypass initial validation and force expensive individual verification during aggregation, enabling CPU resource exhaustion attacks.

## Finding Description

The quorum store's signature verification flow has a critical trust boundary issue:

**1. Optimistic Verification is Enabled by Default:** [1](#0-0) 

**2. Optimistic Verification Skips Cryptographic Checks:** [2](#0-1) 

When `optimistic_sig_verification` is true and the author is not in the `pessimistic_verify_set`, the method returns `Ok(())` without calling `self.verify()` to perform actual cryptographic verification.

**3. NetworkListener Forwards to proof_coordinator Without Re-Verification:** [3](#0-2) 

**4. proof_coordinator Adds Signatures Without Cryptographic Verification:** [4](#0-3) 

The only checks performed are batch_info matching and validator set membership - no signature verification occurs.

**5. Signatures Are Only Verified During Aggregation:** [5](#0-4) 

If the aggregated signature fails verification, the system must individually verify ALL signatures to filter out invalid ones: [6](#0-5) 

**Attack Flow:**
1. Malicious validator sends `SignedBatchInfo` with forged/invalid signature
2. With optimistic verification enabled, `UnverifiedEvent.verify()` calls `optimistic_verify()` which skips cryptographic validation
3. Message becomes `VerifiedEvent` and is forwarded to proof_coordinator
4. proof_coordinator's `add_signature()` adds it to aggregator without verification
5. When enough signatures are collected, `aggregate_and_verify()` is called
6. Aggregated signature verification fails due to invalid signature
7. `filter_invalid_signatures()` must individually verify EVERY signature (expensive operation)
8. Invalid signatures are filtered out, attacker is added to pessimistic_verify_set
9. Process completes but with significant CPU waste

The attacker can repeat this for every batch, causing continuous resource exhaustion.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables:

1. **CPU Resource Exhaustion**: Individual signature verification is computationally expensive (BLS signature verification). When an invalid signature forces filtering, ALL signatures in the aggregator must be individually verified, not just the invalid one.

2. **Consensus Slowdown**: Delayed proof-of-store creation directly impacts consensus performance. Quorum store batches cannot be included in blocks until proofs are created.

3. **Amplification Attack**: Attacker sends one invalid signature → forces verification of N total signatures (where N = number of validators who signed), amplifying the CPU cost by N×.

4. **Network-Wide Impact**: If multiple malicious validators coordinate, they can force expensive filtering for every batch across all validators.

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: HIGH**

1. **Enabled by Default**: Optimistic signature verification is the default configuration, making all nodes vulnerable.

2. **Low Attacker Requirement**: Any validator in the validator set can exploit this. With permissionless staking, attackers can join as validators.

3. **No Rate Limiting**: While each validator can only contribute one signature per batch, they can send invalid signatures for EVERY batch continuously.

4. **Persistent Impact**: Although attackers are added to `pessimistic_verify_set` after first detection, they've already caused the expensive filtering operation. They can also cycle through multiple validator identities.

5. **Real-World Exploitability**: Byzantine validators are expected to exist in any BFT system. This vulnerability makes their attacks significantly more impactful than intended.

## Recommendation

**Immediate Fix**: Always verify signatures before adding to aggregator when they come from network peers:

```rust
// In consensus/src/quorum_store/proof_coordinator.rs
fn add_signature(
    &mut self,
    signed_batch_info: &SignedBatchInfo<BatchInfoExt>,
    validator_verifier: &ValidatorVerifier,
) -> Result<(), SignedBatchInfoError> {
    if signed_batch_info.batch_info() != &self.signature_aggregator.data() {
        return Err(SignedBatchInfoError::WrongInfo((
            signed_batch_info.batch_info().batch_id().id,
            self.signature_aggregator.data().batch_id().id,
        )));
    }

    // ADD THIS: Verify signature before adding to aggregator
    if !signed_batch_info.signature_with_status().is_verified() {
        validator_verifier.verify(
            signed_batch_info.signer(),
            signed_batch_info.batch_info(),
            signed_batch_info.signature()
        ).map_err(|_| SignedBatchInfoError::InvalidSignature)?;
        signed_batch_info.signature_with_status().set_verified();
    }

    match validator_verifier.get_voting_power(&signed_batch_info.signer()) {
        // ... rest of the function
    }
}
```

**Alternative**: Disable optimistic verification for SignedBatchInfo specifically, or reduce the trust boundary by verifying signatures immediately after network receipt before forwarding.

## Proof of Concept

```rust
// PoC demonstrating the vulnerability (conceptual - would need full test harness)
#[tokio::test]
async fn test_invalid_signature_causes_expensive_filtering() {
    // Setup: Create validator set and proof coordinator
    let (validators, validator_verifier) = create_test_validators(10);
    let mut proof_coordinator = ProofCoordinator::new(...);
    
    // Create a valid batch
    let batch_info = create_test_batch_info();
    
    // Honest validators send valid signatures
    for i in 0..7 {
        let signed = validators[i].sign(&batch_info);
        proof_coordinator.add_signature(signed, &validator_verifier).unwrap();
    }
    
    // ATTACK: Malicious validator sends invalid signature
    let malicious_validator = &validators[7];
    let invalid_sig = bls12381::Signature::dummy_signature(); // Invalid signature
    let forged_signed_batch = SignedBatchInfo::new_with_signature(
        batch_info.clone(),
        malicious_validator.author(),
        invalid_sig
    );
    
    // With optimistic verification, this gets added successfully
    proof_coordinator.add_signature(&forged_signed_batch, &validator_verifier).unwrap();
    
    // When aggregating, the system must verify ALL signatures individually
    let start = Instant::now();
    let result = proof_coordinator.aggregate_and_verify(&validator_verifier);
    let elapsed = start.elapsed();
    
    // Observe: Aggregation takes significantly longer due to filtering
    // Individual verification of N signatures instead of one aggregated verification
    assert!(elapsed > expected_fast_path_time * 5); // 5x slower
    
    // The malicious validator is now in pessimistic_verify_set
    assert!(validator_verifier.pessimistic_verify_set().contains(&malicious_validator.author()));
}
```

## Notes

The vulnerability stems from the tension between performance optimization (optimistic verification) and security (defense-in-depth). While the final aggregated signature verification ensures correctness, the lack of early verification creates a resource exhaustion vector. The pessimistic_verify_set provides eventual protection but only after the damage is done.

The attack requires the attacker to be a validator, but with permissionless staking this is achievable. The impact is amplified because filtering requires verifying ALL signatures, not just identifying the invalid one.

### Citations

**File:** config/src/config/consensus_config.rs (L382-382)
```rust
            optimistic_sig_verification: true,
```

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

**File:** consensus/src/quorum_store/network_listener.rs (L57-66)
```rust
                    VerifiedEvent::SignedBatchInfo(signed_batch_infos) => {
                        counters::QUORUM_STORE_MSG_COUNT
                            .with_label_values(&["NetworkListener::signedbatchinfo"])
                            .inc();
                        let cmd =
                            ProofCoordinatorCommand::AppendSignature(sender, *signed_batch_infos);
                        self.proof_coordinator_tx
                            .send(cmd)
                            .await
                            .expect("Could not send signed_batch_info to proof_coordinator");
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L145-178)
```rust
    fn add_signature(
        &mut self,
        signed_batch_info: &SignedBatchInfo<BatchInfoExt>,
        validator_verifier: &ValidatorVerifier,
    ) -> Result<(), SignedBatchInfoError> {
        if signed_batch_info.batch_info() != &self.signature_aggregator.data() {
            return Err(SignedBatchInfoError::WrongInfo((
                signed_batch_info.batch_info().batch_id().id,
                self.signature_aggregator.data().batch_id().id,
            )));
        }

        match validator_verifier.get_voting_power(&signed_batch_info.signer()) {
            Some(voting_power) => {
                self.signature_aggregator.add_signature(
                    signed_batch_info.signer(),
                    signed_batch_info.signature_with_status(),
                );
                self.aggregated_voting_power += voting_power as u128;
                if signed_batch_info.signer() == self.signature_aggregator.data().author() {
                    self.self_voted = true;
                }
            },
            None => {
                error!(
                    "Received signature from author not in validator set: {}",
                    signed_batch_info.signer()
                );
                return Err(SignedBatchInfoError::InvalidAuthor);
            },
        }

        Ok(())
    }
```

**File:** types/src/ledger_info.rs (L517-535)
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
```
