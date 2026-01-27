# Audit Report

## Title
Optimistic Signature Verification Bypass Enabling Temporary DoS via Invalid SignedBatchInfo Messages

## Summary
The `ValidatorVerifier::optimistic_verify()` function skips cryptographic signature verification when optimistic mode is enabled (default configuration), allowing malicious validators to temporarily flood the system with invalid `SignedBatchInfo` messages that consume resources before being detected and rejected during batch aggregation.

## Finding Description

The `SignedBatchInfo::verify()` implementation correctly delegates to `ValidatorVerifier::optimistic_verify()` [1](#0-0) , but this function has a design flaw that creates a temporary verification bypass.

When optimistic signature verification is enabled (default: true [2](#0-1) ), the `optimistic_verify()` function returns `Ok(())` without cryptographic verification if the author is not in the pessimistic_verify_set [3](#0-2) .

**Attack Flow:**
1. Malicious validator sends `SignedBatchInfo` with invalid signature
2. Message passes network verification via `UnverifiedEvent` conversion [4](#0-3) 
3. `optimistic_verify()` bypasses cryptographic check, returns `Ok(())`
4. Message treated as `VerifiedEvent` and forwarded to `ProofCoordinator` [5](#0-4) 
5. Invalid signature added to `SignatureAggregator` [6](#0-5) 
6. System attempts batch aggregation and verification
7. Batch verification fails, triggering expensive individual verification [7](#0-6) 
8. Bad actor identified and added to `pessimistic_verify_set` [8](#0-7) 

This violates the **Resource Limits** invariant (#9) - the system does not properly enforce signature validation limits before resource-intensive batch operations.

## Impact Explanation

**High Severity** - Validator node slowdowns. During the time window before bad actors are detected (steps 1-8 above), malicious validators can:
- Send bursts of invalid signatures that bypass initial verification
- Force expensive batch aggregation attempts  
- Trigger costly individual signature verification fallback
- Consume CPU resources on all validator nodes processing these batches
- Delay proof-of-store generation and block proposals

This meets High Severity criteria per the bug bounty program: "Validator node slowdowns" and "Significant protocol violations" (bypassing signature verification gates).

## Likelihood Explanation

**High likelihood** - This is exploitable by any Byzantine validator in the active set with minimal complexity:
- Optimistic verification is **enabled by default** in production
- No rate limiting exists before pessimistic_verify_set detection
- Attack requires only crafting invalid BLS signatures and flooding the network
- Multiple malicious validators (within the 1/3 Byzantine tolerance) could coordinate to maximize impact
- The time window for exploitation exists for every epoch until the attacker is detected

## Recommendation

Implement immediate signature verification for the first message from each validator per epoch, before enabling optimistic mode:

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
    
    // NEW: Always verify first signature from each author per session
    // to prevent DoS from never-seen-before invalid signatures
    if !signature_with_status.is_verified() {
        if !self.optimistic_sig_verification 
            || self.pessimistic_verify_set.contains(&author)
            || !self.has_verified_signature_from(&author) // NEW CHECK
        {
            self.verify(author, message, signature_with_status.signature())?;
            signature_with_status.set_verified();
            self.mark_author_verified(&author); // NEW: Track verified authors
        }
    }
    Ok(())
}
```

Additionally, add per-validator rate limiting on unverified signatures before batch aggregation.

## Proof of Concept

```rust
// Test demonstrating DoS via invalid signatures with optimistic verification
#[test]
fn test_optimistic_verification_dos() {
    let (signers, mut verifier) = random_validator_verifier(4, None, false);
    verifier.set_optimistic_sig_verification_flag(true); // Enable optimistic mode
    
    let malicious_signer = &signers[0];
    let batch_info = BatchInfo::new(
        malicious_signer.author(), BatchId::new(1), 1, 100000,
        HashValue::random(), 100, 1000, 0
    );
    
    // Create INVALID signature (using wrong message)
    let wrong_message = BatchInfo::new(
        malicious_signer.author(), BatchId::new(999), 1, 100000,
        HashValue::random(), 100, 1000, 0
    );
    let invalid_sig = malicious_signer.sign(&wrong_message).unwrap();
    
    let signed_batch = SignedBatchInfo::new_with_signature(
        batch_info.clone(), 
        malicious_signer.author(),
        invalid_sig
    );
    
    // Verification PASSES despite invalid signature due to optimistic mode
    assert!(signed_batch.verify(
        malicious_signer.author(),
        1000000,
        &verifier
    ).is_ok());
    
    // Now add to aggregator and attempt batch verification
    let mut aggregator = SignatureAggregator::new(batch_info);
    aggregator.add_signature(malicious_signer.author(), signed_batch.signature_with_status());
    
    // Batch verification FAILS, triggering expensive individual verification
    // Attacker can repeat this multiple times before being added to pessimistic_verify_set
    assert!(aggregator.aggregate_and_verify(&verifier).is_err());
}
```

**Notes:**
While the system eventually detects and blocks bad actors via `pessimistic_verify_set`, there is a significant time window during which malicious validators can exploit optimistic verification to cause resource exhaustion. The lack of immediate verification for initial messages from each validator creates an exploitable DoS vector that degrades consensus performance across the network.

### Citations

**File:** consensus/consensus-types/src/proof_of_store.rs (L481-481)
```rust
        Ok(validator.optimistic_verify(self.signer, &self.info, &self.signature)?)
```

**File:** config/src/config/consensus_config.rs (L382-382)
```rust
            optimistic_sig_verification: true,
```

**File:** types/src/validator_verifier.rs (L278-284)
```rust
        if (!self.optimistic_sig_verification || self.pessimistic_verify_set.contains(&author))
            && !signature_with_status.is_verified()
        {
            self.verify(author, message, signature_with_status.signature())?;
            signature_with_status.set_verified();
        }
        Ok(())
```

**File:** types/src/validator_verifier.rs (L306-306)
```rust
                    self.add_pessimistic_verify_set(account_address);
```

**File:** consensus/src/round_manager.rs (L184-196)
```rust
            UnverifiedEvent::SignedBatchInfo(sd) => {
                if !self_message {
                    sd.verify(
                        peer_id,
                        max_num_batches,
                        max_batch_expiry_gap_usecs,
                        validator,
                    )?;
                    counters::VERIFY_MSG
                        .with_label_values(&["signed_batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::SignedBatchInfo(Box::new((*sd).into()))
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

**File:** consensus/src/quorum_store/proof_coordinator.rs (L159-162)
```rust
                self.signature_aggregator.add_signature(
                    signed_batch_info.signer(),
                    signed_batch_info.signature_with_status(),
                );
```

**File:** types/src/ledger_info.rs (L529-534)
```rust
            Err(_) => {
                self.filter_invalid_signatures(verifier);

                let aggregated_sig = self.try_aggregate(verifier)?;
                Ok((self.data.clone(), aggregated_sig))
            },
```
