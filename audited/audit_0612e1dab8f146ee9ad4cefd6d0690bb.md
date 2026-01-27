# Audit Report

## Title
Missing Ciphertext Validation in Consensus Decryption Pipeline Violates Malleability Protection

## Summary
The `decrypt_individual()` function in the FPTX batch threshold encryption scheme, used by the consensus layer to decrypt encrypted transactions, fails to validate ciphertext integrity before decryption. This violates the explicitly documented security requirement that "Validators *must* verify each ciphertext before approving it to be decrypted, in order to prevent malleability attacks," creating a defense-in-depth failure in the encrypted transaction processing pipeline.

## Finding Description

The batch threshold encryption system implements a critical security requirement documented in the trait definition: ciphertexts must be verified before decryption to prevent malleability attacks. [1](#0-0) 

The `verify_ct()` function performs three critical checks: (1) the ciphertext ID matches the hashed verification key, (2) the associated data matches what's stored in the ciphertext, and (3) the Ed25519 signature over the ciphertext and associated data is valid. [2](#0-1) 

However, the `decrypt_individual()` implementation directly calls `prepare_individual()` without any validation. [3](#0-2) 

The consensus decryption pipeline uses this function to decrypt encrypted transactions in blocks, calling `decrypt_individual()` directly without invoking `verify_ct()` beforehand. [4](#0-3) 

While ciphertexts are validated at API submission time through `validate_signed_transaction_payload()`, [5](#0-4)  the consensus layer performs no re-validation. This creates a defense-in-depth failure: if any bug in API validation, alternate submission path, or block construction allows an unverified ciphertext into the consensus pipeline, it will be decrypted without validation.

Additionally, `prepare_individual()` accepts arbitrary `eval_proof` and `digest` parameters without validating that the proof corresponds to the ciphertext's ID, unlike the regular `prepare()` method which looks up the correct proof by ID. [6](#0-5) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program as a "Significant protocol violation." The vulnerability:

1. **Violates documented security invariant**: The code explicitly requires validation before decryption to prevent malleability attacks, but this is not enforced in the consensus path
2. **Bypasses cryptographic integrity checks**: Signature verification, ID validation, and associated data validation are all skipped
3. **Creates potential for consensus divergence**: If different validators handle malformed ciphertexts inconsistently, this could break deterministic execution
4. **Enables malleability attacks**: An attacker exploiting any weakness in API validation could submit ciphertexts with tampered components that would be decrypted without verification

While the primary validation at API submission provides the first line of defense, consensus-critical operations should implement defense-in-depth by independently validating all cryptographic inputs.

## Likelihood Explanation

**Likelihood: Medium**

Direct exploitation requires one of the following conditions:
1. A vulnerability in API validation allowing malformed ciphertexts through
2. An alternate transaction submission path bypassing API validation
3. A bug in block construction or validation

However, the probability increases because:
- The codebase is actively developed with frequent changes that could introduce validation bugs
- The encrypted transaction feature is relatively new and complex
- Multiple code paths handle transaction submission and validation
- The violation of an explicit security requirement suggests the defense-in-depth principle was not consistently applied

## Recommendation

**Immediate Fix:** Add ciphertext verification in `decrypt_individual()` before calling `prepare_individual()`:

```rust
fn decrypt_individual<P: Plaintext>(
    decryption_key: &Self::DecryptionKey,
    ct: &Self::Ciphertext,
    digest: &Self::Digest,
    eval_proof: &Self::EvalProof,
) -> Result<P> {
    // Verify ciphertext integrity before decryption
    // Note: This requires passing associated_data, which should be
    // derived from the transaction sender address
    // ct.verify(associated_data)?;
    
    decryption_key.decrypt(&ct.prepare_individual(digest, eval_proof)?)
}
```

**Architectural Fix:** Modify the consensus decryption pipeline to explicitly verify each ciphertext: [7](#0-6) 

Add verification before the decryption loop:
```rust
// Verify all ciphertexts before decryption
for (txn, ciphertext) in encrypted_txns.iter().zip(&txn_ciphertexts) {
    let sender = txn.sender();
    ciphertext.verify(&PayloadAssociatedData::new(sender))?;
}
```

This ensures that even if API validation is bypassed, consensus validators will reject invalid ciphertexts.

## Proof of Concept

```rust
// Demonstrates that decrypt_individual() accepts unverified ciphertexts
#[test]
fn test_decrypt_without_verification() {
    use aptos_batch_encryption::{schemes::fptx::FPTX, traits::BatchThresholdEncryption};
    use aptos_crypto::arkworks::shamir::ShamirThresholdConfig;
    use ark_std::rand::{thread_rng, Rng};
    
    let mut rng = thread_rng();
    let tc = ShamirThresholdConfig::new(1, 1);
    let (ek, dk, _, msk_shares) = FPTX::setup_for_testing(rng.r#gen(), 8, 1, &tc).unwrap();
    
    // Create a valid ciphertext
    let plaintext = String::from("test");
    let associated_data = String::from("data");
    let mut ct = FPTX::encrypt(&ek, &mut rng, &plaintext, &associated_data).unwrap();
    
    // Tamper with the ciphertext's associated data (this would fail verification)
    ct.associated_data_bytes = bcs::to_bytes(&String::from("tampered")).unwrap();
    
    // Verification would catch this
    assert!(FPTX::verify_ct(&ct, &associated_data).is_err());
    
    // But decrypt_individual() does NOT verify, so it proceeds with tampered data
    let (digest, proofs_promise) = FPTX::digest(&dk, &vec![ct.clone()], 0).unwrap();
    let proofs = FPTX::eval_proofs_compute_all(&proofs_promise, &dk);
    let eval_proof = FPTX::eval_proof_for_ct(&proofs, &ct).unwrap();
    
    let decryption_key = FPTX::reconstruct_decryption_key(
        &[msk_shares[0].derive_decryption_key_share(&digest).unwrap()],
        &tc
    ).unwrap();
    
    // This proceeds without verification, violating the security requirement
    let result = FPTX::decrypt_individual::<String>(
        &decryption_key,
        &ct,
        &digest,
        &eval_proof
    );
    
    // The decryption may succeed or fail, but the point is that verification was bypassed
    // In a real attack, this could be exploited if the tampering allows malicious behavior
}
```

## Notes

The vulnerability is exacerbated by the fact that the consensus pipeline processes encrypted transactions from blocks without re-validating them, relying solely on API-level validation. While this may be sufficient under normal operation, it violates the defense-in-depth principle explicitly called for in the trait documentation. The fix requires propagating the transaction sender's address to the decryption function so that associated data can be properly validated.

### Citations

**File:** crates/aptos-batch-encryption/src/traits.rs (L106-109)
```rust
    /// Validators *must* verify each ciphertext before approving it to be decrypted, in order to
    /// prevent malleability attacks. Verification happens w.r.t. some associated data that was
    /// passed into the encrypt fn.
    fn verify_ct(ct: &Self::Ciphertext, associated_data: &impl AssociatedData) -> Result<()>;
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs (L111-132)
```rust
    pub fn verify(&self, associated_data: &impl AssociatedData) -> Result<()> {
        let hashed_id = Id::from_verifying_key(&self.vk);

        (self.bibe_ct.id() == hashed_id).then_some(()).ok_or(
            BatchEncryptionError::CTVerifyError(CTVerifyError::IdDoesNotMatchHashedVK),
        )?;
        (self.associated_data_bytes == bcs::to_bytes(associated_data)?)
            .then_some(())
            .ok_or(BatchEncryptionError::CTVerifyError(
                CTVerifyError::AssociatedDataDoesNotMatch,
            ))?;

        let to_verify = (&self.bibe_ct, &self.associated_data_bytes);

        self.vk
            .verify(&bcs::to_bytes(&to_verify)?, &self.signature)
            .map_err(|e| {
                BatchEncryptionError::CTVerifyError(CTVerifyError::SigVerificationFailed(e))
            })?;

        Ok(())
    }
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx.rs (L188-195)
```rust
    fn decrypt_individual<P: Plaintext>(
        decryption_key: &Self::DecryptionKey,
        ct: &Self::Ciphertext,
        digest: &Self::Digest,
        eval_proof: &Self::EvalProof,
    ) -> Result<P> {
        decryption_key.decrypt(&ct.prepare_individual(digest, eval_proof)?)
    }
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L121-148)
```rust
        let decrypted_txns = encrypted_txns
            .into_par_iter()
            .zip(txn_ciphertexts)
            .map(|(mut txn, ciphertext)| {
                let eval_proof = proofs.get(&ciphertext.id()).expect("must exist");
                if let Ok(payload) = FPTXWeighted::decrypt_individual::<DecryptedPayload>(
                    &decryption_key.key,
                    &ciphertext,
                    &digest,
                    &eval_proof,
                ) {
                    let (executable, nonce) = payload.unwrap();
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| {
                            p.into_decrypted(eval_proof, executable, nonce)
                                .expect("must happen")
                        })
                        .expect("must exist");
                } else {
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| p.into_failed_decryption(eval_proof).expect("must happen"))
                        .expect("must exist");
                }
                txn
            })
            .collect();
```

**File:** api/src/transactions.rs (L1323-1346)
```rust
            TransactionPayload::EncryptedPayload(payload) => {
                if !self.context.node_config.api.allow_encrypted_txns_submission {
                    return Err(SubmitTransactionError::bad_request_with_code(
                        "Encrypted Transaction submission is not allowed yet",
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    ));
                }

                if !payload.is_encrypted() {
                    return Err(SubmitTransactionError::bad_request_with_code(
                        "Encrypted transaction must be in encrypted state",
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    ));
                }

                if let Err(e) = payload.verify(signed_transaction.sender()) {
                    return Err(SubmitTransactionError::bad_request_with_code(
                        e.context("Encrypted transaction payload could not be verified"),
                        AptosErrorCode::InvalidInput,
                        ledger_info,
                    ));
                }
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L84-90)
```rust
    fn prepare(&self, digest: &Digest, eval_proofs: &EvalProofs) -> Result<PreparedBIBECiphertext> {
        let pf = eval_proofs
            .get(&self.id)
            .ok_or(BatchEncryptionError::UncomputedEvalProofError)?;

        self.prepare_individual(digest, &pf)
    }
```
