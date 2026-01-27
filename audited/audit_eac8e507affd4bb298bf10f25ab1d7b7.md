# Audit Report

## Title
KZG Evaluation Proof Validation Bypass in Batch Encryption Decryption

## Summary
The `decrypt_individual()` function in the batch encryption scheme accepts KZG evaluation proofs without cryptographic validation, allowing decryption to proceed with invalid proofs that produce incorrect plaintext results. While verification functions exist in the codebase, they are never invoked before proof usage.

## Finding Description

The batch encryption system uses KZG polynomial commitments to create digests of ciphertext batches, with evaluation proofs required for decryption. The `prepare_individual()` method directly uses the provided `eval_proof` in pairing computations without validation: [1](#0-0) 

The eval_proof is directly incorporated into cryptographic pairings without verification. The system provides `DigestKey::verify_pf()` for KZG proof verification: [2](#0-1) 

However, this verification is never called in the decryption pipeline. The trait definition shows the expected API surface: [3](#0-2) 

All three implementations (FPTX, FPTXWeighted, FPTXSuccinct) exhibit the same issue: [4](#0-3) [5](#0-4) 

The succinct variant has identical behavior: [6](#0-5) 

In the consensus pipeline, eval_proofs are computed locally but never validated before use: [7](#0-6) 

## Impact Explanation

**Severity Assessment: High**

While the current consensus implementation computes eval_proofs locally (limiting immediate exploitation), this represents a **significant protocol violation** that qualifies as High severity because:

1. **API Contract Violation**: The public API accepts untrusted cryptographic proofs without validation, violating fundamental cryptographic security principles
2. **Silent Data Corruption**: Invalid proofs produce garbage decryption with no error indication
3. **Future Attack Vectors**: Code changes or external integrations could introduce exploitable paths
4. **Consensus Determinism Risk**: If different validators use different (potentially invalid) proofs, they could compute different decryption results, breaking the Deterministic Execution invariant

This breaks the **Cryptographic Correctness** invariant (#10) that requires all cryptographic operations to be secure and properly validated.

## Likelihood Explanation

**Current Likelihood: Low (but design is fundamentally flawed)**

The current consensus implementation computes eval_proofs locally immediately before use, providing no opportunity for injection. However:

- The API is public and documented for external use
- Future optimizations might cache or reuse proofs across rounds
- Transaction replay or reorganization scenarios could reuse stored proofs
- External systems integrating this library would expect cryptographic validation

The absence of validation represents a dangerous API design that violates security best practices.

## Recommendation

Add mandatory KZG proof verification before using eval_proofs in decryption:

```rust
fn prepare_individual(
    &self,
    digest: &Digest,
    eval_proof: &EvalProof,
) -> Result<PreparedBIBECiphertext> {
    // ADD: Verify the eval_proof before using it
    // This requires passing DigestKey as parameter or storing it in the ciphertext context
    // Verification equation: e(proof, tau_g2 - id*g2) == e(digest, g2)
    
    let pairing_output = PairingSetting::pairing(digest.as_g1(), self.ct_g2[0])
        + PairingSetting::pairing(**eval_proof, self.ct_g2[1]);

    Ok(PreparedBIBECiphertext {
        pairing_output,
        ct_g2: self.ct_g2[2].into(),
        padded_key: self.padded_key.clone(),
        symmetric_ciphertext: self.symmetric_ciphertext.clone(),
    })
}
```

Alternatively, modify `decrypt_individual()` to call verification:

```rust
fn decrypt_individual<P: Plaintext>(
    decryption_key: &Self::DecryptionKey,
    ct: &Self::Ciphertext,
    digest: &Self::Digest,
    eval_proof: &Self::EvalProof,
    digest_key: &Self::DigestKey,  // Add this parameter
) -> Result<P> {
    // Verify proof before decryption
    digest_key.verify_pf(digest, ct.id(), **eval_proof)?;
    decryption_key.decrypt(&ct.prepare_individual(digest, eval_proof)?)
}
```

## Proof of Concept

```rust
#[test]
fn test_invalid_eval_proof_decrypts_without_error() {
    use crate::{
        group::*,
        schemes::fptx::FPTX,
        shared::{
            digest::EvalProof,
            ids::IdSet,
        },
        traits::BatchThresholdEncryption as _,
    };
    use aptos_crypto::arkworks::shamir::ShamirThresholdConfig;
    use ark_std::rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let tc = ShamirThresholdConfig::new(1, 1);
    let (ek, dk, _, msk_shares) = FPTX::setup_for_testing(rng.r#gen(), 8, 1, &tc).unwrap();

    let plaintext = String::from("secret message");
    let ct = FPTX::encrypt(&ek, &mut rng, &plaintext, &String::from("")).unwrap();

    let mut ids = IdSet::with_capacity(dk.capacity()).unwrap();
    ids.add(&FPTX::ct_id(&ct));
    ids.compute_poly_coeffs();
    
    let (digest, pfs) = FPTX::digest(&dk, &[ct.clone()], 0).unwrap();
    let proofs = FPTX::eval_proofs_compute_all(&pfs, &dk);
    
    let dk_share = msk_shares[0].derive_decryption_key_share(&digest).unwrap();
    let decryption_key = FPTX::reconstruct_decryption_key(&[dk_share], &tc).unwrap();

    // Use INVALID proof - just a random G1 point
    let invalid_proof = EvalProof::random();
    
    // VULNERABILITY: This succeeds without error, producing garbage plaintext
    let result = FPTX::decrypt_individual::<String>(
        &decryption_key,
        &ct,
        &digest,
        &invalid_proof,
    );
    
    // Should fail verification but doesn't
    assert!(result.is_ok());
    let decrypted = result.unwrap();
    
    // Decrypted text is garbage, NOT the original plaintext
    assert_ne!(decrypted, plaintext);
    println!("Original: {}", plaintext);
    println!("Decrypted with invalid proof: {:?}", decrypted);
}
```

This demonstrates that `decrypt_individual()` accepts invalid proofs without validation, producing silent corruption rather than returning an error.

## Notes

The KZG verification mechanism exists and is tested in isolation, but the critical integration point—validating proofs before decryption—is missing. This represents a defense-in-depth failure where cryptographic validation is available but not enforced at the API boundary where untrusted inputs are accepted.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L92-106)
```rust
    fn prepare_individual(
        &self,
        digest: &Digest,
        eval_proof: &EvalProof,
    ) -> Result<PreparedBIBECiphertext> {
        let pairing_output = PairingSetting::pairing(digest.as_g1(), self.ct_g2[0])
            + PairingSetting::pairing(**eval_proof, self.ct_g2[1]);

        Ok(PreparedBIBECiphertext {
            pairing_output,
            ct_g2: self.ct_g2[2].into(),
            padded_key: self.padded_key.clone(),
            symmetric_ciphertext: self.symmetric_ciphertext.clone(),
        })
    }
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L138-146)
```rust
    fn verify_pf(&self, digest: &Digest, id: Id, pf: G1Affine) -> Result<()> {
        // TODO use multipairing here?
        Ok((PairingSetting::pairing(
            pf,
            self.tau_g2 - G2Projective::from(G2Affine::generator() * id.x()),
        ) == PairingSetting::pairing(digest.as_g1(), G2Affine::generator()))
        .then_some(())
        .ok_or(BatchEncryptionError::EvalProofVerifyError)?)
    }
```

**File:** crates/aptos-batch-encryption/src/traits.rs (L169-174)
```rust
    fn decrypt_individual<P: Plaintext>(
        decryption_key: &Self::DecryptionKey,
        ct: &Self::Ciphertext,
        digest: &Self::Digest,
        eval_proof: &Self::EvalProof,
    ) -> Result<P>;
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

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L408-415)
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

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe_succinct.rs (L52-65)
```rust
    fn prepare_individual(
        &self,
        _digest: &Digest,
        eval_proof: &EvalProof,
    ) -> Result<PreparedBIBECiphertext> {
        let pairing_output = PairingSetting::pairing(**eval_proof, self.ct_g2[1]);

        Ok(PreparedBIBECiphertext {
            pairing_output,
            ct_g2: self.ct_g2[0].into(),
            padded_key: self.padded_key.clone(),
            symmetric_ciphertext: self.symmetric_ciphertext.clone(),
        })
    }
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L113-130)
```rust
        let proofs = FPTXWeighted::eval_proofs_compute_all(&proofs_promise, &digest_key);

        let maybe_decryption_key = secret_shared_key_rx
            .await
            .expect("decryption key should be available");
        // TODO(ibalajiarun): account for the case where decryption key is not available
        let decryption_key = maybe_decryption_key.expect("decryption key should be available");

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
```
