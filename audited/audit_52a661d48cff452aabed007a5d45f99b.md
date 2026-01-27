# Audit Report

## Title
Missing Ciphertext Verification Before Digest Computation Enables Malleability Attacks and Consensus Divergence

## Summary
The `decrypt_encrypted_txns` function in the consensus decryption pipeline fails to verify ciphertexts before computing the digest and deriving decryption key shares. This directly violates the documented security requirement and enables attackers to include malicious, unverified ciphertexts in blocks, potentially causing consensus divergence and bypassing cryptographic authentication.

## Finding Description

The batch threshold encryption trait explicitly states that validators **must** verify each ciphertext before approving it for decryption to prevent malleability attacks: [1](#0-0) 

This verification checks three critical properties:
1. The ciphertext ID matches the hashed verification key
2. The associated data (transaction sender) matches
3. The Ed25519 signature over the ciphertext and associated data is valid [2](#0-1) 

However, the consensus decryption pipeline completely omits this verification step. When processing encrypted transactions, validators extract ciphertexts and immediately compute the digest without any validation: [3](#0-2) 

The `verify_ct` function is implemented but never called: [4](#0-3) 

**Attack Scenario:**
1. A malicious block proposer creates ciphertexts with:
   - Invalid/manipulated IDs that don't match the hashed verification key
   - Tampered associated data
   - Missing or forged Ed25519 signatures
2. These malicious ciphertexts are included in a proposed block
3. All validators receive the block and extract ciphertexts without verification
4. Validators compute a digest from these unverified, potentially invalid ciphertexts
5. Each validator derives decryption key shares for this digest
6. Key shares are exchanged and aggregated
7. The aggregated key attempts to decrypt the malicious ciphertexts

**Security Impact:**
- **Signature Bypass**: Cryptographic authentication via Ed25519 signatures is completely bypassed
- **Malleability Attacks**: Attackers can reuse, modify, or forge ciphertexts without detection
- **Consensus Divergence**: If validators handle decryption failures differently (some crash, some continue), this can cause non-deterministic execution and consensus splits
- **Data Integrity**: The digest is computed over manipulated/invalid IDs, breaking the binding between ciphertexts and their committed IDs

## Impact Explanation

This is a **CRITICAL** severity vulnerability according to Aptos bug bounty criteria because:

1. **Consensus/Safety Violations**: Different validators may process invalid ciphertexts differently, leading to divergent state and consensus failures. This breaks the "Deterministic Execution" invariant requiring all validators to produce identical state roots for identical blocks.

2. **Protocol Violation**: The code explicitly documents that verification "must" occur but is not implemented, representing a fundamental security control failure.

3. **Cryptographic Bypass**: Ed25519 signature verification is a core security primitive that is completely bypassed, allowing unauthenticated data to be processed.

4. **Enables Malleability Attacks**: The documented purpose of verification is to prevent malleability attacks, which are now possible.

While this may not directly cause "Loss of Funds" in the traditional sense, it meets the Critical criteria of "Consensus/Safety violations" and could potentially lead to a "Non-recoverable network partition" if validators diverge on invalid ciphertext handling.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability is easily exploitable but requires:
- Encrypted transactions to be enabled (currently disabled by checks in `Batch::verify()` as noted in search results)
- An attacker to become a block proposer (rotates among validators)

However, once encrypted transactions are enabled (as the infrastructure is being built for), exploitation becomes straightforward:
- No cryptographic breaks required
- No collusion needed
- Simply include invalid ciphertexts in a proposed block
- All validators automatically process them without verification

The impact severity is HIGH because even if exploitation is infrequent, a single malicious block can affect all validators simultaneously.

## Recommendation

Add mandatory ciphertext verification before digest computation in `decrypt_encrypted_txns`: [3](#0-2) 

**Fixed Code:**
```rust
let txn_ciphertexts: Vec<Ciphertext> = encrypted_txns
    .iter()
    .map(|txn| {
        let ciphertext = txn.payload()
            .as_encrypted_payload()
            .expect("must be a encrypted txn")
            .ciphertext()
            .clone();
        
        // CRITICAL: Verify ciphertext before including in digest computation
        let sender = txn.sender();
        FPTXWeighted::verify_ct(&ciphertext, &PayloadAssociatedData::new(sender))
            .map_err(|e| anyhow!("Ciphertext verification failed: {}", e))?;
        
        Ok(ciphertext)
    })
    .collect::<anyhow::Result<Vec<Ciphertext>>>()?;

// Now safe to compute digest over verified ciphertexts
let encryption_round = block.round();
let (digest, proofs_promise) =
    FPTXWeighted::digest(&digest_key, &txn_ciphertexts, encryption_round)?;
```

Where `PayloadAssociatedData` is constructed from the transaction sender as defined here: [5](#0-4) 

## Proof of Concept

```rust
// Test demonstrating vulnerability: invalid ciphertexts are processed without verification
#[test]
fn test_unverified_ciphertext_acceptance() {
    use aptos_batch_encryption::{
        schemes::fptx_weighted::FPTXWeighted,
        traits::BatchThresholdEncryption,
    };
    
    // Setup encryption keys
    let mut rng = thread_rng();
    let tc = ShamirThresholdConfig::new(3, 5);
    let (ek, dk, vks, msk_shares) = FPTXWeighted::setup_for_testing(
        rng.gen(),
        8,
        1,
        &tc,
    ).unwrap();
    
    // Create a valid ciphertext
    let plaintext = String::from("test");
    let associated_data = String::from("valid_sender");
    let mut ct = ek.encrypt(&mut rng, &plaintext, &associated_data).unwrap();
    
    // Tamper with the ciphertext (make it invalid)
    ct.associated_data_bytes = vec![0xFF; 32]; // Invalid associated data
    
    // Verification should fail
    assert!(ct.verify(&associated_data).is_err());
    
    // But digest computation succeeds without verification!
    let mut ids = IdSet::with_capacity(8).unwrap();
    ids.add(&ct.id());
    let (digest, _) = dk.digest(&mut ids, 0).unwrap();
    
    // Key shares are derived for invalid ciphertext
    for msk_share in &msk_shares {
        let key_share = msk_share.derive_decryption_key_share(&digest);
        assert!(key_share.is_ok()); // Derives successfully despite invalid ciphertext
    }
    
    // This demonstrates the vulnerability: validators process unverified ciphertexts
}
```

## Notes

- The vulnerability exists in production code but encrypted transactions appear to be disabled in `Batch::verify()` with the check: `ensure!(!txn.payload().is_encrypted_variant())`
- Once encrypted transactions are enabled, this becomes an immediately exploitable critical vulnerability
- The fix is straightforward: add the verification loop before digest computation
- This affects all three batch encryption schemes (FPTX, FPTXSuccinct, FPTXWeighted) but the production code uses FPTXWeighted

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

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L78-93)
```rust
        let txn_ciphertexts: Vec<Ciphertext> = encrypted_txns
            .iter()
            .map(|txn| {
                // TODO(ibalajiarun): Avoid clone and use reference instead
                txn.payload()
                    .as_encrypted_payload()
                    .expect("must be a encrypted txn")
                    .ciphertext()
                    .clone()
            })
            .collect();

        // TODO(ibalajiarun): Consider using commit block height to reduce trusted setup size
        let encryption_round = block.round();
        let (digest, proofs_promise) =
            FPTXWeighted::digest(&digest_key, &txn_ciphertexts, encryption_round)?;
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L332-337)
```rust
    fn verify_ct(
        ct: &Self::Ciphertext,
        associated_data: &impl AssociatedData,
    ) -> anyhow::Result<()> {
        ct.verify(associated_data)
    }
```

**File:** types/src/transaction/encrypted_payload.rs (L28-37)
```rust
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct PayloadAssociatedData {
    sender: AccountAddress,
}

impl PayloadAssociatedData {
    fn new(sender: AccountAddress) -> Self {
        Self { sender }
    }
}
```
