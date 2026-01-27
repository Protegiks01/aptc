# Audit Report

## Title
Batch Encryption ID Collision Allows Cross-Encryption Attacks via HashMap Overwrite

## Summary
The batch encryption system fails to enforce unique IDs across ciphertexts in a batch. When multiple ciphertexts share the same ID, evaluation proofs computed for decryption are stored in a `HashMap<Id, G1Affine>`, causing duplicate IDs to overwrite earlier proofs. This results in decryption failures for all but one ciphertext sharing the same ID, enabling denial-of-service attacks and breaking the integrity of the batch encryption scheme.

## Finding Description

The vulnerability exists in the interaction between ID collection, proof computation, and proof storage across multiple files in the batch encryption crate.

**Attack Flow:**

1. An attacker generates a single signing key and derives its verifying key [1](#0-0) 

2. The attacker creates multiple BIBE ciphertexts using the same ID by calling the encryption function multiple times with the same key, producing different ciphertexts (due to randomness in encryption) but with identical IDs [2](#0-1) 

3. The verification function only checks that each ciphertext's ID matches its hashed verifying key, but does NOT enforce uniqueness across the batch [3](#0-2) 

4. When creating a digest for the batch, all IDs (including duplicates) are added to the `IdSet` without deduplication [4](#0-3) 

5. During eval proof computation, proofs are calculated for each position in the roots vector [5](#0-4) 

6. **Critical Flaw**: The computed proofs are stored in a `HashMap<Id, G1Affine>`. When multiple ciphertexts have the same ID, only the last proof for each duplicate ID is retained, overwriting earlier proofs [6](#0-5) 

7. During decryption preparation, all ciphertexts with duplicate IDs attempt to retrieve the same proof from the HashMap [7](#0-6) 

8. Only the ciphertext whose position corresponds to the stored proof decrypts correctly; all others fail or produce garbage output [8](#0-7) 

## Impact Explanation

**Medium Severity** - This vulnerability causes state inconsistencies requiring intervention and enables targeted denial-of-service attacks:

- **Decryption Failure**: Legitimate ciphertexts fail to decrypt when an attacker pollutes the batch with duplicate IDs
- **DoS Attack**: An attacker can prevent specific ciphertexts from being decrypted by creating duplicates with the same ID
- **Information Leakage**: The system reveals which ciphertexts decrypt successfully, potentially leaking information about batch composition
- **Protocol Integrity Violation**: Breaks the fundamental assumption that each ciphertext in a batch has a unique identity

This meets the **Medium Severity** criteria from the Aptos bug bounty program: "State inconsistencies requiring intervention" and "Limited funds loss or manipulation" (if encrypted data represents value).

## Likelihood Explanation

**High Likelihood** - This attack is trivial to execute:

- **Low Complexity**: Attacker only needs to reuse a signing key across multiple encryptions
- **No Special Access Required**: Any user can call the public encryption API
- **Deterministic Outcome**: The HashMap collision always occurs with duplicate IDs
- **No Resource Requirements**: Attack requires minimal computational resources
- **Hard to Detect**: The verification functions pass for each individual ciphertext

The attack can be performed by any unprivileged user without requiring validator access or special cryptographic capabilities.

## Recommendation

**Immediate Fix**: Enforce ID uniqueness when creating batches.

Add validation in the digest creation to reject batches with duplicate IDs: [9](#0-8) 

Modify the digest function to check for duplicates:

```rust
fn digest(
    digest_key: &Self::DigestKey,
    cts: &[Self::Ciphertext],
    round: Self::Round,
) -> anyhow::Result<(Self::Digest, Self::EvalProofsPromise)> {
    let ids: Vec<Id> = cts.iter().map(|ct| ct.id()).collect();
    
    // Check for duplicate IDs
    let mut seen = std::collections::HashSet::new();
    for id in &ids {
        if !seen.insert(id) {
            return Err(anyhow!("Duplicate ID detected in batch: {:?}", id));
        }
    }
    
    let mut id_set = IdSet::from_slice(&ids)
        .ok_or(anyhow!("Failed to create IdSet"))?;
    
    digest_key.digest(&mut id_set, round)
}
```

**Alternative Fix**: Modify the eval proof storage to use a different data structure that preserves all proofs, indexed by both ID and position.

## Proof of Concept

```rust
#[test]
fn test_duplicate_id_attack() {
    use ark_std::rand::thread_rng;
    use aptos_crypto::arkworks::shamir::ShamirThresholdConfig;
    use crate::{
        schemes::fptx::FPTX,
        shared::ciphertext::{CTEncrypt, CTDecrypt},
        traits::BatchThresholdEncryption,
    };
    use ed25519_dalek::SigningKey;
    
    let mut rng = thread_rng();
    let tc = ShamirThresholdConfig::new(1, 1);
    let (ek, dk, _, msk_shares) = FPTX::setup_for_testing(rng.gen(), 8, 1, &tc).unwrap();
    
    // Create a single signing key to reuse
    let signing_key = SigningKey::generate(&mut rng);
    let vk = signing_key.verifying_key();
    let shared_id = crate::shared::ids::Id::from_verifying_key(&vk);
    
    // Create two different ciphertexts with the SAME ID
    let plaintext1 = String::from("message1");
    let plaintext2 = String::from("message2");
    let associated_data = String::from("");
    
    let ct1 = ek.bibe_encrypt(&mut rng, &plaintext1, shared_id).unwrap();
    let ct2 = ek.bibe_encrypt(&mut rng, &plaintext2, shared_id).unwrap();
    
    // Wrap them in proper Ciphertexts (simplified - in reality attacker would sign)
    // Both have the same ID
    assert_eq!(ct1.id(), ct2.id());
    
    // Create digest with both ciphertexts
    let mut ids = crate::shared::ids::IdSet::with_capacity(2).unwrap();
    ids.add(&ct1.id());
    ids.add(&ct2.id()); // Duplicate ID!
    
    ids.compute_poly_coeffs();
    let (digest, pfs_promise) = dk.digest(&mut ids, 0).unwrap();
    let pfs = pfs_promise.compute_all(&dk);
    
    // The HashMap only stores ONE proof for the shared ID
    assert_eq!(pfs.computed_proofs.len(), 1); // Only 1 proof despite 2 IDs!
    
    // Try to prepare both ciphertexts - they'll use the SAME proof
    let prepared1 = ct1.prepare(&digest, &pfs);
    let prepared2 = ct2.prepare(&digest, &pfs);
    
    // At least one will fail or decrypt incorrectly
    let dk_key = crate::shared::key_derivation::BIBEDecryptionKey::reconstruct(
        &tc, 
        &[msk_shares[0].derive_decryption_key_share(&digest).unwrap()]
    ).unwrap();
    
    let result1: Result<String, _> = dk_key.decrypt(&prepared1.unwrap());
    let result2: Result<String, _> = dk_key.decrypt(&prepared2.unwrap());
    
    // Demonstrate the attack: at least one decryption fails or is wrong
    assert!(result1.is_err() || result2.is_err() || 
            result1.unwrap() != plaintext1 || result2.unwrap() != plaintext2);
}
```

**Notes**

This vulnerability specifically affects the batch encryption subsystem and does not directly impact consensus, the Move VM, or other core Aptos components. However, if batch encryption is used for any security-critical operations (such as encrypted transactions or private data storage), this vulnerability could enable attacks that corrupt or deny access to encrypted data. The fix requires enforcing ID uniqueness at the batch level rather than relying on the assumption that IDs will be naturally unique.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs (L76-81)
```rust
        let mut signing_key_bytes: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut signing_key_bytes);

        let signing_key: SigningKey = SigningKey::from_bytes(&signing_key_bytes);
        let vk = signing_key.verifying_key();
        let hashed_id = Id::from_verifying_key(&vk);
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs (L82-82)
```rust
        let bibe_ct = self.bibe_encrypt(rng, plaintext, hashed_id)?;
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs (L111-116)
```rust
    pub fn verify(&self, associated_data: &impl AssociatedData) -> Result<()> {
        let hashed_id = Id::from_verifying_key(&self.vk);

        (self.bibe_ct.id() == hashed_id).then_some(()).ok_or(
            BatchEncryptionError::CTVerifyError(CTVerifyError::IdDoesNotMatchHashedVK),
        )?;
```

**File:** crates/aptos-batch-encryption/src/shared/ids/mod.rs (L84-89)
```rust
    pub fn add(&mut self, id: &Id) {
        if self.poly_roots.len() >= self.capacity {
            panic!("Number of ids must be less than capacity");
        }
        self.poly_roots.push(id.root_x);
    }
```

**File:** crates/aptos-batch-encryption/src/shared/ids/mod.rs (L124-146)
```rust
    pub fn compute_all_eval_proofs_with_setup(
        &self,
        setup: &crate::shared::digest::DigestKey,
        round: usize,
    ) -> HashMap<Id, G1Affine> {
        let pfs: Vec<G1Affine> = setup
            .fk_domain
            .eval_proofs_at_x_coords_naive_multi_point_eval(
                &self.poly_coeffs(),
                &self.poly_roots,
                round,
            )
            .iter()
            .map(|g| G1Affine::from(*g))
            .collect();

        HashMap::from_iter(
            self.as_vec()
                .into_iter()
                .zip(pfs)
                .collect::<Vec<(Id, G1Affine)>>(),
        )
    }
```

**File:** crates/aptos-batch-encryption/src/shared/digest.rs (L191-194)
```rust
#[derive(Clone)]
pub struct EvalProofs {
    pub computed_proofs: HashMap<Id, G1Affine>,
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

**File:** crates/aptos-batch-encryption/src/schemes/fptx.rs (L100-110)
```rust
    fn digest(
        digest_key: &Self::DigestKey,
        cts: &[Self::Ciphertext],
        round: Self::Round,
    ) -> anyhow::Result<(Self::Digest, Self::EvalProofsPromise)> {
        let mut ids: IdSet<UncomputedCoeffs> =
            IdSet::from_slice(&cts.iter().map(|ct| ct.id()).collect::<Vec<Id>>())
                .ok_or(anyhow!(""))?;

        digest_key.digest(&mut ids, round)
    }
```
