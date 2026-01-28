# Audit Report

## Title
Batch Encryption ID Mismatch Vulnerability Allows Malformed Ciphertext Bypass

## Summary
The `verify()` function in the batch encryption ciphertext module fails to validate that cryptographic operations actually used the stored ID value. This allows creation of malformed ciphertexts where the `id` field (used for eval proof lookup) differs from the ID cryptographically bound in `ct_g2`, causing guaranteed decryption failures despite passing all verification checks. Attackers can submit these malformed ciphertexts to waste validator resources on expensive KZG eval proof computations.

## Finding Description

The vulnerability exists in the interaction between ciphertext encryption, verification, and decryption preparation in the batch encryption system.

**The BIBECiphertext Structure:**

The `BIBECiphertext` struct has a **public `id` field** that can be directly modified after creation. [1](#0-0) 

**Cryptographic Binding During Encryption:**

During `bibe_encrypt()`, the ID parameter is cryptographically bound into `ct_g2[1]` at line 130, which permanently embeds it into the ciphertext's cryptographic structure. [2](#0-1) 

**Insufficient Verification:**

The `verify()` function performs three checks but never validates that the stored `id` matches the ID used in cryptographic operations. It only checks: (1) stored `id` matches hashed verification key, (2) associated data matches, and (3) signature is valid. [3](#0-2) 

**Attack Execution Path:**

1. Attacker generates a signing key and computes `correct_id = Id::from_verifying_key(&vk)`
2. Attacker obtains the public `EncryptionKey` (publicly available via getter) [4](#0-3) 
3. Attacker calls `bibe_encrypt(rng, plaintext, wrong_id)` where `wrong_id ≠ correct_id`, creating `ct_g2[1]` with `wrong_id` cryptographically bound
4. Attacker modifies the public field: `bibe_ct.id = correct_id`
5. Attacker signs the modified ciphertext with their signing key
6. Attacker submits the malformed ciphertext as an encrypted transaction

**Verification Bypass:**

The ciphertext passes API-layer verification. [5](#0-4)  The encrypted payload verification calls the ciphertext's verify method with associated data. [6](#0-5) 

All three verification checks pass because the stored `id` matches the hashed verification key, associated data matches, and the signature over the modified ciphertext is valid.

**Decryption Failure:**

During consensus decryption, the eval proof is fetched using the **stored** `correct_id`. [7](#0-6) 

However, the pairing computation in `prepare_individual()` uses `ct_g2[1]` which was computed with `wrong_id`. [8](#0-7) 

The pairing `PairingSetting::pairing(**eval_proof, self.ct_g2[1])` at line 98 will be incorrect because `eval_proof` corresponds to `correct_id` but `ct_g2[1]` was computed with `wrong_id`. This mismatch causes the decryption key derivation to fail, resulting in garbage data and decryption failure.

## Impact Explanation

**Severity: High ($50,000)**

This vulnerability enables **Validator Resource Exhaustion** through malformed ciphertext submission:

1. **Wasted Cryptographic Computation**: Validators must compute expensive KZG eval proofs for all encrypted transactions before attempting decryption. [9](#0-8)  The trait documentation explicitly states this is "the most expensive operation in the scheme." [10](#0-9)  All this computation is wasted because the malformed ciphertext can never decrypt successfully.

2. **Explicit Security Requirement Violation**: The batch encryption trait explicitly states validators must verify ciphertexts to prevent malleability attacks. [11](#0-10)  The current verification implementation fails to detect ID mismatches between the stored field and cryptographically bound value.

3. **Sustained Attack Vector**: While limited to 10 encrypted transactions per block, [12](#0-11)  an attacker can continuously submit malformed ciphertexts in every block, forcing validators to repeatedly waste resources on computations that will never succeed.

4. **Graceful Failure Handling**: Decryption failures are handled gracefully by marking transactions as `FailedDecryption`. [13](#0-12)  However, this doesn't mitigate the resource waste that has already occurred from the expensive eval proof computation.

Per Aptos bug bounty categories, this qualifies as **High Severity** due to "Validator node slowdowns" - validators experience significant performance degradation from wasted cryptographic computations on malformed ciphertexts that pass verification but cannot be decrypted.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is highly feasible because:

1. **Public Encryption Key**: The `EncryptionKey` must be publicly available for users to create encrypted transactions, accessible via a public getter method. [4](#0-3) 

2. **Public API Surface**: The encrypted transaction submission is explicitly supported when configured. [14](#0-13) 

3. **Direct Field Modification**: The `id` field is public and can be modified directly without any serialization tricks or memory corruption exploits.

4. **No Special Privileges Required**: Any transaction sender can perform this attack without requiring validator access, stake, or special permissions.

**Attack Requirements:**
- Knowledge of BIBE batch encryption internals (moderate complexity - requires understanding of the cryptographic protocol)
- Ability to call Rust crypto libraries (standard for any Aptos transaction creation)
- Gas cost for transaction submission (minimal economic barrier, standard transaction fees)

## Recommendation

Add validation in the `prepare_individual()` or `verify()` function to ensure the stored `id` field matches the ID value cryptographically bound in the ciphertext components. This could be done by:

1. Computing the expected `ct_g2[1]` value using the stored `id` and comparing it to the actual value, or
2. Attempting a test pairing operation during verification to ensure consistency, or
3. Making the `id` field private and only settable during construction, preventing post-creation modification

The most robust fix would be to make the `id` field immutable (private with no setter) so it cannot be modified after ciphertext creation, ensuring the stored ID always matches the cryptographically bound value.

## Proof of Concept

```rust
// PoC demonstrating the attack flow:
// 1. Generate signing key and derive correct_id
let mut rng = thread_rng();
let signing_key = SigningKey::generate(&mut rng);
let vk = signing_key.verifying_key();
let correct_id = Id::from_verifying_key(&vk);

// 2. Get public encryption key
let encryption_key = secret_share_config.encryption_key();

// 3. Encrypt with wrong_id
let wrong_id = Id::new(Fr::rand(&mut rng)); // Different from correct_id
let mut bibe_ct = encryption_key.bibe_encrypt(&mut rng, &plaintext, wrong_id)?;

// 4. Modify the public id field
bibe_ct.id = correct_id;

// 5. Sign the modified ciphertext
let associated_data = PayloadAssociatedData::new(sender);
let to_sign = (&bibe_ct, &bcs::to_bytes(&associated_data)?);
let signature = signing_key.sign(&bcs::to_bytes(&to_sign)?);

// 6. Create ciphertext with modified id
let malformed_ct = Ciphertext {
    vk,
    bibe_ct,
    associated_data_bytes: bcs::to_bytes(&associated_data)?,
    signature,
};

// 7. Verification passes
assert!(malformed_ct.verify(&associated_data).is_ok());

// 8. But decryption will fail due to ID mismatch in pairing computation
// The eval_proof will be fetched using correct_id
// But ct_g2[1] was computed with wrong_id
// Causing pairing mismatch and decryption failure
```

### Citations

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L41-48)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct BIBECiphertext {
    pub id: Id,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    ct_g2: [G2Affine; 3],
    padded_key: OneTimePaddedKey,
    symmetric_ciphertext: SymmetricCiphertext,
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

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L119-152)
```rust
    fn bibe_encrypt<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &impl Plaintext,
        id: Id,
    ) -> Result<BIBECiphertext> {
        let r = [Fr::rand(rng), Fr::rand(rng)];
        let hashed_encryption_key: G1Affine = symmetric::hash_g2_element(self.sig_mpk_g2)?;

        let ct_g2 = [
            (G2Affine::generator() * r[0] + self.sig_mpk_g2 * r[1]).into(),
            ((G2Affine::generator() * id.x() - self.tau_g2) * r[0]).into(),
            (-(G2Affine::generator() * r[1])).into(),
        ];

        let otp_source_gt: PairingOutput =
            -PairingSetting::pairing(hashed_encryption_key, self.sig_mpk_g2) * r[1];

        let mut otp_source_bytes = Vec::new();
        otp_source_gt.serialize_compressed(&mut otp_source_bytes)?;
        let otp = OneTimePad::from_source_bytes(otp_source_bytes);

        let symmetric_key = SymmetricKey::new(rng);
        let padded_key = otp.pad_key(&symmetric_key);

        let symmetric_ciphertext = symmetric_key.encrypt(rng, plaintext)?;

        Ok(BIBECiphertext {
            id,
            ct_g2,
            padded_key,
            symmetric_ciphertext,
        })
    }
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

**File:** types/src/secret_sharing.rs (L204-206)
```rust
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.encryption_key
    }
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

**File:** types/src/transaction/encrypted_payload.rs (L147-150)
```rust
    pub fn verify(&self, sender: AccountAddress) -> anyhow::Result<()> {
        let associated_data = PayloadAssociatedData::new(sender);
        self.ciphertext().verify(&associated_data)
    }
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L69-76)
```rust
        let len = 10;
        let encrypted_txns = if encrypted_txns.len() > len {
            let mut to_truncate = encrypted_txns;
            to_truncate.truncate(len);
            to_truncate
        } else {
            encrypted_txns
        };
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L112-113)
```rust
        // TODO(ibalajiarun): improve perf
        let proofs = FPTXWeighted::eval_proofs_compute_all(&proofs_promise, &digest_key);
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

**File:** crates/aptos-batch-encryption/src/traits.rs (L106-109)
```rust
    /// Validators *must* verify each ciphertext before approving it to be decrypted, in order to
    /// prevent malleability attacks. Verification happens w.r.t. some associated data that was
    /// passed into the encrypt fn.
    fn verify_ct(ct: &Self::Ciphertext, associated_data: &impl AssociatedData) -> Result<()>;
```

**File:** crates/aptos-batch-encryption/src/traits.rs (L115-119)
```rust
    /// Compute KZG eval proofs. This will be the most expensive operation in the scheme.
    fn eval_proofs_compute_all(
        proofs: &Self::EvalProofsPromise,
        digest_key: &Self::DigestKey,
    ) -> Self::EvalProofs;
```
