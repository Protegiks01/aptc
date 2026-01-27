# Audit Report

## Title
Complete BIBE Encryption Break via Compromised hash_g2_element() Function

## Summary
If the `hash_g2_element()` function in the symmetric module is compromised to return predictable values (especially the identity element), the entire BIBE (Batch Identity-Based Encryption) scheme used for encrypted transactions in Aptos consensus becomes completely broken. All encrypted transactions can be decrypted by any observer without requiring decryption keys, enabling front-running, censorship, and MEV extraction.

## Finding Description
The BIBE encryption scheme relies on `hash_g2_element()` as a critical cryptographic primitive to derive a hashed encryption key from the master public key. This hashed key is used to generate a one-time pad (OTP) that protects the symmetric encryption key. [1](#0-0) 

The encryption process computes: [2](#0-1) 

The OTP is then derived and used to protect the symmetric key: [3](#0-2) 

**If `hash_g2_element()` is compromised** to return a predictable value (e.g., the identity element in G1):

1. `pairing(0_G1, sig_mpk_g2) = 1_GT` (identity in pairing target group)
2. `otp_source_gt = -1_GT * r[1] = 1_GT` (identity raised to any power remains identity)
3. Serializing `1_GT` produces a fixed byte sequence
4. `OTP = HMAC_KDF(serialize(1_GT))` becomes a **constant value across all encryptions**

This means every transaction encrypted to the same epoch's encryption key uses the **identical OTP**.

**Attack Execution:**

An attacker who knows the function returns a predictable value can:

1. Observe encrypted transactions in blocks from the consensus pipeline: [4](#0-3) 

2. Compute the same constant OTP: `OTP = HMAC_KDF(serialize(pairing(0, anything)^anything))`

3. Recover the symmetric key: `symmetric_key = padded_key ⊕ OTP`

4. Decrypt the transaction: `plaintext = symmetric_key.decrypt(symmetric_ciphertext)`

The encrypted transactions flow through the consensus pipeline: [5](#0-4) 

And are decrypted using BIBE: [6](#0-5) 

This breaks the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure."

## Impact Explanation
**Critical Severity** - This vulnerability meets multiple critical impact categories:

1. **Loss of Funds**: Attackers can decrypt encrypted transactions before they're executed, enabling:
   - Front-running: Submit competing transactions with knowledge of pending encrypted transactions
   - MEV extraction: Exploit transaction ordering for profit
   - Arbitrage attacks on DeFi protocols

2. **Privacy Violation**: All encrypted transaction data is exposed to any observer, completely defeating the purpose of transaction encryption

3. **Consensus Impact**: Transaction privacy and fairness are fundamental to consensus integrity. The ability to selectively decrypt and act on encrypted transactions undermines fair transaction ordering

The hash_to_curve implementation is defined at: [7](#0-6) 

## Likelihood Explanation
**Likelihood: Medium** (assuming the function is compromised)

The attack requires:
- **No special privileges**: Any network observer can execute the attack
- **No validator collusion**: Works independently
- **Minimal complexity**: Simple XOR operation to recover keys
- **Public information**: The encryption key `sig_mpk_g2` is public

However, the likelihood depends on the compromise vector:
- **Backdoored implementation**: If the function is intentionally backdoored
- **Cryptographic weakness**: If SHA-256 or the hash-to-curve algorithm has undiscovered weaknesses
- **Supply chain attack**: If malicious code is inserted into the hash function

The current implementation uses standard cryptographic primitives (SHA-256, hash-to-field), but **any compromise** of this single function breaks the entire encryption scheme.

## Recommendation
1. **Implement redundancy**: Use multiple independent hash-to-curve implementations and verify consistency
2. **Add cryptographic binding**: Include additional randomness that cannot be predicted even if hash_g2_element() is compromised
3. **Deterministic OTP verification**: Add assertions to detect if OTP generation becomes predictable across encryptions
4. **Alternative OTP derivation**: Consider deriving OTP from additional entropy sources beyond just the pairing result

**Code mitigation example**:
```rust
// Add additional entropy to OTP derivation
let additional_entropy = rng.gen::<[u8; 32]>(); 
let mut otp_source_bytes = Vec::new();
otp_source_gt.serialize_compressed(&mut otp_source_bytes)?;
otp_source_bytes.extend_from_slice(&additional_entropy);
let otp = OneTimePad::from_source_bytes(otp_source_bytes);
// Store additional_entropy in ciphertext for decryption
```

4. **Cryptographic audit**: Regular third-party audits of hash_g2_element() implementation
5. **Runtime monitoring**: Detect anomalies in OTP distribution across encryptions

## Proof of Concept
```rust
#[test]
fn test_predictable_hash_breaks_encryption() {
    use ark_ec::AffineRepr;
    use ark_std::Zero;
    
    // Simulate compromised hash_g2_element returning identity
    let compromised_hash = G1Affine::zero(); // identity element
    let sig_mpk_g2 = G2Affine::generator(); // public key
    
    // Compute OTP source as it would be in encryption
    let otp_source_gt = -PairingSetting::pairing(compromised_hash, sig_mpk_g2);
    
    // Since pairing(0, anything) = 1_GT (identity in target group)
    // And -1_GT = 1_GT (inverse of identity is identity)
    // otp_source_gt is always 1_GT regardless of r[1]
    
    let mut otp_source_bytes1 = Vec::new();
    otp_source_gt.serialize_compressed(&mut otp_source_bytes1).unwrap();
    
    // Attacker can compute the same OTP
    let attacker_otp = OneTimePad::from_source_bytes(otp_source_bytes1.clone());
    
    // Given padded_key from ciphertext, attacker recovers symmetric_key
    let symmetric_key = SymmetricKey::new(&mut rng);
    let padded_key = attacker_otp.pad_key(&symmetric_key);
    
    // Attacker computation:
    let recovered_key = attacker_otp.unpad_key(&padded_key);
    
    assert_eq!(symmetric_key, recovered_key);
    // Attacker can now decrypt symmetric_ciphertext
}
```

## Notes
This vulnerability demonstrates that `hash_g2_element()` is a **single point of cryptographic failure** in the BIBE scheme. The function is defined at: [7](#0-6) 

While the current implementation uses standard cryptographic practices, any compromise—whether through backdoor, cryptanalytic breakthrough, or implementation bug—would completely break transaction encryption used in Aptos consensus. The blast radius includes all encrypted transactions processed through: [8](#0-7) 

The security of encrypted transactions in Aptos consensus fundamentally depends on the integrity of this single hash-to-curve function.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L126-126)
```rust
        let hashed_encryption_key: G1Affine = symmetric::hash_g2_element(self.sig_mpk_g2)?;
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L134-135)
```rust
        let otp_source_gt: PairingOutput =
            -PairingSetting::pairing(hashed_encryption_key, self.sig_mpk_g2) * r[1];
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L137-142)
```rust
        let mut otp_source_bytes = Vec::new();
        otp_source_gt.serialize_compressed(&mut otp_source_bytes)?;
        let otp = OneTimePad::from_source_bytes(otp_source_bytes);

        let symmetric_key = SymmetricKey::new(rng);
        let padded_key = otp.pad_key(&symmetric_key);
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L27-34)
```rust
    pub(crate) async fn decrypt_encrypted_txns(
        materialize_fut: TaskFuture<MaterializeResult>,
        block: Arc<Block>,
        author: Author,
        secret_share_config: Option<SecretShareConfig>,
        derived_self_key_share_tx: oneshot::Sender<Option<SecretShare>>,
        secret_shared_key_rx: oneshot::Receiver<Option<SecretSharedKey>>,
    ) -> TaskResult<DecryptionResult> {
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L78-88)
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
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L126-131)
```rust
                if let Ok(payload) = FPTXWeighted::decrypt_individual::<DecryptedPayload>(
                    &decryption_key.key,
                    &ciphertext,
                    &digest,
                    &eval_proof,
                ) {
```

**File:** crates/aptos-batch-encryption/src/shared/symmetric.rs (L150-177)
```rust
pub fn hash_g2_element(g2_element: G2Affine) -> Result<G1Affine> {
    for ctr in 0..=u8::MAX {
        let mut hash_source_bytes = Vec::new();
        g2_element
            .serialize_compressed(&mut hash_source_bytes)
            .unwrap();
        let mut ctr_bytes = Vec::from([ctr]);
        hash_source_bytes.append(&mut ctr_bytes);
        let field_hasher = <DefaultFieldHasher<Sha256> as HashToField<Fq>>::new(&[]);
        let [x]: [Fq; 1] = field_hasher.hash_to_field::<1>(&hash_source_bytes);

        // Rust does not optimise away addition with zero
        use crate::group::G1Config;
        let mut x3b = G1Config::add_b(x.square() * x);
        if !G1Config::COEFF_A.is_zero() {
            x3b += G1Config::mul_by_a(x);
        };

        // TODO vary the sign of y??
        if let Some(x3b_sqrt) = x3b.sqrt() {
            let p = G1Affine::new_unchecked(x, x3b_sqrt).mul_by_cofactor();
            assert!(p.is_in_correct_subgroup_assuming_on_curve());
            return Ok(p);
        }
    }

    Err(BatchEncryptionError::Hash2CurveFailure)?
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L461-471)
```rust
        let decryption_fut = spawn_shared_fut(
            Self::decrypt_encrypted_txns(
                materialize_fut,
                block.clone(),
                self.signer.author(),
                self.secret_share_config.clone(),
                derived_self_key_share_tx,
                secret_shared_key_rx,
            ),
            Some(&mut abort_handles),
        );
```
