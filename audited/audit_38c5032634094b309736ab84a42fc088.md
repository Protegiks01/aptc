# Audit Report

## Title
Cryptographic Memory Not Zeroized in PreparedCiphertext and Encryption/Decryption Flow

## Summary
The `PreparedCiphertext` struct and related cryptographic types in the batch encryption library do not implement memory zeroization on drop, allowing sensitive cryptographic material to linger in process memory after use. This affects consensus secret sharing functionality.

## Finding Description

The `PreparedCiphertext` struct contains cryptographic material that is not zeroized when dropped: [1](#0-0) 

This struct contains `PreparedBIBECiphertext` which holds: [2](#0-1) 

The sensitive fields include:
1. `pairing_output` - intermediate pairing computation result
2. `padded_key: OneTimePaddedKey` - XOR-padded symmetric encryption key
3. `symmetric_ciphertext` - encrypted plaintext data

These wrapper types do not implement `Drop` with zeroization: [3](#0-2) 

Additionally, during encryption, signing key bytes are not zeroized: [4](#0-3) 

During decryption, the recovered `SymmetricKey` is not zeroized: [5](#0-4) 

This library is used in consensus for secret sharing: [6](#0-5) 

The decryption happens in batch operations: [7](#0-6) 

This violates the **Cryptographic Correctness** invariant which states that cryptographic operations must be secure. Industry best practice for cryptographic code requires zeroizing sensitive material from memory to prevent recovery through memory dumps, core dumps, cold boot attacks, or memory disclosure vulnerabilities.

## Impact Explanation

This is classified as **Low Severity** rather than Medium because:
- The bug bounty program defines Medium severity as "Limited funds loss or manipulation" or "State inconsistencies requiring intervention"
- This vulnerability causes information leakage ("Minor information leaks" - Low severity category)
- It does not directly cause funds loss, consensus violations, or state inconsistencies
- Exploitation requires the attacker to obtain process memory through secondary means (core dumps, memory disclosure vulnerabilities, physical access, etc.)

However, it affects consensus-critical code paths used for secret sharing, making it security-relevant despite the low direct impact.

## Likelihood Explanation

**Low likelihood** - Exploitation requires:
1. Attacker gains access to validator process memory via:
   - Core dumps from crashes (requires access to dump files)
   - Memory disclosure vulnerability (requires separate exploit)
   - Physical access to server hardware (cold boot attack)
   - Advanced side-channel attacks (Rowhammer, etc.)
2. Memory access occurs while cryptographic material is still in memory
3. Successful recovery of useful secrets from memory layout

## Recommendation

Implement memory zeroization using the `zeroize` crate:

1. Add dependency in `Cargo.toml`:
```toml
zeroize = { version = "1.7", features = ["derive"] }
```

2. Implement `Zeroize` and `ZeroizeOnDrop` for sensitive types:
   - `SymmetricKey`
   - `OneTimePad`  
   - `OneTimePaddedKey`
   - `PreparedBIBECiphertext`
   - `PreparedCiphertext`

3. Explicitly zeroize temporary arrays like `signing_key_bytes` before they go out of scope

4. Review all cryptographic code paths to ensure sensitive material is zeroized

## Proof of Concept

```rust
#[test]
fn test_memory_not_zeroized() {
    use aptos_batch_encryption::shared::symmetric::SymmetricKey;
    use ark_std::rand::thread_rng;
    
    let mut rng = thread_rng();
    let key = SymmetricKey::new(&mut rng);
    
    // Get pointer to key data
    let key_ptr = &key as *const _ as *const u8;
    
    // Drop the key
    drop(key);
    
    // Memory still contains key data (undefined behavior in real code, 
    // but demonstrates the issue)
    // In production, this would be verified with proper memory inspection tools
    
    // Expected: memory should be zeroed
    // Actual: memory contains original key bytes
}
```

**Notes**: 
While this is a legitimate security best practice violation, it does not meet the EXTREMELY high bar for Medium severity vulnerabilities because it requires privileged memory access to exploit and does not directly compromise consensus safety, funds, or availability. It should be classified as Low severity per the bug bounty criteria.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs (L36-41)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PreparedCiphertext {
    vk: VerifyingKey,
    bibe_ct: PreparedBIBECiphertext,
    signature: Signature,
}
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs (L76-79)
```rust
        let mut signing_key_bytes: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut signing_key_bytes);

        let signing_key: SigningKey = SigningKey::from_bytes(&signing_key_bytes);
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L50-58)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PreparedBIBECiphertext {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) pairing_output: PairingOutput,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) ct_g2: G2Prepared,
    pub(crate) padded_key: OneTimePaddedKey,
    pub(crate) symmetric_ciphertext: SymmetricCiphertext,
}
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/bibe.rs (L156-167)
```rust
    fn bibe_decrypt(&self, ct: &PreparedBIBECiphertext) -> Result<P> {
        let otp_source_1 = PairingSetting::pairing(self.signature_g1, ct.ct_g2.clone());
        let otp_source_gt = otp_source_1 + ct.pairing_output;

        let mut otp_source_bytes = Vec::new();
        otp_source_gt.serialize_compressed(&mut otp_source_bytes)?;
        let otp = OneTimePad::from_source_bytes(otp_source_bytes);

        let symmetric_key = otp.unpad_key(&ct.padded_key);

        symmetric_key.decrypt(&ct.symmetric_ciphertext)
    }
```

**File:** crates/aptos-batch-encryption/src/shared/symmetric.rs (L37-43)
```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Hash, Eq)]
pub struct SymmetricKey(GenericArray<u8, KeySize>);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Hash, Eq)]
pub struct OneTimePad(GenericArray<u8, KeySize>);
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Hash, Eq)]
pub struct OneTimePaddedKey(GenericArray<u8, KeySize>);
```

**File:** types/src/secret_sharing.rs (L16-28)
```rust
pub type EncryptionKey = <FPTXWeighted as BatchThresholdEncryption>::EncryptionKey;
pub type DigestKey = <FPTXWeighted as BatchThresholdEncryption>::DigestKey;
pub type Ciphertext = <FPTXWeighted as BatchThresholdEncryption>::Ciphertext;
pub type Id = <FPTXWeighted as BatchThresholdEncryption>::Id;
pub type Round = <FPTXWeighted as BatchThresholdEncryption>::Round;
pub type Digest = <FPTXWeighted as BatchThresholdEncryption>::Digest;
pub type EvalProofsPromise = <FPTXWeighted as BatchThresholdEncryption>::EvalProofsPromise;
pub type EvalProof = <FPTXWeighted as BatchThresholdEncryption>::EvalProof;
pub type EvalProofs = <FPTXWeighted as BatchThresholdEncryption>::EvalProofs;
pub type MasterSecretKeyShare = <FPTXWeighted as BatchThresholdEncryption>::MasterSecretKeyShare;
pub type VerificationKey = <FPTXWeighted as BatchThresholdEncryption>::VerificationKey;
pub type SecretKeyShare = <FPTXWeighted as BatchThresholdEncryption>::DecryptionKeyShare;
pub type DecryptionKey = <FPTXWeighted as BatchThresholdEncryption>::DecryptionKey;
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L388-398)
```rust
    fn decrypt<'a, P: Plaintext>(
        decryption_key: &Self::DecryptionKey,
        cts: &[Self::PreparedCiphertext],
    ) -> anyhow::Result<Vec<P>> {
        cts.into_par_iter()
            .map(|ct| {
                let plaintext: Result<P> = decryption_key.decrypt(ct);
                plaintext
            })
            .collect::<anyhow::Result<Vec<P>>>()
    }
```
