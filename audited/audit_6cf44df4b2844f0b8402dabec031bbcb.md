# Audit Report

## Title
Type Confusion Vulnerability in Batch Encryption Decryption Due to Missing Plaintext Type Validation

## Summary
The `decrypt()` function in the batch encryption system lacks type validation after decryption, allowing arbitrary data interpretation through BCS deserialization type confusion. The generic plaintext type `P` is not validated against what was originally encrypted, enabling potential state inconsistencies in consensus when encrypted transactions are processed.

## Finding Description

The batch encryption system uses a generic decryption function that deserializes ciphertext to any type `P: Plaintext` without validating that `P` matches the originally encrypted type. [1](#0-0) 

The decryption flow operates as follows:

1. AES-GCM decryption produces raw bytes
2. `bcs::from_bytes::<P>(&plaintext_bytes)` deserializes to the requested type `P`
3. No validation ensures `P` matches the type that was encrypted

This propagates through the encryption layers: [2](#0-1) 

And is used in consensus to decrypt encrypted transactions: [3](#0-2) 

The `Plaintext` trait provides no type safety, only requiring serialization: [4](#0-3) 

**Attack Vector:**

BCS (Binary Canonical Serialization) does not embed type information. Two different types with compatible field layouts will have identical or compatible BCS encodings. For example:

- `DecryptedPayload { executable: TransactionExecutable, decryption_nonce: u64 }`
- A malicious struct with the same BCS layout could deserialize as `DecryptedPayload` [5](#0-4) 

Since the decrypted `TransactionExecutable` is used directly in consensus without additional validation: [6](#0-5) 

This breaks the **Deterministic Execution** invariant: validators processing the same ciphertext could interpret it as different types if implementation inconsistencies exist, leading to consensus divergence.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention.

While the ciphertext verification prevents tampering post-creation, the lack of type validation creates these risks:

1. **State Inconsistency**: If validators have implementation differences or use different decryption types, the same ciphertext could be interpreted differently
2. **Transaction Validation Bypass**: Malicious data crafted to deserialize as `DecryptedPayload` could bypass type-level validation
3. **Consensus Integrity**: Type confusion could cause validators to process malformed `TransactionExecutable` values

The impact is limited to Medium because:
- The ciphertext signature protects integrity
- Associated data binding restricts ciphertext context
- Exploitability requires specific BCS serialization compatibility
- Does not directly enable fund theft or complete consensus failure

## Likelihood Explanation

**Medium Likelihood** - The vulnerability exists in production code with uncertain exploitability.

**Factors Increasing Likelihood:**
- The vulnerability is present in actively used consensus code
- BCS's lack of type information makes type confusion inherently possible
- No runtime type validation exists at any layer

**Factors Decreasing Likelihood:**
- Unclear if unprivileged users can create encrypted transactions with arbitrary plaintext types
- Requires crafting data with specific BCS layout matching `DecryptedPayload`
- Ciphertext signatures prevent post-creation modification
- The encryption API may constrain allowable plaintext types (though not enforced in decrypt)

The likelihood depends on access controls in the user-facing encrypted transaction API, which is not evident from the reviewed code.

## Recommendation

Add type validation after decryption to ensure the decrypted plaintext matches the expected type. Implement one of these approaches:

**Option 1: Type Tag in Ciphertext**
Add a type identifier to the symmetric ciphertext that is validated during decryption:

```rust
pub struct SymmetricCiphertext {
    nonce: SymmetricNonce,
    type_tag: String,  // Store type name during encryption
    ct_body: Vec<u8>,
}

pub fn decrypt<P: Plaintext>(&self, ciphertext: &SymmetricCiphertext) -> Result<P> {
    let expected_type = std::any::type_name::<P>();
    ensure!(
        ciphertext.type_tag == expected_type,
        "Type mismatch: expected {}, got {}",
        expected_type,
        ciphertext.type_tag
    );
    
    let plaintext_bytes = cipher.decrypt(&ciphertext.nonce, ciphertext.ct_body.as_ref())?;
    Ok(bcs::from_bytes(&plaintext_bytes)?)
}
```

**Option 2: Domain-Specific Decryption**
Replace the generic `decrypt()` with domain-specific functions that enforce expected types:

```rust
impl SymmetricKey {
    pub fn decrypt_transaction_payload(
        &self, 
        ciphertext: &SymmetricCiphertext
    ) -> Result<DecryptedPayload> {
        let plaintext_bytes = cipher.decrypt(&ciphertext.nonce, ciphertext.ct_body.as_ref())?;
        let payload: DecryptedPayload = bcs::from_bytes(&plaintext_bytes)?;
        // Additional DecryptedPayload-specific validation
        Ok(payload)
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_type_confusion_vulnerability() {
    use crate::shared::symmetric::{SymmetricKey, SymmetricCiphertext};
    use crate::traits::Plaintext;
    use serde::{Deserialize, Serialize};
    use ark_std::rand::thread_rng;

    // Define two types with compatible BCS serialization
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    struct TypeA {
        field1: u8,
        field2: u64,
    }
    impl Plaintext for TypeA {}

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    struct TypeB {
        data1: u8,
        data2: u64,
    }
    impl Plaintext for TypeB {}

    let mut rng = thread_rng();
    let key = SymmetricKey::new(&mut rng);

    // Encrypt as TypeA
    let original = TypeA {
        field1: 42,
        field2: 12345,
    };
    let ciphertext = key.encrypt(&mut rng, &original).unwrap();

    // Decrypt as TypeB - NO TYPE VALIDATION, SUCCEEDS!
    let confused: TypeB = key.decrypt(&ciphertext).unwrap();

    // Verify type confusion: same underlying data, different types
    assert_eq!(confused.data1, original.field1);
    assert_eq!(confused.data2, original.field2);
    println!("Type confusion successful: encrypted TypeA, decrypted as TypeB");
}
```

## Notes

The vulnerability exists at the code level with certainty. The exploitability by unprivileged attackers depends on:
1. Whether users can create encrypted transactions through exposed APIs
2. Whether those APIs allow arbitrary plaintext types or enforce `DecryptedPayload`
3. Access controls on the encryption key material

The batch encryption system is used in consensus for encrypted transaction decryption, making this a security-relevant code path. Even if currently unexploitable due to API restrictions, the lack of type validation violates defense-in-depth principles and creates latent risk.

### Citations

**File:** crates/aptos-batch-encryption/src/shared/symmetric.rs (L112-123)
```rust
    pub fn decrypt<P: Plaintext>(&self, ciphertext: &SymmetricCiphertext) -> Result<P> {
        use aes_gcm::KeyInit as _; // putting this in the global scope causes Hmac<Sha256> to be
                                   // ambiguous for some reason

        let key: &Key<SymmetricCipher> = &self.0;
        let cipher = SymmetricCipher::new(key);
        let plaintext_bytes = cipher
            .decrypt(&ciphertext.nonce, ciphertext.ct_body.as_ref())
            .map_err(|_| BatchEncryptionError::SymmetricDecryptionError)?;
        Ok(bcs::from_bytes(&plaintext_bytes)
            .map_err(|_| BatchEncryptionError::DeserializationError)?)
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

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L126-131)
```rust
                if let Ok(payload) = FPTXWeighted::decrypt_individual::<DecryptedPayload>(
                    &decryption_key.key,
                    &ciphertext,
                    &digest,
                    &eval_proof,
                ) {
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L132-139)
```rust
                    let (executable, nonce) = payload.unwrap();
                    txn.payload_mut()
                        .as_encrypted_payload_mut()
                        .map(|p| {
                            p.into_decrypted(eval_proof, executable, nonce)
                                .expect("must happen")
                        })
                        .expect("must exist");
```

**File:** crates/aptos-batch-encryption/src/traits.rs (L179-179)
```rust
pub trait Plaintext: Serialize + DeserializeOwned + Send + Sync {}
```

**File:** types/src/transaction/encrypted_payload.rs (L15-18)
```rust
pub struct DecryptedPayload {
    executable: TransactionExecutable,
    decryption_nonce: u64,
}
```
