# Audit Report

## Title
Missing Payload Hash Verification After Decryption Enables Potential Consensus Split

## Summary
The `EncryptedPayload` structure contains a `payload_hash` field that is signed as part of the transaction but is never verified against the actual decrypted content after decryption. While the ciphertext itself is protected by Ed25519 signatures preventing direct malleability, the absence of post-decryption integrity verification could allow consensus splits if validators decrypt to different results due to implementation bugs or version inconsistencies.

## Finding Description

The `EncryptedPayload` enum contains a `payload_hash: HashValue` field in all three variants (Encrypted, FailedDecryption, Decrypted): [1](#0-0) 

The ciphertext itself has cryptographic protection via Ed25519 signatures that prevent modification: [2](#0-1) [3](#0-2) 

However, during the decryption process in consensus, the decrypted payload is used without verifying it against the committed `payload_hash`: [4](#0-3) 

The transition to decrypted state preserves the `payload_hash` but never validates it: [5](#0-4) 

**Critical Gap:** There is no code anywhere in the codebase that compares `hash(executable)` against `payload_hash` after decryption. This missing integrity check violates defense-in-depth principles for consensus safety.

**Why This Matters for Consensus Safety:**

1. **Deterministic Execution Invariant**: All validators must produce identical state roots for identical blocks. If validators decrypt to different executables, they execute different transactions.

2. **Missing Safety Net**: While BIBE decryption should be deterministic in theory, defense-in-depth requires verification. The `payload_hash` was included in the transaction structure for this purpose but is never used.

3. **Potential Attack Scenarios**:
   - **Implementation bugs**: If the BIBE library has non-deterministic behavior or bugs
   - **Version skew**: If validators run different BIBE implementation versions with behavioral differences  
   - **Cryptographic edge cases**: Undiscovered weaknesses in BIBE that allow same ciphertext to decrypt differently

## Impact Explanation

**Severity: HIGH (potentially CRITICAL)**

Per the Aptos bug bounty program, this qualifies as:
- **Critical** if exploitable: "Consensus/Safety violations" leading to chain splits
- **High**: "Significant protocol violations" affecting consensus integrity

The impact depends on whether validators can decrypt to different results. If this occurs (through implementation bugs, version differences, or cryptographic issues), the result is a **consensus split** - the most severe failure mode short of total liveness loss. Different validators would:

1. Execute different transactions from the same block
2. Compute different state roots
3. Be unable to reach consensus on subsequent blocks
4. Potentially require a hard fork to resolve

## Likelihood Explanation

**Likelihood: Medium to Low, but consequences are severe**

The likelihood depends on:

1. **BIBE Implementation Quality**: If the BIBE implementation has bugs causing non-determinism, this becomes highly likely
2. **Validator Diversity**: If validators run different software versions, edge cases could emerge
3. **Network Maturity**: As encrypted transactions become more common, the attack surface increases

While cryptographic primitives are assumed secure per the exclusions, **implementation bugs in the BIBE library are not excluded**. The complete absence of post-decryption verification means such bugs would go undetected until causing a consensus split.

The missing check represents a violation of the fail-safe principle: even if decryption is deterministic in theory, critical systems should verify this assumption.

## Recommendation

Add payload hash verification after successful decryption:

```rust
// In consensus/src/pipeline/decryption_pipeline_builder.rs
if let Ok(payload) = FPTXWeighted::decrypt_individual::<DecryptedPayload>(
    &decryption_key.key,
    &ciphertext,
    &digest,
    &eval_proof,
) {
    let (executable, nonce) = payload.unwrap();
    
    // NEW: Verify payload hash matches decrypted content
    let decrypted_payload_hash = HashValue::sha3_256_of(&bcs::to_bytes(&executable)?);
    let committed_payload_hash = txn.payload()
        .as_encrypted_payload()
        .map(|p| match p {
            EncryptedPayload::Encrypted { payload_hash, .. } => *payload_hash,
            _ => unreachable!("Must be in Encrypted state"),
        })
        .expect("must be encrypted payload");
    
    if decrypted_payload_hash != committed_payload_hash {
        // Treat as decryption failure - this indicates either:
        // 1. Implementation bug in BIBE
        // 2. Malicious ciphertext (if BIBE has weaknesses)
        // 3. Version inconsistency between validators
        error!("Payload hash mismatch after decryption: expected {:?}, got {:?}",
               committed_payload_hash, decrypted_payload_hash);
        txn.payload_mut()
            .as_encrypted_payload_mut()
            .map(|p| p.into_failed_decryption(eval_proof).expect("must happen"))
            .expect("must exist");
        continue;
    }
    
    txn.payload_mut()
        .as_encrypted_payload_mut()
        .map(|p| {
            p.into_decrypted(eval_proof, executable, nonce)
                .expect("must happen")
        })
        .expect("must exist");
}
```

Additionally, ensure `payload_hash` is properly computed when creating encrypted transactions (currently test code uses `HashValue::random()`).

## Proof of Concept

```rust
#[test]
fn test_payload_hash_verification_missing() {
    use aptos_types::transaction::encrypted_payload::{EncryptedPayload, DecryptedPayload};
    use aptos_types::transaction::{TransactionExecutable, TransactionExtraConfig};
    use aptos_types::secret_sharing::{Ciphertext, EvalProof};
    use aptos_crypto::HashValue;
    
    // Create an encrypted payload with a specific payload_hash
    let correct_hash = HashValue::sha3_256_of(b"correct_executable");
    let mut encrypted = EncryptedPayload::Encrypted {
        ciphertext: Ciphertext::random(),
        extra_config: TransactionExtraConfig::V1 {
            multisig_address: None,
            replay_protection_nonce: None,
        },
        payload_hash: correct_hash,
    };
    
    // Simulate decryption to a DIFFERENT executable
    let wrong_executable = TransactionExecutable::Empty;
    let wrong_hash = HashValue::sha3_256_of(&bcs::to_bytes(&wrong_executable).unwrap());
    
    assert_ne!(correct_hash, wrong_hash, "Hashes should differ");
    
    // The current implementation allows transition without verification
    encrypted.into_decrypted(
        EvalProof::random(),
        wrong_executable,
        0
    ).expect("Should succeed - this is the bug!");
    
    // At this point, the EncryptedPayload is in Decrypted state with:
    // - payload_hash = correct_hash (from original transaction)
    // - executable = wrong_executable (from "buggy" decryption)
    // No verification caught this mismatch!
    
    match encrypted {
        EncryptedPayload::Decrypted { payload_hash, executable, .. } => {
            let actual_hash = HashValue::sha3_256_of(&bcs::to_bytes(&executable).unwrap());
            assert_ne!(payload_hash, actual_hash, "Demonstrating missing verification");
        },
        _ => panic!("Should be in Decrypted state"),
    }
}
```

This test demonstrates that the system accepts decrypted payloads without verifying they match the committed `payload_hash`, which could lead to consensus splits if validators decrypt to different results.

**Notes:**

The ciphertext field itself IS protected against malleability via Ed25519 signatures. However, the complete absence of payload_hash verification after decryption represents a critical missing safety check that could allow consensus splits to occur undetected if the BIBE implementation has bugs or non-deterministic behavior.

### Citations

**File:** types/src/transaction/encrypted_payload.rs (L42-64)
```rust
pub enum EncryptedPayload {
    Encrypted {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
    },
    FailedDecryption {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
        eval_proof: EvalProof,
    },
    Decrypted {
        ciphertext: Ciphertext,
        extra_config: TransactionExtraConfig,
        payload_hash: HashValue,
        eval_proof: EvalProof,

        // decrypted things
        executable: TransactionExecutable,
        decryption_nonce: u64,
    },
}
```

**File:** types/src/transaction/encrypted_payload.rs (L101-125)
```rust
    pub fn into_decrypted(
        &mut self,
        eval_proof: EvalProof,
        executable: TransactionExecutable,
        nonce: u64,
    ) -> anyhow::Result<()> {
        let Self::Encrypted {
            ciphertext,
            extra_config,
            payload_hash,
        } = self
        else {
            bail!("Payload is not in Encrypted state");
        };

        *self = Self::Decrypted {
            ciphertext: ciphertext.clone(),
            extra_config: extra_config.clone(),
            payload_hash: *payload_hash,
            eval_proof,
            executable,
            decryption_nonce: nonce,
        };
        Ok(())
    }
```

**File:** crates/aptos-batch-encryption/src/shared/ciphertext/mod.rs (L23-31)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(bound(deserialize = "PCT: DeserializeOwned"))]
pub struct Ciphertext<PCT: InnerCiphertext> {
    vk: VerifyingKey,
    bibe_ct: PCT,
    #[serde(with = "serde_bytes")]
    associated_data_bytes: Vec<u8>,
    signature: Signature,
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
