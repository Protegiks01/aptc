# Audit Report

## Title
MultiEd25519 Signature Malleability via Bitmap Manipulation with Duplicate Public Keys

## Summary
The MultiEd25519 signature verification implementation allows signature malleability when an account is initialized with duplicate public keys. An attacker can modify the bitmap field while keeping the same signatures, creating a different valid signature for the same message with a different transaction hash. This breaks the fundamental assumption that valid signatures have unique canonical representations.

## Finding Description

The vulnerability exists in the `MultiEd25519PublicKey::new()` constructor which does not validate that public keys are unique. [1](#0-0) 

Combined with the bitmap-based signature verification mechanism, this allows an attacker to craft multiple valid signatures for the same transaction: [2](#0-1) 

**Attack Scenario:**

1. **Setup Phase**: Attacker creates a MultiEd25519 account with duplicate public keys:
   - `public_keys: [pk_A, pk_B, pk_A, pk_B]` (alternating duplicates)
   - `threshold: 2`

2. **Original Transaction**: Create a valid transaction with:
   - `signatures: [sig_A, sig_B]` (signatures from sk_A and sk_B)
   - `bitmap: 0b11000000...` (positions 0 and 1 set)
   - Transaction hash: `H1`

3. **Malleability Attack**: Without access to any private keys, modify the signature:
   - Keep `signatures: [sig_A, sig_B]` (exact same signatures, same order)
   - Change `bitmap: 0b00110000...` (positions 2 and 3 set)
   - New transaction hash: `H2 ≠ H1`

4. **Verification**: The verification logic processes signatures sequentially based on bitmap bits. For the malleable version:
   - bitmap_index iterates to position 2 (first set bit)
   - Verifies `sig_A` against `public_keys[2] = pk_A` ✓ (passes because pk_A is duplicated)
   - bitmap_index moves to position 3 (second set bit)
   - Verifies `sig_B` against `public_keys[3] = pk_B` ✓ (passes because pk_B is duplicated)
   - Threshold check: 2 signatures ≥ threshold 2 ✓

Both signatures verify successfully despite having different bitmaps and transaction hashes.

**Propagation Path:**
- Transaction submission (JSON or BCS) → Mempool → Consensus → Execution
- The mempool uses `committed_hash()` for deduplication [3](#0-2) 
- Different hashes mean the same logical transaction appears as different transactions to mempool and consensus

## Impact Explanation

**Critical Severity** - This vulnerability breaks multiple critical invariants:

1. **Consensus Safety Violation**: Different validators could include different versions of the malleable transaction in their blocks, potentially causing state divergence if the transactions interact with state in timing-dependent ways.

2. **Transaction Uniqueness Violation**: The fundamental assumption that a valid transaction signature has a unique canonical representation is broken. This affects:
   - Hash-based deduplication in mempool and consensus
   - Transaction tracking and audit systems
   - SPV proofs and light client verification

3. **Resource Exhaustion**: Attacker can flood mempool with multiple valid versions of the same transaction, each with different hashes, bypassing hash-based deduplication.

4. **Deterministic Execution Risk**: If different nodes process different versions of the malleable transaction at different times due to network timing, it could lead to non-deterministic state transitions.

Per Aptos Bug Bounty criteria, this qualifies as **Critical Severity** due to potential consensus/safety violations and protocol integrity breaches.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Create a MultiEd25519 account with carefully arranged duplicate public keys
- No private key compromise needed
- No validator access required

**Attack Complexity:**
- Simple bitmap modification (no cryptographic operations needed)
- Can be automated once account is set up
- Works deterministically

**Barriers:**
- Requires attacker to control account creation with specific duplicate key pattern
- Most users would not intentionally create accounts with duplicate keys
- However, nothing in the protocol prevents this setup

The vulnerability is highly exploitable once the precondition (duplicate keys) is met, but the precondition itself requires deliberate setup by the attacker.

## Recommendation

**Fix 1: Validate Public Key Uniqueness** (Recommended)

Add validation in `MultiEd25519PublicKey::new()` to reject duplicate keys:

```rust
pub fn new(
    public_keys: Vec<Ed25519PublicKey>,
    threshold: u8,
) -> std::result::Result<Self, CryptoMaterialError> {
    let num_of_public_keys = public_keys.len();
    if threshold == 0 || num_of_public_keys < threshold as usize {
        Err(CryptoMaterialError::ValidationError)
    } else if num_of_public_keys > MAX_NUM_OF_KEYS {
        Err(CryptoMaterialError::WrongLengthError)
    } else {
        // Check for duplicate public keys
        let mut unique_keys = std::collections::HashSet::new();
        for key in &public_keys {
            if !unique_keys.insert(key.to_bytes()) {
                return Err(CryptoMaterialError::ValidationError);
            }
        }
        Ok(MultiEd25519PublicKey {
            public_keys,
            threshold,
        })
    }
}
```

**Fix 2: Enforce Canonical Bitmap Encoding**

Require that signatures use the smallest possible bitmap positions, rejecting any signature that doesn't use the canonical encoding.

**Additional Hardening:**
- Add validation in API types to check for duplicate keys [4](#0-3) 
- Update account creation Move functions to reject duplicate keys
- Add migration logic for existing accounts with duplicate keys

## Proof of Concept

```rust
#[cfg(test)]
mod signature_malleability_poc {
    use super::*;
    use crate::ed25519::Ed25519PrivateKey;
    use crate::multi_ed25519::{MultiEd25519PrivateKey, MultiEd25519PublicKey, MultiEd25519Signature};
    use crate::traits::*;
    
    #[test]
    fn test_signature_malleability_with_duplicate_keys() {
        // Generate two distinct key pairs
        let sk_a = Ed25519PrivateKey::generate_for_testing();
        let pk_a = sk_a.public_key();
        let sk_b = Ed25519PrivateKey::generate_for_testing();
        let pk_b = sk_b.public_key();
        
        // Create MultiEd25519PublicKey with duplicate keys: [pk_A, pk_B, pk_A, pk_B]
        let public_keys_with_duplicates = vec![
            pk_a.clone(), pk_b.clone(), pk_a.clone(), pk_b.clone()
        ];
        let multi_pub_key = MultiEd25519PublicKey::new(
            public_keys_with_duplicates, 
            2
        ).unwrap();
        
        // Sign a message with positions 0 and 1
        let message = b"test message";
        let sig_a = sk_a.sign_arbitrary_message(message);
        let sig_b = sk_b.sign_arbitrary_message(message);
        
        // Create original signature with bitmap positions 0 and 1
        let original_bitmap = [0b11000000u8, 0u8, 0u8, 0u8];
        let original_sig = MultiEd25519Signature::new_with_signatures_and_bitmap(
            vec![sig_a.clone(), sig_b.clone()],
            original_bitmap
        );
        
        // Verify original signature passes
        assert!(original_sig.verify_arbitrary_msg(message, &multi_pub_key).is_ok());
        
        // Create malleable signature with same signatures but bitmap positions 2 and 3
        let malleable_bitmap = [0b00110000u8, 0u8, 0u8, 0u8];
        let malleable_sig = MultiEd25519Signature::new_with_signatures_and_bitmap(
            vec![sig_a, sig_b],
            malleable_bitmap
        );
        
        // Verify malleable signature ALSO passes (this is the bug!)
        assert!(malleable_sig.verify_arbitrary_msg(message, &multi_pub_key).is_ok());
        
        // Both signatures are valid but have different serializations
        let original_bytes = original_sig.to_bytes();
        let malleable_bytes = malleable_sig.to_bytes();
        assert_ne!(original_bytes, malleable_bytes, 
            "Signatures should have different byte representations");
        
        // This means they would have different transaction hashes
        println!("VULNERABILITY CONFIRMED:");
        println!("Original bitmap:   {:08b}", original_bitmap[0]);
        println!("Malleable bitmap:  {:08b}", malleable_bitmap[0]);
        println!("Both signatures verify successfully for the same message!");
    }
}
```

## Notes

The core issue stems from two design decisions:
1. Allowing duplicate public keys in `MultiEd25519PublicKey` without validation
2. Using bitmap position to map signatures to public keys during verification

While duplicate keys might seem like an unlikely setup, nothing in the protocol prevents it, and the security of the system should not rely on users avoiding this configuration. The fix should enforce uniqueness at the cryptographic layer to prevent this entire class of malleability attacks.

### Citations

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L82-103)
```rust
impl MultiEd25519PublicKey {
    /// Construct a new MultiEd25519PublicKey.
    /// --- Rules ---
    /// a) threshold cannot be zero.
    /// b) public_keys.len() should be equal to or larger than threshold.
    /// c) support up to MAX_NUM_OF_KEYS public keys.
    pub fn new(
        public_keys: Vec<Ed25519PublicKey>,
        threshold: u8,
    ) -> std::result::Result<Self, CryptoMaterialError> {
        let num_of_public_keys = public_keys.len();
        if threshold == 0 || num_of_public_keys < threshold as usize {
            Err(CryptoMaterialError::ValidationError)
        } else if num_of_public_keys > MAX_NUM_OF_KEYS {
            Err(CryptoMaterialError::WrongLengthError)
        } else {
            Ok(MultiEd25519PublicKey {
                public_keys,
                threshold,
            })
        }
    }
```

**File:** crates/aptos-crypto/src/multi_ed25519.rs (L511-558)
```rust
    fn verify_arbitrary_msg(
        &self,
        message: &[u8],
        public_key: &MultiEd25519PublicKey,
    ) -> Result<()> {
        // NOTE: Public keys need not be validated because we use ed25519_dalek's verify_strict,
        // which checks for small order public keys.
        match bitmap_last_set_bit(self.bitmap) {
            Some(last_bit) if (last_bit as usize) < public_key.public_keys.len() => (),
            _ => {
                return Err(anyhow!(
                    "{}",
                    CryptoMaterialError::BitVecError("Signature index is out of range".to_string())
                ))
            },
        };
        let num_ones_in_bitmap = bitmap_count_ones(self.bitmap);
        if num_ones_in_bitmap < public_key.threshold as u32 {
            return Err(anyhow!(
                "{}",
                CryptoMaterialError::BitVecError(
                    "Not enough signatures to meet the threshold".to_string()
                )
            ));
        }
        if num_ones_in_bitmap != self.signatures.len() as u32 {
            return Err(anyhow!(
                "{}",
                CryptoMaterialError::BitVecError(
                    "Bitmap ones and signatures count are not equal".to_string()
                )
            ));
        }
        let mut bitmap_index = 0;
        // TODO: Eventually switch to deterministic batch verification
        for sig in &self.signatures {
            while !bitmap_get_bit(self.bitmap, bitmap_index) {
                bitmap_index += 1;
            }
            let pk = public_key
                .public_keys
                .get(bitmap_index)
                .ok_or_else(|| anyhow::anyhow!("Public key index {bitmap_index} out of bounds"))?;
            sig.verify_arbitrary_msg(message, pk)?;
            bitmap_index += 1;
        }
        Ok(())
    }
```

**File:** mempool/src/core_mempool/index.rs (L156-164)
```rust
    fn make_key(&self, txn: &MempoolTransaction) -> OrderedQueueKey {
        OrderedQueueKey {
            gas_ranking_score: txn.ranking_score,
            expiration_time: txn.expiration_time,
            insertion_time: txn.insertion_info.insertion_time,
            address: txn.get_sender(),
            replay_protector: txn.get_replay_protector(),
            hash: txn.get_committed_hash(),
        }
```

**File:** api/types/src/transaction.rs (L1325-1371)
```rust
impl VerifyInput for MultiEd25519Signature {
    fn verify(&self) -> anyhow::Result<()> {
        if self.public_keys.is_empty() {
            bail!("MultiEd25519 signature has no public keys")
        } else if self.signatures.is_empty() {
            bail!("MultiEd25519 signature has no signatures")
        } else if self.public_keys.len() > MAX_NUM_OF_KEYS {
            bail!(
                "MultiEd25519 signature has over the maximum number of public keys {}",
                MAX_NUM_OF_KEYS
            )
        } else if self.signatures.len() > MAX_NUM_OF_SIGS {
            bail!(
                "MultiEd25519 signature has over the maximum number of signatures {}",
                MAX_NUM_OF_SIGS
            )
        } else if self.public_keys.len() != self.signatures.len() {
            bail!(
                "MultiEd25519 signature does not have the same number of signatures as public keys"
            )
        } else if self.signatures.len() < self.threshold as usize {
            bail!("MultiEd25519 signature does not have enough signatures to pass the threshold")
        } else if self.threshold == 0 {
            bail!("MultiEd25519 signature threshold must be greater than 0")
        }
        for signature in self.signatures.iter() {
            if signature.inner().len() != ED25519_SIGNATURE_LENGTH {
                bail!("MultiEd25519 signature has a signature with the wrong signature length")
            }
        }
        for public_key in self.public_keys.iter() {
            if public_key.inner().len() != ED25519_PUBLIC_KEY_LENGTH {
                bail!("MultiEd25519 signature has a public key with the wrong public key length")
            }
        }

        if self.bitmap.inner().len() != BITMAP_NUM_OF_BYTES {
            bail!(
                "MultiEd25519 signature has an invalid number of bitmap bytes {} expected {}",
                self.bitmap.inner().len(),
                BITMAP_NUM_OF_BYTES
            );
        }

        Ok(())
    }
}
```
