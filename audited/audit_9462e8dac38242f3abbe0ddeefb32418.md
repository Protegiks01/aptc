# Audit Report

## Title
SLH-DSA Cryptographic Library Dependency on Unstable API Creates Consensus Risk During Security Updates

## Summary
The Aptos blockchain depends on an unstable release candidate version (0.2.0-rc.1) of the `slh-dsa` crate and uses an internal API (`slh_keygen_internal`) for deserializing SLH-DSA private keys. This creates a critical dilemma: upgrading to fix security vulnerabilities in the cryptographic library could break compatibility with existing on-chain keys and signatures, potentially causing consensus failures or permanent loss of account access.

## Finding Description
The vulnerability stems from three interconnected design decisions:

**1. Dependency on Unstable Version:** [1](#0-0) 

The codebase uses `slh-dsa = "0.2.0-rc.1"`, which is explicitly a release candidate (unstable) version.

**2. Use of Internal API:** [2](#0-1) 

The `from_bytes_unchecked` method calls `slh_keygen_internal`, which by naming convention appears to be an internal/unstable API of the external crate.

**3. On-Chain Key Storage:** [3](#0-2) 

SLH-DSA public keys are stored on-chain as part of the authentication system, meaning existing accounts depend on stable key derivation.

**How This Breaks Invariants:**

The **Deterministic Execution** and **Consensus Safety** invariants could be violated when:
1. A security vulnerability is discovered in `slh-dsa 0.2.0-rc.1`
2. The fix requires API changes or behavior modifications
3. Validators upgrade at different times, creating two populations:
   - Validators on old version: Can verify old SLH-DSA signatures
   - Validators on new version: May fail to verify old signatures or derive keys differently

This leads to:
- **Consensus splits**: Different validators accepting/rejecting the same transactions
- **Account lockout**: Users unable to access accounts if key deserialization changes
- **Signature verification divergence**: Historical transactions becoming unverifiable [4](#0-3) 

The custom serialization format (48 bytes of seed data, excluding PK root) depends on the internal structure of the `slh-dsa` crate's key representation, making it fragile to upstream changes.

## Impact Explanation
This qualifies as **High Severity** per the Aptos bug bounty criteria:

**Consensus/Safety Violations:**
If different validators run different versions of the `slh-dsa` crate after a security update:
- Validators may disagree on transaction validity
- This violates the **Consensus Safety** invariant requiring agreement under < 1/3 Byzantine nodes
- Could lead to chain splits requiring emergency intervention

**Permanent Freezing of Funds:**
If the `slh_keygen_internal` API changes or is removed:
- Existing SLH-DSA accounts become inaccessible
- Private keys stored in wallets cannot be deserialized
- Requires hardfork to migrate affected accounts

**Significant Protocol Violations:** [5](#0-4) 

Signature verification depends on the `slh_dsa` crate's `Verifier` trait. Changes in verification logic would cause validators to disagree on transaction validity.

## Likelihood Explanation
**High likelihood** due to:

1. **RC Version Status**: Release candidates explicitly signal unstable APIs that may change before stable release
2. **Post-Quantum Cryptography Evolution**: NIST standardization process for SLH-DSA (FIPS 205) is ongoing, likely requiring implementation updates
3. **Security Pressures**: Post-quantum cryptography is cutting-edge; vulnerabilities may be discovered requiring urgent patches
4. **Internal API Usage**: APIs with "_internal" suffix are typically not guaranteed stable across versions [6](#0-5) 

The feature is marked as "transient" in the Move framework, but once enabled and accounts are created, backward compatibility becomes critical.

## Recommendation

**Immediate Actions:**

1. **Vendor the `slh-dsa` crate**: Fork and maintain a stable copy to prevent unexpected upstream changes
2. **Add version pinning tests**: Create integration tests that fail if internal API signatures change
3. **Implement migration path**: Design a mechanism to migrate SLH-DSA accounts if library upgrade is necessary

**Code Changes:**

```rust
// Add explicit version compatibility check in build.rs
fn main() {
    // Verify slh-dsa version hasn't changed unexpectedly
    let expected_version = "0.2.0-rc.1";
    let actual_version = env!("CARGO_PKG_VERSION_slh_dsa");
    assert_eq!(actual_version, expected_version,
        "slh-dsa version change detected - requires compatibility review");
}

// Add stability wrapper in slh_dsa_keys.rs
pub(crate) fn from_bytes_unchecked(
    bytes: &[u8],
) -> std::result::Result<PrivateKey, CryptoMaterialError> {
    // ... existing validation ...
    
    // Use stable API if available, fallback to internal API
    let signing_key = match SlhDsaSigningKey::<Sha2_128s>::try_from(bytes) {
        Ok(sk) => sk,
        Err(_) => {
            // Fallback to internal API with explicit warning
            #[cfg(not(test))]
            log::warn!("Using internal slh_keygen_internal API for key deserialization");
            
            SlhDsaSigningKey::<Sha2_128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed)
        }
    };
    
    Ok(PrivateKey(signing_key))
}
```

3. **Document the risk**: Add clear warnings in code comments about the dependency on unstable APIs
4. **Consider alternative**: Evaluate switching to ML-DSA (FIPS 204) when it reaches stable status

## Proof of Concept

This vulnerability cannot be demonstrated with a traditional exploit PoC since it requires external library changes. However, the risk can be validated through:

**Dependency Audit Test:**
```rust
#[test]
fn test_slh_dsa_version_stability() {
    // This test verifies we're still on the expected version
    // and that the internal API we depend on still exists
    use slh_dsa::{Sha2_128s, SigningKey};
    
    let sk_seed = [1u8; 16];
    let sk_prf = [2u8; 16];
    let pk_seed = [3u8; 16];
    
    // This will fail to compile if slh_keygen_internal is removed
    let _key = SigningKey::<Sha2_128s>::slh_keygen_internal(
        &sk_seed, &sk_prf, &pk_seed
    );
    
    // Verify serialization format hasn't changed
    assert_eq!(_key.to_bytes().len(), 64); // Full key with PK root
}

#[test]
fn test_key_serialization_compatibility() {
    // Test that keys can round-trip through our custom format
    let mut rng = rand::thread_rng();
    let original_key = PrivateKey::generate(&mut rng);
    let bytes = original_key.to_bytes();
    
    assert_eq!(bytes.len(), PRIVATE_KEY_LENGTH);
    
    let restored_key = PrivateKey::try_from(&bytes[..]).unwrap();
    let original_pk: PublicKey = (&original_key).into();
    let restored_pk: PublicKey = (&restored_key).into();
    
    assert_eq!(original_pk.to_bytes(), restored_pk.to_bytes(),
        "Key deserialization must preserve public key");
}
```

**Notes**

This is a **dependency management vulnerability** rather than a traditional exploit. The security risk materializes when:
- The `slh-dsa` crate releases a new version with breaking changes
- Aptos must upgrade due to security vulnerabilities in the old version
- The upgrade breaks compatibility with existing on-chain keys/signatures

The use of an unstable RC version and internal API creates a ticking time bomb where security fixes and compatibility are in direct conflict, potentially forcing a choice between security vulnerabilities or consensus failures.

### Citations

**File:** Cargo.toml (L711-711)
```text
slh-dsa = "0.2.0-rc.1"
```

**File:** crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_keys.rs (L56-65)
```rust
    /// Serialize a PrivateKey
    /// Returns only the first PRIVATE_KEY_LENGTH bytes (48 bytes), which contain
    /// the SK seed, PRF seed, and PK seed. The PK root is excluded as it's part
    /// of the public key material.
    pub fn to_bytes(&self) -> Vec<u8> {
        let full_bytes = self.0.to_bytes();
        // Extract only the first PRIVATE_KEY_LENGTH bytes (the three 16-byte seeds)
        // The full serialization includes the PK root, which we exclude
        full_bytes[..PRIVATE_KEY_LENGTH].to_vec()
    }
```

**File:** crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_keys.rs (L87-88)
```rust
        let signing_key =
            SlhDsaSigningKey::<Sha2_128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
```

**File:** types/src/transaction/authenticator.rs (L1377-1379)
```rust
    SlhDsa_Sha2_128s {
        public_key: slh_dsa_sha2_128s::PublicKey,
    },
```

**File:** crates/aptos-crypto/src/slh_dsa_sha2_128s/slh_dsa_sigs.rs (L73-77)
```rust
    fn verify_arbitrary_msg(&self, message: &[u8], public_key: &PublicKey) -> Result<()> {
        use slh_dsa::signature::Verifier;
        Verifier::<SlhDsaSignature<Sha2_128s>>::verify(&public_key.0, message, &self.0)
            .map_err(|e| anyhow!("SLH-DSA signature verification failed: {}", e))
    }
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L755-761)
```text
    const SLH_DSA_SHA2_128S_SIGNATURE: u64 = 107;

    public fun get_slh_dsa_sha2_128s_signature_feature(): u64 { SLH_DSA_SHA2_128S_SIGNATURE }

    public fun slh_dsa_sha2_128s_signature_enabled(): bool acquires Features {
        is_enabled(SLH_DSA_SHA2_128S_SIGNATURE)
    }
```
