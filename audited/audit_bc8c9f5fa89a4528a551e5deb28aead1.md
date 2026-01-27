# Audit Report

## Title
Supply Chain Dependency Trust Without Validation in Chunky PVSS Hash-to-Curve Implementation

## Summary
The `unsafe_hash_to_affine()` function in Aptos cryptographic primitives relies entirely on the sha3 crate for hash-to-curve operations without any validation mechanisms. If the sha3 dependency were compromised through a supply chain attack, weak cryptographic generators would be used in the batch encryption PVSS protocol without detection, breaking encrypted transaction confidentiality.

## Finding Description

The `unsafe_hash_to_affine()` function uses the sha3 crate's `Sha3_512::digest()` to hash messages to elliptic curve points: [1](#0-0) 

This function is used to generate critical cryptographic parameters in the chunky PVSS protocol:

1. **Generator G for ElGamal encryption**: [2](#0-1) 

2. **Commitment base G_2**: [3](#0-2) 

These public parameters are used in the FPTXWeighted batch encryption scheme deployed in consensus: [4](#0-3) 

The batch encryption is integrated into the consensus pipeline for decrypting encrypted transactions: [5](#0-4) 

**Critical Vulnerability: No Validation**

The `PublicParameters` struct has a `Valid::check()` implementation that performs zero validation: [6](#0-5) 

**Attack Scenario:**

If an attacker compromises the sha3 crate through supply chain attack (e.g., malicious crates.io upload, compromised maintainer account, or build-time dependency substitution), they could:

1. Modify `Sha3_512::digest()` to return attacker-controlled outputs
2. Generate curve points G and G_2 with known discrete logarithm relationships
3. All validators would deterministically compute identical compromised generators from the same DST values
4. No validation would detect the weak generators
5. Attacker could decrypt all encrypted transactions using knowledge of the discrete log relationships

## Impact Explanation

**Severity: High**

This constitutes a **significant protocol violation** under the High severity category because:

- **Transaction Confidentiality Breach**: Encrypted transactions in blocks could be decrypted by attackers who know the discrete log relationships, violating privacy guarantees
- **Silent Failure**: No detection mechanism exists - the network would continue operating with compromised cryptography
- **Network-Wide Impact**: All validators using the compromised dependency would be affected simultaneously
- **Deterministic Exploitation**: Since all nodes use the same DST and seed values, all would generate identical compromised parameters

While this doesn't reach Critical severity (no direct fund theft, consensus safety violation, or network halt), it breaks a core security property (encrypted transaction confidentiality) and affects the entire network.

## Likelihood Explanation

**Likelihood: Low to Medium**

Prerequisites for exploitation:
- **Supply chain compromise** of the sha3 crate (requires significant attacker capability)
- **Absence of code review** during dependency updates
- **Lack of reproducible build verification** in deployment pipelines

While supply chain attacks are challenging, they are not theoretical:
- Multiple real-world supply chain attacks on Rust crates have occurred
- The dependency trust model has no defense-in-depth
- No runtime validation provides a detection opportunity

## Recommendation

Implement defense-in-depth validation for hash-to-curve outputs:

```rust
impl<E: Pairing> Valid for PublicParameters<E> {
    fn check(&self) -> Result<(), SerializationError> {
        // Validate that G is on the curve and in the correct subgroup
        if !self.pp_elgamal.G.is_on_curve() {
            return Err(SerializationError::InvalidData);
        }
        
        // Validate that G_2 is on the curve and in the correct subgroup
        if !self.G_2.is_on_curve() {
            return Err(SerializationError::InvalidData);
        }
        
        // Verify G and G_2 are not identity elements
        if self.pp_elgamal.G.is_zero() || self.G_2.is_zero() {
            return Err(SerializationError::InvalidData);
        }
        
        // For critical deployments: hardcode known-good generator values
        // and verify hash-to-curve outputs match them
        const EXPECTED_G: &str = "..."; // hex-encoded expected value
        // Compare self.pp_elgamal.G against EXPECTED_G
        
        Ok(())
    }
}
```

Additional recommendations:
1. **Pin dependency versions** and use lock files with hash verification
2. **Implement reproducible builds** to detect binary tampering
3. **Use cargo-vet or cargo-crev** for dependency auditing
4. **Consider dual-hash verification**: use both sha3 and a secondary hash function, comparing results
5. **Runtime assertion**: add checks in `unsafe_hash_to_affine()` that validate point properties before returning

## Proof of Concept

The following demonstrates that no validation occurs when creating public parameters:

```rust
#[test]
fn test_no_validation_on_public_parameters() {
    use crate::pvss::chunky::public_parameters::PublicParameters;
    use ark_bls12_381::Bls12_381;
    use ark_serialize::Valid;
    
    // Create public parameters that would use compromised hash-to-curve
    let pp = PublicParameters::<Bls12_381>::default();
    
    // This succeeds even though we have no guarantees about the
    // cryptographic properties of the generators
    assert!(pp.check().is_ok());
    
    // No validation of:
    // - Whether generators are properly distributed
    // - Whether discrete log relationships exist
    // - Whether points have correct order
    // - Whether outputs match expected values
    
    println!("Public parameters accepted without any validation");
}
```

**Note**: A full exploit PoC would require actually compromising the sha3 crate, which is beyond the scope of this report and ethically inappropriate. The vulnerability exists in the *absence of detection*, not in the ability to compromise sha3 itself.

### Citations

**File:** crates/aptos-crypto/src/arkworks/hashing.rs (L41-41)
```rust
        let hashed = sha3::Sha3_512::digest(&buf);
```

**File:** crates/aptos-dkg/src/pvss/chunky/chunked_elgamal.rs (L78-78)
```rust
        let G = hashing::unsafe_hash_to_affine(b"G", DST);
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L120-124)
```rust
impl<E: Pairing> Valid for PublicParameters<E> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
```

**File:** crates/aptos-dkg/src/pvss/chunky/public_parameters.rs (L184-184)
```rust
            G_2: hashing::unsafe_hash_to_affine(b"G_2", DST),
```

**File:** crates/aptos-batch-encryption/src/schemes/fptx_weighted.rs (L225-225)
```rust
    type SubTranscript = aptos_dkg::pvss::chunky::WeightedSubtranscript<Pairing>;
```

**File:** consensus/src/pipeline/decryption_pipeline_builder.rs (L103-103)
```rust
        let derived_key_share = FPTXWeighted::derive_decryption_key_share(&msk_share, &digest)?;
```
