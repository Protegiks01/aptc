# Audit Report

## Title
Missing Beta_G2 Validation in Groth16 Verification Key Enables Soundness Break in Keyless Authentication

## Summary
The `beta_g2` component of the Groth16 verification key is not validated to be non-zero when set on-chain. A zero/identity `beta_g2` would trivialize the Groth16 verification equation, completely breaking the soundness of keyless account authentication and enabling theft of all keyless account funds. While a validation function exists, it is never called, and even if called, would not detect zero points.

## Finding Description

The Groth16 verification key for keyless accounts contains critical cryptographic parameters including `beta_g2`. The verification equation requires:

`e(A, B) = e(α, β) + e(L, γ) + e(C, δ)`

If `beta_g2` is the identity/zero point, then `e(α, β) = 1` (identity in target group), reducing the equation to:

`e(A, B) = e(L, γ) + e(C, δ)`

This removes one critical term from the verification, fundamentally breaking the soundness of the zero-knowledge proof system.

**Critical Flaw #1: Validation Function Never Called**

A validation function exists but is never invoked: [1](#0-0) 

Neither VK-setting function calls this validation: [2](#0-1) [3](#0-2) 

**Critical Flaw #2: Insufficient Validation Even If Called**

The validation function only checks if points can be deserialized, not if they are non-zero. Arkworks explicitly accepts zero/identity points as valid: [4](#0-3) 

**Rust-Side Assumption Violated**

The Rust deserialization code assumes Move validation occurred, which is false: [5](#0-4) 

**Developer Acknowledgment of Risk**

The developers explicitly documented this threat: [6](#0-5) 

## Impact Explanation

**Severity: Critical (Loss of Funds)**

If a verification key with zero `beta_g2` is set through governance (maliciously, accidentally, or via compromised governance):

1. **Complete Authentication Bypass**: Attackers can forge Groth16 proofs satisfying the weakened equation
2. **Universal Account Compromise**: ALL keyless accounts become vulnerable simultaneously  
3. **Fund Theft**: Attackers can impersonate any keyless account holder and drain funds
4. **Irreversible Without Hard Fork**: Requires governance action and epoch change to fix

This meets Critical Severity criteria: "Loss of Funds (theft or minting)" from the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: Low (requires governance access)**

This vulnerability requires governance-level access to exploit through:
- Malicious governance proposal
- Compromised governance participant keys
- Accidental misconfiguration during legitimate VK update

However, the **missing security control** makes accidental misconfiguration highly likely:
- No validation prevents human error
- Complex cryptographic parameters are easy to misconfigure
- Warning exists but no enforcement mechanism

The fact that the validation function was written but never called suggests this is an **implementation oversight** rather than intentional design.

## Recommendation

**Immediate Fix: Call Validation Function**

Add validation call to both VK-setting functions:

```move
public fun update_groth16_verification_key(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    chain_status::assert_genesis();
    validate_groth16_vk(&vk);  // ADD THIS LINE
    move_to(fx, vk);
}

public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    validate_groth16_vk(&vk);  // ADD THIS LINE
    config_buffer::upsert<Groth16VerificationKey>(vk);
}
```

**Enhanced Fix: Add Non-Zero Validation**

Extend `validate_groth16_vk` to explicitly check points are non-zero:

```move
fun validate_groth16_vk(vk: &Groth16VerificationKey) {
    // Existing deserialization checks
    let alpha_opt = crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(&vk.alpha_g1);
    assert!(option::is_some(&alpha_opt), E_INVALID_BN254_G1_SERIALIZATION);
    
    let beta_opt = crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.beta_g2);
    assert!(option::is_some(&beta_opt), E_INVALID_BN254_G2_SERIALIZATION);
    
    // NEW: Check beta_g2 is not identity/zero
    let beta = option::extract(&mut beta_opt);
    let zero_g2 = crypto_algebra::zero<bn254_algebra::G2>();
    assert!(!crypto_algebra::eq(&beta, &zero_g2), E_ZERO_BETA_G2_NOT_ALLOWED);
    
    // Repeat for gamma_g2, delta_g2, alpha_g1, gamma_abc_g1
}
```

## Proof of Concept

**Step 1: Create Malicious VK with Zero Beta_G2**

```rust
use ark_bn254::G2Affine;
use ark_serialize::CanonicalSerialize;

// Create identity point for beta_g2
let zero_beta_g2 = G2Affine::zero();
let mut beta_bytes = vec![];
zero_beta_g2.serialize_compressed(&mut beta_bytes).unwrap();

// Create Groth16VerificationKey with zero beta_g2
let malicious_vk = Groth16VerificationKey {
    alpha_g1: valid_alpha_bytes,
    beta_g2: beta_bytes,  // IDENTITY POINT
    gamma_g2: valid_gamma_bytes,
    delta_g2: valid_delta_bytes,
    gamma_abc_g1: valid_gamma_abc_bytes,
};
```

**Step 2: Governance Proposal Sets Malicious VK**

```move
script {
    use aptos_framework::keyless_account;
    use aptos_framework::aptos_governance;
    
    fun malicious_vk_update(core_resources: &signer) {
        let framework_signer = aptos_governance::get_signer_testnet_only(core_resources, @0x1);
        
        // Create VK with zero beta_g2 - NO VALIDATION OCCURS
        let malicious_vk = keyless_account::new_groth16_verification_key(
            x"...", // alpha_g1
            x"...", // beta_g2 = IDENTITY POINT
            x"...", // gamma_g2
            x"...", // delta_g2
            vector[x"...", x"..."] // gamma_abc_g1
        );
        
        keyless_account::set_groth16_verification_key_for_next_epoch(&framework_signer, malicious_vk);
        aptos_governance::force_end_epoch(&framework_signer);
    }
}
```

**Step 3: Forge Proofs**

After malicious VK is active, attackers can forge proofs satisfying the reduced equation `e(A, B) = e(L, γ) + e(C, δ)`, bypassing keyless authentication.

## Notes

This vulnerability represents a **defense-in-depth failure** rather than a direct exploit vector for unprivileged attackers. The validation function's existence indicates developer intent to protect against this threat, but the implementation is incomplete. While exploitation requires governance access (privileged role), the missing validation creates a critical single point of failure that should be hardened against accidental misconfiguration, compromised governance, or software bugs in VK generation code.

The cryptographic correctness invariant is violated: elliptic curve points in verification keys must be validated as non-identity to maintain proof system soundness.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L183-192)
```text
    fun validate_groth16_vk(vk: &Groth16VerificationKey) {
        // Could be leveraged to speed up the VM deserialization of the VK by 2x, since it can assume the points are valid.
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(&vk.alpha_g1)), E_INVALID_BN254_G1_SERIALIZATION);
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.beta_g2)), E_INVALID_BN254_G2_SERIALIZATION);
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.gamma_g2)), E_INVALID_BN254_G2_SERIALIZATION);
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.delta_g2)), E_INVALID_BN254_G2_SERIALIZATION);
        for (i in 0..vector::length(&vk.gamma_abc_g1)) {
            assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(vector::borrow(&vk.gamma_abc_g1, i))), E_INVALID_BN254_G1_SERIALIZATION);
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L198-203)
```text
    public fun update_groth16_verification_key(fx: &signer, vk: Groth16VerificationKey) {
        system_addresses::assert_aptos_framework(fx);
        chain_status::assert_genesis();
        // There should not be a previous resource set here.
        move_to(fx, vk);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L262-262)
```text
    /// WARNING: If a malicious key is set, this would lead to stolen funds.
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L263-266)
```text
    public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
        system_addresses::assert_aptos_framework(fx);
        config_buffer::upsert<Groth16VerificationKey>(vk);
    }
```

**File:** crates/aptos-crypto/src/arkworks/serialization.rs (L88-107)
```rust
    #[test]
    fn test_g2_serialization_multiple_points() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct A(#[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G2Affine);

        let mut points = vec![G2Affine::zero()]; // Include zero
        let mut g = G2Projective::generator();

        for _ in 0..MAX_DOUBLINGS {
            points.push(g.into());
            g += g; // double for next
        }

        for p in points {
            let serialized = bcs::to_bytes(&A(p)).expect("Serialization failed");
            let deserialized: A = bcs::from_bytes(&serialized).expect("Deserialization failed");

            assert_eq!(deserialized.0, p, "G2 point round-trip failed for {:?}", p);
        }
    }
```

**File:** types/src/keyless/groth16_vk.rs (L70-78)
```rust
        // NOTE: Technically, we already validate the points when we set the VK in Move, so we could
        // make this 2x faster by avoiding the point validation checks  via
        // `deserialize_with_mode(..., Compress::Yes, Validate::No)`. Due to paranoia, will not
        // optimize this for now.
        Ok(Self::from(VerifyingKey {
            alpha_g1: G1Affine::deserialize_compressed(vk.alpha_g1.as_slice())
                .map_err(|_| CryptoMaterialError::DeserializationError)?,
            beta_g2: G2Affine::deserialize_compressed(vk.beta_g2.as_slice())
                .map_err(|_| CryptoMaterialError::DeserializationError)?,
```
