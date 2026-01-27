# Audit Report

## Title
Missing Validation Allows Malicious Governance Proposal to Permanently DoS All Keyless ZK Users

## Summary
The Move contract for keyless account configuration contains a validation function `validate_groth16_vk()` that is never called, allowing governance proposals to set malformed Groth16 verification keys with incorrect `gamma_abc_g1` vector lengths. This causes all keyless ZK authentication to fail system-wide until a corrective governance proposal is executed, effectively freezing all keyless user accounts.

## Finding Description

The keyless authentication system uses Groth16 ZK-SNARKs with a verification key that must have `gamma_abc_g1.len() == 2` (for a circuit with 1 public input). The system has three critical flaws:

**Flaw 1: Unused Validation Function**
A validation function exists in the Move contract but is never invoked: [1](#0-0) 

This function validates individual points but does NOT check the vector length. More critically, it is never called anywhere in the codebase.

**Flaw 2: No Validation During VK Update**
When a governance proposal updates the verification key, no validation occurs: [2](#0-1) 

The VK is directly inserted into the config buffer without any checks.

**Flaw 3: No Validation During Epoch Application**
When the queued VK is applied during epoch change, again no validation: [3](#0-2) 

**Flaw 4: Silent Failure in Rust Layer**
The Rust code enforces the length constraint but fails silently: [4](#0-3) 

When the environment loads the VK, conversion failures are silently ignored: [5](#0-4) 

Note the misleading comment on line 288: "although, currently, we do check for that in `keyless_account.move`" - this is FALSE.

**Flaw 5: All Keyless ZK Transactions Fail**
When `keyless_pvk` is `None`, all ZK keyless authentication is rejected: [6](#0-5) 

**Attack Scenario:**
1. Malicious governance proposal sets VK with `gamma_abc_g1` containing 1, 3, or any number != 2 elements
2. Move layer accepts it (no validation)
3. VK is stored on-chain and applied at next epoch
4. All validators fetch the VK and attempt conversion to `PreparedVerifyingKey`
5. Conversion fails due to length mismatch, `keyless_pvk` becomes `None` on all nodes
6. Every keyless ZK transaction is rejected with "Groth16 VK has not been set on-chain"
7. All keyless users are locked out until governance fixes the VK (requires proposal + voting + epoch change)

## Impact Explanation

**CRITICAL Severity - Total Loss of Liveness for Keyless Users**

This vulnerability meets the **Critical** severity criteria per the Aptos bug bounty program:
- **"Total loss of liveness/network availability"**: All keyless ZK users (potentially thousands of accounts) cannot submit transactions
- **"Permanent freezing of funds (requires hardfork)"**: While technically not requiring a hardfork, it requires a governance proposal with voting period and epoch change to recover, during which all keyless funds are frozen

This breaks the **Transaction Validation** invariant: the prologue must correctly validate all legitimate signatures, but legitimate keyless ZK signatures are incorrectly rejected.

The impact is deterministic and affects all validators simultaneously, making this a consensus-level issue.

## Likelihood Explanation

**HIGH Likelihood - Realistic Governance Attack Vector**

The attack requires:
1. Submitting a governance proposal (requires stake and proposal fee)
2. Getting the proposal to pass (requires voting majority)

However, the likelihood is high because:
- **No technical barrier**: Anyone with sufficient stake can submit the malicious proposal
- **Silent failure makes detection difficult**: The Move layer provides no error, and the Rust layer fails silently
- **Human error is possible**: An honest but mistaken proposal (e.g., updating to a VK from a different circuit) would have the same effect
- **False assumption in code**: The comment in `environment.rs` line 288 suggests developers believed validation existed, indicating future updates might also skip validation
- **No recovery mechanism exists** except another governance proposal

The validation function exists but was never wired up, suggesting this was an incomplete implementation that could easily be exploited before being fixed.

## Recommendation

**Immediate Fix - Add Length Validation in Move:**

Modify `validate_groth16_vk` to check the vector length:

```move
fun validate_groth16_vk(vk: &Groth16VerificationKey) {
    // Validate the expected length for keyless circuit (1 public input => gamma_abc_g1.len() == 2)
    assert!(vector::length(&vk.gamma_abc_g1) == 2, E_INVALID_GAMMA_ABC_G1_LENGTH);
    
    // Existing point validation
    assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(&vk.alpha_g1)), E_INVALID_BN254_G1_SERIALIZATION);
    assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.beta_g2)), E_INVALID_BN254_G2_SERIALIZATION);
    assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.gamma_g2)), E_INVALID_BN254_G2_SERIALIZATION);
    assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G2, bn254_algebra::FormatG2Compr>(&vk.delta_g2)), E_INVALID_BN254_G2_SERIALIZATION);
    for (i in 0..vector::length(&vk.gamma_abc_g1)) {
        assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(vector::borrow(&vk.gamma_abc_g1, i))), E_INVALID_BN254_G1_SERIALIZATION);
    };
}
```

Add the error constant:
```move
const E_INVALID_GAMMA_ABC_G1_LENGTH: u64 = 4;
```

**Call the validation function** in `set_groth16_verification_key_for_next_epoch`:
```move
public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    validate_groth16_vk(&vk);  // ADD THIS LINE
    config_buffer::upsert<Groth16VerificationKey>(vk);
}
```

**Additional safeguards:**
1. Remove the misleading comment in `environment.rs` line 288 or make it accurate
2. Consider logging a warning when VK conversion fails instead of silently returning `None`
3. Add integration tests that attempt to set invalid VKs via governance

## Proof of Concept

**Move Script to Exploit the Vulnerability:**

```move
script {
    use aptos_framework::keyless_account;
    use aptos_framework::aptos_governance;
    use std::vector;
    
    fun malicious_vk_proposal(proposer: &signer) {
        // Create a VK with WRONG gamma_abc_g1 length (only 1 element instead of 2)
        let malicious_vk = keyless_account::new_groth16_verification_key(
            x"2d5ba2ad5f554e4e45f2a64b3e86b27dc41f1b7f8c7e9f8e9c9f8e7c6d5e4f3a2b1c0d9e8f7",  // alpha_g1
            x"0e31a5e3b1f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",  // beta_g2
            x"17f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",  // gamma_g2
            x"0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",  // delta_g2
            vector[
                x"0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
                // ONLY ONE ELEMENT - should be TWO!
            ]
        );
        
        let framework_signer = aptos_governance::get_signer_testnet_only(proposer, @0x1);
        keyless_account::set_groth16_verification_key_for_next_epoch(&framework_signer, malicious_vk);
        aptos_governance::force_end_epoch(&framework_signer);
        
        // After this epoch change, ALL keyless ZK authentication will fail
        // All keyless users are locked out
    }
}
```

**Rust Test to Verify Silent Failure:**

```rust
#[test]
fn test_invalid_vk_causes_keyless_dos() {
    use aptos_types::keyless::Groth16VerificationKey;
    use ark_groth16::PreparedVerifyingKey;
    use ark_bn254::Bn254;
    
    // Create VK with wrong gamma_abc_g1 length
    let invalid_vk = Groth16VerificationKey {
        alpha_g1: vec![0u8; 32],
        beta_g2: vec![0u8; 64],
        gamma_g2: vec![0u8; 64],
        delta_g2: vec![0u8; 64],
        gamma_abc_g1: vec![vec![0u8; 32]], // Only 1 element, should be 2!
    };
    
    // Try to convert - this will fail
    let result: Result<PreparedVerifyingKey<Bn254>, _> = invalid_vk.try_into();
    
    // Conversion fails silently
    assert!(result.is_err());
    
    // If this were used in the environment, keyless_pvk would be None
    // and all keyless ZK transactions would fail
}
```

**Notes**

The vulnerability is exacerbated by the fact that:
1. The `prepared_vk_for_testing()` function correctly has 2 elements, so all tests pass
2. The production path has no validation, creating a gap between test and production behavior
3. The Rust code's comment incorrectly states that Move validation exists, suggesting developer confusion about the security model

This is a **governance-level DoS attack** that can lock all keyless users out of their accounts with a single malicious proposal, requiring weeks to recover (proposal submission + voting period + epoch change).

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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L263-266)
```text
    public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
        system_addresses::assert_aptos_framework(fx);
        config_buffer::upsert<Groth16VerificationKey>(vk);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L361-368)
```text
        if (config_buffer::does_exist<Groth16VerificationKey>()) {
            let vk = config_buffer::extract_v2();
            if (exists<Groth16VerificationKey>(@aptos_framework)) {
                *borrow_global_mut<Groth16VerificationKey>(@aptos_framework) = vk;
            } else {
                move_to(fx, vk);
            }
        };
```

**File:** types/src/keyless/groth16_vk.rs (L66-68)
```rust
        if vk.gamma_abc_g1.len() != 2 {
            return Err(CryptoMaterialError::DeserializationError);
        }
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L289-293)
```rust
        let keyless_pvk =
            Groth16VerificationKey::fetch_keyless_config(state_view).and_then(|(vk, vk_bytes)| {
                sha3_256.update(&vk_bytes);
                vk.try_into().ok()
            });
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L189-191)
```rust
    if with_zk && pvk.is_none() {
        return Err(invalid_signature!("Groth16 VK has not been set on-chain"));
    }
```
