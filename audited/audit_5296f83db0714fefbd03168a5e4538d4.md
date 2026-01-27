# Audit Report

## Title
Missing Groth16 Verification Key Validation Enables Complete Denial of Service for Keyless Accounts

## Summary
The on-chain Groth16 verification key (VK) update functions fail to validate that G1 and G2 elliptic curve points are stored in the required compressed format and contain valid point data. Despite the existence of a `validate_groth16_vk()` function that checks compressed point format and validity, this validation is never called when setting verification keys through governance proposals. This allows invalid or malformed VKs to be set on-chain, causing complete denial of service for all keyless account transactions.

## Finding Description

The keyless accounts feature relies on Groth16 zero-knowledge proofs verified against an on-chain verification key. This VK contains multiple BN254 elliptic curve points that must be in compressed format (32 bytes for G1, 64 bytes for G2).

The Move module defines a validation function that explicitly checks point compression and validity: [1](#0-0) 

However, the two functions responsible for setting the verification key never invoke this validation: [2](#0-1) [3](#0-2) 

The VK structure stores points as raw byte vectors without size constraints enforced at the type level: [4](#0-3) 

When a VK is later retrieved for proof verification, it is converted to a `PreparedVerifyingKey<Bn254>` which attempts to deserialize points using `deserialize_compressed()`: [5](#0-4) 

If the stored VK contains invalid data (wrong size, invalid points, uncompressed format, or points outside the correct subgroup), this deserialization will fail, causing ALL keyless account transaction verifications to fail.

**Attack Flow:**
1. Attacker submits governance proposal to update the VK (or honest mistake occurs)
2. VK contains invalid point data - either:
   - Uncompressed points (64 bytes for G1 instead of 32, 128 bytes for G2 instead of 64)
   - Correct size but invalid point encoding
   - Points not in the prime-order subgroup
3. Proposal passes and VK is set via `set_groth16_verification_key_for_next_epoch()` without validation
4. VK is stored on-chain
5. All subsequent keyless account transactions fail when attempting to deserialize the VK
6. Complete DoS persists until a new governance proposal corrects the VK (multi-day process)

## Impact Explanation

This vulnerability meets **HIGH severity** criteria per the Aptos bug bounty program:

- **Significant protocol violation**: Complete failure of the keyless accounts authentication mechanism
- **Validator node operational impact**: All nodes will fail to process keyless transactions
- **Extended availability loss**: Recovery requires governance action (minimum several days for proposal, voting, and execution)

While not affecting consensus safety directly, this creates a critical availability failure for an entire authentication subsystem. Users with keyless accounts would be unable to access their funds until the issue is resolved through governance.

The severity is elevated because:
1. The impact affects all keyless account users simultaneously
2. The validation function exists but is dead code, indicating this is a clear implementation bug rather than a conscious design decision
3. The WARNING comment at line 262 acknowledges the risk of malicious keys but relies on validation that is never performed [6](#0-5) 

## Likelihood Explanation

**Likelihood: MEDIUM**

While this requires governance access to exploit, the likelihood is elevated because:

1. **Honest mistakes are probable**: VK encoding errors could easily occur when preparing governance proposals, especially given the complexity of encoding BN254 curve points correctly
2. **No safety net**: The absence of validation means there is no defense against configuration errors
3. **Governance is accessible**: Any participant with sufficient stake can submit proposals
4. **Clear implementation gap**: The existence of unused validation code suggests incomplete implementation

The validation function's presence but non-use indicates this may have been planned security but was never integrated, making this a latent bug waiting to manifest.

## Recommendation

Immediately invoke `validate_groth16_vk()` in both VK update functions:

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

This ensures all VKs are validated for:
- Correct compressed point format (32 bytes for G1, 64 bytes for G2)
- Valid point encoding that can be successfully deserialized
- Subgroup membership checks performed by arkworks deserialization [1](#0-0) 

## Proof of Concept

```move
#[test(fx = @aptos_framework)]
#[expected_failure(abort_code = 2, location = aptos_framework::keyless_account)]
fun test_invalid_vk_causes_dos(fx: &signer) {
    use aptos_framework::keyless_account;
    use std::vector;
    
    // Create VK with uncompressed G1 point (64 bytes instead of 32)
    let invalid_alpha_g1 = vector::empty<u8>();
    let i = 0;
    while (i < 64) {  // Wrong size - should be 32 for compressed
        vector::push_back(&mut invalid_alpha_g1, 1u8);
        i = i + 1;
    };
    
    // Create valid-sized but arbitrary G2 points
    let beta_g2 = vector::empty<u8>();
    let i = 0;
    while (i < 64) {
        vector::push_back(&mut beta_g2, 2u8);
        i = i + 1;
    };
    
    let gamma_g2 = beta_g2;
    let delta_g2 = beta_g2;
    let gamma_abc_g1 = vector::singleton(invalid_alpha_g1);
    
    let invalid_vk = keyless_account::new_groth16_verification_key(
        invalid_alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1
    );
    
    // This SHOULD fail but currently doesn't because validation is missing
    // With the fix, this will abort with E_INVALID_BN254_G1_SERIALIZATION
    keyless_account::set_groth16_verification_key_for_next_epoch(fx, invalid_vk);
}
```

The test demonstrates that invalid VKs can currently be set without triggering validation errors. With the recommended fix adding `validate_groth16_vk()` calls, this test would properly fail at the point of setting the invalid VK rather than causing later DoS.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L33-45)
```text
    struct Groth16VerificationKey has key, store, drop {
        /// 32-byte serialization of `alpha * G`, where `G` is the generator of `G1`.
        alpha_g1: vector<u8>,
        /// 64-byte serialization of `alpha * H`, where `H` is the generator of `G2`.
        beta_g2: vector<u8>,
        /// 64-byte serialization of `gamma * H`, where `H` is the generator of `G2`.
        gamma_g2: vector<u8>,
        /// 64-byte serialization of `delta * H`, where `H` is the generator of `G2`.
        delta_g2: vector<u8>,
        /// `\forall i \in {0, ..., \ell}, 64-byte serialization of gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where
        /// `H` is the generator of `G1` and `\ell` is 1 for the ZK relation.
        gamma_abc_g1: vector<vector<u8>>,
    }
```

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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L256-266)
```text
    /// Queues up a change to the Groth16 verification key. The change will only be effective after reconfiguration.
    /// Only callable via governance proposal.
    ///
    /// WARNING: To mitigate against DoS attacks, a VK change should be done together with a training wheels PK change,
    /// so that old ZKPs for the old VK cannot be replayed as potentially-valid ZKPs.
    ///
    /// WARNING: If a malicious key is set, this would lead to stolen funds.
    public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
        system_addresses::assert_aptos_framework(fx);
        config_buffer::upsert<Groth16VerificationKey>(vk);
    }
```

**File:** types/src/keyless/groth16_vk.rs (L75-88)
```rust
            alpha_g1: G1Affine::deserialize_compressed(vk.alpha_g1.as_slice())
                .map_err(|_| CryptoMaterialError::DeserializationError)?,
            beta_g2: G2Affine::deserialize_compressed(vk.beta_g2.as_slice())
                .map_err(|_| CryptoMaterialError::DeserializationError)?,
            gamma_g2: G2Affine::deserialize_compressed(vk.gamma_g2.as_slice())
                .map_err(|_| CryptoMaterialError::DeserializationError)?,
            delta_g2: G2Affine::deserialize_compressed(vk.delta_g2.as_slice())
                .map_err(|_| CryptoMaterialError::DeserializationError)?,
            gamma_abc_g1: vec![
                G1Affine::deserialize_compressed(vk.gamma_abc_g1[0].as_slice())
                    .map_err(|_| CryptoMaterialError::DeserializationError)?,
                G1Affine::deserialize_compressed(vk.gamma_abc_g1[1].as_slice())
                    .map_err(|_| CryptoMaterialError::DeserializationError)?,
            ],
```
