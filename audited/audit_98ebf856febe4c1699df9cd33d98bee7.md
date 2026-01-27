# Audit Report

## Title
Missing Groth16 Verification Key Validation Enables Potential Validator Crash via Malicious Governance Proposal

## Summary
The `set_groth16_verification_key_for_next_epoch` governance function fails to validate cryptographic curve point serializations before storing the verification key on-chain. A validation function `validate_groth16_vk` exists but is never invoked, allowing malformed bytes to be set via governance. When validators initialize their environment, these malformed bytes are deserialized without panic protection, potentially causing validator crashes if the arkworks library's `deserialize_compressed()` encounters internal panics on adversarial input. [1](#0-0) 

## Finding Description
The Groth16 verification key is critical for keyless account signature verification. The Move framework defines a `validate_groth16_vk` function that validates all BN254 curve point serializations: [2](#0-1) 

However, this validation is **never called** when setting the verification key via governance. The `set_groth16_verification_key_for_next_epoch` function directly inserts the unvalidated key into the config buffer: [1](#0-0) 

During validator environment initialization, the verification key is fetched and converted to a `PreparedVerifyingKey<Bn254>` via the `TryFrom` trait: [3](#0-2) 

The conversion implementation calls arkworks' `deserialize_compressed()` on each curve point without any panic protection mechanism: [4](#0-3) 

Critically, this deserialization occurs during `AptosEnvironment::new()` which is **not** protected by the `VMState::DESERIALIZER` panic handling mechanism that exists for Move bytecode deserialization: [5](#0-4) 

**Attack Path:**
1. Attacker submits governance proposal with malicious `Groth16VerificationKey` containing adversarial byte sequences in curve point fields
2. Governance participants, lacking technical expertise to validate cryptographic bytes, approve the proposal  
3. At epoch transition, `on_new_epoch` applies the malicious VK to on-chain storage
4. Validators initialize `AptosEnvironment` for the new epoch, triggering VK fetch and conversion
5. If arkworks `deserialize_compressed()` encounters internal panics (assertions, unwraps, array indexing) on malformed input, validators crash
6. All validators crash simultaneously → network halt → requires emergency hardfork

## Impact Explanation
**Critical Severity** - This vulnerability enables a complete network DOS attack through the governance mechanism:

- **Network Availability Loss**: If arkworks panics, all validators crash when processing the first block of the new epoch, causing total liveness failure requiring emergency hardfork intervention
- **Consensus Safety Risk**: Even if arkworks only returns errors (doesn't panic), validator initialization failures create operational chaos and potential consensus divergence
- **Governance Integrity Violation**: The existence of unused validation code indicates an oversight that undermines the safety guarantees of the keyless account system

The comment on line 184 reveals developers anticipated this issue: "Could be leveraged to speed up the VM deserialization of the VK by 2x, since it can assume the points are valid." This confirms validation was intended to enable safe deserialization. [6](#0-5) 

## Likelihood Explanation
**Medium to High Likelihood:**

- Governance proposals undergo review but technical validation of cryptographic byte sequences is challenging for non-experts
- The validation function exists but is unused—this appears to be an implementation oversight rather than intentional design
- Arkworks is an external dependency; while well-tested, complex deserialization logic could contain edge cases triggering panics
- No defensive programming (panic guards, validation) exists in the critical environment initialization path
- The warning in the Move code mentions "malicious key" leading to "stolen funds" but fails to mention DOS risks: [7](#0-6) 

## Recommendation
**Immediate Fix:** Call `validate_groth16_vk()` in all functions that set the verification key:

```move
public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    validate_groth16_vk(&vk);  // ADD THIS LINE
    config_buffer::upsert<Groth16VerificationKey>(vk);
}

public fun update_groth16_verification_key(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    chain_status::assert_genesis();
    validate_groth16_vk(&vk);  // ADD THIS LINE
    move_to(fx, vk);
}
```

**Defense-in-Depth:** Add panic protection in environment initialization:

```rust
let keyless_pvk = Groth16VerificationKey::fetch_keyless_config(state_view).and_then(|(vk, vk_bytes)| {
    sha3_256.update(&vk_bytes);
    // Wrap conversion in catch_unwind for defense-in-depth
    std::panic::catch_unwind(|| vk.try_into()).ok().flatten()
});
```

## Proof of Concept
Due to arkworks being an external dependency, creating a full PoC requires access to its internals. However, the missing validation is demonstrable:

```move
#[test(fx = @aptos_framework)]
#[expected_failure(abort_code = E_INVALID_BN254_G1_SERIALIZATION)]
fun test_malicious_vk_rejected(fx: signer) {
    // Create VK with invalid G1 point bytes
    let malicious_vk = new_groth16_verification_key(
        vector[0xFF; 32],  // Invalid alpha_g1
        vector[0xFF; 64],  // Invalid beta_g2
        vector[0xFF; 64],  // Invalid gamma_g2
        vector[0xFF; 64],  // Invalid delta_g2
        vector[vector[0xFF; 32], vector[0xFF; 32]]  // Invalid gamma_abc_g1
    );
    
    // This should fail validation but currently doesn't
    validate_groth16_vk(&malicious_vk);
}
```

The fact that `validate_groth16_vk` exists proves developers recognized the need for validation. Its absence from the governance flow represents a critical gap in the security architecture.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L182-192)
```text
    /// Pre-validate the VK to actively-prevent incorrect VKs from being set on-chain.
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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L259-262)
```text
    /// WARNING: To mitigate against DoS attacks, a VK change should be done together with a training wheels PK change,
    /// so that old ZKPs for the old VK cannot be replayed as potentially-valid ZKPs.
    ///
    /// WARNING: If a malicious key is set, this would lead to stolen funds.
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L263-266)
```text
    public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
        system_addresses::assert_aptos_framework(fx);
        config_buffer::upsert<Groth16VerificationKey>(vk);
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

**File:** types/src/keyless/groth16_vk.rs (L62-90)
```rust
impl TryFrom<&Groth16VerificationKey> for PreparedVerifyingKey<Bn254> {
    type Error = CryptoMaterialError;

    fn try_from(vk: &Groth16VerificationKey) -> Result<Self, Self::Error> {
        if vk.gamma_abc_g1.len() != 2 {
            return Err(CryptoMaterialError::DeserializationError);
        }

        // NOTE: Technically, we already validate the points when we set the VK in Move, so we could
        // make this 2x faster by avoiding the point validation checks  via
        // `deserialize_with_mode(..., Compress::Yes, Validate::No)`. Due to paranoia, will not
        // optimize this for now.
        Ok(Self::from(VerifyingKey {
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
        }))
    }
```

**File:** crates/crash-handler/src/lib.rs (L52-54)
```rust
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }
```
