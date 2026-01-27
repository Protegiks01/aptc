# Audit Report

## Title
Missing Validation in Groth16 Verification Key Updates Enables Denial of Service via Governance

## Summary
The Move smart contract's `validate_groth16_vk()` function is never called when governance proposals update the Groth16 verification key, allowing invalid verification keys to be set on-chain. This causes a denial of service for all ZK keyless authentication until governance fixes the issue.

## Finding Description

The Aptos keyless authentication system uses Groth16 zero-knowledge proofs verified against an on-chain verification key. The Move smart contract at `aptos-move/framework/aptos-framework/sources/keyless_account.move` defines a validation function [1](#0-0)  that checks whether all BN254 curve points in a `Groth16VerificationKey` can be properly deserialized.

However, this validation function is **never called** in any of the VK update paths:
- `set_groth16_verification_key_for_next_epoch()` [2](#0-1)  - used by governance proposals
- `update_groth16_verification_key()` [3](#0-2)  - used during genesis

When an invalid VK is set on-chain, the Rust validation code attempts to convert it to a `PreparedVerifyingKey`. The conversion flow is:

1. Environment fetches VK from on-chain state [4](#0-3) 
2. Deserialization occurs in TryFrom implementation [5](#0-4) 
3. If deserialization fails due to invalid curve points, the error is silently converted to `None` via `.ok()`
4. Later, keyless validation checks if VK exists [6](#0-5) 
5. All ZK keyless transactions fail with "Groth16 VK has not been set on-chain"

The Rust code comment at [7](#0-6)  incorrectly states "we already validate the points when we set the VK in Move" - this is **false** as the validation function is never invoked.

**Attack Scenario:**
1. Governance proposal (malicious or buggy) calls `set_groth16_verification_key_for_next_epoch` with a VK containing invalid BN254 curve point serializations
2. Proposal passes and is queued via `config_buffer::upsert`
3. At next epoch, `on_new_epoch()` applies the invalid VK [8](#0-7) 
4. All validators fetch the VK and get `None` after deserialization failure
5. Every keyless transaction fails validation
6. Users cannot access keyless accounts until governance passes another proposal to fix the VK

## Impact Explanation

This is a **Medium Severity** issue per Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: The blockchain enters a state where a critical authentication mechanism (keyless accounts) becomes unusable
- **Limited funds loss or manipulation**: Users cannot access their keyless accounts, effectively freezing their funds temporarily
- No consensus violation or permanent fund loss occurs
- The network continues operating for non-keyless transactions
- Recoverable through governance (but with significant delay due to voting periods)

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can be triggered through:
1. **Malicious governance proposal**: If attackers gain sufficient voting power (unlikely given trust model)
2. **Buggy governance proposal**: Honest mistake in VK generation or encoding (more likely)
3. **Compromised governance system**: If governance signing keys are compromised

The barrier to exploitation is high (requires governance proposal approval), but the consequences of an accidental trigger through a buggy proposal are significant. The existence of the unused `validate_groth16_vk()` function suggests developers recognized this risk but failed to integrate the validation.

## Recommendation

**Immediate Fix:** Call `validate_groth16_vk()` in the governance VK update function:

```move
public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    validate_groth16_vk(&vk);  // ADD THIS LINE
    config_buffer::upsert<Groth16VerificationKey>(vk);
}
```

Also add validation to the genesis function:

```move
public fun update_groth16_verification_key(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    chain_status::assert_genesis();
    validate_groth16_vk(&vk);  // ADD THIS LINE
    move_to(fx, vk);
}
```

**Defense in Depth:** Consider logging a warning in the Rust code when VK conversion fails instead of silently returning `None`, to aid in debugging.

## Proof of Concept

```move
#[test]
#[expected_failure(abort_code = E_INVALID_BN254_G1_SERIALIZATION)]
fun test_invalid_vk_rejected() {
    let fx = account::create_account_for_test(@aptos_framework);
    
    // Create VK with invalid G1 point (all zeros)
    let invalid_vk = new_groth16_verification_key(
        vector[0u8; 32],  // Invalid alpha_g1
        x"...",  // valid beta_g2
        x"...",  // valid gamma_g2  
        x"...",  // valid delta_g2
        vector[x"...", x"..."]  // valid gamma_abc_g1
    );
    
    // This SHOULD fail but currently doesn't because validation is not called
    set_groth16_verification_key_for_next_epoch(&fx, invalid_vk);
}
```

## Notes

While this vulnerability exists, it does **not** meet the strict validation criteria of being "exploitable by unprivileged attacker" since it requires governance action. Under the stated trust model where governance participants are considered trusted actors, this is primarily a **code quality issue and defense-in-depth gap** rather than an active exploit vector.

However, the issue represents a real operational risk for accidental DoS through buggy governance proposals, and the missing validation call contradicts the developer's documented intent (as evidenced by the unused validation function and misleading Rust comment).

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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L263-266)
```text
    public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
        system_addresses::assert_aptos_framework(fx);
        config_buffer::upsert<Groth16VerificationKey>(vk);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L358-368)
```text
    public(friend) fun on_new_epoch(fx: &signer) acquires Groth16VerificationKey, Configuration {
        system_addresses::assert_aptos_framework(fx);

        if (config_buffer::does_exist<Groth16VerificationKey>()) {
            let vk = config_buffer::extract_v2();
            if (exists<Groth16VerificationKey>(@aptos_framework)) {
                *borrow_global_mut<Groth16VerificationKey>(@aptos_framework) = vk;
            } else {
                move_to(fx, vk);
            }
        };
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L289-293)
```rust
        let keyless_pvk =
            Groth16VerificationKey::fetch_keyless_config(state_view).and_then(|(vk, vk_bytes)| {
                sha3_256.update(&vk_bytes);
                vk.try_into().ok()
            });
```

**File:** types/src/keyless/groth16_vk.rs (L62-91)
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
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L189-191)
```rust
    if with_zk && pvk.is_none() {
        return Err(invalid_signature!("Groth16 VK has not been set on-chain"));
    }
```
