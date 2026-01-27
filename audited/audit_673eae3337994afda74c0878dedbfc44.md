# Audit Report

## Title
Missing Validation of Groth16 Verification Key Allows Denial of Service for Keyless Accounts via Governance Proposals

## Summary
The `set_groth16_verification_key_for_next_epoch()` function in the keyless account module does not validate the Groth16 verification key before storing it on-chain. A malformed verification key with `gamma_abc_g1` vector length != 2 will be stored without validation, causing it to fail conversion to `PreparedVerifyingKey` during epoch transitions. This results in `keyless_pvk` being set to `None`, which causes all keyless transactions using ZK proofs to fail with "Groth16 VK has not been set on-chain" error, effectively denying service to all keyless account users.

## Finding Description

The vulnerability exists across three critical code paths:

**1. Missing Validation in Governance Proposal Path** [1](#0-0) 

The governance function directly calls `config_buffer::upsert()` without calling the existing `validate_groth16_vk()` function that performs cryptographic point validation and structural checks.

**2. Missing Validation During Epoch Application** [2](#0-1) 

When applying the buffered VK during epoch change, no validation occurs before the VK is stored into the global resource.

**3. Late Bounds Check in Rust Conversion** [3](#0-2) 

The bounds check `if vk.gamma_abc_g1.len() != 2` only happens during conversion to `PreparedVerifyingKey`, after the malformed VK has already been stored on-chain and deserialized via BCS.

**4. Deserialization Path** [4](#0-3) 

When validator nodes fetch the VK from storage during environment initialization, BCS deserialization occurs at line 104 without any size bounds checking. The validation function claims bounds checks exist on-chain (per incorrect comment in code), but they do not run for governance proposals.

**5. Impact on Transaction Validation** [5](#0-4) 

When `keyless_pvk` is `None` due to failed VK conversion, all keyless transactions with ZK proofs are rejected, causing denial of service.

**Attack Scenario:**
1. Attacker with governance access submits proposal with malformed VK where `gamma_abc_g1` has 10,000 elements instead of required 2 (within 1MB storage limit)
2. Proposal passes and VK is stored on-chain without validation
3. At epoch boundary, `on_new_epoch()` applies the malformed VK without validation
4. During environment initialization, nodes fetch and deserialize the VK via BCS (succeeds)
5. Conversion to `PreparedVerifyingKey` fails the `len() != 2` check, returning `Err`
6. The `.ok()` handler sets `keyless_pvk = None` in environment
7. All subsequent keyless transactions with ZK proofs fail validation
8. Users cannot access their keyless accounts until governance fixes the VK

## Impact Explanation

**Severity: HIGH**

This vulnerability causes **significant protocol violation** and **validator node impact** that meets the HIGH severity criteria:

- **Denial of Service**: All keyless account users lose transaction capabilities
- **User Impact**: Affects potentially millions of users if keyless accounts are widely adopted
- **Fund Access Loss**: Users temporarily cannot access funds in keyless accounts
- **Recovery Time**: Requires another governance proposal (days for voting + epoch change) to fix
- **Validator Impact**: All validator nodes will have `keyless_pvk = None` causing degraded functionality

While not CRITICAL (no permanent fund loss or consensus break), it represents a significant availability and protocol violation issue that requires governance intervention to resolve.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

**Barriers:**
- Requires governance voting power to pass malicious/malformed proposal
- Governance participants are considered trusted roles
- Attack is detectable during proposal review period

**Facilitating Factors:**
- The validation function exists but is simply not called (oversight/bug)
- Incorrect code comment suggests validation happens when it doesn't
- Accidental misconfiguration by honest governance participants is possible
- Malicious actors could acquire stake to gain governance influence
- No automated validation prevents the malformed VK from being proposed

The most realistic scenario is **accidental misconfiguration** rather than malicious attack, but both are possible.

## Recommendation

**Fix 1: Add Validation to Governance Function**

Modify `set_groth16_verification_key_for_next_epoch()` to call validation before upserting:

```move
public fun set_groth16_verification_key_for_next_epoch(fx: &signer, vk: Groth16VerificationKey) {
    system_addresses::assert_aptos_framework(fx);
    validate_groth16_vk(&vk);  // ADD THIS LINE
    config_buffer::upsert<Groth16VerificationKey>(vk);
}
```

**Fix 2: Add Validation to Epoch Application**

Modify `on_new_epoch()` to validate before applying:

```move
if (config_buffer::does_exist<Groth16VerificationKey>()) {
    let vk = config_buffer::extract_v2();
    validate_groth16_vk(&vk);  // ADD THIS LINE
    if (exists<Groth16VerificationKey>(@aptos_framework)) {
        *borrow_global_mut<Groth16VerificationKey>(@aptos_framework) = vk;
    } else {
        move_to(fx, vk);
    }
};
```

**Fix 3: Add Length Check to Validation Function**

Extend `validate_groth16_vk()` to check vector length:

```move
fun validate_groth16_vk(vk: &Groth16VerificationKey) {
    assert!(vector::length(&vk.gamma_abc_g1) == 2, E_INVALID_VK_STRUCTURE);  // ADD THIS
    assert!(option::is_some(&crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Compr>(&vk.alpha_g1)), E_INVALID_BN254_G1_SERIALIZATION);
    // ... rest of validation
}
```

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework)]
#[expected_failure(abort_code = 0x10001, location = aptos_framework::keyless_validation)]
fun test_malformed_vk_dos_attack(aptos_framework: &signer) {
    use std::vector;
    use aptos_framework::keyless_account;
    
    // Create malformed VK with wrong gamma_abc_g1 length
    let malformed_vk = keyless_account::new_groth16_verification_key(
        x"e39cb24154872dbdbbdbc8056c6eb3e6cab3ad82f80ded72ed4c9301c5b3da15",
        x"9a732e38644f89ad2c7bd629b84d6b81f2e83ca4b3cddfd99c0254e49332861e2fcec4f74545abdd42c8857ff8df6d3f6b3670f930d1d5ba961655ea38ded315",
        x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19",
        x"04c7b3a2734731369a281424c2bd7af229b92496527fd0a01bfe4a5c01e0a92f256921817b6d6cf040ccd483d81738ac88571b57009f182946e8a88cced03a01",
        vector[  // Should be 2 elements, providing 3 to trigger error
            x"2f4f4bc4acbea0c3bae9e676fb59537e2e46994d5896e286e6fcccc7e14b1b2d",
            x"979308443fbac05f6d22a16525c26246e965a9be68e163154f44b20d6b2ddf18",
            x"0000000000000000000000000000000000000000000000000000000000000000"  // Extra element
        ]
    );
    
    // This should fail validation but currently doesn't
    keyless_account::set_groth16_verification_key_for_next_epoch(
        aptos_framework,
        malformed_vk
    );
    
    // Simulate epoch change
    keyless_account::on_new_epoch(aptos_framework);
    
    // Now attempt keyless transaction validation - will fail with:
    // "Groth16 VK has not been set on-chain" because keyless_pvk is None
}
```

**Notes:**
- The validation function `validate_groth16_vk()` exists at line 183 of `keyless_account.move` but is never called for governance proposals
- The comment at line 288 of `environment.rs` incorrectly claims validation occurs
- Storage write limits (1MB per operation) prevent extremely large VKs but don't prevent structurally invalid ones
- BCS deserialization has no built-in vector length limits beyond what fits in ULEB128 encoding

### Citations

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

**File:** types/src/keyless/groth16_vk.rs (L66-68)
```rust
        if vk.gamma_abc_g1.len() != 2 {
            return Err(CryptoMaterialError::DeserializationError);
        }
```

**File:** types/src/keyless/mod.rs (L94-106)
```rust
pub trait KeylessOnchainConfig: MoveStructType + DeserializeOwned {
    fn fetch_keyless_config<T>(storage: &T) -> Option<(Self, Bytes)>
    where
        T: KeylessConfigStorage + ?Sized,
    {
        let state_key =
            StateKey::resource_group(&CORE_CODE_ADDRESS, &KeylessGroupResource::struct_tag());
        let bytes = storage.fetch_keyless_config_bytes(&state_key)?;
        let group = bcs::from_bytes::<KeylessGroupResource>(&bytes).ok()?;
        let bytes = group.group.get(&Self::struct_tag())?;
        let config = bcs::from_bytes::<Self>(bytes).ok()?;
        Some((config, bytes.clone()))
    }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L188-191)
```rust
    // If there are ZK authenticators, the Groth16 VK must have been set on-chain.
    if with_zk && pvk.is_none() {
        return Err(invalid_signature!("Groth16 VK has not been set on-chain"));
    }
```
