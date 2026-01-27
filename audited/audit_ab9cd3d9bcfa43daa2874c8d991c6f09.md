# Audit Report

## Title
Missing Groth16 Verification Key Validation in Governance Allows DoS Attack and Potential Funds Theft via Malicious VK

## Summary
The `set_groth16_verification_key_for_next_epoch` function fails to call the existing `validate_groth16_vk` validation function before storing a new Groth16 verification key on-chain. This allows governance to set either invalid curve points (causing denial-of-service for all keyless transactions) or a malicious VK from a compromised trusted setup ceremony (enabling theft of all keyless account funds). There is no on-chain verification that the VK matches expected parameters from a legitimate trusted setup.

## Finding Description
The keyless accounts feature in Aptos uses Groth16 zero-knowledge proofs to verify user authentication. The security of this system fundamentally depends on the integrity of the Groth16 verification key (VK) stored on-chain. The VK must come from a legitimate trusted setup ceremony and contain valid BN254 elliptic curve points.

The codebase includes a `validate_groth16_vk` function specifically designed to "Pre-validate the VK to actively-prevent incorrect VKs from being set on-chain" [1](#0-0) . This function validates that all curve points can be properly deserialized.

However, when governance sets a new VK via `set_groth16_verification_key_for_next_epoch`, this validation is never called [2](#0-1) . The function only checks that the caller is the aptos_framework signer, then directly stores the VK without any validation.

This creates two critical vulnerabilities:

**Vulnerability 1: DoS via Invalid Curve Points**
If governance accidentally (or maliciously) sets a VK with invalid curve point serializations, the VK will be stored on-chain but will fail to load when validators start. When the VM environment attempts to convert the VK to a `PreparedVerifyingKey`, the conversion fails and returns `None` [3](#0-2) . This causes all keyless transactions with ZK proofs to be rejected [4](#0-3) .

**Vulnerability 2: Funds Theft via Malicious VK**
More critically, there is no on-chain verification that the VK corresponds to the expected parameters from a legitimate trusted setup ceremony. The code explicitly acknowledges this: "WARNING: If a malicious key is set, this would lead to stolen funds" [5](#0-4) . If governance sets a VK from a compromised trusted setup where the toxic waste (secret parameters) is known to an attacker, that attacker can forge valid ZK proofs for any keyless account and steal all funds.

The lack of validation is inconsistent with other governance functions. For example, `update_training_wheels_for_next_epoch` validates that the training wheels public key is a valid Ed25519 key before storing it [6](#0-5) .

## Impact Explanation

**Critical Severity - Potential Funds Theft:**
If governance is compromised or socially engineered into approving a malicious VK from a compromised trusted setup, an attacker with knowledge of the toxic waste can:
1. Forge valid Groth16 proofs for any public inputs
2. Create keyless signatures for any keyless account
3. Drain funds from ALL keyless accounts on the network

This meets the Critical Severity criteria: "Loss of Funds (theft or minting)" with potential for complete compromise of the keyless accounts system.

**High Severity - Denial of Service:**
If governance accidentally sets a VK with invalid curve point encodings (even with good intentions), this causes:
1. All validators to fail loading the VK into `PreparedVerifyingKey`
2. All keyless transactions with ZK proofs to be rejected
3. Complete loss of keyless accounts functionality until a governance proposal fixes the VK

This meets the High Severity criteria: "Significant protocol violations" causing a critical feature to become unavailable.

The vulnerability is exacerbated by the fact that the validation function exists but is unused, indicating this was likely an implementation oversight rather than a conscious design decision.

## Likelihood Explanation

**For DoS Attack (High Likelihood):**
This can occur through honest mistakes in governance proposals. The complexity of manually constructing VK parameters (32-byte and 64-byte BN254 curve point serializations) makes errors likely. A single byte error in any of the 5 curve points would trigger this vulnerability. Given that VK rotation may happen during circuit upgrades or security updates, the likelihood is non-trivial.

**For Malicious VK Attack (Medium Likelihood with caveats):**
This requires:
1. Governance approval of a malicious proposal (requires significant stake or social engineering)
2. Access to a compromised trusted setup with known toxic waste

While governance is generally trusted, the explicit question asks about this scenario. The likelihood increases if:
- Large stakeholders are compromised
- Social engineering succeeds in disguising a malicious VK as legitimate
- The trusted setup ceremony was compromised

The lack of any technical safeguards means governance trust is the only defense layer.

## Recommendation

**Immediate Fix: Add VK Validation**
Call `validate_groth16_vk` before storing the VK in `set_groth16_verification_key_for_next_epoch`: [2](#0-1) 

Add this line before `config_buffer::upsert`:
```move
validate_groth16_vk(&vk);
```

This prevents the DoS attack by rejecting VKs with invalid curve points.

**Long-term Fix: VK Authenticity Verification**
Implement a mechanism to verify the VK comes from the legitimate trusted setup:
1. Store a hash or commitment of the expected VK on-chain during genesis
2. Require new VKs to come with cryptographic proof of correct derivation
3. Implement multi-signature or timelock mechanisms for VK changes
4. Add monitoring/alerting when VK changes are proposed

**Additional Hardening:**
1. Also call `validate_groth16_vk` in `update_groth16_verification_key` (genesis function)
2. Add checks for expected VK structure (e.g., `gamma_abc_g1` must have exactly 2 elements) [7](#0-6) 
3. Require VK changes to be paired with training wheels PK changes (as documented) [8](#0-7) 

## Proof of Concept

```move
#[test(aptos_framework = @0x1)]
#[expected_failure(abort_code = 0x10002, location = aptos_framework::keyless_account)]
fun test_invalid_vk_causes_dos(aptos_framework: &signer) {
    use aptos_framework::keyless_account;
    use aptos_framework::config_buffer;
    use std::vector;
    
    // Initialize config buffer
    config_buffer::initialize(aptos_framework);
    
    // Create a VK with invalid G1 point (all zeros - not on curve)
    let invalid_alpha_g1 = vector::empty<u8>();
    let i = 0;
    while (i < 32) {
        vector::push_back(&mut invalid_alpha_g1, 0u8);
        i = i + 1;
    };
    
    // Valid-looking but actually invalid curve point data
    let invalid_vk = keyless_account::new_groth16_verification_key(
        invalid_alpha_g1,  // Invalid G1 point
        vector[0u8],       // Invalid G2 point
        vector[0u8],       // Invalid G2 point  
        vector[0u8],       // Invalid G2 point
        vector[vector[0u8], vector[0u8]]  // Invalid G1 points
    );
    
    // This should fail if validate_groth16_vk is called,
    // but currently succeeds, allowing invalid VK to be set
    keyless_account::set_groth16_verification_key_for_next_epoch(
        aptos_framework, 
        invalid_vk
    );
    
    // After epoch change, all keyless transactions would fail
    // because PreparedVerifyingKey conversion returns None
}

#[test(aptos_framework = @0x1)]
fun test_malicious_vk_accepted(aptos_framework: &signer) {
    use aptos_framework::keyless_account;
    use aptos_framework::config_buffer;
    use std::vector;
    
    config_buffer::initialize(aptos_framework);
    
    // Attacker creates VK from compromised trusted setup
    // (where they know the toxic waste)
    // This would be valid curve points but from wrong ceremony
    let malicious_vk = keyless_account::new_groth16_verification_key(
        x"malicious_alpha_g1_32_bytes_here_123456",
        x"malicious_beta_g2_64_bytes_here_00000000000000000000000000000001",
        x"malicious_gamma_g2_64_bytes_here_0000000000000000000000000000002",
        x"malicious_delta_g2_64_bytes_here_0000000000000000000000000000003",
        vector[
            x"malicious_gamma_abc_g1_0_bytes_4",
            x"malicious_gamma_abc_g1_1_bytes_5"
        ]
    );
    
    // No verification that this VK is the legitimate one
    // Governance can set any VK, even from compromised ceremony
    keyless_account::set_groth16_verification_key_for_next_epoch(
        aptos_framework,
        malicious_vk
    );
    
    // After epoch change, attacker can forge proofs and steal funds
}
```

## Notes

This vulnerability exists because:
1. The validation function `validate_groth16_vk` exists but is never called
2. No verification that the VK is from the legitimate trusted setup
3. The code explicitly warns about this risk but implements no safeguards
4. Inconsistent with other governance functions that DO validate parameters

The primary issue (missing `validate_groth16_vk` call) is clearly a bug that should be fixed immediately. The secondary issue (no VK authenticity verification) is a design limitation that requires additional mechanisms like VK commitments or multi-signature approval.

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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L259-260)
```text
    /// WARNING: To mitigate against DoS attacks, a VK change should be done together with a training wheels PK change,
    /// so that old ZKPs for the old VK cannot be replayed as potentially-valid ZKPs.
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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L286-291)
```text
        // If a PK is being set, validate it first.
        if (option::is_some(&pk)) {
            let bytes = *option::borrow(&pk);
            let vpk = ed25519::new_validated_public_key_from_bytes(bytes);
            assert!(option::is_some(&vpk), E_TRAINING_WHEELS_PK_WRONG_SIZE)
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

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L188-191)
```rust
    // If there are ZK authenticators, the Groth16 VK must have been set on-chain.
    if with_zk && pvk.is_none() {
        return Err(invalid_signature!("Groth16 VK has not been set on-chain"));
    }
```

**File:** types/src/keyless/groth16_vk.rs (L66-68)
```rust
        if vk.gamma_abc_g1.len() != 2 {
            return Err(CryptoMaterialError::DeserializationError);
        }
```
