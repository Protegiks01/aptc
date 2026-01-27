# Audit Report

## Title
Missing Validation Allows Configuration DoS Attack Against All Keyless Accounts

## Summary
The `max_commited_epk_bytes` configuration field lacks validation when set via governance proposals, allowing it to be set below the minimum ephemeral public key (EPK) size of 34 bytes. This causes all keyless transactions to fail validation, resulting in a complete denial of service for keyless account users.

## Finding Description

The keyless account system uses ephemeral public keys (EPKs) that are serialized using BCS encoding. The minimum EPK size is 34 bytes for Ed25519 keys (32-byte key + 2 bytes BCS overhead) [1](#0-0) , and 67 bytes for Secp256r1 keys (65-byte key + 2 bytes overhead) [2](#0-1) .

The `max_commited_epk_bytes` field in the Configuration struct controls the maximum EPK size accepted by the ZK circuit [3](#0-2) . This value is normally set to 93 bytes [4](#0-3) .

**The Vulnerability Path:**

1. **No Configuration Validation**: The Move function `set_configuration_for_next_epoch` accepts a Configuration struct without validating `max_commited_epk_bytes` [5](#0-4) . There are no assertions checking that this value meets minimum requirements.

2. **Runtime Validation Failure**: During keyless transaction validation, the function `hash_public_inputs` is called to compute the public inputs hash for ZK proof verification [6](#0-5) . This calls `pad_and_pack_bytes_to_scalars_with_len` with the EPK bytes and `config.max_commited_epk_bytes`.

3. **Critical Check**: The packing function validates that the EPK length does not exceed `max_bytes` [7](#0-6) . If `max_commited_epk_bytes` is set to 33 or lower, this check fails for all Ed25519 EPKs (34 bytes), causing the transaction to be rejected with an error.

4. **System-Wide Impact**: The validation occurs in `verify_keyless_signature_without_ephemeral_signature_check`, which is called for every keyless transaction [8](#0-7) . If the configuration is invalid, ALL keyless transactions fail validation.

**Attack Scenario:**

A malicious or mistaken governance proposal sets `max_commited_epk_bytes` to 33 bytes (or any value < 34). After the next epoch transition when this configuration becomes active, all keyless account users are locked out of their accounts because every transaction they submit fails with "Byte array length of 34 is NOT <= max length of 33 bytes" during public inputs hash computation.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Significant Protocol Violation**: The keyless authentication system is a core protocol feature. Breaking all keyless transactions violates the Transaction Validation invariant that "Prologue/epilogue checks must enforce all invariants."

2. **Complete Availability Loss**: Users with keyless accounts cannot access their funds or execute any transactions. This represents a total loss of availability for an entire class of users.

3. **Network-Wide Impact**: Unlike localized bugs, this affects every keyless account user across the entire Aptos network simultaneously.

4. **Requires Governance Intervention**: Recovery requires another governance proposal to fix the configuration, which takes time to execute and may delay critical user operations.

5. **Potential Consensus Issues**: During epoch transition, if some validators have updated their configuration while others haven't (due to timing), they may reject different sets of transactions, potentially causing temporary consensus divergence.

While not reaching Critical severity (no fund theft, no permanent network halt), this represents a severe availability issue and significant protocol violation qualifying for High severity ($50,000 tier).

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to occur because:

1. **No Validation Safeguards**: The Move code provides no validation to prevent this misconfiguration. There are no assertions, no minimum value checks, and no circuit constant comparisons.

2. **Governance Process Risk**: While governance proposals undergo review, configuration parameters with complex technical requirements (like circuit constraints) may not be fully understood by all governance participants. A well-intentioned proposal attempting to "optimize" the configuration could inadvertently set this value too low.

3. **Misleading Documentation**: The inline comments suggest this field affects circuit behavior [9](#0-8) , but don't explicitly warn that values below 34 bytes will break all keyless transactions.

4. **No Runtime Warning**: There's no early warning system - the misconfiguration only manifests when users try to submit transactions after the epoch change.

The attack requires governance approval, which provides some protection, but the lack of technical safeguards and the complexity of the parameter make accidental misconfiguration a realistic concern.

## Recommendation

**Immediate Fix**: Add validation to the Move code to prevent `max_commited_epk_bytes` from being set below the minimum EPK size:

```move
/// Minimum EPK size in bytes (Ed25519: 32-byte key + 2 bytes BCS encoding)
const MIN_EPK_BYTES: u16 = 34;

public fun set_configuration_for_next_epoch(fx: &signer, config: Configuration) {
    system_addresses::assert_aptos_framework(fx);
    
    // Validate max_commited_epk_bytes is at least the minimum EPK size
    assert!(
        config.max_commited_epk_bytes >= MIN_EPK_BYTES,
        error::invalid_argument(E_MAX_COMMITED_EPK_BYTES_TOO_SMALL)
    );
    
    config_buffer::upsert<Configuration>(config);
}
```

**Additional Safeguards**:

1. Add similar validation to `new_configuration` constructor [10](#0-9) 

2. Define the minimum as a constant that can be updated if new EPK types are added

3. Add documentation warning about the minimum value requirement

4. Consider adding a circuit constant validation check in Rust code during configuration loading as a defense-in-depth measure

## Proof of Concept

```move
#[test(framework = @0x1)]
#[expected_failure(abort_code = 0x50001, location = aptos_framework::keyless_account)]
fun test_max_commited_epk_bytes_validation(framework: &signer) {
    use aptos_framework::keyless_account;
    use std::vector;
    use std::option;
    
    // Create a configuration with max_commited_epk_bytes set below minimum EPK size
    let bad_config = keyless_account::new_configuration(
        vector::empty(), // override_aud_val
        3,               // max_signatures_per_txn
        10_000_000,      // max_exp_horizon_secs
        option::none(),  // training_wheels_pubkey
        33,              // max_commited_epk_bytes - TOO SMALL! (minimum is 34)
        120,             // max_iss_val_bytes
        350,             // max_extra_field_bytes
        300              // max_jwt_header_b64_bytes
    );
    
    // This should fail with validation error once the fix is implemented
    keyless_account::set_configuration_for_next_epoch(framework, bad_config);
}
```

**Rust-based Validation Test**:

To demonstrate the runtime failure with current code, when `max_commited_epk_bytes = 33`:

```rust
#[test]
fn test_epk_validation_fails_with_small_max_bytes() {
    use aptos_crypto::{ed25519::Ed25519PrivateKey, traits::Uniform};
    use aptos_types::transaction::authenticator::EphemeralPublicKey;
    use aptos_crypto::poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len;
    
    let ed25519_pk = Ed25519PrivateKey::generate_for_testing().public_key();
    let epk = EphemeralPublicKey::Ed25519 {
        public_key: ed25519_pk,
    };
    
    let epk_bytes = epk.to_bytes();
    assert_eq!(epk_bytes.len(), 34); // Ed25519 EPK is 34 bytes
    
    // Attempting to pack with max_bytes = 33 should fail
    let result = pad_and_pack_bytes_to_scalars_with_len(&epk_bytes, 33);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("NOT <= max length"));
}
```

## Notes

This vulnerability demonstrates a critical gap in configuration validation for the keyless account system. While the circuit constants define the correct value of 93 bytes, nothing prevents a governance proposal from setting a value that breaks the system. The fix is straightforward but essential for preventing accidental or malicious DoS attacks against keyless account users.

### Citations

**File:** types/src/unit_tests/keyless_serialization_test.rs (L38-42)
```rust
    const EXPECTED_EPK_LENGTH: usize = Ed25519PrivateKey::LENGTH + 2;
    let epk_bytes: [u8; EXPECTED_EPK_LENGTH] = [
        0, 32, 32, 253, 186, 201, 177, 11, 117, 135, 187, 167, 181, 188, 22, 59, 206, 105, 231,
        150, 215, 30, 78, 212, 76, 16, 252, 180, 72, 134, 137, 247, 161, 68,
    ];
```

**File:** crates/aptos-crypto/src/secp256r1_ecdsa/mod.rs (L36-36)
```rust
pub const PUBLIC_KEY_LENGTH: usize = 65;
```

**File:** types/src/keyless/configuration.rs (L28-28)
```rust
    pub max_commited_epk_bytes: u16,
```

**File:** types/src/keyless/circuit_constants.rs (L25-26)
```rust
pub(crate) const MAX_COMMITED_EPK_BYTES: u16 =
    3 * poseidon_bn254::keyless::BYTES_PACKED_PER_SCALAR as u16;
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L84-111)
```text
        /// The max length of an ephemeral public key supported in our circuit (93 bytes)
        ///
        /// Note: Currently, the circuit derives the JWT's nonce field by hashing the EPK as:
        /// ```
        /// Poseidon_6(
        ///   epk_0, epk_1, epk_2,
        ///   max_commited_epk_bytes,
        ///   exp_date,
        ///   epk_blinder
        /// )
        /// ```
        /// and the public inputs hash by hashing the EPK with other inputs as:
        /// ```
        /// Poseidon_14(
        ///   epk_0, epk_1, epk_2,
        ///   max_commited_epk_bytes,
        ///   [...]
        /// )
        /// ```
        /// where `max_committed_epk_byte` is passed in as one of the witnesses to the circuit. As a result, (some)
        /// changes to this field could technically be handled by the same circuit: e.g., if we let the epk_i chunks
        /// exceed 31 bytes, but no more than 32, then `max_commited_epk_bytes` could now be in (93, 96]. Whether such a
        /// restricted set of changes is useful remains unclear. Therefore, the verdict will be that...
        ///
        /// If changed: (Likely) requires a circuit change because over-decreasing (or increasing) it leads to fewer (or
        ///   more) EPK chunks. This would break the current way the circuit hashes the nonce and the public inputs.
        ///   => prover service redeployment.
        max_commited_epk_bytes: u16,
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L160-180)
```text
    public fun new_configuration(
        override_aud_val: vector<String>,
        max_signatures_per_txn: u16,
        max_exp_horizon_secs: u64,
        training_wheels_pubkey: Option<vector<u8>>,
        max_commited_epk_bytes: u16,
        max_iss_val_bytes: u16,
        max_extra_field_bytes: u16,
        max_jwt_header_b64_bytes: u32
    ): Configuration {
        Configuration {
            override_aud_vals: override_aud_val,
            max_signatures_per_txn,
            max_exp_horizon_secs,
            training_wheels_pubkey,
            max_commited_epk_bytes,
            max_iss_val_bytes,
            max_extra_field_bytes,
            max_jwt_header_b64_bytes,
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L274-277)
```text
    public fun set_configuration_for_next_epoch(fx: &signer, config: Configuration) {
        system_addresses::assert_aptos_framework(fx);
        config_buffer::upsert<Configuration>(config);
    }
```

**File:** types/src/keyless/bn254_circom.rs (L331-334)
```rust
    let mut epk_frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
        epk.to_bytes().as_slice(),
        config.max_commited_epk_bytes as usize,
    )?;
```

**File:** crates/aptos-crypto/src/poseidon_bn254/keyless.rs (L97-102)
```rust
    if len > max_bytes {
        bail!(
            "Byte array length of {} is NOT <= max length of {} bytes.",
            bytes.len(),
            max_bytes
        );
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L307-316)
```rust
                        let public_inputs_hash = get_public_inputs_hash(
                            signature,
                            public_key.inner_keyless_pk(),
                            rsa_jwk,
                            config,
                        )
                        .map_err(|_| {
                            // println!("[aptos-vm][groth16] PIH computation failed");
                            invalid_signature!("Could not compute public inputs hash")
                        })?;
```
