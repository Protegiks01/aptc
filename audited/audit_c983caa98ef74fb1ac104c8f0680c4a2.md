# Audit Report

## Title
Inconsistent Validation Bypass for training_wheels_pubkey via set_configuration_for_next_epoch

## Summary
The `training_wheels_pubkey` field in keyless account configuration can be set to a weak, compromised, or invalid Ed25519 key through the `set_configuration_for_next_epoch()` function, which bypasses the cryptographic validation present in `update_training_wheels_for_next_epoch()`. This allows governance proposals to set keys that have not been validated for small-order subgroup membership or curve point validity.

## Finding Description
The keyless account module provides two paths for updating the `training_wheels_pubkey`:

**Path 1 (Validated)**: `update_training_wheels_for_next_epoch()` [1](#0-0) 

This function validates the public key using `ed25519::new_validated_public_key_from_bytes()`, which performs:
- Point-on-curve validation
- Small-order subgroup checks via native function `public_key_validate_internal` [2](#0-1) 

The native implementation explicitly checks for small-order points: [3](#0-2) 

**Path 2 (Unvalidated)**: `set_configuration_for_next_epoch()` [4](#0-3) 

This function accepts any `Configuration` struct without validation, including configurations created via: [5](#0-4) 

**Attack Scenario:**
A governance proposal could call `new_configuration()` with `training_wheels_pubkey: Some(malicious_key_bytes)` where `malicious_key_bytes` is:
1. A key whose private key is known to the attacker
2. A small-order point (e.g., identity element)
3. An invalid curve point that passes basic length checks but fails cryptographic validation

Then call `set_configuration_for_next_epoch()` to queue this configuration. After epoch transition via `on_new_epoch()`, the weak key becomes active.

**Runtime Deserialization:**
During keyless transaction validation, the runtime deserializes the training wheels key: [6](#0-5) 

The `Ed25519PublicKey::try_from()` uses `from_bytes_unchecked()` which explicitly does NOT validate small-order subgroups: [7](#0-6) 

Test evidence confirms weak keys are rejected by the validated path: [8](#0-7) 

## Impact Explanation
**Severity: Medium to High**

If a compromised or weak training wheels key is set:

1. **Security Mechanism Bypass (High)**: The training wheels mechanism is a critical safety layer during keyless account rollout. Per the function warning at line 282: "If a malicious key is set, this *could* lead to stolen funds." [9](#0-8) 

2. **Signature Forgery**: An attacker who controls the private key corresponding to the training wheels public key can forge signatures for any Groth16 proof: [10](#0-9) 

3. **DoS Attack (Medium)**: Setting an invalid curve point causes all keyless transactions to fail with "The training wheels PK set on chain is not a valid PK" error.

## Likelihood Explanation
**Likelihood: Low (requires governance compromise)**

While the vulnerability is technically exploitable, it requires:
- Governance proposal approval (requires significant stake)
- Successful voting by validators
- Knowledge to use `set_configuration_for_next_epoch` instead of the intended `update_training_wheels_for_next_epoch`

However, the inconsistent validation creates a dangerous **defense-in-depth failure**. The existence of two code paths with different security properties violates the principle of least surprise and could lead to accidental misuse even by well-intentioned governance participants.

## Recommendation
Add validation to `set_configuration_for_next_epoch()` or make the Configuration constructor validate its inputs:

```move
public fun set_configuration_for_next_epoch(fx: &signer, config: Configuration) {
    system_addresses::assert_aptos_framework(fx);
    
    // Validate training_wheels_pubkey if present
    if (option::is_some(&config.training_wheels_pubkey)) {
        let bytes = *option::borrow(&config.training_wheels_pubkey);
        let vpk = ed25519::new_validated_public_key_from_bytes(bytes);
        assert!(option::is_some(&vpk), E_TRAINING_WHEELS_PK_WRONG_SIZE)
    };
    
    config_buffer::upsert<Configuration>(config);
}
```

Alternatively, deprecate direct use of `set_configuration_for_next_epoch` for keyless configuration updates and require all training wheels updates to go through the validated function.

## Proof of Concept
```move
module test::weak_key_exploit {
    use aptos_framework::keyless_account;
    use std::option;
    
    // This governance proposal bypasses validation
    public entry fun malicious_proposal(framework: &signer) {
        // Create weak key (small-order point - identity element)
        let weak_key = x"0100000000000000000000000000000000000000000000000000000000000000";
        
        // Create configuration with weak key
        let malicious_config = keyless_account::new_configuration(
            vector[], // override_aud_vals  
            3,        // max_signatures_per_txn
            10000000, // max_exp_horizon_secs
            option::some(weak_key), // WEAK KEY - bypasses validation!
            93,       // max_commited_epk_bytes
            120,      // max_iss_val_bytes
            350,      // max_extra_field_bytes
            350       // max_jwt_header_b64_bytes
        );
        
        // This succeeds - no validation!
        keyless_account::set_configuration_for_next_epoch(framework, malicious_config);
        
        // After epoch transition, the weak key is active
        // Attacker can now forge training wheels signatures
    }
}
```

## Notes
The vulnerability demonstrates a critical inconsistency between two API surfaces for the same security-sensitive operation. While exploitation requires governance-level access, the lack of validation in `set_configuration_for_next_epoch` violates the security invariant that all training wheels keys must be validated Ed25519 public keys free from small-order subgroup vulnerabilities. The warning comments acknowledge the danger but don't enforce protection through code.

### Citations

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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L282-282)
```text
    /// WARNING: If a malicious key is set, this *could* lead to stolen funds.
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L283-302)
```text
    public fun update_training_wheels_for_next_epoch(fx: &signer, pk: Option<vector<u8>>) acquires Configuration {
        system_addresses::assert_aptos_framework(fx);

        // If a PK is being set, validate it first.
        if (option::is_some(&pk)) {
            let bytes = *option::borrow(&pk);
            let vpk = ed25519::new_validated_public_key_from_bytes(bytes);
            assert!(option::is_some(&vpk), E_TRAINING_WHEELS_PK_WRONG_SIZE)
        };

        let config = if (config_buffer::does_exist<Configuration>()) {
            config_buffer::extract_v2<Configuration>()
        } else {
            *borrow_global<Configuration>(signer::address_of(fx))
        };

        config.training_wheels_pubkey = pk;

        set_configuration_for_next_epoch(fx, config);
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/cryptography/ed25519.move (L79-87)
```text
    public fun new_validated_public_key_from_bytes(bytes: vector<u8>): Option<ValidatedPublicKey> {
        if (public_key_validate_internal(bytes)) {
            option::some(ValidatedPublicKey {
                bytes
            })
        } else {
            option::none<ValidatedPublicKey>()
        }
    }
```

**File:** aptos-move/framework/src/natives/cryptography/ed25519.rs (L67-82)
```rust
    // This deserialization only performs point-on-curve checks, so we check for small subgroup below
    // NOTE(Gas): O(1) cost: some arithmetic for converting to (X, Y, Z, T) coordinates
    let point = match CompressedEdwardsY(key_bytes_slice).decompress() {
        Some(point) => point,
        None => {
            return Ok(smallvec![Value::bool(false)]);
        },
    };

    // Check if the point lies on a small subgroup. This is required when using curves with a
    // small cofactor (e.g., in Ed25519, cofactor = 8).
    // NOTE(Gas): O(1) cost: multiplies the point by the cofactor
    context.charge(ED25519_PER_PUBKEY_SMALL_ORDER_CHECK * NumArgs::one())?;
    let valid = !point.is_small_order();

    Ok(smallvec![Value::bool(valid)])
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L222-233)
```rust
    let training_wheels_pk = match &config.training_wheels_pubkey {
        None => None,
        // This takes ~4.4 microseconds, so we are not too concerned about speed here.
        // (Run `cargo bench -- ed25519/pk_deserialize` in `crates/aptos-crypto`.)
        Some(bytes) => Some(EphemeralPublicKey::ed25519(
            Ed25519PublicKey::try_from(bytes.as_slice()).map_err(|_| {
                // println!("[aptos-vm][groth16] On chain TW PK is invalid");

                invalid_signature!("The training wheels PK set on chain is not a valid PK")
            })?,
        )),
    };
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L323-344)
```rust
                        if training_wheels_pk.is_some() {
                            match &zksig.training_wheels_signature {
                                Some(training_wheels_sig) => {
                                    training_wheels_sig
                                        .verify(
                                            &groth16_and_stmt,
                                            training_wheels_pk.as_ref().unwrap(),
                                        )
                                        .map_err(|_| {
                                            // println!("[aptos-vm][groth16] TW sig verification failed");
                                            invalid_signature!(
                                                "Could not verify training wheels signature"
                                            )
                                        })?;
                                },
                                None => {
                                    // println!("[aptos-vm][groth16] Expected TW sig to be set");
                                    return Err(invalid_signature!(
                                        "Training wheels signature expected but it is missing"
                                    ));
                                },
                            }
```

**File:** crates/aptos-crypto/src/ed25519/ed25519_keys.rs (L100-111)
```rust
    /// Deserialize an Ed25519PublicKey without any validation checks apart from expected key size
    /// and valid curve point, although not necessarily in the prime-order subgroup.
    ///
    /// This function does NOT check the public key for membership in a small subgroup.
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<Ed25519PublicKey, CryptoMaterialError> {
        match ed25519_dalek::PublicKey::from_bytes(bytes) {
            Ok(dalek_public_key) => Ok(Ed25519PublicKey(dalek_public_key)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
```

**File:** testsuite/fuzzer/data/0x1/ed25519/public_key_validate_internal/sources/call_native.move (L12-32)
```text
        let invalid_pk_bytes_zeros = x"0000000000000000000000000000000000000000000000000000000000000000";
        let result_fail_zeros = ed25519::new_validated_public_key_from_bytes(invalid_pk_bytes_zeros);
        assert!(option::is_none(&result_fail_zeros), 2);

        let invalid_len_31 = vector::empty<u8>();
        let i = 0; while (i < 31) { vector::push_back(&mut invalid_len_31, 0u8); i = i + 1; };
        let result_fail_len31 = ed25519::new_validated_public_key_from_bytes(invalid_len_31);
        assert!(option::is_none(&result_fail_len31), 3);

        let invalid_len_33 = vector::empty<u8>();
        let i = 0; while (i < 33) { vector::push_back(&mut invalid_len_33, 0u8); i = i + 1; };
        let result_fail_len33 = ed25519::new_validated_public_key_from_bytes(invalid_len_33);
        assert!(option::is_none(&result_fail_len33), 4);

        let invalid_pk_bytes_high = x"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let result_fail_high = ed25519::new_validated_public_key_from_bytes(invalid_pk_bytes_high);
        assert!(option::is_none(&result_fail_high), 5);

        let small_order_pk_bytes = x"0100000000000000000000000000000000000000000000000000000000000000";
        let result_fail_small_order = ed25519::new_validated_public_key_from_bytes(small_order_pk_bytes);
        assert!(option::is_none(&result_fail_small_order), 6);
```
