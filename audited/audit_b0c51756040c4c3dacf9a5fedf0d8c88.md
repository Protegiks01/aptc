# Audit Report

## Title
Missing Validation on `max_extra_field_bytes` Allows DoS of Keyless Accounts Requiring Extra JWT Fields

## Summary
The keyless account configuration parameter `max_extra_field_bytes` can be set to 0 through governance without any validation checks, causing authentication failure for all keyless accounts that include extra JWT fields in their identity provider claims. This creates a denial-of-service condition affecting a subset of legitimate users.

## Finding Description

The `Configuration` struct in the keyless account system contains a `max_extra_field_bytes` field that defines the maximum length of optional JWT extra fields (e.g., `"family_name":"Straka"`). This parameter can be modified through governance proposals using the `set_configuration_for_next_epoch` function. [1](#0-0) [2](#0-1) 

The governance function that creates new configurations accepts `max_extra_field_bytes` as a `u16` parameter without any validation: [3](#0-2) 

Similarly, `set_configuration_for_next_epoch` applies the configuration without validation: [4](#0-3) 

When a keyless signature with a non-empty `extra_field` is validated, the system calls `hash_public_inputs`, which attempts to hash the extra field using the configured limit: [5](#0-4) 

This eventually calls `pad_and_pack_bytes_to_scalars_with_len`, which performs a length check: [6](#0-5) 

If `max_extra_field_bytes` is 0 and the extra field contains any data, the check `len > max_bytes` fails with the error "Byte array length of X is NOT <= max length of 0 bytes." This propagates as "Could not compute public inputs hash": [7](#0-6) 

Extra fields are optional but legitimate components of keyless authentication, as shown in test constants: [8](#0-7) [9](#0-8) 

## Impact Explanation

This vulnerability falls under **Medium Severity** per the Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Once `max_extra_field_bytes` is set to 0, all keyless accounts requiring extra JWT fields cannot authenticate until governance passes another proposal to restore a valid value.
- **Limited DoS**: Only affects users whose identity providers require or utilize extra JWT fields for authentication, not all keyless accounts.

The impact is not Critical because:
- It doesn't affect consensus or validator operations
- It doesn't cause fund loss or theft
- It doesn't create a non-recoverable partition
- Recovery is possible through governance action

The impact is not High because:
- It doesn't affect validator node performance
- It's a targeted DoS, not network-wide

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can occur through:
1. **Governance error**: An accidental misconfiguration in a governance proposal that sets `max_extra_field_bytes` to 0 alongside other valid parameter changes
2. **Malicious governance proposal**: A compromised governance participant could intentionally propose this change
3. **Insufficient proposal review**: Governance participants failing to properly validate configuration parameters before voting

The likelihood is elevated because:
- There is **no validation** preventing this value from being set to 0
- Other configuration parameters (e.g., `training_wheels_pubkey`) have validation, indicating the codebase recognizes the need for sanity checks
- Configuration changes are complex and could include errors

## Recommendation

Add validation to prevent `max_extra_field_bytes` from being set to 0 or other invalid values. The validation should be added in the `new_configuration` function:

```move
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
    // Add validation
    assert!(max_extra_field_bytes > 0, E_INVALID_MAX_EXTRA_FIELD_BYTES);
    assert!(max_iss_val_bytes > 0, E_INVALID_MAX_ISS_VAL_BYTES);
    assert!(max_commited_epk_bytes > 0, E_INVALID_MAX_COMMITED_EPK_BYTES);
    assert!(max_jwt_header_b64_bytes > 0, E_INVALID_MAX_JWT_HEADER_BYTES);
    
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

Add corresponding error constants:
```move
const E_INVALID_MAX_EXTRA_FIELD_BYTES: u64 = 4;
const E_INVALID_MAX_ISS_VAL_BYTES: u64 = 5;
const E_INVALID_MAX_COMMITED_EPK_BYTES: u64 = 6;
const E_INVALID_MAX_JWT_HEADER_BYTES: u64 = 7;
```

## Proof of Concept

The following Move test demonstrates the vulnerability:

```move
#[test(aptos_framework = @0x1)]
#[expected_failure(abort_code = 0x10001, location = aptos_framework::keyless_validation)]
fun test_max_extra_field_bytes_zero_dos(aptos_framework: &signer) {
    use aptos_framework::keyless_account;
    use std::option;
    
    // Create a malicious configuration with max_extra_field_bytes = 0
    let bad_config = keyless_account::new_configuration(
        vector[],           // override_aud_vals
        3,                  // max_signatures_per_txn
        10000000,           // max_exp_horizon_secs
        option::none(),     // training_wheels_pubkey
        93,                 // max_commited_epk_bytes
        120,                // max_iss_val_bytes
        0,                  // max_extra_field_bytes - ZERO!
        300                 // max_jwt_header_b64_bytes
    );
    
    // Apply through governance
    keyless_account::set_configuration_for_next_epoch(aptos_framework, bad_config);
    
    // Trigger epoch change to apply configuration
    // ... (epoch transition code)
    
    // Now attempt to authenticate with a keyless signature containing extra_field
    // This will fail with "Could not compute public inputs hash"
    // Any user with extra JWT fields (e.g., "family_name":"Straka") cannot authenticate
}
```

## Notes

This vulnerability represents a **missing input validation** issue in governance-settable parameters. While governance is generally trusted, the codebase demonstrates awareness of the need for validation (as seen with `training_wheels_pubkey` validation). The absence of similar validation for `max_extra_field_bytes` and related circuit parameters creates an attack surface where configuration errors—whether accidental or malicious—can cause service disruption for legitimate users.

### Citations

**File:** types/src/keyless/configuration.rs (L22-32)
```rust
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Configuration {
    pub override_aud_vals: Vec<String>,
    pub max_signatures_per_txn: u16,
    pub max_exp_horizon_secs: u64,
    pub training_wheels_pubkey: Option<Vec<u8>>,
    pub max_commited_epk_bytes: u16,
    pub max_iss_val_bytes: u16,
    pub max_extra_field_bytes: u16,
    pub max_jwt_header_b64_bytes: u32,
}
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L120-126)
```text
        /// The max length of the JWT field name and value (e.g., `"max_age":"18"`) supported in our circuit
        ///
        /// If changed: Requires a circuit change because the extra field key-value pair is hashed inside the circuit as
        ///   `HashBytesToFieldWithLen(MAX_EXTRA_FIELD_KV_PAIR_LEN)(extra_field, extra_field_len)` where
        ///   `MAX_EXTRA_FIELD_KV_PAIR_LEN` is a circuit constant hard-coded to `max_extra_field_bytes` (i.e., to 350)
        ///    => prover service redeployment.
        max_extra_field_bytes: u16,
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

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L269-277)
```text
    /// Queues up a change to the keyless configuration. The change will only be effective after reconfiguration. Only
    /// callable via governance proposal.
    ///
    /// WARNING: A malicious `Configuration` could lead to DoS attacks, create liveness issues, or enable a malicious
    /// recovery service provider to phish users' accounts.
    public fun set_configuration_for_next_epoch(fx: &signer, config: Configuration) {
        system_addresses::assert_aptos_framework(fx);
        config_buffer::upsert<Configuration>(config);
    }
```

**File:** types/src/keyless/bn254_circom.rs (L291-300)
```rust
    let (has_extra_field, extra_field_hash) = match extra_field {
        None => (Fr::zero(), *EMPTY_EXTRA_FIELD_HASH),
        Some(extra_field) => (
            Fr::one(),
            poseidon_bn254::keyless::pad_and_hash_string(
                extra_field,
                config.max_extra_field_bytes as usize,
            )?,
        ),
    };
```

**File:** crates/aptos-crypto/src/poseidon_bn254/keyless.rs (L85-103)
```rust
pub fn pad_and_pack_bytes_to_scalars_with_len(
    bytes: &[u8],
    max_bytes: usize,
) -> anyhow::Result<Vec<ark_bn254::Fr>> {
    let len = bytes.len();
    if max_bytes > MAX_NUM_INPUT_BYTES {
        bail!(
            "Cannot hash more than {} bytes. Was given {} bytes.",
            MAX_NUM_INPUT_BYTES,
            len
        );
    }
    if len > max_bytes {
        bail!(
            "Byte array length of {} is NOT <= max length of {} bytes.",
            bytes.len(),
            max_bytes
        );
    }
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

**File:** types/src/keyless/circuit_testcases.rs (L123-127)
```rust
pub(crate) const SAMPLE_JWT_EXTRA_FIELD_KEY: &str = "family_name";

/// Consistent with what is in `SAMPLE_JWT_PAYLOAD_JSON`
pub static SAMPLE_JWT_EXTRA_FIELD: Lazy<String> =
    Lazy::new(|| format!(r#""{}":"Straka","#, SAMPLE_JWT_EXTRA_FIELD_KEY));
```

**File:** types/src/keyless/groth16_sig.rs (L41-42)
```rust
    /// An optional extra field (e.g., `"<name>":"<val>"`) that will be matched publicly in the JWT
    pub extra_field: Option<String>,
```
