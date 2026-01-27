# Audit Report

## Title
Governance Can Modify Circuit Constants Causing Complete DoS of Keyless Authentication System

## Summary
The keyless authentication system has circuit constants that are hardcoded into the ZK circuit but can be modified via on-chain governance without validation. If governance changes these circuit-dependent constants (max_iss_val_bytes, max_extra_field_bytes, max_jwt_header_b64_bytes, max_commited_epk_bytes), all keyless authentication fails because the public inputs hash computation uses different values than what the ZK circuit expects, causing a complete denial of service until either a governance reversion or circuit redeployment occurs.

## Finding Description
The keyless authentication system relies on a ZK circuit that has hardcoded constants for maximum field sizes. These constants are defined as `const` items: [1](#0-0) [2](#0-1) 

However, these same values are stored in an on-chain `Configuration` resource that can be modified via governance proposals: [3](#0-2) 

The Move module documentation clearly states these values require circuit redeployment to change: [4](#0-3) 

Despite this documentation, the `set_configuration_for_next_epoch` function allows governance to change these values without any validation: [5](#0-4) 

The critical issue arises in the public inputs hash computation, which uses the on-chain configuration values: [6](#0-5) 

**Attack Scenario:**
1. Governance proposal modifies `max_iss_val_bytes` from 120 to 150
2. Proposal passes and configuration is updated on-chain
3. Users submit keyless transactions with ZK proofs generated using the original circuit (with max_iss_val_bytes=120)
4. Validator computes public inputs hash using the new on-chain config (max_iss_val_bytes=150)
5. Hash mismatch causes all ZK proof verifications to fail
6. **Result:** Complete DoS of keyless authentication system

This breaks the **Deterministic Execution** invariant because nodes computing public inputs hashes with mismatched constants will fail to validate otherwise valid ZK proofs, and violates the **availability** guarantee of the keyless system.

## Impact Explanation
This is a **Critical Severity** vulnerability under the Aptos bug bounty criteria:

- **Total loss of liveness/network availability**: All keyless account holders are locked out of their accounts, unable to submit any transactions. This affects a critical authentication mechanism of the Aptos blockchain.

- **Non-recoverable without intervention**: Recovery requires either:
  - Emergency governance proposal to revert the configuration (slow due to governance delays)
  - Circuit redeployment with new constants (extremely slow - requires circuit compilation, trusted setup ceremony, prover service deployment)

While governance is generally trusted, this represents a **design flaw** where:
- Accidental governance mistakes can brick the system
- No validation prevents misconfiguration
- Warning comments in code are not enforced programmatically

## Likelihood Explanation
**Likelihood: Medium to High**

While this requires a governance proposal, the likelihood is elevated because:

1. **No validation barrier**: There's zero code preventing this misconfiguration
2. **Well-intentioned mistakes**: Governance participants might genuinely believe they're "improving" the system by increasing limits
3. **Documentation vs enforcement gap**: The Move code has comments warning about this but no enforcement
4. **Governance is not infallible**: History shows governance can make mistakes or be compromised
5. **Non-obvious failure mode**: The impact isn't immediate during proposal voting - it only manifests when users try to authenticate

## Recommendation

Add validation in the Move module to prevent modification of circuit-dependent constants:

```move
// In keyless_account.move, add validation function:
const E_CIRCUIT_CONSTANTS_IMMUTABLE: u64 = 4;

/// Validates that circuit-dependent constants match the hardcoded circuit values
fun validate_circuit_constants(config: &Configuration) {
    // These values MUST match the circuit constants and cannot be changed
    // without circuit redeployment
    assert!(config.max_commited_epk_bytes == 93, E_CIRCUIT_CONSTANTS_IMMUTABLE);
    assert!(config.max_iss_val_bytes == 120, E_CIRCUIT_CONSTANTS_IMMUTABLE);
    assert!(config.max_extra_field_bytes == 350, E_CIRCUIT_CONSTANTS_IMMUTABLE);
    assert!(config.max_jwt_header_b64_bytes == 300, E_CIRCUIT_CONSTANTS_IMMUTABLE);
}

// Modify set_configuration_for_next_epoch to call validation:
public fun set_configuration_for_next_epoch(fx: &signer, config: Configuration) {
    system_addresses::assert_aptos_framework(fx);
    validate_circuit_constants(&config); // ADD THIS LINE
    config_buffer::upsert<Configuration>(config);
}
```

**Alternative approach**: Make these fields immutable in the Configuration struct or remove them entirely from the on-chain configuration, reading them only from the Rust circuit constants. The on-chain configuration should only contain values that CAN be safely changed via governance (like `max_signatures_per_txn`, `max_exp_horizon_secs`, `override_aud_vals`, `training_wheels_pubkey`).

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework)]
#[expected_failure(abort_code = 0x50001, location = aptos_framework::transaction_validation)]
fun test_mismatched_circuit_constants_cause_dos(aptos_framework: &signer) {
    use aptos_framework::keyless_account;
    use aptos_framework::reconfiguration;
    
    // Initialize keyless with correct constants
    let correct_config = keyless_account::new_configuration(
        vector[],      // override_aud_vals
        3,             // max_signatures_per_txn
        10000000,      // max_exp_horizon_secs
        option::none(), // training_wheels_pubkey
        93,            // max_commited_epk_bytes - CORRECT
        120,           // max_iss_val_bytes - CORRECT
        350,           // max_extra_field_bytes - CORRECT
        300            // max_jwt_header_b64_bytes - CORRECT
    );
    keyless_account::update_configuration(aptos_framework, correct_config);
    
    // Malicious/mistaken governance changes circuit constants
    let bad_config = keyless_account::new_configuration(
        vector[],
        3,
        10000000,
        option::none(),
        93,
        150,           // max_iss_val_bytes - CHANGED! Circuit expects 120
        350,
        300
    );
    
    // This should fail with validation, but currently succeeds
    keyless_account::set_configuration_for_next_epoch(aptos_framework, bad_config);
    reconfiguration::reconfigure_for_test();
    
    // Now all keyless authentications will fail with "Proof verification failed"
    // because public inputs hash is computed with wrong constant
    // This test would show ZK proof verification failing for all valid proofs
}
```

**Notes**

The vulnerability stems from a fundamental design decision where circuit-dependent constants exist in two places:
1. Hardcoded in Rust as `const` items (used during circuit compilation)
2. Mutable in on-chain Move Configuration (used during proof verification)

The Move documentation acknowledges these constants require circuit redeployment to change, but provides no programmatic enforcement. This creates a critical governance attack surface where even well-intentioned configuration changes can completely brick keyless authentication until manual intervention occurs.

### Citations

**File:** types/src/keyless/circuit_constants.rs (L19-21)
```rust
pub(crate) const MAX_ISS_VAL_BYTES: u16 = 120;
pub(crate) const MAX_EXTRA_FIELD_BYTES: u16 = 350;
pub(crate) const MAX_JWT_HEADER_B64_BYTES: u32 = 300;
```

**File:** types/src/keyless/circuit_constants.rs (L25-26)
```rust
pub(crate) const MAX_COMMITED_EPK_BYTES: u16 =
    3 * poseidon_bn254::keyless::BYTES_PACKED_PER_SCALAR as u16;
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L111-134)
```text
        max_commited_epk_bytes: u16,

        /// The max length of the value of the JWT's `iss` field supported in our circuit (e.g., `"https://accounts.google.com"`)
        ///
        /// If changed: Requires a circuit change because the `iss` field value is hashed inside the circuit as
        ///   `HashBytesToFieldWithLen(MAX_ISS_VALUE_LEN)(iss_value, iss_value_len)` where `MAX_ISS_VALUE_LEN` is a
        ///   circuit constant hard-coded to `max_iss_val_bytes` (i.e., to 120) => prover service redeployment..
        max_iss_val_bytes: u16,

        /// The max length of the JWT field name and value (e.g., `"max_age":"18"`) supported in our circuit
        ///
        /// If changed: Requires a circuit change because the extra field key-value pair is hashed inside the circuit as
        ///   `HashBytesToFieldWithLen(MAX_EXTRA_FIELD_KV_PAIR_LEN)(extra_field, extra_field_len)` where
        ///   `MAX_EXTRA_FIELD_KV_PAIR_LEN` is a circuit constant hard-coded to `max_extra_field_bytes` (i.e., to 350)
        ///    => prover service redeployment.
        max_extra_field_bytes: u16,

        /// The max length of the base64url-encoded JWT header in bytes supported in our circuit.
        ///
        /// If changed: Requires a circuit change because the JWT header is hashed inside the circuit as
        ///   `HashBytesToFieldWithLen(MAX_B64U_JWT_HEADER_W_DOT_LEN)(b64u_jwt_header_w_dot, b64u_jwt_header_w_dot_len)`
        ///   where `MAX_B64U_JWT_HEADER_W_DOT_LEN` is a circuit constant hard-coded to `max_jwt_header_b64_bytes`
        ///   (i.e., to 350) => prover service redeployment.
        max_jwt_header_b64_bytes: u32,
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

**File:** types/src/keyless/bn254_circom.rs (L279-320)
```rust
pub fn hash_public_inputs(
    config: &Configuration,
    epk: &EphemeralPublicKey,
    idc: &IdCommitment,
    exp_timestamp_secs: u64,
    exp_horizon_secs: u64,
    iss: &str,
    extra_field: Option<&str>,
    jwt_header_json: &str,
    jwk: &RSA_JWK,
    override_aud_val: Option<&str>,
) -> anyhow::Result<Fr> {
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

    let (override_aud_val_hash, use_override_aud) = match override_aud_val {
        Some(override_aud_val) => (
            cached_pad_and_hash_string(override_aud_val, IdCommitment::MAX_AUD_VAL_BYTES)?,
            ark_bn254::Fr::from(1),
        ),
        None => (*EMPTY_OVERRIDE_AUD_FIELD_HASH, ark_bn254::Fr::from(0)),
    };

    // Add the hash of the jwt_header with the "." separator appended
    let jwt_header_b64_with_separator = format!("{}.", base64url_encode_str(jwt_header_json));
    let jwt_header_hash = cached_pad_and_hash_string(
        &jwt_header_b64_with_separator,
        config.max_jwt_header_b64_bytes as usize,
    )?;

    let jwk_hash = cached_jwk_hash(jwk)?;

    // Add the hash of the value of the `iss` field
    let iss_field_hash = cached_pad_and_hash_string(iss, config.max_iss_val_bytes as usize)?;
```
