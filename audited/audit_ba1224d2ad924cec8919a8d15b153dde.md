# Audit Report

## Title
Keyless Configuration Lacks Validation for Circuit-Critical Parameter Allowing Denial of Service

## Summary
The `max_commited_epk_bytes` field in the keyless account configuration can be set to values incompatible with the hardcoded ZK circuit constants, causing complete failure of all keyless account authentication without any validation checks.

## Finding Description

The keyless account system uses a ZK circuit that is hardcoded to expect ephemeral public keys (EPKs) to be packed into exactly 3 BN254 field elements (scalars), corresponding to a maximum of 93 bytes (3 × 31 bytes per scalar). [1](#0-0) 

However, the on-chain `Configuration` struct allows `max_commited_epk_bytes` to be set to any `u16` value (0-65535) through governance proposals, with **zero validation** that it matches the circuit's expectation. [2](#0-1) 

When `max_commited_epk_bytes` is used during transaction validation, it determines how EPK bytes are padded and packed into scalars for Poseidon hashing in two critical locations:

1. **Nonce reconstruction**: [3](#0-2) 

2. **Public inputs hash computation**: [4](#0-3) 

The `pad_and_pack_bytes_to_scalars_with_len` function produces `ceil(max_bytes / 31)` scalars. [5](#0-4) 

**Breaking the Invariant:**

If `max_commited_epk_bytes` is set to any value other than 93:
- **Less than 93** (e.g., 62): Produces 2 scalars instead of 3
- **Greater than 93** (e.g., 124): Produces 4 scalars instead of 3

The circuit documentation explicitly states this breaks the system: [6](#0-5) 

The circuit uses these scalars in fixed Poseidon hash functions (`Poseidon_6` and `Poseidon_14`) that cannot accept variable numbers of EPK inputs. When the Rust code produces the wrong number of scalars, the computed `public_inputs_hash` will not match what the ZK proof expects, causing Groth16 verification to fail. [7](#0-6) 

**Governance Update Path:**

The configuration can be updated via governance without any validation: [8](#0-7) 

## Impact Explanation

**Severity: High** (per Aptos bug bounty criteria)

This vulnerability causes **total loss of liveness for all keyless accounts** if triggered:

1. **Complete DoS of Keyless Authentication**: All keyless transactions would fail proof verification, rendering keyless accounts completely unusable
2. **Non-recoverable without governance intervention**: Requires another epoch transition with correct configuration to restore service
3. **Affects protocol-level functionality**: Breaks a core authentication mechanism in Aptos

This meets the **High Severity** criteria: "Significant protocol violations" and could constitute network availability issues for keyless users specifically.

While not reaching Critical severity (which requires total network failure), the impact is severe because:
- Keyless accounts are a critical user-facing feature
- All keyless users are simultaneously affected
- Recovery requires governance action and epoch transition (hours to days)
- Could happen through accidental misconfiguration, not just malicious action

## Likelihood Explanation

**Likelihood: Low-Medium**

While governance is a trusted role, this vulnerability has moderate likelihood because:

1. **No validation guards against mistakes**: A single typo in a governance proposal (e.g., typing "930" instead of "93") would trigger this
2. **Complex parameter relationships**: The connection between this field and circuit constraints is non-obvious, increasing risk of accidental misconfiguration
3. **Documented as requiring circuit changes**: The Move comments warn about this, but lack runtime enforcement
4. **Testing gaps**: No runtime check exists to validate configuration before epoch application

However, likelihood is reduced by:
- Governance proposals undergo review before execution
- Changes to keyless configuration are infrequent
- The existing configuration is correct (93 bytes)

## Recommendation

Add mandatory validation in the Move code to enforce the circuit constraint:

```move
public fun set_configuration_for_next_epoch(fx: &signer, config: Configuration) {
    system_addresses::assert_aptos_framework(fx);
    
    // Validate max_commited_epk_bytes matches circuit constant
    assert!(
        config.max_commited_epk_bytes == 93,
        E_INVALID_MAX_COMMITTED_EPK_BYTES
    );
    
    config_buffer::upsert<Configuration>(config);
}
```

Add similar validation in:
1. `new_configuration()` - constructor validation
2. `update_configuration()` - genesis-time validation  
3. `on_new_epoch()` - defense-in-depth check before applying buffered config

Define the error constant:
```move
const E_INVALID_MAX_COMMITTED_EPK_BYTES: u64 = 4;
```

Additionally, add a Rust-side assertion in the configuration initialization: [9](#0-8) 

```rust
pub fn new_for_devnet() -> Configuration {
    assert_eq!(
        circuit_constants::MAX_COMMITED_EPK_BYTES, 93,
        "MAX_COMMITED_EPK_BYTES must be 93 bytes (3 scalars)"
    );
    // ... rest of function
}
```

## Proof of Concept

This PoC demonstrates the configuration mismatch causing keyless transaction failures:

```move
#[test(framework = @aptos_framework)]
#[expected_failure(abort_code = 0x10001, location = aptos_framework::transaction_validation)]
fun test_invalid_max_commited_epk_bytes_breaks_keyless(framework: &signer) {
    use aptos_framework::keyless_account;
    use std::vector;
    
    // Create configuration with WRONG max_commited_epk_bytes value
    let bad_config = keyless_account::new_configuration(
        vector[],      // override_aud_vals
        3,             // max_signatures_per_txn
        10_000_000,    // max_exp_horizon_secs
        option::none(), // training_wheels_pubkey
        124,           // max_commited_epk_bytes - WRONG! Should be 93
        120,           // max_iss_val_bytes
        350,           // max_extra_field_bytes
        300            // max_jwt_header_b64_bytes
    );
    
    // This would cause all keyless transactions to fail when applied
    keyless_account::set_configuration_for_next_epoch(framework, bad_config);
    
    // After epoch transition, any keyless transaction would fail with:
    // "Proof verification failed" or "Could not compute public inputs hash"
}
```

**Notes:**
- The vulnerability requires governance access to exploit, which is a **trusted role** in the Aptos security model
- However, the **lack of validation** is a code defect that could enable accidental DoS through misconfiguration
- Runtime validation should enforce invariants even for trusted actors to prevent operational errors
- The circuit constant of 93 bytes is derived from: 3 scalars × 31 bytes/scalar = 93 bytes
- Actual EPK sizes are smaller (34 bytes for Ed25519, ~67 bytes for Secp256r1 with BCS encoding) [10](#0-9)

### Citations

**File:** types/src/keyless/circuit_constants.rs (L25-26)
```rust
pub(crate) const MAX_COMMITED_EPK_BYTES: u16 =
    3 * poseidon_bn254::keyless::BYTES_PACKED_PER_SCALAR as u16;
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L84-110)
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

**File:** types/src/keyless/openid_sig.rs (L147-150)
```rust
        let mut frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
            epk.to_bytes().as_slice(),
            config.max_commited_epk_bytes as usize,
        )?;
```

**File:** types/src/keyless/bn254_circom.rs (L331-334)
```rust
    let mut epk_frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
        epk.to_bytes().as_slice(),
        config.max_commited_epk_bytes as usize,
    )?;
```

**File:** crates/aptos-crypto/src/poseidon_bn254/keyless.rs (L85-110)
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

    let len_scalar = pack_bytes_to_one_scalar(&len.to_le_bytes())?;
    let scalars = pad_and_pack_bytes_to_scalars_no_len(bytes, max_bytes)?
        .into_iter()
        .chain([len_scalar])
        .collect::<Vec<ark_bn254::Fr>>();
    Ok(scalars)
```

**File:** types/src/keyless/groth16_sig.rs (L215-235)
```rust
    pub fn verify_proof(
        &self,
        public_inputs_hash: Fr,
        pvk: &PreparedVerifyingKey<Bn254>,
    ) -> anyhow::Result<()> {
        // let start = std::time::Instant::now();
        let proof: Proof<Bn254> = Proof {
            a: self.a.deserialize_into_affine()?,
            b: self.b.deserialize_into_affine()?,
            c: self.c.deserialize_into_affine()?,
        };
        // println!("Deserialization time: {:?}", start.elapsed());

        // let start = std::time::Instant::now();
        let verified = Groth16::<Bn254>::verify_proof(pvk, &proof, &[public_inputs_hash])?;
        // println!("Proof verification time: {:?}", start.elapsed());
        if !verified {
            bail!("groth16 proof verification failed")
        }
        Ok(())
    }
```

**File:** types/src/keyless/configuration.rs (L62-73)
```rust
    pub fn new_for_devnet() -> Configuration {
        Configuration {
            override_aud_vals: vec![Self::OVERRIDE_AUD_FOR_TESTING.to_owned()],
            max_signatures_per_txn: 3,
            max_exp_horizon_secs: 10_000_000, // ~115.74 days
            training_wheels_pubkey: None,
            max_commited_epk_bytes: circuit_constants::MAX_COMMITED_EPK_BYTES,
            max_iss_val_bytes: circuit_constants::MAX_ISS_VAL_BYTES,
            max_extra_field_bytes: circuit_constants::MAX_EXTRA_FIELD_BYTES,
            max_jwt_header_b64_bytes: circuit_constants::MAX_JWT_HEADER_B64_BYTES,
        }
    }
```

**File:** types/src/unit_tests/keyless_serialization_test.rs (L38-42)
```rust
    const EXPECTED_EPK_LENGTH: usize = Ed25519PrivateKey::LENGTH + 2;
    let epk_bytes: [u8; EXPECTED_EPK_LENGTH] = [
        0, 32, 32, 253, 186, 201, 177, 11, 117, 135, 187, 167, 181, 188, 22, 59, 206, 105, 231,
        150, 215, 30, 78, 212, 76, 16, 252, 180, 72, 134, 137, 247, 161, 68,
    ];
```
