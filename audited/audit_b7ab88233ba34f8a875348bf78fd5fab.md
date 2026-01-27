# Audit Report

## Title
Ephemeral Public Key Indefinite Lifetime Extension via Blinder Reuse Bypass

## Summary
The keyless authentication system allows the same ephemeral public key (EPK) to be reused with different blinders to generate multiple valid nonces, enabling users to indefinitely extend an EPK's lifetime beyond the intended `max_exp_horizon_secs` boundary. This violates the fundamental "ephemeral" security property and creates an unbounded window for key compromise exploitation.

## Finding Description

The keyless authentication system uses ephemeral key pairs that are supposed to have bounded lifetimes. The `reconstruct_oauth_nonce()` function computes a nonce as: [1](#0-0) 

The nonce is constructed from three inputs: the EPK, expiration timestamp, and a blinder. By design, different blinders produce different nonces for the same EPK.

The validation logic checks that the expiration is within `max_exp_horizon_secs` from the JWT's `iat` (issued-at time): [2](#0-1) 

**Critical flaw:** The validation checks `exp_date_secs < iat + max_exp_horizon_secs`, where `iat` is the JWT issuance time, NOT the EPK creation time. Since there is no on-chain tracking of EPK creation times or usage history, an attacker can:

1. Create EPK at time T₀
2. Authenticate with OAuth at T₀, get JWT₁ with `iat=T₀`, set expiry to `T₀ + max_exp_horizon`
3. Just before expiry, authenticate again at time T₁ with a different blinder
4. Get JWT₂ with `iat=T₁`, set expiry to `T₁ + max_exp_horizon`
5. Repeat indefinitely, extending the EPK's lifetime without bound

The on-chain configuration only stores global parameters, with no per-EPK state: [3](#0-2) 

The validation system confirms there is no EPK usage tracking: [4](#0-3) 

## Impact Explanation

This is **High Severity** under "Significant protocol violations" because:

1. **Violates Ephemeral Key Invariant**: The term "ephemeral" implies bounded lifetime, yet EPKs can be kept alive indefinitely through re-authentication cycles

2. **Extended Compromise Window**: If an EPK's private key is stolen (e.g., from a compromised device), the attacker's exploitation window extends from the intended `max_exp_horizon_secs` (currently ~115 days on devnet) to potentially years or indefinitely

3. **Defeats Security Model**: The `max_exp_horizon_secs` parameter is explicitly documented to limit "how far in the future from the JWT's issued-at-time can the EPK expiration date be set" - but this doesn't enforce a maximum lifetime from EPK creation, undermining the security guarantee users expect

4. **No Revocation Mechanism**: Users cannot truly revoke an EPK by waiting for expiration, as it can be perpetually refreshed

## Likelihood Explanation

**Likelihood: High**

- **Attack Complexity**: Low - any user with a keyless account can perform this attack
- **Prerequisites**: Only requires ability to authenticate with OAuth provider (standard user capability)
- **Detection**: Difficult to detect as the behavior appears legitimate (valid JWTs, valid signatures)
- **Incentive**: High for attackers who have compromised an EPK's private key and want to maintain persistent access

## Recommendation

Implement on-chain tracking of EPK first-use timestamps to enforce maximum lifetime from creation:

**Option 1: On-chain EPK Registry (Stronger Security)**
- Add a Move resource storing `Table<EphemeralPublicKey, u64>` mapping EPKs to their first-seen timestamp
- In validation, check: `exp_date_secs < first_seen_time + max_total_lifetime_secs`
- Add garbage collection for expired entries

**Option 2: Modified Validation (Simpler)**
- Require the JWT's `iat` timestamp to be within a small window of the current blockchain time (e.g., ±24 hours)
- This prevents using old JWTs to extend lifetimes while maintaining usability
- Modify the check to: `ensure!(current_time - iat < max_jwt_age && exp_date_secs < iat + max_exp_horizon_secs)`

**Recommended Fix (Option 2 - Simpler):**

In `verify_jwt_claims()`, add:

```rust
let current_time = seconds_from_epoch(
    onchain_timestamp_obj.microseconds / 1_000_000
)?;
let jwt_issued_time = seconds_from_epoch(claims.oidc_claims.iat)?;
let max_jwt_age_secs = 86400; // 24 hours

ensure!(
    current_time >= jwt_issued_time && 
    current_time - jwt_issued_time < max_jwt_age_secs,
    "JWT issued-at time is too far in the past or future"
);
```

## Proof of Concept

**Attack Scenario:**

```rust
// Time T0: Create ephemeral key pair
let esk = EphemeralPrivateKey::Ed25519 { inner_private_key: Ed25519PrivateKey::generate(&mut rng) };
let epk = esk.public_key();

// Time T0: Authenticate with blinder1
let blinder1 = vec![0x01; 31];
let expiry1 = T0 + max_exp_horizon_secs;
let nonce1 = OpenIdSig::reconstruct_oauth_nonce(&blinder1, expiry1, &epk, config)?;
// Get JWT1 from OAuth with iat=T0, nonce=nonce1

// Use EPK for max_exp_horizon_secs...

// Time T0 + max_exp_horizon_secs - 1 day: Re-authenticate with blinder2
let blinder2 = vec![0x02; 31];
let expiry2 = (T0 + max_exp_horizon_secs - 86400) + max_exp_horizon_secs;
let nonce2 = OpenIdSig::reconstruct_oauth_nonce(&blinder2, expiry2, &epk, config)?;
// Get JWT2 from OAuth with iat=T0+max_exp_horizon_secs-86400, nonce=nonce2

// EPK lifetime extended by another max_exp_horizon_secs
// Repeat indefinitely - same EPK, different blinders/nonces/JWTs
```

**Validation confirms both JWTs are valid:**
- JWT1: `expiry1 (T0 + max_exp_horizon) < iat1 (T0) + max_exp_horizon` ✓
- JWT2: `expiry2 (T0 + 2*max_exp_horizon - 86400) < iat2 (T0 + max_exp_horizon - 86400) + max_exp_horizon` ✓

Both pass validation despite using the same EPK, violating the ephemeral key invariant.

## Notes

This vulnerability exists because:
1. The nonce reconstruction allows the same EPK to be used with different blinders
2. The validation checks expiry against JWT `iat` time, not EPK creation time  
3. There is no on-chain state tracking EPK usage or first-seen timestamps
4. Users can re-authenticate with OAuth at any time to get fresh JWTs with new `iat` values

The impact is amplified when EPK private keys are compromised, as attackers gain an indefinite exploitation window rather than the intended bounded lifetime.

### Citations

**File:** types/src/keyless/openid_sig.rs (L64-78)
```rust
        let max_expiration_date = seconds_from_epoch(
            claims
                .oidc_claims
                .iat
                .checked_add(config.max_exp_horizon_secs)
                .ok_or_else(|| {
                    anyhow::anyhow!("Overflow when adding iat and max_exp_horizon_secs")
                })?,
        )?;
        let expiration_date = seconds_from_epoch(exp_timestamp_secs)?;

        ensure!(
            expiration_date < max_expiration_date,
            "The ephemeral public key's expiration date is too far into the future"
        );
```

**File:** types/src/keyless/openid_sig.rs (L141-159)
```rust
    pub fn reconstruct_oauth_nonce(
        epk_blinder: &[u8],
        exp_timestamp_secs: u64,
        epk: &EphemeralPublicKey,
        config: &Configuration,
    ) -> anyhow::Result<String> {
        let mut frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
            epk.to_bytes().as_slice(),
            config.max_commited_epk_bytes as usize,
        )?;

        frs.push(Fr::from(exp_timestamp_secs));
        frs.push(poseidon_bn254::keyless::pack_bytes_to_one_scalar(
            epk_blinder,
        )?);

        let nonce_fr = poseidon_bn254::hash_scalars(frs)?;
        Ok(nonce_fr.to_string())
    }
```

**File:** aptos-move/framework/aptos-framework/sources/keyless_account.move (L48-135)
```text
    struct Configuration has key, store, drop, copy {
        /// An override `aud` for the identity of a recovery service, which will help users recover their keyless accounts
        /// associated with dapps or wallets that have disappeared.
        /// IMPORTANT: This recovery service **cannot**, on its own, take over user accounts: a user must first sign in
        /// via OAuth in the recovery service in order to allow it to rotate any of that user's keyless accounts.
        ///
        /// Furthermore, the ZKP eventually expires, so there is a limited window within which a malicious recovery
        /// service could rotate accounts. In the future, we can make this window arbitrarily small by further lowering
        /// the maximum expiration horizon for ZKPs used for recovery, instead of relying on the `max_exp_horizon_secs`
        /// value in this resource.
        ///
        /// If changed: There is no prover service support yet for recovery mode => ZKPs with override aud's enabled
        ///   will not be served by the prover service => as long as training wheels are "on," such recovery ZKPs will
        ///   never arrive on chain.
        ///   (Once support is implemented in the prover service, in an abundance of caution, the training wheel check
        ///    should only pass if the override aud in the public statement matches one in this list. Therefore, changes
        ///    to this value should be picked up automatically by the prover service.)
        override_aud_vals: vector<String>,

        /// No transaction can have more than this many keyless signatures.
        ///
        /// If changed: Only affects the Aptos validators; prover service not impacted.
        max_signatures_per_txn: u16,

        /// How far in the future from the JWT's issued-at-time can the EPK expiration date be set?
        /// Specifically, validators enforce that the ZKP's expiration horizon is less than this `max_exp_horizon_secs`
        /// value.
        ///
        /// If changed: Only affects the Aptos validators; prover service not impacted.
        max_exp_horizon_secs: u64,

        /// The training wheels PK, if training wheels are on.
        ///
        /// If changed: Prover service has to be re-deployed with the associated training wheel SK.
        training_wheels_pubkey: Option<vector<u8>>,

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
    }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L152-273)
```rust
/// Ensures that **all** keyless authenticators in the transaction are valid.
pub(crate) fn validate_authenticators(
    pvk: Option<&PreparedVerifyingKey<Bn254>>,
    configuration: Option<&Configuration>,
    authenticators: &Vec<(AnyKeylessPublicKey, KeylessSignature)>,
    features: &Features,
    resolver: &impl AptosMoveResolver,
    module_storage: &impl ModuleStorage,
) -> Result<(), VMStatus> {
    let mut with_zk = false;
    for (pk, sig) in authenticators {
        // Feature-gating for keyless TXNs (whether ZK or ZKless, whether passkey-based or not)
        if matches!(sig.cert, EphemeralCertificate::ZeroKnowledgeSig { .. }) {
            if !features.is_zk_keyless_enabled() {
                return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
            }

            with_zk = true;
        }
        if matches!(sig.cert, EphemeralCertificate::OpenIdSig { .. })
            && !features.is_zkless_keyless_enabled()
        {
            return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
        }
        if matches!(sig.ephemeral_signature, EphemeralSignature::WebAuthn { .. })
            && !features.is_keyless_with_passkeys_enabled()
        {
            return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
        }
        if matches!(pk, AnyKeylessPublicKey::Federated { .. })
            && !features.is_federated_keyless_enabled()
        {
            return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
        }
    }

    // If there are ZK authenticators, the Groth16 VK must have been set on-chain.
    if with_zk && pvk.is_none() {
        return Err(invalid_signature!("Groth16 VK has not been set on-chain"));
    }

    let config = configuration.ok_or_else(|| {
        // Preserve error code for compatibility.
        value_deserialization_error!(format!(
            "get_resource failed on {}::{}::{}",
            CORE_CODE_ADDRESS.to_hex_literal(),
            Configuration::struct_tag().module,
            Configuration::struct_tag().name
        ))
    })?;
    if authenticators.len() > config.max_signatures_per_txn as usize {
        // println!("[aptos-vm][groth16] Too many keyless authenticators");
        return Err(invalid_signature!("Too many keyless authenticators"));
    }

    let onchain_timestamp_obj = get_current_time_onchain(resolver)?;
    // Check the expiry timestamp on all authenticators first to fail fast
    // This is a redundant check to quickly dismiss expired signatures early and save compute on more computationally costly checks.
    // The actual check is performed in `verify_keyless_signature_without_ephemeral_signature_check`.
    for (_, sig) in authenticators {
        sig.verify_expiry(onchain_timestamp_obj.microseconds)
            .map_err(|_| {
                // println!("[aptos-vm][groth16] ZKP expired");

                invalid_signature!("The ephemeral keypair has expired")
            })?;
    }

    let patched_jwks = get_jwks_onchain(resolver)?;

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

    for (pk, sig) in authenticators {
        // Try looking up the jwk in 0x1.
        let jwk = match get_jwk_for_authenticator(&patched_jwks.jwks, pk.inner_keyless_pk(), sig) {
            // 1: If found in 0x1, then we consider that the ground truth & we are done.
            Ok(jwk) => jwk,
            // 2: If not found in 0x1, we check the Keyless PK type.
            Err(e) => {
                match pk {
                    // 2.a: If this is a federated keyless account; look in `jwk_addr` for JWKs
                    AnyKeylessPublicKey::Federated(fed_pk) => {
                        let federated_jwks =
                            get_federated_jwks_onchain(resolver, &fed_pk.jwk_addr, module_storage)
                                .map_err(|_| {
                                    invalid_signature!(format!(
                                        "Could not fetch federated PatchedJWKs at {}",
                                        fed_pk.jwk_addr
                                    ))
                                })?;
                        // 2.a.i If not found in jwk_addr either, then we fail the validation.
                        get_jwk_for_authenticator(&federated_jwks.jwks, pk.inner_keyless_pk(), sig)?
                    },
                    // 2.b: If this is not a federated keyless account, then we fail the validation.
                    AnyKeylessPublicKey::Normal(_) => return Err(e),
                }
            },
        };
        verify_keyless_signature_without_ephemeral_signature_check(
            pk,
            sig,
            &jwk,
            onchain_timestamp_obj.microseconds,
            &training_wheels_pk,
            config,
            pvk,
        )?;
    }

    Ok(())
}
```
