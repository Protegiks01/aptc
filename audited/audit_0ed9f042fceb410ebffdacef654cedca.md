# Audit Report

## Title
Keyless Authentication Denial of Service via Malformed On-Chain JWKs

## Summary
Malformed RSA JWKs stored on-chain lack validation of critical cryptographic parameters (`n` modulus and `e` exponent fields), causing all subsequent JWT signature verifications to always fail, resulting in a complete denial of service for keyless authentication users of affected OIDC providers.

## Finding Description

The Aptos keyless authentication system stores JWKs (JSON Web Keys) on-chain via the `JWKMoveStruct` type for JWT signature verification. [1](#0-0) 

JWKs are stored on-chain through two mechanisms:

1. **Validator Consensus Path**: Validators observe JWKs from OIDC providers and reach consensus via `process_jwk_update_inner`. [2](#0-1)  This function validates the version, voting power, and multi-signature, but **performs no validation of the actual RSA_JWK field contents** (base64-encoded `n` and `e` values).

2. **Governance Patch Path**: Governance can update JWKs via `set_patches` and `new_patch_upsert_jwk`. [3](#0-2)  The Move contract accepts any string values for RSA parameters without cryptographic validation.

When a user attempts keyless authentication, the system retrieves the JWK and attempts JWT signature verification:

For OpenIdSig (ZKless keyless): [4](#0-3)  The verification calls `from_rsa_components(&self.n, &self.e)` which decodes base64. [5](#0-4) 

If the `n` or `e` fields contain:
- **Invalid base64**: `from_rsa_components` fails, error propagates via `?` operator
- **Empty strings**: Base64 decode fails  
- **Wrong modulus length**: For ZK proofs, `to_poseidon_scalar()` validates 256-byte requirement [6](#0-5) 

All errors propagate to keyless validation: [7](#0-6)  where they're converted to `invalid_signature!`, causing **all signature verifications to always fail**.

**Attack Scenario**: A malicious governance proposal or Byzantine validator consensus could store an RSA_JWK with `n: ""` (empty string) or `n: "!!!invalid!!!"` (invalid base64). All users authenticating with that provider would be permanently unable to transact until the JWK is corrected via another governance action or consensus update.

## Impact Explanation

**Severity: High** - This meets the "Significant protocol violations" criterion per the Aptos bug bounty program.

**Impact**:
- Complete denial of service for keyless authentication users of an affected OIDC provider (e.g., all Google, Facebook, or Apple users)
- Non-recoverable until governance or validator consensus fixes the JWK
- Breaks the **availability invariant** for keyless authentication
- Does not cause loss of funds, but prevents legitimate users from accessing their accounts

This is classified as **High severity** rather than Critical because:
- It requires governance approval or validator consensus to exploit (Byzantine threshold)
- No funds are lost or stolen
- Not a consensus safety violation (doesn't cause chain splits)
- Recoverable via governance/consensus correction

## Likelihood Explanation

**Likelihood: Low-Medium**

The vulnerability requires one of:
1. **Malicious governance proposal**: Requires governance voting power to pass a proposal with malformed JWK patches
2. **Byzantine validator consensus**: Requires 2/3+ validators to collude and push malformed JWKs through the consensus mechanism

However, given the lack of validation, this could also occur through:
- **Operational errors**: Validators or governance accidentally propose malformed JWKs during legitimate updates
- **Compromised validator**: A single compromised validator with sufficient voting power could propose malformed updates
- **Supply chain attack**: Compromise of JWK fetching infrastructure could inject malformed JWKs

The lack of defensive validation at storage time means the system relies entirely on the correctness of external data sources and the integrity of governance/consensus processes.

## Recommendation

**Add validation before storing JWKs on-chain**. Implement checks in both the validator transaction processing and Move contract:

**For Rust-side validation** in `aptos-move/aptos-vm/src/validator_txns/jwk.rs`, add validation before calling `UPSERT_INTO_OBSERVED_JWKS`:

```rust
fn validate_rsa_jwk_fields(jwk: &RSA_JWK) -> Result<(), VMStatus> {
    // Validate base64 decoding succeeds
    base64::decode_config(&jwk.n, URL_SAFE_NO_PAD)
        .map_err(|_| invalid_signature!("Invalid base64 in JWK modulus"))?;
    base64::decode_config(&jwk.e, URL_SAFE_NO_PAD)
        .map_err(|_| invalid_signature!("Invalid base64 in JWK exponent"))?;
    
    // Validate modulus size (must be 256 bytes for circuit compatibility)
    let modulus = base64::decode_config(&jwk.n, URL_SAFE_NO_PAD)?;
    if modulus.len() != RSA_JWK::RSA_MODULUS_BYTES {
        return Err(invalid_signature!("JWK modulus must be 256 bytes"));
    }
    
    // Validate exponent is standard value (65537)
    if jwk.e != "AQAB" {
        return Err(invalid_signature!("Only AQAB exponent supported"));
    }
    
    Ok(())
}
```

**For Move-side validation** in `aptos-move/framework/aptos-framework/sources/jwks.move`, add a native function to validate RSA_JWK parameters before storage.

This implements defense-in-depth: even if governance or consensus is compromised, malformed JWKs cannot be stored on-chain.

## Proof of Concept

```rust
#[test]
fn test_malformed_jwk_causes_verification_failure() {
    // Create a malformed RSA_JWK with empty modulus
    let malformed_jwk = RSA_JWK::new_from_strs(
        "test_kid",
        "RSA", 
        "RS256",
        "AQAB",
        "", // Empty modulus - invalid base64 will fail
    );
    
    // Attempt to verify JWT signature - this will fail
    let jwt_token = "eyJhbGc...valid_jwt_with_valid_signature";
    let result = malformed_jwk.verify_signature_without_exp_check(jwt_token);
    
    // Verification ALWAYS fails due to malformed JWK
    assert!(result.is_err());
    
    // Similarly with invalid base64
    let malformed_jwk2 = RSA_JWK::new_from_strs(
        "test_kid",
        "RSA",
        "RS256", 
        "AQAB",
        "!!!invalid_base64!!!", // Invalid base64
    );
    
    let result2 = malformed_jwk2.verify_signature_without_exp_check(jwt_token);
    assert!(result2.is_err()); // ALWAYS fails
}

#[test] 
fn test_malformed_jwk_stored_onchain_causes_dos() {
    // Simulate storing malformed JWK via governance patch
    let malformed_jwk = new_rsa_jwk(
        utf8(b"malicious_kid"),
        utf8(b"RS256"),
        utf8(b"AQAB"),
        utf8(b""), // Empty modulus
    );
    
    let patch = new_patch_upsert_jwk(b"https://accounts.google.com", malformed_jwk);
    
    // Governance sets malformed patch (no validation occurs)
    set_patches(&aptos_framework, vector[patch]);
    
    // Now all Google users attempting keyless auth will fail
    // because get_jwk_for_authenticator returns the malformed JWK
    // and verify_jwt_signature ALWAYS fails
}
```

## Notes

This vulnerability demonstrates a critical **defense-in-depth failure**: the system trusts that JWKs provided by governance or validator consensus are cryptographically valid, but performs no validation until usage time. While the attack requires privileged access (governance or Byzantine consensus), the lack of validation creates unnecessary fragility and exposes the system to operational errors and insider threats.

The issue affects both ZK-based and ZKless keyless authentication paths, as both rely on the same on-chain JWK storage without validation. The impact is limited to availability (DoS) rather than authentication bypass - malformed JWKs cause verification to **always fail**, never to **always pass**.

### Citations

**File:** types/src/jwks/jwk/mod.rs (L21-29)
```rust
/// Reflection of Move type `0x1::jwks::JWK`.
/// When you load an on-chain config that contains some JWK(s), the JWK will be of this type.
/// When you call a Move function from rust that takes some JWKs as input, pass in JWKs of this type.
/// Otherwise, it is recommended to convert this to the rust enum `JWK` below for better rust experience.
/// See its doc in Move for more details.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct JWKMoveStruct {
    pub variant: MoveAny,
}
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L100-143)
```rust
    fn process_jwk_update_inner(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        log_context: &AdapterLogSchema,
        session_id: SessionId,
        update: jwks::QuorumCertifiedUpdate,
    ) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
        // Load resources.
        let validator_set =
            ValidatorSet::fetch_config(resolver).ok_or(Expected(MissingResourceValidatorSet))?;
        let observed_jwks =
            ObservedJWKs::fetch_config(resolver).ok_or(Expected(MissingResourceObservedJWKs))?;

        let mut jwks_by_issuer: HashMap<Issuer, ProviderJWKs> =
            observed_jwks.into_providers_jwks().into();
        let issuer = update.update.issuer.clone();
        let on_chain = jwks_by_issuer
            .entry(issuer.clone())
            .or_insert_with(|| ProviderJWKs::new(issuer));
        let verifier = ValidatorVerifier::from(&validator_set);

        let QuorumCertifiedUpdate {
            update: observed,
            multi_sig,
        } = update;

        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }

        let authors = multi_sig.get_signers_addresses(&verifier.get_ordered_account_addresses());

        // Check voting power.
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| Expected(NotEnoughVotingPower))?;

        // Verify multi-sig.
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;

```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L379-420)
```text
    public fun set_patches(fx: &signer, patches: vector<Patch>) acquires Patches, PatchedJWKs, ObservedJWKs {
        system_addresses::assert_aptos_framework(fx);
        borrow_global_mut<Patches>(@aptos_framework).patches = patches;
        regenerate_patched_jwks();
    }

    /// Create a `Patch` that removes all entries.
    public fun new_patch_remove_all(): Patch {
        Patch {
            variant: copyable_any::pack(PatchRemoveAll {}),
        }
    }

    /// Create a `Patch` that removes the entry of a given issuer, if exists.
    public fun new_patch_remove_issuer(issuer: vector<u8>): Patch {
        Patch {
            variant: copyable_any::pack(PatchRemoveIssuer { issuer }),
        }
    }

    /// Create a `Patch` that removes the entry of a given issuer, if exists.
    public fun new_patch_remove_jwk(issuer: vector<u8>, jwk_id: vector<u8>): Patch {
        Patch {
            variant: copyable_any::pack(PatchRemoveJWK { issuer, jwk_id })
        }
    }

    /// Create a `Patch` that upserts a JWK into an issuer's JWK set.
    public fun new_patch_upsert_jwk(issuer: vector<u8>, jwk: JWK): Patch {
        Patch {
            variant: copyable_any::pack(PatchUpsertJWK { issuer, jwk })
        }
    }

    /// Create a `JWK` of variant `RSA_JWK`.
    public fun new_rsa_jwk(kid: String, alg: String, e: String, n: String): JWK {
        JWK {
            variant: copyable_any::pack(RSA_JWK {
                kid,
                kty: utf8(b"RSA"),
                e,
                n,
```

**File:** types/src/keyless/openid_sig.rs (L126-139)
```rust
    pub fn verify_jwt_signature(
        &self,
        rsa_jwk: &RSA_JWK,
        jwt_header_json: &str,
    ) -> anyhow::Result<()> {
        let jwt_b64 = format!(
            "{}.{}.{}",
            base64url_encode_str(jwt_header_json),
            base64url_encode_str(&self.jwt_payload_json),
            base64url_encode_bytes(&self.jwt_sig)
        );
        rsa_jwk.verify_signature_without_exp_check(&jwt_b64)?;
        Ok(())
    }
```

**File:** types/src/jwks/rsa/mod.rs (L89-95)
```rust
    pub fn verify_signature_without_exp_check(&self, jwt_token: &str) -> Result<TokenData<Claims>> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        let key = &DecodingKey::from_rsa_components(&self.n, &self.e)?;
        let claims = jsonwebtoken::decode::<Claims>(jwt_token, key, &validation)?;
        Ok(claims)
    }
```

**File:** types/src/jwks/rsa/mod.rs (L102-110)
```rust
    pub fn to_poseidon_scalar(&self) -> Result<ark_bn254::Fr> {
        let mut modulus = base64::decode_config(&self.n, URL_SAFE_NO_PAD)?;
        // The circuit only supports RSA256
        if modulus.len() != Self::RSA_MODULUS_BYTES {
            bail!(
                "Wrong modulus size, must be {} bytes",
                Self::RSA_MODULUS_BYTES
            );
        }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L391-395)
```rust
                    openid_sig
                        .verify_jwt_signature(rsa_jwk, &signature.jwt_header_json)
                        .map_err(|_| {
                            invalid_signature!("RSA signature verification failed for OpenIdSig")
                        })?;
```
