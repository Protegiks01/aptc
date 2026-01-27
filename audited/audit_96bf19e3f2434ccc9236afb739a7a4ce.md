# Audit Report

## Title
State Corruption via Unvalidated JWK Content in ObservedJWKUpdate Validator Transactions

## Summary
The `is_vtxn_expected()` function and subsequent validation pipeline fail to validate the cryptographic content of JWKs (JSON Web Keys) in `ObservedJWKUpdate` validator transactions before committing them to on-chain state. Malformed RSA JWKs with invalid base64 encoding or incorrect key parameters can pass all validation checks and be stored on-chain, breaking keyless authentication for entire issuers and requiring governance intervention to recover.

## Finding Description

The validation pipeline for `ObservedJWKUpdate` validator transactions has a critical gap:

**Consensus Phase** - [1](#0-0)  only checks configuration flags without validating transaction content. Additionally, [2](#0-1)  shows that `ObservedJWKUpdate` verification returns `Ok(())` without performing any cryptographic validation, unlike `DKGResult` which performs actual verification.

**Execution Phase** - [3](#0-2)  validates version increment, voting power quorum, and multi-signature validity, but does NOT validate the actual JWK content (RSA modulus, exponent, base64 encoding, key size).

**Move State Update** - [4](#0-3)  processes JWKs through `upsert_jwk()` which [5](#0-4)  shows only performs key ID comparison without content validation.

**JWK Observation** - [6](#0-5)  shows validators directly sign observed JWKs from OIDC providers without validating RSA parameters. The parsing at [7](#0-6)  only validates field presence and string types, not cryptographic validity.

**Validation Only At Use** - [8](#0-7)  shows that JWK validation occurs when creating `DecodingKey` during signature verification, which is AFTER the malformed data is already committed to state.

**Attack Path:**
1. Compromised or buggy OIDC provider serves JWKs with invalid base64 in `n` (RSA modulus) or wrong key size
2. Validators' [9](#0-8)  fetch these JWKs via HTTP
3. Validators sign the malformed data without validation
4. With quorum signatures, the update passes all checks and is committed
5. On-chain state now contains unusable JWKs
6. Future keyless authentication attempts fail when `DecodingKey::from_rsa_components()` rejects invalid parameters
7. All users of the affected issuer cannot authenticate until governance removes the malformed JWK

## Impact Explanation

This qualifies as **Medium Severity** under "State inconsistencies requiring intervention":

- **Breaks Critical Infrastructure**: Keyless authentication becomes unavailable for all users of the affected OIDC provider (e.g., all Google or Facebook login users)
- **Network-Wide Impact**: All validator nodes store the corrupted state
- **Requires Governance Intervention**: Only governance proposals can remove malformed JWKs from `ObservedJWKs` resource
- **Non-Self-Recovering**: System cannot automatically detect or fix the issue
- **Deterministic Execution Maintained**: All validators reach the same (corrupted) state, so consensus safety is preserved

This could potentially escalate to **High Severity** if it's shown to cause significant protocol violations affecting validator operations beyond just keyless authentication.

## Likelihood Explanation

**Moderate to High Likelihood:**

1. **Accidental Trigger**: OIDC providers (Google, Facebook, etc.) could have bugs or make configuration changes that produce JWKs with:
   - Invalid base64 encoding in modulus/exponent
   - Wrong key sizes (not 256 bytes as expected)
   - Malformed JSON structures

2. **No Defensive Validation**: The system trusts external data sources without verification, violating defense-in-depth principles

3. **Already Observed**: Similar issues have occurred in Web3 systems where external data feeds (oracles, API endpoints) serve malformed data

4. **Attack Complexity**: While requiring compromised OIDC providers or Byzantine validator majority for malicious exploitation, **accidental** bugs in external systems are realistic

## Recommendation

Implement comprehensive JWK content validation before signing and before state commitment:

**Option 1: Validate at Observation Time** (crates/aptos-jwk-consensus/src/jwk_manager/mod.rs)
```rust
pub fn process_new_observation(
    &mut self,
    issuer: Issuer,
    jwks: Vec<JWKMoveStruct>,
) -> Result<()> {
    // Add validation before signing
    for jwk_move in &jwks {
        let jwk = JWK::try_from(jwk_move)?;
        if let JWK::RSA(rsa_jwk) = jwk {
            rsa_jwk.validate_rsa_parameters()?; // NEW: Validate base64, key size, etc.
        }
    }
    // ... rest of signing logic
}
```

**Option 2: Validate at Execution Time** (aptos-move/aptos-vm/src/validator_txns/jwk.rs)
```rust
fn process_jwk_update_inner(...) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
    // ... existing validation ...
    
    // NEW: Validate JWK content before state update
    for jwk_move in &observed.jwks {
        let jwk = JWK::try_from(jwk_move)
            .map_err(|_| Expected(MalformedJWKContent))?;
        if let JWK::RSA(rsa_jwk) = jwk {
            validate_rsa_jwk_parameters(&rsa_jwk)
                .map_err(|_| Expected(MalformedJWKContent))?;
        }
    }
    
    // ... proceed with state update
}
```

**Validation Function**:
```rust
fn validate_rsa_jwk_parameters(jwk: &RSA_JWK) -> Result<()> {
    // Validate base64 encoding
    let modulus = base64::decode_config(&jwk.n, URL_SAFE_NO_PAD)
        .context("Invalid base64 in RSA modulus")?;
    let exponent = base64::decode_config(&jwk.e, URL_SAFE_NO_PAD)
        .context("Invalid base64 in RSA exponent")?;
    
    // Validate modulus size
    ensure!(
        modulus.len() == RSA_JWK::RSA_MODULUS_BYTES,
        "RSA modulus must be {} bytes, got {}",
        RSA_JWK::RSA_MODULUS_BYTES,
        modulus.len()
    );
    
    // Validate exponent is reasonable (typically 65537)
    ensure!(!exponent.is_empty(), "RSA exponent cannot be empty");
    
    // Attempt to create DecodingKey to validate RSA parameters
    DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .context("Invalid RSA key parameters")?;
    
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_malformed_jwk_accepted() {
    // Create ObservedJWKUpdate with malformed RSA JWK
    let malformed_jwk = RSA_JWK {
        kid: "malicious-key".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        e: "INVALID_BASE64!!!".to_string(), // Invalid base64
        n: "SHORT".to_string(), // Wrong size
    };
    
    let provider_jwks = ProviderJWKs {
        issuer: b"https://evil-issuer.com".to_vec(),
        version: 1,
        jwks: vec![JWKMoveStruct::from(JWK::RSA(malformed_jwk))],
    };
    
    // This passes is_vtxn_expected() - only checks config
    assert!(is_vtxn_expected(&randomness_config, &jwk_consensus_config, 
        &ValidatorTransaction::ObservedJWKUpdate(QuorumCertifiedUpdate {
            update: provider_jwks.clone(),
            multi_sig: AggregateSignature::empty(),
        })));
    
    // This passes vtxn.verify() - returns Ok(()) without checking
    let vtxn = ValidatorTransaction::ObservedJWKUpdate(QuorumCertifiedUpdate {
        update: provider_jwks.clone(),
        multi_sig: create_valid_multi_sig(&provider_jwks), // Valid sig from validators
    });
    assert!(vtxn.verify(&verifier).is_ok());
    
    // Execution would accept this with valid multi-sig and voting power
    // State is now corrupted - trying to use this JWK fails:
    let jwk = JWK::RSA(malformed_jwk);
    assert!(DecodingKey::from_rsa_components(&malformed_jwk.n, &malformed_jwk.e).is_err());
    // Keyless authentication now broken for this issuer!
}
```

## Notes

This vulnerability demonstrates a **defense-in-depth failure** where external data from OIDC providers is trusted without cryptographic validation. While the threat model assumes validators are honest, the system should defend against compromised or buggy external dependencies. The gap between validation at commit time (none) and validation at use time (strict) creates a window for state corruption.

### Citations

**File:** consensus/src/util/mod.rs (L15-24)
```rust
pub fn is_vtxn_expected(
    randomness_config: &OnChainRandomnessConfig,
    jwk_consensus_config: &OnChainJWKConsensusConfig,
    vtxn: &ValidatorTransaction,
) -> bool {
    match vtxn {
        ValidatorTransaction::DKGResult(_) => randomness_config.randomness_enabled(),
        ValidatorTransaction::ObservedJWKUpdate(_) => jwk_consensus_config.jwk_consensus_enabled(),
    }
}
```

**File:** types/src/validator_txn.rs (L45-52)
```rust
    pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        match self {
            ValidatorTransaction::DKGResult(dkg_result) => dkg_result
                .verify(verifier)
                .context("DKGResult verification failed"),
            ValidatorTransaction::ObservedJWKUpdate(_) => Ok(()),
        }
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L127-142)
```rust
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

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L478-491)
```text
                assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
                vector::for_each(proposed_provider_jwks.jwks, |jwk|{
                    let variant_type_name = *string::bytes(copyable_any::type_name(&jwk.variant));
                    let is_delete = if (variant_type_name == b"0x1::jwks::UnsupportedJWK") {
                        let repr = copyable_any::unpack<UnsupportedJWK>(jwk.variant);
                        &repr.payload == &DELETE_COMMAND_INDICATOR
                    } else {
                        false
                    };
                    if (is_delete) {
                        remove_jwk(&mut cur_issuer_jwks, get_jwk_id(&jwk));
                    } else {
                        upsert_jwk(&mut cur_issuer_jwks, jwk);
                    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L626-654)
```text
    fun upsert_jwk(set: &mut ProviderJWKs, jwk: JWK): Option<JWK> {
        let found = false;
        let index = 0;
        let num_entries = vector::length(&set.jwks);
        while (index < num_entries) {
            let cur_entry = vector::borrow(&set.jwks, index);
            let comparison = compare_u8_vector(get_jwk_id(&jwk), get_jwk_id(cur_entry));
            if (is_greater_than(&comparison)) {
                index = index + 1;
            } else {
                found = is_equal(&comparison);
                break
            }
        };

        // Now if `found == true`, `index` points to the JWK we want to update/remove; otherwise, `index` points to
        // where we want to insert.
        let ret = if (found) {
            let entry = vector::borrow_mut(&mut set.jwks, index);
            let old_entry = option::some(*entry);
            *entry = jwk;
            old_entry
        } else {
            vector::insert(&mut set.jwks, index, jwk);
            option::none()
        };

        ret
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L197-205)
```rust
            let observed = ProviderJWKs {
                issuer: issuer.clone(),
                version: state.on_chain_version() + 1,
                jwks,
            };
            let signature = self
                .consensus_key
                .sign(&observed)
                .context("process_new_observation failed with signing error")?;
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

**File:** types/src/jwks/rsa/mod.rs (L132-177)
```rust
impl TryFrom<&serde_json::Value> for RSA_JWK {
    type Error = anyhow::Error;

    fn try_from(json_value: &serde_json::Value) -> Result<Self, Self::Error> {
        let kty = json_value
            .get("kty")
            .ok_or_else(|| anyhow!("Field `kty` not found"))?
            .as_str()
            .ok_or_else(|| anyhow!("Field `kty` is not a string"))?
            .to_string();

        ensure!(
            kty.as_str() == "RSA",
            "json to rsa jwk conversion failed with incorrect kty"
        );

        let ret = Self {
            kty,
            kid: json_value
                .get("kid")
                .ok_or_else(|| anyhow!("Field `kid` not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Field `kid` is not a string"))?
                .to_string(),
            alg: json_value
                .get("alg")
                .ok_or_else(|| anyhow!("Field `alg` not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Field `alg` is not a string"))?
                .to_string(),
            e: json_value
                .get("e")
                .ok_or_else(|| anyhow!("Field `e` not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Field `e` is not a string"))?
                .to_string(),
            n: json_value
                .get("n")
                .ok_or_else(|| anyhow!("Field `n` not found"))?
                .as_str()
                .ok_or_else(|| anyhow!("Field `n` is not a string"))?
                .to_string(),
        };

        Ok(ret)
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L102-110)
```rust
async fn fetch_jwks(open_id_config_url: &str, my_addr: Option<AccountAddress>) -> Result<Vec<JWK>> {
    let jwks_uri = fetch_jwks_uri_from_openid_config(open_id_config_url)
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with open-id config request: {e}"))?;
    let jwks = fetch_jwks_from_jwks_uri(my_addr, jwks_uri.as_str())
        .await
        .map_err(|e| anyhow!("fetch_jwks failed with jwks uri request: {e}"))?;
    Ok(jwks)
}
```
