# Audit Report

## Title
Weak RSA JWK Acceptance in Validator Transactions Enables Keyless Account Compromise

## Summary
The `ValidatorTransaction::ObservedJWKUpdate` variant accepts JWKs without validating their cryptographic parameters. The `verify()` method returns `Ok(())` without checking RSA modulus size or key strength, allowing weak JWKs (< 2048 bits) to be stored on-chain and used for keyless account authentication. This enables attackers who can factor weak RSA keys to forge JWT signatures and steal funds from affected keyless accounts. [1](#0-0) 

## Finding Description

The vulnerability exists in the validator transaction verification flow for JWK updates. When validators observe JWK updates from OIDC providers (Google, Apple, etc.) and submit them as `ValidatorTransaction::ObservedJWKUpdate`, the system performs no cryptographic validation of the JWK parameters themselves.

**Attack Flow:**

1. **Weak JWK Injection**: A `QuorumCertifiedUpdate` containing weak RSA JWKs (e.g., 1024-bit modulus) is submitted. This could occur if:
   - An OIDC provider is compromised and rotates to weak keys
   - An OIDC provider mistakenly deploys weak keys
   - Validators observe these weak keys through normal operation

2. **Missing Validation**: The `verify()` method for `ObservedJWKUpdate` simply returns `Ok(())` without any validation: [2](#0-1) 

3. **Processing Without Parameter Checks**: The `process_jwk_update_inner` function validates version correctness, voting power, and multi-signature, but does NOT validate RSA modulus size or key strength: [3](#0-2) 

4. **On-Chain Storage**: Weak JWKs are stored on-chain via `upsert_into_observed_jwks` without any cryptographic parameter validation: [4](#0-3) 

5. **Vulnerable Usage**: The weak JWKs are then used to verify JWT signatures for ZKless keyless accounts. The `verify_signature_without_exp_check` method uses `jsonwebtoken::decode` which does not enforce minimum RSA key sizes: [5](#0-4) 

6. **Signature Verification**: For OpenIdSig certificates (ZKless keyless), the weak JWK is used directly for RSA signature verification: [6](#0-5) 

7. **Exploitation**: An attacker who factors the weak RSA modulus can forge JWT signatures and steal funds from all keyless accounts using that weak JWK.

**Note on ZK vs ZKless Paths**: The ZK proof path (Groth16) is protected because `to_poseidon_scalar()` enforces exactly 2048-bit keys: [7](#0-6) 

However, ZKless keyless accounts (OpenIdSig) have no such protection and are fully vulnerable.

## Impact Explanation

**Severity: HIGH** (Up to $50,000 per Aptos Bug Bounty)

This vulnerability enables **fund theft from ZKless keyless accounts**:

1. **Direct Fund Loss**: All ZKless keyless accounts relying on a weak JWK can be compromised
2. **Multi-Account Impact**: A single weak JWK from a popular OIDC provider affects all users of that provider
3. **Persistent Vulnerability**: Once on-chain, weak JWKs remain until governance removes them
4. **No User Defense**: Users have no way to protect themselves if their OIDC provider's JWK is weak

While this requires an external OIDC provider to deploy weak keys (through compromise or error), **defense-in-depth principles require that Aptos validate JWK strength** rather than blindly trusting external providers. The protocol should protect users even when external dependencies fail.

The impact is limited from Critical to High because:
- Requires weak JWK deployment by OIDC provider (external factor)
- Only affects ZKless keyless accounts (ZK accounts are protected)
- Requires attacker to successfully factor the weak RSA key

## Likelihood Explanation

**Likelihood: MEDIUM**

The likelihood depends on external factors:

1. **OIDC Provider Compromise/Error**: While major providers (Google, Apple) have strong security, smaller or newer OIDC providers might:
   - Deploy keys below recommended sizes
   - Suffer security compromises leading to weak key deployment
   - Have legacy systems with weak keys

2. **Validator Observation**: Validators correctly observe and certify whatever JWKs the OIDC provider presents

3. **Attacker Capability**: Factoring 1024-bit RSA keys is feasible for well-resourced attackers; smaller keys are trivial

Historical precedent: Multiple real-world incidents have involved RSA keys below 2048 bits, and several OIDC providers have had security incidents.

## Recommendation

Add cryptographic parameter validation in the `verify()` method for `ValidatorTransaction::ObservedJWKUpdate`:

```rust
pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
    match self {
        ValidatorTransaction::DKGResult(dkg_result) => dkg_result
            .verify(verifier)
            .context("DKGResult verification failed"),
        ValidatorTransaction::ObservedJWKUpdate(jwk_update) => {
            // Validate JWK cryptographic parameters
            for jwk_move_struct in &jwk_update.update.jwks {
                let jwk = jwks::jwk::JWK::try_from(jwk_move_struct)
                    .context("Failed to parse JWK")?;
                
                match jwk {
                    jwks::jwk::JWK::RSA(rsa_jwk) => {
                        // Decode and check modulus size
                        let modulus = base64::decode_config(&rsa_jwk.n, base64::URL_SAFE_NO_PAD)
                            .context("Failed to decode RSA modulus")?;
                        
                        const MIN_RSA_MODULUS_BYTES: usize = 256; // 2048 bits
                        ensure!(
                            modulus.len() >= MIN_RSA_MODULUS_BYTES,
                            "RSA modulus too small: {} bytes (minimum {} bytes required)",
                            modulus.len(),
                            MIN_RSA_MODULUS_BYTES
                        );
                        
                        // Additional validation: check for known weak exponents
                        let exponent = base64::decode_config(&rsa_jwk.e, base64::URL_SAFE_NO_PAD)
                            .context("Failed to decode RSA exponent")?;
                        ensure!(
                            !exponent.is_empty(),
                            "RSA exponent cannot be empty"
                        );
                    },
                    jwks::jwk::JWK::Unsupported(_) => {
                        // Unsupported JWKs are allowed (may be delete commands)
                    },
                }
            }
            Ok(())
        },
    }
}
```

Additionally, add validation in `process_jwk_update_inner` as a defense-in-depth measure before the multi-signature check.

## Proof of Concept

```rust
#[test]
fn test_weak_rsa_jwk_rejection() {
    use aptos_types::{
        jwks::{QuorumCertifiedUpdate, ProviderJWKs, jwk::JWKMoveStruct, rsa::RSA_JWK},
        validator_txn::ValidatorTransaction,
        validator_verifier::ValidatorVerifier,
        aggregate_signature::AggregateSignature,
    };
    use aptos_crypto::bls12381;
    
    // Create a weak RSA JWK with 1024-bit modulus (128 bytes)
    let weak_jwk = RSA_JWK {
        kid: "weak-key-1".to_string(),
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        e: "AQAB".to_string(),
        // Base64-encoded 1024-bit (128 byte) modulus
        n: base64::encode_config(&vec![0xFF; 128], base64::URL_SAFE_NO_PAD),
    };
    
    let provider_jwks = ProviderJWKs {
        issuer: b"https://accounts.google.com".to_vec(),
        version: 1,
        jwks: vec![JWKMoveStruct::from(weak_jwk)],
    };
    
    let update = QuorumCertifiedUpdate {
        update: provider_jwks,
        multi_sig: AggregateSignature::empty(), // Simplified for PoC
    };
    
    let validator_txn = ValidatorTransaction::ObservedJWKUpdate(update);
    
    // Create a simple validator verifier
    let verifier = ValidatorVerifier::new(vec![]); // Simplified for PoC
    
    // This should fail with the fix, but currently succeeds
    let result = validator_txn.verify(&verifier);
    
    // With the vulnerability, this passes
    assert!(result.is_ok()); // Current behavior
    
    // After fix, this should fail:
    // assert!(result.is_err());
    // assert!(result.unwrap_err().to_string().contains("RSA modulus too small"));
}
```

## Notes

The vulnerability specifically affects **ZKless keyless accounts** using the OpenIdSig certificate type, as the ZK proof path enforces 2048-bit minimum through the circuit constraints. However, ZKless keyless is an active feature as documented in the features configuration.

The root cause is a missing validation layer that should enforce cryptographic best practices regardless of what external OIDC providers deploy. This follows defense-in-depth principles where each layer provides independent security guarantees.

### Citations

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

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L128-142)
```rust
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

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L460-505)
```text
    /// NOTE: It is assumed verification has been done to ensure each update is quorum-certified,
    /// and its `version` equals to the on-chain version + 1.
    public fun upsert_into_observed_jwks(fx: &signer, provider_jwks_vec: vector<ProviderJWKs>) acquires ObservedJWKs, PatchedJWKs, Patches {
        system_addresses::assert_aptos_framework(fx);
        let observed_jwks = borrow_global_mut<ObservedJWKs>(@aptos_framework);

        if (features::is_jwk_consensus_per_key_mode_enabled()) {
            vector::for_each(provider_jwks_vec, |proposed_provider_jwks|{
                let maybe_cur_issuer_jwks = remove_issuer(&mut observed_jwks.jwks, proposed_provider_jwks.issuer);
                let cur_issuer_jwks = if (option::is_some(&maybe_cur_issuer_jwks)) {
                    option::extract(&mut maybe_cur_issuer_jwks)
                } else {
                    ProviderJWKs {
                        issuer: proposed_provider_jwks.issuer,
                        version: 0,
                        jwks: vector[],
                    }
                };
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
                });
                cur_issuer_jwks.version = cur_issuer_jwks.version + 1;
                upsert_provider_jwks(&mut observed_jwks.jwks, cur_issuer_jwks);
            });
        } else {
            vector::for_each(provider_jwks_vec, |provider_jwks| {
                upsert_provider_jwks(&mut observed_jwks.jwks, provider_jwks);
            });
        };

        let epoch = reconfiguration::current_epoch();
        emit(ObservedJWKsUpdated { epoch, jwks: observed_jwks.jwks });
        regenerate_patched_jwks();
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

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L368-398)
```rust
        EphemeralCertificate::OpenIdSig(openid_sig) => {
            match jwk {
                JWK::RSA(rsa_jwk) => {
                    openid_sig
                        .verify_jwt_claims(
                            signature.exp_date_secs,
                            &signature.ephemeral_pubkey,
                            public_key.inner_keyless_pk(),
                            config,
                        )
                        .map_err(|_| invalid_signature!("OpenID claim verification failed"))?;

                    // TODO(OpenIdSig): Implement batch verification for all RSA signatures in
                    //  one TXN.
                    // Note: Individual OpenID RSA signature verification will be fast when the
                    // RSA public exponent is small (e.g., 65537). For the same TXN, batch
                    // verification of all RSA signatures will be even faster even when the
                    // exponent is the same. Across different TXNs, batch verification will be
                    // (1) more difficult to implement and (2) not very beneficial since, when
                    // it fails, bad signature identification will require re-verifying all
                    // signatures assuming an adversarial batch.
                    //
                    // We are now ready to verify the RSA signature
                    openid_sig
                        .verify_jwt_signature(rsa_jwk, &signature.jwt_header_json)
                        .map_err(|_| {
                            invalid_signature!("RSA signature verification failed for OpenIdSig")
                        })?;
                },
                JWK::Unsupported(_) => return Err(invalid_signature!("JWK is not supported")),
            }
```
