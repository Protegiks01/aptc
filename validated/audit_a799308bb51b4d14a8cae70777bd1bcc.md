# Audit Report

## Title
Weak RSA Key Validation Bypass in Federated Keyless Accounts Enables Signature Forgery and Fund Theft

## Summary
The Aptos keyless authentication system fails to validate RSA key cryptographic parameters (modulus size, exponent value) for federated JWKs during OpenID signature verification. This allows attackers to factor weak RSA keys installed by federated keyless dapp owners and forge valid transaction signatures, leading to complete account compromise and fund theft.

## Finding Description

The vulnerability exists in the OpenID signature verification path for federated keyless accounts. When a federated keyless dapp owner installs JWKs via `update_federated_jwk_set`, no cryptographic validation is performed on the RSA parameters. [1](#0-0) 

The `new_rsa_jwk` function creates RSA_JWK structs without any validation of modulus size or exponent value: [2](#0-1) 

During signature verification, the `RSA_JWK::verify_signature_without_exp_check` method directly uses `DecodingKey::from_rsa_components` without validating key strength: [3](#0-2) 

While `RSA_JWK::to_poseidon_scalar` validates that the modulus is exactly 256 bytes (2048 bits), this validation only occurs for ZK proof verification, NOT for OpenIdSig verification: [4](#0-3) 

The ZK proof path calls `get_public_inputs_hash` which invokes `to_poseidon_scalar`: [5](#0-4) 

However, the OpenIdSig verification path calls `verify_jwt_signature` which bypasses modulus size checks entirely: [6](#0-5) [7](#0-6) 

**Attack Path:**

1. Malicious or negligent federated dapp owner installs weak RSA keys (512-bit modulus or e=3 exponent) via `update_federated_jwk_set`
2. Users create federated keyless accounts under this dapp
3. Attacker observes a legitimate transaction from a target user, extracting from the public OpenIdSig struct:
   - pepper, uid_key, epk_blinder, jwt_payload_json (which contains iss, aud, sub/email) [8](#0-7) 

4. Attacker factors the weak RSA private key (512-bit RSA is factorable in reasonable time with commodity hardware)
5. Attacker generates new ephemeral keypair
6. Attacker crafts malicious JWT matching all observed claims and signs with factored RSA private key
7. Attacker constructs KeylessSignature with forged OpenIdSig reusing observed pepper and uid_key
8. Transaction passes all verification checks because JWT signature verification accepts the weak RSA key

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability enables **Loss of Funds** through complete authentication bypass:

- **Direct fund theft**: Attackers can drain all funds from compromised federated keyless accounts
- **Scale**: Affects ALL users of any federated keyless dapp using weak RSA keys
- **Irreversibility**: Once funds are stolen, recovery requires governance intervention or is impossible
- **Authentication bypass**: Complete compromise of the keyless authentication system for affected accounts

This aligns with Aptos Bug Bounty Category 1: "Loss of Funds (Critical)" - Direct theft of APT or other tokens.

The vulnerability breaks the **Cryptographic Correctness** invariant by allowing cryptographically weak RSA keys to be used for signature verification, enabling signature forgery attacks.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Factors increasing likelihood:**
- Federated keyless is a new feature (AIP-96), dapp developers may not understand RSA security requirements
- No validation warnings prevent weak keys from being installed
- The `patch_federated_jwks` function only checks size limits, not cryptographic strength
- 512-bit RSA can be factored with commodity hardware in hours/days
- RSA with e=3 is vulnerable to cube-root attacks
- All required attack parameters (pepper, uid_key, epk_blinder, jwt_payload_json) are publicly observable in transaction signatures
- uid_val often corresponds to public email addresses [9](#0-8) 

**Factors decreasing likelihood:**
- Requires a federated dapp to install weak keys (not all dapps will)
- Requires attacker to observe at least one transaction from target user
- Limited to federated keyless accounts (not regular keyless accounts using governance-controlled JWKs)

**Overall Assessment:** Given the lack of validation and potential for developer error with a new feature, this is likely to occur in production, especially as federated keyless adoption grows.

## Recommendation

Add RSA key strength validation in `patch_federated_jwks` and `new_rsa_jwk`:

1. **Validate modulus size**: Require RSA modulus to be exactly 256 bytes (2048 bits) for all JWK installations
2. **Validate exponent value**: Only accept e="AQAB" (65537) and reject weak exponents like e=3
3. **Apply validation consistently**: Ensure both ZK proof path and OpenIdSig path validate key strength

Add validation in `new_rsa_jwk` in jwks.move:
```move
public fun new_rsa_jwk(kid: String, alg: String, e: String, n: String): JWK {
    // Validate exponent is AQAB (65537)
    assert!(e == utf8(b"AQAB"), error::invalid_argument(EWEAK_RSA_EXPONENT));
    
    // Validate modulus size is 256 bytes when base64-decoded
    // (This requires adding native validation function)
    
    JWK {
        variant: copyable_any::pack(RSA_JWK {
            kid,
            kty: utf8(b"RSA"),
            e,
            n,
            alg,
        }),
    }
}
```

Additionally, add validation in `verify_signature_without_exp_check` as a defense-in-depth measure to validate key strength at signature verification time.

## Proof of Concept

While a full PoC requires factoring an RSA key, the vulnerability can be demonstrated by:

1. Deploy a test federated dapp that calls `update_federated_jwk_set` with a 512-bit RSA modulus
2. Create a federated keyless account using this dapp's jwk_addr
3. Submit a transaction with OpenIdSig
4. Observe that the transaction is accepted despite the weak RSA key

The lack of validation can be verified by code inspection showing no checks in the installation or verification paths for OpenIdSig.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L183-203)
```text
    public fun patch_federated_jwks(jwk_owner: &signer, patches: vector<Patch>) acquires FederatedJWKs {
        // Prevents accidental calls in 0x1::jwks that install federated JWKs at the Aptos framework address.
        assert!(!system_addresses::is_aptos_framework_address(signer::address_of(jwk_owner)),
            error::invalid_argument(EINSTALL_FEDERATED_JWKS_AT_APTOS_FRAMEWORK)
        );

        let jwk_addr = signer::address_of(jwk_owner);
        if (!exists<FederatedJWKs>(jwk_addr)) {
            move_to(jwk_owner, FederatedJWKs { jwks: AllProvidersJWKs { entries: vector[] } });
        };

        let fed_jwks = borrow_global_mut<FederatedJWKs>(jwk_addr);
        vector::for_each_ref(&patches, |obj|{
            let patch: &Patch = obj;
            apply_patch(&mut fed_jwks.jwks, *patch);
        });

        // TODO: Can we check the size more efficiently instead of serializing it via BCS?
        let num_bytes = vector::length(&bcs::to_bytes(fed_jwks));
        assert!(num_bytes < MAX_FEDERATED_JWKS_SIZE_BYTES, error::invalid_argument(EFEDERATED_JWKS_TOO_LARGE));
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L258-277)
```text
    public entry fun update_federated_jwk_set(jwk_owner: &signer, iss: vector<u8>, kid_vec: vector<String>, alg_vec: vector<String>, e_vec: vector<String>, n_vec: vector<String>) acquires FederatedJWKs {
        assert!(!vector::is_empty(&kid_vec), error::invalid_argument(EINVALID_FEDERATED_JWK_SET));
        let num_jwk = vector::length<String>(&kid_vec);
        assert!(vector::length(&alg_vec) == num_jwk , error::invalid_argument(EINVALID_FEDERATED_JWK_SET));
        assert!(vector::length(&e_vec) == num_jwk, error::invalid_argument(EINVALID_FEDERATED_JWK_SET));
        assert!(vector::length(&n_vec) == num_jwk, error::invalid_argument(EINVALID_FEDERATED_JWK_SET));

        let remove_all_patch = new_patch_remove_all();
        let patches = vector[remove_all_patch];
        while (!vector::is_empty(&kid_vec)) {
            let kid = vector::pop_back(&mut kid_vec);
            let alg = vector::pop_back(&mut alg_vec);
            let e = vector::pop_back(&mut e_vec);
            let n = vector::pop_back(&mut n_vec);
            let jwk = new_rsa_jwk(kid, alg, e, n);
            let patch = new_patch_upsert_jwk(iss, jwk);
            vector::push_back(&mut patches, patch)
        };
        patch_federated_jwks(jwk_owner, patches);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L414-424)
```text
    public fun new_rsa_jwk(kid: String, alg: String, e: String, n: String): JWK {
        JWK {
            variant: copyable_any::pack(RSA_JWK {
                kid,
                kty: utf8(b"RSA"),
                e,
                n,
                alg,
            }),
        }
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

**File:** types/src/jwks/rsa/mod.rs (L102-125)
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

        // This is done to match the circuit, which requires the modulus in a verify specific format
        // due to how RSA verification is implemented
        modulus.reverse();

        let mut scalars = modulus
            .chunks(24) // Pack 3 64 bit limbs per scalar, so chunk into 24 bytes per scalar
            .map(|chunk| {
                poseidon_bn254::keyless::pack_bytes_to_one_scalar(chunk)
                    .expect("chunk converts to scalar")
            })
            .collect::<Vec<ark_bn254::Fr>>();
        scalars.push(ark_bn254::Fr::from(Self::RSA_MODULUS_BYTES as i32));
        poseidon_bn254::hash_scalars(scalars)
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

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L368-399)
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
        },
```

**File:** types/src/keyless/openid_sig.rs (L20-38)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, Serialize)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct OpenIdSig {
    /// The decoded bytes of the JWS signature in the JWT (<https://datatracker.ietf.org/doc/html/rfc7515#section-3>)
    #[serde(with = "serde_bytes")]
    pub jwt_sig: Vec<u8>,
    /// The decoded/plaintext JSON payload of the JWT (<https://datatracker.ietf.org/doc/html/rfc7519#section-3>)
    pub jwt_payload_json: String,
    /// The name of the key in the claim that maps to the user identifier; e.g., "sub" or "email"
    pub uid_key: String,
    /// The random value used to obfuscate the EPK from OIDC providers in the nonce field
    #[serde(with = "serde_bytes")]
    pub epk_blinder: Vec<u8>,
    /// The privacy-preserving value used to calculate the identity commitment. It is typically uniquely derived from `(iss, client_id, uid_key, uid_val)`.
    pub pepper: Pepper,
    /// When an override aud_val is used, the signature needs to contain the aud_val committed in the
    /// IDC, since the JWT will contain the override.
    pub idc_aud_val: Option<String>,
}
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
