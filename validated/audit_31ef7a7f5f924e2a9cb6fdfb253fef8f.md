# Audit Report

## Title
Unbounded RSA Modulus Size in Keyless Authentication Enables Validator CPU Exhaustion

## Summary
The keyless authentication system lacks validation on RSA modulus sizes when parsing JWKs for OpenIdSig verification. Attackers can install federated JWKs with extremely large RSA keys (e.g., 8192-bit moduli) and submit transactions that force all validators to perform computationally expensive signature verifications before any gas is charged, causing significant CPU exhaustion.

## Finding Description

The Aptos keyless authentication system supports two signature verification paths: ZeroKnowledgeSig (using ZK proofs) and OpenIdSig (using direct RSA signature verification). While the ZK path enforces a 256-byte (2048-bit) RSA modulus size constraint, the OpenIdSig path has no such validation.

**Missing Validation in JWK Parsing:**

When JWKs are parsed, the `TryFrom<&serde_json::Value>` implementation for `RSA_JWK` extracts the modulus `n` field as a raw string without any size validation. [1](#0-0) 

The only RSA modulus size validation exists in `to_poseidon_scalar()`, which explicitly checks for the "circuit-supported RSA modulus size" of 256 bytes (2048 bits) at the constant definition and validation logic. [2](#0-1) [3](#0-2)  However, this method is exclusively used for zero-knowledge proof verification, not for OpenIdSig verification.

**Vulnerable Signature Verification Path:**

For OpenIdSig-based keyless transactions, the signature verification uses `verify_signature_without_exp_check()` which directly calls `jsonwebtoken::decode()` with the unvalidated RSA key components. [4](#0-3) 

This verification is invoked through `OpenIdSig::verify_jwt_signature()` during transaction validation. [5](#0-4) 

The critical issue is that keyless authenticator validation occurs during `validate_signed_transaction()` BEFORE the transaction prologue executes. [6](#0-5)  The code explicitly enforces this ordering with a comment stating "The prologue MUST be run AFTER any validation." [7](#0-6) 

Gas checking only happens inside `run_prologue_with_payload()`, which is called after validation. [8](#0-7) 

This means expensive RSA signature verification with large keys is performed before any gas is charged.

**Attack Path:**

1. Any user can call the public entry function `update_federated_jwk_set()` to install custom JWKs at their own address. [9](#0-8) 

2. The only constraints are that JWKs cannot be installed at the `@aptos_framework` address [10](#0-9)  and the BCS-serialized size must be under 2 KiB (2048 bytes). [11](#0-10) [12](#0-11) 

3. An 8192-bit RSA modulus encodes to approximately 1365 base64url characters (1024 bytes × 4/3 encoding overhead), which fits within the 2 KiB limit along with other JWK fields.

4. The attacker creates federated keyless accounts using these oversized JWKs and submits transactions with OpenIdSig signatures.

5. During validation, federated JWKs are retrieved from the attacker's address and used for signature verification. [13](#0-12)  The expensive RSA verification occurs here. [14](#0-13) 

6. All validators processing blocks containing these transactions must perform the expensive RSA signature verification before any gas is charged.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria: "Validator node slowdowns."

RSA signature verification computational cost scales approximately quadratically with key size. An 8192-bit RSA key is 4x larger than the standard 2048-bit key, resulting in approximately 16x slower verification. This creates an asymmetric resource exhaustion attack where:

- The attacker pays only normal transaction gas costs
- Validators incur significantly higher CPU costs for signature verification  
- The verification happens before gas charging in the transaction validation phase
- Multiple transactions can be submitted to continuously exhaust validator CPU resources
- All validators in the network are affected when processing blocks containing such transactions

This breaks the fundamental Resource Limits invariant: signature verification cost is unbounded and not reflected in gas consumption, allowing attackers to impose disproportionate computational burden on validators.

## Likelihood Explanation

**Likelihood: High**

The attack is straightforward to execute with no special privileges required:
- `update_federated_jwk_set()` is a public entry function callable by any user
- No compromises of trusted OIDC providers needed
- Attacker has full control over federated JWK installation at their own address
- The 2 KiB serialization limit accommodates 8192-bit RSA keys
- Can be repeated arbitrarily by submitting multiple transactions
- Standard cryptographic libraries easily generate large RSA keys
- The attacker only needs to control a simple OIDC provider to sign JWTs

## Recommendation

Add RSA modulus size validation when parsing JWKs for OpenIdSig verification:

1. **In JWK Parsing**: Modify the `TryFrom<&serde_json::Value>` implementation for `RSA_JWK` to validate that the base64url-decoded modulus `n` does not exceed a maximum size (e.g., 256 bytes for 2048-bit RSA).

2. **In Federated JWK Installation**: Add validation in `patch_federated_jwks()` or `update_federated_jwk_set()` to check RSA modulus sizes before allowing JWK installation.

3. **In Signature Verification**: Add an early check in `verify_signature_without_exp_check()` to reject RSA keys exceeding the maximum supported modulus size.

The recommended maximum should match the ZK path constraint: 256 bytes (2048-bit RSA), which provides adequate security while preventing computational DoS attacks.

## Proof of Concept

```move
// PoC: Install 8192-bit RSA JWK and submit transaction
// Step 1: Generate 8192-bit RSA key offline
// Step 2: Call update_federated_jwk_set with large modulus
script {
    use aptos_framework::jwks;
    use std::string::utf8;
    
    fun install_large_jwk(attacker: &signer) {
        // 8192-bit RSA modulus (1024 bytes) encoded as base64url
        let large_n = utf8(b"<1365-character base64url string>");
        
        jwks::update_federated_jwk_set(
            attacker,
            b"https://attacker-oidc.com",
            vector[utf8(b"large-key-id")],
            vector[utf8(b"RS256")],
            vector[utf8(b"AQAB")],
            vector[large_n]
        );
    }
}
```

```rust
// Step 3: Create federated keyless account pointing to attacker's address
// Step 4: Submit transaction with OpenIdSig using the large RSA key
// Result: All validators perform expensive 8192-bit RSA verification
//         before any gas is charged, causing CPU exhaustion
```

### Citations

**File:** types/src/jwks/rsa/mod.rs (L54-54)
```rust
    pub const RSA_MODULUS_BYTES: usize = 256;
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

**File:** types/src/jwks/rsa/mod.rs (L132-178)
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1798-1811)
```rust
        let keyless_authenticators = aptos_types::keyless::get_authenticators(transaction)
            .map_err(|_| VMStatus::error(StatusCode::INVALID_SIGNATURE, None))?;

        // If there are keyless TXN authenticators, validate them all.
        if !keyless_authenticators.is_empty() && !self.is_simulation {
            keyless_validation::validate_authenticators(
                self.environment().keyless_pvk(),
                self.environment().keyless_configuration(),
                &keyless_authenticators,
                self.features(),
                session.resolver,
                module_storage,
            )?;
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1932-1939)
```rust
        // The prologue MUST be run AFTER any validation. Otherwise you may run prologue and hit
        // SEQUENCE_NUMBER_TOO_NEW if there is more than one transaction from the same sender and
        // end up skipping validation.
        let executable = transaction
            .executable_ref()
            .map_err(|_| deprecated_module_bundle!())?;
        let extra_config = transaction.extra_config();
        self.run_prologue_with_payload(
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2805-2814)
```rust
        check_gas(
            self.gas_params(log_context)?,
            self.gas_feature_version(),
            session.resolver,
            module_storage,
            txn_data,
            self.features(),
            is_approved_gov_script,
            log_context,
        )?;
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L33-33)
```text
    const MAX_FEDERATED_JWKS_SIZE_BYTES: u64 = 2 * 1024; // 2 KiB
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L185-187)
```text
        assert!(!system_addresses::is_aptos_framework_address(signer::address_of(jwk_owner)),
            error::invalid_argument(EINSTALL_FEDERATED_JWKS_AT_APTOS_FRAMEWORK)
        );
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L200-202)
```text
        // TODO: Can we check the size more efficiently instead of serializing it via BCS?
        let num_bytes = vector::length(&bcs::to_bytes(fed_jwks));
        assert!(num_bytes < MAX_FEDERATED_JWKS_SIZE_BYTES, error::invalid_argument(EFEDERATED_JWKS_TOO_LARGE));
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

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L244-254)
```rust
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
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L391-395)
```rust
                    openid_sig
                        .verify_jwt_signature(rsa_jwk, &signature.jwt_header_json)
                        .map_err(|_| {
                            invalid_signature!("RSA signature verification failed for OpenIdSig")
                        })?;
```
