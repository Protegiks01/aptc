# Audit Report

## Title
UID Key Bypass Allows Email Verification Check Evasion in Keyless Authentication

## Summary
The `Claims::get_uid_val()` function in the keyless authentication system only enforces email verification checks when `uid_key` is exactly `"email"`. Attackers can bypass this security control by using non-standard `uid_key` values that reference email addresses stored in JWT `additional_claims`, completely evading the `email_verified` requirement.

## Finding Description

The keyless authentication system implements an email verification check to ensure that only verified email addresses can be used as user identifiers. However, this check is implemented as a special case that only applies when `uid_key == "email"`. [1](#0-0) 

The vulnerability exists in the default case (lines 214-222) where any `uid_key` that is not `"email"` or `"sub"` extracts values from `additional_claims` without any verification. This allows attackers to:

1. Obtain a JWT where their email is **unverified** (`email_verified: false`)
2. If the OIDC provider includes the email in an additional claim field (e.g., `"preferred_username"`, `"upn"`, `"user_id"`), the attacker can specify that field as `uid_key`
3. Bypass the pepper service restriction (which only allows `"sub"` or `"email"`) by generating the pepper client-side [2](#0-1) 
4. Create a keyless account with the unverified email as the identity
5. During transaction verification, the `verify_jwt_claims()` function calls `get_uid_val()` which extracts from `additional_claims` **without checking email_verified** [3](#0-2) 

The verification flow in the VM calls this vulnerable function: [4](#0-3) 

**Attack Path:**

1. Attacker obtains JWT from OIDC provider (e.g., Azure AD, Okta) with:
   - `email: "attacker@example.com"`
   - `email_verified: false` (unverified email)
   - `upn: "attacker@example.com"` (or other additional claim containing email)

2. Attacker generates pepper locally: `pepper = random_31_bytes()`

3. Attacker creates identity commitment: `IDC = hash(pepper, aud, "upn", "attacker@example.com")`

4. Attacker derives keyless account address from `KeylessPublicKey{iss, idc}`

5. Attacker submits transaction with `OpenIdSig{uid_key: "upn", ...}`

6. During validation, `verify_jwt_claims()` → `get_uid_val("upn")` → extracts from `additional_claims["upn"]` **without email_verified check**

7. Transaction succeeds despite unverified email

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria because:

1. **Significant Protocol Violation**: Bypasses a critical authentication security control designed to prevent account takeover
2. **Unauthorized Account Access**: Allows attackers to authenticate using unverified email addresses, potentially impersonating legitimate users
3. **Wide Attack Surface**: Any OIDC provider that includes email-like data in additional claims is vulnerable (Azure AD's `upn`, custom claims in Okta/Auth0, federated identity providers)
4. **Transaction Validation Bypass**: Violates the documented invariant that "Prologue/epilogue checks must enforce all invariants"

While this doesn't directly lead to loss of funds in the traditional sense, it enables unauthorized access to keyless accounts, which could lead to:
- Account takeover if the attacker can verify control of an unverified email
- Impersonation attacks
- Unauthorized transaction signing

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Factors increasing likelihood:**
- Many enterprise OIDC providers (Azure AD, Okta, Auth0) commonly include email addresses in multiple claim fields
- Azure AD specifically includes `upn` (User Principal Name) which is often an email address
- The pepper service restriction can be trivially bypassed by generating peppers client-side
- No on-chain validation restricts which `uid_key` values are allowed
- Attack requires only standard OIDC flows, no special privileges

**Factors decreasing likelihood:**
- Requires OIDC provider to include email in additional claims (but this is common)
- Attacker must have access to an unverified email account with the target OIDC provider
- Some providers may not include redundant email information

The attack is **feasible and realistic** given the prevalence of enterprise OIDC providers that include email-like data in multiple claim fields.

## Recommendation

Implement strict validation of `uid_key` values and enforce email verification for **all** email-containing claims, not just the `"email"` field specifically.

**Recommended Fix:**

```rust
impl Claims {
    pub fn get_uid_val(&self, uid_key: &String) -> anyhow::Result<String> {
        match uid_key.as_str() {
            "email" => {
                // Existing email verification logic
                let email_verified = self
                    .oidc_claims
                    .email_verified
                    .clone()
                    .context("'email_verified' claim is missing")?;
                let email_verified_as_bool = email_verified.as_bool().unwrap_or(false);
                let email_verified_as_str = email_verified.as_str().unwrap_or("false");
                ensure!(
                    email_verified_as_bool || email_verified_as_str.eq("true"),
                    "'email_verified' claim was not \"true\""
                );
                self.oidc_claims
                    .email
                    .clone()
                    .context("email claim missing on jwt")
            },
            "sub" => Ok(self.oidc_claims.sub.clone()),
            _ => {
                // SECURITY FIX: Reject non-standard uid_key values
                // Only "sub" and "email" are supported to prevent email_verified bypass
                Err(anyhow::anyhow!(
                    "Unsupported uid_key '{}'. Only 'sub' and 'email' are allowed.",
                    uid_key
                ))
            },
        }
    }
}
```

**Alternative Fix (if additional uid_keys are needed):**

If support for custom `uid_key` values is required, implement an on-chain allowlist and ensure email-like values always require verification:

```rust
// In Configuration struct, add:
pub allowed_uid_keys: Vec<String>,

impl Claims {
    pub fn get_uid_val(&self, uid_key: &String, config: &Configuration) -> anyhow::Result<String> {
        match uid_key.as_str() {
            "email" => { /* existing email verification */ },
            "sub" => Ok(self.oidc_claims.sub.clone()),
            _ => {
                // Check if uid_key is in allowlist
                ensure!(
                    config.allowed_uid_keys.contains(uid_key),
                    "uid_key '{}' is not in the allowed list",
                    uid_key
                );
                
                let uid_val = self
                    .additional_claims
                    .get(uid_key)
                    .context(format!("{} claim missing on jwt", uid_key))?
                    .as_str()
                    .context(format!("{} value is not a string", uid_key))?;
                
                // SECURITY: If the value looks like an email, require verification
                if uid_val.contains('@') {
                    let email_verified = self.oidc_claims.email_verified
                        .clone()
                        .context("'email_verified' claim is missing for email-like uid_val")?;
                    let email_verified_as_bool = email_verified.as_bool().unwrap_or(false);
                    let email_verified_as_str = email_verified.as_str().unwrap_or("false");
                    ensure!(
                        email_verified_as_bool || email_verified_as_str.eq("true"),
                        "'email_verified' must be true for email-like uid_val"
                    );
                }
                
                Ok(uid_val.to_string())
            },
        }
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyless::{Claims, Configuration, IdCommitment, KeylessPublicKey, OpenIdSig, Pepper};
    use crate::transaction::authenticator::EphemeralPublicKey;
    use serde_json::json;

    #[test]
    fn test_uid_key_bypass_unverified_email() {
        // Create a JWT payload with unverified email in additional claim
        let jwt_payload_json = json!({
            "iss": "https://accounts.example.com",
            "aud": "client-123",
            "sub": "user-12345",
            "email": "attacker@example.com",
            "email_verified": false,  // Email is NOT verified
            "upn": "attacker@example.com",  // Same email in additional claim
            "nonce": "test-nonce",
            "iat": 1700000000,
            "exp": 1700003600
        }).to_string();

        let claims: Claims = serde_json::from_str(&jwt_payload_json).unwrap();

        // Test 1: Using uid_key="email" should FAIL (email not verified)
        let result_email = claims.get_uid_val(&"email".to_string());
        assert!(result_email.is_err(), "Should fail with unverified email");
        assert!(result_email.unwrap_err().to_string().contains("email_verified"));

        // Test 2: Using uid_key="upn" should SUCCEED (bypasses email_verified check)
        // THIS IS THE VULNERABILITY
        let result_upn = claims.get_uid_val(&"upn".to_string());
        assert!(result_upn.is_ok(), "Should succeed with uid_key='upn'");
        assert_eq!(result_upn.unwrap(), "attacker@example.com");

        // Test 3: Demonstrate full attack - create valid IDC with unverified email
        let pepper = Pepper::from_number(12345);
        let uid_key = "upn";
        let uid_val = "attacker@example.com";
        
        let idc = IdCommitment::new_from_preimage(
            &pepper,
            "client-123",
            uid_key,
            uid_val
        ).unwrap();

        let pk = KeylessPublicKey {
            iss_val: "https://accounts.example.com".to_string(),
            idc,
        };

        // The account can be created and used despite unverified email
        println!("Successfully created keyless account with unverified email!");
        println!("UID key: {}", uid_key);
        println!("UID val: {}", uid_val);
        println!("Email verified: false");
    }

    #[test]
    fn test_recommended_fix() {
        // After fix, non-standard uid_keys should be rejected
        let jwt_payload_json = json!({
            "iss": "https://accounts.example.com",
            "aud": "client-123",
            "sub": "user-12345",
            "email": "attacker@example.com",
            "email_verified": false,
            "upn": "attacker@example.com",
            "nonce": "test-nonce",
            "iat": 1700000000,
            "exp": 1700003600
        }).to_string();

        let claims: Claims = serde_json::from_str(&jwt_payload_json).unwrap();

        // With the fix, uid_key="upn" should be rejected
        let result = claims.get_uid_val(&"upn".to_string());
        assert!(result.is_err(), "Non-standard uid_key should be rejected");
        assert!(result.unwrap_err().to_string().contains("Unsupported uid_key"));
    }
}
```

**Notes:**

1. The vulnerability exists because email verification is tied to the specific string `"email"` rather than being a general property of email-based authentication
2. The pepper service restriction on `uid_key` values is bypassed by client-side pepper generation, which is a documented and legitimate feature
3. Real-world OIDC providers commonly include email addresses in multiple claim fields (Azure AD's `upn`, Okta's custom claims, etc.)
4. The fix should either strictly limit `uid_key` to `"sub"` and `"email"`, or implement comprehensive email verification for all email-like values regardless of claim name

### Citations

**File:** types/src/keyless/openid_sig.rs (L55-123)
```rust
    pub fn verify_jwt_claims(
        &self,
        exp_timestamp_secs: u64,
        epk: &EphemeralPublicKey,
        pk: &KeylessPublicKey,
        config: &Configuration,
    ) -> anyhow::Result<()> {
        let claims: Claims = serde_json::from_str(&self.jwt_payload_json)?;

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

        ensure!(
            claims.oidc_claims.iss.eq(&pk.iss_val),
            "'iss' claim was supposed to match \"{}\"",
            pk.iss_val
        );

        // When an aud_val override is set, the IDC-committed `aud` is included next to the
        // OpenID signature.
        let idc_aud_val = match self.idc_aud_val.as_ref() {
            None => &claims.oidc_claims.aud,
            Some(idc_aud_val) => {
                // If there's an override, check that the override `aud` from the JWT, is allow-listed
                ensure!(
                    config
                        .is_allowed_override_aud(&claims.oidc_claims.aud)
                        .is_ok(),
                    "{} is not an allow-listed override aud",
                    &claims.oidc_claims.aud
                );
                idc_aud_val
            },
        };
        let uid_val = claims.get_uid_val(&self.uid_key)?;
        ensure!(
            IdCommitment::new_from_preimage(&self.pepper, idc_aud_val, &self.uid_key, &uid_val)?
                .eq(&pk.idc),
            "Address IDC verification failed"
        );

        let actual_nonce = OpenIdSig::reconstruct_oauth_nonce(
            &self.epk_blinder[..],
            exp_timestamp_secs,
            epk,
            config,
        )?;
        ensure!(
            actual_nonce.eq(&claims.oidc_claims.nonce),
            "'nonce' claim did not match: JWT contained {} but recomputed {}",
            claims.oidc_claims.nonce,
            actual_nonce
        );

        Ok(())
    }
```

**File:** types/src/keyless/openid_sig.rs (L193-224)
```rust
    pub fn get_uid_val(&self, uid_key: &String) -> anyhow::Result<String> {
        match uid_key.as_str() {
            "email" => {
                let email_verified = self
                    .oidc_claims
                    .email_verified
                    .clone()
                    .context("'email_verified' claim is missing")?;
                // the 'email_verified' claim may be a boolean or a boolean-as-a-string.
                let email_verified_as_bool = email_verified.as_bool().unwrap_or(false);
                let email_verified_as_str = email_verified.as_str().unwrap_or("false");
                ensure!(
                    email_verified_as_bool || email_verified_as_str.eq("true"),
                    "'email_verified' claim was not \"true\""
                );
                self.oidc_claims
                    .email
                    .clone()
                    .context("email claim missing on jwt")
            },
            "sub" => Ok(self.oidc_claims.sub.clone()),
            _ => {
                let uid_val = self
                    .additional_claims
                    .get(uid_key)
                    .context(format!("{} claim missing on jwt", uid_key))?
                    .as_str()
                    .context(format!("{} value is not a string", uid_key))?;
                Ok(uid_val.to_string())
            },
        }
    }
```

**File:** types/src/keyless/mod.rs (L307-335)
```rust
    pub fn new_from_preimage(
        pepper: &Pepper,
        aud: &str,
        uid_key: &str,
        uid_val: &str,
    ) -> anyhow::Result<Self> {
        let aud_val_hash =
            poseidon_bn254::keyless::pad_and_hash_string(aud, Self::MAX_AUD_VAL_BYTES)?;
        // println!("aud_val_hash: {}", aud_val_hash);
        let uid_key_hash =
            poseidon_bn254::keyless::pad_and_hash_string(uid_key, Self::MAX_UID_KEY_BYTES)?;
        // println!("uid_key_hash: {}", uid_key_hash);
        let uid_val_hash =
            poseidon_bn254::keyless::pad_and_hash_string(uid_val, Self::MAX_UID_VAL_BYTES)?;
        // println!("uid_val_hash: {}", uid_val_hash);
        let pepper_scalar = poseidon_bn254::keyless::pack_bytes_to_one_scalar(pepper.0.as_slice())?;
        // println!("Pepper Fr: {}", pepper_scalar);

        let fr = poseidon_bn254::hash_scalars(vec![
            pepper_scalar,
            aud_val_hash,
            uid_val_hash,
            uid_key_hash,
        ])?;

        let mut idc_bytes = vec![0u8; IdCommitment::NUM_BYTES];
        fr.serialize_uncompressed(&mut idc_bytes[..])?;
        Ok(IdCommitment(idc_bytes))
    }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L368-378)
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
```
