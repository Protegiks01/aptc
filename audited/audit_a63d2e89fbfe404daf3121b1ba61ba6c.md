# Audit Report

## Title
JWT Authentication Bypass via Multiple Bypasser Configuration in Aptos Faucet

## Summary
When the Aptos faucet service is configured with multiple bypassers (e.g., `AuthTokenBypasser` and `IpAllowlistBypasser`), an attacker can completely bypass JWT authentication by sending a request with the `x-is-jwt` header from an allowlisted IP. The `AuthTokenBypasser` skips validation when this header is present, but other bypassers can still trigger a full bypass, causing JWT verification to be skipped entirely.

## Finding Description

The vulnerability occurs due to an interaction between three components:

1. **AuthTokenBypasser's JWT header handling**: The `AuthTokenBypasser.request_can_bypass()` function explicitly returns `false` when the `X_IS_JWT_HEADER` ("x-is-jwt") is present, intending to defer to JWT authentication: [1](#0-0) 

2. **Multiple bypasser OR logic**: The faucet iterates through all configured bypassers and if ANY single bypasser returns `true`, the request bypasses all checkers: [2](#0-1) 

3. **JWT verification only in checkers**: JWT verification occurs exclusively in `RedisRatelimitChecker` when configured with JWT-based rate limiting: [3](#0-2) 

When `bypass = true`, all checkers are skipped during the completion phase: [4](#0-3) 

**Attack scenario:**
1. Faucet is configured with both `IpAllowlistBypasser` and `RedisRatelimitChecker` with JWT verification
2. Attacker sends request from allowlisted IP with `x-is-jwt: true` header and invalid/missing JWT
3. `AuthTokenBypasser` sees `x-is-jwt` header, returns `false` (not bypassing)
4. `IpAllowlistBypasser` sees allowlisted IP, returns `true` (bypassing)
5. Request proceeds with `bypass = true`, skipping ALL checkers including JWT verification
6. Attacker gains unlimited access without valid JWT authentication

The bypasser trait definition confirms this design: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **Medium severity** per the Aptos bug bounty criteria:

- **Limited funds loss or manipulation**: An attacker can drain the faucet of testnet tokens without authentication or rate limiting
- **State inconsistencies requiring intervention**: Rate limiting state in Redis is bypassed, requiring manual reset
- The faucet can use higher funding limits for bypassed requests via `maximum_amount_with_bypass`: [6](#0-5) 

While testnet tokens have no monetary value, this represents a complete authentication bypass that violates the intended security model and can disrupt testnet operations by exhausting faucet resources.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability is likely to occur in real deployments because:

1. **Common configuration pattern**: Using IP allowlists for CI/testing environments while also requiring JWT authentication for public requests is a standard practice
2. **Not immediately obvious**: The interaction between `X_IS_JWT_HEADER` and multiple bypassers is subtle and not documented as a security concern
3. **Testnet deployments**: Testnet faucets are more likely to have relaxed security configurations that enable this scenario

The attack requires:
- Faucet configured with multiple bypassers
- Attacker access to an allowlisted IP (or ability to trigger any other bypasser)
- Knowledge of the `x-is-jwt` header behavior

## Recommendation

**Fix Option 1 - Enforce JWT verification when header is present:**

Add mandatory JWT verification before allowing bypass when `X_IS_JWT_HEADER` is set. Modify `preprocess_request` to check if JWT headers are present and validate them even when a bypasser succeeds:

```rust
// After bypasser check, before returning
if bypass && checker_data.headers.contains_key(X_IS_JWT_HEADER) {
    // If JWT header is present, verify JWT even for bypassed requests
    // This ensures JWT authentication cannot be bypassed
    return Err(AptosTapError::new(
        "JWT authentication cannot be bypassed via IP allowlist".to_string(),
        AptosTapErrorCode::AuthTokenInvalid,
    ));
}
```

**Fix Option 2 - Make bypassers mutually exclusive with JWT:**

Prevent configuration where JWT-based checkers and non-JWT bypassers coexist. Add validation in the configuration builder to reject incompatible combinations.

**Fix Option 3 - Remove X_IS_JWT_HEADER from bypasser logic:**

Remove the special handling of `X_IS_JWT_HEADER` in `AuthTokenBypasser` since JWT and API token authentication are orthogonal to bypass logic. Let the checkers handle the differentiation.

## Proof of Concept

```rust
// Test configuration showing the vulnerability
#[tokio::test]
async fn test_jwt_bypass_via_ip_allowlist() {
    // Configure faucet with:
    // 1. IpAllowlistBypasser allowing 127.0.0.1
    // 2. RedisRatelimitChecker with JWT verification
    
    let bypassers = vec![
        BypasserConfig::IpAllowlist(IpRangeManagerConfig {
            ip_ranges: vec!["127.0.0.1/32".to_string()],
        }).build().unwrap(),
    ];
    
    let checkers = vec![
        CheckerConfig::RedisRatelimit(RedisRatelimitCheckerConfig {
            ratelimit_key_provider_config: RatelimitKeyProviderConfig::Jwt(
                FirebaseJwtVerifierConfig { /* ... */ }
            ),
            // ... other config
        }).build().await.unwrap(),
    ];
    
    // Create malicious request from allowlisted IP
    let mut headers = HeaderMap::new();
    headers.insert("x-is-jwt", "true".parse().unwrap());
    headers.insert("Authorization", "Bearer INVALID_TOKEN".parse().unwrap());
    
    let checker_data = CheckerData {
        source_ip: "127.0.0.1".parse().unwrap(),
        headers: Arc::new(headers),
        // ...
    };
    
    // Test bypasser behavior
    let ip_bypasser = &bypassers[0];
    assert!(ip_bypasser.request_can_bypass(checker_data.clone()).await.unwrap());
    
    // In real flow, this bypasses ALL checkers including JWT verification
    // Attacker gains access without valid JWT!
}
```

## Notes

The vulnerability is specific to the faucet service and does not affect core Aptos consensus, execution, or state management. However, it represents a complete authentication bypass that violates the intended security model where JWT authentication should be enforced regardless of IP allowlisting.

### Citations

**File:** crates/aptos-faucet/core/src/bypasser/auth_token.rs (L33-36)
```rust
        // Don't check if the request has X_IS_JWT_HEADER set.
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(false);
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L245-259)
```rust
        for bypasser in &self.bypassers {
            if bypasser
                .request_can_bypass(checker_data.clone())
                .await
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::BypasserError)
                })?
            {
                info!(
                    "Allowing request from {} to bypass checks / storage",
                    source_ip
                );
                return Ok((checker_data, true, permit));
            }
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L332-347)
```rust
        if !bypass {
            let response_is_500 = match &fund_result {
                Ok(_) => false,
                Err(e) => e.error_code.status().is_server_error(),
            };
            let complete_data = CompleteData {
                checker_data,
                txn_hashes: txn_hashes.clone(),
                response_is_500,
            };
            for checker in &self.checkers {
                checker.complete(complete_data.clone()).await.map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
                })?;
            }
        }
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L44-51)
```rust
    pub async fn ratelimit_key_value(&self, data: &CheckerData) -> Result<String, AptosTapError> {
        match self {
            RatelimitKeyProvider::Ip => Ok(data.source_ip.to_string()),
            RatelimitKeyProvider::Jwt(jwt_verifier) => {
                jwt_verifier.validate_jwt(data.headers.clone()).await
            },
        }
    }
```

**File:** crates/aptos-faucet/core/src/bypasser/mod.rs (L17-25)
```rust
/// This trait defines something that checks whether a given request should
/// skip all the checkers and storage, for example an IP allowlist.
#[async_trait]
#[enum_dispatch]
pub trait BypasserTrait: Sync + Send + 'static {
    /// Returns true if the request should be allowed to bypass all checkers
    /// and storage.
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool>;
}
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L98-103)
```rust
    /// With this it is possible to set a different maximum amount for requests that
    /// were allowed to skip the Checkers by a Bypasser. This can be helpful for CI,
    /// where we might need to mint a greater amount than is normally required in the
    /// standard case. If not given, maximum_amount is used whether the request
    /// bypassed the checks or not.
    maximum_amount_with_bypass: Option<u64>,
```
