# Audit Report

## Title
Authentication Bypass in Aptos Faucet via X-IS-JWT Header Presence Check

## Summary
The `AuthTokenChecker` in the Aptos faucet service contains an authentication bypass vulnerability where it only checks for the presence of the `x-is-jwt` header using `contains_key()` without validating its value, allowing attackers to bypass bearer token authentication entirely by setting this header to any value.

## Finding Description

The `AuthTokenChecker.check()` function is designed to validate bearer tokens from the Authorization header. However, it contains a flawed bypass mechanism for JWT authentication. [1](#0-0) 

This code only verifies that the `X_IS_JWT_HEADER` exists in the request headers, not its value. An attacker can set this header to any arbitrary data (including non-UTF8 binary data, empty string, "false", or random values) to completely bypass the bearer token validation that follows.

The proper validation of this header should check that its value equals "true" (case-insensitive), as implemented correctly in the JWT validation logic: [2](#0-1) 

**Attack Flow:**
1. Attacker sends request to faucet with `x-is-jwt: anythinghere` (or binary data)
2. `AuthTokenChecker` calls `contains_key(X_IS_JWT_HEADER)` at line 38 - returns true
3. Function returns `Ok(vec![])` - no rejection, bypassing all auth token validation
4. Unless JWT validation happens elsewhere (e.g., via `RedisRatelimitChecker` with JWT mode), the request proceeds without authentication

To answer the original security question: The `to_str().ok()` on the Authorization header properly handles non-UTF8 data by returning `None`, which causes rejection. However, the vulnerability exists in the **earlier** bypass check at line 38, which uses `contains_key()` instead of validating the header value, allowing attackers to inject any data in the `x-is-jwt` header to bypass authentication. [3](#0-2) 

## Impact Explanation

**Severity Assessment: LOW (Out of Scope for Main Report)**

While this is a legitimate authentication bypass vulnerability, it affects only the Aptos faucet service, which is an auxiliary development tool for distributing testnet/devnet tokens, not a core blockchain component. The impact is limited to:

- Unauthorized access to faucet funds on test networks
- Potential denial of service by draining testnet token allocations
- Does NOT affect mainnet funds, consensus, or validator operations
- Does NOT impact core blockchain security, state management, or execution

Per the Aptos Bug Bounty severity categories, this does not meet the Medium severity threshold ($10,000+) which requires "Limited funds loss or manipulation" or "State inconsistencies requiring intervention" on the actual blockchain. This would be categorized as Low severity (up to $1,000) as a "non-critical implementation bug" in auxiliary infrastructure.

## Likelihood Explanation

**Likelihood: HIGH** if the faucet is configured with only `AuthTokenChecker` without separate JWT validation.

The attack is trivial to execute - an attacker simply adds an HTTP header to their request. However, the actual exploitability depends on the faucet configuration:

- If `AuthTokenChecker` is the only auth mechanism: Fully exploitable
- If `RedisRatelimitChecker` with JWT mode is also configured: The JWT validation there would catch invalid JWTs, mitigating the bypass [4](#0-3) 

## Recommendation

Validate the `X_IS_JWT_HEADER` value, not just its presence:

```rust
// Don't check if the request has X_IS_JWT_HEADER set to "true".
if data
    .headers
    .get(X_IS_JWT_HEADER)
    .and_then(|v| v.to_str().ok())
    .map(|v| v.eq_ignore_ascii_case("true"))
    .unwrap_or(false)
{
    return Ok(vec![]);
}
```

This ensures that only requests explicitly indicating JWT authentication with the correct header value can bypass bearer token validation.

## Proof of Concept

```bash
# Without the header (requires valid bearer token)
curl -X POST http://faucet-url/fund \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"address": "0x123..."}'
# Expected: Rejected by AuthTokenChecker

# With x-is-jwt header set to any value (bypasses validation)
curl -X POST http://faucet-url/fund \
  -H "x-is-jwt: false" \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"address": "0x123..."}'
# Expected: Bypasses AuthTokenChecker, may succeed if no other JWT validation

# With binary data in x-is-jwt header
curl -X POST http://faucet-url/fund \
  -H "x-is-jwt: $(printf '\x00\xff\xfe')" \
  -H "Authorization: Bearer invalid_token" \
  -H "Content-Type: application/json" \
  -d '{"address": "0x123..."}'
# Expected: Bypasses AuthTokenChecker via contains_key() check
```

---

## Notes

**Important Context:** This vulnerability exists in the Aptos faucet service codebase, which is auxiliary infrastructure for development and testing, not part of the core Aptos blockchain protocol (consensus, execution engine, state management, governance, or staking systems). While it represents a real security issue in the code, it does not meet the severity thresholds outlined in the audit requirements focused on critical blockchain components and does not affect mainnet operations or core protocol security.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/auth_token.rs (L38-40)
```rust
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(vec![]);
        }
```

**File:** crates/aptos-faucet/core/src/checkers/auth_token.rs (L42-53)
```rust
        let auth_token = match data
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_whitespace().nth(1))
        {
            Some(auth_token) => auth_token,
            None => return Ok(vec![RejectionReason::new(
                "Either the Authorization header is missing or it is not in the form of 'Bearer <token>'".to_string(),
                RejectionReasonCode::AuthTokenInvalid,
            )]),
        };
```

**File:** crates/aptos-faucet/core/src/firebase_jwt.rs (L70-89)
```rust
    let is_jwt = headers
        .get(X_IS_JWT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .ok_or_else(|| {
            AptosTapError::new(
                format!(
                    "The {} header must be present and set to 'true'",
                    X_IS_JWT_HEADER
                ),
                AptosTapErrorCode::AuthTokenInvalid,
            )
        })?;

    if !is_jwt {
        return Err(AptosTapError::new(
            format!("The {} header must be set to 'true'", X_IS_JWT_HEADER),
            AptosTapErrorCode::AuthTokenInvalid,
        ));
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
