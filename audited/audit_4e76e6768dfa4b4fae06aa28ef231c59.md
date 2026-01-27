# Audit Report

## Title
Authentication Bypass in Faucet Service via X_IS_JWT_HEADER Header Manipulation

## Summary
The `AuthTokenChecker` in the Aptos faucet service contains a logic flaw where setting the `X_IS_JWT_HEADER` header causes the checker to immediately return success without validating any credentials. JWT validation only occurs in `RedisRatelimitChecker` when specifically configured with JWT-based rate limiting. In deployments without JWT-based rate limiting, attackers can bypass authentication entirely by setting a single HTTP header.

## Finding Description

**IMPORTANT SCOPE NOTE**: This vulnerability affects the **Aptos faucet service** (an auxiliary developer tool for distributing test tokens), NOT the core blockchain consensus, Move VM, state management, governance, or staking systems. While this is a legitimate authentication bypass in the faucet, it does not impact blockchain security invariants.

The authentication bypass occurs in the `AuthTokenChecker.check()` function: [1](#0-0) 

When `X_IS_JWT_HEADER` is present in request headers, the checker immediately returns an empty rejection list (success) without performing any authentication. The intent appears to be that JWT validation would happen elsewhere, specifically in the `FirebaseJwtVerifier`: [2](#0-1) 

However, JWT validation is **only invoked** by the `RedisRatelimitChecker` when configured with JWT-based rate limiting: [3](#0-2) 

**Attack Scenario:**

If the faucet is configured with:
1. `AuthTokenChecker` enabled (to require auth tokens), AND
2. Either NO `RedisRatelimitChecker`, OR `RedisRatelimitChecker` with IP-based rate limiting (not JWT-based)

Then an attacker can:
1. Send a request with `X_IS_JWT_HEADER: true` (or any value)
2. Omit valid JWT credentials or provide invalid ones
3. Bypass `AuthTokenChecker` completely (early return at line 38-39)
4. No other component validates the JWT
5. Successfully access the faucet without authentication

The request processing flow confirms this: [4](#0-3) 

All checkers are invoked sequentially, but there's no enforcement that JWT validation must occur when `X_IS_JWT_HEADER` is set.

## Impact Explanation

**Severity: OUT OF SCOPE for Core Blockchain Audit**

This vulnerability affects the **faucet service only**, which is an off-chain auxiliary tool for distributing test tokens. It does NOT impact:

- ✗ Consensus safety or liveness
- ✗ Move VM execution integrity  
- ✗ Blockchain state consistency
- ✗ On-chain governance
- ✗ Validator staking systems

The impact is limited to:
- Unauthorized faucet fund drainage (test tokens only)
- Bypass of faucet rate limits and authentication

While this is a legitimate HIGH severity issue **for the faucet service itself**, it falls outside the scope of this audit which focuses on "consensus vulnerabilities, Move VM implementation bugs, state management attacks, and on-chain governance security."

## Likelihood Explanation

**Likelihood: High** (if vulnerable configuration exists)

Exploitation requires:
- Faucet deployed with `AuthTokenChecker` enabled
- Faucet NOT using JWT-based `RedisRatelimitChecker`
- Attacker sends HTTP request with `X_IS_JWT_HEADER` header

No special privileges, cryptographic operations, or complex timing are required. The attack is a simple HTTP header manipulation.

## Recommendation

**Design Fix**: Remove the dangerous assumption that JWT validation will happen elsewhere. The `AuthTokenChecker` should not bypass validation based on header presence alone.

**Option 1 - Remove Early Return:**
Remove lines 37-40 from `auth_token.rs`. Require explicit auth token validation even when `X_IS_JWT_HEADER` is present.

**Option 2 - Validate JWT in AuthTokenChecker:**
If JWT support is needed, validate the JWT within `AuthTokenChecker` itself rather than relying on external components.

**Option 3 - Configuration Validation:**
Add startup validation that enforces: if any checker allows `X_IS_JWT_HEADER` bypass, then JWT-based `RedisRatelimitChecker` must be configured.

## Proof of Concept

```rust
// Exploitation via HTTP request (curl example):
// curl -X POST http://faucet-server/fund \
//   -H "Content-Type: application/json" \
//   -H "x-is-jwt: true" \
//   -d '{"address": "0x1234..."}'
//
// This bypasses AuthTokenChecker without any valid credentials
// if the faucet lacks JWT-based RedisRatelimitChecker

// Integration test demonstrating the bypass:
#[tokio::test]
async fn test_jwt_header_bypass() {
    // Start faucet with AuthTokenChecker but NO JWT validation
    let config = RunConfig {
        checker_configs: vec![
            CheckerConfig::AuthToken(/* config */),
            // NO RedisRatelimit with JWT validation
        ],
        // ... other config
    };
    
    let port = start_faucet(config).await;
    
    // Request WITHOUT x-is-jwt header should fail
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/fund", port))
        .json(&FundRequest { address: Some("0x123".to_string()), ..Default::default() })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403); // Should be rejected
    
    // Request WITH x-is-jwt header should succeed (VULNERABILITY)
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/fund", port))
        .header("x-is-jwt", "true")  // No valid JWT provided!
        .json(&FundRequest { address: Some("0x123".to_string()), ..Default::default() })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200); // Bypassed authentication!
}
```

---

**Notes:**

This audit report documents an authentication bypass in the **Aptos faucet service**, which is an off-chain auxiliary tool for test token distribution. While this is a legitimate security issue for the faucet itself, it does not affect the core Aptos blockchain's consensus, execution, state management, governance, or staking systems that are the focus of this security audit.

The faucet vulnerability allows unauthorized access to test tokens but has no impact on mainnet funds, validator operations, or blockchain integrity.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/auth_token.rs (L37-40)
```rust
        // Don't check if the request has X_IS_JWT_HEADER set.
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(vec![]);
        }
```

**File:** crates/aptos-faucet/core/src/firebase_jwt.rs (L41-64)
```rust
    pub async fn validate_jwt(&self, headers: Arc<HeaderMap>) -> Result<String, AptosTapError> {
        let auth_token = jwt_sub(headers)?;

        let verify = self.jwt_verifier.verify::<JwtClaims>(&auth_token);
        let token_data = match verify.await {
            Some(token_data) => token_data,
            None => {
                return Err(AptosTapError::new(
                    "Failed to verify JWT token".to_string(),
                    AptosTapErrorCode::AuthTokenInvalid,
                ));
            },
        };
        let claims = token_data.claims;

        if !claims.email_verified {
            return Err(AptosTapError::new(
                "The JWT token is not verified".to_string(),
                AptosTapErrorCode::AuthTokenInvalid,
            ));
        }

        Ok(claims.sub)
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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L261-270)
```rust
        // Ensure request passes checkers.
        let mut rejection_reasons = Vec::new();
        for checker in &self.checkers {
            rejection_reasons.extend(checker.check(checker_data.clone(), dry_run).await.map_err(
                |e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError),
            )?);
            if !rejection_reasons.is_empty() && self.return_rejections_early {
                break;
            }
        }
```
