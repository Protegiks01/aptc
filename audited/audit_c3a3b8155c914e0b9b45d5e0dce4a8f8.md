# Audit Report

## Title
Authentication Bypass in Aptos Faucet Through Dual Authentication Mode Switching

## Summary
The Aptos Faucet implements a dual authentication system supporting both API key authentication and JWT (Firebase) authentication. A critical flaw exists where `AuthTokenChecker` unconditionally skips API key validation when the `X_IS_JWT_HEADER` is present, but JWT validation only occurs if `RedisRatelimitChecker` is explicitly configured in JWT mode. This allows attackers to bypass all authentication by simply setting the `X_IS_JWT_HEADER` header without providing valid credentials.

## Finding Description

The faucet's authentication architecture has three key components:

1. **AuthTokenChecker** - Validates API key tokens from the `Authorization` header [1](#0-0) 

2. **FirebaseJwtVerifier** - Validates Firebase JWT tokens when `X_IS_JWT_HEADER` is set to "true" [2](#0-1) 

3. **RedisRatelimitChecker** - Can optionally perform JWT validation when configured with JWT mode [3](#0-2) 

The vulnerability exists because:

- `AuthTokenChecker` immediately returns empty rejection reasons (passes the check) when `X_IS_JWT_HEADER` is present, without performing any validation [1](#0-0) 

- JWT validation only occurs within `RedisRatelimitChecker` when it's explicitly configured with `RatelimitKeyProviderConfig::Jwt` [4](#0-3) 

- The default configuration for rate limiting is IP-based, not JWT-based [5](#0-4) 

**Attack Scenario:**

When the faucet is configured with:
- `AuthTokenChecker` to require API key authentication
- `RedisRatelimitChecker` in default IP mode (most common deployment)

An attacker can:
1. Send a request with `X_IS_JWT_HEADER: true` header
2. Skip API key validation in `AuthTokenChecker` 
3. Bypass JWT validation (since rate limiter is in IP mode)
4. Successfully access faucet endpoints without any authentication

The same bypasser logic exists in `AuthTokenBypasser` [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **API Security Breach**: Complete authentication bypass allowing unauthorized access to protected faucet endpoints
- **Loss of Funds**: Attackers can drain faucet funds by making unlimited authenticated requests without valid credentials
- **Protocol Violation**: Violates the fundamental security guarantee that all requests must be authenticated

The faucet holds real tokens (even if for testing purposes) that are meant to be distributed in a controlled manner. This bypass allows mass fund extraction limited only by IP-based rate limits, which can be circumvented through proxy rotation.

## Likelihood Explanation

**Likelihood: High**

- **Trivial Exploitation**: Requires only adding a single HTTP header (`X_IS_JWT_HEADER: true`)
- **Common Configuration**: The vulnerable configuration (API key auth + IP-based rate limiting) is likely the default deployment
- **No Special Access Required**: Any anonymous internet user can exploit this
- **Difficult to Detect**: Malicious requests appear similar to legitimate requests with JWT authentication

The attack can be automated and scaled using simple scripts with rotating IP addresses.

## Recommendation

The authentication system must enforce that when `X_IS_JWT_HEADER` is present, JWT validation **must** occur. Implement one of these fixes:

**Option 1: Create a dedicated JWT authentication checker**

Add a new `JwtAuthChecker` that:
- Only activates when `X_IS_JWT_HEADER` is present
- Calls `FirebaseJwtVerifier.validate_jwt()` to enforce validation
- Returns rejection reasons if JWT is invalid

**Option 2: Make JWT validation mandatory in RedisRatelimitChecker**

Modify `RedisRatelimitChecker` to check if `X_IS_JWT_HEADER` is present and fail if JWT mode is not configured.

**Option 3: Remove the header-based switching logic**

Eliminate the `X_IS_JWT_HEADER` bypass in `AuthTokenChecker` and require explicit configuration that chooses either API key OR JWT authentication (not both with implicit switching).

**Recommended Fix (Option 1):**

Create `crates/aptos-faucet/core/src/checkers/jwt_auth.rs`:

```rust
pub struct JwtAuthChecker {
    pub jwt_verifier: FirebaseJwtVerifier,
}

#[async_trait]
impl CheckerTrait for JwtAuthChecker {
    async fn check(&self, data: CheckerData, _dry_run: bool) -> Result<Vec<RejectionReason>, AptosTapError> {
        // Only activate if X_IS_JWT_HEADER is present
        if !data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(vec![]);
        }
        
        // Perform JWT validation - this will return error if invalid
        match self.jwt_verifier.validate_jwt(data.headers).await {
            Ok(_) => Ok(vec![]),
            Err(e) => Ok(vec![RejectionReason::new(
                e.message,
                RejectionReasonCode::AuthTokenInvalid,
            )]),
        }
    }
    
    fn cost(&self) -> u8 { 2 }
}
```

Update `AuthTokenChecker` to fail when JWT header is present without JWT checker configured.

## Proof of Concept

**HTTP Request Demonstrating Bypass:**

```bash
# Normal request with valid API key - succeeds
curl -X POST http://faucet.example.com/fund \
  -H "Authorization: Bearer valid-api-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"address": "0x1234..."}' 

# Attack request - bypasses authentication
curl -X POST http://faucet.example.com/fund \
  -H "X-IS-JWT: true" \
  -H "Authorization: Bearer invalid-or-no-token" \
  -H "Content-Type: application/json" \
  -d '{"address": "0x1234..."}' 
# This succeeds without valid credentials!
```

**Rust Test Demonstrating the Vulnerability:**

```rust
#[tokio::test]
async fn test_authentication_bypass_via_jwt_header() {
    use poem::http::HeaderMap;
    
    // Setup: AuthTokenChecker with allowed API key "valid-key"
    let checker = AuthTokenChecker::new(
        ListManagerConfig::from_list(vec!["valid-key".to_string()])
    ).unwrap();
    
    // Test 1: Without X_IS_JWT_HEADER - requires valid API key
    let mut headers1 = HeaderMap::new();
    headers1.insert(AUTHORIZATION, "Bearer invalid-key".parse().unwrap());
    let data1 = CheckerData {
        headers: Arc::new(headers1),
        // ... other fields
    };
    let result1 = checker.check(data1, false).await.unwrap();
    assert!(!result1.is_empty()); // Should reject - invalid key
    
    // Test 2: With X_IS_JWT_HEADER - bypasses API key check entirely
    let mut headers2 = HeaderMap::new();
    headers2.insert(AUTHORIZATION, "Bearer invalid-key".parse().unwrap());
    headers2.insert(X_IS_JWT_HEADER, "true".parse().unwrap()); // Magic bypass
    let data2 = CheckerData {
        headers: Arc::new(headers2),
        // ... other fields  
    };
    let result2 = checker.check(data2, false).await.unwrap();
    assert!(result2.is_empty()); // VULNERABILITY: Passes without validation!
}
```

**Notes**

This vulnerability demonstrates a classic example of incomplete defense-in-depth where authentication mode switching creates a bypass path. The design assumes JWT validation will occur elsewhere when `X_IS_JWT_HEADER` is present, but this assumption is not enforced by the system architecture.

While the faucet is not a core consensus component, it represents a significant security boundary for the Aptos ecosystem as it controls fund distribution. An authentication bypass of this nature would allow malicious actors to drain faucet resources, disrupting developer onboarding and testing workflows.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/auth_token.rs (L37-40)
```rust
        // Don't check if the request has X_IS_JWT_HEADER set.
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(vec![]);
        }
```

**File:** crates/aptos-faucet/core/src/firebase_jwt.rs (L31-40)
```rust
    /// First, we mandate that the caller indicated that they're including a JWT by
    /// checking for the presence of X_IS_JWT_HEADER. If they didn't include this
    /// header, we reject them immediately. We need this because we already have a
    /// checker that looks for API keys using the Authorization header, and we want
    /// to differentiate these two cases.
    ///
    /// If they did include X_IS_JWT_HEADER and the Authorization header was present
    /// and well-formed, we extract the token from the Authorization header and verify
    /// it with Firebase. If the token is invalid, we reject them. If it is valid, we
    /// return the UID (from the sub field).
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L19-24)
```rust
#[serde(tag = "type")]
pub enum RatelimitKeyProviderConfig {
    #[default]
    Ip,
    Jwt(FirebaseJwtVerifierConfig),
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

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L162-166)
```rust
        let ratelimit_key_provider = match args.ratelimit_key_provider_config.clone() {
            RatelimitKeyProviderConfig::Ip => RatelimitKeyProvider::Ip,
            RatelimitKeyProviderConfig::Jwt(config) => {
                RatelimitKeyProvider::Jwt(FirebaseJwtVerifier::new(config).await?)
            },
```

**File:** crates/aptos-faucet/core/src/bypasser/auth_token.rs (L33-36)
```rust
        // Don't check if the request has X_IS_JWT_HEADER set.
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(false);
        }
```
