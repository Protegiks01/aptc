# Audit Report

## Title
Configuration-Dependent Authentication Bypass in Faucet Service via JWT Header Manipulation

## Summary
The `AuthTokenBypasser.request_can_bypass()` function checks for the `X_IS_JWT_HEADER` presence before validating the Authorization header. When this header is present, the function assumes JWT validation will occur elsewhere, but this validation is only performed by `RedisRatelimitChecker` when configured with `RatelimitKeyProvider::Jwt`. In configurations lacking this specific checker, an attacker can bypass authentication entirely by setting `x-is-jwt: true` without providing a valid JWT token.

## Finding Description

The faucet service implements two separate authentication mechanisms that both use the `Authorization` header:
1. **API Key Authentication**: Validated by `AuthTokenChecker`
2. **Firebase JWT Authentication**: Distinguished by the presence of `x-is-jwt: true` header

The security issue arises from an incorrect assumption about validation responsibility: [1](#0-0) 

When `X_IS_JWT_HEADER` is present, the bypasser immediately returns `false` without checking credentials. Similarly, `AuthTokenChecker` also skips validation when this header is present: [2](#0-1) 

Both components assume JWT validation will happen in `RedisRatelimitChecker`: [3](#0-2) 

However, JWT validation is **optional** and only occurs when the faucet is configured with `RedisRatelimitChecker` using `RatelimitKeyProvider::Jwt`: [4](#0-3) 

**Attack Path:**
1. Attacker sends request with `x-is-jwt: true` header
2. Omits valid Authorization header or provides arbitrary value
3. `AuthTokenBypasser` skips bypass token check (line 34-36)
4. `AuthTokenChecker` skips API key validation (line 38-40)
5. If `RedisRatelimitChecker` with JWT validation is not configured, no validation occurs
6. Request proceeds to funding without authentication

## Impact Explanation

**Severity: Medium** - Per Aptos bug bounty categories, this represents "Limited funds loss or manipulation."

This vulnerability allows unauthorized access to the faucet service, enabling attackers to:
- Request test tokens without valid credentials
- Potentially drain faucet funds on testnet/devnet deployments
- Bypass rate limiting mechanisms if configured by IP instead of JWT

**Important Context:** This vulnerability affects the **faucet service**, which is an external API service for distributing test tokens, not the core blockchain consensus, execution, or state management layers. It does not:
- Affect consensus safety or liveness
- Compromise validator nodes
- Manipulate on-chain state or governance
- Violate Move VM security guarantees
- Impact mainnet blockchain operations

The faucet typically operates on testnets where tokens have no real economic value. However, if misconfigured on mainnet-connected environments with actual APT tokens, this could result in unauthorized token distribution.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability is exploitable only in specific configurations:
- Faucet must have `AuthTokenChecker` enabled (common for API key auth)
- Faucet must **not** have `RedisRatelimitChecker` with `RatelimitKeyProvider::Jwt`

Realistic vulnerable configurations:
```yaml
checker_configs:
  - type: AuthToken
    file_path: /path/to/tokens.txt
  - type: MemoryRatelimit  # IP-based, no JWT validation
  - type: IpBlocklist
    file_path: /path/to/blocklist.txt
```

Safe configurations include `RedisRatelimitChecker` with JWT:
```yaml
checker_configs:
  - type: AuthToken
  - type: RedisRatelimit
    ratelimit_key_provider_config:
      type: Jwt
      identity_platform_gcp_project: "project-id"
```

The vulnerability requires no special privileges or complex exploitation techniques—a simple HTTP request with the header suffices.

## Recommendation

**Option 1: Mandatory JWT Validation (Recommended)**

Create a dedicated `JwtChecker` that validates JWT tokens when `X_IS_JWT_HEADER` is present:

```rust
// In crates/aptos-faucet/core/src/checkers/jwt_auth.rs
pub struct JwtAuthChecker {
    pub verifier: FirebaseJwtVerifier,
}

#[async_trait]
impl CheckerTrait for JwtAuthChecker {
    async fn check(&self, data: CheckerData, _dry_run: bool) -> Result<Vec<RejectionReason>, AptosTapError> {
        // Only validate if JWT header is present
        if !data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(vec![]);
        }
        
        // Validate JWT - will return error if invalid
        self.verifier.validate_jwt(data.headers.clone()).await?;
        Ok(vec![])
    }
    
    fn cost(&self) -> u8 { 10 }
}
```

**Option 2: Remove Conditional Logic**

Modify `AuthTokenChecker` to validate both API keys and reject JWT requests explicitly:

```rust
// In auth_token.rs, replace lines 37-40
if data.headers.contains_key(X_IS_JWT_HEADER) {
    return Ok(vec![RejectionReason::new(
        "JWT authentication requires RedisRatelimitChecker with JWT configuration".to_string(),
        RejectionReasonCode::AuthTokenInvalid,
    )]);
}
```

**Option 3: Configuration Validation**

Add startup validation that enforces: if `AuthTokenChecker` is present, then `RedisRatelimitChecker` with JWT must also be configured.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use poem::http::HeaderMap;
    
    #[tokio::test]
    async fn test_jwt_header_bypass() {
        // Setup: Faucet with AuthTokenChecker but no JWT validation
        let mut headers = HeaderMap::new();
        headers.insert("x-is-jwt", "true".parse().unwrap());
        // Note: No valid Authorization header or only garbage value
        headers.insert("Authorization", "Bearer garbage".parse().unwrap());
        
        let checker_data = CheckerData {
            receiver: AccountAddress::random(),
            source_ip: "127.0.0.1".parse().unwrap(),
            headers: Arc::new(headers),
            time_request_received_secs: 0,
        };
        
        // AuthTokenChecker should skip validation due to x-is-jwt header
        let auth_checker = AuthTokenChecker::new(ListManagerConfig {
            file_path: "test_tokens.txt".into(),
        }).unwrap();
        
        let result = auth_checker.check(checker_data.clone(), false).await.unwrap();
        assert_eq!(result.len(), 0); // PASSES without validation!
        
        // Without RedisRatelimitChecker with JWT config, no validation occurs
        // Request would proceed to funding
    }
}
```

**Exploitation Steps:**
1. Identify faucet endpoint (e.g., `https://faucet.testnet.aptoslabs.com/fund`)
2. Send POST request with headers:
   ```
   x-is-jwt: true
   Authorization: Bearer invalid-or-empty
   ```
3. Include valid account address in request body
4. Receive funded tokens without valid authentication

## Notes

**Scope Clarification:** This vulnerability exists in the **Aptos Faucet service** (`crates/aptos-faucet/`), which is an external API service for distributing test tokens. While it is part of the Aptos Core repository, it is **not** a core blockchain component (consensus, Move VM, state management, governance, or staking).

The faucet service compromise does not affect:
- Blockchain consensus safety or liveness
- Validator node security
- On-chain transaction validation
- Smart contract execution
- State consistency or Merkle tree integrity

This issue represents a **service-level authentication bypass** rather than a blockchain protocol vulnerability. The severity is assessed as Medium based on its limited scope to the faucet service and typical deployment on testnets with non-valuable tokens.

### Citations

**File:** crates/aptos-faucet/core/src/bypasser/auth_token.rs (L32-36)
```rust
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        // Don't check if the request has X_IS_JWT_HEADER set.
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(false);
        }
```

**File:** crates/aptos-faucet/core/src/checkers/auth_token.rs (L37-40)
```rust
        // Don't check if the request has X_IS_JWT_HEADER set.
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(vec![]);
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

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L162-167)
```rust
        let ratelimit_key_provider = match args.ratelimit_key_provider_config.clone() {
            RatelimitKeyProviderConfig::Ip => RatelimitKeyProvider::Ip,
            RatelimitKeyProviderConfig::Jwt(config) => {
                RatelimitKeyProvider::Jwt(FirebaseJwtVerifier::new(config).await?)
            },
        };
```
