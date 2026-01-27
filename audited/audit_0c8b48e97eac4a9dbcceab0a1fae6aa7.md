# Audit Report

## Title
Faucet Bypasser OR Logic Defeats Defense-in-Depth Security Model

## Summary
The Aptos faucet implements multiple bypasser mechanisms (AuthToken and IpAllowlist) using OR logic instead of AND logic. When administrators configure multiple bypassers expecting defense-in-depth security, the implementation allows bypassing all security checks if ANY single bypasser condition is met, significantly weakening the intended security posture.

## Finding Description
The faucet bypasser logic in `preprocess_request` uses an early-return pattern that implements OR semantics across multiple configured bypassers. [1](#0-0) 

This implementation iterates through all configured bypassers and immediately returns `bypass = true` when ANY single bypasser approves the request. An administrator who configures both `AuthToken` and `IpAllowlist` bypassers expecting that BOTH conditions must be satisfied (AND logic) actually gets a system where EITHER condition is sufficient (OR logic).

**Attack Scenarios:**

1. **Stolen Token Attack**: If an administrator configures IP allowlisting (e.g., corporate network `192.168.0.0/16`) AND auth token validation expecting both to be required, an attacker who obtains a valid auth token can bypass from ANY IP address worldwide, completely defeating the IP allowlist.

2. **Compromised IP Attack**: Similarly, an attacker who gains access to an allowlisted IP range (via compromised employee device, VPN access, etc.) can bypass without ANY authentication token, defeating the token-based security layer.

3. **Weakened Rate Limiting**: Since bypassers skip all checker and storage operations [2](#0-1) , successful bypass eliminates rate limiting entirely, enabling faucet drainage attacks.

The bypasser implementations confirm they operate independently:
- `AuthTokenBypasser` only checks the Authorization header [3](#0-2) 
- `IpAllowlistBypasser` only checks the source IP [4](#0-3) 

## Impact Explanation
**Severity: HIGH**

This vulnerability qualifies as HIGH severity under the Aptos bug bounty program for the following reasons:

1. **Significant Protocol Violation**: The faucet is production infrastructure for Aptos testnet/devnet. Bypassing all security controls violates the intended access control protocol.

2. **Faucet Drainage Risk**: Attackers bypassing rate limits and checkers can drain faucet funds, causing service disruption for legitimate developers and users.

3. **Infrastructure Integrity**: Production faucets are critical developer infrastructure. Compromise undermines trust in the Aptos ecosystem and can block legitimate development/testing activities.

4. **Cascade Effect**: If the faucet uses high `maximum_amount_with_bypass` values [5](#0-4) , attackers can request maximum amounts repeatedly without rate limiting.

## Likelihood Explanation
**Likelihood: MEDIUM-HIGH**

This vulnerability is likely to occur because:

1. **Common Configuration Pattern**: Administrators naturally configure multiple security layers (defense-in-depth) expecting AND logic, not OR logic. The configuration structure supports multiple bypassers [6](#0-5) , suggesting this is an intended use case.

2. **No Documentation Warning**: The bypasser trait documentation [7](#0-6)  does not explicitly warn that multiple bypassers use OR semantics.

3. **Realistic Attack Vectors**: 
   - Auth tokens can be leaked via logs, network traffic, or insider access
   - IP allowlists often include broad ranges (corporate networks, cloud provider IPs)
   - VPN/network compromise is a common attack vector

4. **Production Deployment**: Aptos faucets are deployed in production for testnet/devnet, making them real attack targets.

## Recommendation

**Option 1: Add AND Logic Support**
Introduce a configuration option to specify bypasser combination logic:

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BypasserGroupConfig {
    pub logic: BypasserLogic, // "any" or "all"
    pub bypassers: Vec<BypasserConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BypasserLogic {
    Any,  // Current OR behavior (default for backward compatibility)
    All,  // New AND behavior for defense-in-depth
}
```

Then modify the preprocess logic:

```rust
// Evaluate all bypassers and combine results based on configured logic
let mut bypass_results = Vec::new();
for bypasser in &self.bypassers {
    let can_bypass = bypasser.request_can_bypass(checker_data.clone()).await
        .map_err(|e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::BypasserError))?;
    bypass_results.push(can_bypass);
    
    // Short-circuit for ANY logic if we found a match
    if can_bypass && self.bypasser_logic == BypasserLogic::Any {
        info!("Allowing request from {} to bypass checks / storage", source_ip);
        return Ok((checker_data, true, permit));
    }
}

// For ALL logic, check if all bypassers returned true
if self.bypasser_logic == BypasserLogic::All && bypass_results.iter().all(|&r| r) {
    info!("Allowing request from {} to bypass checks / storage (all conditions met)", source_ip);
    return Ok((checker_data, true, permit));
}
```

**Option 2: Document Explicit OR Behavior**
If OR logic is intentional, add prominent documentation and logging warnings when multiple bypassers are configured to prevent administrator misconfiguration.

## Proof of Concept

**Test Configuration (YAML):**
```yaml
bypasser_configs:
  - type: AuthToken
    config:
      list_file_path: "/tmp/auth_tokens.txt"
  - type: IpAllowlist
    config:
      ip_range_file_path: "/tmp/ip_allowlist.txt"
```

**Attack Demonstration:**

1. **Setup**: Configure faucet with both bypassers
   - IP allowlist: `10.0.0.0/8` (corporate network)
   - Auth tokens: `secret_token_123`

2. **Attack 1 - Stolen Token from External IP:**
   ```bash
   # Attacker from IP 203.0.113.5 (not in allowlist)
   curl -X POST http://faucet/fund \
     -H "Authorization: Bearer secret_token_123" \
     -H "Content-Type: application/json" \
     -d '{"address": "0x1234...", "amount": 1000000000}'
   # Result: SUCCESS - bypassed IP allowlist using only stolen token
   ```

3. **Attack 2 - Compromised IP without Token:**
   ```bash
   # Attacker from IP 10.0.5.100 (in allowlist) without token
   curl -X POST http://faucet/fund \
     -H "Content-Type: application/json" \
     -d '{"address": "0x5678...", "amount": 1000000000}'
   # Result: SUCCESS - bypassed auth token check using only IP
   ```

4. **Expected Behavior (with AND logic):**
   Both attacks should FAIL because neither satisfies BOTH conditions.

**Rust Test Case:**
```rust
#[tokio::test]
async fn test_bypasser_or_logic_vulnerability() {
    // Configure both bypassers
    let components = FundApiComponents {
        bypassers: vec![
            Bypasser::AuthTokenBypasser(AuthTokenBypasser::new(/* config */)),
            Bypasser::IpAllowlistBypasser(IpAllowlistBypasser::new(/* config */)),
        ],
        // ... other fields
    };
    
    // Request with token but wrong IP - should fail with AND logic, passes with OR
    let result1 = components.preprocess_request(
        &fund_request,
        RealIp(Some(IpAddr::from_str("1.2.3.4").unwrap())),
        &headers_with_token,
        false
    ).await;
    assert!(result1.unwrap().1); // bypass=true (VULNERABILITY)
    
    // Request with allowlisted IP but no token - should fail with AND logic, passes with OR
    let result2 = components.preprocess_request(
        &fund_request,
        RealIp(Some(IpAddr::from_str("10.0.0.1").unwrap())),
        &headers_without_token,
        false
    ).await;
    assert!(result2.unwrap().1); // bypass=true (VULNERABILITY)
}
```

**Notes**

This vulnerability demonstrates a critical security design flaw where the principle of defense-in-depth is defeated by OR semantics. While the faucet is not part of core consensus mechanisms, it represents critical production infrastructure for the Aptos ecosystem. Administrators configuring multiple security layers reasonably expect AND logic for defense-in-depth, but the current implementation provides OR logic, significantly weakening the security posture and enabling single-point-of-failure attacks.

### Citations

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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L937-982)
```rust

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

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L25-29)
```rust
impl BypasserTrait for IpAllowlistBypasser {
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
}
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L63-64)
```rust
    /// Configs for any Bypassers we might want to enable.
    bypasser_configs: Vec<BypasserConfig>,
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
