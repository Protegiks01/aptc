# Audit Report

## Title
Bypass Tokens Enable Unlimited Faucet Access Through Sharing and Account Reuse

## Summary
The `AuthTokenBypasser` implementation allows bypass tokens to be freely shared between unlimited users and reused across unlimited accounts without any tracking or limits, enabling complete bypass of rate limiting and potential fund draining from the faucet.

## Finding Description

The `request_can_bypass()` function in `AuthTokenBypasser` implements a critical design flaw where it only verifies token existence in a static list without any binding to users or usage tracking. [1](#0-0) 

The token verification logic performs a simple membership check against a static `ListManager` that loads tokens from a file: [2](#0-1) 

When any bypasser returns `true`, the fund endpoint completely bypasses all checkers and storage operations: [3](#0-2) 

This bypass has severe consequences:

1. **Complete Rate Limit Bypass**: When `bypass=true`, all checker completion steps are skipped, including rate limiting storage updates: [4](#0-3) 

2. **Higher Funding Amounts**: Bypassed requests can receive higher funding amounts through `maximum_amount_with_bypass`: [5](#0-4) 

3. **No Token Usage Tracking**: There is no mechanism to:
   - Associate tokens with specific account addresses
   - Track how many times a token has been used
   - Limit token usage per account or IP
   - Detect shared or leaked tokens

**Attack Path:**
1. Attacker obtains a valid bypass token (through leakage, insider sharing, or legitimate CI token access)
2. Shares the token with unlimited colluders or uses across multiple machines/IPs
3. Each entity makes unlimited funding requests for different account addresses
4. All requests bypass rate limiting completely (no checker execution)
5. Each request potentially receives `maximum_amount_with_bypass` (which can be significantly higher)
6. Faucet funds are drained without any tracking or throttling

The rate limiting checker confirms that bypass completely circumvents usage tracking: [6](#0-5) 

## Impact Explanation

This vulnerability allows **unlimited faucet access** through a single leaked or shared bypass token, breaking the faucet's anti-abuse mechanisms entirely. 

Per the Aptos bug bounty criteria, this qualifies as **High Severity** due to:
- **Significant protocol violations**: Complete bypass of rate limiting and anti-abuse systems
- **Limited funds loss**: Potential draining of faucet funds (severity depends on faucet funding amount)
- **API operational impact**: Denial of service to legitimate users once faucet is drained

If the faucet is deployed with significant funding (especially on mainnet or high-value testnets), this could result in substantial fund loss. Even on testnets, this breaks the operational security model of the faucet service.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Prerequisites for exploitation:
1. **Token Acquisition** (MEDIUM barrier): Attacker needs a valid bypass token through:
   - Token leakage in public repositories or documentation
   - Insider sharing from legitimate CI/testing users
   - Social engineering targeting developers with token access
   - Accidental exposure in logs or configuration files

2. **Exploitation** (TRIVIAL barrier): Once a token is obtained:
   - No technical barriers exist
   - Simple HTTP requests with Authorization header
   - Can be automated across multiple IPs/machines
   - No detection mechanisms in place

Given that bypass tokens are likely shared for legitimate purposes (CI, testing, development), the risk of leakage or misuse is substantial. The complete lack of usage tracking makes detection impossible.

## Recommendation

Implement comprehensive token usage tracking and per-account limits:

```rust
// Add to AuthTokenBypasser struct
pub struct AuthTokenBypasser {
    pub manager: ListManager,
    // Track token usage per (token, account_address) pair
    pub usage_tracker: Arc<RwLock<HashMap<(String, AccountAddress), UsageInfo>>>,
    // Maximum requests per token per account per day
    pub max_requests_per_account_per_day: u32,
}

struct UsageInfo {
    count: u32,
    last_reset: u64, // timestamp
}

// Modify request_can_bypass
async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
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

    if !self.manager.contains(auth_token) {
        return Ok(false);
    }

    // Check per-account usage limits
    let key = (auth_token.to_string(), data.receiver);
    let mut tracker = self.usage_tracker.write().await;
    
    let usage = tracker.entry(key.clone()).or_insert(UsageInfo {
        count: 0,
        last_reset: get_current_time_secs(),
    });

    // Reset daily counter if needed
    if days_since_tap_epoch(get_current_time_secs()) > 
       days_since_tap_epoch(usage.last_reset) {
        usage.count = 0;
        usage.last_reset = get_current_time_secs();
    }

    // Enforce per-account limit
    if usage.count >= self.max_requests_per_account_per_day {
        return Ok(false); // Deny bypass
    }

    usage.count += 1;
    Ok(true)
}
```

Additional recommendations:
1. **Token Rotation**: Implement time-limited tokens with expiration
2. **Monitoring**: Add alerting for unusual bypass token usage patterns
3. **Audit Logging**: Log all bypass token usage with account addresses and amounts
4. **Token Scoping**: Associate tokens with specific accounts/purposes in configuration

## Proof of Concept

```rust
// Test demonstrating unlimited sharing and reuse
#[tokio::test]
async fn test_bypass_token_sharing_vulnerability() -> Result<()> {
    // Setup faucet with a bypass token
    let bypass_token = "shared_token";
    
    // Attacker 1 uses the token for Account A
    let request1 = FundRequest {
        amount: Some(1000),
        address: Some("0xA".to_string()),
        auth_key: None,
        pub_key: None,
    };
    
    let response1 = reqwest::Client::new()
        .post("http://localhost:8080/fund")
        .json(&request1)
        .header("Authorization", format!("Bearer {}", bypass_token))
        .send()
        .await?;
    assert_eq!(response1.status(), 200); // Success
    
    // Attacker 2 (different IP) reuses SAME token for Account B
    let request2 = FundRequest {
        amount: Some(1000),
        address: Some("0xB".to_string()),
        auth_key: None,
        pub_key: None,
    };
    
    let response2 = reqwest::Client::new()
        .post("http://localhost:8080/fund")
        .json(&request2)
        .header("Authorization", format!("Bearer {}", bypass_token))
        .send()
        .await?;
    assert_eq!(response2.status(), 200); // Success - NO rate limiting!
    
    // Repeat for unlimited accounts (C, D, E, F, ...)
    // All bypass rate limiting using the SAME shared token
    // Faucet can be drained without any tracking
    
    Ok(())
}
```

## Notes

This vulnerability is specific to the faucet service, which is auxiliary infrastructure rather than core consensus. However, it represents a complete failure of the faucet's anti-abuse mechanisms and could result in operational denial of service or fund loss depending on deployment context and funding amounts. The issue is particularly concerning because bypass tokens are likely shared legitimately for CI/testing purposes, increasing the attack surface for token leakage or insider misuse.

### Citations

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

**File:** crates/aptos-faucet/core/src/common/list_manager.rs (L20-42)
```rust
impl ListManager {
    pub fn new(config: ListManagerConfig) -> Result<Self> {
        let file = File::open(&config.file)
            .with_context(|| format!("Failed to open {}", config.file.to_string_lossy()))?;
        let mut items = HashSet::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            if line.starts_with('#') || line.starts_with("//") || line.is_empty() {
                continue;
            }
            items.insert(line);
        }
        Ok(Self { items })
    }

    pub fn contains(&self, item: &str) -> bool {
        self.items.contains(item)
    }

    pub fn num_items(&self) -> usize {
        self.items.len()
    }
}
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L244-258)
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

**File:** crates/aptos-faucet/core/src/funder/common.rs (L176-185)
```rust
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

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L66-91)
```rust
#[async_trait]
impl CheckerTrait for MemoryRatelimitChecker {
    async fn check(
        &self,
        data: CheckerData,
        dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        self.clear_if_new_day().await;

        let mut ip_to_requests_today = self.ip_to_requests_today.lock().await;

        let requests_today = ip_to_requests_today.get_or_insert_mut(data.source_ip, || 1);
        if *requests_today >= self.max_requests_per_day {
            return Ok(vec![RejectionReason::new(
                format!(
                    "IP {} has exceeded the daily limit of {} requests",
                    data.source_ip, self.max_requests_per_day
                ),
                RejectionReasonCode::UsageLimitExhausted,
            )]);
        } else if !dry_run {
            *requests_today += 1;
        }

        Ok(vec![])
    }
```
