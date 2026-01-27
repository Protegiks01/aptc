# Audit Report

## Title
Authentication Token Bypasser Allows Unrestricted Faucet Abuse with Compromised Credentials

## Summary
The `request_can_bypass()` function in the `AuthTokenBypasser` only validates the presence of a valid authentication token in request headers, but does not validate the `source_ip` or `receiver` fields of `CheckerData`. This allows an attacker with a compromised auth token to bypass all security controls including IP blocklists, rate limiting, and CAPTCHA verification, enabling unlimited faucet abuse from any IP address to any receiver address. [1](#0-0) 

## Finding Description
The Aptos faucet implements a bypasser mechanism to allow privileged requests to skip security checks. The `AuthTokenBypasser` is designed to grant bypass privileges based on the presence of a valid token in the `Authorization` header.

The `CheckerData` structure contains four fields that represent the request context: [2](#0-1) 

However, the `AuthTokenBypasser.request_can_bypass()` implementation only examines the `headers` field to verify token validity. It does not validate:
- Whether `source_ip` is on the IP blocklist
- Whether `receiver` has any restrictions
- Any rate limiting constraints

When a bypasser returns `true`, the request completely skips all configured checkers: [3](#0-2) 

This means critical security controls are bypassed, including:

**IP Blocklist Check:** Normally rejects requests from blocklisted IPs [4](#0-3) 

**Rate Limiting:** Normally enforces daily request limits per IP [5](#0-4) 

**Attack Scenario:**
1. Attacker obtains valid auth token (via leak, theft, insider access, or social engineering)
2. Attacker makes requests from blocklisted IP addresses (bypasses IP blocklist checker)
3. Attacker makes unlimited requests (bypasses rate limiting checker)
4. Attacker requests funds for any receiver address without restriction
5. Attacker can drain faucet resources or abuse the service for malicious purposes

The vulnerability violates the principle of defense-in-depth. Even if one security control (auth token) is compromised, other controls (IP blocklist, rate limiting) should still provide protection.

## Impact Explanation
**Medium Severity** - This vulnerability allows limited funds loss and service abuse:

- **Funds Loss**: An attacker with a compromised auth token can drain faucet funds through unlimited requests, potentially exhausting the faucet's token supply
- **Service Abuse**: The faucet can be weaponized to fund malicious accounts or support attack infrastructure
- **Circumvention of Security Controls**: All layered security measures (IP blocklist, rate limits, CAPTCHA) become ineffective once an auth token is compromised
- **Resource Exhaustion**: Unlimited requests can overload the faucet service and blockchain nodes processing funding transactions

While this does not directly compromise consensus or blockchain core security, it represents a significant service-level vulnerability that can lead to resource exhaustion and unauthorized fund distribution. The impact aligns with **Medium Severity** criteria: "Limited funds loss or manipulation, State inconsistencies requiring intervention."

## Likelihood Explanation
**Moderate to High Likelihood:**

- **Token Compromise**: Auth tokens can be compromised through various vectors:
  - Leaked credentials in code repositories or logs
  - Insider threats or social engineering
  - Stolen tokens from development environments
  - Misconfigured access controls
  
- **Exploitation Complexity**: Once a token is obtained, exploitation is trivial—simply include the token in the `Authorization` header

- **Detection Difficulty**: Without additional monitoring on source IPs and request patterns for token-authenticated requests, abuse may go unnoticed until significant damage occurs

- **Mitigation Absence**: The current implementation provides no defense-in-depth; a single compromised credential grants unrestricted access

## Recommendation
Implement defense-in-depth by adding validation of `source_ip` and rate limiting even for authenticated requests:

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

        // Validate token exists in allowlist
        if !self.manager.contains(auth_token) {
            return Ok(false);
        }

        // ADD: Still enforce IP blocklist even for authenticated requests
        // ADD: Log authenticated requests for monitoring
        // ADD: Consider implementing a separate, higher rate limit for token holders
        
        Ok(true)
    }
}
```

**Additional Recommendations:**
1. Implement IP blocklist checking even for token-authenticated requests
2. Add monitoring and alerting for unusual patterns in token usage
3. Implement token-specific rate limits (higher than public, but not unlimited)
4. Add token rotation and expiration mechanisms
5. Log all token-authenticated requests with full context for audit trails

## Proof of Concept

```rust
// PoC: Demonstrate bypass with compromised token
// 
// Setup:
// 1. Configure faucet with IP blocklist containing 192.168.1.100
// 2. Configure rate limit of 1 request per IP per day
// 3. Add valid token "compromised-token-123" to auth token list
//
// Test Case 1: Without auth token, request from blocklisted IP is rejected
// curl -X POST http://faucet/fund \
//   -H "Content-Type: application/json" \
//   -H "X-Forwarded-For: 192.168.1.100" \
//   -d '{"address": "0xALICE"}'
// Expected: 403 Forbidden - "IP 192.168.1.100 is in blocklist"
//
// Test Case 2: With auth token, same request bypasses IP blocklist
// curl -X POST http://faucet/fund \
//   -H "Content-Type: application/json" \
//   -H "Authorization: Bearer compromised-token-123" \
//   -H "X-Forwarded-For: 192.168.1.100" \
//   -d '{"address": "0xALICE"}'
// Expected: 200 OK - Request succeeds despite blocklisted IP
//
// Test Case 3: Multiple requests bypass rate limiting
// for i in {1..100}; do
//   curl -X POST http://faucet/fund \
//     -H "Authorization: Bearer compromised-token-123" \
//     -H "X-Forwarded-For: 192.168.1.100" \
//     -d "{\"address\": \"0xBOB$i\"}"
// done
// Expected: All 100 requests succeed, bypassing daily rate limit
//
// Impact: Attacker with compromised token can:
// - Drain faucet from blocklisted IPs
// - Make unlimited requests (no rate limiting)
// - Fund arbitrary addresses without restriction
```

**Notes:**
- This vulnerability affects the faucet service specifically, not the core blockchain consensus or state management
- The flaw is in the incomplete validation logic within the bypasser implementation, which only checks headers and ignores critical security context in `source_ip` and `receiver` fields
- Auth tokens are stored as plain strings in a file with no additional metadata for IP restrictions or rate limits ( [6](#0-5) )
- The design intent of bypassers is documented to "skip all the checkers and storage" ( [7](#0-6) ), but this creates a single point of failure when credentials are compromised

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

**File:** crates/aptos-faucet/core/src/checkers/mod.rs (L147-153)
```rust
#[derive(Clone, Debug)]
pub struct CheckerData {
    pub time_request_received_secs: u64,
    pub receiver: AccountAddress,
    pub source_ip: IpAddr,
    pub headers: Arc<HeaderMap>,
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

**File:** crates/aptos-faucet/core/src/checkers/ip_blocklist.rs (L26-56)
```rust
impl CheckerTrait for IpBlocklistChecker {
    async fn check(
        &self,
        data: CheckerData,
        _dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        match &data.source_ip {
            IpAddr::V4(source_ip) => {
                if self.manager.ipv4_list.contains(source_ip) {
                    return Ok(vec![RejectionReason::new(
                        format!("IP {} is in blocklist", source_ip),
                        RejectionReasonCode::IpInBlocklist,
                    )]);
                }
            },
            IpAddr::V6(source_ip) => {
                if self.manager.ipv6_list.contains(source_ip) {
                    return Ok(vec![RejectionReason::new(
                        format!("IP {} is in blocklist", source_ip),
                        RejectionReasonCode::IpInBlocklist,
                    )]);
                }
            },
        }
        Ok(vec![])
    }

    fn cost(&self) -> u8 {
        1
    }
}
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L67-91)
```rust
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

**File:** crates/aptos-faucet/core/src/common/list_manager.rs (L16-42)
```rust
pub struct ListManager {
    items: HashSet<String>,
}

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

**File:** crates/aptos-faucet/core/src/bypasser/mod.rs (L17-24)
```rust
/// This trait defines something that checks whether a given request should
/// skip all the checkers and storage, for example an IP allowlist.
#[async_trait]
#[enum_dispatch]
pub trait BypasserTrait: Sync + Send + 'static {
    /// Returns true if the request should be allowed to bypass all checkers
    /// and storage.
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool>;
```
