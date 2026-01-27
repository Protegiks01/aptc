# Audit Report

## Title
IPv4-Mapped IPv6 Address Normalization Bypass in Faucet Rate Limiting

## Summary
The Aptos faucet rate limiting system fails to normalize IPv4-mapped IPv6 addresses (e.g., `::ffff:192.168.1.1`) to their IPv4 equivalents (e.g., `192.168.1.1`). This allows an attacker to bypass rate limits by sending requests that alternate between IPv4 and IPv4-mapped IPv6 representations of the same IP address, which are treated as distinct identities by both the Redis and memory-based rate limiters.

## Finding Description

The vulnerability exists in how the faucet's rate limiting checkers handle IP addresses. When a request is processed, the source IP is extracted and stored in `CheckerData` as a `std::net::IpAddr` type. [1](#0-0) 

The IP address is then passed to rate limiting checkers without any normalization:

**RedisRatelimitChecker** converts the IP to a string for use as a Redis key: [2](#0-1) 

The `to_string()` method on `IpAddr` preserves the original format without normalization. This means:
- `IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))` → `"192.168.1.1"`
- `IpAddr::V6("::ffff:192.168.1.1")` → `"::ffff:192.168.1.1"`

These are stored as different keys in Redis, creating separate rate limit counters. [3](#0-2) 

**MemoryRatelimitChecker** uses `IpAddr` directly as a HashMap key: [4](#0-3) 

Rust's standard library `IpAddr` type does not consider IPv4-mapped IPv6 addresses equal to their IPv4 equivalents. The direct usage at line 77 means `IpAddr::V4(192.168.1.1)` and `IpAddr::V6(::ffff:192.168.1.1)` are treated as distinct keys. [5](#0-4) 

**Attack Path:**
1. Attacker sends requests from IP `1.2.3.4` until rate limit is reached
2. Attacker then sends requests that appear to come from `::ffff:1.2.3.4` (via dual-stack network paths or header manipulation if proxies don't properly sanitize)
3. Rate limiter treats this as a new IP with a fresh quota
4. Process repeats to continuously bypass daily request limits

The source IP is extracted in `preprocess_request()` using the `RealIp` extractor from the poem framework: [6](#0-5) 

## Impact Explanation

This vulnerability allows bypassing the faucet's rate limiting mechanism, which is the primary security control to prevent abuse. According to the Aptos bug bounty criteria, this represents a **Medium Severity** issue as it enables:

- **Service degradation**: Rapid drainage of faucet funds disrupts testnet operations
- **Resource exhaustion**: Attackers can request significantly more tokens than intended
- **Denial of service**: Legitimate developers may be unable to obtain testnet tokens

However, I must note that this vulnerability is limited to the **faucet service only** and does not affect:
- Core blockchain consensus or safety
- Mainnet operations
- Validator security
- On-chain state or governance
- Real user funds (only testnet tokens)

## Likelihood Explanation

**Likelihood: Medium to High**

The exploit is feasible if:
1. The faucet deployment is dual-stack (supports both IPv4 and IPv6)
2. Network infrastructure inconsistently represents IP addresses
3. The `RealIp` extractor receives addresses in different formats from proxies/load balancers

The attack requires no special privileges and can be executed by any client capable of controlling their network connection type or exploiting proxy header handling inconsistencies.

## Recommendation

Implement IP address normalization to convert all IPv4-mapped IPv6 addresses to their canonical IPv4 form before rate limiting:

```rust
// In checkers/mod.rs or a utility module
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            // Check if it's an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
            if let Some(ipv4) = v6.to_ipv4_mapped() {
                IpAddr::V4(ipv4)
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}
```

Then apply normalization in both rate limiters:

**For RedisRatelimitChecker:**
```rust
// In redis_ratelimit.rs, modify ratelimit_key_value
pub async fn ratelimit_key_value(&self, data: &CheckerData) -> Result<String, AptosTapError> {
    match self {
        RatelimitKeyProvider::Ip => Ok(normalize_ip(data.source_ip).to_string()),
        // ... rest of implementation
    }
}
```

**For MemoryRatelimitChecker:**
```rust
// In memory_ratelimit.rs, normalize before using as key
async fn check(&self, data: CheckerData, dry_run: bool) -> Result<Vec<RejectionReason>, AptosTapError> {
    self.clear_if_new_day().await;
    let normalized_ip = normalize_ip(data.source_ip);
    let mut ip_to_requests_today = self.ip_to_requests_today.lock().await;
    let requests_today = ip_to_requests_today.get_or_insert_mut(normalized_ip, || 1);
    // ... rest of implementation
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_mapped_ipv6_bypass() {
        // Demonstrate that IPv4 and IPv4-mapped IPv6 are treated differently
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv6_mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
        
        // These represent the same IP but are not equal
        assert_ne!(ipv4, ipv6_mapped);
        
        // String representations are different (used in Redis keys)
        assert_eq!(ipv4.to_string(), "192.168.1.1");
        assert_eq!(ipv6_mapped.to_string(), "::ffff:192.168.1.1");
        assert_ne!(ipv4.to_string(), ipv6_mapped.to_string());
        
        // HashMap treats them as different keys (used in MemoryRatelimitChecker)
        let mut map = std::collections::HashMap::new();
        map.insert(ipv4, 1);
        map.insert(ipv6_mapped, 1);
        assert_eq!(map.len(), 2); // Two separate entries instead of one
    }
}
```

## Notes

**Important Clarifications:**

1. **Scope Limitation**: This vulnerability affects **only the faucet service**, which is an auxiliary testnet component. It has **zero impact** on the core Aptos blockchain, consensus mechanism, validator operations, mainnet, or real user funds.

2. **Deployment Dependency**: Exploitability depends on network infrastructure configuration. If the faucet is behind a properly configured reverse proxy that consistently normalizes IP addresses before setting forwarded headers, the attack surface is reduced. However, the vulnerability exists in the code regardless of deployment configuration.

3. **Testnet Impact Only**: The faucet distributes testnet tokens with no monetary value. The primary harm is disruption to developers and testers, not financial loss.

4. **Bug Bounty Alignment**: Given that the Aptos bug bounty program focuses on consensus, execution, storage, governance, and staking components, this faucet-specific issue may fall outside the primary scope. However, it represents a legitimate security weakness in the aptos-core repository that should be addressed for defense-in-depth.

### Citations

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

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L186-199)
```rust
    fn get_key_and_secs_until_next_day(
        &self,
        ratelimit_key_prefix: &str,
        ratelimit_key_value: &str,
    ) -> (String, u64) {
        let now_secs = get_current_time_secs();
        let seconds_until_next_day = seconds_until_next_day(now_secs);
        let key = format!(
            "{}:{}:{}",
            ratelimit_key_prefix,
            ratelimit_key_value,
            days_since_tap_epoch(now_secs)
        );
        (key, seconds_until_next_day)
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L31-42)
```rust
pub struct MemoryRatelimitChecker {
    pub max_requests_per_day: u32,

    /// Map of IP to how many requests they've submitted today (where the
    /// response wasn't a 500). To avoid OOMing the server, we set a limit
    /// on how many entries we have in the table.
    pub ip_to_requests_today: Mutex<LruCache<IpAddr, u32>>,

    /// Used for tracking daily ratelimit. See the comment in RedisRatelimitChecker
    /// for more information on how we track daily limits.
    pub current_day: AtomicU64,
}
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L68-91)
```rust
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
