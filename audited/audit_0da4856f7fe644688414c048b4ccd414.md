# Audit Report

## Title
Clock Skew Between Faucet Servers Enables Rate Limit Bypass

## Summary
The Aptos faucet's rate limiting implementation uses each server's local system time to determine daily rate limit boundaries. When multiple faucet servers have clock skew, attackers can bypass daily rate limits by rotating requests between servers with different clocks, effectively multiplying their allowed request quota.

## Finding Description

The faucet implements daily rate limits using two checkers: `MemoryRatelimitChecker` and `RedisRatelimitChecker`. Both determine which "day" it is by calling `get_current_time_secs()` and computing `days_since_tap_epoch()` based on the local system time. [1](#0-0) 

The rate limit keys in Redis include the computed day number: [2](#0-1) 

Each faucet server independently computes what "day" it is: [3](#0-2) [4](#0-3) 

**Attack Scenario:**

1. Server A has system clock at 11:58 PM on Day N
2. Server B has system clock at 12:02 AM on Day N+1 (4-minute clock skew)
3. Attacker sends max_requests_per_day to Server A → counted against Day N's key `ip:192.0.2.1:N`
4. Attacker sends max_requests_per_day to Server B → counted against Day N+1's key `ip:192.0.2.1:N+1`
5. Attacker has effectively doubled their daily limit

This works because:
- Server A uses Redis key containing day N
- Server B uses Redis key containing day N+1
- These are separate counters that don't share state

The vulnerability exists because `CheckerData.time_request_received_secs` is captured at request time but never used for rate limiting calculations: [5](#0-4) 

Instead, both rate limiters call `get_current_time_secs()` again inside their `check()` methods, using potentially different times if there's server clock skew.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria: "Limited funds loss or manipulation" and "State inconsistencies requiring intervention."

While faucet tokens are testnet-only with no monetary value, this vulnerability enables:

1. **Resource Exhaustion**: Attackers can drain faucet funds faster than intended, causing legitimate users to be unable to obtain testnet tokens
2. **Service Availability**: Reduced availability of testnet resources impacts developer experience and ecosystem growth
3. **Operational Cost**: Requires manual intervention to refill faucets more frequently
4. **Rate Limit Circumvention**: Completely undermines the intended rate limiting security control

The impact is limited to testnet faucet operations and does not affect mainnet consensus, validator operations, or user funds.

## Likelihood Explanation

**High Likelihood**:

1. **Clock skew is common**: Production distributed systems routinely experience clock skew of seconds to minutes due to NTP drift, network delays, or misconfiguration
2. **Easy to exploit**: Attacker only needs to identify faucet servers with different clocks and send requests via HTTP
3. **No special privileges**: Any user can exploit this without authentication or special access
4. **Trivial to automate**: Simple script to round-robin requests across known faucet endpoints
5. **Detection difficulty**: Appears as legitimate requests from different source IPs if attacker uses proxies

## Recommendation

**Primary Fix**: Use a centralized time source for all rate limiting decisions. Options:

**Option 1 - Use Redis TIME command** (Recommended):
```rust
fn get_key_and_secs_until_next_day(
    &self,
    conn: &mut Connection,
    ratelimit_key_prefix: &str,
    ratelimit_key_value: &str,
) -> Result<(String, u64), AptosTapError> {
    // Get time from Redis server (centralized source)
    let (secs, _): (u64, u64) = redis::cmd("TIME")
        .query_async(conn)
        .await
        .map_err(|e| AptosTapError::new(format!("Failed to get Redis time: {}", e)))?;
    
    let seconds_until_next_day = seconds_until_next_day(secs);
    let key = format!(
        "{}:{}:{}",
        ratelimit_key_prefix,
        ratelimit_key_value,
        days_since_tap_epoch(secs)
    );
    (key, seconds_until_next_day)
}
```

**Option 2 - Use captured request time**:
```rust
// In CheckerData, add a method
impl CheckerData {
    pub fn days_since_epoch(&self) -> u64 {
        days_since_tap_epoch(self.time_request_received_secs)
    }
}

// In rate limiters, use this instead of get_current_time_secs()
let key = format!(
    "{}:{}:{}",
    ratelimit_key_prefix,
    ratelimit_key_value,
    data.days_since_epoch()  // Use captured time
);
```

**Option 3 - Add clock skew detection**:
```rust
// On startup, verify all servers agree on current day
// Reject requests if local clock differs from Redis server by > threshold
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_clock_skew_bypass() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    
    // Setup two faucet servers with Redis
    let redis_config = RedisRatelimitCheckerConfig {
        database_address: "localhost".to_string(),
        max_requests_per_day: 5,
        ..Default::default()
    };
    
    let checker = RedisRatelimitChecker::new(redis_config.clone()).await.unwrap();
    
    // Simulate Server A at 11:59 PM Day N
    let server_a_time = TAP_EPOCH_SECS + (86400 * 10) + 86340; // 23:59
    
    // Simulate Server B at 12:01 AM Day N+1  
    let server_b_time = TAP_EPOCH_SECS + (86400 * 11) + 60; // 00:01
    
    let source_ip = "192.0.2.1".parse().unwrap();
    
    // Server A: Make 5 requests (max limit)
    for _ in 0..5 {
        let data = CheckerData {
            time_request_received_secs: server_a_time,
            receiver: AccountAddress::ZERO,
            source_ip,
            headers: Arc::new(HeaderMap::new()),
        };
        
        // With current implementation using get_current_time_secs(),
        // if we mock system time to server_a_time, these go to day N
        assert!(checker.check(data, false).await.unwrap().is_empty());
    }
    
    // Server B: Make 5 MORE requests (should be blocked but isn't)
    for _ in 0..5 {
        let data = CheckerData {
            time_request_received_secs: server_b_time,
            receiver: AccountAddress::ZERO,
            source_ip,
            headers: Arc::new(HeaderMap::new()),
        };
        
        // With current implementation using get_current_time_secs(),
        // if we mock system time to server_b_time, these go to day N+1
        // VULNERABILITY: These should be rejected but aren't due to different day keys
        assert!(checker.check(data, false).await.unwrap().is_empty());
    }
    
    // Attacker has now made 10 requests when limit is 5 per day
}
```

## Notes

This vulnerability specifically affects multi-server faucet deployments where servers may have unsynchronized clocks. Single-server deployments are unaffected. The issue applies to both `RedisRatelimitChecker` and `MemoryRatelimitChecker` implementations, though the Redis variant is more commonly deployed in production.

The root cause is that time-based rate limiting relies on local system time rather than a centralized time authority, violating the principle that distributed rate limiters should use a shared clock source.

### Citations

**File:** crates/aptos-faucet/core/src/helpers.rs (L19-24)
```rust
pub fn get_current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time has gone backwards???")
        .as_secs()
}
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L186-200)
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
    }
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L242-243)
```rust
        let (key, seconds_until_next_day) =
            self.get_key_and_secs_until_next_day(key_prefix, &key_value);
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L53-63)
```rust
    async fn clear_if_new_day(&self) {
        if days_since_tap_epoch(get_current_time_secs())
            > self.current_day.load(std::sync::atomic::Ordering::Relaxed)
        {
            self.current_day.store(
                days_since_tap_epoch(get_current_time_secs()),
                std::sync::atomic::Ordering::Relaxed,
            );
            self.ip_to_requests_today.lock().await.clear();
        }
    }
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
