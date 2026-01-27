# Audit Report

## Title
Redis Key Expiration Mismatch Allows Rate Limit Bypass in Aptos Faucet

## Summary
The Aptos faucet's Redis-based rate limiting system uses misaligned epoch boundaries for key generation and TTL calculation, allowing attackers to bypass daily rate limits by exploiting the timing window where Unix day boundaries cross TAP_EPOCH day boundaries. This enables users to obtain up to 2x their intended daily token allocation.

## Finding Description

The vulnerability exists in the interaction between two helper functions that use different epoch bases: [1](#0-0) [2](#0-1) 

The critical issue is in how these functions are used together: [3](#0-2) 

**The Epoch Mismatch:**
- `days_since_tap_epoch()` calculates day numbers from `TAP_EPOCH_SECS` (1664089260), creating day boundaries at TAP_EPOCH_SECS + N×86400
- `seconds_until_next_day()` uses modulo 86400 on the raw timestamp, creating day boundaries at Unix epoch multiples (N×86400)
- These systems are offset by 1664089260 % 86400 = 43260 seconds (≈12 hours)

**Exploitation Scenario:**

1. At Unix timestamp 1664150399 (during TAP_EPOCH day 0, 1 second before Unix day boundary):
   - Redis key: "ip:192.168.1.1:0" (day 0)
   - User makes `max_requests_per_day` requests, reaching the limit
   - Key TTL: 1 second (until Unix day boundary)

2. At Unix timestamp 1664150400 (Unix day boundary crossed, but still TAP_EPOCH day 0):
   - Previous key expired due to TTL
   - `days_since_tap_epoch(1664150400)` = 0 (still day 0!)
   - TAP_EPOCH day 0 doesn't end until timestamp 1664175660 (25260 seconds later)

3. User makes new requests:
   - Same key name "ip:192.168.1.1:0" is generated (same TAP_EPOCH day)
   - Key doesn't exist in Redis (was expired)
   - New key created with fresh counter = 1 [4](#0-3) 

4. User can now make another `max_requests_per_day` requests during the same TAP_EPOCH day, effectively bypassing the rate limit.

## Impact Explanation

**Severity: Medium**

While this vulnerability is in the faucet (a testnet utility) rather than core consensus/VM components, it represents a significant security issue:

1. **Rate Limit Bypass**: Attackers can obtain 2x their intended daily token allocation by timing requests around Unix day boundaries that fall within TAP_EPOCH days
2. **Faucet Resource Exhaustion**: Coordinated exploitation by multiple actors could rapidly drain faucet reserves, causing denial of service for legitimate users
3. **Testnet Integrity**: Large-scale abuse could impact testnet stability and developer experience
4. **Pattern Risk**: The same epoch mismatch pattern could exist in other rate-limiting code if copied

This meets the **Medium severity** criteria as it enables manipulation of the faucet's resource distribution mechanism, though it doesn't affect mainnet funds or consensus.

## Likelihood Explanation

**Likelihood: High**

- **Predictability**: Unix and TAP_EPOCH day boundaries are deterministic and publicly calculable
- **Exploitation Window**: The vulnerability is exploitable for up to 43260 seconds (12 hours) per TAP_EPOCH day
- **Attack Complexity**: Low - attackers only need to:
  1. Calculate when Unix day boundaries fall within TAP_EPOCH days
  2. Make max requests before the boundary
  3. Make max requests after the boundary
- **No Privileges Required**: Any user with network access can exploit this
- **Detection Difficulty**: The behavior appears as legitimate usage spread across a "day boundary"

## Recommendation

Use consistent epoch boundaries for both key generation and TTL calculation. The fix should align TTL expiration with TAP_EPOCH day boundaries:

```rust
// In helpers.rs, add a new function:
pub fn seconds_until_next_tap_epoch_day(current_time_secs: u64) -> u64 {
    let seconds_since_tap_epoch = current_time_secs - TAP_EPOCH_SECS;
    let seconds_into_current_day = seconds_since_tap_epoch % 86400;
    86400 - seconds_into_current_day
}

// In redis_ratelimit.rs, update get_key_and_secs_until_next_day:
fn get_key_and_secs_until_next_day(
    &self,
    ratelimit_key_prefix: &str,
    ratelimit_key_value: &str,
) -> (String, u64) {
    let now_secs = get_current_time_secs();
    let seconds_until_next_day = seconds_until_next_tap_epoch_day(now_secs); // Changed
    let key = format!(
        "{}:{}:{}",
        ratelimit_key_prefix,
        ratelimit_key_value,
        days_since_tap_epoch(now_secs)
    );
    (key, seconds_until_next_day)
}
```

This ensures Redis keys expire precisely when TAP_EPOCH days end, eliminating the timing window.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_epoch_mismatch_vulnerability() {
        // TAP_EPOCH_SECS = 1664089260
        // Unix day boundary at 1664150400
        // TAP_EPOCH day 0 ends at 1664175660
        
        // Time just before Unix day boundary (still in TAP_EPOCH day 0)
        let time_before_unix_day = 1664150399;
        let day_before = days_since_tap_epoch(time_before_unix_day);
        let ttl_before = seconds_until_next_day(time_before_unix_day);
        
        assert_eq!(day_before, 0, "Should be TAP_EPOCH day 0");
        assert_eq!(ttl_before, 1, "Should have 1 second until Unix day boundary");
        
        // Time after Unix day boundary (still in TAP_EPOCH day 0!)
        let time_after_unix_day = 1664150400;
        let day_after = days_since_tap_epoch(time_after_unix_day);
        let ttl_after = seconds_until_next_day(time_after_unix_day);
        
        assert_eq!(day_after, 0, "Should STILL be TAP_EPOCH day 0");
        assert_eq!(ttl_after, 86400, "New Unix day started, long TTL");
        
        // The vulnerability: same day number but key would have expired
        assert_eq!(day_before, day_after, "Same TAP_EPOCH day = same key name");
        
        // TAP_EPOCH day 0 doesn't end until 25260 seconds later
        let tap_epoch_day_end = 1664175660;
        let day_at_tap_end = days_since_tap_epoch(tap_epoch_day_end);
        assert_eq!(day_at_tap_end, 1, "TAP_EPOCH day only changes here");
        
        println!("Vulnerability confirmed: {} second window where same key can be recreated", 
                 tap_epoch_day_end - time_after_unix_day);
    }
}
```

## Notes

This vulnerability is specific to the faucet component and does not affect core blockchain consensus, Move VM execution, or on-chain state management. However, it represents a significant issue for testnet operations and could be exploited to drain faucet resources or bypass intended usage restrictions. The pattern of mixing epoch bases should be audited in other rate-limiting or time-based systems across the codebase.

### Citations

**File:** crates/aptos-faucet/core/src/helpers.rs (L33-35)
```rust
pub fn days_since_tap_epoch(current_time_secs: u64) -> u64 {
    (current_time_secs - TAP_EPOCH_SECS) / 86400
}
```

**File:** crates/aptos-faucet/core/src/helpers.rs (L37-40)
```rust
pub fn seconds_until_next_day(current_time_secs: u64) -> u64 {
    let seconds_since_midnight = current_time_secs % 86400;
    86400 - seconds_since_midnight
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

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L273-292)
```rust
                None => {
                    let (incremented_limit_value,): (i64,) = redis::pipe()
                        .atomic()
                        .incr(&key, 1)
                        // Expire at the end of the day roughly.
                        .expire(&key, seconds_until_next_day as usize)
                        // Only set the expiration if one isn't already set.
                        // Only works with Redis 7 sadly.
                        // .arg("NX")
                        .ignore()
                        .query_async(&mut *conn)
                        .await
                        .map_err(|e| {
                            AptosTapError::new_with_error_code(
                                format!("Failed to increment value for redis key {}: {}", key, e),
                                AptosTapErrorCode::StorageError,
                            )
                        })?;
                    incremented_limit_value
                },
```
