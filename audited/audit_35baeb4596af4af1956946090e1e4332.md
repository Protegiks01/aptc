# Audit Report

## Title
Aptos Faucet Rate Limiting Day Boundary Misalignment Allows Double Quota Exploitation

## Summary
The Redis-based rate limiting implementation in the Aptos Faucet contains a timing vulnerability where the day counter calculation (`days_since_tap_epoch`) and TTL expiration (`seconds_until_next_day`) use misaligned epoch references. This allows attackers to obtain double the intended daily quota by timing requests around the TAP_EPOCH day boundary at 07:21:00 UTC.

## Finding Description

The vulnerability exists in the `get_key_and_secs_until_next_day()` function where two different time calculations create a 7-hour-21-minute window for exploitation. [1](#0-0) 

The TAP_EPOCH_SECS constant is set to 1664089260 (September 25, 2021, 12:01am PDT). When calculated: `1664089260 % 86400 = 26460 seconds = 7 hours, 21 minutes`. [2](#0-1) 

The day counter uses TAP_EPOCH as its reference point, incrementing at 07:21:00 UTC each day. [3](#0-2) 

However, the TTL calculation uses Unix epoch (midnight UTC) as its reference point. [4](#0-3) 

The Redis key includes the day number from `days_since_tap_epoch`, but the TTL expires at Unix epoch midnight, creating a misalignment.

**Exploitation Path:**
1. At 07:20:59 UTC, attacker exhausts daily quota with key `"prefix:value:D"` and TTL of ~59,940 seconds (16h 39m until midnight)
2. At 07:21:00 UTC, `days_since_tap_epoch` increments to `D+1`, creating new key `"prefix:value:D+1"`  
3. Attacker can immediately exhaust another full daily quota with the new key
4. Old key remains in Redis with 16+ hours of TTL but is never checked again [5](#0-4) 

When the limit_value is None (first request of new day), the TTL is set based on `seconds_until_next_day`, which doesn't align with when the day counter will increment next.

## Impact Explanation

**Severity Assessment: Out of Scope / Low**

While this is a genuine rate limiting bypass vulnerability, it falls outside the critical blockchain security scope:

1. **Not a blockchain consensus/execution issue**: The faucet is an auxiliary testnet service, not part of core blockchain operations (AptosBFT consensus, Move VM execution, state management)
2. **No impact on blockchain invariants**: Does not affect Deterministic Execution, Consensus Safety, Move VM Safety, State Consistency, or any of the 10 listed critical invariants
3. **Limited to testnet token distribution**: Exploitation only results in receiving extra free testnet tokens, which have no real-world value
4. **No funds at risk**: Does not enable theft, minting, or manipulation of mainnet funds
5. **No consensus/availability impact**: Does not affect validator operations, network liveness, or blockchain state

Per Aptos Bug Bounty categories, this does not meet Medium severity criteria ("Limited funds loss or manipulation" / "State inconsistencies requiring intervention") as it affects only a testnet utility service.

## Likelihood Explanation

**Likelihood: High (if in scope)**

The vulnerability is easily exploitable:
- Requires no special privileges or insider access
- Attack timing is predictable (daily at 07:21:00 UTC)
- No complex technical requirements
- Can be automated with simple scripts
- Window of opportunity occurs every 24 hours

However, the impact is confined to testnet faucet abuse rather than blockchain security compromise.

## Recommendation

**Option 1: Align TTL calculation with TAP_EPOCH day boundaries**
```rust
pub fn seconds_until_next_tap_epoch_day(current_time_secs: u64) -> u64 {
    let seconds_since_tap_epoch = current_time_secs - TAP_EPOCH_SECS;
    let seconds_into_current_day = seconds_since_tap_epoch % 86400;
    86400 - seconds_into_current_day
}
```

Then update `get_key_and_secs_until_next_day`:
```rust
let seconds_until_next_day = seconds_until_next_tap_epoch_day(now_secs);
```

**Option 2: Use Unix epoch day boundaries for both calculations**
```rust
fn get_key_and_secs_until_next_day(...) -> (String, u64) {
    let now_secs = get_current_time_secs();
    let seconds_until_next_day = seconds_until_next_day(now_secs);
    let days_since_unix_epoch = now_secs / 86400;  // Use Unix epoch consistently
    let key = format!("{}:{}:{}", ratelimit_key_prefix, ratelimit_key_value, days_since_unix_epoch);
    (key, seconds_until_next_day)
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_day_boundary_misalignment() {
        // TAP_EPOCH_SECS % 86400 = 26460 (7h 21m into Unix day)
        assert_eq!(1664089260 % 86400, 26460);
        
        // Simulate time at 07:20:59 UTC on some day
        let time_before = 1700000000u64; // arbitrary timestamp
        let adjusted_time_before = (time_before / 86400) * 86400 + 26459; // 1 sec before boundary
        
        let day_before = days_since_tap_epoch(adjusted_time_before);
        let ttl_before = seconds_until_next_day(adjusted_time_before);
        
        // One second later at 07:21:00 UTC
        let adjusted_time_after = adjusted_time_before + 1;
        let day_after = days_since_tap_epoch(adjusted_time_after);
        let ttl_after = seconds_until_next_day(adjusted_time_after);
        
        // Day counter increments
        assert_eq!(day_after, day_before + 1);
        
        // But TTL still has ~16.6 hours (59940 seconds) until Unix midnight
        assert!(ttl_after > 59000);
        assert!(ttl_before > 59000);
        
        println!("Day boundary crossed: {} -> {}", day_before, day_after);
        println!("TTL still has {} seconds until expiry", ttl_after);
        println!("Attacker gets new key but old key hasn't expired!");
    }
}
```

---

**Notes:**

This vulnerability is **technically valid** as a rate limiting bypass bug, but it **does not qualify** as a Critical, High, or Medium severity blockchain security issue per the Aptos Bug Bounty program scope. The faucet is an auxiliary testnet service, and exploitation only results in receiving extra free testnet tokens with no real-world value or impact on blockchain consensus, execution, storage, or validator operations.

For an elite Aptos Blockchain Security Auditor focused on "consensus vulnerabilities, Move VM implementation bugs, state management attacks, and on-chain governance security," this finding falls outside the primary security audit scope targeting the core blockchain implementation.

### Citations

**File:** crates/aptos-faucet/core/src/helpers.rs (L29-29)
```rust
pub const TAP_EPOCH_SECS: u64 = 1664089260;
```

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
