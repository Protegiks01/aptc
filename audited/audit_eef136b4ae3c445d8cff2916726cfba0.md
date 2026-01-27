# Audit Report

## Title
Off-By-One Error in MemoryRatelimitChecker Prevents Any Requests When max_requests_per_day=1

## Summary
The `MemoryRatelimitChecker.check()` function contains an off-by-one error that causes users to receive exactly `(max_requests_per_day - 1)` requests instead of the configured limit. When `max_requests_per_day` is set to 1, users cannot make any requests at all, resulting in complete denial of service for the faucet.

## Finding Description
The bug exists in the rate limiting logic where the counter is incorrectly initialized and compared. [1](#0-0) 

When a new IP address makes its first request, the code initializes the counter to 1 immediately. [2](#0-1)  Then it checks if this value is `>=` the configured limit. For `max_requests_per_day = 1`, the check `1 >= 1` evaluates to true, causing immediate rejection.

The correct implementation can be seen in the Redis-based rate limiter, which initializes counters to 0 and uses strict greater-than comparison. [3](#0-2) [4](#0-3) 

**Execution trace when max_requests_per_day = 1:**
1. First request arrives from IP 1.2.3.4
2. `get_or_insert_mut` initializes counter to 1
3. Check: `1 >= 1` → TRUE
4. Request rejected with "IP has exceeded the daily limit"
5. User receives 0 requests instead of 1

**General impact:** Users receive `(max_requests_per_day - 1)` requests for any configured value.

## Impact Explanation
This is classified as **Low Severity** per Aptos bug bounty criteria as a "non-critical implementation bug." The faucet service is not a critical blockchain component—it does not affect consensus safety, Move VM execution, state consistency, or validator operations. The bug causes functional degradation of a testing/development service used for token distribution, but does not compromise blockchain security, validator nodes, or user funds on mainnet.

## Likelihood Explanation
This bug triggers automatically whenever:
1. The faucet is deployed with `MemoryRatelimit` checker (instead of `RedisRatelimit`)
2. Any value is configured for `max_requests_per_day`
3. Users make requests to the faucet

The likelihood is HIGH that affected deployments experience this issue, but the scope is limited to faucet functionality only.

## Recommendation
Fix both the initialization value and comparison operator to match the Redis implementation:

```rust
// Change line 77 from:
let requests_today = ip_to_requests_today.get_or_insert_mut(data.source_ip, || 1);

// To:
let requests_today = ip_to_requests_today.get_or_insert_mut(data.source_ip, || 0);

// Change line 78 from:
if *requests_today >= self.max_requests_per_day {

// To:
if *requests_today > self.max_requests_per_day {
```

Alternatively, keep `>=` but adjust the initialization and increment logic to match the intended semantics.

## Proof of Concept
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    
    #[tokio::test]
    async fn test_max_requests_per_day_boundary() {
        // Test with max_requests_per_day = 1
        let config = MemoryRatelimitCheckerConfig {
            max_requests_per_day: 1,
            max_entries_in_map: NonZeroUsize::new(1000).unwrap(),
        };
        let checker = MemoryRatelimitChecker::new(config);
        
        let test_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let checker_data = CheckerData {
            source_ip: test_ip,
            // ... other fields
        };
        
        // First request - should be ALLOWED but will be REJECTED due to bug
        let result = checker.check(checker_data.clone(), false).await.unwrap();
        assert!(result.is_empty(), "First request should be allowed, got: {:?}", result);
        
        // Second request - should be REJECTED
        let result = checker.check(checker_data.clone(), false).await.unwrap();
        assert!(!result.is_empty(), "Second request should be rejected");
    }
    
    #[tokio::test]
    async fn test_max_requests_general() {
        // Test with max_requests_per_day = 3
        let config = MemoryRatelimitCheckerConfig {
            max_requests_per_day: 3,
            max_entries_in_map: NonZeroUsize::new(1000).unwrap(),
        };
        let checker = MemoryRatelimitChecker::new(config);
        
        let test_ip: IpAddr = "192.168.1.2".parse().unwrap();
        let checker_data = CheckerData {
            source_ip: test_ip,
            // ... other fields
        };
        
        // Should allow exactly 3 requests
        for i in 1..=3 {
            let result = checker.check(checker_data.clone(), false).await.unwrap();
            assert!(result.is_empty(), "Request {} should be allowed", i);
        }
        
        // 4th request should be rejected
        let result = checker.check(checker_data.clone(), false).await.unwrap();
        assert!(!result.is_empty(), "4th request should be rejected");
    }
}
```

## Notes
This finding demonstrates a discrepancy between the Memory and Redis rate limiter implementations. While the Redis version correctly allows `max_requests_per_day` requests, the Memory version allows only `(max_requests_per_day - 1)` requests due to incorrect initialization and comparison logic. The bug is isolated to the faucet service and does not impact core blockchain security properties.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L77-77)
```rust
        let requests_today = ip_to_requests_today.get_or_insert_mut(data.source_ip, || 1);
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L78-85)
```rust
        if *requests_today >= self.max_requests_per_day {
            return Ok(vec![RejectionReason::new(
                format!(
                    "IP {} has exceeded the daily limit of {} requests",
                    data.source_ip, self.max_requests_per_day
                ),
                RejectionReasonCode::UsageLimitExhausted,
            )]);
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L207-207)
```rust
        if limit_value.unwrap_or(0) > self.args.max_requests_per_day as i64 {
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L247-252)
```rust
        let limit_value: Option<i64> = conn.get(&key).await.map_err(|e| {
            AptosTapError::new_with_error_code(
                format!("Failed to get value for redis key {}: {}", key, e),
                AptosTapErrorCode::StorageError,
            )
        })?;
```
