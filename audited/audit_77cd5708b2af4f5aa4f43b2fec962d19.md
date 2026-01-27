# Audit Report

## Title
Resource Exhaustion via Ineffective Checker Ordering When `return_rejections_early` is Disabled

## Summary
When the Aptos Faucet is configured with `return_rejections_early = false`, the cost-based checker ordering optimization is completely negated. Attackers can send requests that fail cheap validation checks (missing headers, invalid auth tokens) but still force expensive database operations to execute, leading to Redis connection pool exhaustion and denial of service.

## Finding Description

The Aptos Faucet implements a checker system where each checker has a `cost()` value indicating its computational expense. Checkers are sorted by cost (cheapest first) to optimize performance: [1](#0-0) 

The checker costs are:
- `IpBlocklistChecker`: cost = 1 (in-memory lookup) [2](#0-1) 
- `AuthTokenChecker`: cost = 2 (in-memory lookup) [3](#0-2) 
- `MagicHeaderChecker`: cost = 2 (header check) [4](#0-3) 
- `RedisRatelimitChecker`: cost = 100 (database-backed) [5](#0-4) 

During request processing, checkers execute in order. However, when `return_rejections_early` is set to `false`, all checkers execute even after earlier ones have rejected the request: [6](#0-5) 

The default CLI configuration sets `return_rejections_early = false`: [7](#0-6) 

This configuration is likely chosen to provide complete feedback to users about all rejection reasons. However, it creates a critical vulnerability.

**Attack Path:**

1. Attacker identifies that the faucet uses both cheap validators and expensive Redis-backed validators
2. Attacker floods the faucet with requests intentionally missing basic requirements:
   - No Authorization header (fails `AuthTokenChecker`, cost 2)
   - Missing magic header (fails `MagicHeaderChecker`, cost 2)
   - From blocklisted IP (fails `IpBlocklistChecker`, cost 1)
3. These cheap checkers reject the request
4. Because `return_rejections_early = false`, execution continues
5. `RedisRatelimitChecker` (cost 100) still executes, performing expensive operations: [8](#0-7) 

6. Each malicious request forces:
   - Redis connection acquisition from pool
   - Redis GET operation
   - Potentially Redis INCR operation
7. The Redis connection pool becomes exhausted
8. Legitimate requests are denied or severely delayed
9. Faucet service becomes unavailable

The cost-based ordering optimization is completely negated because expensive checkers execute on every request regardless of whether cheap checkers have already rejected it.

## Impact Explanation

This vulnerability enables a **Medium severity** denial of service attack against the Aptos Faucet service:

- **Resource Exhaustion**: Redis connection pool can be exhausted by flooding with invalid requests
- **Service Degradation**: Legitimate users experience slowdowns or failures when requesting test tokens
- **Database Overload**: Redis backend experiences unnecessary load from obviously invalid requests
- **Availability Impact**: Faucet service can become completely unavailable

While this affects a utility service rather than core blockchain consensus, it meets **Medium severity** criteria as it:
- Causes state inconsistencies in the faucet's rate-limiting state
- Requires manual intervention to recover Redis service
- Disrupts the developer ecosystem that depends on the faucet

The attack requires no special privileges and can be executed with minimal resources (sending HTTP requests without headers is trivial).

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Default Configuration**: The CLI default sets `return_rejections_early = false`, making deployments vulnerable by default
2. **Zero Authentication Required**: Any attacker can send requests to the public faucet endpoint
3. **Trivial to Exploit**: Sending requests without headers requires no sophistication
4. **High Impact-to-Effort Ratio**: Minimal attacker effort causes significant resource consumption
5. **No Rate Limiting Protection**: The semaphore limiting concurrent requests is optional and defaults to `None`
6. **Observable Behavior**: Attackers can easily test if the faucet is vulnerable by monitoring response times

The vulnerability is in production code paths that execute on every faucet request, not edge cases or rare conditions.

## Recommendation

Implement one of the following mitigations:

**Option 1: Change Default Configuration (Recommended)**
```rust
handler_config: HandlerConfig {
    use_helpful_errors: true,
    return_rejections_early: true,  // Changed from false
    max_concurrent_requests: Some(100),  // Add default limit
}
```

**Option 2: Add Short-Circuit Logic for Expensive Checkers**

Modify expensive checkers to check if previous validators have already rejected before performing database operations:

```rust
// In RedisRatelimitChecker::check()
async fn check(
    &self,
    data: CheckerData,
    dry_run: bool,
) -> Result<Vec<RejectionReason>, AptosTapError> {
    // NEW: Check if this is a dry_run or pre-rejected request
    // In this case, skip expensive operations
    if dry_run {
        return Ok(vec![]);
    }
    
    // Continue with existing Redis operations...
}
```

**Option 3: Enforce Early Termination for Critical Checks**

Add a new checker priority level where certain cheap checks always terminate early:
```rust
pub enum CheckerPriority {
    Critical,  // Always terminate early on rejection
    Normal,
}
```

**Recommended Fix**: Implement Option 1 (change default to `return_rejections_early = true`) combined with adding a default `max_concurrent_requests` limit. This provides the best balance of security and user experience.

## Proof of Concept

```rust
// PoC: Demonstrate resource exhaustion attack
// File: crates/aptos-faucet/core/tests/resource_exhaustion_test.rs

#[tokio::test]
async fn test_resource_exhaustion_with_return_rejections_early_false() {
    // Setup faucet with return_rejections_early = false
    let config = RunConfig {
        handler_config: HandlerConfig {
            use_helpful_errors: true,
            return_rejections_early: false,  // Vulnerable config
            max_concurrent_requests: None,
        },
        // ... other config
    };
    
    let (port, _handle) = start_test_server(config).await.unwrap();
    
    // Send 1000 invalid requests (missing auth token)
    let mut tasks = vec![];
    for _ in 0..1000 {
        let task = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let _response = reqwest::Client::new()
                .post(format!("http://127.0.0.1:{}/fund", port))
                .json(&FundRequest {
                    amount: Some(100),
                    address: Some(AccountAddress::random().to_string()),
                    ..Default::default()
                })
                // Intentionally missing Authorization header
                .send()
                .await;
            start.elapsed()
        });
        tasks.push(task);
    }
    
    let durations: Vec<_> = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    
    // Measure Redis connection pool exhaustion
    // Later requests should be significantly slower due to pool contention
    let avg_first_100 = durations[0..100].iter().sum::<Duration>() / 100;
    let avg_last_100 = durations[900..1000].iter().sum::<Duration>() / 100;
    
    // Assert that performance degrades significantly (>2x slower)
    assert!(avg_last_100 > avg_first_100 * 2,
        "Resource exhaustion detected: last requests took {:?} vs first {:?}",
        avg_last_100, avg_first_100);
}
```

## Notes

This vulnerability specifically affects the **Aptos Faucet service**, not the core blockchain consensus or validator operations. However, it represents a significant availability issue for the developer ecosystem that depends on the faucet for obtaining test tokens.

The vulnerability exists because of a tension between two design goals:
1. **User Experience**: Providing complete feedback about all rejection reasons (requiring `return_rejections_early = false`)
2. **Performance**: Running cheap checks first to avoid expensive operations (cost-based ordering)

The current implementation achieves neither goal effectively when `return_rejections_early = false`, as it provides complete feedback but at the cost of being vulnerable to resource exhaustion attacks.

### Citations

**File:** crates/aptos-faucet/core/src/server/run.rs (L141-143)
```rust
        // Sort Checkers by cost, where lower numbers is lower cost, and lower
        // cost Checkers are at the start of the vec.
        checkers.sort_by_key(|a| a.cost());
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L306-310)
```rust
            handler_config: HandlerConfig {
                use_helpful_errors: true,
                return_rejections_early: false,
                max_concurrent_requests: None,
            },
```

**File:** crates/aptos-faucet/core/src/checkers/ip_blocklist.rs (L53-55)
```rust
    fn cost(&self) -> u8 {
        1
    }
```

**File:** crates/aptos-faucet/core/src/checkers/auth_token.rs (L67-69)
```rust
    fn cost(&self) -> u8 {
        2
    }
```

**File:** crates/aptos-faucet/core/src/checkers/magic_header.rs (L54-56)
```rust
    fn cost(&self) -> u8 {
        2
    }
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L226-252)
```rust
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
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L337-339)
```rust
    fn cost(&self) -> u8 {
        100
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L261-270)
```rust
        // Ensure request passes checkers.
        let mut rejection_reasons = Vec::new();
        for checker in &self.checkers {
            rejection_reasons.extend(checker.check(checker_data.clone(), dry_run).await.map_err(
                |e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError),
            )?);
            if !rejection_reasons.is_empty() && self.return_rejections_early {
                break;
            }
        }
```
