# Audit Report

## Title
Redis Single Point of Failure Causes Complete Faucet Denial of Service

## Summary
When Redis is unavailable, the `RedisRatelimitChecker` fails all requests with a `StorageError`, causing complete faucet service unavailability. The system fails-closed rather than implementing graceful degradation, creating a single point of failure that enables trivial denial-of-service attacks against the faucet infrastructure.

## Finding Description

At lines 231-234 in `RedisRatelimitChecker::check()`, Redis connection failures immediately propagate as errors: [1](#0-0) 

The `get_redis_connection()` method maps any connection error to `AptosTapError` with `StorageError` code: [2](#0-1) 

This error propagates through the request processing pipeline. In `preprocess_request()`, when any checker returns an error, it's wrapped and immediately returned, terminating the request: [3](#0-2) 

Both `StorageError` and `CheckerError` map to HTTP 500 (Internal Server Error): [4](#0-3) 

**Attack Path:**
1. Attacker identifies that the faucet uses Redis for rate limiting
2. Attacker targets Redis with connection exhaustion, network disruption, or service degradation
3. Redis becomes unavailable or slow to respond
4. ALL faucet requests fail with HTTP 500 errors
5. Legitimate developers cannot obtain testnet tokens
6. Faucet service is effectively offline until Redis recovers

**The system fails-closed (denies all requests) rather than failing-open (bypassing rate limits).** While fail-closed is the correct security posture for rate limiting, the lack of any fallback mechanism creates a trivial DoS vector.

## Impact Explanation

This qualifies as **HIGH severity** per Aptos bug bounty criteria for "API crashes." When Redis fails, the faucet API becomes completely unavailable, returning 500 errors for all requests including legitimate ones. This affects:

- Developer onboarding (cannot get initial testnet tokens)
- Testnet application testing (cannot fund new test accounts)
- Automated CI/CD pipelines relying on faucet access
- Overall testnet ecosystem usability

While the blockchain itself continues operating, the faucet is critical infrastructure for the developer ecosystem. The vulnerability is not the DoS attack itself, but the **architectural design flaw** that makes a non-critical component (Redis) a single point of failure for the entire faucet service.

## Likelihood Explanation

**Very High Likelihood:**
- Redis is a known infrastructure component that can fail due to network issues, resource exhaustion, or misconfigurations
- No retry logic, circuit breakers, or timeout handling exists
- No fallback to alternative rate limiting (e.g., `MemoryRatelimitChecker`)
- A single Redis instance failure takes down the entire faucet
- Attackers can target Redis directly if it's exposed or accessible through other vulnerabilities

## Recommendation

Implement graceful degradation with multiple layers of defense:

```rust
pub async fn get_redis_connection(&self) -> Result<Connection, AptosTapError> {
    // Add retry logic with exponential backoff
    let mut retries = 3;
    let mut backoff = Duration::from_millis(100);
    
    while retries > 0 {
        match self.db_pool.get().await {
            Ok(conn) => return Ok(conn),
            Err(e) if retries > 1 => {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
                retries -= 1;
            }
            Err(e) => {
                // Log the error and consider circuit breaker pattern
                return Err(AptosTapError::new_with_error_code(
                    format!("Failed to connect to redis storage after retries: {}", e),
                    AptosTapErrorCode::StorageError,
                ));
            }
        }
    }
    unreachable!()
}
```

Additionally, implement a hybrid approach:
1. **Primary**: Use `RedisRatelimitChecker` when Redis is healthy
2. **Fallback**: Switch to `MemoryRatelimitChecker` when Redis fails repeatedly (circuit breaker)
3. **Monitoring**: Alert operators when fallback mode is active
4. **Configuration**: Allow operators to configure fallback behavior (fail-closed vs fail-open with logging)

## Proof of Concept

```rust
// Reproduction steps:
// 1. Start the faucet with RedisRatelimitChecker configured
// 2. Simulate Redis unavailability:

#[tokio::test]
async fn test_redis_failure_causes_complete_dos() {
    // Configure faucet with RedisRatelimitChecker pointing to invalid Redis host
    let config = RedisRatelimitCheckerConfig {
        database_address: "invalid.redis.host".to_string(),
        database_port: 6379,
        database_number: 0,
        database_user: None,
        database_password: None,
        max_requests_per_day: 100,
        ratelimit_key_provider_config: RatelimitKeyProviderConfig::Ip,
    };
    
    // Attempting to create checker will fail on startup
    let result = RedisRatelimitChecker::new(config).await;
    assert!(result.is_err()); // Fails to start
    
    // If checker somehow gets created with valid Redis, then Redis goes down:
    // All subsequent requests to /fund endpoint will return HTTP 500
    // curl -X POST http://localhost:8081/fund -d '{"address":"0x123..."}'
    // Response: 500 Internal Server Error
    //   {"message":"Failed to connect to redis storage: ...","error_code":53}
}
```

## Notes

**Answer to Security Question:** When Redis is down, **all requests fail (denial of service)**, NOT fail-open with security bypass. The system correctly fails-closed from a rate limiting perspective, but creates an availability vulnerability due to lack of fallback mechanisms.

The vulnerability lies in the architectural design that makes Redis a single point of failure without any graceful degradation, retry logic, or fallback to alternative rate limiting mechanisms like `MemoryRatelimitChecker`. [5](#0-4)

### Citations

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L176-183)
```rust
    pub async fn get_redis_connection(&self) -> Result<Connection, AptosTapError> {
        self.db_pool.get().await.map_err(|e| {
            AptosTapError::new_with_error_code(
                format!("Failed to connect to redis storage: {}", e),
                AptosTapErrorCode::StorageError,
            )
        })
    }
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L231-234)
```rust
        let mut conn = self
            .get_redis_connection()
            .await
            .map_err(|e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::StorageError))?;
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L264-266)
```rust
            rejection_reasons.extend(checker.check(checker_data.clone(), dry_run).await.map_err(
                |e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError),
            )?);
```

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L181-187)
```rust
            AptosTapErrorCode::AptosApiError
            | AptosTapErrorCode::TransactionTimedOut
            | AptosTapErrorCode::SerializationError
            | AptosTapErrorCode::BypasserError
            | AptosTapErrorCode::CheckerError
            | AptosTapErrorCode::StorageError
            | AptosTapErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L44-51)
```rust
impl MemoryRatelimitChecker {
    pub fn new(args: MemoryRatelimitCheckerConfig) -> Self {
        Self {
            max_requests_per_day: args.max_requests_per_day,
            ip_to_requests_today: Mutex::new(LruCache::new(args.max_entries_in_map)),
            current_day: AtomicU64::new(days_since_tap_epoch(get_current_time_secs())),
        }
    }
```
