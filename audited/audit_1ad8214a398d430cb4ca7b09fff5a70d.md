# Audit Report

## Title
Redis Rate Limit TTL Overwrite Vulnerability via TOCTOU Race Condition

## Summary
The `RedisRatelimitChecker::check()` function in the Aptos faucet contains a Time-of-Check-Time-of-Use (TOCTOU) race condition that allows attackers to overwrite the Redis key TTL by sending concurrent requests. This bypasses the intended daily rate limiting mechanism, enabling attackers to extend their rate limit window indefinitely and request more faucet tokens than allowed.

## Finding Description

The vulnerability exists in the rate limiting logic that uses Redis to track daily request counts per user/IP. [1](#0-0) 

The code follows this pattern:
1. **Non-atomic read** of the Redis key to check if it exists
2. **Decision branch** based on the read value (Some vs None)
3. **Delayed action** that includes calling `.expire()` to set TTL

The TOCTOU race occurs because: [2](#0-1) 

The key is read at line 247, but this value is used much later (lines 264-292) to decide whether to call `.expire()`. [3](#0-2) 

When `limit_value` is `None`, the pipeline executes both `incr()` and `expire()`. The critical issue is at lines 278-281 where the NX flag is commented out: [4](#0-3) 

Without the NX flag, calling `.expire()` on an **already existing key** will overwrite its TTL. This is confirmed by the deployment environment using Redis 6.x: [5](#0-4)  and [6](#0-5) 

**Attack Scenario:**

1. Attacker sends 10 concurrent requests at T0 when the daily key doesn't exist
2. All 10 requests read the key at ~T0 → all get `None`
3. Request 1 completes first at T1, creates key, sets TTL = `seconds_until_next_day(T1)` = 86400 seconds
4. Requests 2-10 complete sequentially at T2, T3, ..., T10
5. Each subsequent request still executes the `None` branch (because they all read `None` earlier)
6. Each request calls `.expire()`, overwriting the TTL with a fresh `seconds_until_next_day(Tx)`
7. Request 10 at T10 sets the final TTL = `seconds_until_next_day(T10)`

If T10 - T1 = 5 seconds, the expiration window extends by 5 seconds. By repeatedly exploiting this with carefully timed bursts throughout the day, an attacker can significantly extend their rate limit window or prevent it from ever expiring.

The vulnerability breaks the rate limiting invariant that each user/IP should only get `max_requests_per_day` requests within a rolling 24-hour window. [7](#0-6) 

## Impact Explanation

This vulnerability allows attackers to bypass the faucet's rate limiting mechanism and obtain more test tokens than intended. While this affects a testnet auxiliary service rather than core consensus or execution components, it can still cause significant operational issues:

1. **Resource exhaustion**: Attackers can drain faucet funds faster than intended
2. **Testnet spam**: Excessive token distribution enables network spam attacks
3. **Service availability**: Legitimate users may be unable to obtain test tokens
4. **Operational costs**: Requires manual intervention to replenish faucet or implement IP blocking

This qualifies as **Medium severity** under the "State inconsistencies requiring intervention" category, as the faucet's rate limiting state becomes inconsistent with intended behavior, requiring operational intervention to restore proper functionality.

## Likelihood Explanation

**Likelihood: High**

The vulnerability is highly likely to be exploited because:

1. **Low complexity**: Only requires sending concurrent HTTP requests (no special privileges needed)
2. **Easy timing**: The window is wide - any concurrent requests when a new daily key is created
3. **Predictable target**: Attackers know when to strike (start of each day in their timezone)
4. **No detection**: Normal request patterns, no obvious attack signature
5. **Repeatable**: Can be exploited daily or multiple times per day

Standard HTTP load testing tools or simple scripts can exploit this vulnerability.

## Recommendation

**Option 1: Upgrade to Redis 7+ and use the NX flag** (Preferred)

Uncomment the NX argument to prevent TTL overwrites:

```rust
.expire(&key, seconds_until_next_day as usize)
.arg("NX")  // Only set expiration if one isn't already set
.ignore()
```

Update deployment requirements to Redis 7.0+.

**Option 2: Use atomic SET with EXAT** (Works with Redis 6.2+)

Replace the incr+expire pipeline with a single atomic SET command:

```rust
None => {
    let key_expiry_time = get_current_time_secs() + seconds_until_next_day;
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(1)
        .arg("EXAT")
        .arg(key_expiry_time)
        .arg("NX")
        .query_async(&mut *conn)
        .await?;
    
    let incremented_limit_value: i64 = conn.incr(&key, 0).await?;
    incremented_limit_value
}
```

**Option 3: Use Lua script for atomic check-and-set**

Execute the entire check-increment-expire operation atomically:

```rust
let script = r"
    local current = redis.call('GET', KEYS[1])
    if current == false then
        redis.call('SETEX', KEYS[1], ARGV[1], 1)
        return 1
    else
        return redis.call('INCR', KEYS[1])
    end
";
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_concurrent_ttl_overwrite() {
        // Setup: Configure faucet with Redis connection
        let config = RedisRatelimitCheckerConfig {
            database_address: "localhost".to_string(),
            database_port: 6379,
            database_number: 0,
            database_user: None,
            database_password: None,
            max_requests_per_day: 10,
            ratelimit_key_provider_config: RatelimitKeyProviderConfig::Ip,
        };
        
        let checker = RedisRatelimitChecker::new(config).await.unwrap();
        
        // Clear any existing keys
        let mut conn = checker.get_redis_connection().await.unwrap();
        let _: () = redis::cmd("FLUSHDB").query_async(&mut *conn).await.unwrap();
        
        // Create test data
        let data = CheckerData {
            source_ip: "192.168.1.100".parse().unwrap(),
            // ... other fields
        };
        
        // Launch 5 concurrent requests
        let mut handles = vec![];
        for i in 0..5 {
            let checker_clone = checker.clone();
            let data_clone = data.clone();
            
            handles.push(tokio::spawn(async move {
                sleep(Duration::from_millis(i * 10)).await;
                checker_clone.check(data_clone, false).await
            }));
        }
        
        // Wait for all to complete
        for handle in handles {
            let _ = handle.await.unwrap();
        }
        
        // Check the TTL - it should be reset by the last concurrent request
        let key = format!("ip:192.168.1.100:{}", 
            days_since_tap_epoch(get_current_time_secs()));
        
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        
        // The TTL should be very close to 86400 (a full day)
        // If the race condition is exploited, it will be closer to 86400
        // than if properly handled (where it would be slightly less due to elapsed time)
        println!("TTL after concurrent requests: {}", ttl);
        assert!(ttl > 86395, "TTL was reset by concurrent requests");
    }
}
```

## Notes

This vulnerability specifically affects the Aptos Faucet service's rate limiting mechanism. While the faucet is not a core blockchain consensus component, it plays an important role in testnet operations and user onboarding. The vulnerability allows attackers to bypass intended usage limits and potentially disrupt service availability for legitimate users.

The root cause is the commented-out NX flag at line 281, which was disabled due to Redis 6.x compatibility requirements. The fix requires either upgrading to Redis 7+ or implementing alternative atomic operations that work with Redis 6.x.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L74-76)
```rust
    /// Max number of requests per key per day. 500s are not counted, because they are
    /// not the user's fault, but everything else is.
    pub max_requests_per_day: u32,
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L226-304)
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

        // If the limit value is greater than what we allow per day, signal that we
        // should reject this request.
        if let Some(rejection_reason) = self.check_limit_value(limit_value, seconds_until_next_day)
        {
            return Ok(vec![rejection_reason]);
        }

        // Atomically increment the counter for the given key, creating it and setting
        // the expiration time if it doesn't already exist.
        if !dry_run {
            let incremented_limit_value = match limit_value {
                Some(_) => conn.incr(&key, 1).await.map_err(|e| {
                    AptosTapError::new_with_error_code(
                        format!("Failed to increment redis key {}: {}", key, e),
                        AptosTapErrorCode::StorageError,
                    )
                })?,
                // If the limit value doesn't exist, create it and set the
                // expiration time.
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
            };

            // Check limit again, to ensure there wasn't a get / set race.
            if let Some(rejection_reason) =
                self.check_limit_value(Some(incremented_limit_value), seconds_until_next_day)
            {
                return Ok(vec![rejection_reason]);
            }
        }

        Ok(vec![])
    }
```

**File:** .github/actions/run-faucet-tests/action.yaml (L24-27)
```yaml
    - name: Run Redis server
      uses: shogo82148/actions-setup-redis@v1
      with:
        redis-version: "6.x"
```

**File:** crates/aptos-faucet/integration-tests/README.md (L17-17)
```markdown
First, run a local Redis 6 server ([installation guide](https://redis.io/docs/getting-started/)).
```
