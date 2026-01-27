# Audit Report

## Title
Redis Rate Limiter Silent EXPIRE Failure Leading to Permanent User Rate Limiting and Memory Exhaustion

## Summary
The Redis rate limiting implementation in the faucet service uses `.ignore()` on the EXPIRE command within an atomic pipeline, preventing detection of EXPIRE failures. If INCR succeeds but EXPIRE fails, rate limit keys persist without TTL, causing permanent user rate limiting and Redis memory exhaustion.

## Finding Description
In the rate limiting logic, when a new rate limit key is created, the code uses a Redis atomic pipeline to both increment the counter and set an expiration time. [1](#0-0) 

The pipeline executes `INCR` followed by `EXPIRE`, but critically calls `.ignore()` after the EXPIRE command. This tells the Redis client to exclude the EXPIRE result from the returned tuple, which only contains the INCR value.

**The vulnerability**: If the Redis EXPIRE command fails (either by returning 0 indicating the key doesn't exist, or by returning an error due to internal Redis issues, memory pressure, or configuration problems), the `.ignore()` call prevents the code from detecting this failure. The code only verifies that `.query_async()` didn't return a connection-level error, then proceeds using the incremented value.

**Attack scenario**:
1. User makes a faucet request, triggering rate limit check
2. The rate limit key doesn't exist yet (first request of the day)
3. Pipeline executes: INCR succeeds (creates key, returns 1)
4. EXPIRE fails due to Redis resource constraints, internal error, or edge case
5. `.ignore()` suppresses the EXPIRE failure
6. Code proceeds as if operation succeeded
7. Rate limit key now exists in Redis **without any TTL**
8. User makes subsequent requests, hitting their daily limit
9. Key never expires → user is **permanently rate-limited**
10. Over time, non-expiring keys accumulate → Redis memory exhaustion

The code performs no subsequent verification that the TTL was actually set. [2](#0-1) 

## Impact Explanation
This vulnerability meets **Medium severity** criteria per the Aptos bug bounty program: "State inconsistencies requiring intervention."

**Specific impacts**:
- **Permanent User Rate Limiting**: Users who trigger this condition become permanently unable to access the faucet service, requiring manual Redis intervention to unblock them
- **Redis Memory Exhaustion**: Rate limit keys accumulate without expiration, eventually filling Redis memory and causing faucet service failure
- **Denial of Service**: The faucet service becomes unavailable when Redis runs out of memory, preventing all users from obtaining testnet/devnet tokens
- **Manual Intervention Required**: Operations teams must manually identify and delete non-expiring keys or restart Redis, disrupting service

While this doesn't affect consensus or mainnet funds (faucet distributes testnet tokens), it causes significant service degradation and availability issues.

## Likelihood Explanation
**Likelihood: Medium to Low**, but impact justifies concern:

**Factors increasing likelihood**:
- The `.ignore()` call explicitly prevents error detection
- No TTL verification exists anywhere in the code
- Redis MULTI/EXEC doesn't rollback on individual command failures
- Memory pressure, configuration issues, or internal Redis errors could cause EXPIRE to fail

**Factors decreasing likelihood**:
- In normal Redis operation with MULTI/EXEC atomicity, EXPIRE should succeed if INCR creates the key
- Redis is generally reliable, and EXPIRE failures are uncommon
- Requires specific Redis error conditions to manifest

**However**, even if rare, the consequences are severe: permanent user lockout and service failure requiring manual intervention. The bug exists and is exploitable under realistic (if uncommon) failure scenarios.

## Recommendation
**Fix: Verify EXPIRE succeeded by capturing and checking its result**

Remove `.ignore()` and verify the EXPIRE result:

```rust
None => {
    let (incremented_limit_value, expire_result): (i64, i64) = redis::pipe()
        .atomic()
        .incr(&key, 1)
        .expire(&key, seconds_until_next_day as usize)
        // Remove .ignore() to capture expire result
        .query_async(&mut *conn)
        .await
        .map_err(|e| {
            AptosTapError::new_with_error_code(
                format!("Failed to increment value for redis key {}: {}", key, e),
                AptosTapErrorCode::StorageError,
            )
        })?;
    
    // Verify EXPIRE succeeded (returns 1 if key exists, 0 if not)
    if expire_result != 1 {
        return Err(AptosTapError::new_with_error_code(
            format!("Failed to set expiration for redis key {}: EXPIRE returned {}", key, expire_result),
            AptosTapErrorCode::StorageError,
        ));
    }
    
    incremented_limit_value
}
```

**Alternative fix using SET with EX**: Use a single `SET` command with `EX` option instead of separate INCR/EXPIRE:

```rust
None => {
    // Use SET with EX to atomically create key with expiration
    let _: () = conn.set_ex(&key, 1, seconds_until_next_day as usize).await.map_err(|e| {
        AptosTapError::new_with_error_code(
            format!("Failed to create redis key with expiration: {}", e),
            AptosTapErrorCode::StorageError,
        )
    })?;
    1 // Return initial value
}
```

**Additional safeguard**: Implement a periodic cleanup job that identifies and removes keys older than expected TTL, or use Redis's `maxmemory-policy` with appropriate eviction settings.

## Proof of Concept
Since this requires specific Redis failure conditions, a full PoC would need to mock Redis behavior. Here's a conceptual test:

```rust
#[tokio::test]
async fn test_expire_failure_detection() {
    // Mock Redis connection that succeeds INCR but fails EXPIRE
    let mut mock_conn = MockRedisConnection::new(vec![
        MockCmd::new(
            redis::cmd("MULTI"),
            Ok("OK"),
        ),
        MockCmd::new(
            redis::cmd("INCR").arg("test:key"),
            Ok(1), // INCR succeeds
        ),
        MockCmd::new(
            redis::cmd("EXPIRE").arg("test:key").arg(86400),
            Ok(0), // EXPIRE fails (key doesn't exist, or returns error)
        ),
        MockCmd::new(
            redis::cmd("EXEC"),
            Ok(vec![1, 0]), // INCR=1, EXPIRE=0
        ),
    ]);
    
    // With current implementation using .ignore(), this would succeed
    // even though EXPIRE failed
    let result = checker.check(data, false).await;
    
    // Expected: Should detect EXPIRE failure and return error
    // Actual: Succeeds, leaving key without TTL
    assert!(result.is_err(), "Should detect EXPIRE failure");
}
```

To reproduce in production:
1. Configure Redis with very limited memory (`maxmemory` setting)
2. Fill Redis close to capacity
3. Make faucet request to trigger rate limit key creation
4. INCR may succeed (small operation) but EXPIRE may fail (cannot allocate expiration metadata)
5. Observe key exists without TTL using `TTL` command: returns -1 (no expiration)

## Notes
This vulnerability is specific to the faucet service and does not affect core consensus, Move VM, or blockchain state. However, it causes significant operational issues (permanent user lockout, service degradation) that require manual intervention, meeting the Medium severity threshold for "state inconsistencies requiring intervention."

### Citations

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L274-290)
```rust
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
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L295-300)
```rust
            // Check limit again, to ensure there wasn't a get / set race.
            if let Some(rejection_reason) =
                self.check_limit_value(Some(incremented_limit_value), seconds_until_next_day)
            {
                return Ok(vec![rejection_reason]);
            }
```
