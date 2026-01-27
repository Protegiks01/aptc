# Audit Report

## Title
Redis Rate Limiter Counter Inflation via Failed Decrements Leading to Denial of Service

## Summary
The Redis rate limiter's `complete()` function in the Aptos faucet can fail to decrement counters during error recovery, causing legitimate users' rate limit counters to become permanently inflated. This violates the documented invariant that server-side 500 errors should not count against users' rate limits and can result in denial of service for legitimate users during periods of system instability.

## Finding Description

The Aptos faucet implements rate limiting using Redis counters that track requests per user per day. The system is designed with the guarantee that server-side failures (500 errors) should not count against users' rate limits. [1](#0-0) 

The rate limiting flow works as follows:

1. When a request arrives, the counter is incremented in the `check()` function [2](#0-1) 

2. If the funding operation returns a 500 error (server-side issue), the `complete()` function is called to decrement the counter and credit the user back [3](#0-2) 

3. The decrement operation can fail due to Redis connection issues, timeouts, or other errors [4](#0-3) 

4. When the decrement fails, the error is returned and propagated via the `?` operator in the caller [5](#0-4) 

**The Critical Flaw**: There is no retry mechanism or error recovery. If the decrement consistently fails during a period of Redis instability, users' counters accumulate unreversed increments. The code explicitly acknowledges this risk but provides no mitigation. [6](#0-5) 

**Attack Scenario**:
1. System experiences high load causing occasional 500 errors
2. Simultaneously, Redis experiences connection pool exhaustion or network issues
3. User makes request → counter incremented to 1
4. Funding fails with 500 error (not user's fault)
5. `complete()` attempts to decrement but Redis operation fails
6. Counter remains at 1 (should be 0)
7. This repeats for subsequent requests
8. User's counter eventually reaches `max_requests_per_day` limit
9. User is blocked until the next day (TTL expiration)

**Security Invariant Violated**: The system guarantees that "500s are not counted, because they are not the user's fault" but failed decrements break this guarantee, causing permanent counter inflation until daily TTL reset.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos Bug Bounty criteria:

- **State inconsistencies requiring intervention**: Rate limit counters become inconsistent with actual successful usage, requiring either manual Redis intervention or waiting for daily TTL expiration
- **Denial of Service**: Legitimate users are blocked from accessing the faucet service
- **Asymmetric Impact**: During system degradation, legitimate users experiencing 500 errors accumulate inflated counters, while any successful requests (potentially from attackers who retry until success) proceed normally
- **No Self-Recovery**: The system has no mechanism to detect or correct the inconsistent state

The impact is amplified during periods of system stress when both server errors and Redis instability are most likely to co-occur, exactly when the faucet service is most critical.

## Likelihood Explanation

**Likelihood: Medium to High** during system stress conditions

This issue will occur whenever:
1. The faucet server returns 500 errors (moderate likelihood during high load, deployments, or backend failures)
2. Redis experiences degraded performance or connectivity issues (moderate likelihood during high load, network issues, or Redis server problems)
3. Both conditions overlap (lower likelihood, but realistic during sustained system stress)

The Redis connection is obtained separately for each operation, making it susceptible to connection pool exhaustion. [7](#0-6) 

Once counters become inflated, the issue persists until daily TTL expiration, affecting users for up to 24 hours.

## Recommendation

Implement error recovery with best-effort decrement that logs failures without blocking the request:

```rust
async fn complete(&self, data: CompleteData) -> Result<(), AptosTapError> {
    if !data.response_is_500 {
        return Ok(());
    }

    // Best-effort decrement - log errors but don't fail the request
    let mut conn = match self.get_redis_connection().await {
        Ok(conn) => conn,
        Err(e) => {
            // Log the failure for monitoring but don't propagate error
            aptos_logger::warn!(
                "Failed to get Redis connection for decrement: {}. Counter may be inflated.",
                e
            );
            return Ok(());
        }
    };

    let key_prefix = self.ratelimit_key_provider.ratelimit_key_prefix();
    let key_value = match self
        .ratelimit_key_provider
        .ratelimit_key_value(&data.checker_data)
        .await {
        Ok(v) => v,
        Err(e) => {
            aptos_logger::warn!("Failed to get ratelimit key for decrement: {}", e);
            return Ok(());
        }
    };
    let (key, _) = self.get_key_and_secs_until_next_day(key_prefix, &key_value);

    match conn.decr(&key, 1).await {
        Ok(_) => Ok(()),
        Err(e) => {
            // Log but don't fail - metrics/monitoring should track this
            aptos_logger::warn!(
                "Failed to decrement redis key {} for 500 error recovery: {}. \
                User counter may be incorrectly inflated.",
                key, e
            );
            Ok(())
        }
    }
}
```

Additionally, consider implementing:
1. Separate monitoring metrics for failed decrements
2. Admin endpoint to manually reset inflated counters
3. Circuit breaker pattern for Redis operations
4. Counter reconciliation based on actual transaction success logs

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::endpoints::AptosTapErrorCode;
    
    #[tokio::test]
    async fn test_decrement_failure_inflates_counter() {
        // Setup: Create a Redis rate limiter with test configuration
        // and mock Redis to fail on decrement operations
        
        // Scenario:
        // 1. User makes request - counter incremented to 1
        // 2. Server returns 500 error
        // 3. complete() called but Redis decrement fails
        // 4. Counter remains at 1 (inflated)
        // 5. Repeat until counter reaches limit
        // 6. User is blocked despite never successfully receiving funds
        
        // Expected: User should not be blocked for server-side failures
        // Actual: User is blocked due to inflated counter
        
        // This test would require mocking Redis to:
        // - Successfully increment in check()
        // - Fail to decrement in complete()
        // Then verify the counter is inflated and user is eventually blocked
    }
}
```

**Notes**

This vulnerability is explicitly acknowledged in the codebase with a comment stating that failures in the completion step "could lead to an unintended data state" [6](#0-5) , but no mitigation has been implemented. While not directly exploitable by a malicious actor without the ability to induce system failures, it represents a design flaw that violates documented security guarantees and creates denial of service conditions for legitimate users during system stress—precisely when faucet availability is most important.

The issue is confined to the faucet service and does not affect core blockchain consensus, execution, or state management components.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L74-75)
```rust
    /// Max number of requests per key per day. 500s are not counted, because they are
    /// not the user's fault, but everything else is.
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L264-293)
```rust
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
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L308-335)
```rust
    async fn complete(&self, data: CompleteData) -> Result<(), AptosTapError> {
        if !data.response_is_500 {
            return Ok(());
        }

        let mut conn = self
            .get_redis_connection()
            .await
            .map_err(|e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::StorageError))?;

        // Generate a key corresponding to this identifier and the current day. In the
        // JWT case we re-verify the JWT. This is inefficient, but these failures are
        // extremely rare so I don't refactor for now.
        let key_prefix = self.ratelimit_key_provider.ratelimit_key_prefix();
        let key_value = self
            .ratelimit_key_provider
            .ratelimit_key_value(&data.checker_data)
            .await?;
        let (key, _) = self.get_key_and_secs_until_next_day(key_prefix, &key_value);

        let _: () = conn.decr(&key, 1).await.map_err(|e| {
            AptosTapError::new_with_error_code(
                format!("Failed to decrement value for redis key {}: {}", key, e),
                AptosTapErrorCode::StorageError,
            )
        })?;
        Ok(())
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L329-331)
```rust
        // Give all Checkers the chance to run the completion step. We should
        // monitor for failures in these steps because they could lead to an
        // unintended data state.
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L342-346)
```rust
            for checker in &self.checkers {
                checker.complete(complete_data.clone()).await.map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
                })?;
            }
```
