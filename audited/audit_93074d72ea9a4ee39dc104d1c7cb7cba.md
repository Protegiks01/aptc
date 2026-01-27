# Audit Report

## Title
JWT Expiration Race Condition Causes Permanent Quota Consumption on Server Errors

## Summary

In the Redis rate limiter for the Aptos faucet, when a JWT is valid during the `check()` phase but expires before the `complete()` phase executes, users permanently lose quota for server-side 500 errors. This violates the documented design principle that 500 errors should not count against user quotas. [1](#0-0) 

## Finding Description

The `RedisRatelimitChecker` implements a two-phase quota management system:

1. **Check Phase**: Validates the JWT and increments the Redis counter [2](#0-1) 

2. **Complete Phase**: If a 500 error occurs, re-validates the JWT and decrements the counter [3](#0-2) 

**The Vulnerability:**

When a request is made with a JWT that is about to expire:
- The JWT passes validation in `check()` and the counter is incremented
- Request processing takes time (network latency, server load, etc.)
- A 500 error occurs (server-side issue, not user's fault)
- By the time `complete()` executes, the JWT has expired
- JWT re-validation fails, throwing `AuthTokenInvalid` error [4](#0-3) 

- The decrement operation never executes [5](#0-4) 

- The error from `complete()` is wrapped as `CheckerError` and propagates, causing the entire request to fail [6](#0-5) 

This breaks the documented invariant that **"500s are not counted, because they are not the user's fault"**.

## Impact Explanation

**Severity: Medium**

This issue constitutes a **state inconsistency requiring intervention** and represents **limited quota manipulation** under the Aptos Bug Bounty Medium category criteria.

**Impact:**
- Users permanently lose daily quota allowance for server errors when using JWTs near expiration
- Legitimate users may be incorrectly rate-limited after server-side failures
- Violates fairness guarantees of the faucet service
- Creates a timing-based quota exhaustion vector

**Why Not Higher Severity:**
- Limited to faucet service, does not affect blockchain consensus or mainnet funds
- Does not cause permanent fund loss (testnet tokens only)
- Does not affect validator nodes or core protocol

## Likelihood Explanation

**Likelihood: Medium-High**

This condition occurs naturally when:
- JWTs approach their expiration time (standard JWT lifetimes are 15-60 minutes)
- Request processing spans the expiration boundary (only needs seconds)
- Server experiences intermittent 500 errors (database issues, network problems, resource exhaustion)

**Triggering Factors:**
- Users in different time zones making requests near JWT expiration
- Server load causing processing delays
- Natural JWT rotation cycles
- Legitimate server-side errors (infrastructure issues, rate limiting from external services)

An attacker could potentially increase likelihood by:
- Timing requests to coincide with JWT expiration
- Making requests during known high-load periods
- Though they cannot directly control server 500 errors

## Recommendation

**Solution: Cache the JWT validation result in `check()` and reuse it in `complete()`**

Instead of re-validating the JWT in `complete()`, store the validated key value in `CompleteData` during the `check()` phase:

```rust
// In CheckerData or CompleteData struct:
pub struct CompleteData {
    pub checker_data: CheckerData,
    pub txn_hashes: Vec<String>,
    pub response_is_500: bool,
    pub ratelimit_key_value: Option<String>, // Add this field
}
```

Modify `check()` to store the key: [7](#0-6) 

Store the validated `key_value` in the request context and pass it to `complete()`.

Modify `complete()` to use cached value:
```rust
async fn complete(&self, data: CompleteData) -> Result<(), AptosTapError> {
    if !data.response_is_500 {
        return Ok(());
    }

    let mut conn = self.get_redis_connection().await?;

    // Use cached key_value instead of re-validating JWT
    let key_value = match data.ratelimit_key_value {
        Some(v) => v,
        None => {
            // Fallback: re-validate if not cached (shouldn't happen)
            self.ratelimit_key_provider
                .ratelimit_key_value(&data.checker_data)
                .await?
        }
    };
    
    let key_prefix = self.ratelimit_key_provider.ratelimit_key_prefix();
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

This ensures the decrement uses the same identity validated during `check()`, preventing JWT expiration from blocking quota reclamation.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_jwt_expiration_quota_consumption() {
        // Setup: Create RedisRatelimitChecker with JWT validation
        // Create a JWT that expires in 2 seconds
        
        // Step 1: Call check() - JWT is valid, counter incremented
        let checker_data = create_test_checker_data_with_expiring_jwt(2);
        let result = checker.check(checker_data.clone(), false).await;
        assert!(result.is_ok());
        
        // Verify counter was incremented to 1
        let current_count = get_redis_counter_value().await;
        assert_eq!(current_count, 1);
        
        // Step 2: Simulate request processing delay beyond JWT expiration
        sleep(Duration::from_secs(3)).await;
        
        // Step 3: Simulate 500 error response
        let complete_data = CompleteData {
            checker_data,
            txn_hashes: vec![],
            response_is_500: true,
        };
        
        // Step 4: Call complete() - JWT expired, decrement fails
        let complete_result = checker.complete(complete_data).await;
        assert!(complete_result.is_err());
        
        // Verify: Counter remains at 1 (not decremented)
        let final_count = get_redis_counter_value().await;
        assert_eq!(final_count, 1); // BUG: Should be 0 for 500 errors
        
        // User has permanently lost quota despite 500 error
    }
}
```

**Notes:**

This vulnerability is limited to the faucet component and does not affect core blockchain security, but represents a correctness issue in quota management that violates documented design principles and can lead to unfair rate limiting of legitimate users.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L74-76)
```rust
    /// Max number of requests per key per day. 500s are not counted, because they are
    /// not the user's fault, but everything else is.
    pub max_requests_per_day: u32,
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L238-243)
```rust
        let key_value = self
            .ratelimit_key_provider
            .ratelimit_key_value(&data)
            .await?;
        let (key, seconds_until_next_day) =
            self.get_key_and_secs_until_next_day(key_prefix, &key_value);
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L308-325)
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
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L328-333)
```rust
        let _: () = conn.decr(&key, 1).await.map_err(|e| {
            AptosTapError::new_with_error_code(
                format!("Failed to decrement value for redis key {}: {}", key, e),
                AptosTapErrorCode::StorageError,
            )
        })?;
```

**File:** crates/aptos-faucet/core/src/firebase_jwt.rs (L44-53)
```rust
        let verify = self.jwt_verifier.verify::<JwtClaims>(&auth_token);
        let token_data = match verify.await {
            Some(token_data) => token_data,
            None => {
                return Err(AptosTapError::new(
                    "Failed to verify JWT token".to_string(),
                    AptosTapErrorCode::AuthTokenInvalid,
                ));
            },
        };
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L342-346)
```rust
            for checker in &self.checkers {
                checker.complete(complete_data.clone()).await.map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
                })?;
            }
```
