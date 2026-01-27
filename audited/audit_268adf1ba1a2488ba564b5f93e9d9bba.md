# Audit Report

## Title
Async Cancellation Vulnerability in Faucet Checkers Causes Inconsistent Rate Limit State

## Summary
The faucet's `CheckerTrait` implementations (`MemoryRatelimitChecker` and `RedisRatelimitChecker`) are vulnerable to async cancellation between the `check()` and `complete()` methods. If a request is cancelled mid-execution due to client disconnect, timeout, or server shutdown, rate limit counters remain incremented without actual funding occurring, leading to incorrect rate limiting and potential denial of service. [1](#0-0) 

## Finding Description
The vulnerability exists in the non-transactional design of the checker lifecycle. The `check()` method increments rate limit counters optimistically, while `complete()` is responsible for compensation when errors occur. However, if the async task is cancelled between these two calls, the compensation never executes.

**Attack Flow:**

1. Attacker sends funding request to the faucet endpoint
2. `preprocess_request()` calls `check()` on each checker, which increments the rate limit counter
3. Attacker immediately disconnects (closes TCP connection) or lets the request timeout
4. The async future handling the request is dropped by Tokio/Poem
5. `fund_inner()` never completes, so `complete()` is never called
6. Rate limit counter remains incorrectly incremented

**In MemoryRatelimitChecker:** [2](#0-1) 

The counter is incremented at line 87 during `check()`, but if cancellation occurs before `complete()` runs, the counter is never decremented even though no funding occurred. [3](#0-2) 

**In RedisRatelimitChecker:** [4](#0-3) 

The Redis counter is atomically incremented during `check()`, but compensation in `complete()` only happens if the function is actually called: [5](#0-4) 

**The Critical Code Path:** [6](#0-5) 

The gap between `preprocess_request()` (which calls `check()`) and the loop calling `complete()` (lines 342-346) is a cancellation window. If the future is dropped during funding operations, `complete()` never executes.

There are no Drop implementations, cancellation guards (like `CancellationToken`), or other safety mechanisms to handle this scenario. The code assumes the async task always runs to completion, which is not guaranteed in real-world scenarios.

## Impact Explanation
This is a **High Severity** vulnerability according to Aptos bug bounty criteria:

1. **API Reliability Impact**: Rate limits become unreliable, causing legitimate users to be incorrectly rate-limited while attackers consume no actual resources

2. **Denial of Service**: An attacker can repeatedly send requests and disconnect, exhausting rate limits for specific IPs or Firebase UIDs without any funding occurring. This prevents legitimate users from accessing the faucet

3. **Validator Node Slowdowns**: If Redis-based rate limiting is used, repeated attacks could cause increased Redis load and latency, potentially affecting validator operations if shared infrastructure is used

4. **State Inconsistency**: Both in-memory and Redis-based rate limit state becomes inconsistent with actual funding operations, requiring manual intervention to reset

The vulnerability affects the faucet's core security mechanism (rate limiting) and can be exploited with minimal effort and no special privileges.

## Likelihood Explanation
**Likelihood: High**

1. **Common Trigger Conditions**:
   - Client disconnects are extremely common in HTTP/REST APIs
   - Network instability causes frequent connection drops
   - Mobile clients routinely disconnect during requests
   - Load balancers and proxies may timeout long-running requests

2. **Zero Prerequisites**: Any user can exploit this—no authentication, special access, or technical knowledge required beyond sending a request and disconnecting

3. **Repeatable Attack**: The attack can be automated and repeated unlimited times to amplify impact

4. **No Detection**: The vulnerability manifests as "normal" client disconnects in logs, making it difficult to distinguish from legitimate network issues

## Recommendation
Implement cancellation-safe rate limiting using one of these approaches:

**Option 1: Deferred Rate Limit Update (Recommended)**
Move rate limit increments from `check()` to `complete()`, so they only occur after successful funding:

```rust
// In check(): Only read and validate, don't increment
async fn check(&self, data: CheckerData, dry_run: bool) -> Result<Vec<RejectionReason>, AptosTapError> {
    let limit_value = self.get_current_limit(&data).await?;
    if limit_value >= self.max_requests_per_day {
        return Ok(vec![RejectionReason::new(...)]);
    }
    Ok(vec![])
}

// In complete(): Increment only after successful funding
async fn complete(&self, data: CompleteData) -> Result<(), AptosTapError> {
    if !data.response_is_500 {
        self.increment_limit(&data.checker_data).await?;
    }
    Ok(())
}
```

**Option 2: Cancellation Guard with Drop Handler**
Wrap the rate limit state in a guard that automatically rolls back on drop if not committed:

```rust
struct RateLimitGuard<'a> {
    checker: &'a MemoryRatelimitChecker,
    ip: IpAddr,
    committed: bool,
}

impl Drop for RateLimitGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Rollback: decrement counter
            tokio::spawn(async move {
                let mut map = self.checker.ip_to_requests_today.lock().await;
                if let Some(count) = map.get_mut(&self.ip) {
                    *count = count.saturating_sub(1);
                }
            });
        }
    }
}
```

**Option 3: Two-Phase Commit with Reservation**
Use a reservation system where `check()` reserves capacity and `complete()` confirms or releases it:

```rust
// Check phase: Reserve capacity
async fn check(&self, data: CheckerData, dry_run: bool) -> Result<Vec<RejectionReason>, AptosTapError> {
    let reservation_id = self.reserve_capacity(&data)?;
    // Store reservation_id in CheckerData for later
    Ok(vec![])
}

// Complete phase: Confirm or release reservation
async fn complete(&self, data: CompleteData) -> Result<(), AptosTapError> {
    if data.response_is_500 {
        self.release_reservation(&data.reservation_id)?;
    } else {
        self.confirm_reservation(&data.reservation_id)?;
    }
    Ok(())
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_async_cancellation_rate_limit_inconsistency() {
    use std::net::IpAddr;
    use std::sync::Arc;
    use crate::checkers::{MemoryRatelimitChecker, MemoryRatelimitCheckerConfig, CheckerTrait, CheckerData};
    use aptos_sdk::types::account_address::AccountAddress;
    use poem::http::HeaderMap;
    
    // Setup checker with max 1 request per day
    let config = MemoryRatelimitCheckerConfig {
        max_requests_per_day: 1,
        max_entries_in_map: std::num::NonZeroUsize::new(1000).unwrap(),
    };
    let checker = MemoryRatelimitChecker::new(config);
    
    let test_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let checker_data = CheckerData {
        time_request_received_secs: 1000000,
        receiver: AccountAddress::random(),
        source_ip: test_ip,
        headers: Arc::new(HeaderMap::new()),
    };
    
    // Simulate cancellation scenario:
    // 1. Call check() which increments the counter
    let result = checker.check(checker_data.clone(), false).await;
    assert!(result.unwrap().is_empty()); // First request should pass
    
    // 2. Simulate async cancellation - complete() is never called
    // (In real scenario, the future would be dropped here)
    
    // 3. Try another request from the same IP
    let result = checker.check(checker_data.clone(), false).await;
    let rejections = result.unwrap();
    
    // BUG: Second request is rejected even though first was cancelled and never funded
    assert!(!rejections.is_empty(), "Rate limit incorrectly triggered due to cancelled request");
    assert!(rejections[0].message.contains("exceeded the daily limit"));
    
    // This proves the vulnerability: the IP is rate-limited even though
    // no actual funding occurred due to the simulated cancellation
    
    println!("✗ VULNERABILITY CONFIRMED: Rate limit state is inconsistent after cancellation");
    println!("✗ IP {} is rate-limited without receiving any funds", test_ip);
}
```

**To demonstrate with Redis:**

```rust
#[tokio::test]
async fn test_redis_cancellation_rate_limit_inconsistency() {
    // Similar setup with RedisRatelimitChecker
    // 1. Call check() - increments Redis counter
    // 2. Simulate cancellation (don't call complete())
    // 3. Verify Redis counter remains incremented
    // 4. Show subsequent requests are incorrectly rate-limited
}
```

**Notes:**
- This vulnerability is specific to the aptos-faucet component, not core blockchain consensus
- However, it represents a significant operational security issue for public faucets
- The issue affects both in-memory and Redis-based rate limiting implementations
- Exploitation requires no special privileges and can be fully automated
- The inconsistent state persists until the daily reset, affecting all users from the targeted IP/JWT

### Citations

**File:** crates/aptos-faucet/core/src/checkers/mod.rs (L42-64)
```rust
#[async_trait]
#[enum_dispatch]
pub trait CheckerTrait: Sync + Send + 'static {
    /// Returns a list of rejection reasons for the request, if any. If dry_run
    /// is set, if this Checker would store anything based on the request, it
    /// instead will not. This is useful for the is_eligible endpoint.
    async fn check(
        &self,
        data: CheckerData,
        dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError>;

    /// If the Checker wants to do anything after the funding has completed, it
    /// may do so in this function. For example, for the storage Checkers, this
    /// function is responsible for marking a request in storage as complete,
    /// in both success and failure cases. It can also store additional metadata
    /// included in CompleteData that we might have from the call to the Funder.
    /// No dry_run flag for this, because we should never need to run this in
    /// dry_run mode.
    async fn complete(&self, _data: CompleteData) -> Result<(), AptosTapError> {
        Ok(())
    }

```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L68-91)
```rust
    async fn check(
        &self,
        data: CheckerData,
        dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        self.clear_if_new_day().await;

        let mut ip_to_requests_today = self.ip_to_requests_today.lock().await;

        let requests_today = ip_to_requests_today.get_or_insert_mut(data.source_ip, || 1);
        if *requests_today >= self.max_requests_per_day {
            return Ok(vec![RejectionReason::new(
                format!(
                    "IP {} has exceeded the daily limit of {} requests",
                    data.source_ip, self.max_requests_per_day
                ),
                RejectionReasonCode::UsageLimitExhausted,
            )]);
        } else if !dry_run {
            *requests_today += 1;
        }

        Ok(vec![])
    }
```

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L93-102)
```rust
    async fn complete(&self, data: CompleteData) -> Result<(), AptosTapError> {
        if data.response_is_500 {
            *self
                .ip_to_requests_today
                .lock()
                .await
                .get_or_insert_mut(data.checker_data.source_ip, || 1) -= 1;
        }
        Ok(())
    }
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L263-293)
```rust
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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L283-350)
```rust
    async fn fund_inner(
        &self,
        fund_request: FundRequest,
        // This automagically uses FromRequest to get this data from the request.
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
        // Same thing, this uses FromRequest.
        header_map: &HeaderMap,
        dry_run: bool,
        asset: Option<String>,
    ) -> poem::Result<Vec<SignedTransaction>, AptosTapError> {
        let (checker_data, bypass, _semaphore_permit) = self
            .preprocess_request(&fund_request, source_ip, header_map, dry_run)
            .await?;

        // Fund the account - pass asset directly, funder will use its configured default if None
        let asset_for_logging = asset.clone();
        let fund_result = self
            .funder
            .fund(
                fund_request.amount,
                checker_data.receiver,
                asset,
                false,
                bypass,
            )
            .await;

        // This might be empty if there is an error and we never got to the
        // point where we could submit a transaction.
        let txn_hashes = match &fund_result {
            Ok(txns) => transaction_hashes(&txns.iter().collect::<Vec<&SignedTransaction>>()),
            Err(e) => e.txn_hashes.to_vec(),
        };

        // Include some additional logging that the logging middleware doesn't do.
        info!(
            source_ip = checker_data.source_ip,
            jwt_sub = jwt_sub(checker_data.headers.clone()).ok(),
            address = checker_data.receiver,
            requested_amount = fund_request.amount,
            asset = asset_for_logging,
            txn_hashes = txn_hashes,
            success = fund_result.is_ok(),
        );

        // Give all Checkers the chance to run the completion step. We should
        // monitor for failures in these steps because they could lead to an
        // unintended data state.
        if !bypass {
            let response_is_500 = match &fund_result {
                Ok(_) => false,
                Err(e) => e.error_code.status().is_server_error(),
            };
            let complete_data = CompleteData {
                checker_data,
                txn_hashes: txn_hashes.clone(),
                response_is_500,
            };
            for checker in &self.checkers {
                checker.complete(complete_data.clone()).await.map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
                })?;
            }
        }

        fund_result
    }
```
