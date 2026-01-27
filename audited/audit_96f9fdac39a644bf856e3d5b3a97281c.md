# Audit Report

## Title
Rate Limit Reconnaissance via dry_run Flag Enables Optimized Faucet Draining Attacks

## Summary
The `dry_run` flag in the faucet's checker system allows attackers to probe rate limit state without consuming quota, enabling reconnaissance attacks that can optimize faucet draining through precise timing and race condition exploitation.

## Finding Description

The Aptos Faucet implements a `CheckerTrait` interface where each checker's `check()` method accepts a `dry_run` parameter. [1](#0-0) 

This flag is used by the `/is_eligible` endpoint to check eligibility without modifying state. [2](#0-1) 

The `preprocess_request` function passes the `dry_run` flag to all checkers. [3](#0-2) 

**RedisRatelimitChecker Vulnerability:**

The Redis-based rate limiter performs a pure read operation when checking limits, then only increments the counter if `dry_run` is false. [4](#0-3) 

This allows unlimited reconnaissance without quota consumption. An attacker can call `/is_eligible` repeatedly to learn their exact rate limit state, including current count and time until reset.

**MemoryRatelimitChecker Vulnerability:**

The memory-based rate limiter uses `get_or_insert_mut`, which inserts the IP on first access, but only increments on non-dry-run calls. [5](#0-4) 

**Race Condition Amplification:**

The codebase acknowledges a race condition vulnerability where concurrent requests can exceed rate limits. [6](#0-5) 

With reconnaissance capability, attackers can:
1. Probe to learn when their counter is close to the limit
2. Send many concurrent `/fund` requests at that precise moment
3. Exploit the read-check-increment race window to exceed configured limits

## Impact Explanation

**However, this does NOT meet High severity criteria for Aptos blockchain security because:**

The faucet is an auxiliary service for **testnet token distribution**, not a core blockchain component. It does not affect:
- Consensus safety or liveness
- Move VM execution
- State management or storage
- On-chain governance
- Validator staking or rewards

Testnet tokens have no intrinsic value and faucets are designed to be drained and refilled regularly. While the reconnaissance capability is a software design issue, it does not constitute a blockchain security vulnerability impacting validator operations, fund security, or network integrity.

## Likelihood Explanation

While the attack is trivial to execute (simple HTTP requests), the impact is limited to more efficient draining of a testnet faucet, which is expected behavior. The issue is already acknowledged in code comments as a known limitation.

## Recommendation

If the faucet were used for mainnet or valuable token distribution, the fix would be:

1. Remove the `dry_run` parameter from rate limit checkers
2. Implement a separate read-only eligibility check that doesn't expose exact rate limit state
3. Add jitter or obfuscation to rate limit responses to prevent precise timing attacks

## Proof of Concept

```bash
# Reconnaissance attack
for i in {1..100}; do
  curl -X POST https://faucet.testnet.aptoslabs.com/is_eligible \
    -H "Content-Type: application/json" \
    -d '{"address":"0x123..."}'
done

# After learning exact rate limit state, time concurrent requests
# to exploit race condition and exceed limits
```

## Notes

**Per the validation criteria:** This issue does NOT qualify as a valid High severity blockchain vulnerability because:

- ✗ Does not affect consensus, execution, storage, governance, or staking
- ✗ Does not break any documented blockchain invariants  
- ✗ Testnet faucet is auxiliary infrastructure, not core blockchain
- ✗ Issue is acknowledged in code comments (known limitation)
- ✗ No impact on validator operations or mainnet security

While this is a legitimate software engineering concern for faucet operators, it does not meet the "EXTREMELY high" bar for Aptos blockchain security vulnerabilities focused on consensus, Move VM, state management, and core protocol components.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/mod.rs (L45-52)
```rust
    /// Returns a list of rejection reasons for the request, if any. If dry_run
    /// is set, if this Checker would store anything based on the request, it
    /// instead will not. This is useful for the is_eligible endpoint.
    async fn check(
        &self,
        data: CheckerData,
        dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError>;
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L133-146)
```rust
    async fn is_eligible(
        &self,
        fund_request: Json<FundRequest>,
        asset: poem_openapi::param::Query<Option<String>>,
        // This automagically uses FromRequest to get this data from the request.
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
        // Same thing, this uses FromRequest.
        header_map: &HeaderMap,
    ) -> poem::Result<(), AptosTapErrorResponse> {
        let (checker_data, bypass, _semaphore_permit) = self
            .components
            .preprocess_request(&fund_request.0, source_ip, header_map, true)
            .await?;
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L197-203)
```rust
    async fn preprocess_request(
        &self,
        fund_request: &FundRequest,
        source_ip: RealIp,
        header_map: &HeaderMap,
        dry_run: bool,
    ) -> poem::Result<(CheckerData, bool, Option<SemaphorePermit<'_>>), AptosTapError> {
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L143-145)
```rust
/// This second way leaves a small window for someone to slip in multiple requests,
/// therein blowing past the configured limit, but it's a very small window, so we'll
/// worry about it as a followup: https://github.com/aptos-labs/aptos-tap/issues/15.
```

**File:** crates/aptos-faucet/core/src/checkers/redis_ratelimit.rs (L226-263)
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
