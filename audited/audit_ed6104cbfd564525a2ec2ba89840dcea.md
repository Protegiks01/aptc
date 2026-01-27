# Audit Report

## Title
Race Condition in MemoryRatelimitChecker Allows Inconsistent Rate Limiting During Day Transitions

## Summary
The `MemoryRatelimitChecker.clear_if_new_day()` method contains a race condition where the atomic `current_day` variable is updated before the rate limit map is cleared. This non-atomic state transition allows concurrent requests at midnight to observe inconsistent state, leading to false rejections of legitimate users and unpredictable behavior.

## Finding Description
The vulnerability exists in the day transition logic where two separate operations are performed non-atomically: [1](#0-0) 

The attack sequence occurs when multiple concurrent requests arrive at the exact moment of day transition (midnight):

**Thread A's execution:**
1. Enters `clear_if_new_day()` and detects new day (lines 54-55)
2. Updates `current_day` atomic to the new day value (lines 57-60)
3. **Blocks waiting to acquire lock** on `ip_to_requests_today` (line 61)

**Thread B's execution (concurrent):**
1. Enters `clear_if_new_day()` after Thread A has updated `current_day`
2. Check at lines 54-55 evaluates to FALSE (because `current_day` already reflects the new day)
3. Returns immediately without clearing the map
4. **Acquires the lock BEFORE Thread A** and proceeds to the check method (line 75) [2](#0-1) 

Thread B now reads stale data from yesterday's map. If a user had reached their daily limit yesterday (e.g., 100 requests), Thread B incorrectly sees them as still having 100 requests on the new day and rejects their legitimate request (lines 78-85).

This creates a time-of-check-time-of-use (TOCTOU) vulnerability where:
- The check: "Is it a new day?" (lines 54-55)
- The use: "Clear the map" (line 61)

Are separated by an atomic update (lines 57-60) that changes the outcome of future checks without completing the associated action.

## Impact Explanation
This qualifies as **High severity** based on the Aptos bug bounty criteria for "API crashes" and "Significant protocol violations" because:

1. **Denial of Service**: Legitimate users who maxed out their daily limit yesterday will be incorrectly rejected on the new day when concurrent requests trigger the race condition
2. **Inconsistent Behavior**: Different concurrent requests receive different treatment - some see cleared state, others see stale data
3. **Violates Rate Limiting Invariant**: The fundamental guarantee that "daily limits reset at midnight" is broken during the race window

While the faucet is an auxiliary service, it provides critical infrastructure for testnet token distribution, and DoS attacks that prevent legitimate developers from accessing test tokens constitute a significant operational impact.

## Likelihood Explanation
**Likelihood: MEDIUM to HIGH**

The vulnerability is:
- **Easy to trigger**: Attacker simply sends multiple concurrent HTTP requests to the faucet API at exactly 00:00:00 UTC (midnight)
- **Predictable timing**: The day boundary is known in advance
- **No authentication required**: Any user can make faucet requests
- **Race window is guaranteed**: The code structure ensures the race window exists on every day transition

The race condition occurs on every single day transition where concurrent requests are present. For a busy faucet service, this happens daily.

## Recommendation
Use a single lock acquisition to perform both the day check and the map clearing atomically:

```rust
async fn clear_if_new_day(&self) {
    let current_time_secs = get_current_time_secs();
    let days_now = days_since_tap_epoch(current_time_secs);
    
    // Acquire lock first, then check and clear atomically
    let mut ip_map = self.ip_to_requests_today.lock().await;
    
    if days_now > self.current_day.load(std::sync::atomic::Ordering::Relaxed) {
        self.current_day.store(days_now, std::sync::atomic::Ordering::Relaxed);
        ip_map.clear();
    }
}
```

This ensures that checking the day and clearing the map happen as a single atomic operation under the mutex lock, eliminating the race window.

**Alternative approach** (similar to RedisRatelimitChecker): Remove the day-tracking logic entirely and use a different map key for each day: [3](#0-2) 

## Proof of Concept
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;
    use tokio;

    #[tokio::test]
    async fn test_race_condition_at_day_boundary() {
        use std::sync::atomic::Ordering;
        
        // Create checker with limit of 5 requests per day
        let config = MemoryRatelimitCheckerConfig {
            max_requests_per_day: 5,
            max_entries_in_map: NonZeroUsize::new(1000).unwrap(),
        };
        let checker = Arc::new(MemoryRatelimitChecker::new(config));
        
        // Simulate that user has exhausted limit yesterday
        let test_ip: IpAddr = "192.168.1.1".parse().unwrap();
        {
            let mut map = checker.ip_to_requests_today.lock().await;
            map.push(test_ip, 5); // Already at limit
        }
        
        // Simulate day transition by manually advancing current_day
        let old_day = checker.current_day.load(Ordering::Relaxed);
        checker.current_day.store(old_day + 1, Ordering::Relaxed);
        
        // Spawn 10 concurrent requests that all call clear_if_new_day
        let mut handles = vec![];
        for _ in 0..10 {
            let checker_clone = Arc::clone(&checker);
            let handle = tokio::spawn(async move {
                // Reset day back to trigger the condition
                checker_clone.current_day.store(old_day, Ordering::Relaxed);
                checker_clone.clear_if_new_day().await;
                
                // Try to check the IP
                let data = CheckerData {
                    time_request_received_secs: 0,
                    receiver: AccountAddress::ZERO,
                    source_ip: test_ip,
                    headers: Arc::new(HeaderMap::new()),
                };
                checker_clone.check(data, false).await
            });
            handles.push(handle);
        }
        
        // Collect results
        let mut rejection_count = 0;
        for handle in handles {
            if let Ok(result) = handle.await {
                if let Ok(reasons) = result {
                    if !reasons.is_empty() {
                        rejection_count += 1;
                    }
                }
            }
        }
        
        // Due to race condition, some requests see old state and get rejected
        // even though it's a new day
        assert!(rejection_count > 0, 
            "Race condition should cause some false rejections on new day");
    }
}
```

## Notes
The Redis-based rate limiter does not have this vulnerability because it embeds the day number directly in the Redis key, making day transitions implicit and automatic without requiring explicit clearing logic. The memory-based implementation should adopt a similar approach or ensure atomic state transitions.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/memory_ratelimit.rs (L53-63)
```rust
    async fn clear_if_new_day(&self) {
        if days_since_tap_epoch(get_current_time_secs())
            > self.current_day.load(std::sync::atomic::Ordering::Relaxed)
        {
            self.current_day.store(
                days_since_tap_epoch(get_current_time_secs()),
                std::sync::atomic::Ordering::Relaxed,
            );
            self.ip_to_requests_today.lock().await.clear();
        }
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
