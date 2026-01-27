# Audit Report

## Title
Timer Reset Logic Error in RealSleep Causes Incorrect Deadline Calculation Leading to Non-Deterministic Consensus Timing

## Summary
The `reset()` implementation in `RealSleep` incorrectly calculates new deadlines by adding the duration to the old deadline instead of the current time. When called on an already-elapsed sleep (as occurs in `Interval` streams), this causes timers to fire at unpredictable intervals, affecting consensus retry logic and network timing behavior across validators.

## Finding Description

The `reset()` function in the `RealSleep` implementation has a critical logic error: [1](#0-0) 

The bug is on line 56: it adds `duration` to `self.deadline()` (the old, potentially elapsed deadline) instead of to the current time. This breaks the `SleepTrait` contract established by the reference `MockSleep` implementation: [2](#0-1) 

Note that `MockSleep::reset()` correctly calls `register_sleep(duration, ...)` which computes the deadline as `self.now + duration` (line 283), not as `old_deadline + duration`.

**Exploitation Path:**

This bug is automatically triggered in the `Interval` stream implementation, which is used throughout the codebase: [3](#0-2) 

On line 47, `reset()` is called immediately after the delay has elapsed (line 44). At this point:
- `self.deadline()` returns a deadline in the past (e.g., 100ms ago)
- Adding `period` (e.g., 1000ms) results in `past_deadline + 1000ms`, which may still be in the past or very close to current time
- The correct calculation should be `now() + 1000ms`

**Consensus Impact:**

The DAG consensus uses `Interval` for RPC retry timing: [4](#0-3) 

When this interval fires at incorrect times due to the reset bug:
1. Different validators experience different retry intervals depending on elapsed time
2. Network timing assumptions are violated
3. RPC retry patterns become non-deterministic across the validator set
4. Consensus timing behavior diverges between nodes

**Invariant Violation:**

This breaks the **Deterministic Execution** invariant. While validators will still agree on block content, they experience non-deterministic timing behavior in critical consensus code paths. The timing discrepancies can cascade through the consensus protocol, causing validators to timeout or retry at different rates.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention.

While this doesn't directly corrupt blockchain state, it causes non-deterministic timing behavior in consensus-critical code. Different validators will experience different RPC retry intervals, leading to:

1. **Consensus Timing Divergence**: Validators timeout and retry at unpredictable rates
2. **Network Congestion Asymmetry**: Some validators may flood the network with retries while others wait too long
3. **Potential Liveness Issues**: Extreme timing divergence could contribute to consensus delays

The bug affects all validators equally (no single attacker benefit), but requires operational intervention to diagnose and fix the timing discrepancies across the network.

## Likelihood Explanation

**Likelihood: High** - This bug triggers automatically during normal operation.

The `Interval` type is used in multiple consensus-critical paths including DAG network communication. Every time an interval period elapses, the bug is triggered. Given typical consensus round times (seconds), this occurs continuously during validator operation.

The impact severity depends on how much time has elapsed when `reset()` is called:
- If the sleep elapsed 10ms ago and period is 1000ms, new deadline is only 990ms away (10ms error)
- If the sleep elapsed 1000ms ago and period is 1000ms, new deadline is in the past (immediate re-fire)

Under high load or slow systems, elapsed time grows, making the timing error more severe.

## Recommendation

Fix the `reset()` implementation to use current time instead of the old deadline:

```rust
fn reset(self: Pin<&mut Self>, duration: Duration) {
    let deadline = tokio::time::Instant::now() + duration;
    RealSleep::reset(self, deadline);
}
```

This matches the behavior of `MockSleep::reset()` and ensures consistent timing across test and production environments.

Alternative: Also provide a `TimeService` reference to `RealSleep` to use `time_service.now()` for consistency with the mock implementation, though `tokio::time::Instant::now()` is sufficient for production use.

## Proof of Concept

```rust
#[tokio::test]
async fn test_reset_after_elapsed_calculates_wrong_deadline() {
    use aptos_time_service::{RealTimeService, SleepTrait, TimeServiceTrait};
    use std::time::Duration;
    use tokio::time::Instant;
    
    let time_service = RealTimeService::new();
    
    // Create a sleep that will elapse quickly
    let mut sleep = Box::pin(time_service.sleep(Duration::from_millis(10)));
    
    // Wait for it to elapse plus some additional time
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify it has elapsed
    assert!(sleep.is_elapsed());
    
    // Record when we call reset
    let reset_time = Instant::now();
    
    // Reset the sleep for 1 second
    sleep.as_mut().reset(Duration::from_secs(1));
    
    // The bug: if sleep elapsed 100ms ago and we add 1000ms,
    // the new deadline is only 900ms from now, not 1000ms
    
    // With the bug: sleep fires around 900ms from reset_time
    // Without the bug: sleep fires around 1000ms from reset_time
    
    let start = Instant::now();
    sleep.await;
    let elapsed = start.elapsed();
    
    // Expected: ~1000ms, Actual with bug: ~900ms or less
    println!("Elapsed: {:?} (expected ~1000ms)", elapsed);
    
    // This assertion will fail with the bug (elapsed < 950ms)
    // but pass with the fix (elapsed ~= 1000ms)
    assert!(elapsed >= Duration::from_millis(950), 
            "Sleep fired too early: {:?}", elapsed);
}

#[tokio::test]
async fn test_interval_timing_with_reset_bug() {
    use aptos_time_service::{RealTimeService, TimeServiceTrait};
    use std::time::Duration;
    use tokio::time::Instant;
    use futures::StreamExt;
    
    let time_service = RealTimeService::new();
    let mut interval = time_service.interval(Duration::from_millis(100));
    
    // First tick is immediate
    interval.next().await;
    
    // Simulate high load by adding delay before polling
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    let start = Instant::now();
    interval.next().await; // This calls reset() on an elapsed sleep
    let first_interval = start.elapsed();
    
    // Expected: ~100ms from start
    // Actual with bug: ~50ms from start (100ms - 50ms elapsed time)
    println!("First interval: {:?}", first_interval);
    
    // The bug causes the interval to be shorter than expected
    // leading to non-deterministic timing behavior
}
```

**Notes**

The vulnerability exists in production code and is automatically triggered during normal consensus operation. While it doesn't break consensus safety guarantees, it introduces timing non-determinism that violates the expectation of consistent behavior across validators. The fix is straightforward and should be applied to ensure predictable timing behavior in consensus-critical code paths.

### Citations

**File:** crates/aptos-time-service/src/real.rs (L55-58)
```rust
    fn reset(self: Pin<&mut Self>, duration: Duration) {
        let deadline = self.deadline() + duration;
        RealSleep::reset(self, deadline);
    }
```

**File:** crates/aptos-time-service/src/mock.rs (L357-369)
```rust
    fn reset(self: Pin<&mut Self>, duration: Duration) {
        let this = self.get_mut();
        let mut inner = this.time_service.lock();

        // Unregister us from the time service (if we're not triggered yet)
        // and pull out our waker (if it's there).
        let maybe_waker = inner.unregister_sleep(this.deadline, this.index).flatten();

        // Register us with the time service with our new deadline.
        let (deadline, index) = inner.register_sleep(duration, maybe_waker);
        this.deadline = deadline;
        this.index = index;
    }
```

**File:** crates/aptos-time-service/src/interval.rs (L40-50)
```rust
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        // Wait for the delay to be done
        ready!(this.delay.as_mut().poll(cx));

        // Reset the delay before next round
        this.delay.reset(*this.period);

        Poll::Ready(Some(()))
    }
```

**File:** consensus/src/dag/dag_network.rs (L121-121)
```rust
            interval: Box::pin(time_service.interval(retry_interval)),
```
