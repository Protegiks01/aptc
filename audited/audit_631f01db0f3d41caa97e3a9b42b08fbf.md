# Audit Report

## Title
Clock Skew Causes Consensus Timeout Inconsistencies via Mixed Use of System Time and Monotonic Time

## Summary
The Aptos consensus layer uses **system time** (affected by clock skew) for round deadline calculations but **monotonic time** (unaffected by clock skew) for actual timeout enforcement. This architectural flaw causes validators with different system clocks to compute different round deadlines, leading to inconsistent voting decisions on identical proposals and potential consensus liveness failures.

## Finding Description

The vulnerability arises from mixing two different time sources in the consensus protocol:

**1. Deadline Calculation Uses System Time**

The `ClockTimeService::get_current_timestamp()` method returns system time that is affected by clock adjustments: [1](#0-0) 

This calls `aptos_infallible::duration_since_epoch()` which uses `SystemTime::now()`: [2](#0-1) 

The consensus round deadline is calculated using this system time: [3](#0-2) 

**2. Timeout Enforcement Uses Monotonic Time**

The actual timeout mechanism uses `tokio::time::sleep()` which relies on monotonic time (unaffected by clock adjustments): [4](#0-3) 

**3. Deadline Used for Critical Voting Decisions**

The round deadline is used to reject proposals whose timestamp would exceed the deadline: [5](#0-4) 

This `ensure!` check causes validators with different system clocks to make different voting decisions on identical proposals.

**4. Payload Fetching Mixes Time Sources**

The `wait_for_payload()` method calculates timeout duration by subtracting system times, then passes this to `tokio::time::timeout()` which uses monotonic time: [6](#0-5) 

**The Attack Scenario:**

When validators have clock skew:
- Validator A (clock ahead 2s): deadline = (T+2s) + 5s = T+7s
- Validator B (correct clock): deadline = T + 5s = T+5s
- Proposal arrives with timestamp T+6s:
  - Validator A: T+6s < T+7s → **accepts and votes**
  - Validator B: T+6s ≥ T+5s → **rejects via ensure! failure, no vote cast**

This breaks consensus agreement, preventing quorum formation (2f+1 votes).

## Impact Explanation

**Severity: High** (potentially Critical under widespread conditions)

This vulnerability causes **consensus liveness degradation or failure**:

1. **Voting Inconsistency**: Validators with different clock skews make different voting decisions on identical proposals, preventing quorum formation.

2. **Payload Timeout Mismatch**: If the system clock jumps forward during payload fetching, the calculated duration `deadline - get_current_timestamp()` becomes near-zero, causing immediate timeout even though monotonic time hasn't elapsed. This causes validators to fail voting on valid proposals.

3. **Round Timeout Cascades**: When validators can't reach quorum due to clock-based disagreements, rounds timeout repeatedly, severely degrading throughput.

Per Aptos bug bounty criteria:
- **High Severity** ($50,000): "Validator node slowdowns" - clock skew causes consensus degradation and "Significant protocol violations" - validators disagree on voting decisions
- **Critical Severity** (up to $1,000,000): If clock skew affects enough validators to prevent quorum consistently, this becomes "Total loss of liveness/network availability"

## Likelihood Explanation

**Likelihood: Medium to High**

1. **Natural Occurrence**: Clock skew is inherent to distributed systems:
   - NTP synchronization typically maintains 1-100ms accuracy but can drift to seconds during network issues or misconfigurations
   - Validators in geographically distributed data centers have independent clocks
   - System administrators may adjust clocks during maintenance
   - Virtualized environments (common for validators) have well-documented clock drift issues

2. **Attack Vector**:
   - Malicious validator operator can intentionally skew their node's system clock
   - NTP spoofing attacks (if validators use unauthenticated NTP)
   - No special privileges required beyond controlling system time on a validator node

3. **Low Detection Difficulty**: The issue manifests as normal timeout behavior, making it difficult to diagnose as a clock skew problem versus network congestion.

## Recommendation

**Solution: Use consistent time source for both deadline calculation and timeout enforcement**

**Option 1 (Recommended): Use monotonic time for round deadlines**
```rust
// In ClockTimeService, add a method for monotonic time
fn get_monotonic_instant(&self) -> Instant {
    Instant::now()
}

// In RoundState::setup_deadline, use monotonic time base
let now_monotonic = self.time_service.get_monotonic_instant();
self.current_round_deadline_instant = now_monotonic + timeout;

// In RoundManager proposal validation, compare monotonic times
let block_timestamp_instant = /* convert from block timestamp */;
ensure!(
    block_timestamp_instant < self.round_state.current_round_deadline_instant(),
    "Proposal would exceed round deadline"
);
```

**Option 2: Use system time for both (less recommended)**
Replace `tokio::time::timeout` with a custom implementation that uses system time, but this introduces other issues with clock adjustments.

**Critical Fix for wait_for_payload:**
Store the deadline as a monotonic Instant from the start, avoiding system time subtraction entirely.

## Proof of Concept

While a full PoC requires a multi-validator test environment, the vulnerability can be demonstrated by:

1. Running two validator nodes with their system clocks set 2 seconds apart
2. Configuring initial round timeout to 5 seconds
3. Having the proposer create a block with timestamp T+6s (where T is the base time)
4. Observing that the validator with the fast clock votes while the validator with correct clock rejects via the ensure! check
5. Quorum cannot be formed, round times out

The vulnerability is present in the current codebase as evidenced by the cited code paths.

## Notes

**Mitigating Factors:**
- Byzantine fault tolerance design means < 1/3 validators with issues shouldn't halt consensus entirely
- The 5-minute timestamp bound check in `verify_well_formed()` provides an upper limit on acceptable skew

**Aggravating Factors:**
- This is a systematic issue affecting all validators running the same code
- Clock skew between validators is expected and common in distributed systems
- The issue is particularly severe in `wait_for_payload()` where system clock jumps cause immediate timeouts

**Monitoring:** The codebase includes clock skew monitoring but no enforcement: [7](#0-6)

### Citations

**File:** consensus/src/util/time_service.rs (L114-125)
```rust
    fn run_after(&self, timeout: Duration, mut t: Box<dyn ScheduledTask>) -> AbortHandle {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let task = Abortable::new(
            async move {
                sleep(timeout).await;
                t.run().await;
            },
            abort_registration,
        );
        self.executor.spawn(task);
        abort_handle
    }
```

**File:** consensus/src/util/time_service.rs (L127-129)
```rust
    fn get_current_timestamp(&self) -> Duration {
        aptos_infallible::duration_since_epoch()
    }
```

**File:** crates/aptos-infallible/src/time.rs (L9-13)
```rust
pub fn duration_since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is before the UNIX_EPOCH")
}
```

**File:** consensus/src/liveness/round_state.rs (L373-384)
```rust
        let now = self.time_service.get_current_timestamp();
        debug!(
            round = self.current_round,
            "{:?} passed since the previous deadline.",
            now.checked_sub(self.current_round_deadline)
                .map_or_else(|| "0 ms".to_string(), |v| format!("{:?}", v))
        );
        debug!(
            round = self.current_round,
            "Set round deadline to {:?} from now", timeout
        );
        self.current_round_deadline = now + timeout;
```

**File:** consensus/src/round_manager.rs (L1233-1241)
```rust
        let block_time_since_epoch = Duration::from_micros(proposal.timestamp_usecs());

        ensure!(
            block_time_since_epoch < self.round_state.current_round_deadline(),
            "[RoundManager] Waiting until proposal block timestamp usecs {:?} \
            would exceed the round duration {:?}, hence will not vote for this round",
            block_time_since_epoch,
            self.round_state.current_round_deadline(),
        );
```

**File:** consensus/src/block_storage/block_store.rs (L589-594)
```rust
    pub async fn wait_for_payload(&self, block: &Block, deadline: Duration) -> anyhow::Result<()> {
        let duration = deadline.saturating_sub(self.time_service.get_current_timestamp());
        tokio::time::timeout(duration, self.payload_manager.get_transactions(block, None))
            .await??;
        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L1954-1958)
```rust
            // Continually capture the time of consensus process to ensure that clock skew between
            // validators is reasonable and to find any unusual (possibly byzantine) clock behavior.
            counters::OP_COUNTERS
                .gauge("time_since_epoch_ms")
                .set(duration_since_epoch().as_millis() as i64);
```
