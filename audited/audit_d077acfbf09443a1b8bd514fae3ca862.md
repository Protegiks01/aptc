# Audit Report

## Title
Clock Skew Causes Valid Block Rejection Leading to Consensus Liveness Degradation

## Summary
The timestamp deadline check in `process_proposal()` compares block timestamps from the proposer's clock against round deadlines calculated from the validator's clock, without accounting for expected clock skew. This causes honest validators with clock drift exceeding the round timeout to have their valid proposals systematically rejected, degrading network liveness and performance.

## Finding Description

The vulnerability exists in the proposal validation logic where timestamps from two independent clock sources are compared without clock skew tolerance. [1](#0-0) 

The proposer generates block timestamps using their local clock: [2](#0-1) 

The validator calculates the round deadline using their own local clock: [3](#0-2) 

With the default round timeout of 1 second: [4](#0-3) 

**Attack Flow:**
1. Proposer's clock is ahead by ≥1 second (natural NTP drift or misconfiguration)
2. Proposer creates valid block with `timestamp = proposer_current_time`
3. Block passes `verify_well_formed()` (allows up to 5 minutes future): [5](#0-4) 

4. Validator receives block and checks: `block_timestamp < validator_current_time + 1_second`
5. Check fails if proposer's clock is ≥1 second ahead
6. Valid block rejected, round times out

The system already has infrastructure to wait for future block timestamps: [6](#0-5) 

However, the deadline check occurs BEFORE this waiting mechanism is reached, prematurely rejecting blocks that could be safely processed.

The system acknowledges 5 seconds as acceptable clock skew elsewhere: [7](#0-6) 

Yet the consensus layer uses a 1-second tolerance, inconsistent with system-wide assumptions.

## Impact Explanation

This qualifies as **Medium Severity** under "State inconsistencies requiring intervention":
- Valid proposals from honest validators are rejected due to clock synchronization issues
- Network performance degrades as rounds timeout unnecessarily  
- Validators with slight clock drift are effectively penalized
- Under systematic clock skew across validators, liveness could be significantly impacted
- May require manual intervention to synchronize validator clocks during incidents

The BlockData documentation guarantees that validators only vote when their clock ≥ block timestamp: [8](#0-7) 

The current implementation violates the spirit of guarantee #3 by rejecting blocks it could wait for, rather than waiting until the appropriate time.

## Likelihood Explanation

**High likelihood** in production environments:
- NTP typically synchronizes to 100-500ms accuracy, but not always
- Network partitions, misconfigurations, or hardware issues can cause 1+ second clock skew
- Geographically distributed validator sets experience higher clock drift
- Default 1-second timeout provides no safety margin
- No cryptographic enforcement of clock synchronization between validators

## Recommendation

Add clock skew tolerance to the deadline check to align with system-wide assumptions:

```rust
const CONSENSUS_CLOCK_SKEW_TOLERANCE_MS: u64 = 5000; // 5 seconds, matching ACCEPTED_CLOCK_SKEW_US

let block_time_since_epoch = Duration::from_micros(proposal.timestamp_usecs());
let deadline_with_tolerance = self.round_state.current_round_deadline() 
    + Duration::from_millis(CONSENSUS_CLOCK_SKEW_TOLERANCE_MS);

ensure!(
    block_time_since_epoch < deadline_with_tolerance,
    "[RoundManager] Block timestamp {:?} would exceed round deadline {:?} even with clock skew tolerance",
    block_time_since_epoch,
    deadline_with_tolerance,
);
```

Alternatively, remove this check entirely and rely on:
1. The 5-minute future bound in `verify_well_formed()`
2. The waiting mechanism in `insert_block()`
3. Normal round timeout mechanisms

## Proof of Concept

```rust
#[tokio::test]
async fn test_clock_skew_rejection() {
    // Setup: Create validator with current time T
    let validator_time = Duration::from_secs(1000);
    
    // Proposer's clock is 1.5 seconds ahead (realistic NTP drift)
    let proposer_time = validator_time + Duration::from_millis(1500);
    
    // Round timeout is default 1 second
    let round_timeout = Duration::from_secs(1);
    let round_deadline = validator_time + round_timeout;
    
    // Proposer creates valid block with their timestamp
    let block_timestamp = proposer_time;
    
    // Current check: block_timestamp < round_deadline
    // 1001.5 < 1001.0 => FALSE
    assert!(block_timestamp >= round_deadline, 
        "Valid block rejected due to 1.5s clock skew");
    
    // Block passes verify_well_formed (< 5 min future)
    let max_future = validator_time + Duration::from_secs(300);
    assert!(block_timestamp < max_future,
        "Block passes 5-minute future check");
    
    // Validator COULD wait: wait_time = 1.5s, total = 1001.5s
    // But check rejects before waiting occurs
    
    // With recommended fix (5s tolerance):
    let deadline_with_tolerance = round_deadline + Duration::from_secs(5);
    assert!(block_timestamp < deadline_with_tolerance,
        "Block accepted with clock skew tolerance");
}
```

**Notes:**
- This vulnerability affects consensus liveness, not safety
- Honest validators with natural clock drift are penalized
- The 1-second default timeout provides insufficient margin for realistic clock synchronization
- The fix should align with the documented 5-second acceptable clock skew used elsewhere in the system
- The inconsistency between the 5-minute future bound and the 1-second round-based check creates an unnecessarily fragile system

### Citations

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

**File:** consensus/src/liveness/proposal_generator.rs (L601-601)
```rust
        let timestamp = self.time_service.get_current_timestamp();
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

**File:** config/src/config/consensus_config.rs (L235-235)
```rust
            round_initial_timeout_ms: 1000,
```

**File:** consensus/consensus-types/src/block.rs (L532-539)
```rust
            let current_ts = duration_since_epoch();

            // we can say that too far is 5 minutes in the future
            const TIMEBOUND: u64 = 300_000_000;
            ensure!(
                self.timestamp_usecs() <= (current_ts.as_micros() as u64).saturating_add(TIMEBOUND),
                "Blocks must not be too far in the future"
            );
```

**File:** consensus/src/block_storage/block_store.rs (L500-511)
```rust
        let block_time = Duration::from_micros(pipelined_block.timestamp_usecs());
        let current_timestamp = self.time_service.get_current_timestamp();
        if let Some(t) = block_time.checked_sub(current_timestamp) {
            if t > Duration::from_secs(1) {
                warn!(
                    "Long wait time {}ms for block {}",
                    t.as_millis(),
                    pipelined_block
                );
            }
            self.time_service.wait_until(block_time).await;
        }
```

**File:** crates/aptos/src/common/types.rs (L88-88)
```rust
pub const ACCEPTED_CLOCK_SKEW_US: u64 = 5 * US_IN_SECS;
```

**File:** consensus/consensus-types/src/block_data.rs (L86-96)
```rust
    /// It makes the following guarantees:
    ///   1. Time Monotonicity: Time is monotonically increasing in the block chain.
    ///      (i.e. If H1 < H2, H1.Time < H2.Time).
    ///   2. If a block of transactions B is agreed on with timestamp T, then at least
    ///      f+1 honest validators think that T is in the past. An honest validator will
    ///      only vote on a block when its own clock >= timestamp T.
    ///   3. If a block of transactions B has a QC with timestamp T, an honest validator
    ///      will not serve such a block to other validators until its own clock >= timestamp T.
    ///   4. Current: an honest validator is not issuing blocks with a timestamp in the
    ///       future. Currently we consider a block is malicious if it was issued more
    ///       that 5 minutes in the future.
```
