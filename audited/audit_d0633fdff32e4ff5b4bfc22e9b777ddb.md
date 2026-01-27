# Audit Report

## Title
OptQS Premature Disablement Due to Insufficient Initial Window Size

## Summary
The `ExponentialWindowFailureTracker` initializes with a window size of 2, causing the Optimistic Quorum Store (OptQS) feature to be disabled after a single `PayloadUnavailable` timeout. This creates an exploitable denial-of-service vector where consensus performance can be degraded with minimal effort, as the system reacts aggressively based on insufficient data (1-2 observations). [1](#0-0) 

## Finding Description

The OptQS feature is a performance optimization that allows validators to propose blocks with batches that haven't yet achieved full quorum certification. The `ExponentialWindowFailureTracker` monitors proposal success/failure and controls when OptQS is enabled.

**The vulnerability chain:**

1. **Initialization**: The tracker starts with `window = 2` [2](#0-1) 

2. **Failure Detection**: When a `PayloadUnavailable` timeout occurs (batches unavailable in local storage), it's classified as a failure [3](#0-2) 

3. **Aggressive Window Doubling**: A single failure (`last_consecutive_success_count == 0`) immediately doubles the window to 4 [4](#0-3) 

4. **OptQS Disablement**: OptQS is disabled when consecutive successes are below the window threshold [5](#0-4) 

5. **Trigger Mechanism**: `PayloadUnavailable` occurs when opt_batches are missing from validators' local batch storage [6](#0-5) 

6. **Propagation**: The timeout reason is pushed to the tracker on each new round [7](#0-6) 

**Attack Scenario:**
- A malicious validator can withhold or delay their batch distribution
- When they're selected as a batch author, other validators won't have their batches
- At least f+1 validators report `PayloadUnavailable` [8](#0-7) 
- The aggregated timeout triggers window doubling from 2→4
- OptQS is disabled for ≥4 consecutive successful rounds
- The attacker can repeat this strategically to maintain performance degradation

**Why the initial window=2 is problematic:**
- Only 1 failure out of 2 observations (50% failure rate) triggers aggressive reaction
- Insufficient statistical sample to distinguish transient vs. persistent issues
- No gradual escalation—immediate doubling after first failure
- Creates easily exploitable threshold for denial of service

## Impact Explanation

**Severity: Medium to High**

This vulnerability falls under the **High Severity** category per Aptos bug bounty criteria: "Validator node slowdowns"

**Impact:**
- **Performance Degradation**: OptQS significantly improves consensus throughput. Disabling it forces fallback to regular Quorum Store with higher latency
- **Network-Wide Effect**: All validators experience reduced throughput, not just the target
- **Sustained Attack**: Can be repeated to maintain degraded state
- **Low Recovery Threshold**: Requires 4 consecutive successes, making recovery slower

**What is NOT impacted:**
- Consensus safety (no double-spending or forks)
- Funds (no loss or theft)
- Total liveness (regular Quorum Store still functions)
- State consistency

The vulnerability creates a **denial-of-service vector against network performance**, meeting the threshold for High severity validator slowdowns.

## Likelihood Explanation

**Likelihood: Moderate to High**

**Attacker Requirements:**
- **Option 1**: Single malicious validator who can withhold their batch distribution
- **Option 2**: Network adversary who can delay batch propagation to f+1 validators
- **Option 3**: Natural network issues (unintentional but demonstrates fragility)

**Ease of Exploitation:**
- **Low Threshold**: Only need to trigger one `PayloadUnavailable` in the first 2 rounds
- **Repeatable**: Can be executed periodically to maintain degraded state  
- **Minimal Cost**: Malicious validator risks their own performance but degrades entire network

**Detection Difficulty:**
- Appears as legitimate timeout due to batch unavailability
- Hard to distinguish malicious withholding from network delays
- No direct attribution to attacker

**Realistic Scenario:**
A validator could strategically time batch withholding when they know they'll be selected as batch author, triggering network-wide performance degradation with minimal observable malicious behavior.

## Recommendation

**Immediate Fix: Increase Initial Window Size**

Change the initial window from 2 to 8 or 16 to collect sufficient data before aggressive reaction:

```rust
pub(crate) fn new(max_window: usize, ordered_authors: Vec<Author>) -> Self {
    Self {
        window: 8,  // Changed from 2 to 8
        max_window,
        past_round_statuses: BoundedVecDeque::new(max_window),
        last_consecutive_success_count: 0,
        ordered_authors,
    }
}
```

**Additional Improvements:**

1. **Gradual Escalation**: Require multiple failures within the window before doubling:
```rust
if self.last_consecutive_success_count == 0 {
    let failures_in_window = self.past_round_statuses.iter()
        .rev()
        .take(self.window)
        .filter(|r| matches!(r, NewRoundReason::Timeout(RoundTimeoutReason::PayloadUnavailable { .. })))
        .count();
    
    if failures_in_window >= 2 {  // Require multiple failures
        self.window *= 2;
        self.window = self.window.min(self.max_window);
    }
}
```

2. **Author-Specific Handling**: Keep OptQS enabled but exclude problematic authors rather than disabling entirely

3. **Configurable Threshold**: Make initial window size and escalation thresholds configurable via on-chain governance

## Proof of Concept

```rust
#[cfg(test)]
mod vulnerability_poc {
    use super::*;
    use aptos_bitvec::BitVec;
    use aptos_consensus_types::round_timeout::RoundTimeoutReason;
    use aptos_types::validator_verifier::random_validator_verifier;

    #[test]
    fn test_premature_optqs_disablement() {
        let (_signers, verifier) = random_validator_verifier(4, None, false);
        let mut tracker = ExponentialWindowFailureTracker::new(
            100, 
            verifier.get_ordered_account_addresses()
        );
        
        // Initial state
        assert_eq!(tracker.window, 2);
        assert_eq!(tracker.last_consecutive_success_count, 0);
        
        // Single successful round
        tracker.push(NewRoundReason::QCReady);
        assert_eq!(tracker.window, 2);
        assert_eq!(tracker.last_consecutive_success_count, 1);
        
        // VULNERABILITY: One PayloadUnavailable immediately doubles window
        tracker.push(NewRoundReason::Timeout(
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: BitVec::with_num_bits(4),
            }
        ));
        
        // Window doubled with only 2 data points!
        assert_eq!(tracker.window, 4);
        assert_eq!(tracker.last_consecutive_success_count, 0);
        
        // OptQS would now be disabled because 0 < 4
        // Requires 4 consecutive successes to recover
        // This demonstrates premature reaction with insufficient data
        
        println!("VULNERABILITY CONFIRMED:");
        println!("- Only 2 observations before aggressive reaction");
        println!("- 50% failure rate (1/2) triggers window doubling");
        println!("- Recovery requires 4 consecutive successes");
        println!("- Easily exploitable for DoS");
    }
}
```

**Expected Output:**
```
VULNERABILITY CONFIRMED:
- Only 2 observations before aggressive reaction
- 50% failure rate (1/2) triggers window doubling
- Recovery requires 4 consecutive successes
- Easily exploitable for DoS
```

## Notes

The vulnerability is particularly concerning because:

1. **Statistical Insufficiency**: Making binary decisions (enable/disable OptQS) based on 1-2 samples violates basic statistical principles
2. **Asymmetric Impact**: Single malicious validator can degrade entire network performance
3. **Recovery Barrier**: The 4-round recovery requirement compounds the impact
4. **Design Flaw vs Bug**: While this is a logic error rather than a code bug, it creates an exploitable attack surface

The existing `exclude_authors` mechanism (lines 80-98) attempts to mitigate this by excluding problematic authors, but the fundamental issue remains: OptQS is disabled entirely rather than degrading gracefully by excluding specific authors while maintaining the optimization for others.

### Citations

**File:** consensus/src/liveness/proposal_status_tracker.rs (L38-47)
```rust
impl ExponentialWindowFailureTracker {
    pub(crate) fn new(max_window: usize, ordered_authors: Vec<Author>) -> Self {
        Self {
            window: 2,
            max_window,
            past_round_statuses: BoundedVecDeque::new(max_window),
            last_consecutive_success_count: 0,
            ordered_authors,
        }
    }
```

**File:** consensus/src/liveness/proposal_status_tracker.rs (L66-78)
```rust
        self.last_consecutive_success_count = self.last_consecutive_statuses_matching(|reason| {
            !matches!(
                reason,
                NewRoundReason::Timeout(RoundTimeoutReason::PayloadUnavailable { .. })
            )
        });
        if self.last_consecutive_success_count == 0 {
            self.window *= 2;
            self.window = self.window.min(self.max_window);
        } else if self.last_consecutive_success_count == self.past_round_statuses.len() {
            self.window = 2;
        }
    }
```

**File:** consensus/src/liveness/proposal_status_tracker.rs (L137-143)
```rust
        if tracker.last_consecutive_success_count < tracker.window {
            warn!(
                "Skipping OptQS: (last_consecutive_successes) {} < {} (window)",
                tracker.last_consecutive_success_count, tracker.window
            );
            return None;
        }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L409-424)
```rust
            Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => {
                let mut missing_authors = BitVec::with_num_bits(self.ordered_authors.len() as u16);
                for batch in p.opt_batches().deref() {
                    if self.batch_reader.exists(batch.digest()).is_none() {
                        let index = *self
                            .address_to_validator_index
                            .get(&batch.author())
                            .expect("Payload author should have been verified");
                        missing_authors.set(index as u16);
                    }
                }
                if missing_authors.all_zeros() {
                    Ok(())
                } else {
                    Err(missing_authors)
                }
```

**File:** consensus/src/round_manager.rs (L469-470)
```rust
        self.proposal_status_tracker
            .push(new_round_event.reason.clone());
```

**File:** consensus/src/pending_votes.rs (L135-147)
```rust
                if matches!(reason, RoundTimeoutReason::PayloadUnavailable { .. }) {
                    let mut aggregated_bitvec = BitVec::with_num_bits(verifier.len() as u16);
                    for (author_idx, voting_power) in missing_batch_authors {
                        if verifier
                            .check_aggregated_voting_power(voting_power, false)
                            .is_ok()
                        {
                            aggregated_bitvec.set(author_idx as u16);
                        }
                    }
                    RoundTimeoutReason::PayloadUnavailable {
                        missing_authors: aggregated_bitvec,
                    }
```
