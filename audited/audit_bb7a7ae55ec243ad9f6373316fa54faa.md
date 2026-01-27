# Audit Report

## Title
Exponential Window Failure Tracker Hysteresis Vulnerability Allows Permanent OptQS Disablement

## Summary
The `ExponentialWindowFailureTracker` in `proposal_status_tracker.rs` contains a critical asymmetry flaw where the failure window grows exponentially with each `PayloadUnavailable` timeout but only resets when ALL stored history (up to 100 rounds) consists of consecutive successes. This creates a hysteresis trap where a malicious validator or transient network issues can permanently disable Optimistic Quorum Store (OptQS), forcing the network into a degraded performance state. [1](#0-0) 

## Finding Description

The vulnerability exists in the condition that determines whether OptQS is enabled. [2](#0-1)  The logic checks if `last_consecutive_success_count < window`, and if true, OptQS is disabled.

The window growth and reset logic exhibits severe asymmetry: [3](#0-2) 

**Window Growth (Easy):**
- Each `PayloadUnavailable` failure doubles the window size (line 72-74)
- Window grows exponentially: 2 → 4 → 8 → 16 → 32 → 64 → 100 (max)
- Takes only 6-7 failures to reach maximum window size

**Window Reset (Extremely Difficult):**
- Window only resets to 2 when `last_consecutive_success_count == past_round_statuses.len()` (line 75-77)
- Since `past_round_statuses` is bounded by `max_window` (hardcoded to 100), [4](#0-3)  this requires 100 consecutive successful rounds with ZERO `PayloadUnavailable` failures
- Otherwise, the window remains at its current elevated level

**Attack Vector:**

A malicious validator can exploit this by:
1. Creating batches but deliberately not propagating them to other validators
2. When proposals include their batches as `opt_batches` in OptQuorumStore payloads, other validators won't have them locally
3. This triggers `PayloadUnavailable` timeouts [5](#0-4) 
4. The failure tracker doubles the window with each failure [6](#0-5) 

Once the window reaches 100, the attacker needs only to inject 1 failure every 99 rounds to keep `last_consecutive_success_count < 100`, permanently disabling OptQS.

**Even Without an Attacker:**

In production networks, occasional legitimate issues (network partitions, slow nodes, temporary connectivity problems) naturally cause rare `PayloadUnavailable` events. Once these issues grow the window to 100:
- The network needs 100 CONSECUTIVE perfect rounds to recover
- Any single legitimate failure resets the consecutive counter to 0
- Achieving 100 consecutive perfect rounds in a real distributed system is extremely difficult
- The network becomes trapped in a degraded state

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

**Validator Node Slowdowns:** OptQS (Optimistic Quorum Store) provides significant performance benefits by enabling optimistic proposals and faster batch inclusion. When OptQS is disabled, the network falls back to non-optimistic mode, which:
- Increases consensus latency
- Reduces throughput
- Degrades overall network performance

**Protocol Violation:** The failure tracker is designed to temporarily disable OptQS during network issues and automatically re-enable it when the network recovers. The hysteresis flaw violates this design intent by creating a state where recovery is practically impossible.

**Network-Wide Impact:** Unlike single-node issues, this affects the entire consensus network. Once triggered, all validators suffer from degraded OptQS availability, impacting overall blockchain throughput and user experience.

The vulnerability falls under "Validator node slowdowns" which is classified as High severity with potential rewards up to $50,000.

## Likelihood Explanation

**High Likelihood - Can Occur Naturally:**

Even without malicious actors, this vulnerability can be triggered by:
- Transient network partitions during deployment or maintenance
- Validator nodes experiencing temporary slowdowns
- Network congestion causing batch propagation delays
- Cloud infrastructure issues affecting specific validators

Once triggered, the 100-consecutive-success requirement makes recovery extremely unlikely in production.

**Trivial to Exploit Maliciously:**

A single malicious validator can:
1. Deliberately withhold batch propagation to cause initial failures
2. Wait for the window to grow to 100 (requires ~6-7 failures)
3. Inject 1 failure every 99 rounds to maintain the degraded state
4. Even after being excluded from OptQS proposals [7](#0-6)  the window remains large, and other legitimate network issues keep OptQS disabled

**Attacker Requirements:**
- Must be a validator in the active set
- No collusion needed
- No special privileges beyond normal validator capabilities

## Recommendation

Implement a gradual window decay mechanism instead of the current binary reset:

```rust
fn compute_failure_window(&mut self) {
    self.last_consecutive_success_count = self.last_consecutive_statuses_matching(|reason| {
        !matches!(
            reason,
            NewRoundReason::Timeout(RoundTimeoutReason::PayloadUnavailable { .. })
        )
    });
    
    if self.last_consecutive_success_count == 0 {
        // Double on immediate failure
        self.window *= 2;
        self.window = self.window.min(self.max_window);
    } else if self.last_consecutive_success_count == self.past_round_statuses.len() {
        // Full reset when all history is successful
        self.window = 2;
    } else if self.last_consecutive_success_count >= self.window {
        // ADDED: Gradual decay when meeting current threshold
        // Halve the window to make recovery easier
        self.window = (self.window / 2).max(2);
    }
}
```

**Alternative Recommendation:**

Implement a time-based or count-based decay where the window gradually shrinks if there are sustained periods of success, even without meeting the full consecutive requirement:

```rust
// Track rounds since last failure
if self.last_consecutive_success_count >= self.window / 2 {
    // After sustaining half-window successes, start shrinking
    self.window = ((self.window * 3) / 4).max(2);
}
```

Both approaches prevent the hysteresis trap while maintaining the exponential backoff for genuine failure scenarios.

## Proof of Concept

```rust
#[test]
fn test_hysteresis_vulnerability() {
    use aptos_bitvec::BitVec;
    use aptos_types::validator_verifier::random_validator_verifier;
    
    let (_signers, verifier) = random_validator_verifier(4, None, false);
    let mut tracker = ExponentialWindowFailureTracker::new(
        100,
        verifier.get_ordered_account_addresses()
    );
    
    // Grow window to max_window with 7 failures
    for _ in 0..7 {
        tracker.push(NewRoundReason::Timeout(
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: BitVec::with_num_bits(4),
            },
        ));
    }
    assert_eq!(tracker.window, 100);
    
    // Demonstrate the hysteresis trap:
    // Even with 99% success rate, OptQS stays disabled
    for cycle in 0..5 {
        // 99 consecutive successes
        for _ in 0..99 {
            tracker.push(NewRoundReason::QCReady);
        }
        
        // Check: last_consecutive_success_count = 99, but 99 < 100
        assert_eq!(tracker.last_consecutive_success_count, 99);
        assert!(tracker.last_consecutive_success_count < tracker.window);
        // OptQS would be DISABLED here despite 99% success rate
        
        // One failure resets everything
        tracker.push(NewRoundReason::Timeout(
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: BitVec::with_num_bits(4),
            },
        ));
        assert_eq!(tracker.last_consecutive_success_count, 0);
        assert_eq!(tracker.window, 100); // Still at max
    }
    
    // Network is stuck: OptQS permanently disabled despite 99% health
    // This demonstrates the vulnerability
}

#[test]
fn test_optqs_disabled_with_hysteresis() {
    use std::sync::Arc;
    use aptos_infallible::Mutex;
    use aptos_types::validator_verifier::random_validator_verifier;
    use aptos_bitvec::BitVec;
    
    let (_signers, verifier) = random_validator_verifier(4, None, false);
    let tracker = Arc::new(Mutex::new(ExponentialWindowFailureTracker::new(
        100,
        verifier.get_ordered_account_addresses()
    )));
    
    let provider = OptQSPullParamsProvider::new(
        true, // enable_opt_qs = true
        0,
        tracker.clone(),
    );
    
    // Grow window to 100
    for _ in 0..7 {
        tracker.lock().push(NewRoundReason::Timeout(
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: BitVec::with_num_bits(4),
            },
        ));
    }
    
    // 99 successes
    for _ in 0..99 {
        tracker.lock().push(NewRoundReason::QCReady);
    }
    
    // OptQS is DISABLED despite enable_opt_qs=true and 99 consecutive successes
    let params = provider.get_params();
    assert!(params.is_none(), "OptQS should be disabled due to 99 < 100");
}
```

**Expected Behavior:** The tests demonstrate that once the window reaches 100, even with 99% success rate (99 successes followed by 1 failure repeatedly), OptQS remains permanently disabled.

**Notes**

This vulnerability represents a classic hysteresis problem in distributed systems where the recovery threshold is set unrealistically high. The current design assumes that achieving 100 consecutive perfect rounds is feasible, but in real-world production networks with hundreds of validators across different continents, occasional transient issues are inevitable. The exponential growth without proportional decay creates a trap that degrades network performance indefinitely.

### Citations

**File:** consensus/src/liveness/proposal_status_tracker.rs (L65-78)
```rust
    fn compute_failure_window(&mut self) {
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

**File:** consensus/src/liveness/proposal_status_tracker.rs (L145-155)
```rust
        let exclude_authors = tracker.get_exclude_authors();
        if !exclude_authors.is_empty() {
            let exclude_authors_str: Vec<_> =
                exclude_authors.iter().map(|a| a.short_str()).collect();
            for author in &exclude_authors_str {
                counters::OPTQS_EXCLUDE_AUTHORS_COUNT
                    .with_label_values(&[author.as_str()])
                    .inc();
            }
            warn!("OptQS exclude authors: {:?}", exclude_authors_str);
        }
```

**File:** consensus/src/epoch_manager.rs (L901-904)
```rust
        let failures_tracker = Arc::new(Mutex::new(ExponentialWindowFailureTracker::new(
            100,
            epoch_state.verifier.get_ordered_account_addresses(),
        )));
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

**File:** consensus/src/round_manager.rs (L968-983)
```rust
    fn compute_timeout_reason(&self, round: Round) -> RoundTimeoutReason {
        if self.round_state().vote_sent().is_some() {
            return RoundTimeoutReason::NoQC;
        }

        match self.block_store.get_block_for_round(round) {
            None => RoundTimeoutReason::ProposalNotReceived,
            Some(block) => {
                if let Err(missing_authors) = self.block_store.check_payload(block.block()) {
                    RoundTimeoutReason::PayloadUnavailable { missing_authors }
                } else {
                    RoundTimeoutReason::Unknown
                }
            },
        }
    }
```
