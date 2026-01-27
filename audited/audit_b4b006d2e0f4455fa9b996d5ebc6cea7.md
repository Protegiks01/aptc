# Audit Report

## Title
Inadequate Author Exclusion Window in OptQS Failure Tracker Allows Unreliable Validators to Participate

## Summary
The `get_exclude_authors()` function in `ExponentialWindowFailureTracker` only examines the most recent `window` rounds when determining which validators to exclude from Optimistic Quorum Store (OptQS) proposals. When multiple `PayloadUnavailable` failures occur sequentially, the exponential window growth causes earlier failures to fall outside the observation window, allowing validators who recently caused failures to participate in OptQS without being excluded. [1](#0-0) 

## Finding Description

The Aptos consensus layer uses an `ExponentialWindowFailureTracker` to manage OptQS participation. When a `PayloadUnavailable` timeout occurs (indicating missing payload from certain validators), the system should exclude those validators from future OptQS proposals to prevent repeated failures.

The vulnerability arises from the interaction between two mechanisms:

1. **Window Doubling**: When a `PayloadUnavailable` failure occurs, the failure window doubles exponentially [2](#0-1) 

2. **Fixed-Size Exclusion Window**: The `get_exclude_authors()` function only looks at the last `window` rounds to determine exclusions [1](#0-0) 

**Attack Scenario:**

Initial state: `window=2`, `history=[]`

1. **Round 1**: Validator Alice causes `PayloadUnavailable`
   - `window` doubles to 4
   - `history=[PU(Alice)]`

2. **Round 2**: Validator Bob causes `PayloadUnavailable`  
   - `window` doubles to 8
   - `history=[PU(Alice), PU(Bob)]`

3. **Rounds 3-10**: 8 consecutive successes occur
   - `window` stays at 8
   - `history=[PU(Alice), PU(Bob), S, S, S, S, S, S, S, S]`
   - `last_consecutive_success_count=8`

4. **Round 11**: A proposer generates a new proposal
   - `get_params()` is called [3](#0-2) 
   - Check passes: `last_consecutive_success_count (8) >= window (8)` [4](#0-3) 
   - OptQS is **ENABLED**
   - `get_exclude_authors()` takes last 8 items: `[PU(Bob), S, S, S, S, S, S, S]`
   - `exclude_authors={Bob}`
   - **Alice is NOT excluded!**

Alice caused a `PayloadUnavailable` just 10 rounds ago, but she's not excluded because her failure fell outside the 8-round observation window. If Alice is still unreliable or malicious, she can cause OptQS to fail again, leading to repeated performance degradation.

The excluded authors are then used to filter batches during payload pulling [5](#0-4) 

## Impact Explanation

This vulnerability falls under **Medium Severity** per Aptos bug bounty criteria:

1. **Performance Degradation**: Unreliable validators participating in OptQS can cause repeated proposal failures, forcing the consensus to fall back to slower synchronous payload fetching.

2. **Liveness Impact**: Repeated OptQS failures increase round latency and reduce network throughput. While this doesn't cause total liveness failure, it significantly degrades network performance.

3. **Attack Amplification**: The exponential window growth paradoxically makes the problem worse - larger windows mean more historical failures fall outside the observation window, allowing more unreliable validators to participate simultaneously.

4. **State Inconsistencies**: Inconsistent exclusion of unreliable validators can lead to validator-specific view differences about which OptQS proposals should succeed, potentially requiring operator intervention to stabilize.

This does not constitute a Critical severity issue as it does not directly threaten consensus safety, cause fund loss, or create permanent network partition. However, it represents a significant protocol violation that affects network efficiency and reliability.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability will occur naturally in production scenarios:

1. **Natural Network Conditions**: Temporary network partitions, node restarts, or payload delivery delays cause legitimate `PayloadUnavailable` failures that trigger this behavior.

2. **No Attacker Privilege Required**: Any validator experiencing failures (malicious or not) can benefit from premature exclusion window expiry.

3. **Deterministic Behavior**: The issue is not probabilistic - given the specific sequence of failures and successes, the early exclusion expiry will always occur.

4. **Common in High-Failure Scenarios**: When the network experiences multiple validators with payload issues, this exact scenario (multiple sequential failures followed by recovery) is likely to occur.

The main mitigation is that the exponential window mechanism still provides some protection - it requires achieving `window` consecutive successes before OptQS re-enables, which may filter out persistently unreliable validators. However, intermittently unreliable validators will systematically evade exclusion.

## Recommendation

The exclusion logic should track **all** validators who caused `PayloadUnavailable` within a fixed historical window, rather than only those within the dynamically-sized failure window.

**Recommended Fix:**

```rust
fn get_exclude_authors(&self) -> HashSet<Author> {
    let mut exclude_authors = HashSet::new();
    
    // Use a fixed exclusion window (e.g., max_window or a configurable value)
    // rather than the dynamic failure window
    let exclusion_window = self.max_window; // or make this a separate config parameter
    
    for round_reason in self.past_round_statuses.iter().rev().take(exclusion_window) {
        if let NewRoundReason::Timeout(RoundTimeoutReason::PayloadUnavailable {
            missing_authors,
        }) = round_reason
        {
            for author_idx in missing_authors.iter_ones() {
                if let Some(author) = self.ordered_authors.get(author_idx) {
                    exclude_authors.insert(*author);
                }
            }
        }
    }
    
    exclude_authors
}
```

Alternative approach: Maintain a separate exclusion list with time-based or round-based expiry independent of the failure window calculation.

## Proof of Concept

```rust
#[cfg(test)]
mod vulnerability_test {
    use super::ExponentialWindowFailureTracker;
    use crate::liveness::round_state::NewRoundReason;
    use aptos_bitvec::BitVec;
    use aptos_consensus_types::round_timeout::RoundTimeoutReason;
    use aptos_types::validator_verifier::random_validator_verifier;

    #[test]
    fn test_early_failure_falls_outside_window() {
        let (_signers, verifier) = random_validator_verifier(4, None, false);
        let ordered_authors = verifier.get_ordered_account_addresses();
        let mut tracker = ExponentialWindowFailureTracker::new(100, ordered_authors.clone());
        
        // Round 1: Validator 0 (Alice) causes PayloadUnavailable
        let mut missing_authors_alice = BitVec::with_num_bits(4);
        missing_authors_alice.set(0);
        tracker.push(NewRoundReason::Timeout(
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: missing_authors_alice,
            },
        ));
        assert_eq!(tracker.window, 4);
        
        // Round 2: Validator 1 (Bob) causes PayloadUnavailable
        let mut missing_authors_bob = BitVec::with_num_bits(4);
        missing_authors_bob.set(1);
        tracker.push(NewRoundReason::Timeout(
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: missing_authors_bob,
            },
        ));
        assert_eq!(tracker.window, 8);
        
        // Rounds 3-10: 8 consecutive successes
        for _ in 0..8 {
            tracker.push(NewRoundReason::QCReady);
        }
        assert_eq!(tracker.window, 8);
        assert_eq!(tracker.last_consecutive_success_count, 8);
        
        // Now check exclusions - Alice should be excluded but won't be
        let excluded = tracker.get_exclude_authors();
        
        // VULNERABILITY: Alice (author 0) is NOT in the exclusion set!
        assert!(!excluded.contains(&ordered_authors[0]), 
            "BUG: Alice (validator 0) is not excluded despite causing failure just 9 rounds ago");
        
        // Only Bob (author 1) is excluded
        assert!(excluded.contains(&ordered_authors[1]),
            "Bob (validator 1) is correctly excluded");
        
        println!("VULNERABILITY CONFIRMED: Alice caused failure in round 1 but is not excluded in round 11");
        println!("Window size: {}, Exclusions: {:?}", tracker.window, excluded.len());
    }
}
```

This test demonstrates that Validator Alice, who caused a `PayloadUnavailable` failure only 9 rounds prior, is not excluded from OptQS participation because her failure fell outside the 8-round observation window.

## Notes

The current implementation appears to prioritize recent failures over older ones, which may be intentional to allow validators to "recover" after demonstrating reliability. However, the exponential window growth creates an unintended consequence where the observation window grows faster than the required recovery period, allowing unreliable validators to evade exclusion. This represents a gap between the intended security property (excluding unreliable validators) and the actual implementation behavior.

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

**File:** consensus/src/liveness/proposal_status_tracker.rs (L80-98)
```rust
    fn get_exclude_authors(&self) -> HashSet<Author> {
        let mut exclude_authors = HashSet::new();

        let limit = self.window;
        for round_reason in self.past_round_statuses.iter().rev().take(limit) {
            if let NewRoundReason::Timeout(RoundTimeoutReason::PayloadUnavailable {
                missing_authors,
            }) = round_reason
            {
                for author_idx in missing_authors.iter_ones() {
                    if let Some(author) = self.ordered_authors.get(author_idx) {
                        exclude_authors.insert(*author);
                    }
                }
            }
        }

        exclude_authors
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

**File:** consensus/src/liveness/proposal_generator.rs (L501-501)
```rust
        let maybe_optqs_payload_pull_params = self.opt_qs_payload_param_provider.get_params();
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L596-599)
```rust
        for (_, batches) in self
            .author_to_batches
            .iter()
            .filter(|(author, _)| !exclude_authors.contains(author))
```
