# Audit Report

## Title
Off-by-One Window Boundary Error Allows Recently-Failed Validators to Participate in OptQS Without Exclusion

## Summary
The `get_exclude_authors()` function in `ExponentialWindowFailureTracker` fails to exclude validators who recently caused `PayloadUnavailable` failures when OptQS is re-enabled. This occurs because the exclusion lookup window examines exactly the last `window` rounds, but OptQS is re-enabled after exactly `window` consecutive successes, placing the triggering failure outside the lookup window by one round.

## Finding Description
The OptQS (Optimistic Quorum Store) mechanism uses an exponential window algorithm to decide when to enable optimistic batch pulling and which validators to exclude based on recent payload availability failures. [1](#0-0) 

When a `PayloadUnavailable` timeout occurs, the window size doubles. [2](#0-1) 

OptQS is re-enabled when `last_consecutive_success_count >= window`, meaning at least `window` consecutive non-PayloadUnavailable rounds have occurred. [3](#0-2) 

However, `get_exclude_authors()` only examines the last `window` entries in `past_round_statuses`: [4](#0-3) 

**The Vulnerability:**
After a `PayloadUnavailable` failure at round N:
1. Window doubles (e.g., from 2 to 4)
2. Exactly 4 consecutive successful rounds occur (N+1, N+2, N+3, N+4)
3. OptQS is re-enabled at round N+4 (since `last_consecutive_success_count = 4 >= window = 4`)
4. `get_exclude_authors()` examines rounds N+1 through N+4 (the last 4 rounds)
5. The `PayloadUnavailable` failure at round N is NOT examined (it's the 5th round back)
6. The failing validator is NOT excluded from the returned `OptQSPayloadPullParams`

This empty `exclude_authors` set is then used by the proof manager to pull batches: [5](#0-4) 

The batch queue uses `exclude_authors` to filter out unreliable validators: [6](#0-5) 

**Impact:** If the failing validator is still unreliable (network issues, malicious behavior, resource constraints), their batches will be included in the next OptQS proposal, potentially causing an immediate subsequent `PayloadUnavailable` failure and degrading consensus liveness.

## Impact Explanation
This vulnerability falls under **Medium Severity** per the Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Repeated OptQS failures cause the exponential window to grow repeatedly, potentially disabling OptQS entirely or requiring manual intervention
- **Consensus liveness degradation**: Unreliable validators causing repeated payload unavailability lead to round timeouts, slowing block production and reducing network throughput
- **Not Critical/High**: Does not cause consensus safety violations, fund loss, or complete network halt, as the system has fallback mechanisms (OptQS gets disabled, regular consensus continues)

## Likelihood Explanation
**Likelihood: Medium to High**

This issue will occur in production environments because:
1. **Transient network issues are common**: Validators may experience temporary network partitions, bandwidth limitations, or DDoS attacks that cause their batches to be unavailable
2. **Automatic re-enablement**: OptQS automatically re-enables after the exact window size of successes, triggering the off-by-one boundary condition
3. **No manual intervention required**: The vulnerability is triggered automatically by the state machine logic
4. **Persistent unreliability**: Validators with ongoing but intermittent issues (slow storage, unstable network) will repeatedly trigger this pattern

The vulnerability requires no attacker action—it naturally occurs when validators have transient reliability issues.

## Recommendation
Modify `get_exclude_authors()` to examine `window + 1` rounds instead of exactly `window` rounds when collecting failures. This ensures that the failure which triggered the window growth is included in the exclusion calculation:

```rust
fn get_exclude_authors(&self) -> HashSet<Author> {
    let mut exclude_authors = HashSet::new();
    
    // Look at window + 1 rounds to include the failure that triggered window growth
    let limit = (self.window + 1).min(self.past_round_statuses.len());
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

Alternative fix: Only re-enable OptQS when `last_consecutive_success_count > window` (strict inequality) instead of `>=`, ensuring at least one extra success round where failures are truly outside the window.

## Proof of Concept
```rust
#[cfg(test)]
mod vulnerability_test {
    use super::*;
    use crate::liveness::round_state::NewRoundReason;
    use aptos_bitvec::BitVec;
    use aptos_consensus_types::round_timeout::RoundTimeoutReason;
    use aptos_types::validator_verifier::random_validator_verifier;

    #[test]
    fn test_exclude_authors_off_by_one_vulnerability() {
        let (_signers, verifier) = random_validator_verifier(4, None, false);
        let mut tracker = ExponentialWindowFailureTracker::new(
            100, 
            verifier.get_ordered_account_addresses()
        );
        
        // Initial successful rounds
        tracker.push(NewRoundReason::QCReady);
        tracker.push(NewRoundReason::QCReady);
        assert_eq!(tracker.window, 2);
        
        // Validator 0 causes PayloadUnavailable failure
        let mut missing_authors = BitVec::with_num_bits(4);
        missing_authors.set(0); // Validator at index 0 is missing
        tracker.push(NewRoundReason::Timeout(
            RoundTimeoutReason::PayloadUnavailable { missing_authors }
        ));
        assert_eq!(tracker.window, 4); // Window doubled
        assert_eq!(tracker.last_consecutive_success_count, 0);
        
        // Exactly 4 consecutive successes
        for _ in 0..4 {
            tracker.push(NewRoundReason::QCReady);
        }
        assert_eq!(tracker.last_consecutive_success_count, 4);
        
        // BUG: get_exclude_authors() should exclude validator 0, but returns empty!
        let exclude_authors = tracker.get_exclude_authors();
        
        // Expected: validator 0 should be excluded (they just failed 4 rounds ago)
        // Actual: exclude_authors is EMPTY because the failure is outside the window
        assert!(
            !exclude_authors.is_empty(),
            "VULNERABILITY: Validator who caused PayloadUnavailable 4 rounds ago is not excluded!"
        );
        
        // This assertion will FAIL, demonstrating the vulnerability
        assert!(exclude_authors.contains(&verifier.get_ordered_account_addresses()[0]));
    }
}
```

This test will fail, confirming that validators who recently caused `PayloadUnavailable` failures are not excluded when OptQS is re-enabled, allowing them to potentially cause immediate subsequent failures.

## Notes
The root cause is a semantic mismatch between two uses of the `window` parameter:
1. **Re-enablement threshold**: "Wait for `window` consecutive successes before trying OptQS again"
2. **Exclusion lookback**: "Look back `window` rounds to find validators to exclude"

These two meanings are incompatible when the re-enablement condition is met with equality (`last_consecutive_success_count == window`), as the failure that caused the window growth is then exactly one round outside the exclusion lookback window.

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

**File:** consensus/src/liveness/proposal_status_tracker.rs (L128-160)
```rust
    fn get_params(&self) -> Option<OptQSPayloadPullParams> {
        if !self.enable_opt_qs {
            return None;
        }

        let tracker = self.failure_tracker.lock();

        counters::OPTQS_LAST_CONSECUTIVE_SUCCESS_COUNT
            .observe(tracker.last_consecutive_success_count as f64);
        if tracker.last_consecutive_success_count < tracker.window {
            warn!(
                "Skipping OptQS: (last_consecutive_successes) {} < {} (window)",
                tracker.last_consecutive_success_count, tracker.window
            );
            return None;
        }

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
        Some(OptQSPayloadPullParams {
            exclude_authors,
            minimum_batch_age_usecs: self.minimum_batch_age_usecs,
        })
    }
```

**File:** consensus/src/quorum_store/proof_manager.rs (L131-148)
```rust
            if let Some(ref params) = request.maybe_optqs_payload_pull_params {
                let max_opt_batch_txns_size = request.max_txns - txns_with_proof_size;
                let max_opt_batch_txns_after_filtering = request.max_txns_after_filtering - cur_unique_txns;
                let (opt_batches, opt_payload_size, _) =
                    self.batch_proof_queue.pull_batches(
                        &excluded_batches
                            .iter()
                            .cloned()
                            .chain(proof_block.iter().map(|proof| proof.info().clone()))
                            .collect(),
                        &params.exclude_authors,
                        max_opt_batch_txns_size,
                        max_opt_batch_txns_after_filtering,
                        request.soft_max_txns_after_filtering,
                        request.return_non_full,
                        request.block_timestamp,
                        Some(params.minimum_batch_age_usecs),
                    );
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L596-600)
```rust
        for (_, batches) in self
            .author_to_batches
            .iter()
            .filter(|(author, _)| !exclude_authors.contains(author))
        {
```
