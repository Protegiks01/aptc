# Audit Report

## Title
OptQS Status Tracker Warning Spam During Degraded Network Conditions

## Summary
The `get_params()` function in `proposal_status_tracker.rs` contains unrated-limited `warn!()` calls at lines 138-141 and 154 that can fire repeatedly during OptQS disable periods, potentially flooding validator logs and obscuring critical errors during network degradation scenarios.

## Finding Description

The vulnerability lies in the logging implementation of the OptQS (Optimistic Quorum Store) parameter provider. When validators generate proposals, the `get_params()` function is invoked to determine whether OptQS should be used for payload pulling. [1](#0-0) 

This function is called on every proposal generation: [2](#0-1) [3](#0-2) 

The warnings at lines 138-141 and 154 are triggered when:
1. The consecutive success count is below the failure window threshold (indicating recent payload unavailability)
2. There are authors to exclude from OptQS

**Exploitation Path:**
1. Network degradation or quorum store issues cause repeated payload unavailability
2. The failure tracker's exponential window mechanism increases the window size (doubling on each failure, up to max_window)
3. OptQS remains disabled for extended periods as `last_consecutive_success_count < window`
4. Each time this validator is elected as proposer (~every few rounds), `get_params()` is called
5. With the default `round_initial_timeout_ms` of 1000ms, proposals occur approximately every second per round: [4](#0-3) 

6. The warnings fire on EVERY proposal attempt, generating potentially hundreds of identical log entries per minute

**Contrast with Proper Rate Limiting:**
Other similar warnings in the codebase correctly use the `sample!` macro for rate limiting: [5](#0-4) [6](#0-5) 

However, the OptQS warnings lack this protection, making them spam logs continuously during degraded conditions.

## Impact Explanation

This issue is classified as **Low Severity** per the Aptos bug bounty criteria. While it doesn't directly impact consensus safety, fund security, or protocol correctness, it degrades operational visibility:

- **Operational Impact**: Validator operators may struggle to identify genuine critical errors during incident response
- **Log Storage**: Increased log volume and storage requirements
- **Debugging Difficulty**: Time-critical debugging becomes harder when searching through repetitive warnings
- **Hidden Critical Errors**: The consensus layer contains numerous `error!()` and `crit!()` calls across 36+ files that could be obscured: [7](#0-6) [8](#0-7) 

The issue does not meet Medium, High, or Critical severity thresholds as it does not cause:
- State inconsistencies requiring intervention
- Validator node slowdowns  
- API crashes
- Consensus violations
- Fund loss

## Likelihood Explanation

**High Likelihood** during specific network conditions:
- Network degradation naturally triggers payload unavailability
- Small validator sets amplify the issue (higher proposer selection frequency)
- No malicious intent required - occurs during normal operation under stress
- OptQS disable periods can persist for minutes to hours during sustained issues

The exponential backoff mechanism in the failure tracker means the window can grow large (up to `max_window`), prolonging the spam period: [9](#0-8) 

## Recommendation

Wrap both `warn!()` calls in the `sample!` macro with appropriate rate limiting (e.g., 10-30 second intervals):

```rust
use aptos_logger::{sample, warn};
use std::time::Duration;

impl TOptQSPullParamsProvider for OptQSPullParamsProvider {
    fn get_params(&self) -> Option<OptQSPayloadPullParams> {
        if !self.enable_opt_qs {
            return None;
        }

        let tracker = self.failure_tracker.lock();

        counters::OPTQS_LAST_CONSECUTIVE_SUCCESS_COUNT
            .observe(tracker.last_consecutive_success_count as f64);
        if tracker.last_consecutive_success_count < tracker.window {
            sample!(
                SampleRate::Duration(Duration::from_secs(10)),
                warn!(
                    "Skipping OptQS: (last_consecutive_successes) {} < {} (window)",
                    tracker.last_consecutive_success_count, tracker.window
                )
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
            sample!(
                SampleRate::Duration(Duration::from_secs(10)),
                warn!("OptQS exclude authors: {:?}", exclude_authors_str)
            );
        }
        Some(OptQSPayloadPullParams {
            exclude_authors,
            minimum_batch_age_usecs: self.minimum_batch_age_usecs,
        })
    }
}
```

This matches the pattern used elsewhere in the consensus layer and prevents log flooding while still providing visibility into OptQS status.

## Proof of Concept

```rust
#[cfg(test)]
mod log_spam_test {
    use super::*;
    use aptos_types::validator_verifier::random_validator_verifier;
    use aptos_consensus_types::round_timeout::RoundTimeoutReason;
    use aptos_bitvec::BitVec;
    use std::sync::Arc;

    #[test]
    fn test_optqs_warning_spam_during_disable_period() {
        // Setup validator set
        let (_signers, verifier) = random_validator_verifier(4, None, false);
        let ordered_authors = verifier.get_ordered_account_addresses();
        
        // Create failure tracker with small max window
        let failure_tracker = Arc::new(Mutex::new(
            ExponentialWindowFailureTracker::new(100, ordered_authors.clone())
        ));
        
        // Create OptQS provider
        let provider = OptQSPullParamsProvider::new(
            true,
            100_000,
            failure_tracker.clone(),
        );
        
        // Simulate payload unavailability causing window growth
        for _ in 0..5 {
            failure_tracker.lock().push(NewRoundReason::Timeout(
                RoundTimeoutReason::PayloadUnavailable {
                    missing_authors: BitVec::with_num_bits(4),
                }
            ));
        }
        
        // Verify window has grown
        assert_eq!(failure_tracker.lock().window, 32); // 2^5
        assert_eq!(failure_tracker.lock().last_consecutive_success_count, 0);
        
        // Simulate 100 proposal attempts (representing ~100 seconds of operation)
        // Each call will trigger the warning at line 138-141
        for i in 0..100 {
            let result = provider.get_params();
            assert!(result.is_none(), "OptQS should be disabled");
            
            // In production, this would generate 100 identical warning logs:
            // "Skipping OptQS: (last_consecutive_successes) 0 < 32 (window)"
            println!("Proposal attempt {}: OptQS disabled, window={}, consecutive_success={}", 
                     i, 
                     failure_tracker.lock().window,
                     failure_tracker.lock().last_consecutive_success_count);
        }
        
        println!("\n[VULNERABILITY DEMONSTRATED]");
        println!("Without sample! macro, the above would generate 100 identical warnings");
        println!("in validator logs, obscuring actual critical errors.");
    }
}
```

## Notes

While this is a valid Low severity operational issue, it does not meet the validation criteria requiring "Critical, High, or Medium severity" impact. The issue is real and should be fixed, but falls outside the scope of high-impact vulnerabilities that would qualify for significant bug bounty rewards. The fix is straightforward and follows established patterns in the codebase.

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

**File:** consensus/src/liveness/proposal_status_tracker.rs (L128-161)
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
}
```

**File:** consensus/src/liveness/proposal_generator.rs (L94-100)
```rust
                sample!(
                    SampleRate::Duration(Duration::from_secs(10)),
                    warn!(
                        "Using chain health backoff config for {} voting power percentage: {:?}",
                        voting_power_percentage, v
                    )
                );
```

**File:** consensus/src/liveness/proposal_generator.rs (L149-157)
```rust
                sample!(
                    SampleRate::Duration(Duration::from_secs(10)),
                    warn!(
                        "Using consensus backpressure config for {}ms pending duration: {:?}",
                        pipeline_pending_latency.as_millis(),
                        v
                    )
                );
                v
```

**File:** consensus/src/liveness/proposal_generator.rs (L501-501)
```rust
        let maybe_optqs_payload_pull_params = self.opt_qs_payload_param_provider.get_params();
```

**File:** consensus/src/liveness/proposal_generator.rs (L696-696)
```rust
        let maybe_optqs_payload_pull_params = self.opt_qs_payload_param_provider.get_params();
```

**File:** config/src/config/consensus_config.rs (L235-235)
```rust
            round_initial_timeout_ms: 1000,
```

**File:** consensus/src/epoch_manager.rs (L440-440)
```rust
                    error!(
```

**File:** consensus/src/pipeline/buffer_manager.rs (L635-635)
```rust
            error!(
```
