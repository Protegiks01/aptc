# Audit Report

## Title
Non-Deterministic Timeout Reason Aggregation Causes Validator State Divergence in Proposal Status Tracking

## Summary
Validators maintain divergent internal state in their `ExponentialWindowFailureTracker` due to race conditions in timeout reason aggregation. When round timeouts occur, different validators aggregate timeout reasons from different subsets of timeout votes based on network timing, leading to inconsistent recording of `NewRoundReason` values. This causes validators to have different window sizes and make conflicting optimistic/pessimistic quorum store decisions.

## Finding Description
The vulnerability exists in how timeout reasons are aggregated and propagated through the proposal status tracking system: [1](#0-0) 

When a round times out, each validator locally aggregates timeout reasons from the individual `RoundTimeout` messages they've received. The aggregated reason is determined by the reason with the most voting power (f+1 minimum) among the locally available votes. [2](#0-1) 

When transitioning to a new round, this locally-computed timeout reason becomes part of the `NewRoundReason` that gets pushed to the tracker. Critically, the timeout certificate itself does NOT include the aggregated reason: [3](#0-2) [4](#0-3) 

This means different validators can record different reasons for the same round timeout based on which timeout votes they received before processing the round transition. [5](#0-4) 

The tracker treats only `PayloadUnavailable` as a failure, while other timeout reasons are treated as successes. This divergence in recorded reasons causes:
1. Different `last_consecutive_success_count` values
2. Different `window` sizes (doubled on failure, reset on sustained success)
3. Different OptQS enabling decisions when validators become proposers [6](#0-5) 

When the `BoundedVecDeque` reaches capacity (max_window=100), different validators will evict different historical statuses: [7](#0-6) 

## Impact Explanation
This vulnerability constitutes a **Medium** severity "State inconsistency requiring intervention" per the Aptos bug bounty program:

1. **State Divergence**: Validators maintain inconsistent internal consensus state, violating the expectation that honest validators behave identically given identical inputs.

2. **Liveness Impact**: Divergent window sizes cause validators to make different OptQS decisions (excluding different authors' batches), potentially degrading network throughput when optimistic proposals fail due to missing batches.

3. **Diagnostic Difficulty**: Operators cannot easily detect or diagnose why validators exhibit different proposal generation behavior, as the tracker state is not externally visible.

4. **No Consensus Safety Violation**: This does NOT cause chain splits, double-spending, or fund loss, as validators still vote on actual proposal content and execute deterministically.

## Likelihood Explanation
This issue occurs **naturally and frequently** without any attacker involvement:

1. **Network Variability**: Normal network delays cause validators to receive timeout votes at different times
2. **Concurrent Round Transitions**: When validators transition rounds based on timeout certificates, they aggregate whatever timeout votes they've received up to that point
3. **Threshold Effects**: When timeout reasons are close in voting power (e.g., 2 vs 2 for f+1=2), timing determines which reason exceeds the threshold first
4. **Cumulative Divergence**: Once divergence occurs, it compounds over subsequent rounds as the BoundedVecDeque evolves differently

The likelihood is HIGH in production networks with realistic network latency and under stress conditions where timeouts are frequent.

## Recommendation
To fix this vulnerability, the aggregated timeout reason must be made deterministic across all validators. Two approaches:

**Option 1: Include Timeout Reason in Timeout Certificate**
Modify `TwoChainTimeoutCertificate` to include the aggregated timeout reason as part of the certified data. This requires:
1. Computing an aggregated reason during TC formation
2. Including it in the TC structure
3. Verifying it during TC validation

**Option 2: Deterministic Local Computation**
Ensure all validators compute the same aggregated reason by:
1. Only aggregating timeout reasons from the specific validators whose signatures are in the TC
2. Using a deterministic tie-breaking rule (e.g., lexicographic ordering) when multiple reasons have equal voting power
3. Requiring f+1 strict majority rather than just meeting the threshold

**Recommended Fix (Option 2 - simpler):**

In `consensus/src/pending_votes.rs`, modify the `aggregated_timeout_reason` method to use deterministic ordering:

```rust
fn aggregated_timeout_reason(&self, verifier: &ValidatorVerifier) -> RoundTimeoutReason {
    // ... existing code ...
    
    reason_voting_power
        .into_iter()
        .filter(|(_, voting_power)| {
            verifier.check_aggregated_voting_power(*voting_power, false).is_ok()
        })
        .max_by(|(reason_a, vp_a), (reason_b, vp_b)| {
            // Deterministic ordering: first by voting power, then by variant discriminant
            vp_a.cmp(vp_b).then_with(|| {
                std::mem::discriminant(reason_a).cmp(&std::mem::discriminant(reason_b))
            })
        })
        .map(|(reason, _)| {
            // ... existing PayloadUnavailable handling ...
        })
        .unwrap_or(RoundTimeoutReason::Unknown)
}
```

## Proof of Concept

```rust
#[test]
fn test_divergent_timeout_reason_aggregation() {
    use aptos_types::validator_verifier::random_validator_verifier;
    use aptos_bitvec::BitVec;
    
    let (signers, verifier) = random_validator_verifier(4, None, false);
    
    // Scenario: Round 10 timeout with 4 validators (f=1, need 2f+1=3 for quorum)
    // V0, V1 send ProposalNotReceived
    // V2, V3 send PayloadUnavailable
    
    // Validator A's view: receives votes from V0, V1, V2 first
    let mut tracker_a = ExponentialWindowFailureTracker::new(
        100, 
        verifier.get_ordered_account_addresses()
    );
    let mut votes_a = TwoChainTimeoutVotes::new(/* ... */);
    votes_a.add(v0, timeout, sig_v0, RoundTimeoutReason::ProposalNotReceived);
    votes_a.add(v1, timeout, sig_v1, RoundTimeoutReason::ProposalNotReceived);
    votes_a.add(v2, timeout, sig_v2, RoundTimeoutReason::PayloadUnavailable { 
        missing_authors: BitVec::with_num_bits(4) 
    });
    let (_, reason_a) = votes_a.unpack_aggregate(&verifier);
    // reason_a = ProposalNotReceived (voting power 2 > 1)
    tracker_a.push(NewRoundReason::Timeout(reason_a));
    assert_eq!(tracker_a.window, 2); // No window increase
    
    // Validator B's view: receives votes from V0, V2, V3 first  
    let mut tracker_b = ExponentialWindowFailureTracker::new(
        100,
        verifier.get_ordered_account_addresses()
    );
    let mut votes_b = TwoChainTimeoutVotes::new(/* ... */);
    votes_b.add(v0, timeout, sig_v0, RoundTimeoutReason::ProposalNotReceived);
    votes_b.add(v2, timeout, sig_v2, RoundTimeoutReason::PayloadUnavailable { 
        missing_authors: BitVec::with_num_bits(4) 
    });
    votes_b.add(v3, timeout, sig_v3, RoundTimeoutReason::PayloadUnavailable { 
        missing_authors: BitVec::with_num_bits(4) 
    });
    let (_, reason_b) = votes_b.unpack_aggregate(&verifier);
    // reason_b = PayloadUnavailable (voting power 2 > 1)
    tracker_b.push(NewRoundReason::Timeout(reason_b));
    assert_eq!(tracker_b.window, 4); // Window doubled!
    
    // Validators now have divergent state
    assert_ne!(tracker_a.window, tracker_b.window);
    assert_ne!(tracker_a.last_consecutive_success_count, 
               tracker_b.last_consecutive_success_count);
}
```

## Notes
This vulnerability demonstrates a subtle but important protocol design issue where local state that should be deterministic across validators becomes non-deterministic due to network timing. While it does not directly compromise consensus safety or cause fund loss, it violates the principle of deterministic validator behavior and can lead to performance degradation and operational complexity. The fix requires ensuring that all validators either agree on the timeout reason through the timeout certificate, or use a deterministic algorithm to compute it from the same inputs.

### Citations

**File:** consensus/src/pending_votes.rs (L93-153)
```rust
    fn aggregated_timeout_reason(&self, verifier: &ValidatorVerifier) -> RoundTimeoutReason {
        let mut reason_voting_power: HashMap<RoundTimeoutReason, u128> = HashMap::new();
        let mut missing_batch_authors: HashMap<usize, u128> = HashMap::new();
        // let ordered_authors = verifier.get_ordered_account_addresses();
        for (author, reason) in &self.timeout_reason {
            // To aggregate the reason, we only care about the variant type itself and
            // exclude any data within the variants.
            let reason_key = match reason {
                reason @ RoundTimeoutReason::Unknown
                | reason @ RoundTimeoutReason::ProposalNotReceived
                | reason @ RoundTimeoutReason::NoQC => reason.clone(),
                RoundTimeoutReason::PayloadUnavailable { missing_authors } => {
                    for missing_idx in missing_authors.iter_ones() {
                        *missing_batch_authors.entry(missing_idx).or_default() +=
                            verifier.get_voting_power(author).unwrap_or_default() as u128;
                    }
                    RoundTimeoutReason::PayloadUnavailable {
                        // Since we care only about the variant type, we replace the bitvec
                        // with a placeholder.
                        missing_authors: BitVec::with_num_bits(verifier.len() as u16),
                    }
                },
            };
            *reason_voting_power.entry(reason_key).or_default() +=
                verifier.get_voting_power(author).unwrap_or_default() as u128;
        }
        // The aggregated timeout reason is the reason with the most voting power received from
        // at least f+1 peers by voting power. If such voting power does not exist, then the
        // reason is unknown.

        reason_voting_power
            .into_iter()
            .max_by_key(|(_, voting_power)| *voting_power)
            .filter(|(_, voting_power)| {
                verifier
                    .check_aggregated_voting_power(*voting_power, false)
                    .is_ok()
            })
            .map(|(reason, _)| {
                // If the aggregated reason is due to unavailable payload, we will compute the
                // aggregated missing authors bitvec counting batch authors that have been reported
                // missing by minority peers.
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
                } else {
                    reason
                }
            })
            .unwrap_or(RoundTimeoutReason::Unknown)
    }
```

**File:** consensus/src/liveness/round_state.rs (L264-276)
```rust
            let (prev_round_timeout_votes, prev_round_timeout_reason) = prev_round_timeout_votes
                .map(|votes| votes.unpack_aggregate(verifier))
                .unzip();

            // The new round reason is QCReady in case both QC.round + 1 == new_round, otherwise
            // it's Timeout and TC.round + 1 == new_round.
            let new_round_reason = if sync_info.highest_certified_round() + 1 == new_round {
                NewRoundReason::QCReady
            } else {
                let prev_round_timeout_reason =
                    prev_round_timeout_reason.unwrap_or(RoundTimeoutReason::Unknown);
                NewRoundReason::Timeout(prev_round_timeout_reason)
            };
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L109-112)
```rust
pub struct TwoChainTimeoutCertificate {
    timeout: TwoChainTimeout,
    signatures_with_rounds: AggregateSignatureWithRounds,
}
```

**File:** consensus/consensus-types/src/sync_info.rs (L14-25)
```rust
#[derive(Deserialize, Serialize, Clone, Eq, PartialEq)]
/// This struct describes basic synchronization metadata.
pub struct SyncInfo {
    /// Highest quorum certificate known to the peer.
    highest_quorum_cert: QuorumCert,
    /// Highest ordered cert known to the peer.
    highest_ordered_cert: Option<WrappedLedgerInfo>,
    /// Highest commit cert (ordered cert with execution result) known to the peer.
    highest_commit_cert: WrappedLedgerInfo,
    /// Optional highest timeout certificate if available.
    highest_2chain_timeout_cert: Option<TwoChainTimeoutCertificate>,
}
```

**File:** consensus/src/liveness/proposal_status_tracker.rs (L49-78)
```rust
    pub(crate) fn push(&mut self, status: NewRoundReason) {
        self.past_round_statuses.push_back(status);
        self.compute_failure_window();
    }

    fn last_consecutive_statuses_matching<F>(&self, matcher: F) -> usize
    where
        F: Fn(&NewRoundReason) -> bool,
    {
        self.past_round_statuses
            .iter()
            .rev()
            .take_while(|reason| matcher(reason))
            .count()
    }

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

**File:** crates/aptos-collections/src/bounded_vec_deque.rs (L28-38)
```rust
    pub fn push_back(&mut self, item: T) -> Option<T> {
        let oldest = if self.is_full() {
            self.inner.pop_front()
        } else {
            None
        };

        self.inner.push_back(item);
        assert!(self.inner.len() <= self.capacity);
        oldest
    }
```
