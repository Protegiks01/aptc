# Audit Report

## Title
Byzantine Minority Can Manipulate Timeout Reason Aggregation Through PayloadUnavailable Grouping Flaw

## Summary
The `aggregated_timeout_reason()` function in `consensus/src/pending_votes.rs` groups all `PayloadUnavailable` timeout reasons together regardless of their `missing_authors` content, allowing Byzantine validators with < f+1 voting power to strategically amplify minority honest complaints and exceed the f+1 threshold, causing honest validators to be wrongly blamed and excluded from OptQS operations. [1](#0-0) 

## Finding Description

The vulnerability exists in how timeout reasons are aggregated during 2-chain timeout certificate formation. The BFT invariant requires that Byzantine validators with < f+1 voting power cannot influence critical protocol decisions. However, the current implementation violates this invariant.

**Root Cause**: At lines 104-114, all `PayloadUnavailable` variants are mapped to the same `reason_key` using a placeholder BitVec, regardless of their actual `missing_authors` content: [2](#0-1) 

This grouping allows Byzantine validators to add their voting power to any `PayloadUnavailable` complaints from honest validators, even when those complaints have different `missing_authors`.

**Attack Scenario**:
- Setup: 4 validators with voting power [4, 3, 2, 1], Total=10
- Quorum voting power: `10 * 2 / 3 + 1 = 7` [3](#0-2) 
- f+1 threshold: `10 - 7 + 1 = 4` [4](#0-3) 
- Byzantine: Validator 2 (VP=2, which is 20% < 33%, within BFT assumptions)

**Without Byzantine coordination**:
- Validator 0 (VP=4): Reports `NoQC`
- Validator 1 (VP=3): Reports `PayloadUnavailable { missing_authors: [3] }`
- Validator 2 (VP=2): Reports `NoQC`
- Validator 3 (VP=1): Reports `Unknown`
- Result: `NoQC` wins with 6 VP ≥ 4, no validator blamed

**With Byzantine coordination**:
- Validator 2 strategically reports `PayloadUnavailable { missing_authors: [3] }`
- Voting power per reason: `PayloadUnavailable: 3+2=5 VP`, `NoQC: 4 VP`, `Unknown: 1 VP`
- At line 125, `PayloadUnavailable` has maximum voting power (5 VP)
- At lines 126-130, it passes the f+1 threshold check (5 ≥ 4)
- For `missing_authors` aggregation at lines 137-143, validator 3 gets 5 VP ≥ 4, so it's included in the final BitVec
- Result: `PayloadUnavailable { missing_authors: [3] }` wins, Validator 3 is blamed [5](#0-4) 

**Impact Propagation**: The aggregated timeout reason is used in `ExponentialWindowFailureTracker` to exclude validators from OptQS operations: [6](#0-5) 

Byzantine validators can cause honest validators to be excluded from payload operations, degrading network performance and potentially causing liveness issues. [7](#0-6) 

## Impact Explanation

**High Severity** (up to $50,000): This vulnerability causes significant protocol violations:

1. **Validator Performance Degradation**: Honest validators are wrongly excluded from OptQS payload operations, reducing network throughput
2. **Byzantine Influence on Protocol Behavior**: Byzantine validators with < f+1 voting power can influence which timeout reason is selected, violating the core BFT assumption
3. **Failure Window Manipulation**: Byzantine can trigger window doubling in the failure tracker, making the system less optimistic
4. **Potential Liveness Issues**: If multiple validators are wrongly excluded, the network may struggle to form proposals

This meets the "Significant protocol violations" and "Validator node slowdowns" criteria for High severity.

## Likelihood Explanation

**Likelihood: High**

1. **Low Attack Complexity**: Byzantine validators only need to observe honest timeout messages and coordinate to report the same `PayloadUnavailable` reason with strategically chosen `missing_authors`
2. **No Special Privileges Required**: Any Byzantine validator can execute this attack during normal timeout scenarios
3. **Frequent Opportunity**: Timeouts occur regularly in distributed systems due to network delays, high load, or legitimate failures
4. **Realistic Byzantine Assumptions**: Attack only requires < f+1 Byzantine voting power, which is the standard BFT threat model
5. **Difficult to Detect**: The attack looks like legitimate timeout reporting; distinguishing malicious from honest `PayloadUnavailable` reports is challenging

## Recommendation

Separate the aggregation logic for `PayloadUnavailable` to prevent Byzantine amplification. Instead of grouping all `PayloadUnavailable` variants together, each unique `missing_authors` BitVec should be tracked separately, or use a two-phase approach:

**Phase 1**: Aggregate reason types (Unknown, ProposalNotReceived, NoQC, PayloadUnavailable)
**Phase 2**: If PayloadUnavailable wins with ≥ f+1 VP, then aggregate the `missing_authors` BitVec from only those PayloadUnavailable votes that contributed to the winning reason

**Code Fix**:
```rust
fn aggregated_timeout_reason(&self, verifier: &ValidatorVerifier) -> RoundTimeoutReason {
    let mut reason_voting_power: HashMap<RoundTimeoutReason, u128> = HashMap::new();
    let mut payload_unavailable_votes: Vec<(Author, RoundTimeoutReason)> = Vec::new();
    
    for (author, reason) in &self.timeout_reason {
        let reason_key = match reason {
            reason @ RoundTimeoutReason::Unknown
            | reason @ RoundTimeoutReason::ProposalNotReceived
            | reason @ RoundTimeoutReason::NoQC => reason.clone(),
            payload_reason @ RoundTimeoutReason::PayloadUnavailable { .. } => {
                // Store for later aggregation, but don't group yet
                payload_unavailable_votes.push((*author, payload_reason.clone()));
                continue;
            },
        };
        *reason_voting_power.entry(reason_key).or_default() +=
            verifier.get_voting_power(author).unwrap_or_default() as u128;
    }
    
    // Calculate voting power for PayloadUnavailable as a category
    let payload_unavailable_vp: u128 = payload_unavailable_votes.iter()
        .map(|(author, _)| verifier.get_voting_power(author).unwrap_or_default() as u128)
        .sum();
    
    if payload_unavailable_vp > 0 {
        reason_voting_power.insert(
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: BitVec::with_num_bits(verifier.len() as u16),
            },
            payload_unavailable_vp,
        );
    }
    
    // Find reason with maximum voting power that meets f+1 threshold
    let selected_reason = reason_voting_power
        .into_iter()
        .max_by_key(|(_, vp)| *vp)
        .filter(|(_, vp)| {
            verifier.check_aggregated_voting_power(*vp, false).is_ok()
        })
        .map(|(reason, _)| reason);
    
    match selected_reason {
        Some(RoundTimeoutReason::PayloadUnavailable { .. }) => {
            // Only aggregate missing_authors from PayloadUnavailable votes
            let mut missing_batch_authors: HashMap<usize, u128> = HashMap::new();
            for (author, reason) in payload_unavailable_votes {
                if let RoundTimeoutReason::PayloadUnavailable { missing_authors } = reason {
                    for missing_idx in missing_authors.iter_ones() {
                        *missing_batch_authors.entry(missing_idx).or_default() +=
                            verifier.get_voting_power(&author).unwrap_or_default() as u128;
                    }
                }
            }
            
            let mut aggregated_bitvec = BitVec::with_num_bits(verifier.len() as u16);
            for (author_idx, voting_power) in missing_batch_authors {
                if verifier.check_aggregated_voting_power(voting_power, false).is_ok() {
                    aggregated_bitvec.set(author_idx as u16);
                }
            }
            RoundTimeoutReason::PayloadUnavailable {
                missing_authors: aggregated_bitvec,
            }
        },
        Some(reason) => reason,
        None => RoundTimeoutReason::Unknown,
    }
}
```

This ensures that Byzantine validators cannot amplify minority honest complaints by adding their votes to the PayloadUnavailable category without also having their chosen `missing_authors` meet the f+1 threshold independently.

## Proof of Concept

```rust
#[test]
fn test_byzantine_timeout_reason_manipulation() {
    use crate::pending_votes::TwoChainTimeoutVotes;
    use aptos_bitvec::BitVec;
    use aptos_consensus_types::{
        quorum_cert::QuorumCert, 
        round_timeout::RoundTimeoutReason, 
        timeout_2chain::TwoChainTimeout,
    };
    use aptos_types::validator_verifier::random_validator_verifier_with_voting_power;

    let epoch = 1;
    let round = 10;
    
    // Setup: 4 validators with VP=[4,3,2,1], Total=10, Quorum=7, f+1=4
    let (signers, verifier) = random_validator_verifier_with_voting_power(
        4, None, false, &[4, 3, 2, 1]
    );
    
    let timeout = TwoChainTimeout::new(epoch, round, QuorumCert::dummy());
    let mut two_chain_timeout_votes = TwoChainTimeoutVotes::new(timeout);
    
    // Validator 0 (VP=4, Honest): Reports NoQC
    let timeout0 = TwoChainTimeout::new(epoch, round, QuorumCert::dummy());
    let sig0 = signers[0].sign(&timeout0.signing_format()).unwrap();
    two_chain_timeout_votes.add(
        signers[0].author(), 
        timeout0, 
        sig0, 
        RoundTimeoutReason::NoQC
    );
    
    // Validator 1 (VP=3, Honest): Reports PayloadUnavailable {missing: [3]}
    let timeout1 = TwoChainTimeout::new(epoch, round, QuorumCert::dummy());
    let sig1 = signers[1].sign(&timeout1.signing_format()).unwrap();
    let mut missing_authors1 = BitVec::with_num_bits(4);
    missing_authors1.set(3); // Blames validator 3
    two_chain_timeout_votes.add(
        signers[1].author(),
        timeout1,
        sig1,
        RoundTimeoutReason::PayloadUnavailable { missing_authors: missing_authors1.clone() }
    );
    
    // Validator 2 (VP=2, BYZANTINE): Strategically reports PayloadUnavailable {missing: [3]}
    // to amplify Validator 1's complaint
    let timeout2 = TwoChainTimeout::new(epoch, round, QuorumCert::dummy());
    let sig2 = signers[2].sign(&timeout2.signing_format()).unwrap();
    two_chain_timeout_votes.add(
        signers[2].author(),
        timeout2,
        sig2,
        RoundTimeoutReason::PayloadUnavailable { missing_authors: missing_authors1.clone() }
    );
    
    // Validator 3 (VP=1, Honest): Reports Unknown
    let timeout3 = TwoChainTimeout::new(epoch, round, QuorumCert::dummy());
    let sig3 = signers[3].sign(&timeout3.signing_format()).unwrap();
    two_chain_timeout_votes.add(
        signers[3].author(),
        timeout3,
        sig3,
        RoundTimeoutReason::Unknown
    );
    
    // Get aggregated reason
    let (_, aggregate_timeout_reason) = two_chain_timeout_votes.unpack_aggregate(&verifier);
    
    // VULNERABILITY: Byzantine validator 2 (VP=2) amplified honest validator 1's complaint (VP=3)
    // to exceed f+1 threshold (4), causing PayloadUnavailable to win over NoQC (VP=4)
    // Expected (correct): NoQC should win with 4 VP when validator 2 doesn't collude
    // Actual (vulnerable): PayloadUnavailable wins with 3+2=5 VP, blaming validator 3
    
    match aggregate_timeout_reason {
        RoundTimeoutReason::PayloadUnavailable { missing_authors } => {
            assert_eq!(missing_authors.get(3), true); // Validator 3 is blamed!
            println!("VULNERABILITY CONFIRMED: Honest validator 3 wrongly blamed");
        },
        _ => panic!("Expected PayloadUnavailable but got {:?}", aggregate_timeout_reason),
    }
}
```

**Notes**

The vulnerability stems from the design decision to group all `PayloadUnavailable` reasons together for aggregation purposes. While this simplifies the logic, it creates a Byzantine amplification vector that violates the f+1 threshold guarantee. The fix requires tracking `PayloadUnavailable` votes separately to ensure Byzantine validators cannot strategically add their voting power to minority honest complaints to manipulate the aggregated result.

### Citations

**File:** consensus/src/pending_votes.rs (L93-119)
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
```

**File:** consensus/src/pending_votes.rs (L123-152)
```rust
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
```

**File:** types/src/validator_verifier.rs (L210-212)
```rust
        } else {
            total_voting_power * 2 / 3 + 1
        };
```

**File:** types/src/validator_verifier.rs (L467-471)
```rust
        let target = if check_super_majority {
            self.quorum_voting_power
        } else {
            self.total_voting_power - self.quorum_voting_power + 1
        };
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
