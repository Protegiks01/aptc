# Audit Report

## Title
Byzantine Validators Can Spoof Timeout Reasons to Falsely Blame and Exclude Honest Validators from OptQS

## Summary
Byzantine validators can attach false timeout reasons to valid timeout signatures, allowing them to falsely blame honest validators for payload unavailability. This causes honest validators to be excluded from Optimistic Quorum Store (OptQS) proposals, degrading network performance and potentially impacting liveness.

## Finding Description

The vulnerability exists because timeout reasons in the AptosBFT consensus protocol are not cryptographically signed. When a validator broadcasts a timeout, only the `TwoChainTimeout` structure (epoch, round, hqc_round) is signed via the `TimeoutSigningRepr` format, not the attached `RoundTimeoutReason`. [1](#0-0) 

The signature verification in `RoundTimeout::verify()` only validates the signature against `timeout.signing_format()`, which excludes the reason field entirely. [2](#0-1) 

Byzantine validators can exploit this by creating valid timeout signatures for legitimate timeouts, then attaching false `RoundTimeoutReason::PayloadUnavailable { missing_authors }` with a bitvec falsely identifying honest validators as having missing payloads.

When timeout votes are aggregated, the system accepts timeout reasons with only f+1 voting power threshold (not the full 2f+1 quorum). The aggregation logic checks for f+1 support using `check_aggregated_voting_power` with `check_super_majority = false`. [3](#0-2) 

The f+1 threshold is calculated as `total_voting_power - quorum_voting_power + 1`: [4](#0-3) 

When processing timeout messages, the reason is stored without any validation against the node's local state or cryptographic verification: [5](#0-4) 

For `PayloadUnavailable` reasons, the aggregation logic accumulates which authors were reported missing by validators with f+1 voting power: [6](#0-5) 

This aggregated timeout reason flows into `NewRoundReason` when starting a new consensus round: [7](#0-6) 

The `RoundManager` pushes this reason to the `ExponentialWindowFailureTracker`: [8](#0-7) 

The tracker extracts the falsely accused validators from `PayloadUnavailable` timeout reasons and adds them to an exclusion list: [9](#0-8) 

These excluded validators are then filtered out during OptQS batch pulling, preventing their batches from being included in optimistic proposals: [10](#0-9) 

## Impact Explanation

This vulnerability falls under **Medium Severity** ($10,000) per the Aptos bug bounty criteria as it causes:

1. **Performance degradation**: Excluding honest validators from OptQS reduces the available batch pool, lowering transaction throughput and increasing proposal latency.

2. **State inconsistencies**: False metrics are recorded showing honest validators as having unavailable payloads, damaging their operational reputation and making network debugging difficult.

3. **Potential liveness impact**: If Byzantine validators coordinate to exclude enough honest validators simultaneously, proposal generation may be significantly delayed, especially during periods when OptQS is critical for performance.

The impact is appropriately categorized as Medium rather than High/Critical because:
- It does not break consensus safety properties (no double-spending or chain splits)
- It does not cause permanent state corruption requiring hard fork
- The exclusion is temporary and resets after consecutive successful rounds
- The system can still function through non-optimistic proposals, albeit with degraded performance
- It requires coordination among f+1 Byzantine validators

This aligns with the Medium severity category: "Limited protocol violations with state inconsistencies requiring manual intervention and temporary liveness issues."

## Likelihood Explanation

**Likelihood: Medium to High**

Attack requirements:
- Only f+1 Byzantine validators (by voting power) need to coordinate
- Under standard BFT assumptions (f < n/3), this is realistic and within the threat model
- No additional cryptographic resources or exploits required
- Attack can be executed during any timeout round without special conditions

The attack is particularly stealthy because:
- False timeout reasons appear as legitimate diagnostic information
- No cryptographic verification failures occur that would alert operators
- System metrics appear normal except for the false blame assignment
- The attack doesn't require persistent state manipulation

Byzantine validators have economic incentives to execute this attack:
- Degrade competitors' operational reputation
- Reduce other validators' transaction fee revenue by excluding them from OptQS
- Create artificial performance issues that may trigger manual intervention

The primary limitation is that Byzantine validators must coordinate to reach f+1 voting power, but this is a standard assumption in BFT systems and well within the threat model.

## Recommendation

**Short-term mitigation:**
Include the `RoundTimeoutReason` in the cryptographically signed portion of timeout messages. Modify `TimeoutSigningRepr` to include a hash of the reason, or create an extended signing format that includes the reason data.

**Recommended fix:**

1. Extend `TimeoutSigningRepr` to include the timeout reason:
   - Add a `reason_hash` field to `TimeoutSigningRepr` computed as the hash of the serialized `RoundTimeoutReason`
   - Update `TwoChainTimeout::signing_format()` to include this hash
   - Update `RoundTimeout::verify()` to check that the provided reason matches the signed hash

2. Add local validation of timeout reasons:
   - When receiving a `PayloadUnavailable` reason, cross-check the `missing_authors` bitvec against the node's local payload availability state
   - Reject timeout messages where the reason contradicts local observations by more than a configurable threshold

3. Implement Byzantine behavior detection:
   - Track validators that frequently report timeout reasons that contradict the majority view
   - Log warnings when f+1 validators report contradictory timeout reasons
   - Consider reputation tracking to identify validators submitting suspicious timeout reasons

## Proof of Concept

The following demonstrates the attack conceptually (full implementation would require consensus test framework):

```rust
// Byzantine validator creates a valid timeout signature
let timeout = TwoChainTimeout::new(epoch, round, quorum_cert);
let signature = byzantine_validator.sign(&timeout.signing_format())?;

// Attach false reason blaming honest validators
let mut false_missing_authors = BitVec::with_num_bits(num_validators);
false_missing_authors.set(honest_validator_index); // Falsely blame honest validator

let false_reason = RoundTimeoutReason::PayloadUnavailable {
    missing_authors: false_missing_authors,
};

// Broadcast the timeout with false reason
let round_timeout = RoundTimeout::new(
    timeout,
    byzantine_validator.author(),
    false_reason, // Not covered by signature!
    signature,
);

// If f+1 Byzantine validators coordinate to send the same false reason,
// it will be accepted as the aggregated timeout reason and honest validators
// will be excluded from OptQS proposals in subsequent rounds.
```

The attack succeeds because `RoundTimeout::verify()` only validates the signature against `timeout.signing_format()`, which does not include the `reason` field, allowing Byzantine validators to attach arbitrary false reasons to valid timeout signatures.

## Notes

This vulnerability represents a design flaw in the AptosBFT timeout mechanism where diagnostic information (timeout reasons) was not included in the signed message format. While the impact is limited to performance degradation rather than safety violations, it allows Byzantine validators to manipulate network performance and validator reputation within the boundaries of the BFT threat model. The fix requires a protocol-level change to include timeout reasons in the signed data structure.

### Citations

**File:** consensus/consensus-types/src/timeout_2chain.rs (L66-72)
```rust
    pub fn signing_format(&self) -> TimeoutSigningRepr {
        TimeoutSigningRepr {
            epoch: self.epoch(),
            round: self.round(),
            hqc_round: self.hqc_round(),
        }
    }
```

**File:** consensus/consensus-types/src/round_timeout.rs (L97-107)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        self.timeout.verify(validator)?;
        validator
            .verify(
                self.author(),
                &self.timeout.signing_format(),
                &self.signature,
            )
            .context("Failed to verify 2-chain timeout signature")?;
        Ok(())
    }
```

**File:** consensus/src/pending_votes.rs (L104-147)
```rust
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
```

**File:** consensus/src/pending_votes.rs (L227-232)
```rust
        two_chain_votes.add(
            round_timeout.author(),
            timeout.clone(),
            signature.clone(),
            round_timeout.reason().clone(),
        );
```

**File:** types/src/validator_verifier.rs (L462-480)
```rust
    pub fn check_aggregated_voting_power(
        &self,
        aggregated_voting_power: u128,
        check_super_majority: bool,
    ) -> std::result::Result<u128, VerifyError> {
        let target = if check_super_majority {
            self.quorum_voting_power
        } else {
            self.total_voting_power - self.quorum_voting_power + 1
        };

        if aggregated_voting_power < target {
            return Err(VerifyError::TooLittleVotingPower {
                voting_power: aggregated_voting_power,
                expected_voting_power: target,
            });
        }
        Ok(aggregated_voting_power)
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

**File:** consensus/src/round_manager.rs (L469-470)
```rust
        self.proposal_status_tracker
            .push(new_round_event.reason.clone());
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

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L596-600)
```rust
        for (_, batches) in self
            .author_to_batches
            .iter()
            .filter(|(author, _)| !exclude_authors.contains(author))
        {
```
