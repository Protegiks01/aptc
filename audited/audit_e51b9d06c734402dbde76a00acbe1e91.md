# Audit Report

## Title
OptQuorumStore Denial-of-Service via All-Authors-Excluded Attack

## Summary
A Byzantine proposer can disable OptQuorumStore optimization by crafting proposals with unavailable batches from all validators, causing all authors to be excluded from future optimistic proposals and forcing consensus to fall back to slower regular proposals for an exponentially growing window of rounds.

## Finding Description

The vulnerability exists in the OptQuorumStore (OptQS) consensus optimization layer through a chain of insufficient validation and missing sanity checks.

**Weak Batch Validation:** When an OptQuorumStore proposal is verified, only author validity is checked, not whether batch digests actually exist or are available. [1](#0-0)  This allows a Byzantine proposer to include batch infos with valid author addresses but fake or non-existent digests that will pass the verification step.

**Missing Batch Detection:** When honest validators receive such a proposal, they check payload availability by verifying locally available batches. [2](#0-1)  For each missing batch, the validator sets the corresponding author's bit in the `missing_authors` BitVec. If the proposal references unavailable batches from all validators, all bits get set.

**Timeout Reason Aggregation:** When validators timeout due to payload unavailability, their timeout reasons are aggregated. [3](#0-2)  For each author index, if f+1 voting power reports that author as missing, that bit is set in the aggregated BitVec, resulting in all bits being set when all validators' batches are unavailable.

**Failure Tracking and Author Exclusion:** The aggregated timeout reason is pushed to the ExponentialWindowFailureTracker. [4](#0-3)  When generating the next OptQS proposal, the system extracts excluded authors from recent timeout reasons. [5](#0-4)  If all validators were marked as missing, all are added to `exclude_authors`.

**No Sanity Check:** The OptQS parameter provider returns parameters with all authors excluded without any validation or upper bound checking. [6](#0-5)  This allows the pathological case where the entire validator set is excluded.

**Complete Batch Exclusion:** When pulling batches for the next OptQS proposal, the batch proof queue filters out all authors in the exclude set. [7](#0-6)  With all authors excluded, no opt_batches are pulled, effectively disabling the OptQS optimization.

**Attack Execution:**
1. Byzantine validator becomes proposer through normal rotation
2. Crafts OptQS proposal with batch infos having valid author addresses but fake digests
3. Proposal passes verification (only author validity checked via signature verification) [8](#0-7) 
4. Honest validators cannot find batches and timeout with all authors marked as missing
5. If f+1 validators report this, aggregated timeout has all bits set
6. OptQS disabled for exponential failure window (doubling each failure up to `max_window`) [9](#0-8) 
7. Consensus falls back to slower regular proposals for potentially hundreds of rounds

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria for "Validator node slowdowns."

**Severity Justification:**
- **Significant Performance Degradation:** OptQS optimization is designed to improve consensus throughput. Disabling it forces fallback to slower regular proposals, significantly degrading network performance
- **Exponential Impact Window:** The failure window doubles with each failure (up to `max_window`), potentially lasting hundreds of rounds before recovery
- **Network-Wide Effect:** All validators are simultaneously affected, impacting the entire network's consensus throughput
- **Repeatable Attack:** A Byzantine proposer can re-trigger the attack each time they become proposer, maintaining degraded performance
- **No Validator Collusion Required:** Single Byzantine validator sufficient when they become proposer

**Not Critical Because:**
- Does not cause fund loss or theft
- Does not violate consensus safety (no double-spending or chain splits)
- Regular (non-optimistic) proposals can still proceed
- Network eventually recovers when failure window expires
- Does not require hard fork to resolve

## Likelihood Explanation

**Likelihood: Medium to High**

This attack is realistic and feasible:

**Low Attack Barriers:**
- Only requires single Byzantine validator to become proposer (normal rotation ensures this happens periodically)
- No validator collusion needed
- No special network position or insider access required
- Attack can be repeated each time Byzantine validator becomes proposer

**Weak Protocol Defenses:**
- Batch existence never verified during proposal validation
- Only author validity checked, not digest authenticity
- No protection against referencing non-existent batches
- No sanity check prevents excluding all authors
- No upper bound on excluded author set size
- No automatic recovery mechanism when OptQS becomes unusable

**Natural Occurrence Possible:**
- Could occur naturally during network partitions or high latency
- May happen if batches don't propagate quickly enough
- Makes malicious attack indistinguishable from network issues

## Recommendation

**Immediate Fixes:**

1. **Add Sanity Check for Excluded Authors:**
   - In `OptQSPullParamsProvider::get_params()`, check if `exclude_authors` contains more than a threshold (e.g., > 50% of validators)
   - If threshold exceeded, return `None` to disable OptQS temporarily rather than excluding all authors
   - Add metric to track when this occurs

2. **Strengthen Batch Validation:**
   - In `verify_opt_batches()`, add optional batch existence checking when the validator has batch_reader access
   - Consider adding age checks or propagation time requirements for opt_batches
   - Implement reputation system to track authors with frequently unavailable batches

3. **Add Recovery Mechanism:**
   - Implement automatic reset of exclude_authors after a certain number of successful rounds
   - Consider decay function for author exclusions rather than complete exclusion
   - Add circuit breaker that forces regular proposals if exclusion set grows too large

4. **Enhanced Monitoring:**
   - Add alerts when exclude_authors exceeds threshold
   - Track metrics for OptQS disable events
   - Monitor for repeated patterns indicating potential attack

## Proof of Concept

```rust
// Conceptual PoC - demonstrating the attack flow
// In practice, would require Byzantine proposer node

// Step 1: Byzantine proposer crafts malicious OptBlockData
let mut fake_opt_batches = Vec::new();
for validator in validator_set.iter() {
    let fake_batch_info = BatchInfo::new(
        validator.author(),
        HashValue::random(), // Fake digest that doesn't exist
        epoch,
        expiration,
        0, // num_txns
        0, // num_bytes
    );
    fake_opt_batches.push(fake_batch_info);
}

let malicious_payload = Payload::OptQuorumStore(
    OptQuorumStorePayload::V1(OptQuorumStorePayloadV1 {
        opt_batches: fake_opt_batches,
        // ... other fields
    })
);

// Step 2: Create and sign proposal
let opt_block_data = OptBlockData::new(
    vec![], // validator_txns
    malicious_payload,
    proposer_author,
    epoch,
    round,
    timestamp,
    parent_block_info,
    grandparent_qc,
);

// Step 3: Proposal passes verify() because only authors checked
// verify_opt_batches() only validates author addresses are in validator set
// Does NOT check if batch digests exist or are available

// Step 4: Honest validators call check_payload_availability()
// All batches fail exists() check -> all bits set in missing_authors

// Step 5: Validators timeout with PayloadUnavailable { missing_authors: <all bits set> }

// Step 6: After aggregation and failure tracking:
// - ExponentialWindowFailureTracker records failure
// - get_exclude_authors() returns all validators
// - Next OptQS proposal has empty opt_batches
// - OptQS disabled for exponential window
```

## Notes

This vulnerability demonstrates a critical gap in OptQuorumStore's trust assumptions. The optimization assumes proposers will only include reasonably available batches, but provides no enforcement mechanism. The exponential backoff intended to handle transient availability issues becomes a weapon when all authors are excluded simultaneously, creating a persistent degradation that can be repeatedly triggered by a single Byzantine actor.

### Citations

**File:** consensus/consensus-types/src/common.rs (L558-572)
```rust
    pub fn verify_opt_batches<T: TBatchInfo>(
        verifier: &ValidatorVerifier,
        opt_batches: &OptBatches<T>,
    ) -> anyhow::Result<()> {
        let authors = verifier.address_to_validator_index();
        for batch in &opt_batches.batch_summary {
            ensure!(
                authors.contains_key(&batch.author()),
                "Invalid author {} for batch {}",
                batch.author(),
                batch.digest()
            );
        }
        Ok(())
    }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L409-425)
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
            },
```

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

**File:** consensus/src/liveness/proposal_status_tracker.rs (L49-52)
```rust
    pub(crate) fn push(&mut self, status: NewRoundReason) {
        self.past_round_statuses.push_back(status);
        self.compute_failure_window();
    }
```

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

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L596-600)
```rust
        for (_, batches) in self
            .author_to_batches
            .iter()
            .filter(|(author, _)| !exclude_authors.contains(author))
        {
```

**File:** consensus/consensus-types/src/opt_proposal_msg.rs (L96-123)
```rust
    pub fn verify(
        &self,
        sender: Author,
        validator: &ValidatorVerifier,
        proof_cache: &ProofCache,
        quorum_store_enabled: bool,
    ) -> Result<()> {
        ensure!(
            self.proposer() == sender,
            "OptProposal author {:?} doesn't match sender {:?}",
            self.proposer(),
            sender
        );

        let (payload_verify_result, qc_verify_result) = rayon::join(
            || {
                self.block_data()
                    .payload()
                    .verify(validator, proof_cache, quorum_store_enabled)
            },
            || self.block_data().grandparent_qc().verify(validator),
        );
        payload_verify_result?;
        qc_verify_result?;

        // Note that we postpone the verification of SyncInfo until it's being used.
        self.verify_well_formed()
    }
```
