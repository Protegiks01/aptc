# Audit Report

## Title
Byzantine Proposer Can Falsely Exclude Honest Validators from OptQS Through Unauthenticated Batch Attribution

## Summary
A Byzantine validator acting as proposer can craft OptQuorumStore payloads with fake batch entries attributed to honest validators, causing all receiving validators to incorrectly report those honest validators as having missing payloads. This triggers automatic exclusion from OptQS, systematically degrading network efficiency and violating fairness guarantees.

## Finding Description

The vulnerability exists in the OptQuorumStore (OptQS) payload verification and timeout handling mechanism. The attack exploits the lack of cryptographic authentication on `BatchInfo` entries in `opt_batches`.

**Attack Flow:**

1. **Malicious Payload Creation**: When a Byzantine validator becomes proposer, they create an `OptQuorumStorePayload` with fake `BatchInfo` entries. The `BatchInfo` structure contains only metadata fields without any signature field [1](#0-0) , allowing arbitrary attribution to any validator.

2. **Weak Verification**: The payload passes validation because `verify_opt_batches()` only checks if the author is in the validator set [2](#0-1) , with no signature verification.

3. **False Missing Detection**: When honest validators receive the block, `check_payload_availability()` verifies batch availability by checking if the digest exists locally [3](#0-2) . Since the fake batches don't exist (wrong digest), validators mark the falsely-attributed author as missing in the `missing_authors` BitVec.

4. **Timeout Propagation**: When validators timeout due to unavailable payload, they create `RoundTimeoutReason::PayloadUnavailable` with the manipulated `missing_authors` [4](#0-3) .

5. **Byzantine Aggregation**: The `aggregated_timeout_reason()` function aggregates timeout reasons from multiple validators [5](#0-4) . If f+1 validators report an author as missing (which happens because all honest validators see the same fake batch), that author gets marked in the aggregated BitVec.

6. **Exclusion from OptQS**: The `get_exclude_authors()` function reads the aggregated `missing_authors` BitVec and adds those validators to the exclusion set [6](#0-5) .

7. **Network Degradation**: When pulling batches for OptQS, excluded authors are filtered out [7](#0-6) , preventing their legitimate batches from being included.

**Root Cause**: Unlike `ProofOfStore` which has cryptographic signatures via the `multi_signature` field [8](#0-7) , the `BatchInfo` structure in `opt_batches` has no signature field, allowing arbitrary batch attribution without proof of authorship.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability causes **significant protocol violations** through:

1. **Network Efficiency Degradation**: Byzantine proposers can systematically exclude honest validators from OptQS, forcing the network to use less efficient payload mechanisms.

2. **Unfair Validator Treatment**: Honest validators are penalized for malicious actions they didn't commit, violating fairness guarantees.

3. **Potential Liveness Impact**: If enough validators are excluded, block production efficiency could degrade significantly under high transaction load.

4. **Byzantine Amplification**: A single Byzantine proposer can affect the entire validator set's behavior by manipulating exclusion lists, exceeding the expected impact of f Byzantine validators.

While this doesn't directly cause fund loss or consensus safety violations, it represents a **significant protocol violation** qualifying as HIGH severity under the Aptos Bug Bounty "Validator Node Slowdowns" or "Significant Protocol Violations" category.

## Likelihood Explanation

**Likelihood: High**

- **Attack Complexity**: Low - Byzantine proposer only needs to construct malicious `BatchInfo` entries when they are the leader
- **Detection Difficulty**: High - The attack appears as legitimate payload unavailability to observers
- **Frequency**: Occurs every time a Byzantine validator is the proposer (1/n probability per round)
- **Prerequisites**: Only requires being selected as proposer through normal rotation
- **Persistence**: Exclusion persists across the configured window size, allowing sustained impact

With f Byzantine validators rotating as proposers, this attack can be executed repeatedly to maintain continuous degradation of network efficiency.

## Recommendation

Add cryptographic authentication to `opt_batches` similar to `ProofOfStore`:

1. Require validators to sign `BatchInfo` entries they create
2. Extend `verify_opt_batches()` to verify signatures on batch entries
3. Alternatively, only allow validators to reference their own batches in `opt_batches`, verified through signature checks on the proposal itself

This ensures that batch attribution cannot be forged by Byzantine proposers.

## Proof of Concept

A Byzantine validator acting as proposer can:
1. Create an `OptQuorumStorePayloadV1` with `opt_batches` containing `BatchInfo { author: target_validator, digest: random_hash(), ... }`
2. Broadcast this as part of their proposal
3. Honest validators will fail to find the batch locally and report `target_validator` as missing
4. After timeout aggregation with f+1 reports, `target_validator` gets excluded from future OptQS pulls

The vulnerability is exploitable every round the Byzantine validator is selected as proposer, causing systematic degradation of network efficiency.

## Notes

The distinction between `opt_batches` (containing plain `BatchInfo`) and `proofs` (containing `ProofOfStore<BatchInfo>` with signatures) [9](#0-8)  is the root cause. The `opt_batches` field lacks the cryptographic authentication present in other payload types, enabling this attack vector.

### Citations

**File:** consensus/consensus-types/src/proof_of_store.rs (L49-58)
```rust
pub struct BatchInfo {
    author: PeerId,
    batch_id: BatchId,
    epoch: u64,
    expiration: u64,
    digest: HashValue,
    num_txns: u64,
    num_bytes: u64,
    gas_bucket_start: u64,
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L618-622)
```rust
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ProofOfStore<T> {
    info: T,
    multi_signature: AggregateSignature,
}
```

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

**File:** consensus/consensus-types/src/round_timeout.rs (L16-22)
```rust
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Hash, Debug)]
pub enum RoundTimeoutReason {
    Unknown,
    ProposalNotReceived,
    PayloadUnavailable { missing_authors: BitVec },
    NoQC,
}
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

**File:** consensus/consensus-types/src/payload.rs (L290-296)
```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OptQuorumStorePayloadV1<T: TBatchInfo> {
    inline_batches: InlineBatches<T>,
    opt_batches: OptBatches<T>,
    proofs: ProofBatches<T>,
    execution_limits: PayloadExecutionLimit,
}
```
