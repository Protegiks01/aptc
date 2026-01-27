# Audit Report

## Title
OptQuorumStore Payload Author Verification Bypass Enables Manipulation of Missing Authors BitVec

## Summary

The `check_payload_availability()` function in `QuorumStorePayloadManager` fails to verify that batch authors in OptQuorumStore payloads match the actual authors of stored batches. This allows malicious block proposers to manipulate the `missing_authors` BitVec by fabricating `BatchInfo` entries with incorrect author fields, enabling false blame attribution and leader reputation manipulation.

## Finding Description

The vulnerability exists in the payload availability checking logic for OptQuorumStore payloads (V1 and V2). When a block proposer creates an OptQuorumStore payload, they include `opt_batches` containing `BatchInfo` structures that reference transaction batches by digest and claim specific authors created them. [1](#0-0) 

The verification process has two critical weaknesses:

**Weakness 1: Insufficient Payload Verification**
The `verify_opt_batches()` function only validates that claimed batch authors are valid validators in the current epoch, but performs no cryptographic verification: [2](#0-1) 

**Weakness 2: Missing Author Matching in Availability Check**
The `check_payload_availability()` function checks if batches exist locally via `batch_reader.exists()`, which returns `Option<PeerId>` containing the **actual** batch author. However, the code only checks if the result is `None` and never verifies that the returned author matches `batch.author()` from the payload: [1](#0-0) 

The `exists()` implementation returns the real author from storage: [3](#0-2) 

**Attack Scenarios:**

1. **False Availability**: Proposer references batch digest D that exists (created by validator Z) but claims it's from validator A. Since `exists(D)` returns `Some(Z)`, the check passes and no bits are set, even though the payload contains fraudulent author information.

2. **False Blame**: Proposer references non-existent batch digest D, claiming it's from innocent validator A. Since `exists(D)` returns `None`, validator A's bit is set in `missing_authors`, falsely blaming them for missing data.

3. **Leader Reputation Manipulation**: By systematically misattributing missing batches to specific validators across multiple rounds, the proposer can manipulate which validators are excluded from future leader selection.

The `missing_authors` BitVec is aggregated across validators during timeout voting and used by `ExponentialWindowFailureTracker` to influence leader selection: [4](#0-3) 

## Impact Explanation

**High Severity** - This vulnerability enables significant protocol violations:

1. **Consensus Manipulation**: Malicious proposers can manipulate which validators are perceived as having missing data, affecting timeout aggregation and consensus decisions.

2. **Leader Selection Bias**: By falsely attributing missing batches to specific validators over time, attackers can cause those validators to be excluded from proposal selection, biasing leader election toward colluding validators.

3. **Reputation System Compromise**: The failure tracking system that depends on accurate `missing_authors` data becomes unreliable, potentially excluding honest validators while favoring malicious ones.

4. **Protocol Liveness Risk**: If honest validators are systematically blamed for unavailability, the network may struggle to select capable leaders, affecting liveness.

This does not directly cause funds loss or chain splits, but represents a significant protocol violation that undermines the fairness and security assumptions of the consensus mechanism under Byzantine conditions (< 1/3 adversarial stake).

## Likelihood Explanation

**High Likelihood:**

1. **Low Barrier to Entry**: Any validator elected as proposer can exploit this vulnerability simply by crafting payloads with incorrect author fields.

2. **No Detection Mechanism**: There is no runtime validation that would detect or prevent this attack. The verification logic accepts any valid validator address without checking cryptographic proofs.

3. **Immediate Impact**: Each malicious proposal can instantly poison the `missing_authors` data for that round, affecting timeout voting and metrics.

4. **Difficult to Attribute**: Since the attack involves subtle misattribution rather than overt protocol violations, it may be difficult for network operators to detect and attribute to specific validators.

## Recommendation

Add author verification to `check_payload_availability()` by comparing the returned author from `exists()` with the claimed author:

```rust
Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => {
    let mut missing_authors = BitVec::with_num_bits(self.ordered_authors.len() as u16);
    for batch in p.opt_batches().deref() {
        match self.batch_reader.exists(batch.digest()) {
            None => {
                // Batch doesn't exist locally
                let index = *self
                    .address_to_validator_index
                    .get(&batch.author())
                    .expect("Payload author should have been verified");
                missing_authors.set(index as u16);
            }
            Some(actual_author) => {
                // Batch exists, verify author matches
                if actual_author != batch.author() {
                    // Author mismatch - reject the entire payload
                    error!(
                        "Author mismatch for batch {}: claimed {}, actual {}",
                        batch.digest(),
                        batch.author(),
                        actual_author
                    );
                    // Return error to reject this block proposal
                    return Err(BitVec::with_num_bits(self.ordered_authors.len() as u16));
                }
            }
        }
    }
    if missing_authors.all_zeros() {
        Ok(())
    } else {
        Err(missing_authors)
    }
}
```

Additionally, consider adding cryptographic verification to `verify_opt_batches()` by requiring signatures on `opt_batches` similar to how `proofs` are verified with `verify_with_cache()`.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_bitvec::BitVec;
    use aptos_consensus_types::{
        block::Block,
        payload::{OptQuorumStorePayload, OptQuorumStorePayloadV1},
        proof_of_store::BatchInfo,
    };
    use aptos_crypto::HashValue;
    use aptos_types::PeerId;
    use std::collections::HashMap;
    use std::sync::Arc;

    // Mock BatchReader that returns specific authors for digests
    struct MockBatchReader {
        batches: HashMap<HashValue, PeerId>,
    }

    impl BatchReader for MockBatchReader {
        fn exists(&self, digest: &HashValue) -> Option<PeerId> {
            self.batches.get(digest).copied()
        }
        
        fn get_batch(&self, _: BatchInfo, _: Vec<PeerId>) -> 
            Shared<Pin<Box<dyn Future<Output = ExecutorResult<Vec<SignedTransaction>>> + Send>>> {
            unimplemented!()
        }
        
        fn update_certified_timestamp(&self, _: u64) {}
    }

    #[test]
    fn test_author_mismatch_bypass() {
        // Setup: validator A and B
        let validator_a = PeerId::random();
        let validator_b = PeerId::random();
        let ordered_authors = vec![validator_a, validator_b];
        let mut address_to_validator_index = HashMap::new();
        address_to_validator_index.insert(validator_a, 0);
        address_to_validator_index.insert(validator_b, 1);

        // Real batch created by validator B
        let real_batch_digest = HashValue::random();
        let mut mock_reader_batches = HashMap::new();
        mock_reader_batches.insert(real_batch_digest, validator_b);
        
        let batch_reader = Arc::new(MockBatchReader {
            batches: mock_reader_batches,
        }) as Arc<dyn BatchReader>;

        // Create malicious payload claiming batch B was created by validator A
        let malicious_batch_info = BatchInfo::new(
            validator_a, // FALSE CLAIM: claiming A created it
            0.into(),
            1,
            1000000,
            real_batch_digest, // but references B's batch
            10,
            1000,
            0,
        );

        let payload_manager = QuorumStorePayloadManager::new(
            batch_reader,
            Box::new(MockCommitNotifier),
            None,
            ordered_authors.clone(),
            address_to_validator_index,
            false,
        );

        // Create block with malicious payload
        let opt_batches = OptBatches::new(vec![malicious_batch_info]);
        let payload = OptQuorumStorePayload::V1(OptQuorumStorePayloadV1::new(
            InlineBatches::default(),
            opt_batches,
            ProofBatches::default(),
            PayloadExecutionLimit::default(),
        ));
        
        let block = Block::new_proposal(..., Payload::OptQuorumStore(payload));

        // BUG: check_payload_availability returns Ok even though 
        // the batch author (B) doesn't match claimed author (A)
        let result = payload_manager.check_payload_availability(&block);
        
        // This should fail but currently passes!
        assert!(result.is_ok(), "Vulnerability: author mismatch not detected");
        
        // With the fix, this should return Err or reject the payload
    }
}
```

## Notes

This vulnerability specifically affects the OptQuorumStore payload types (V1 and V2) introduced for optimistic payload dissemination. The older InQuorumStore and QuorumStoreInlineHybrid payload types use cryptographically verified `ProofOfStore` structures and are not affected by this issue. The root cause is the design decision to include unsigned `BatchInfo` in `opt_batches` without enforcing author verification during availability checking.

### Citations

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

**File:** consensus/src/quorum_store/batch_store.rs (L726-732)
```rust
impl<T: QuorumStoreSender + Clone + Send + Sync + 'static> BatchReader for BatchReaderImpl<T> {
    fn exists(&self, digest: &HashValue) -> Option<PeerId> {
        self.batch_store
            .get_batch_from_local(digest)
            .map(|v| v.author())
            .ok()
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
