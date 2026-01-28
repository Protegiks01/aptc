# Audit Report

## Title
Two-Chain Timeout Certificate Verification Failure Due to Signature Update Race Condition

## Summary
The timeout certificate aggregation logic in `TwoChainTimeoutVotes` fails to properly track signature updates when validators send multiple timeout messages with increasing HQC (Highest Quorum Certificate) rounds. This creates an inconsistency where the stored timeout's HQC round does not match the maximum signed HQC round, causing legitimate timeout certificates to fail verification and disrupting consensus liveness.

## Finding Description

The vulnerability exists in the interaction between three critical components in the Aptos consensus layer:

**1. No Duplicate Detection**: Unlike vote processing which uses the `author_to_vote` HashMap to detect duplicates and equivocations, `insert_round_timeout()` has no mechanism to prevent validators from sending multiple timeout messages for the same round. [1](#0-0) 

This contrasts sharply with `insert_vote()`, which explicitly checks for duplicate votes and equivocations using the `author_to_vote` HashMap: [2](#0-1) 

**2. Signature Tracking Bug**: The `add_signature()` method in `PartialSignaturesWithRound` uses `or_insert()`, which only inserts a new entry if the key doesn't exist. This means the FIRST signature from each validator is recorded, but subsequent signatures from the same validator are silently ignored, even if they contain updated information: [3](#0-2) 

**3. Timeout Replacement Without Signature Update**: When `TwoChainTimeoutWithPartialSignatures::add()` receives a timeout with a higher HQC round, it correctly updates the stored timeout object (line 260). However, when it subsequently calls `add_signature()` with the new HQC round (line 262), the signature is NOT updated due to the `or_insert()` behavior: [4](#0-3) 

**Exploitation Scenario**:

During normal AptosBFT operation, validators may receive new quorum certificates while an ongoing round is timing out:

1. Validator A sends `RoundTimeout(round=10, HQC_round=5)` → Stored timeout HQC=5, Signatures: `{A: (5, sig_A)}`
2. Validator B sends `RoundTimeout(round=10, HQC_round=6)` → Stored timeout updated to HQC=6, Signatures: `{A: (5, sig_A), B: (6, sig_B)}`
3. Validator A receives QC for round 8 and legitimately sends updated `RoundTimeout(round=10, HQC_round=8)`
   - Stored timeout updated to HQC=8
   - `add_signature(A, 8, sig_A_new)` called
   - But A's signature remains `(5, sig_A)` due to `or_insert()`
   - Signatures: `{A: (5, sig_A), B: (6, sig_B)}`
4. Validator C sends `RoundTimeout(round=10, HQC_round=5)` → Signatures: `{A: (5, sig_A), B: (6, sig_B), C: (5, sig_C)}`

When quorum is reached and `aggregate_signatures()` creates the `TwoChainTimeoutCertificate`:
- Stored `timeout.hqc_round()` = 8
- Signature HQC rounds: [5, 6, 5]
- `max(signed rounds)` = 6

**Verification Failure**: When the TC is verified (e.g., in a `ProposalMsg`), the consistency check fails because it requires that the stored timeout's HQC round must equal the maximum of all signed HQC rounds: [5](#0-4) 

The verification error message is: `"Inconsistent hqc round, qc has round 8, highest signed round 6"`

This causes the legitimately aggregated TC to be rejected, even though all signatures are valid and the quorum threshold was reached.

## Impact Explanation

**Medium Severity** per Aptos Bug Bounty criteria: "State inconsistencies requiring manual intervention" and "Temporary liveness issues"

This vulnerability causes:

1. **Consensus Liveness Degradation**: Legitimate timeout certificates fail verification during the proposal phase, preventing round progression when timeouts occur. This directly impacts the network's ability to recover from scenarios requiring timeouts (slow validators, network partitions).

2. **State Inconsistency**: The TC successfully passes aggregation (voting power check succeeds), but subsequently fails verification when used. This creates a confusing state where the node believes it has a valid TC but cannot use it.

3. **Diagnostic Complexity**: The failure manifests only during TC usage in proposals, not during aggregation. The error message indicates an "inconsistent hqc round" but the root cause (signature not updated) is non-obvious, making debugging difficult.

4. **Network-Wide Impact**: All nodes receiving a proposal with the malformed TC will reject it, potentially causing the round to fail and requiring another timeout cycle.

The issue does NOT affect safety (no double-spending or chain splits), but significantly impacts liveness, which is critical for a production blockchain. Under adversarial conditions or during network stress, this could cause prolonged consensus stalls requiring manual intervention or node restarts.

## Likelihood Explanation

**HIGH likelihood** of occurrence:

1. **Natural Trigger During Normal Operations**: Validators routinely receive new quorum certificates during ongoing rounds due to block proposals from other validators. It is entirely normal and expected for a validator's view of the highest QC to change during a timeout period. No malicious behavior is required.

2. **Common Network Conditions**: Network delays, varying block propagation times, and validators catching up after brief disconnections all create scenarios where validators have different HQC rounds during the same timeout round.

3. **No Protective Measures**: The code completely lacks duplicate detection for timeout messages at all levels:
   - No validation in `insert_round_timeout()` [1](#0-0) 
   - No validation in `RoundState::insert_round_timeout()` [6](#0-5) 
   - No validation in `RoundManager::process_round_timeout()` [7](#0-6) 

4. **Malicious Amplification**: While the bug can occur naturally, a malicious validator could deliberately exploit it by sending multiple timeout messages with incrementally increasing HQC rounds to ensure the inconsistency occurs and disrupts consensus.

5. **Test Coverage Gap**: The existing test suite does not cover the scenario of the same validator sending multiple timeout messages with different HQC rounds. The test at [8](#0-7)  tests timeouts from different validators with different HQC rounds, but not multiple timeouts from the same validator.

## Recommendation

Implement one of the following fixes:

**Option 1: Add Duplicate Detection (Preferred)**
Track timeout authors similar to how votes are tracked with `author_to_vote`, and return `VoteReceptionResult::DuplicateVote` for subsequent timeout messages from the same author in the same round.

**Option 2: Update Signature on Newer Timeout**
Change `add_signature()` to use `insert()` instead of `or_insert()` to allow signature updates:

```rust
pub fn add_signature(
    &mut self,
    validator: AccountAddress,
    round: Round,
    signature: bls12381::Signature,
) {
    self.signatures.insert(validator, (round, signature)); // Changed from or_insert
}
```

**Option 3: Reject Higher HQC Updates**
Reject timeout messages from validators who have already sent a timeout for the current round, maintaining only the first timeout received from each validator.

Option 1 is recommended as it aligns with the existing vote processing logic and provides clearer semantics about duplicate timeout handling.

## Proof of Concept

```rust
#[test]
fn test_same_validator_multiple_timeouts_with_different_hqc() {
    use aptos_consensus_types::{
        quorum_cert::QuorumCert,
        timeout_2chain::{TwoChainTimeout, TwoChainTimeoutWithPartialSignatures},
    };
    use aptos_types::validator_verifier::random_validator_verifier;

    let (signers, validators) = random_validator_verifier(4, None, false);
    
    // Create timeouts with different HQC rounds from same validator
    let timeout_hqc5 = TwoChainTimeout::new(1, 10, QuorumCert::dummy_at_round(5));
    let timeout_hqc8 = TwoChainTimeout::new(1, 10, QuorumCert::dummy_at_round(8));
    
    let mut tc_with_partial = TwoChainTimeoutWithPartialSignatures::new(timeout_hqc5.clone());
    
    // Validator 0 sends timeout with HQC=5
    tc_with_partial.add(
        signers[0].author(),
        timeout_hqc5.clone(),
        timeout_hqc5.sign(&signers[0]).unwrap(),
    );
    
    // Validator 1 sends timeout with HQC=6
    let timeout_hqc6 = TwoChainTimeout::new(1, 10, QuorumCert::dummy_at_round(6));
    tc_with_partial.add(
        signers[1].author(),
        timeout_hqc6.clone(),
        timeout_hqc6.sign(&signers[1]).unwrap(),
    );
    
    // Validator 0 sends UPDATED timeout with HQC=8 (this should update signature but doesn't)
    tc_with_partial.add(
        signers[0].author(),
        timeout_hqc8.clone(),
        timeout_hqc8.sign(&signers[0]).unwrap(),
    );
    
    // Validator 2 sends timeout to reach quorum
    tc_with_partial.add(
        signers[2].author(),
        timeout_hqc5.clone(),
        timeout_hqc5.sign(&signers[2]).unwrap(),
    );
    
    // Aggregate signatures
    let tc = tc_with_partial.aggregate_signatures(&validators).unwrap();
    
    // This will fail with "Inconsistent hqc round" error
    // because tc.timeout.hqc_round() = 8 but max(signed_rounds) = 6
    assert!(tc.verify(&validators).is_err());
}
```

## Notes

This vulnerability is particularly insidious because:

1. **It occurs during legitimate consensus operation** - validators naturally update their HQC view during timeout periods
2. **No protective layers exist** - unlike vote processing which has multiple safeguards
3. **The failure is delayed** - TC passes aggregation but fails only during verification
4. **The error message is misleading** - suggests TC construction problem rather than signature tracking bug

The fix should prioritize maintaining consistency between the stored timeout's HQC round and the signatures collected, either by preventing multiple timeout messages from the same validator or by properly updating signatures when a validator's HQC round increases.

### Citations

**File:** consensus/src/pending_votes.rs (L190-271)
```rust
    pub fn insert_round_timeout(
        &mut self,
        round_timeout: &RoundTimeout,
        validator_verifier: &ValidatorVerifier,
    ) -> VoteReceptionResult {
        //
        // Let's check if we can create a TC
        //

        let timeout = round_timeout.two_chain_timeout();
        let signature = round_timeout.signature();

        let validator_voting_power = validator_verifier
            .get_voting_power(&round_timeout.author())
            .unwrap_or(0);
        if validator_voting_power == 0 {
            warn!(
                "Received vote with no voting power, from {}",
                round_timeout.author()
            );
        }
        let cur_epoch = round_timeout.epoch();
        let cur_round = round_timeout.round();

        counters::CONSENSUS_CURRENT_ROUND_TIMEOUT_VOTED_POWER
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(validator_voting_power as f64);
        counters::CONSENSUS_LAST_TIMEOUT_VOTE_EPOCH
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(cur_epoch as i64);
        counters::CONSENSUS_LAST_TIMEOUT_VOTE_ROUND
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(cur_round as i64);

        let two_chain_votes = self
            .maybe_2chain_timeout_votes
            .get_or_insert_with(|| TwoChainTimeoutVotes::new(timeout.clone()));
        two_chain_votes.add(
            round_timeout.author(),
            timeout.clone(),
            signature.clone(),
            round_timeout.reason().clone(),
        );

        let partial_tc = two_chain_votes.partial_2chain_tc_mut();
        let tc_voting_power =
            match validator_verifier.check_voting_power(partial_tc.signers(), true) {
                Ok(_) => {
                    return match partial_tc.aggregate_signatures(validator_verifier) {
                        Ok(tc_with_sig) => {
                            VoteReceptionResult::New2ChainTimeoutCertificate(Arc::new(tc_with_sig))
                        },
                        Err(e) => VoteReceptionResult::ErrorAggregatingTimeoutCertificate(e),
                    };
                },
                Err(VerifyError::TooLittleVotingPower { voting_power, .. }) => voting_power,
                Err(error) => {
                    error!(
                        "MUST_FIX: 2-chain timeout vote received could not be added: {}, vote: {}",
                        error, timeout
                    );
                    return VoteReceptionResult::ErrorAddingVote(error);
                },
            };

        // Echo timeout if receive f+1 timeout message.
        if !self.echo_timeout {
            let f_plus_one = validator_verifier.total_voting_power()
                - validator_verifier.quorum_voting_power()
                + 1;
            if tc_voting_power >= f_plus_one {
                self.echo_timeout = true;
                return VoteReceptionResult::EchoTimeout(tc_voting_power);
            }
        }

        //
        // No TC could be formed, return the TC's voting power
        //

        VoteReceptionResult::VoteAdded(tc_voting_power)
    }
```

**File:** consensus/src/pending_votes.rs (L287-309)
```rust
        if let Some((previously_seen_vote, previous_li_digest)) =
            self.author_to_vote.get(&vote.author())
        {
            // is it the same vote?
            if &li_digest == previous_li_digest {
                // we've already seen an equivalent vote before
                let new_timeout_vote = vote.is_timeout() && !previously_seen_vote.is_timeout();
                if !new_timeout_vote {
                    // it's not a new timeout vote
                    return VoteReceptionResult::DuplicateVote;
                }
            } else {
                // we have seen a different vote for the same round
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
        }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L170-181)
```rust
        let signed_hqc = self
            .signatures_with_rounds
            .rounds()
            .iter()
            .max()
            .ok_or_else(|| anyhow::anyhow!("Empty rounds"))?;
        ensure!(
            hqc_round == *signed_hqc,
            "Inconsistent hqc round, qc has round {}, highest signed round {}",
            hqc_round,
            *signed_hqc
        );
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L242-263)
```rust
    pub fn add(
        &mut self,
        author: Author,
        timeout: TwoChainTimeout,
        signature: bls12381::Signature,
    ) {
        debug_assert_eq!(
            self.timeout.epoch(),
            timeout.epoch(),
            "Timeout should have the same epoch as TimeoutCert"
        );
        debug_assert_eq!(
            self.timeout.round(),
            timeout.round(),
            "Timeout should have the same round as TimeoutCert"
        );
        let hqc_round = timeout.hqc_round();
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
        }
        self.signatures.add_signature(author, hqc_round, signature);
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L320-329)
```rust
    pub fn add_signature(
        &mut self,
        validator: AccountAddress,
        round: Round,
        signature: bls12381::Signature,
    ) {
        self.signatures
            .entry(validator)
            .or_insert((round, signature));
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L407-509)
```rust
    #[test]
    fn test_2chain_timeout_certificate() {
        use crate::vote_data::VoteData;
        use aptos_crypto::hash::CryptoHash;
        use aptos_types::{
            aggregate_signature::PartialSignatures,
            block_info::BlockInfo,
            ledger_info::{LedgerInfo, LedgerInfoWithVerifiedSignatures},
            validator_verifier::random_validator_verifier,
        };

        let num_nodes = 4;
        let (signers, validators) = random_validator_verifier(num_nodes, None, false);
        let quorum_size = validators.quorum_voting_power() as usize;
        let generate_quorum = |round, num_of_signature| {
            let vote_data = VoteData::new(BlockInfo::random(round), BlockInfo::random(0));
            let mut ledger_info = LedgerInfoWithVerifiedSignatures::new(
                LedgerInfo::new(BlockInfo::empty(), vote_data.hash()),
                PartialSignatures::empty(),
            );
            for signer in &signers[0..num_of_signature] {
                let signature = signer.sign(ledger_info.ledger_info()).unwrap();
                ledger_info.add_signature(signer.author(), signature);
            }
            QuorumCert::new(
                vote_data,
                ledger_info.aggregate_signatures(&validators).unwrap(),
            )
        };
        let generate_timeout = |round, qc_round| {
            TwoChainTimeout::new(1, round, generate_quorum(qc_round, quorum_size))
        };

        let timeouts: Vec<_> = (1..=3)
            .map(|qc_round| generate_timeout(4, qc_round))
            .collect();
        // timeout cert with (round, hqc round) = (4, 1), (4, 2), (4, 3)
        let mut tc_with_partial_sig =
            TwoChainTimeoutWithPartialSignatures::new(timeouts[0].clone());
        for (timeout, signer) in timeouts.iter().zip(&signers) {
            tc_with_partial_sig.add(
                signer.author(),
                timeout.clone(),
                timeout.sign(signer).unwrap(),
            );
        }

        let tc_with_sig = tc_with_partial_sig
            .aggregate_signatures(&validators)
            .unwrap();
        tc_with_sig.verify(&validators).unwrap();

        // timeout round < hqc round
        let mut invalid_tc_with_partial_sig = tc_with_partial_sig.clone();
        invalid_tc_with_partial_sig.timeout.round = 1;

        let invalid_tc_with_sig = invalid_tc_with_partial_sig
            .aggregate_signatures(&validators)
            .unwrap();
        invalid_tc_with_sig.verify(&validators).unwrap_err();

        // invalid signature
        let mut invalid_timeout_cert = invalid_tc_with_partial_sig.clone();
        invalid_timeout_cert.signatures.replace_signature(
            signers[0].author(),
            0,
            bls12381::Signature::dummy_signature(),
        );

        let invalid_tc_with_sig = invalid_timeout_cert
            .aggregate_signatures(&validators)
            .unwrap();
        invalid_tc_with_sig.verify(&validators).unwrap_err();

        // not enough signatures
        let mut invalid_timeout_cert = invalid_tc_with_partial_sig.clone();
        invalid_timeout_cert
            .signatures
            .remove_signature(&signers[0].author());
        let invalid_tc_with_sig = invalid_timeout_cert
            .aggregate_signatures(&validators)
            .unwrap();

        invalid_tc_with_sig.verify(&validators).unwrap_err();

        // hqc round does not match signed round
        let mut invalid_timeout_cert = invalid_tc_with_partial_sig.clone();
        invalid_timeout_cert.timeout.quorum_cert = generate_quorum(2, quorum_size);

        let invalid_tc_with_sig = invalid_timeout_cert
            .aggregate_signatures(&validators)
            .unwrap();
        invalid_tc_with_sig.verify(&validators).unwrap_err();

        // invalid quorum cert
        let mut invalid_timeout_cert = invalid_tc_with_partial_sig;
        invalid_timeout_cert.timeout.quorum_cert = generate_quorum(3, quorum_size - 1);
        let invalid_tc_with_sig = invalid_timeout_cert
            .aggregate_signatures(&validators)
            .unwrap();

        invalid_tc_with_sig.verify(&validators).unwrap_err();
    }
```

**File:** consensus/src/liveness/round_state.rs (L306-316)
```rust
    pub fn insert_round_timeout(
        &mut self,
        timeout: &RoundTimeout,
        verifier: &ValidatorVerifier,
    ) -> VoteReceptionResult {
        if timeout.round() == self.current_round {
            self.pending_votes.insert_round_timeout(timeout, verifier)
        } else {
            VoteReceptionResult::UnexpectedRound(timeout.round(), self.current_round)
        }
    }
```

**File:** consensus/src/round_manager.rs (L1881-1895)
```rust
    async fn process_round_timeout(&mut self, timeout: RoundTimeout) -> anyhow::Result<()> {
        info!(
            self.new_log(LogEvent::ReceiveRoundTimeout)
                .remote_peer(timeout.author()),
            vote = %timeout,
            epoch = timeout.epoch(),
            round = timeout.round(),
        );

        let vote_reception_result = self
            .round_state
            .insert_round_timeout(&timeout, &self.epoch_state.verifier);
        self.process_timeout_reception_result(&timeout, vote_reception_result)
            .await
    }
```
