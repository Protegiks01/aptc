# Audit Report

## Title
Malicious Validator Can Corrupt 2-Chain Timeout Certificate Aggregation via Multiple Timeout Messages with Different HQC Rounds

## Summary
A malicious validator can send multiple `RoundTimeout` messages for the same round with different `hqc_round` values. Due to a logic flaw in timeout aggregation, this creates timeout certificates with inconsistent internal state where `timeout.hqc_round()` reflects the highest value received but signatures correspond to lower values. When other nodes verify these certificates in proposals, verification fails, causing denial of service against the victim validator.

## Finding Description

The vulnerability exists in the 2-chain timeout certificate aggregation logic within the consensus layer. The system accepts multiple timeout messages from the same validator without deduplication. [1](#0-0) 

When processing timeout votes, the `TwoChainTimeoutWithPartialSignatures::add` method updates `self.timeout` to the timeout with the highest `hqc_round`: [2](#0-1) 

However, the signature storage uses `or_insert` semantics which preserves the first signature from each author and does not update it: [3](#0-2) 

This creates an inconsistency where the TC's `timeout.hqc_round()` may be 10, but the stored signature for that validator corresponds to `hqc_round=5`.

**Attack Scenario:**
1. Four validators A (malicious), B, C, D exist with equal voting power (quorum = 67%)
2. All validators timeout at round 10
3. Validators B, C, D send timeout messages with `hqc_round=5`
4. Malicious validator A sends first timeout with `hqc_round=5`
5. Before quorum is reached, validator A sends second timeout with `hqc_round=10`
6. The partial TC's `self.timeout` is updated to `hqc_round=10`, but A's signature remains for `hqc_round=5`
7. When quorum is reached, TC is formed with `timeout.hqc_round() = 10` but `max(signed_rounds) = 5`

The TC is stored without verification: [4](#0-3) 

When the victim node includes this TC in a proposal's `sync_info`, other nodes verify it: [5](#0-4) 

The verification checks that `hqc_round == max(signed_hqc)` and fails: [6](#0-5) 

Proposal verification happens when processing unverified events: [7](#0-6) 

This causes the proposal to be rejected, preventing the victim validator from participating effectively in consensus.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria)

This vulnerability enables a single malicious validator to cause denial of service against honest validators:

1. **Validator node slowdowns**: Victim nodes continuously produce invalid proposals that are rejected by peers, matching the "Validator Node Slowdowns" High severity category.

2. **Significant protocol violations**: The victim node's consensus state becomes unusable for proposal generation, as it stores a timeout certificate that fails verification.

3. **Liveness impact**: If the victim is the leader for multiple consecutive rounds, it significantly degrades network liveness by producing invalid proposals.

The attack does NOT cause consensus safety violations (no chain splits or double-spending) because the malformed TC fails verification at other nodes. However, it prevents the victim node from participating effectively in consensus, which qualifies as High severity according to the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: High**

The attack is highly practical:

1. **Low barrier**: Requires only a single malicious validator (< 1/3 Byzantine threshold that AptosBFT is designed to tolerate)
2. **Simple execution**: The attacker simply sends two timeout messages with different `hqc_round` values
3. **No coordination needed**: No collusion with other validators required
4. **Timing window**: The attack succeeds whenever the second message arrives after the first but before quorum is reached, which is a realistic window in distributed systems
5. **Repeatable**: Can be executed every round to continuously disrupt specific validators

## Recommendation

Implement one or more of the following fixes:

1. **Add deduplication**: Track which validators have already sent timeout messages for the current round and reject duplicates
2. **Update signature on timeout update**: When updating `self.timeout` to a higher `hqc_round`, also update the corresponding signature in the map instead of using `or_insert`
3. **Verify TC before storage**: Call `tc.verify()` immediately after aggregation in `aggregate_signatures()` before returning the TC
4. **Consistent state enforcement**: Ensure that when `self.timeout` is updated, the signature map entry is also updated to maintain consistency

Example fix for option 2:
```rust
pub fn add_signature(
    &mut self,
    validator: AccountAddress,
    round: Round,
    signature: bls12381::Signature,
) {
    self.signatures
        .insert(validator, (round, signature)); // Use insert instead of or_insert
}
```

## Proof of Concept

```rust
#[test]
fn test_malicious_validator_multiple_timeouts() {
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

    // Malicious validator A sends timeout with hqc_round=5
    let timeout_low = generate_timeout(10, 5);
    let sig_low = timeout_low.sign(&signers[0]).unwrap();
    
    // Honest validators B, C send timeout with hqc_round=5
    let timeout_b = generate_timeout(10, 5);
    let sig_b = timeout_b.sign(&signers[1]).unwrap();
    
    let timeout_c = generate_timeout(10, 5);
    let sig_c = timeout_c.sign(&signers[2]).unwrap();
    
    // Malicious validator A sends second timeout with hqc_round=10
    let timeout_high = generate_timeout(10, 10);
    let sig_high = timeout_high.sign(&signers[0]).unwrap();
    
    // Simulate aggregation
    let mut tc_with_partial_sig = TwoChainTimeoutWithPartialSignatures::new(timeout_low.clone());
    
    // Add first timeout from A with hqc_round=5
    tc_with_partial_sig.add(signers[0].author(), timeout_low.clone(), sig_low);
    
    // Add second timeout from A with hqc_round=10 (before quorum)
    tc_with_partial_sig.add(signers[0].author(), timeout_high.clone(), sig_high);
    
    // Add honest validators' timeouts
    tc_with_partial_sig.add(signers[1].author(), timeout_b, sig_b);
    tc_with_partial_sig.add(signers[2].author(), timeout_c, sig_c);
    
    // Aggregate signatures
    let tc_with_sig = tc_with_partial_sig.aggregate_signatures(&validators).unwrap();
    
    // Verification should fail because timeout.hqc_round()=10 but max(signed_rounds)=5
    assert!(tc_with_sig.verify(&validators).is_err());
}
```

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

**File:** consensus/consensus-types/src/timeout_2chain.rs (L176-181)
```rust
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

**File:** consensus/src/round_manager.rs (L120-127)
```rust
            UnverifiedEvent::ProposalMsg(p) => {
                if !self_message {
                    p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proposal"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProposalMsg(p)
```

**File:** consensus/src/round_manager.rs (L2005-2015)
```rust
    async fn new_2chain_tc_aggregated(
        &mut self,
        tc: Arc<TwoChainTimeoutCertificate>,
    ) -> anyhow::Result<()> {
        let result = self
            .block_store
            .insert_2chain_timeout_certificate(tc)
            .context("[RoundManager] Failed to process a newly aggregated 2-chain TC");
        self.process_certificates().await?;
        result
    }
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L113-115)
```rust
        if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
```
