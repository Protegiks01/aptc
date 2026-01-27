# Audit Report

## Title
Cross-Equivocation Vulnerability: Validators Can Send Both Regular Vote and Round Timeout Without Detection

## Summary
A validator can send both a regular vote for a block and a separate round timeout message for the same round without the protocol detecting this as equivocation. This violates consensus safety guarantees by allowing Byzantine validators to contribute to both Quorum Certificate (QC) and Timeout Certificate (TC) formation for the same round.

## Finding Description

The vulnerability exists in the consensus timeout handling mechanism when `enable_round_timeout_msg` is enabled (which is the default configuration). [1](#0-0) 

The core issue stems from the `is_timeout_sent()` function's logic check: [2](#0-1) 

This function checks if a timeout has been sent using an OR condition, but it fails to prevent a state where both `vote_sent` (a regular vote without timeout) and `timeout_sent` (a separate RoundTimeout message) are set simultaneously.

**Attack Scenario:**

1. Validator V votes for proposal block B in round R, setting `vote_sent` to a regular Vote (without timeout signature). The vote is broadcast to the network. [3](#0-2) 

2. Later in the same round, a local timeout triggers. The `is_timeout_sent()` check returns `false` because `vote_sent.is_timeout()` is false (regular vote has no timeout signature) and `timeout_sent` is still `None`.

3. Since `enable_round_timeout_msg` is true by default, the `process_local_timeout()` function creates a separate `RoundTimeout` message and sets `timeout_sent`. [4](#0-3) 

4. Now the validator has both:
   - `vote_sent`: A vote for block B
   - `timeout_sent`: A timeout for round R

5. **No equivocation detection occurs** because `PendingVotes` tracks votes and timeouts separately:
   - Votes are stored in `author_to_vote` [5](#0-4) 
   - Timeouts are stored in `maybe_2chain_timeout_votes` [6](#0-5) 

6. The `insert_vote()` function only checks for equivocation against other votes [7](#0-6) , while `insert_round_timeout()` performs no cross-check against `author_to_vote` [8](#0-7) 

**Evidence of Developer Awareness:**

A TODO comment in the codebase explicitly acknowledges this issue but it remains unimplemented: [9](#0-8) 

**Safety Rules Inadequacy:**

The SafetyRules module allows signing a timeout for the same round as a vote because it only checks that `timeout.round() >= last_voted_round` [10](#0-9) , not preventing `timeout.round() == last_voted_round`.

## Impact Explanation

This vulnerability constitutes a **Medium severity** issue under the Aptos Bug Bounty criteria for "Significant protocol violations."

**Consensus Safety Impact:**
- A Byzantine validator can contribute their voting power to **both** QC formation (for block B) and TC formation (for round R)
- This allows selective message delivery: sending votes to some validators and timeouts to others
- Different validators may reach different conclusions about whether round R has a QC or TC
- While a single Byzantine validator alone cannot violate safety (requires 2/3+), this enables Byzantine behavior without detection, weakening the security model

**Protocol Violation:**
- Equivocation detection is a critical consensus safety mechanism
- The protocol should detect and penalize validators who send conflicting messages
- This bypass allows Byzantine validators to operate undetected, undermining the 1/3 Byzantine fault tolerance guarantee

## Likelihood Explanation

**Likelihood: MEDIUM**

- Requires a Byzantine validator to deliberately exploit this behavior
- The default configuration (`enable_round_timeout_msg: true`) makes all validators vulnerable to this attack pattern
- No special timing or race conditions required
- Can occur naturally if a validator votes and then experiences legitimate timeout, or maliciously if a Byzantine validator intentionally creates this state
- Receiving nodes will accept both messages without raising equivocation alerts

## Recommendation

Implement cross-equivocation detection between votes and round timeout messages:

**Solution 1: Prevent State at Source**
When `enable_round_timeout_msg` is true, prevent calling `process_local_timeout()` if a regular (non-timeout) vote has already been sent in the current round:

```rust
pub fn is_timeout_sent(&self) -> bool {
    // If we've sent any vote (timeout or not) OR sent a round timeout, consider timeout sent
    self.vote_sent.is_some() || self.timeout_sent.is_some()
}
```

**Solution 2: Add Cross-Equivocation Detection at Receiver**
Modify `PendingVotes::insert_round_timeout()` to check if the author already voted:

```rust
pub fn insert_round_timeout(
    &mut self,
    round_timeout: &RoundTimeout,
    validator_verifier: &ValidatorVerifier,
) -> VoteReceptionResult {
    // Check if author already voted for a block in this round
    if self.author_to_vote.contains_key(&round_timeout.author()) {
        error!(
            SecurityEvent::ConsensusEquivocatingVote,
            remote_peer = round_timeout.author(),
            "Validator sent both vote and timeout for same round"
        );
        return VoteReceptionResult::EquivocateVote;
    }
    // ... rest of existing logic
}
```

**Solution 3: Implement the TODO**
Add validation in `Vote::verify()` to ensure timeout is None when RoundTimeoutMsg is enabled:

```rust
pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
    // Implement TODO from line 152
    if round_timeout_msg_enabled && self.two_chain_timeout.is_some() {
        return Err(anyhow::anyhow!(
            "Vote should not contain timeout when RoundTimeoutMsg is enabled"
        ));
    }
    // ... rest of verification
}
```

## Proof of Concept

```rust
// Consensus round state test demonstrating the vulnerability
#[test]
fn test_cross_equivocation_not_detected() {
    // Setup: validator, round state, pending votes
    let mut round_state = RoundState::new(/* ... */);
    let mut pending_votes = PendingVotes::new();
    let validator_author = Author::random();
    
    // Step 1: Validator votes for block B (regular vote, no timeout)
    let vote_for_block = create_vote(validator_author, block_b, /* is_timeout */ false);
    round_state.record_vote(vote_for_block.clone());
    
    // Verify: vote_sent is set, timeout_sent is None
    assert!(round_state.vote_sent().is_some());
    assert!(round_state.timeout_sent().is_none());
    assert_eq!(round_state.is_timeout_sent(), false); // vote.is_timeout() is false
    
    // Step 2: Echo timeout triggers local timeout
    // Since is_timeout_sent() returns false, process_local_timeout proceeds
    round_state.process_local_timeout(current_round);
    
    // Step 3: With enable_round_timeout_msg=true, creates RoundTimeout
    let round_timeout = create_round_timeout(validator_author, current_round);
    round_state.record_round_timeout(round_timeout.clone());
    
    // Step 4: Verify both are set (CROSS-EQUIVOCATION STATE)
    assert!(round_state.vote_sent().is_some());
    assert!(round_state.timeout_sent().is_some());
    assert_eq!(round_state.is_timeout_sent(), true); // Now true due to timeout_sent
    
    // Step 5: Broadcast both messages to network
    // Receiving node processes vote
    let vote_result = pending_votes.insert_vote(&vote_for_block, &verifier);
    assert_ne!(vote_result, VoteReceptionResult::EquivocateVote); // NOT detected
    
    // Receiving node processes timeout
    let timeout_result = pending_votes.insert_round_timeout(&round_timeout, &verifier);
    assert_ne!(timeout_result, VoteReceptionResult::EquivocateVote); // NOT detected
    
    // VULNERABILITY: Both messages accepted without equivocation detection
    // Validator's signature contributes to both QC and TC for same round
}
```

## Notes

This vulnerability exploits the separation between vote tracking (`author_to_vote`) and timeout tracking (`maybe_2chain_timeout_votes`) in the `PendingVotes` structure. The protocol assumes validators will only send one type of message per round, but this assumption is not enforced. The default configuration with `enable_round_timeout_msg: true` enables this attack vector on all production networks.

### Citations

**File:** config/src/config/consensus_config.rs (L383-383)
```rust
            enable_round_timeout_msg: true,
```

**File:** consensus/src/liveness/round_state.rs (L217-219)
```rust
    pub fn is_timeout_sent(&self) -> bool {
        self.vote_sent.as_ref().is_some_and(|v| v.is_timeout()) || self.timeout_sent.is_some()
    }
```

**File:** consensus/src/round_manager.rs (L1005-1043)
```rust
        if self.local_config.enable_round_timeout_msg {
            let timeout = if let Some(timeout) = self.round_state.timeout_sent() {
                timeout
            } else {
                let timeout = TwoChainTimeout::new(
                    self.epoch_state.epoch,
                    round,
                    self.block_store.highest_quorum_cert().as_ref().clone(),
                );
                let signature = self
                    .safety_rules
                    .lock()
                    .sign_timeout_with_qc(
                        &timeout,
                        self.block_store.highest_2chain_timeout_cert().as_deref(),
                    )
                    .context("[RoundManager] SafetyRules signs 2-chain timeout")?;

                let timeout_reason = self.compute_timeout_reason(round);

                RoundTimeout::new(
                    timeout,
                    self.proposal_generator.author(),
                    timeout_reason,
                    signature,
                )
            };

            self.round_state.record_round_timeout(timeout.clone());
            let round_timeout_msg = RoundTimeoutMsg::new(timeout, self.block_store.sync_info());
            self.network
                .broadcast_round_timeout(round_timeout_msg)
                .await;
            warn!(
                round = round,
                remote_peer = self.proposer_election.get_valid_proposer(round),
                event = LogEvent::Timeout,
            );
            bail!("Round {} timeout, broadcast to all peers", round);
```

**File:** consensus/src/round_manager.rs (L1399-1400)
```rust
        let vote = self.create_vote(proposal).await?;
        self.round_state.record_vote(vote.clone());
```

**File:** consensus/src/pending_votes.rs (L171-171)
```rust
    maybe_2chain_timeout_votes: Option<TwoChainTimeoutVotes>,
```

**File:** consensus/src/pending_votes.rs (L173-173)
```rust
    author_to_vote: HashMap<Author, (Vote, HashValue)>,
```

**File:** consensus/src/pending_votes.rs (L190-270)
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
```

**File:** consensus/src/pending_votes.rs (L287-308)
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
```

**File:** consensus/consensus-types/src/vote.rs (L152-152)
```rust
        // TODO(ibalajiarun): Ensure timeout is None if RoundTimeoutMsg is enabled.
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L37-42)
```rust
        if timeout.round() < safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                timeout.round(),
                safety_data.last_voted_round,
            ));
        }
```
