# Audit Report

## Title
Consensus Protocol Violation: Validators Can Contribute to Both QC and TC for Same Round

## Summary
When `enable_round_timeout_msg` is enabled (the default configuration), validators can vote for a block proposal and sign a timeout message for the same round, allowing their voting power to contribute to both a Quorum Certificate (QC) and Timeout Certificate (TC) simultaneously. This violates the consensus protocol invariant that validators should provide consistent signals about round outcomes.

## Finding Description

The vulnerability exists through the interaction of three components when `enable_round_timeout_msg = true`:

**1. RoundState Tracking Allows Both States**

The `RoundState` struct maintains separate fields for votes and timeouts that can both be set for the same round: [1](#0-0) 

Both fields are set independently via `record_vote()` and `record_round_timeout()`: [2](#0-1) 

**2. SafetyRules Permits Equal Round Timeout**

The `guarded_sign_timeout_with_qc` function checks if the timeout round is strictly less than `last_voted_round`, but allows equality: [3](#0-2) 

When `timeout.round() == last_voted_round`, neither the error branch (line 37) nor the update branch (line 43) executes, allowing the timeout to be signed for the same round as a vote.

**3. PendingVotes Accepts Both Without Cross-Validation**

The `insert_vote` function tracks votes using `author_to_vote`: [4](#0-3) 

However, `insert_round_timeout` does not check `author_to_vote`: [5](#0-4) 

**4. Attack Scenario Execution Path**

When `enable_round_timeout_msg = true` (the default), the `process_local_timeout` function creates a separate RoundTimeout message without checking if a vote was already sent: [6](#0-5) 

Notice that unlike the legacy behavior (when the flag is false), there is no check of `vote_sent()` before creating the timeout.

**5. Default Configuration Enables Vulnerability**

The `enable_round_timeout_msg` flag is set to `true` by default: [7](#0-6) 

**Exploitation Flow:**
1. Validator V votes for block B in round N (sets `vote_sent`)
2. Before QC forms, local timeout fires
3. `process_local_timeout` creates RoundTimeout for round N (sets `timeout_sent`)
4. SafetyRules signs it because N >= N (equality passes)
5. Both messages broadcast to network
6. Other validators accept both via separate code paths
7. V's voting power contributes to both QC and TC for round N

## Impact Explanation

**Severity: Medium**

This represents a **protocol violation** rather than a direct consensus safety violation. The impact aligns with the Medium severity category in the Aptos bug bounty: "State inconsistencies requiring manual intervention."

**Specific Impacts:**
- **Protocol Ambiguity**: Validators provide conflicting signals about whether round N succeeded (QC) or failed (TC)
- **Liveness Risk**: Different validators may see different certificates first, potentially causing voting disagreements in subsequent rounds
- **Coordination Confusion**: Network must resolve conflicting signals about round status

**Why Not Higher Severity:**
- Does not enable direct fund theft or double-spending
- Does not cause permanent network partition
- Does not bypass the 2-chain commit rule
- Deterministic proposer selection helps mitigate worst-case scenarios
- Does not affect validator node availability

The issue causes confusion and potential temporary liveness degradation rather than catastrophic consensus failure.

## Likelihood Explanation

**Likelihood: High**

This vulnerability can manifest under normal network operations:

1. **Default Configuration**: `enable_round_timeout_msg = true` is the default setting
2. **Common Timing Window**: Occurs when a validator votes but the round times out before QC formation - a frequent scenario during:
   - Network latency spikes
   - High transaction load
   - Validator synchronization delays
   - Network partitions or packet loss
3. **No Malicious Intent Required**: Any validator experiencing normal timeout conditions will trigger this behavior
4. **Automatic Occurrence**: Once timing conditions are met, the protocol automatically exhibits this behavior

The vulnerability does not require attacker coordination, precise timing attacks, or Byzantine behavior - it emerges from normal consensus operation under realistic network conditions.

## Recommendation

**Fix Option 1: Prevent Timeout After Vote (Stricter)**

In `process_local_timeout` when `enable_round_timeout_msg = true`, check if a vote was already sent:

```rust
if self.local_config.enable_round_timeout_msg {
    // Check if already voted in this round
    if let Some(vote) = self.round_state.vote_sent() {
        if vote.vote_data().proposed().round() == round {
            // Already voted, don't send separate timeout
            return Ok(());
        }
    }
    // ... rest of timeout logic
}
```

**Fix Option 2: Update SafetyRules Check (More Conservative)**

Modify `guarded_sign_timeout_with_qc` to reject equal rounds:

```rust
if timeout.round() <= safety_data.last_voted_round {
    return Err(Error::IncorrectLastVotedRound(
        timeout.round(),
        safety_data.last_voted_round,
    ));
}
```

**Fix Option 3: Cross-Validate in PendingVotes (Defense in Depth)**

Add check in `insert_round_timeout`:

```rust
// Check if author already voted for a block in this round
if self.author_to_vote.contains_key(&round_timeout.author()) {
    return VoteReceptionResult::EquivocateVote;
}
```

**Recommended Approach**: Implement Fix Option 1 for immediate protection, combined with Fix Option 3 for defense in depth.

## Proof of Concept

The existing test demonstrates the sending behavior but does not verify cross-acceptance: [8](#0-7) 

A complete PoC would extend this test to verify that both messages are accepted by other validators and contribute to both QC and TC formation, demonstrating the protocol violation.

**Notes**

This vulnerability represents a **protocol design issue** introduced when the `enable_round_timeout_msg` feature was added. The legacy behavior (when the flag is false) explicitly prevents this by reusing the existing vote and adding a timeout signature to it. The new separate timeout message mechanism lacks equivalent protection, allowing validators to inadvertently provide conflicting consensus signals.

While this does not immediately enable fund theft or chain splits, it violates fundamental consensus protocol assumptions and could lead to coordination issues requiring manual intervention, particularly under adverse network conditions where multiple validators might exhibit this behavior simultaneously.

### Citations

**File:** consensus/src/liveness/round_state.rs (L161-163)
```rust
    vote_sent: Option<Vote>,
    // Timeout sent locally for the current round.
    timeout_sent: Option<RoundTimeout>,
```

**File:** consensus/src/liveness/round_state.rs (L318-328)
```rust
    pub fn record_vote(&mut self, vote: Vote) {
        if vote.vote_data().proposed().round() == self.current_round {
            self.vote_sent = Some(vote);
        }
    }

    pub fn record_round_timeout(&mut self, timeout: RoundTimeout) {
        if timeout.round() == self.current_round {
            self.timeout_sent = Some(timeout)
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L37-45)
```rust
        if timeout.round() < safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                timeout.round(),
                safety_data.last_voted_round,
            ));
        }
        if timeout.round() > safety_data.last_voted_round {
            self.verify_and_update_last_vote_round(timeout.round(), &mut safety_data)?;
        }
```

**File:** consensus/src/pending_votes.rs (L190-232)
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
```

**File:** consensus/src/pending_votes.rs (L287-316)
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

        //
        // 2. Store new vote (or update, in case it's a new timeout vote)
        //

        self.author_to_vote
            .insert(vote.author(), (vote.clone(), li_digest));
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

**File:** config/src/config/consensus_config.rs (L383-383)
```rust
            enable_round_timeout_msg: true,
```

**File:** consensus/src/round_manager_tests/consensus_test.rs (L1142-1184)
```rust
fn timeout_sent_on_timeout_after_vote() {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let local_config = ConsensusConfig {
        enable_round_timeout_msg: true,
        ..Default::default()
    };
    let mut nodes = NodeSetup::create_nodes(
        &mut playground,
        runtime.handle().clone(),
        1,
        None,
        None,
        None,
        Some(local_config),
        None,
        None,
        false,
    );
    let node = &mut nodes[0];
    timed_block_on(&runtime, async {
        let proposal_msg = node.next_proposal().await;
        let id = proposal_msg.proposal().id();
        node.round_manager
            .process_proposal_msg(proposal_msg)
            .await
            .unwrap();
        let vote_msg = node.next_vote().await;
        let vote = vote_msg.vote();
        assert!(!vote.is_timeout());
        assert_eq!(vote.vote_data().proposed().id(), id);
        // Process the outgoing vote message and verify that it contains a round signature
        // and that the vote is the same as above.
        node.round_manager
            .process_local_timeout(1)
            .await
            .unwrap_err();
        let timeout_msg = node.next_timeout().await;

        assert_eq!(timeout_msg.round(), vote.vote_data().proposed().round());
        assert_eq!(timeout_msg.sync_info(), vote_msg.sync_info());
    });
}
```
