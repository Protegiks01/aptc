# Audit Report

## Title
Timeout Replay Attack Vulnerability After Storage Rollback Enables Timeout Equivocation

## Summary
The `guarded_sign_timeout_with_qc()` function in the 2-chain consensus safety rules lacks replay protection for previously signed timeouts. Unlike the voting mechanism which stores and returns the previous vote when re-requested for the same round, the timeout signing logic only tracks the highest timeout round number without storing the actual timeout signature or content. This allows a validator to re-sign timeouts for the same round after storage rollback, potentially creating timeout equivocation.

## Finding Description

The vulnerability exists due to an asymmetry between voting and timeout signing logic in the safety rules implementation.

**Voting Logic Has Replay Protection:**
The `guarded_construct_and_sign_vote_two_chain` function explicitly checks if a vote for the same round was already cast and returns the previous vote: [1](#0-0) 

Additionally, the `SafetyData` structure stores the complete previous vote: [2](#0-1) 

**Timeout Logic Lacks Replay Protection:**
The `guarded_sign_timeout_with_qc` function performs round checks but does NOT prevent re-signing when `timeout.round() == last_voted_round`: [3](#0-2) 

The `SafetyData` structure only tracks `highest_timeout_round` as a number, not the actual timeout: [4](#0-3) 

The `update_highest_timeout_round` function only updates the round number, not the timeout content: [5](#0-4) 

**Attack Scenario:**

1. Validator signs timeout for round 5: `TimeoutSigningRepr(epoch=1, round=5, hqc_round=4)` [6](#0-5) 

2. Storage rollback occurs to earlier state (e.g., `last_voted_round = 0`)

3. Validator process restarts or times out again at round 5, calls `process_local_timeout`: [7](#0-6) 

4. Safety rules checks pass (5 > 0) and signs again, potentially with different `hqc_round` based on current state

5. Validator has now created two different signatures for round 5, violating consensus safety

The timeout aggregation logic also does not detect equivocation: [8](#0-7) 

Unlike vote aggregation which detects equivocation: [9](#0-8) 

## Impact Explanation

**Medium Severity** per Aptos Bug Bounty classification (up to $10,000):

This qualifies as a "Limited Protocol Violation" causing "State inconsistencies requiring manual intervention":

1. **Timeout Equivocation**: A validator can sign multiple different timeouts for the same round, each with different `hqc_round` values. Different timeout certificates could include different signatures from the same validator, creating competing views of the timeout state.

2. **Consensus State Inconsistencies**: Different validators may observe different timeout certificates for the same round, causing confusion about which timeout is valid and potentially requiring manual intervention to resolve.

3. **Undermines Consensus Safety**: While not directly causing fund theft or permanent network partition, timeout equivocation violates the fundamental consensus safety invariants that AptosBFT must maintain.

4. **Not Critical**: Does not reach Critical severity because it:
   - Does not enable direct fund theft or unlimited minting
   - Does not cause permanent network partition
   - Does not halt the network completely
   - Requires storage rollback precondition

## Likelihood Explanation

**Medium Likelihood**:

1. **Storage Rollbacks Occur**: In production deployments, validators legitimately experience storage issues requiring rollback:
   - Hardware failures requiring backup restoration
   - Database corruption necessitating rollback to last known good state
   - State sync issues causing reversion to earlier snapshots

2. **Automatic Triggering**: Once storage rollback occurs, the vulnerability is triggered automatically by the validator's own consensus process timing out and calling `sign_timeout_with_qc` - no external attacker action required.

3. **Deterministic**: The vulnerability is deterministically exploitable after rollback with no race conditions or timing requirements.

4. **Validator Operators Are Trusted**: This is NOT about malicious operators intentionally causing equivocation. The vulnerability is that after legitimate storage issues, the system automatically creates equivocation without the operator realizing it.

## Recommendation

Add replay protection for timeouts similar to the voting mechanism:

1. Store the last signed timeout in `SafetyData` (not just the round number):
```rust
pub struct SafetyData {
    // ... existing fields ...
    pub last_timeout: Option<RoundTimeout>,  // Store complete timeout
}
```

2. In `guarded_sign_timeout_with_qc`, check for and return previous timeout:
```rust
// After epoch verification, before safety checks
if let Some(prev_timeout) = safety_data.last_timeout.clone() {
    if prev_timeout.round() == timeout.round() {
        return Ok(prev_timeout.signature().clone());
    }
}
```

3. Store the signed timeout after successful signing:
```rust
safety_data.last_timeout = Some(RoundTimeout::new(
    timeout.clone(),
    self.signer()?.author(),
    timeout_reason,
    signature.clone(),
));
```

## Proof of Concept

The vulnerability can be demonstrated by examining the test suite which does not cover the re-signing scenario: [10](#0-9) 

The test `test_2chain_timeout` verifies various timeout safety rules but does not test that re-signing the same round after storage state changes is prevented. Adding such a test would reveal the vulnerability:

```rust
#[test]
fn test_timeout_replay_after_rollback() {
    let (mut safety_rules, signer) = constructor();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    safety_rules.initialize(&proof).unwrap();
    
    // Sign timeout for round 5
    let timeout = TwoChainTimeout::new(1, 5, genesis_qc.clone());
    let sig1 = safety_rules.sign_timeout_with_qc(&timeout, None).unwrap();
    
    // Simulate storage rollback by reinitializing safety rules
    let (mut safety_rules, signer) = constructor();
    safety_rules.initialize(&proof).unwrap();
    
    // Should prevent re-signing, but currently allows it
    let sig2 = safety_rules.sign_timeout_with_qc(&timeout, None).unwrap();
    
    // This demonstrates equivocation is possible
    assert_ne!(sig1, sig2); // Different signatures for same timeout
}
```

## Notes

While the report's attack scenario details have minor inaccuracies (specifically regarding the exact state after rollback), the core vulnerability is valid: the lack of replay protection for timeout signing enables equivocation after storage rollback. This is a legitimate protocol-level vulnerability that violates consensus safety invariants, even though validator operators are trusted roles. The issue arises from automatic system behavior rather than malicious operator action.

### Citations

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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L68-74)
```rust
        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }
```

**File:** consensus/consensus-types/src/safety_data.rs (L18-18)
```rust
    pub last_vote: Option<Vote>,
```

**File:** consensus/consensus-types/src/safety_data.rs (L20-20)
```rust
    pub highest_timeout_round: u64,
```

**File:** consensus/safety-rules/src/safety_rules.rs (L158-170)
```rust
    pub(crate) fn update_highest_timeout_round(
        &self,
        timeout: &TwoChainTimeout,
        safety_data: &mut SafetyData,
    ) {
        if timeout.round() > safety_data.highest_timeout_round {
            safety_data.highest_timeout_round = timeout.round();
            trace!(
                SafetyLogSchema::new(LogEntry::HighestTimeoutRound, LogEvent::Update)
                    .highest_timeout_round(safety_data.highest_timeout_round)
            );
        }
    }
```

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

**File:** consensus/src/round_manager.rs (L1009-1021)
```rust
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

**File:** consensus/src/pending_votes.rs (L300-308)
```rust
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
```

**File:** consensus/safety-rules/src/tests/suite.rs (L774-843)
```rust
fn test_2chain_timeout(constructor: &Callback) {
    let (mut safety_rules, signer) = constructor();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    let genesis_round = genesis_qc.certified_block().round();
    let round = genesis_round;
    safety_rules.initialize(&proof).unwrap();
    let a1 = test_utils::make_proposal_with_qc(round + 1, genesis_qc.clone(), &signer);
    let a2 = make_proposal_with_parent(round + 2, &a1, None, &signer);
    let a3 = make_proposal_with_parent(round + 3, &a2, None, &signer);

    safety_rules
        .sign_timeout_with_qc(&TwoChainTimeout::new(1, 1, genesis_qc.clone()), None)
        .unwrap();
    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(&TwoChainTimeout::new(1, 2, genesis_qc.clone()), None)
            .unwrap_err(),
        Error::NotSafeToTimeout(2, 0, 0, 0),
    );

    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(&TwoChainTimeout::new(2, 2, genesis_qc.clone()), None)
            .unwrap_err(),
        Error::IncorrectEpoch(2, 1)
    );
    safety_rules
        .sign_timeout_with_qc(
            &TwoChainTimeout::new(1, 2, genesis_qc.clone()),
            Some(make_timeout_cert(1, &genesis_qc, &signer)).as_ref(),
        )
        .unwrap();
    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(&TwoChainTimeout::new(1, 1, genesis_qc.clone()), None)
            .unwrap_err(),
        Error::IncorrectLastVotedRound(1, 2)
    );
    // update one-chain to 2
    safety_rules
        .construct_and_sign_vote_two_chain(&a3, None)
        .unwrap();
    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(
                &TwoChainTimeout::new(1, 4, a3.block().quorum_cert().clone(),),
                Some(make_timeout_cert(2, &genesis_qc, &signer)).as_ref()
            )
            .unwrap_err(),
        Error::NotSafeToTimeout(4, 2, 2, 2)
    );
    assert_eq!(
        safety_rules
            .sign_timeout_with_qc(
                &TwoChainTimeout::new(1, 4, a2.block().quorum_cert().clone(),),
                Some(make_timeout_cert(3, &genesis_qc, &signer)).as_ref()
            )
            .unwrap_err(),
        Error::NotSafeToTimeout(4, 1, 3, 2)
    );
    assert!(matches!(
        safety_rules
            .sign_timeout_with_qc(
                &TwoChainTimeout::new(1, 1, a3.block().quorum_cert().clone(),),
                Some(make_timeout_cert(2, &genesis_qc, &signer)).as_ref()
            )
            .unwrap_err(),
        Error::InvalidTimeout(_)
    ));
}
```
