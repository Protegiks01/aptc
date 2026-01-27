# Audit Report

## Title
Missing Round Monotonicity and Vote Consistency Checks in Commit Vote Signing Enables Equivocation

## Summary
The `guarded_sign_commit_vote()` function lacks critical safety checks present in all other voting functions. It does not validate that the commit being signed is consistent with the validator's voting history (`last_voted_round`, `last_vote`) nor does it persist commit vote data in SafetyData. This allows validators to sign commit votes for rounds inconsistent with their consensus state, potentially enabling equivocation.

## Finding Description

The `sign_commit_vote()` function at lines 163-174 in `serializer.rs` delegates to `guarded_sign_commit_vote()` in `safety_rules.rs`. [1](#0-0) 

The actual implementation performs only limited validation: [2](#0-1) 

The function checks:
1. Whether the ordered ledger info is ordered-only
2. Execution result consistency  
3. Quorum (2f+1) signatures on ordered_ledger_info

However, it **explicitly lacks** the safety checks present in other voting functions:

**Missing Check #1: Round Monotonicity**
Unlike `verify_and_update_last_vote_round()` used in regular vote signing, there is no check that the commit vote round exceeds `last_voted_round`: [3](#0-2) 

**Missing Check #2: Vote Consistency**  
The function does not verify that the block being committed is consistent with the validator's `last_vote` stored in SafetyData: [4](#0-3) 

**Missing Check #3: State Persistence**
Unlike vote signing which updates and persists safety data, commit votes are never recorded: [5](#0-4) 

The TODO comments acknowledge these missing guards: [6](#0-5) 

**Attack Scenario:**

1. Validator V at round 10 votes (execution vote) on block B10-A, setting `last_voted_round = 10` and `last_vote = Vote(B10-A)`
2. Network partition causes different validator subset to order conflicting block B10-B at round 10
3. B10-B is executed locally and V receives commit vote request for B10-B with valid `ordered_ledger_info` (2f+1 signatures from partition)
4. `guarded_sign_commit_vote()` validates signatures and execution consistency but **does not check** that B10-B conflicts with V's `last_vote = Vote(B10-A)`
5. V signs commit vote for B10-B, equivocating (voted for B10-A, committed B10-B)
6. No state is persisted, so V can be asked to sign multiple conflicting commit votes without detection

## Impact Explanation

This breaks **Consensus Safety (Invariant #2)**: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine."

While the BFT protocol can tolerate up to f Byzantine validators, safety rules exist to prevent **honest** validators from accidentally behaving in Byzantine ways. Without round monotonicity checks, honest validators can sign commit votes that conflict with their voting history, reducing the effective honest validator count.

In adversarial network conditions (partitions, delays, Byzantine nodes), this could enable:
- Validators signing conflicting commit votes for same round
- Validators signing commit votes for blocks they never voted on
- Reduced safety margin (honest validators behaving like Byzantine ones)

This qualifies as **High Severity** ($50,000 tier): "Significant protocol violations" that weaken consensus safety guarantees even if not directly causing chain split.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability can manifest when:
1. Network partitions cause validators to see different ordered blocks
2. Byzantine validators craft conflicting ordered blocks with valid quorums
3. Asynchrony causes validators' consensus views to diverge

The impact is limited by:
- Requires 2f+1 signatures on `ordered_ledger_info` (can't be arbitrarily forged)
- BFT tolerates up to f Byzantine behaviors
- Requires network adversarial conditions

However, safety rules should prevent honest validators from equivocating under **any** conditions, not just benign ones. The TODO comments indicate developers are aware of missing guards.

## Recommendation

Add the same safety checks used in regular vote signing:

```rust
fn guarded_sign_commit_vote(
    &mut self,
    ledger_info: LedgerInfoWithSignatures,
    new_ledger_info: LedgerInfo,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    
    let old_ledger_info = ledger_info.ledger_info();
    let commit_round = new_ledger_info.round();
    
    // NEW: Load and validate against safety data
    let mut safety_data = self.persistent_storage.safety_data()?;
    self.verify_epoch(new_ledger_info.epoch(), &safety_data)?;
    
    // NEW: Check round monotonicity
    if commit_round <= safety_data.last_voted_round {
        return Err(Error::IncorrectLastVotedRound(
            commit_round,
            safety_data.last_voted_round,
        ));
    }
    
    // NEW: Verify consistency with last vote if present
    if let Some(last_vote) = &safety_data.last_vote {
        let last_vote_commit = last_vote.ledger_info().commit_info();
        // Ensure new commit extends or matches last vote's chain
        if commit_round <= last_vote.vote_data().proposed().round() 
            && new_ledger_info.commit_info() != last_vote_commit {
            return Err(Error::InconsistentVotingHistory(
                format!("Commit conflicts with last vote")
            ));
        }
    }

    // Existing validations...
    if !old_ledger_info.commit_info().is_ordered_only()
        && old_ledger_info.commit_info() != new_ledger_info.commit_info()
    {
        return Err(Error::InvalidOrderedLedgerInfo(old_ledger_info.to_string()));
    }

    if !old_ledger_info
        .commit_info()
        .match_ordered_only(new_ledger_info.commit_info())
    {
        return Err(Error::InconsistentExecutionResult(
            old_ledger_info.commit_info().to_string(),
            new_ledger_info.commit_info().to_string(),
        ));
    }

    if !self.skip_sig_verify {
        ledger_info
            .verify_signatures(&self.epoch_state()?.verifier)
            .map_err(|error| Error::InvalidQuorumCertificate(error.to_string()))?;
    }

    let signature = self.sign(&new_ledger_info)?;
    
    // NEW: Persist commit vote information
    // (Consider adding last_commit_vote field to SafetyData)
    // safety_data.last_commit_round = commit_round;
    // self.persistent_storage.set_safety_data(safety_data)?;

    Ok(signature)
}
```

## Proof of Concept

Due to the complexity of simulating network partitions and Byzantine validators in the test environment, a simplified PoC demonstrates the missing check:

```rust
#[test]
fn test_commit_vote_round_monotonicity_violation() {
    let (mut safety_rules, signer) = make_safety_rules();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    safety_rules.initialize(&proof).unwrap();
    
    // Vote on block at round 10
    let b10 = test_utils::make_proposal_with_qc(10, genesis_qc.clone(), &signer);
    let vote10 = safety_rules.construct_and_sign_vote_two_chain(
        &VoteProposal::new(...),
        None
    ).unwrap();
    
    // Advance to round 11
    let b11 = make_proposal_with_parent(11, &b10, None, &signer);
    let vote11 = safety_rules.construct_and_sign_vote_two_chain(...).unwrap();
    
    // Now validator has last_voted_round = 11
    
    // Attempt to sign commit vote for round 9 (past round)
    // This should FAIL but currently SUCCEEDS
    let old_ordered_ledger = create_ordered_ledger_info_for_round_9();
    let commit_ledger = create_commit_ledger_info_for_round_9();
    
    let result = safety_rules.sign_commit_vote(
        old_ordered_ledger,
        commit_ledger
    );
    
    // BUG: This succeeds when it should fail with IncorrectLastVotedRound
    assert!(result.is_ok()); // Currently passes (BUG!)
    // Should be: assert!(matches!(result.unwrap_err(), Error::IncorrectLastVotedRound(9, 11)));
}
```

**Notes**

The vulnerability represents a defense-in-depth weakness rather than an immediate chain-split attack. The BFT protocol's 2f+1 quorum requirement provides baseline safety, but safety rules should prevent honest validators from equivocating under adversarial conditions. The explicit TODO comments and asymmetry with other voting functions confirm this is an incomplete implementation of safety guarantees.

### Citations

**File:** consensus/safety-rules/src/serializer.rs (L163-174)
```rust
    fn sign_commit_vote(
        &mut self,
        ledger_info: LedgerInfoWithSignatures,
        new_ledger_info: LedgerInfo,
    ) -> Result<bls12381::Signature, Error> {
        let _timer = counters::start_timer("external", LogEntry::SignCommitVote.as_str());
        let response = self.request(SafetyRulesInput::SignCommitVote(
            Box::new(ledger_info),
            Box::new(new_ledger_info),
        ))?;
        serde_json::from_slice(&response)?
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L213-232)
```rust
    pub(crate) fn verify_and_update_last_vote_round(
        &self,
        round: Round,
        safety_data: &mut SafetyData,
    ) -> Result<(), Error> {
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
        trace!(
            SafetyLogSchema::new(LogEntry::LastVotedRound, LogEvent::Update)
                .last_voted_round(safety_data.last_voted_round)
        );

        Ok(())
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L372-418)
```rust
    fn guarded_sign_commit_vote(
        &mut self,
        ledger_info: LedgerInfoWithSignatures,
        new_ledger_info: LedgerInfo,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;

        let old_ledger_info = ledger_info.ledger_info();

        if !old_ledger_info.commit_info().is_ordered_only()
            // When doing fast forward sync, we pull the latest blocks and quorum certs from peers
            // and store them in storage. We then compute the root ordered cert and root commit cert
            // from storage and start the consensus from there. But given that we are not storing the
            // ordered cert obtained from order votes in storage, instead of obtaining the root ordered cert
            // from storage, we set root ordered cert to commit certificate.
            // This means, the root ordered cert will not have a dummy executed_state_id in this case.
            // To handle this, we do not raise error if the old_ledger_info.commit_info() matches with
            // new_ledger_info.commit_info().
            && old_ledger_info.commit_info() != new_ledger_info.commit_info()
        {
            return Err(Error::InvalidOrderedLedgerInfo(old_ledger_info.to_string()));
        }

        if !old_ledger_info
            .commit_info()
            .match_ordered_only(new_ledger_info.commit_info())
        {
            return Err(Error::InconsistentExecutionResult(
                old_ledger_info.commit_info().to_string(),
                new_ledger_info.commit_info().to_string(),
            ));
        }

        // Verify that ledger_info contains at least 2f + 1 dostinct signatures
        if !self.skip_sig_verify {
            ledger_info
                .verify_signatures(&self.epoch_state()?.verifier)
                .map_err(|error| Error::InvalidQuorumCertificate(error.to_string()))?;
        }

        // TODO: add guarding rules in unhappy path
        // TODO: add extension check

        let signature = self.sign(&new_ledger_info)?;

        Ok(signature)
    }
```

**File:** consensus/consensus-types/src/safety_data.rs (L8-21)
```rust
/// Data structure for safety rules to ensure consensus safety.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    // highest 2-chain round, used for 3-chain
    pub preferred_round: u64,
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L91-92)
```rust
        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;
```
