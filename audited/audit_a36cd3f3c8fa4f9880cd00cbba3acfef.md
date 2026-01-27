# Audit Report

## Title
Missing Safety Rules in Commit Vote Signing Allows Validator Equivocation on Consensus Commits

## Summary
The `guarded_sign_commit_vote` function in `consensus/safety-rules/src/safety_rules.rs` lacks critical safety checks that prevent validators from signing multiple conflicting commit votes for the same or earlier rounds, violating BFT consensus safety guarantees. This allows potential validator equivocation that could contribute to chain forks.

## Finding Description

The `sign_commit_vote` function in the safety rules module is responsible for validators signing commit votes after block execution. However, unlike other signing functions in the same module, it lacks essential safety checks to prevent equivocation. [1](#0-0) 

The function delegates to `guarded_sign_commit_vote` in the actual SafetyRules implementation: [2](#0-1) 

**Critical Missing Validations:**

1. **No Round Tracking**: Unlike `guarded_construct_and_sign_vote_two_chain`, which verifies and updates `last_voted_round` to prevent voting on the same round twice, `guarded_sign_commit_vote` performs no such check. [3](#0-2) 

2. **No State Persistence**: The voting function persists the vote to prevent re-voting, but commit signing does not: [4](#0-3) 

3. **Explicit TODOs Acknowledge Missing Checks**: The code contains TODO comments indicating missing validation: [5](#0-4) 

**Current Validation Only Checks Consistency Between Parameters:**

The existing validation only ensures the `ledger_info` (ordered proof) and `new_ledger_info` (commit info) represent the same block at different execution stages: [6](#0-5) 

This uses `match_ordered_only` to verify the ordered-only fields match: [7](#0-6) 

**However**, there is no validation that:
- The commit extends properly from previously committed blocks
- The validator hasn't already signed a commit for this round
- The round/version is greater than previously signed commits

**SafetyData Structure Has No Commit Tracking:** [8](#0-7) 

The SafetyData tracks `last_voted_round` for voting but has no equivalent tracking for commit signing.

## Impact Explanation

This vulnerability represents a **Critical Severity** consensus safety violation under the Aptos bug bounty program criteria:

1. **Consensus Safety Violation**: The fundamental BFT safety guarantee is that validators cannot equivocate. This bug breaks that guarantee for commit signing, allowing validators to sign conflicting commits.

2. **Potential Chain Forks**: If multiple validators (whether through bugs or Byzantine behavior) sign conflicting commits, it could lead to chain forks where different validators commit to different blocks at the same round.

3. **Weakened Byzantine Tolerance**: While BFT consensus tolerates up to f Byzantine validators (< 1/3), this bug makes it easier for Byzantine validators to cause safety violations by removing the safety rules that should prevent commit equivocation.

4. **Defense-in-Depth Failure**: Safety rules are designed to be the last line of defense against equivocation. Even if upper consensus layers have bugs, safety rules should prevent signing conflicting states. This bug removes that protection layer.

The explicit TODO comments acknowledging missing "guarding rules" and "extension check" confirm this is a known gap in the safety implementation.

## Likelihood Explanation

**Moderate to High Likelihood** of exploitation under certain conditions:

1. **Byzantine Validator Scenario**: A Byzantine validator could deliberately attempt to sign conflicting commits. The missing safety checks make this trivial to execute.

2. **Software Bug Scenario**: If there's a bug in the buffer manager or consensus logic that causes a validator to attempt signing multiple commits, the safety rules won't prevent it.

3. **Network Partition Scenario**: During network partitions or under network manipulation attacks, a validator might receive conflicting consensus information. Safety rules should prevent equivocation in this case but currently don't.

4. **Race Condition Scenario**: Concurrent execution paths could potentially lead to multiple signing attempts for the same round if upper layers have race conditions.

The vulnerability doesn't require active exploitation but rather represents a missing safety net that should be present in any BFT implementation.

## Recommendation

Implement comprehensive safety checks in `guarded_sign_commit_vote` similar to those in `guarded_construct_and_sign_vote_two_chain`:

```rust
fn guarded_sign_commit_vote(
    &mut self,
    ledger_info: LedgerInfoWithSignatures,
    new_ledger_info: LedgerInfo,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    
    let old_ledger_info = ledger_info.ledger_info();
    let mut safety_data = self.persistent_storage.safety_data()?;
    
    // Verify epoch matches
    self.verify_epoch(new_ledger_info.epoch(), &safety_data)?;
    
    // Verify the commit extends the chain properly
    let commit_round = new_ledger_info.round();
    let commit_version = new_ledger_info.version();
    
    // Check against last committed state
    if commit_round <= safety_data.last_voted_round {
        return Err(Error::IncorrectLastVotedRound(
            commit_round,
            safety_data.last_voted_round,
        ));
    }
    
    // Existing validation checks
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
    
    // Verify signatures
    if !self.skip_sig_verify {
        ledger_info
            .verify_signatures(&self.epoch_state()?.verifier)
            .map_err(|error| Error::InvalidQuorumCertificate(error.to_string()))?;
    }
    
    // Extension check: verify this commit properly extends the chain
    // This could include checking that commit_version > last_committed_version
    // and that the parent relationships are valid
    
    let signature = self.sign(&new_ledger_info)?;
    
    // Update and persist safety data to prevent re-signing
    safety_data.last_voted_round = commit_round;
    self.persistent_storage.set_safety_data(safety_data)?;
    
    Ok(signature)
}
```

Additionally, extend `SafetyData` to track commit-specific state:

```rust
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    pub last_committed_round: u64,  // Add this
    pub last_committed_version: u64, // Add this
    pub preferred_round: u64,
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    pub highest_timeout_round: u64,
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_commit_vote_equivocation() {
    // Setup
    let (storage, mut safety_rules) = test_utils::make_safety_rules();
    
    // Create two different ledger infos for the same round
    let round = 100;
    let epoch = 1;
    
    let block_info_1 = BlockInfo::new(
        epoch,
        round,
        HashValue::random(),
        *ACCUMULATOR_PLACEHOLDER_HASH,
        0,
        1000000,
        None,
    );
    
    let block_info_2 = BlockInfo::new(
        epoch,
        round,
        HashValue::random(), // Different block ID
        *ACCUMULATOR_PLACEHOLDER_HASH,
        0,
        1000000,
        None,
    );
    
    let ordered_li_1 = LedgerInfo::new(block_info_1.clone(), HashValue::zero());
    let ordered_proof_1 = create_quorum_cert(&ordered_li_1);
    
    let ordered_li_2 = LedgerInfo::new(block_info_2.clone(), HashValue::zero());
    let ordered_proof_2 = create_quorum_cert(&ordered_li_2);
    
    // Create commit ledger infos with execution results
    let mut executed_block_info_1 = block_info_1.clone();
    executed_block_info_1.set_executed_state_id(HashValue::random());
    let commit_li_1 = LedgerInfo::new(executed_block_info_1, HashValue::zero());
    
    let mut executed_block_info_2 = block_info_2.clone();
    executed_block_info_2.set_executed_state_id(HashValue::random());
    let commit_li_2 = LedgerInfo::new(executed_block_info_2, HashValue::zero());
    
    // Sign first commit - should succeed
    let sig1 = safety_rules.sign_commit_vote(ordered_proof_1, commit_li_1);
    assert!(sig1.is_ok(), "First commit signature should succeed");
    
    // Sign conflicting commit for same round - should FAIL but currently SUCCEEDS
    let sig2 = safety_rules.sign_commit_vote(ordered_proof_2, commit_li_2);
    
    // This assertion SHOULD pass (preventing equivocation) but will FAIL
    // because the safety rules don't check for duplicate round signing
    assert!(sig2.is_err(), "Second commit signature should fail due to equivocation");
    
    // In the current implementation, sig2.is_ok() == true, demonstrating the vulnerability
}
```

## Notes

This vulnerability specifically affects the decoupled execution pipeline where commit voting is separated from the initial block voting. The missing safety checks create a gap in the defense-in-depth security model that BFT consensus systems rely on. While upper layers of the consensus protocol should prevent most scenarios where this could be triggered, safety rules exist precisely to catch edge cases, bugs, and Byzantine behavior that upper layers might miss.

The explicit TODO comments in the code indicate this is a known incomplete implementation, making it a high-priority issue to address before production deployment under adversarial conditions.

### Citations

**File:** consensus/src/metrics_safety_rules.rs (L139-150)
```rust
    fn sign_commit_vote(
        &mut self,
        ledger_info: LedgerInfoWithSignatures,
        new_ledger_info: LedgerInfo,
    ) -> Result<bls12381::Signature, Error> {
        self.retry(|inner| {
            monitor!(
                "safety_rules",
                inner.sign_commit_vote(ledger_info.clone(), new_ledger_info.clone())
            )
        })
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-80)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L91-92)
```rust
        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** types/src/block_info.rs (L196-204)
```rust
    pub fn match_ordered_only(&self, executed_block_info: &BlockInfo) -> bool {
        self.epoch == executed_block_info.epoch
            && self.round == executed_block_info.round
            && self.id == executed_block_info.id
            && (self.timestamp_usecs == executed_block_info.timestamp_usecs
            // executed block info has changed its timestamp because it's a reconfiguration suffix
                || (self.timestamp_usecs > executed_block_info.timestamp_usecs
                    && executed_block_info.has_reconfiguration()))
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
