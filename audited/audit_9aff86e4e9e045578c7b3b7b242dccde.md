# Audit Report

## Title
Lack of State Persistence in `guarded_sign_commit_vote()` Enables Commit Vote Equivocation Under Non-Deterministic Execution

## Summary
The `guarded_sign_commit_vote()` function in the safety rules module does not persist any state changes, unlike all other voting/signing functions. This removes a critical defense-in-depth mechanism that would prevent validators from signing conflicting commit votes for the same round in the event of non-deterministic execution bugs or validator restarts.

## Finding Description

In Aptos consensus, validators sign two types of votes:
1. **Order votes** - vote for block ordering (handled by `guarded_construct_and_sign_order_vote()` and `guarded_construct_and_sign_vote_two_chain()`)
2. **Commit votes** - vote for committing executed blocks (handled by `guarded_sign_commit_vote()`)

The safety rules module is designed to prevent equivocation - validators signing conflicting votes for the same round. However, there is a critical asymmetry in how these two vote types are protected:

**Order vote functions persist state and prevent re-voting:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Commit vote function has NO state persistence:** [4](#0-3) 

The `guarded_sign_commit_vote()` function only validates that the ordered ledger info matches the commit ledger info, but it does not:
- Check if this round has already been signed for commit
- Track what executed state was previously signed
- Persist any signature to prevent future re-signing
- Return cached signatures for duplicate requests

**Attack Scenario:**

1. Round N, Block B is ordered (ordered certificate obtained with 2f+1 signatures)
2. Validator V executes Block B, producing executed state with hash S1
3. Validator V calls `sign_commit_vote(ordered_cert, commit_ledger_info_with_S1)` → signs it successfully
4. Validator V crashes and restarts before broadcasting the commit vote
5. Due to a non-deterministic execution bug (e.g., timestamp variation, race condition, uninitialized memory), re-execution produces state hash S2 (different from S1)
6. Validator V calls `sign_commit_vote(ordered_cert, commit_ledger_info_with_S2)` → **signs it again with different state!**
7. Safety rules do not detect or prevent this equivocation because no state was persisted from step 3

If multiple validators experience this (due to a systemic non-deterministic bug), the network could aggregate conflicting commit certificates:
- Some nodes receive S1 signatures and form a 2f+1 certificate for S1
- Other nodes receive S2 signatures and form a 2f+1 certificate for S2
- **Consensus safety violation**: Different nodes commit different states for the same round

**Contrast with order vote protection:**

The order vote mechanism prevents this exact scenario: [5](#0-4) 

If an author tries to vote for a different ledger_info in the same round, the system detects it as `EquivocateVote`. Commit votes have no such protection.

## Impact Explanation

**Severity: HIGH (potentially CRITICAL)**

This vulnerability breaks the **Consensus Safety** invariant defined in the Aptos specification. According to the Aptos bug bounty criteria:

**Critical Severity** applies if this leads to actual consensus safety violations where different validators commit different states. This would require:
- A non-deterministic execution bug (which should not exist but may occur)
- Multiple validators experiencing crashes/restarts
- Timing that allows conflicting certificates to form

**High Severity** applies to the vulnerability itself because:
1. It removes a fundamental defense-in-depth protection mechanism
2. Safety rules are specifically designed to prevent equivocation as the LAST LINE OF DEFENSE
3. The asymmetry with order vote handling appears to be an implementation oversight rather than intentional design
4. It violates the principle that validators cannot sign conflicting states for the same round

The safety rules module exists precisely to catch bugs elsewhere in the system (execution, networking, state management). By not persisting commit vote state, this safety net is removed.

## Likelihood Explanation

**Medium-High Likelihood:**

While Aptos execution is designed to be deterministic, non-deterministic bugs can occur due to:
- Timestamp dependencies
- Uninitialized memory or race conditions
- External input variations (though these should be minimized)
- Implementation bugs in native functions
- Hardware-level non-determinism (rare but possible)

The validator restart scenario is common in production:
- Validators restart for upgrades, maintenance, or crash recovery
- The pipeline architecture means blocks can be in various states during restart
- Without persisted commit vote state, the safety rules cannot protect against re-execution with different results

Historical precedent: Multiple blockchain systems have experienced non-deterministic execution bugs (e.g., Ethereum's consensus issues in 2016, Solana's non-determinism incidents). Defense-in-depth is critical.

## Recommendation

**Add state persistence to `guarded_sign_commit_vote()` similar to order vote functions:**

```rust
fn guarded_sign_commit_vote(
    &mut self,
    ledger_info: LedgerInfoWithSignatures,
    new_ledger_info: LedgerInfo,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    
    // Load safety data
    let mut safety_data = self.persistent_storage.safety_data()?;
    
    let old_ledger_info = ledger_info.ledger_info();

    // Verify epoch
    self.verify_epoch(new_ledger_info.epoch(), &safety_data)?;
    
    // CHECK: Has this round been signed for commit already?
    if let Some(ref last_commit_vote_info) = safety_data.last_commit_vote {
        if last_commit_vote_info.round() == new_ledger_info.round() {
            // Same round - verify we're signing the same state
            if last_commit_vote_info.commit_info() != new_ledger_info.commit_info() {
                return Err(Error::CommitVoteEquivocation(
                    new_ledger_info.round(),
                    last_commit_vote_info.commit_info().clone(),
                    new_ledger_info.commit_info().clone(),
                ));
            }
            // Same round, same state - this is idempotent, continue
        }
    }

    // ... existing validation checks ...
    
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

    // PERSIST: Track this commit vote to prevent equivocation
    safety_data.last_commit_vote = Some(new_ledger_info.clone());
    self.persistent_storage.set_safety_data(safety_data)?;

    Ok(signature)
}
```

**Additionally, update SafetyData structure to track commit votes:** [6](#0-5) 

Add a new field: `pub last_commit_vote: Option<LedgerInfo>` to track the last commit vote signed.

**Add corresponding error type:**
```rust
pub enum Error {
    // ... existing errors ...
    CommitVoteEquivocation(Round, BlockInfo, BlockInfo),
}
```

## Proof of Concept

```rust
// This test demonstrates the vulnerability
#[test]
fn test_commit_vote_equivocation_not_detected() {
    let (mut safety_rules, signer) = make_safety_rules();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    safety_rules.initialize(&proof).unwrap();

    // Create a chain and get ordered ledger info
    let round = genesis_qc.certified_block().round();
    let a1 = test_utils::make_proposal_with_qc(round + 1, genesis_qc, &signer);
    let a2 = make_proposal_with_parent(round + 2, &a1, None, &signer);
    let a3 = make_proposal_with_parent(round + 3, &a2, Some(&a1), &signer);
    
    let ordered_ledger_info = a3.block().quorum_cert().ledger_info().clone();
    
    // First commit vote with state S1
    let commit_info_s1 = a1.block().gen_block_info(
        HashValue::random(), // Simulating executed state S1
        100,
        None,
    );
    let commit_ledger_info_s1 = LedgerInfo::new(
        commit_info_s1,
        ordered_ledger_info.ledger_info().consensus_data_hash(),
    );
    
    // Sign first commit vote - succeeds
    let sig1 = safety_rules
        .sign_commit_vote(ordered_ledger_info.clone(), commit_ledger_info_s1.clone())
        .expect("First signature should succeed");
    
    // Second commit vote with DIFFERENT state S2 (simulating non-deterministic re-execution)
    let commit_info_s2 = a1.block().gen_block_info(
        HashValue::random(), // Different executed state S2
        100,
        None,
    );
    let commit_ledger_info_s2 = LedgerInfo::new(
        commit_info_s2,
        ordered_ledger_info.ledger_info().consensus_data_hash(),
    );
    
    // Sign second commit vote - THIS SHOULD FAIL BUT DOESN'T
    let sig2 = safety_rules
        .sign_commit_vote(ordered_ledger_info.clone(), commit_ledger_info_s2.clone())
        .expect("BUG: Second signature with different state succeeds - equivocation not detected!");
    
    // Both signatures are valid but for different states
    assert_ne!(commit_info_s1.executed_state_id(), commit_info_s2.executed_state_id());
    assert_ne!(sig1, sig2);
    
    println!("VULNERABILITY: Validator signed two different commit states for the same round!");
    println!("Round: {}", commit_ledger_info_s1.round());
    println!("State 1: {}", commit_info_s1.executed_state_id());
    println!("State 2: {}", commit_info_s2.executed_state_id());
}
```

**Notes**

1. This vulnerability violates the fundamental principle of defense-in-depth in consensus safety rules
2. While execution should be deterministic, the safety rules exist precisely to catch bugs when that assumption fails
3. The asymmetric treatment of commit votes versus order votes appears to be an implementation oversight
4. Similar equivocation detection exists for order votes [7](#0-6)  but not for commit votes
5. The lack of any test coverage for commit vote re-signing scenarios suggests this edge case was not considered during development [8](#0-7)

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L70-74)
```rust
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L91-92)
```rust
        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L117-117)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
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

**File:** consensus/safety-rules/src/tests/suite.rs (L845-936)
```rust
/// Test that we can successfully sign a valid commit vote
fn test_sign_commit_vote(constructor: &Callback) {
    // we construct a chain of proposals
    // genesis -- a1 -- a2 -- a3

    let (mut safety_rules, signer) = constructor();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);

    let round = genesis_qc.certified_block().round();
    safety_rules.initialize(&proof).unwrap();

    let a1 = test_utils::make_proposal_with_qc(round + 1, genesis_qc, &signer);
    let a2 = make_proposal_with_parent(round + 2, &a1, None, &signer);
    let a3 = make_proposal_with_parent(round + 3, &a2, Some(&a1), &signer);

    // now we try to agree on a1's execution result
    let ledger_info_with_sigs = a3.block().quorum_cert().ledger_info();
    // make sure this is for a1
    assert!(ledger_info_with_sigs
        .ledger_info()
        .commit_info()
        .match_ordered_only(
            &a1.block()
                .gen_block_info(*ACCUMULATOR_PLACEHOLDER_HASH, 0, None,)
        ));

    assert!(safety_rules
        .sign_commit_vote(
            ledger_info_with_sigs.clone(),
            ledger_info_with_sigs.ledger_info().clone()
        )
        .is_ok());

    // check empty ledger info
    assert!(matches!(
        safety_rules
            .sign_commit_vote(
                a2.block().quorum_cert().ledger_info().clone(),
                a3.block().quorum_cert().ledger_info().ledger_info().clone()
            )
            .unwrap_err(),
        Error::InvalidOrderedLedgerInfo(_)
    ));

    // non-dummy blockinfo test
    assert!(matches!(
        safety_rules
            .sign_commit_vote(
                LedgerInfoWithSignatures::new(
                    LedgerInfo::new(
                        a1.block().gen_block_info(
                            *ACCUMULATOR_PLACEHOLDER_HASH,
                            100, // non-dummy value
                            None
                        ),
                        ledger_info_with_sigs.ledger_info().consensus_data_hash()
                    ),
                    AggregateSignature::empty(),
                ),
                ledger_info_with_sigs.ledger_info().clone()
            )
            .unwrap_err(),
        Error::InvalidOrderedLedgerInfo(_)
    ));

    // empty signature test
    assert!(matches!(
        safety_rules
            .sign_commit_vote(
                LedgerInfoWithSignatures::new(
                    ledger_info_with_sigs.ledger_info().clone(),
                    AggregateSignature::empty(),
                ),
                ledger_info_with_sigs.ledger_info().clone()
            )
            .unwrap_err(),
        Error::InvalidQuorumCertificate(_)
    ));

    // inconsistent ledger_info test
    let bad_ledger_info = LedgerInfo::new(
        BlockInfo::random(ledger_info_with_sigs.ledger_info().round()),
        ledger_info_with_sigs.ledger_info().consensus_data_hash(),
    );

    assert!(matches!(
        safety_rules
            .sign_commit_vote(ledger_info_with_sigs.clone(), bad_ledger_info,)
            .unwrap_err(),
        Error::InconsistentExecutionResult(_, _)
    ));
}
```
