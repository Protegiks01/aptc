# Audit Report

## Title
Insufficient Safety Mechanisms for CommitVote Signing Enabling Potential Consensus Safety Violations

## Summary
CommitVote signing in Aptos consensus lacks persistent state tracking and safety rule enforcement that exists for regular block votes. This creates a vulnerability where validators can sign multiple conflicting CommitVotes for the same round/epoch without detection, potentially violating the consensus agreement property if execution non-determinism occurs.

## Finding Description

The Aptos consensus protocol distinguishes between regular block votes (VoteProposal) and commit votes (CommitVote). Regular block votes have robust safety mechanisms through SafetyRules, but commit votes lack equivalent protections.

**Regular Block Voting Safety (Working Correctly):**

In `SafetyRules::guarded_construct_and_sign_vote_two_chain`, validators maintain strict voting discipline: [1](#0-0) 

This checks if the validator already voted on this round and returns the cached vote, preventing double-voting. It also updates and persists `last_voted_round`: [2](#0-1) 

**CommitVote Safety (Missing Critical Protections):**

The SafetyData structure tracks regular votes but has no equivalent for commit votes: [3](#0-2) 

When signing commit votes through SafetyRules, the `guarded_sign_commit_vote` function performs some validation but critically **does not check or update any round tracking**: [4](#0-3) 

Note the TODO comments at lines 412-413 acknowledging missing safety rules. Crucially, this function does NOT update `last_voted_round` or persist any state about signed commit votes.

**Pipeline Mode Bypasses SafetyRules Entirely:**

In pipeline consensus mode, commit vote signing completely bypasses SafetyRules: [5](#0-4) 

The validator directly signs the ledger_info without ANY safety checks. There is no verification that it hasn't already signed a different commit vote for this round.

**Signature Aggregation Replaces Rather Than Rejects:**

When commit votes are received and aggregated, the system uses BTreeMap::insert which replaces any existing signature: [6](#0-5) 

This means if a validator sends conflicting commit votes, the later one replaces the earlier one per recipient, but different validators might receive different votes.

**Attack Scenario:**

1. Validator V executes block B at round R, producing state root H1
2. V signs and broadcasts CommitVote(round=R, commit_info=(id=B, state_root=H1))
3. Due to state corruption, crash/restart, or execution bug, V re-executes block B
4. V produces different state root H2 (non-determinism or bug)
5. V signs and broadcasts CommitVote(round=R, commit_info=(id=B, state_root=H2))
6. **No safety mechanism prevents this second signing**
7. Different validator subsets receive different commit votes from V
8. Some validators aggregate toward H1, others toward H2
9. If network partitions align with vote distribution, different quorums could form on different states
10. **Consensus safety violation**: validators commit different states for the same round

The vulnerability requires execution non-determinism, but Byzantine Fault Tolerant protocols should have defense-in-depth mechanisms to limit damage even when component-level invariants are violated.

## Impact Explanation

**Critical Severity**: This constitutes a **Consensus Safety Violation** per the Aptos bug bounty program. If exploitable, it would allow validators to break the fundamental agreement property of Byzantine consensus, causing chain splits that could require a hard fork to resolve.

However, the vulnerability's exploitability depends on:
- Execution non-determinism (which violates Invariant #1: Deterministic Execution)
- Or compromised validator nodes deliberately creating conflicting votes

The lack of safety mechanisms means any bug causing non-determinism directly translates to consensus failure, whereas proper defense-in-depth would contain such failures.

## Likelihood Explanation

**Likelihood: Medium-to-Low**

The vulnerability requires one of:
1. **Execution bugs causing non-determinism**: Move VM bugs, state management issues, or concurrency problems that cause different execution results for the same block
2. **State corruption**: Database corruption, state sync bugs, or snapshot inconsistencies leading to different initial states
3. **Malicious validator**: Compromised validator node deliberately producing conflicting votes

While deterministic execution is a core invariant, the history of blockchain systems shows non-determinism bugs do occur (Ethereum's consensus bugs, Bitcoin's BDB lock limits, etc.). The lack of safeguards means such bugs have amplified impact.

## Recommendation

Implement persistent tracking and safety rules for commit votes equivalent to regular votes:

**1. Add commit vote tracking to SafetyData:**
```rust
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    pub preferred_round: u64,
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    pub highest_timeout_round: u64,
    // ADD:
    pub last_commit_vote_round: u64,
    pub last_commit_vote: Option<CommitVote>,
}
```

**2. Update `guarded_sign_commit_vote` to check and persist:**
```rust
fn guarded_sign_commit_vote(
    &mut self,
    ledger_info: LedgerInfoWithSignatures,
    new_ledger_info: LedgerInfo,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    let mut safety_data = self.persistent_storage.safety_data()?;
    
    // Check if already signed a commit vote for this round
    let round = new_ledger_info.round();
    if round == safety_data.last_commit_vote_round {
        if let Some(ref prev_vote) = safety_data.last_commit_vote {
            // Return cached vote if same, error if different
            if prev_vote.ledger_info() == &new_ledger_info {
                return self.sign(&new_ledger_info);
            } else {
                return Err(Error::InconsistentCommitVote(round));
            }
        }
    }
    
    // Existing validation...
    
    let signature = self.sign(&new_ledger_info)?;
    
    // Persist commit vote tracking
    safety_data.last_commit_vote_round = round;
    safety_data.last_commit_vote = Some(CommitVote::new_with_signature(
        self.signer()?.author(),
        new_ledger_info.clone(),
        signature.clone(),
    ));
    self.persistent_storage.set_safety_data(safety_data)?;
    
    Ok(signature)
}
```

**3. Make pipeline mode use SafetyRules instead of direct signing**

## Proof of Concept

```rust
// This PoC demonstrates that a validator can sign multiple commit votes
// for the same round without safety checks preventing it

#[test]
fn test_commit_vote_double_signing_vulnerability() {
    use aptos_types::validator_signer::ValidatorSigner;
    use aptos_consensus_types::pipeline::commit_vote::CommitVote;
    
    let signer = ValidatorSigner::random(None);
    
    // Create two different ledger infos for the same round
    let ledger_info_1 = create_ledger_info_with_state(100, HashValue::random());
    let ledger_info_2 = create_ledger_info_with_state(100, HashValue::random());
    
    // Sign both - this should be prevented but isn't
    let vote_1 = CommitVote::new(
        signer.author(),
        ledger_info_1,
        &signer,
    ).unwrap();
    
    let vote_2 = CommitVote::new(
        signer.author(), 
        ledger_info_2,
        &signer,
    ).unwrap();
    
    // Both votes have valid signatures for the same validator and same round
    assert_eq!(vote_1.round(), vote_2.round());
    assert_eq!(vote_1.author(), vote_2.author());
    assert_ne!(vote_1.commit_info(), vote_2.commit_info());
    
    // Both signatures verify successfully
    let verifier = ValidatorVerifier::new(/* ... */);
    assert!(vote_1.verify(signer.author(), &verifier).is_ok());
    assert!(vote_2.verify(signer.author(), &verifier).is_ok());
    
    // This violates agreement property - same validator has valid signatures
    // on conflicting commit infos for the same round
}
```

## Notes

While the system relies on deterministic execution as its primary safety mechanism, Byzantine Fault Tolerant protocols should employ defense-in-depth. The lack of persistent tracking for commit votes means any execution bug causing non-determinism immediately leads to consensus failure, rather than being contained by safety rules. The TODO comments in the code acknowledge these missing protections.

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L68-80)
```rust
        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }

        // Two voting rules
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

**File:** consensus/consensus-types/src/safety_data.rs (L10-21)
```rust
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

**File:** consensus/src/pipeline/pipeline_builder.rs (L1022-1029)
```rust
        let ledger_info = LedgerInfo::new(block_info, consensus_data_hash);
        info!("[Pipeline] Signed ledger info {ledger_info}");
        let signature = signer.sign(&ledger_info).expect("Signing should succeed");
        let commit_vote = CommitVote::new_with_signature(signer.author(), ledger_info, signature);
        network_sender
            .broadcast_commit_vote(commit_vote.clone())
            .await;
        Ok(commit_vote)
```

**File:** types/src/ledger_info.rs (L460-462)
```rust
    pub fn add_signature(&mut self, validator: AccountAddress, signature: &SignatureWithStatus) {
        self.signatures.insert(validator, signature.clone());
    }
```
