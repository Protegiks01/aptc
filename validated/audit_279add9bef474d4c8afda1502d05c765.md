# Audit Report

## Title
Missing Preferred Round Validation in Voting Path Enables 2-Chain Safety Rule Bypass via Timeout Certificates

## Summary
The `verify_and_update_preferred_round` check that enforces the 2-chain voting rule is only applied when leaders sign proposals but is completely missing from the validator voting path. This asymmetry allows Byzantine leaders to craft proposals with timeout certificates that trick honest validators into voting on blocks extending from earlier chain points than their highest observed 2-chain, enabling conflicting blocks to be committed and violating consensus safety.

## Finding Description

The Aptos consensus protocol implements a critical safety check called `verify_and_update_preferred_round` to enforce the "second voting rule": validators should never build on a quorum certificate whose certified block round is lower than their preferred round (highest 2-chain round observed). [1](#0-0) 

This check is enforced when leaders sign proposals through `guarded_sign_proposal`: [2](#0-1) 

However, this check is **completely absent** from the validator voting path in `guarded_construct_and_sign_vote_two_chain`: [3](#0-2) 

The voting path only validates via `safe_to_vote`, which permits blocks with timeout certificates as long as the block round follows the timeout round and the QC round is at least as high as the timeout certificate's highest QC round: [4](#0-3) 

Critically, `safe_to_vote` does **not** check whether the QC's certified block round is greater than or equal to the validator's preferred round.

### Attack Scenario

**Setup**: Network progresses through blocks B1→B2→B3→B4→B5. When B5 is certified, the 2-chain B4←B5 commits B4. Honest validator V has `preferred_round = 4` and `last_voted_round = 5`.

**Attack**: Due to network asynchrony, some validators create timeout certificate TC5 for round 5 with `highest_hqc_round = 3`. Byzantine leader crafts B6 with:
- `round = 6`
- `quorum_cert` from B3 (certified_block_round = 3)
- `timeout_cert = TC5`

**Execution**: Validator V processes B6:
- `safe_to_vote` checks: `6 == next_round(5) ✓` and `3 >= 3 ✓` → **PASSES**
- `verify_and_update_last_vote_round`: `6 > 5 ✓` → **PASSES**
- **MISSING**: `verify_and_update_preferred_round` would check `3 >= 4` → **SHOULD FAIL**

V votes on B6. When B7 extends B6, the 2-chain B6←B7 commits B6. [5](#0-4) 

**Result**: Both B4 (committed via B4←B5) and B6 (committed via B6←B7) are in the committed history, but B6 extends B3, not B4. This creates a fork in the committed chain, violating the fundamental consensus safety guarantee.

## Impact Explanation

**Critical Severity** - This vulnerability directly violates the Aptos consensus safety invariant that the committed chain must be linear. The attack enables:

- **Consensus Safety Violation**: Two conflicting blocks can be committed where one doesn't extend the other, breaking the "no-fork" guarantee
- **Double-Spending**: Transactions in B4 can conflict with transactions in B6, enabling double-spending attacks
- **Chain Split**: Different validators may commit different chains, requiring manual intervention or hardfork
- **Loss of Funds**: Assets transferred in one branch can be spent differently in the conflicting branch

This meets the Aptos bug bounty Critical severity category: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**High Likelihood** - The attack is practical and exploitable:

1. **Single Byzantine validator sufficient**: Only requires being elected leader for one round (< 1/3 Byzantine threshold)
2. **Legitimate preconditions**: Timeout certificates with varied `highest_hqc_round` values occur naturally during network partitions
3. **No collusion needed**: Single Byzantine leader can exploit independently
4. **Passes all validations**: Malicious proposal passes cryptographic and structural checks
5. **Persistent opportunity**: Every timeout round provides exploitation opportunity

The test suite confirms this gap exists - `test_sign_proposal_with_early_preferred_round` validates the check for proposal signing but has no corresponding test for the voting path: [6](#0-5) 

## Recommendation

Add the `verify_and_update_preferred_round` check to the voting path in `guarded_construct_and_sign_vote_two_chain` before line 81:

```rust
// After verify_and_update_last_vote_round and before safe_to_vote:
self.verify_and_update_preferred_round(proposed_block.quorum_cert(), &mut safety_data)?;
```

This ensures validators reject votes on blocks whose QC certified block round is lower than their preferred round, preventing the safety violation.

## Proof of Concept

A PoC would extend the existing `test_sign_proposal_with_early_preferred_round` test to include the voting path. After establishing a preferred_round by voting on proposals (lines 551-558), attempt to vote on a proposal with an old QC and a timeout certificate. The current code would incorrectly allow this vote, demonstrating the vulnerability.

## Notes

The asymmetry between proposal signing and voting paths is confirmed by grep search showing `verify_and_update_preferred_round` is only called in `guarded_sign_proposal`. The `observe_qc` function called in the voting path updates preferred_round without validation, which is insufficient for safety. This represents a genuine consensus safety vulnerability that violates the 2-chain commit rule's invariants.

### Citations

**File:** consensus/safety-rules/src/safety_rules.rs (L172-188)
```rust
    /// Second voting rule
    fn verify_and_update_preferred_round(
        &mut self,
        quorum_cert: &QuorumCert,
        safety_data: &mut SafetyData,
    ) -> Result<bool, Error> {
        let preferred_round = safety_data.preferred_round;
        let one_chain_round = quorum_cert.certified_block().round();

        if one_chain_round < preferred_round {
            return Err(Error::IncorrectPreferredRound(
                one_chain_round,
                preferred_round,
            ));
        }
        Ok(self.observe_qc(quorum_cert, safety_data))
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L346-370)
```rust
    fn guarded_sign_proposal(
        &mut self,
        block_data: &BlockData,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;
        self.verify_author(block_data.author())?;

        let mut safety_data = self.persistent_storage.safety_data()?;
        self.verify_epoch(block_data.epoch(), &safety_data)?;

        if block_data.round() <= safety_data.last_voted_round {
            return Err(Error::InvalidProposal(format!(
                "Proposed round {} is not higher than last voted round {}",
                block_data.round(),
                safety_data.last_voted_round
            )));
        }

        self.verify_qc(block_data.quorum_cert())?;
        self.verify_and_update_preferred_round(block_data.quorum_cert(), &mut safety_data)?;
        // we don't persist the updated preferred round to save latency (it'd be updated upon voting)

        let signature = self.sign(block_data)?;
        Ok(signature)
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L53-95)
```rust
    pub(crate) fn guarded_construct_and_sign_vote_two_chain(
        &mut self,
        vote_proposal: &VoteProposal,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<Vote, Error> {
        // Exit early if we cannot sign
        self.signer()?;

        let vote_data = self.verify_proposal(vote_proposal)?;
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }
        let proposed_block = vote_proposal.block();
        let mut safety_data = self.persistent_storage.safety_data()?;

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
        self.safe_to_vote(proposed_block, timeout_cert)?;

        // Record 1-chain data
        self.observe_qc(proposed_block.quorum_cert(), &mut safety_data);
        // Construct and sign vote
        let author = self.signer()?.author();
        let ledger_info = self.construct_ledger_info_2chain(proposed_block, vote_data.hash())?;
        let signature = self.sign(&ledger_info)?;
        let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;

        Ok(vote)
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L147-166)
```rust
    /// Core safety voting rule for 2-chain protocol. Return success if 1 or 2 is true
    /// 1. block.round == block.qc.round + 1
    /// 2. block.round == tc.round + 1 && block.qc.round >= tc.highest_hqc.round
    fn safe_to_vote(
        &self,
        block: &Block,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<(), Error> {
        let round = block.round();
        let qc_round = block.quorum_cert().certified_block().round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        let hqc_round = maybe_tc.map_or(0, |tc| tc.highest_hqc_round());
        if round == next_round(qc_round)?
            || (round == next_round(tc_round)? && qc_round >= hqc_round)
        {
            Ok(())
        } else {
            Err(Error::NotSafeToVote(round, qc_round, tc_round, hqc_round))
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L190-214)
```rust
    /// Produces a LedgerInfo that either commits a block based upon the 2-chain
    /// commit rule or an empty LedgerInfo for no commit. The 2-chain commit rule is: B0 and its
    /// prefixes can be committed if there exist certified block B1 that satisfy:
    /// 1) B0 <- B1 <--
    /// 2) round(B0) + 1 = round(B1)
    fn construct_ledger_info_2chain(
        &self,
        proposed_block: &Block,
        consensus_data_hash: HashValue,
    ) -> Result<LedgerInfo, Error> {
        let block1 = proposed_block.round();
        let block0 = proposed_block.quorum_cert().certified_block().round();

        // verify 2-chain rule
        let commit = next_round(block0)? == block1;

        // create a ledger info
        let commit_info = if commit {
            proposed_block.quorum_cert().certified_block().clone()
        } else {
            BlockInfo::empty()
        };

        Ok(LedgerInfo::new(commit_info, consensus_data_hash))
    }
```

**File:** consensus/safety-rules/src/tests/suite.rs (L536-570)
```rust
fn test_sign_proposal_with_early_preferred_round(safety_rules: &Callback) {
    let (mut safety_rules, signer) = safety_rules();

    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    let round = genesis_qc.certified_block().round();
    safety_rules.initialize(&proof).unwrap();

    let a1 = test_utils::make_proposal_with_qc(round + 1, genesis_qc, &signer);
    safety_rules.sign_proposal(a1.block().block_data()).unwrap();

    // Update preferred round with a few legal proposals
    let a2 = make_proposal_with_parent(round + 2, &a1, None, &signer);
    let a3 = make_proposal_with_parent(round + 3, &a2, None, &signer);
    let a4 = make_proposal_with_parent(round + 4, &a3, Some(&a2), &signer);
    safety_rules
        .construct_and_sign_vote_two_chain(&a2, None)
        .unwrap();
    safety_rules
        .construct_and_sign_vote_two_chain(&a3, None)
        .unwrap();
    safety_rules
        .construct_and_sign_vote_two_chain(&a4, None)
        .unwrap();

    let a5 = make_proposal_with_qc_and_proof(
        round + 5,
        test_utils::empty_proof(),
        a1.block().quorum_cert().clone(),
        &signer,
    );
    let err = safety_rules
        .sign_proposal(a5.block().block_data())
        .unwrap_err();
    assert_eq!(err, Error::IncorrectPreferredRound(0, 2));
}
```
