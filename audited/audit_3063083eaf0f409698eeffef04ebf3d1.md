# Audit Report

## Title
Missing Preferred Round Validation in Voting Path Enables 2-Chain Safety Rule Bypass via Timeout Certificates

## Summary
The `verify_and_update_preferred_round` check, explicitly labeled as the "Second voting rule," is only enforced when leaders sign proposals but is completely absent from the validator voting path. This asymmetry allows Byzantine leaders to exploit timeout certificates to make honest validators vote on blocks extending from earlier chain points than their highest observed 2-chain, enabling conflicting blocks to be committed and violating consensus safety.

## Finding Description

The Aptos consensus implementation defines two voting rules to ensure safety:

1. **First voting rule** (`verify_and_update_last_vote_round`): Ensures validators only vote on strictly increasing rounds [1](#0-0) 

2. **Second voting rule** (`verify_and_update_preferred_round`): Ensures the proposal's QC one-chain round is at least as high as the validator's preferred_round (highest 2-chain round observed) [2](#0-1) 

The second voting rule is critical for preventing validators from voting on branches that "go backwards" relative to the highest 2-chain they've witnessed. The error `IncorrectPreferredRound` is returned when `one_chain_round < preferred_round` [3](#0-2) 

**Critical Asymmetry:**

When leaders sign proposals, both voting rules are enforced in `guarded_sign_proposal` [4](#0-3) 

However, when validators vote on proposals in `guarded_construct_and_sign_vote_two_chain`, the comment states "Two voting rules" but the implementation only applies the first rule and `safe_to_vote`, NOT the second voting rule [5](#0-4) 

The `safe_to_vote` function checks different conditions than `verify_and_update_preferred_round`. It permits blocks with timeout certificates as long as `round == next_round(tc_round) && qc_round >= hqc_round`, without validating against preferred_round [6](#0-5) 

**Attack Execution:**

1. Network progresses: genesis(0) → B1(1) → B2(2) → B3(3) → B4(4) → B5(5)
2. Honest validator V votes on all blocks through B5, establishing `preferred_round = 4` (from 2-chain B3→B4→B5)
3. B4 is committed via the certified 2-chain B3→B4→B5
4. Due to network partition, some validators form timeout certificate TC5 with `highest_hqc_round = 3`
5. Byzantine leader crafts B6_malicious: round=6, QC from B3 (round 3), timeout_cert=TC5
6. Honest validator V receives B6_malicious:
   - ✅ `safe_to_vote`: `6 == next_round(5) && 3 >= 3` → PASSES
   - ✅ `verify_and_update_last_vote_round`: `6 > 5` → PASSES  
   - ❌ **MISSING**: `verify_and_update_preferred_round` would check `3 >= 4` → SHOULD FAIL
7. V votes on B6_malicious despite QC round (3) < preferred_round (4)
8. B6 gets certified, then B7 extends B6 and gets certified, committing B6

**Result:** Both B4 (round 4) and B6 (round 6) become committed, but B6 extends B3 rather than B4, creating a fork in the committed chain after B3. This violates the fundamental consensus safety guarantee of a single canonical committed chain.

The RoundManager's `vote_block` method has no additional preferred_round validation before calling safety rules [7](#0-6) 

## Impact Explanation

**Critical Severity** - This vulnerability directly violates core consensus safety invariants:

- **Consensus Safety Violation**: Enables two conflicting blocks (B4 and B6) to be committed on divergent branches, breaking the "no-fork" guarantee that is fundamental to blockchain consensus
- **Double-Spending**: Transactions committed in B4 can be replaced by conflicting transactions in B6, enabling theft of funds
- **Chain Split**: Different validators commit different canonical chains, requiring manual intervention or hard fork to resolve
- **Loss of Funds**: Assets transferred in one branch can be double-spent in the conflicting branch

This meets the Aptos bug bounty Critical severity category: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**High Likelihood** - The attack is practical and exploitable in production:

1. **Low Attacker Requirements**: Requires only a single Byzantine validator elected as leader (< 1/3 threshold), which occurs naturally in rotation
2. **Realistic Preconditions**: Network partitions and timeouts occur organically in distributed systems, making timeout certificate formation with varied `highest_hqc_round` values a common occurrence
3. **No Collusion Needed**: A single Byzantine leader can exploit this independently
4. **Undetectable**: The malicious proposal passes all cryptographic validations, structural checks, and the `safe_to_vote` rule - only the missing semantic check would catch it
5. **Persistent**: Every round with a timeout certificate provides an exploitation opportunity

## Recommendation

Add the second voting rule check to the validator voting path. In `guarded_construct_and_sign_vote_two_chain`, call `verify_and_update_preferred_round` after `verify_and_update_last_vote_round`:

```rust
// Two voting rules
self.verify_and_update_last_vote_round(
    proposed_block.block_data().round(),
    &mut safety_data,
)?;

// ADD THIS: Second voting rule
self.verify_and_update_preferred_round(proposed_block.quorum_cert(), &mut safety_data)?;

self.safe_to_vote(proposed_block, timeout_cert)?;
```

This ensures both voting rules are consistently enforced in both the leader signing path and validator voting path.

## Proof of Concept

The vulnerability can be demonstrated by extending the existing test suite. The test `test_sign_proposal_with_early_preferred_round` validates that proposal signing correctly rejects early preferred rounds [8](#0-7) 

A parallel test for the voting path would show that `construct_and_sign_vote_two_chain` DOES NOT reject proposals with QC rounds earlier than preferred_round when accompanied by timeout certificates, confirming the vulnerability.

## Notes

The code structure provides clear evidence of this bug:
- The comment "Second voting rule" explicitly identifies the purpose of `verify_and_update_preferred_round`
- The voting path comment "Two voting rules" indicates both should be applied, but only the first is implemented
- The asymmetry between leader and validator paths (one has the check, the other doesn't) suggests this is an implementation oversight rather than intentional design
- The `safe_to_vote` function was likely intended to replace both voting rules but only covers the first rule's logic, missing the preferred_round invariant

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

**File:** consensus/safety-rules/src/safety_rules.rs (L212-232)
```rust
    /// First voting rule
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

**File:** consensus/safety-rules/src/error.rs (L17-18)
```rust
    #[error("Provided round, {0}, is incompatible with preferred round, {1}")]
    IncorrectPreferredRound(u64, u64),
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L76-84)
```rust
        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;

        // Record 1-chain data
        self.observe_qc(proposed_block.quorum_cert(), &mut safety_data);
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

**File:** consensus/src/round_manager.rs (L1500-1543)
```rust
    async fn vote_block(&mut self, proposed_block: Block) -> anyhow::Result<Vote> {
        let block_arc = self
            .block_store
            .insert_block(proposed_block)
            .await
            .context("[RoundManager] Failed to execute_and_insert the block")?;

        // Short circuit if already voted.
        ensure!(
            self.round_state.vote_sent().is_none(),
            "[RoundManager] Already vote on this round {}",
            self.round_state.current_round()
        );

        ensure!(
            !self.sync_only(),
            "[RoundManager] sync_only flag is set, stop voting"
        );

        let vote_proposal = block_arc.vote_proposal();
        let vote_result = self.safety_rules.lock().construct_and_sign_vote_two_chain(
            &vote_proposal,
            self.block_store.highest_2chain_timeout_cert().as_deref(),
        );
        let vote = vote_result.context(format!(
            "[RoundManager] SafetyRules Rejected {}",
            block_arc.block()
        ))?;
        if !block_arc.block().is_nil_block() {
            observe_block(block_arc.block().timestamp_usecs(), BlockStage::VOTED);
        }

        if block_arc.block().is_opt_block() {
            observe_block(
                block_arc.block().timestamp_usecs(),
                BlockStage::VOTED_OPT_BLOCK,
            );
        }

        self.storage
            .save_vote(&vote)
            .context("[RoundManager] Fail to persist last vote")?;

        Ok(vote)
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
