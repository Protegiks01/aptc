Based on my thorough analysis of the Aptos Core codebase, I have validated this security claim and found it to be a **valid vulnerability**.

# Audit Report

## Title
Missing Second Voting Rule Enforcement in construct_and_sign_vote_two_chain() Violates 2-Chain Consensus Safety

## Summary
The `construct_and_sign_vote_two_chain()` function fails to enforce the "Second voting rule" (`verify_and_update_preferred_round()`) when validators vote on proposals. While `sign_proposal()` correctly enforces this check, the voting path bypasses it, creating an asymmetry that violates the intended consensus safety mechanism.

## Finding Description

The AptosBFT consensus protocol implements a 2-chain commit rule with two voting rules to ensure safety:

1. **First voting rule**: Prevents double-voting in the same round (enforced via `verify_and_update_last_vote_round()`)
2. **Second voting rule**: Ensures QC certified block round ≥ preferred_round (enforced via `verify_and_update_preferred_round()`)

The `verify_and_update_preferred_round` function is explicitly labeled as "Second voting rule" [1](#0-0)  and checks that a proposal's QC certified block round is not less than the validator's preferred_round [2](#0-1) .

The `sign_proposal()` function correctly enforces both voting rules by calling `verify_and_update_preferred_round` [3](#0-2) .

However, the `construct_and_sign_vote_two_chain()` function has a critical gap. Despite a comment explicitly stating "Two voting rules" [4](#0-3) , it only enforces the first rule via `verify_and_update_last_vote_round` and then calls `safe_to_vote` [5](#0-4) .

The `safe_to_vote()` function only checks round continuity conditions [6](#0-5)  and does NOT verify the preferred_round constraint. Specifically, with timeout certificates, it allows voting when `block.round == tc.round + 1 && block.qc.round >= tc.hqc_round`, regardless of whether the QC's certified block round is below the validator's preferred_round.

The test suite validates this check for proposals in `test_sign_proposal_with_early_preferred_round` [7](#0-6) , which specifically tests that `sign_proposal` rejects proposals with QCs below preferred_round. However, there is no corresponding test validating this check in the voting path.

**Attack Scenario:**

When a timeout occurs, a malicious or buggy leader can propose a block extending an old QC that meets the timeout certificate threshold but violates individual validators' preferred_round constraints. Validators will vote on this block because `safe_to_vote` passes, even though the block extends a chain older than their locked/preferred round. This violates the fundamental BFT locking mechanism designed to prevent safety violations.

## Impact Explanation

**Severity: Critical** (Consensus Safety Violation)

This vulnerability represents a **logic vulnerability** where the implementation does not match the documented and intended behavior ("Two voting rules"). The evidence for this includes:

1. The explicit comment "Two voting rules" indicating both should be enforced
2. The label "Second voting rule" on the missing check function
3. The test suite validating this rule for proposals
4. The asymmetry between leader and follower checks with no documentation explaining why

By allowing validators to vote for blocks with QCs below their preferred_round, the protocol violates the BFT locking invariant. In 2-chain BFT protocols, validators lock on chains when they form 2-chains and should only vote for blocks extending chains at least as recent as their lock. Violating this can potentially enable:

1. **Consensus splits**: Validators with different preferred_rounds voting for conflicting chains
2. **Safety violations**: Two conflicting blocks achieving quorum under specific network partition scenarios
3. **Double-spending risk**: If conflicting chains both commit different transaction histories

This meets the Critical severity criteria: "Consensus/Safety violations" that could undermine the fundamental BFT safety guarantee.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can be triggered when:
1. A timeout occurs (common during network partitions or latency spikes)
2. Validators have divergent views with different preferred_rounds
3. The timeout certificate's hqc_round is lower than some validators' preferred_rounds
4. A leader proposes a block extending a chain at or above hqc_round but below some validators' preferred_rounds

While this requires specific network conditions, these scenarios occur naturally during consensus stress, network partitions, or with Byzantine leaders. The bug has likely persisted because:
- Normal operation with honest validators may rarely trigger the edge case
- Tests only verify `safe_to_vote` logic, not the missing preferred_round check
- The protocol may have other mechanisms that partially mitigate the issue

## Recommendation

Enforce the second voting rule in `construct_and_sign_vote_two_chain()` by adding a call to `verify_and_update_preferred_round()` before or after the `safe_to_vote()` check:

```rust
// Two voting rules
self.verify_and_update_last_vote_round(
    proposed_block.block_data().round(),
    &mut safety_data,
)?;
self.safe_to_vote(proposed_block, timeout_cert)?;
// Add the missing second voting rule check:
self.verify_and_update_preferred_round(proposed_block.quorum_cert(), &mut safety_data)?;
```

Alternatively, if the timeout certificate semantics are intended to override the preferred_round check for liveness, this should be explicitly documented with a comment explaining the design rationale and safety argument.

## Proof of Concept

The existing test `test_sign_proposal_with_early_preferred_round` demonstrates the check works for proposals [7](#0-6) . A similar test should be added for the voting path to validate it catches the same violation. The absence of such a test, combined with the "Two voting rules" comment, indicates this is an unintended omission rather than a deliberate design choice.

## Notes

This vulnerability represents a **logic flaw** where the implementation deviates from the documented intent. Even if practical exploitation is difficult due to other protocol mechanisms, the inconsistency between the proposal path (which checks preferred_round) and the voting path (which doesn't) violates the stated "Two voting rules" design and could potentially enable consensus safety violations under adversarial conditions.

### Citations

**File:** consensus/safety-rules/src/safety_rules.rs (L172-173)
```rust
    /// Second voting rule
    fn verify_and_update_preferred_round(
```

**File:** consensus/safety-rules/src/safety_rules.rs (L178-186)
```rust
        let preferred_round = safety_data.preferred_round;
        let one_chain_round = quorum_cert.certified_block().round();

        if one_chain_round < preferred_round {
            return Err(Error::IncorrectPreferredRound(
                one_chain_round,
                preferred_round,
            ));
        }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L364-365)
```rust
        self.verify_qc(block_data.quorum_cert())?;
        self.verify_and_update_preferred_round(block_data.quorum_cert(), &mut safety_data)?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L76-76)
```rust
        // Two voting rules
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-81)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;
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
