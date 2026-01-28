# Audit Report

## Title
Proposal Well-Formedness Check Missing Timeout Certificate HQC Validation Causing Liveness Attacks

## Summary
The `verify_well_formed()` function in `ProposalMsg` validates that proposals follow timeout certificates but fails to check that the proposal's QC round is at least as high as the timeout certificate's highest HQC round. This allows malicious proposers to create structurally valid proposals that cannot gather votes, causing repeated round timeouts and validator resource waste.

## Finding Description

The AptosBFT 2-chain consensus protocol allows proposals to advance rounds based on either a Quorum Certificate (QC) or a Timeout Certificate (TC). The safety voting rule requires that when following a TC, the proposal's QC must be at least as high as the TC's highest HQC round. [1](#0-0) 

However, the proposal well-formedness check only validates that the proposal round equals the maximum of the QC round and TC round plus one, without checking the HQC constraint: [2](#0-1) 

The `highest_timeout_round()` method returns the timeout round itself, not the HQC round within the timeout: [3](#0-2) 

The timeout certificate structure confirms that `highest_hqc_round()` returns the QC round contained in the timeout, which is distinct from the timeout round: [4](#0-3) 

**Attack Scenario:**

1. A timeout certificate exists for round 100 with `TC.highest_hqc_round() = 95`
2. Malicious proposer (when their turn comes) creates a proposal for round 101 with a QC certifying round 90
3. The proposal passes `verify_well_formed()`: `101 - 1 == max(90, 100) = 100` ✓
4. Honest validators receive the proposal and attempt to vote
5. The voting safety check fails: `101 != 90 + 1` AND `!(101 == 100 + 1 AND 90 >= 95)` ✗
6. No validator can vote, the round times out
7. The malicious proposer can repeat this attack in subsequent rounds when they are the proposer

The proposal verification happens during network message processing: [5](#0-4) 

When validators attempt to vote, they call `vote_block()` which invokes the safety rules: [6](#0-5) 

This leads to the `safe_to_vote()` check that enforces the HQC constraint: [7](#0-6) 

When the safety check fails, an error is returned: [8](#0-7) 

## Impact Explanation

This vulnerability enables **liveness attacks** where a malicious proposer can create proposals that pass validation but are unvotable, causing:

- **Validator Node Slowdowns**: Honest validators waste resources processing, executing, and attempting to vote on invalid proposals
- **Protocol Violations**: Proposals violate the core safety voting rules while passing well-formedness checks
- **Repeated Round Timeouts**: Each malicious proposal forces a timeout (typically 1-2 seconds initially, increasing exponentially)

This qualifies as **High Severity** per the Aptos bug bounty program criteria: "Validator node slowdowns, Significant protocol violations."

The attack does not break consensus safety (no double-spending or chain splits) but significantly degrades liveness and wastes validator resources.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
- The attacker to be a validator (already has staking power)
- The attacker's turn as proposer (happens naturally through round-robin leader election)
- A timeout certificate to exist with HQC round higher than available QCs

The conditions are realistic in a live network, especially during periods of network instability where timeouts occur naturally. A malicious validator can exploit their proposer turns repeatedly to maximize disruption.

## Recommendation

Add a validation check in `verify_well_formed()` to ensure that when a timeout certificate is present, the proposal's QC round is at least as high as the timeout certificate's highest HQC round:

```rust
// In ProposalMsg::verify_well_formed()
if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
    let proposal_qc_round = self.proposal.quorum_cert().certified_block().round();
    let tc_hqc_round = tc.highest_hqc_round();
    ensure!(
        proposal_qc_round >= tc_hqc_round,
        "Proposal QC round {} is lower than TC's highest HQC round {}",
        proposal_qc_round,
        tc_hqc_round
    );
}
```

This ensures proposals can only pass validation if they would also pass the voting safety check, preventing the creation of unvotable proposals.

## Proof of Concept

The vulnerability can be demonstrated by constructing a scenario where:
1. A timeout certificate is formed for round 100 with highest_hqc_round = 95
2. A malicious validator creates a proposal for round 101 with a QC for round 90
3. The proposal passes `verify_well_formed()` but fails `safe_to_vote()`

While a full executable PoC would require setting up the consensus test infrastructure with multiple validators and timeout scenarios, the code analysis clearly demonstrates the validation gap between the two checks.

### Citations

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

**File:** consensus/consensus-types/src/proposal_msg.rs (L64-73)
```rust
        let highest_certified_round = std::cmp::max(
            self.proposal.quorum_cert().certified_block().round(),
            self.sync_info.highest_timeout_round(),
        );
        ensure!(
            previous_round == highest_certified_round,
            "Proposal {} does not have a certified round {}",
            self.proposal,
            previous_round
        );
```

**File:** consensus/consensus-types/src/sync_info.rs (L120-123)
```rust
    pub fn highest_timeout_round(&self) -> Round {
        self.highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round())
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L195-198)
```rust
    /// The highest hqc round of the 2f+1 participants
    pub fn highest_hqc_round(&self) -> Round {
        self.timeout.hqc_round()
    }
```

**File:** consensus/src/round_manager.rs (L120-127)
```rust
            UnverifiedEvent::ProposalMsg(p) => {
                if !self_message {
                    p.verify(peer_id, validator, proof_cache, quorum_store_enabled)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proposal"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProposalMsg(p)
```

**File:** consensus/src/round_manager.rs (L1500-1527)
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
```

**File:** consensus/safety-rules/src/error.rs (L47-48)
```rust
    #[error("Does not satisfy 2-chain voting rule. Round {0}, Quorum round {1}, TC round {2},  HQC round in TC {3}")]
    NotSafeToVote(u64, u64, u64, u64),
```
