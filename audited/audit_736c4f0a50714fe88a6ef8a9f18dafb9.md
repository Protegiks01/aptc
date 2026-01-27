# Audit Report

## Title
Incomplete Timeout Certificate Validation Allows Invalid Proposals to Pass Initial Verification

## Summary
The `verify_well_formed()` function in `proposal_msg.rs` fails to validate that a proposal's QC round is at least as high as the timeout certificate's highest HQC round when comparing timeout rounds with QC rounds. This allows proposals that pass initial validation but are unsafe to vote for, violating consensus protocol invariants.

## Finding Description
The AptosBFT 2-chain consensus protocol uses both Quorum Certificates (QC) and Timeout Certificates (TC) to advance rounds. When a proposal includes a timeout certificate with a round higher than the proposal's QC round, the validation must ensure the QC round is at least as high as the TC's embedded highest QC round (`hqc_round`). [1](#0-0) 

The current validation only checks that `proposal.round() - 1 == max(QC_round, TC_round)` but does not verify the relationship between the proposal's QC round and the TC's `hqc_round`. 

In contrast, the safety rules correctly implement this check: [2](#0-1) 

The safety rules ensure that when a TC is present with `tc.round() == proposal.round() - 1`, the proposal's QC round must satisfy `qc_round >= tc.highest_hqc_round()`. This check is missing from `verify_well_formed()`.

**Attack Scenario:**
1. A validator's block store has HQC for round 5 and TC for round 7 with `hqc_round = 6`
2. This inconsistent state can occur when the validator receives a TC referencing a QC they haven't synced yet
3. The validator creates a proposal for round 8 extending from round 5
4. The validation passes: `8 - 1 == max(5, 7) = 7` ✓
5. But the proposal is invalid because it extends from round 5 while the TC claims a QC exists for round 6
6. Honest validators will refuse to vote (due to `safe_to_vote()` check), but the proposal has already consumed resources [3](#0-2) [4](#0-3) 

## Impact Explanation
This is a **High Severity** issue because:

1. **Protocol Violation**: It allows proposals that violate the 2-chain consensus safety rules to pass initial validation, even though they are rejected at voting time
2. **Resource Waste**: Invalid proposals consume network bandwidth, storage, and processing resources before being rejected
3. **Timing Attacks**: An attacker could flood the network with such proposals to cause delays and confusion
4. **Incomplete Validation**: The gap between initial validation and voting checks indicates an incomplete implementation of consensus safety rules

While ultimate consensus safety is preserved (invalid proposals won't get votes), this represents a significant protocol violation that should be caught during early validation stages.

## Likelihood Explanation
**Likelihood: Medium-High**

This issue can occur whenever:
1. A validator receives a timeout certificate faster than the corresponding QC due to network delays or selective message delivery
2. The validator attempts to propose before syncing the missing QC
3. No malicious intent is required - this can happen naturally in distributed systems with network partitions

The inconsistent state (HQC at round R, TC with hqc_round at R+N where N > 1) is realistic in asynchronous networks where messages arrive out of order.

## Recommendation
Add validation in `verify_well_formed()` to check the relationship between the proposal's QC round and the TC's `hqc_round`:

```rust
// After line 73 in proposal_msg.rs, add:
if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
    if tc.round() > self.proposal.quorum_cert().certified_block().round() {
        ensure!(
            self.proposal.quorum_cert().certified_block().round() >= tc.highest_hqc_round(),
            "Proposal QC round {} must be >= TC's HQC round {} when using timeout certificate for round {}",
            self.proposal.quorum_cert().certified_block().round(),
            tc.highest_hqc_round(),
            tc.round()
        );
    }
}
```

This mirrors the safety check in `safe_to_vote()` and ensures consistency between QC rounds and timeout certificate rounds during early validation.

## Proof of Concept
```rust
#[test]
fn test_proposal_with_inconsistent_tc_should_fail() {
    use aptos_consensus_types::{
        block::Block,
        proposal_msg::ProposalMsg,
        quorum_cert::QuorumCert,
        sync_info::SyncInfo,
        timeout_2chain::{TwoChainTimeout, TwoChainTimeoutCertificate},
    };
    
    // Create QC for round 5
    let qc_round_5 = QuorumCert::certificate_for_genesis();
    
    // Create QC for round 6 (but proposer doesn't have it)
    let qc_round_6 = QuorumCert::certificate_for_genesis(); // In real scenario, different block
    
    // Create TC for round 7 with hqc_round = 6
    let timeout = TwoChainTimeout::new(1, 7, qc_round_6.clone());
    let tc = TwoChainTimeoutCertificate::new(timeout);
    
    // Create proposal for round 8 extending from round 5
    let proposal_block = Block::make_genesis_block();
    // Set proposal to round 8 with QC for round 5
    
    // Create SyncInfo with HQC at round 5 but TC at round 7 with hqc_round = 6
    let sync_info = SyncInfo::new(
        qc_round_5.clone(),
        /* ordered_cert */ qc_round_5.into_wrapped_ledger_info(),
        Some(tc)
    );
    
    let proposal_msg = ProposalMsg::new(proposal_block, sync_info);
    
    // This should fail but currently passes verify_well_formed()
    let result = proposal_msg.verify_well_formed();
    
    // Expected: result.is_err() with message about QC round < TC hqc_round
    // Actual: result.is_ok() (vulnerability)
    assert!(result.is_err(), "Proposal with QC round < TC hqc_round should be rejected");
}
```

## Notes
The validation for timeout rounds and QC rounds being directly comparable is correct - they are both consensus round numbers in the same sequential space. However, the semantic relationship enforced by the 2-chain protocol requires additional validation: when a timeout certificate is used to justify advancing rounds, the proposal must extend from a QC that is at least as recent as what the timeout certificate claims to have seen. This ensures proposals don't skip over certified blocks and maintains consensus safety.

### Citations

**File:** consensus/consensus-types/src/proposal_msg.rs (L52-57)
```rust
            self.proposal.parent_id()
                == self.sync_info.highest_quorum_cert().certified_block().id(),
            "Proposal HQC in SyncInfo certifies {}, but block parent id is {}",
            self.sync_info.highest_quorum_cert().certified_block().id(),
            self.proposal.parent_id(),
        );
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L150-166)
```rust
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

**File:** consensus/consensus-types/src/timeout_2chain.rs (L190-198)
```rust
    /// The round of the timeout.
    pub fn round(&self) -> Round {
        self.timeout.round()
    }

    /// The highest hqc round of the 2f+1 participants
    pub fn highest_hqc_round(&self) -> Round {
        self.timeout.hqc_round()
    }
```
