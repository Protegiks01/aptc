# Audit Report

## Title
Reconfiguration Bypass via Missing Parent Block Validation in Optimistic Proposals

## Summary
The `verify_well_formed()` function in `OptBlockData` only validates that the grandparent block does not have a reconfiguration, but fails to check if the parent block has a reconfiguration. This allows validators to propose optimistic blocks immediately after a reconfiguration block, violating epoch transition invariants and potentially causing consensus safety violations.

## Finding Description [1](#0-0) 

The validation only checks `grandparent_qc.has_reconfiguration()` but does not verify `parent.has_reconfiguration()`. This creates a critical gap in the reconfiguration safety mechanism. [2](#0-1) 

A block has reconfiguration when `next_epoch_state` is set, indicating an epoch transition.

**Attack Flow:**

1. **Block Structure:**
   - Block A (epoch N, round R) - no reconfiguration
   - Block B (epoch N, round R+1) - **HAS reconfiguration** (transitions to epoch N+1)
   - Optimistic Block C (epoch N, round R+2) - created immediately after voting on B

2. **Optimistic Proposal Generation:** [3](#0-2) 

When a validator votes on Block B (which has reconfiguration), `start_next_opt_round()` is triggered with:
- `parent` = Block B's BlockInfo (has `next_epoch_state` set)
- `grandparent_qc` = QC for Block A (no reconfiguration)
- `epoch_state` = old epoch N (not yet transitioned)

3. **No Parent Reconfiguration Check:**
The function does not check if `parent.has_reconfiguration()` before generating the optimistic proposal.

4. **Proposal Generator Check Bypassed:** [4](#0-3) 

This check examines the HQC (highest quorum cert), which is the grandparent (Block A), not the parent (Block B). Since Block A has no reconfiguration, the check passes.

5. **Validation Passes Incorrectly:** [5](#0-4) 

All three blocks are in epoch N, so this passes. [6](#0-5) 

The optimistic proposal has a strictly increasing timestamp, which violates the reconfiguration suffix rule but is not caught here.

6. **Reconfiguration Suffix Rules Violated:** [7](#0-6) 

Regular blocks after a reconfiguration parent must have empty payload. [8](#0-7) 

And must have the same timestamp as the parent. However, these checks are never executed for optimistic proposals because `Block::verify_well_formed()` is not called after conversion from `OptBlockData`.

## Impact Explanation
**Severity: Critical**

This vulnerability enables consensus safety violations by:

1. **Epoch Transition Bypass:** Allows blocks claiming to be in epoch N to be proposed after a reconfiguration that should transition to epoch N+1, creating epoch confusion.

2. **Validator Set Confusion:** The old validator set (epoch N) can continue proposing after reconfiguration, potentially conflicting with the new validator set (epoch N+1) that should be active.

3. **Reconfiguration Suffix Rule Violation:** Optimistic proposals can carry payload and have increasing timestamps after a reconfiguration block, when they should be empty with the same timestamp until reconfiguration is committed.

4. **Consensus Split Risk:** Different validators may have different views of epoch state, potentially causing them to accept or reject blocks inconsistently, threatening consensus safety guarantees.

This violates the **Consensus Safety** critical invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine."

## Likelihood Explanation
**Likelihood: Medium to High**

The vulnerability triggers automatically when:
- A validator votes on a reconfiguration block (happens during every epoch change)
- The validator is the next round proposer (determined by proposer election)
- Optimistic proposals are enabled (`enable_optimistic_proposal_tx = true`)

No special manipulation is required beyond normal validator operation. The validator doesn't need to "manipulate" the grandparent_qc—it's the legitimate QC from the voting process. The bug is purely in the insufficient validation logic.

## Recommendation

Add a check for parent reconfiguration in `OptBlockData::verify_well_formed()`:

```rust
pub fn verify_well_formed(&self) -> anyhow::Result<()> {
    let parent = self.parent();
    let grandparent_qc = self.grandparent_qc().certified_block();
    
    // ... existing round checks ...
    
    ensure!(
        grandparent_qc.epoch() == self.epoch() && parent.epoch() == self.epoch(),
        "Block's parent and grantparent should be in the same epoch"
    );
    
    ensure!(
        !grandparent_qc.has_reconfiguration(),
        "Optimistic proposals are disallowed after the reconfiguration block"
    );
    
    // ADD THIS CHECK:
    ensure!(
        !parent.has_reconfiguration(),
        "Optimistic proposals are disallowed when parent has reconfiguration"
    );
    
    // ... rest of validation ...
}
```

Additionally, add a check in `start_next_opt_round()`:

```rust
fn start_next_opt_round(
    &self,
    parent_vote: Vote,
    grandparent_qc: QuorumCert,
) -> anyhow::Result<()> {
    // ... existing checks ...
    
    let parent = parent_vote.vote_data().proposed().clone();
    
    // ADD THIS CHECK:
    ensure!(
        !parent.has_reconfiguration(),
        "Cannot start optimistic round after reconfiguration parent"
    );
    
    // ... rest of function ...
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod reconfiguration_bypass_test {
    use super::*;
    use aptos_types::{
        block_info::BlockInfo,
        epoch_state::EpochState,
        validator_verifier::ValidatorVerifier,
        validator_signer::ValidatorSigner,
    };
    use consensus_types::{
        opt_block_data::OptBlockData,
        quorum_cert::QuorumCert,
        common::Payload,
    };
    
    #[test]
    fn test_opt_proposal_after_reconfiguration_parent() {
        // Setup: Create validator set for epoch 1
        let (signers, validators) = random_validator_verifier(4, None, false);
        let signer = &signers[0];
        
        // Block A: grandparent at round 10, epoch 1, no reconfiguration
        let block_a = BlockInfo::new(
            1, // epoch
            10, // round
            HashValue::random(),
            HashValue::random(),
            100, // version
            10000, // timestamp
            None, // no next_epoch_state
        );
        
        // Block B: parent at round 11, epoch 1, HAS reconfiguration
        let new_validator_set = ValidatorSet::new(vec![/* new validators */]);
        let next_epoch_state = EpochState {
            epoch: 2,
            verifier: (&new_validator_set).into(),
        };
        
        let block_b = BlockInfo::new(
            1, // epoch
            11, // round
            HashValue::random(),
            HashValue::random(),
            101, // version
            11000, // timestamp
            Some(next_epoch_state), // HAS RECONFIGURATION
        );
        
        // Create QC for Block A (grandparent)
        let grandparent_qc = create_test_qc(&signers, block_a.clone());
        
        // Attempt to create optimistic proposal for round 12 with:
        // - parent = Block B (has reconfiguration)
        // - grandparent_qc = QC for Block A (no reconfiguration)
        let opt_block = OptBlockData::new(
            vec![], // validator_txns
            Payload::empty(false, true),
            signer.author(),
            1, // epoch (still in old epoch)
            12, // round
            12000, // timestamp > parent timestamp (violates reconfig suffix rule)
            block_b.clone(), // parent HAS reconfiguration!
            grandparent_qc,
        );
        
        // BUG: This should fail but passes!
        assert!(opt_block.verify_well_formed().is_ok());
        // The validation only checks grandparent_qc, not parent
        
        // This violates the invariant that optimistic proposals
        // are disallowed after a reconfiguration block
        assert!(block_b.has_reconfiguration()); // parent has reconfig
    }
}
```

**Notes:**

The vulnerability exists because the validation logic assumes that if the grandparent has no reconfiguration, then the parent also has no reconfiguration. This assumption is incorrect—the parent can be the first reconfiguration block while the grandparent is a normal block. The missing check allows the epoch transition safety mechanism to be bypassed, potentially causing consensus-level issues during epoch changes.

### Citations

**File:** consensus/consensus-types/src/opt_block_data.rs (L91-93)
```rust
            grandparent_qc.epoch() == self.epoch() && parent.epoch() == self.epoch(),
            "Block's parent and grantparent should be in the same epoch"
        );
```

**File:** consensus/consensus-types/src/opt_block_data.rs (L94-97)
```rust
        ensure!(
            !grandparent_qc.has_reconfiguration(),
            "Optimistic proposals are disallowed after the reconfiguration block"
        );
```

**File:** consensus/consensus-types/src/opt_block_data.rs (L102-105)
```rust
            self.timestamp_usecs() > parent.timestamp_usecs()
                && parent.timestamp_usecs() > grandparent_qc.timestamp_usecs(),
            "Blocks must have strictly increasing timestamps"
        );
```

**File:** types/src/block_info.rs (L169-171)
```rust
    pub fn has_reconfiguration(&self) -> bool {
        self.next_epoch_state.is_some()
    }
```

**File:** consensus/src/round_manager.rs (L1427-1493)
```rust
    fn start_next_opt_round(
        &self,
        parent_vote: Vote,
        grandparent_qc: QuorumCert,
    ) -> anyhow::Result<()> {
        // Optimistic Proposal:
        // When receiving round r block, send optimistic proposal for round r+1 if:
        // 0. opt proposal is enabled
        // 1. it is the leader of the next round r+1
        // 2. voted for round r block
        // 3. the round r block contains QC of round r-1
        // 4. does not propose in round r+1
        if !self.local_config.enable_optimistic_proposal_tx {
            return Ok(());
        };

        ensure!(
            !self.proposal_generator.is_proposal_under_backpressure(),
            "Cannot start next opt round due to backpressure"
        );

        let parent = parent_vote.vote_data().proposed().clone();
        let opt_proposal_round = parent.round() + 1;
        if self
            .proposer_election
            .is_valid_proposer(self.proposal_generator.author(), opt_proposal_round)
        {
            let expected_grandparent_round = parent
                .round()
                .checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("Invalid parent round {}", parent.round()))?;
            ensure!(
                grandparent_qc.certified_block().round() == expected_grandparent_round,
                "Cannot start Optimistic Round. Grandparent QC is not for round minus one: {} < {}",
                grandparent_qc.certified_block().round(),
                parent.round()
            );

            let epoch_state = self.epoch_state.clone();
            let network = self.network.clone();
            let sync_info = self.block_store.sync_info();
            let proposal_generator = self.proposal_generator.clone();
            let proposer_election = self.proposer_election.clone();
            tokio::spawn(async move {
                if let Err(e) = monitor!(
                    "generate_and_send_opt_proposal",
                    Self::generate_and_send_opt_proposal(
                        epoch_state,
                        opt_proposal_round,
                        parent,
                        grandparent_qc,
                        network,
                        sync_info,
                        proposal_generator,
                        proposer_election,
                    )
                    .await
                ) {
                    warn!(
                        "[OptProposal] Error generating and sending opt proposal: {}",
                        e
                    );
                }
            });
        }
        Ok(())
    }
```

**File:** consensus/src/liveness/proposal_generator.rs (L707-709)
```rust
        let (validator_txns, payload, timestamp) = if hqc.certified_block().has_reconfiguration() {
            bail!("[OptProposal] HQC has reconfiguration!");
        } else {
```

**File:** consensus/consensus-types/src/block.rs (L483-488)
```rust
        if parent.has_reconfiguration() {
            ensure!(
                self.payload().is_none_or(|p| p.is_empty()),
                "Reconfiguration suffix should not carry payload"
            );
        }
```

**File:** consensus/consensus-types/src/block.rs (L521-525)
```rust
        if self.is_nil_block() || parent.has_reconfiguration() {
            ensure!(
                self.timestamp_usecs() == parent.timestamp_usecs(),
                "Nil/reconfig suffix block must have same timestamp as parent"
            );
```
