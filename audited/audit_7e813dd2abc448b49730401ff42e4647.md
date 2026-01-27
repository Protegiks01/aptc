# Audit Report

## Title
Consensus Observer Missing Round Progression Validation Allows Malicious Publishers to Send Invalid Blocks

## Summary
The consensus observer does not validate round progression rules when processing ordered blocks. Unlike regular consensus validators that call `verify_well_formed()` and validate `failed_authors`, the observer only performs basic checks (parent ID matching, proof verification). This allows a malicious consensus publisher to send blocks that violate consensus round progression rules, potentially causing state divergence and incorrect validator performance tracking.

## Finding Description

The consensus observer processes ordered blocks through `process_ordered_block()` but fails to validate critical consensus invariants that regular validators enforce. [1](#0-0) 

The observer only performs these validations:
1. `verify_ordered_blocks()` - checks blocks are chained internally
2. `verify_ordered_proof()` - verifies cryptographic signatures  
3. `verify_payloads_against_ordered_block()` - checks payload consistency
4. Parent ID check - ensures first block extends last ordered block

However, it does NOT call `verify_well_formed()` which validates: [2](#0-1) 

Most critically, the observer does NOT validate the `failed_authors` field that documents round skips. Regular consensus validators enforce this: [3](#0-2) 

Additionally, `ProposalMsg::verify_well_formed()` enforces strict round progression rules: [4](#0-3) 

This ensures `proposal.round() - 1 == max(qc.certified_round, timeout_round)`, preventing arbitrary round skipping. The observer has no equivalent validation.

A malicious publisher can exploit this by sending `OrderedBlock` messages with:
- Blocks that skip rounds without proper timeout justification
- Incorrect or manipulated `failed_authors` fields
- Blocks violating timestamp monotonicity
- Blocks with rounds not properly justified by QC or TC

When these blocks are executed, the `failed_authors` field is converted to `failed_proposer_indices` and passed to the VM: [5](#0-4) 

The `failed_proposer_indices` directly affect validator performance statistics via `stake::update_performance_statistics()`, which impacts validator rewards and reputation.

## Impact Explanation

**High Severity** - This vulnerability causes significant protocol violations:

1. **State Divergence**: Observer nodes may execute blocks with incorrect metadata (wrong failed_authors), leading to different state than validator nodes. This breaks the "Deterministic Execution" invariant.

2. **Validator Performance Manipulation**: Malicious publishers can manipulate `failed_authors` to incorrectly penalize or reward validators, affecting staking economics and validator reputation.

3. **Consensus Rule Violations**: Accepting blocks that violate round progression rules breaks the consensus protocol's safety guarantees about how rounds advance (only via QC or TC).

4. **Observer Reliability**: Observer nodes become unreliable for applications depending on them, as they may have incorrect validator performance data and deviate from canonical chain state.

While this doesn't directly cause fund loss or complete network partition (since only observer nodes are affected, not full validators), it represents a significant protocol violation affecting observer node reliability and validator staking correctness.

## Likelihood Explanation

**High Likelihood**:

1. **Attack Complexity**: Low - Publisher only needs to construct blocks with incorrect round numbers or failed_authors
2. **Attack Prerequisites**: Attacker must control or compromise a consensus publisher that observer nodes subscribe to
3. **Detection Difficulty**: Medium - State divergence may not be immediately obvious until state roots are compared
4. **Affected Systems**: All consensus observer nodes subscribed to a malicious publisher

The attack is straightforward to execute once a publisher is compromised or behaves maliciously. Observer nodes are commonly deployed for read-heavy applications, making this a practical concern.

## Recommendation

Add comprehensive validation in `process_ordered_block()` before accepting blocks:

```rust
async fn process_ordered_block(
    &mut self,
    pending_block_with_metadata: Arc<PendingBlockWithMetadata>,
) {
    // ... existing code ...
    
    // NEW: Validate each block's well-formedness
    for block in ordered_block.blocks() {
        if let Err(error) = block.block().verify_well_formed() {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Block failed well-formedness check! Ignoring: {:?}, Error: {:?}",
                    block.block_info(),
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
            return;
        }
        
        // NEW: Validate failed_authors if present
        if let Some(failed_authors) = block.block().block_data().failed_authors() {
            let parent_round = block.quorum_cert().certified_block().round();
            let expected_failed_authors = self.compute_expected_failed_authors(
                block.round(),
                parent_round,
            );
            
            if failed_authors != &expected_failed_authors {
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Block has invalid failed_authors! Expected: {:?}, Got: {:?}",
                        expected_failed_authors,
                        failed_authors
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
                return;
            }
        }
    }
    
    // ... rest of existing code ...
}
```

Additionally, implement `compute_expected_failed_authors()` in the observer to validate round skips, similar to `ProposalGenerator::compute_failed_authors()`.

## Proof of Concept

```rust
// Proof of Concept: Malicious publisher sends blocks with incorrect failed_authors

use consensus::consensus_observer::network::observer_message::{OrderedBlock, BlockPayload};
use aptos_consensus_types::{
    block::Block,
    block_data::{BlockData, BlockType},
    pipelined_block::PipelinedBlock,
};

#[test]
fn test_observer_accepts_invalid_failed_authors() {
    // Setup: Create observer and initialize with root block at round 10
    let mut observer = create_test_observer();
    let root_block = create_block(10, vec![]); // Round 10, no failed_authors
    observer.insert_ordered_block(root_block);
    
    // Attack: Create block at round 15 with manipulated failed_authors
    // Claim rounds 11-14 had failures, but provide wrong validator addresses
    let malicious_failed_authors = vec![
        (11, AccountAddress::random()),  // Wrong validator
        (12, AccountAddress::random()),  // Wrong validator  
        (13, AccountAddress::random()),  // Wrong validator
        (14, AccountAddress::random()),  // Wrong validator
    ];
    
    let malicious_block = Block::new_proposal(
        Payload::empty(),
        15,  // Round 15
        current_timestamp(),
        malicious_failed_authors,  // Manipulated list
        create_qc_for_round(10),   // Valid QC for round 10
        AccountAddress::random(),
    );
    
    // Create OrderedBlock message with malicious block
    let ordered_block = OrderedBlock::new(
        vec![Arc::new(PipelinedBlock::new_ordered(malicious_block))],
        create_ledger_info(15),
    );
    
    // Observer accepts without validating failed_authors!
    observer.process_ordered_block_message(ordered_block).await;
    
    // Verify: Observer accepted the invalid block
    assert!(observer.get_ordered_block(15).is_some());
    
    // Impact: When executed, wrong validators get penalized
    // The failed_proposer_indices in block metadata will be wrong
    // stake::update_performance_statistics() will penalize wrong validators
}
```

**Notes**

The vulnerability exists because the consensus observer was designed to trust the consensus publisher's blocks after verifying cryptographic proofs, without enforcing the same consensus rules that regular validators enforce. This creates a security gap where observers can be fed invalid blocks that pass signature checks but violate protocol invariants. The fix requires observers to implement the same validation logic as validators, particularly `verify_well_formed()` and `failed_authors` validation.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L716-801)
```rust
    /// Processes the ordered block. This assumes the ordered block
    /// has been sanity checked and that all payloads exist.
    async fn process_ordered_block(
        &mut self,
        pending_block_with_metadata: Arc<PendingBlockWithMetadata>,
    ) {
        // Unpack the pending block
        let (peer_network_id, message_received_time, observed_ordered_block) =
            pending_block_with_metadata.unpack();
        let ordered_block = observed_ordered_block.ordered_block().clone();

        // Verify the ordered block proof
        let epoch_state = self.get_epoch_state();
        if ordered_block.proof_block_info().epoch() == epoch_state.epoch {
            if let Err(error) = ordered_block.verify_ordered_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify ordered proof! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        ordered_block.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
                return;
            }
        } else {
            // Drop the block and log an error (the block should always be for the current epoch)
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received ordered block for a different epoch! Ignoring: {:?}",
                    ordered_block.proof_block_info()
                ))
            );
            return;
        };

        // Verify the block payloads against the ordered block
        if let Err(error) = self
            .observer_block_data
            .lock()
            .verify_payloads_against_ordered_block(&ordered_block)
        {
            // Log the error and update the invalid message counter
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to verify block payloads against ordered block! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                    ordered_block.proof_block_info(),
                    peer_network_id,
                    error
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::ORDERED_BLOCK_LABEL);
            return;
        }

        // The block was verified correctly. If the block is a child of our
        // last block, we can insert it into the ordered block store.
        let last_ordered_block = self.observer_block_data.lock().get_last_ordered_block();
        if last_ordered_block.id() == ordered_block.first_block().parent_id() {
            // Update the latency metrics for ordered block processing
            update_message_processing_latency_metrics(
                message_received_time,
                &peer_network_id,
                metrics::ORDERED_BLOCK_LABEL,
            );

            // Insert the ordered block into the pending blocks
            self.observer_block_data
                .lock()
                .insert_ordered_block(observed_ordered_block.clone());

            // If state sync is not syncing to a commit, finalize the ordered blocks
            if !self.state_sync_manager.is_syncing_to_commit() {
                self.finalize_ordered_block(ordered_block).await;
            }
        } else {
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Parent block for ordered block is missing! Ignoring: {:?}",
                    ordered_block.proof_block_info()
                ))
            );
        }
    }
```

**File:** consensus/consensus-types/src/block.rs (L469-550)
```rust
    pub fn verify_well_formed(&self) -> anyhow::Result<()> {
        ensure!(
            !self.is_genesis_block(),
            "We must not accept genesis from others"
        );
        let parent = self.quorum_cert().certified_block();
        ensure!(
            parent.round() < self.round(),
            "Block must have a greater round than parent's block"
        );
        ensure!(
            parent.epoch() == self.epoch(),
            "block's parent should be in the same epoch"
        );
        if parent.has_reconfiguration() {
            ensure!(
                self.payload().is_none_or(|p| p.is_empty()),
                "Reconfiguration suffix should not carry payload"
            );
        }

        if let Some(payload) = self.payload() {
            payload.verify_epoch(self.epoch())?;
        }

        if let Some(failed_authors) = self.block_data().failed_authors() {
            // when validating for being well formed,
            // allow for missing failed authors,
            // for whatever reason (from different max configuration, etc),
            // but don't allow anything that shouldn't be there.
            //
            // we validate the full correctness of this field in round_manager.process_proposal()
            let succ_round = self.round() + u64::from(self.is_nil_block());
            let skipped_rounds = succ_round.checked_sub(parent.round() + 1);
            ensure!(
                skipped_rounds.is_some(),
                "Block round is smaller than block's parent round"
            );
            ensure!(
                failed_authors.len() <= skipped_rounds.unwrap() as usize,
                "Block has more failed authors than missed rounds"
            );
            let mut bound = parent.round();
            for (round, _) in failed_authors {
                ensure!(
                    bound < *round && *round < succ_round,
                    "Incorrect round in failed authors"
                );
                bound = *round;
            }
        }

        if self.is_nil_block() || parent.has_reconfiguration() {
            ensure!(
                self.timestamp_usecs() == parent.timestamp_usecs(),
                "Nil/reconfig suffix block must have same timestamp as parent"
            );
        } else {
            ensure!(
                self.timestamp_usecs() > parent.timestamp_usecs(),
                "Blocks must have strictly increasing timestamps"
            );

            let current_ts = duration_since_epoch();

            // we can say that too far is 5 minutes in the future
            const TIMEBOUND: u64 = 300_000_000;
            ensure!(
                self.timestamp_usecs() <= (current_ts.as_micros() as u64).saturating_add(TIMEBOUND),
                "Blocks must not be too far in the future"
            );
        }
        ensure!(
            !self.quorum_cert().ends_epoch(),
            "Block cannot be proposed in an epoch that has ended"
        );
        debug_checked_verify_eq!(
            self.id(),
            self.block_data.hash(),
            "Block id mismatch the hash"
        );
        Ok(())
```

**File:** consensus/src/round_manager.rs (L1217-1231)
```rust
            // Validate that failed_authors list is correctly specified in the block.
            let expected_failed_authors = self.proposal_generator.compute_failed_authors(
                proposal.round(),
                proposal.quorum_cert().certified_block().round(),
                false,
                self.proposer_election.clone(),
            );
            ensure!(
                proposal.block_data().failed_authors().is_some_and(|failed_authors| *failed_authors == expected_failed_authors),
                "[RoundManager] Proposal for block {} has invalid failed_authors list {:?}, expected {:?}",
                proposal.round(),
                proposal.block_data().failed_authors(),
                expected_failed_authors,
            );
        }
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L68-73)
```rust
        ensure!(
            previous_round == highest_certified_round,
            "Proposal {} does not have a certified round {}",
            self.proposal,
            previous_round
        );
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L154-199)
```text
    fun block_prologue_common(
        vm: &signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64
    ): u64 acquires BlockResource, CommitHistory {
        // Operational constraint: can only be invoked by the VM.
        system_addresses::assert_vm(vm);

        // Blocks can only be produced by a valid proposer or by the VM itself for Nil blocks (no user txs).
        assert!(
            proposer == @vm_reserved || stake::is_current_epoch_validator(proposer),
            error::permission_denied(EINVALID_PROPOSER),
        );

        let proposer_index = option::none();
        if (proposer != @vm_reserved) {
            proposer_index = option::some(stake::get_validator_index(proposer));
        };

        let block_metadata_ref = borrow_global_mut<BlockResource>(@aptos_framework);
        block_metadata_ref.height = event::counter(&block_metadata_ref.new_block_events);

        let new_block_event = NewBlockEvent {
            hash,
            epoch,
            round,
            height: block_metadata_ref.height,
            previous_block_votes_bitvec,
            proposer,
            failed_proposer_indices,
            time_microseconds: timestamp,
        };
        emit_new_block_event(vm, &mut block_metadata_ref.new_block_events, new_block_event);

        // Performance scores have to be updated before the epoch transition as the transaction that triggers the
        // transition is the last block in the previous epoch.
        stake::update_performance_statistics(proposer_index, failed_proposer_indices);
        state_storage::on_new_block(reconfiguration::current_epoch());

        block_metadata_ref.epoch_interval
    }
```
