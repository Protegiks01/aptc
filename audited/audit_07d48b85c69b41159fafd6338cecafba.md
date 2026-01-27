# Audit Report

## Title
Consensus Observer DoS via Unverified Epoch Extraction in CommitDecision Messages

## Summary
The consensus observer processes `CommitDecision` messages by extracting epoch and round values from the embedded `LedgerInfoWithSignatures` **before** verifying cryptographic signatures. An attacker can send malicious `CommitDecision` messages with arbitrarily high epoch values and invalid signatures, causing the node to update its root state to unverified data and enter expensive state sync operations targeting non-existent epochs, resulting in resource exhaustion and denial of service.

## Finding Description

The vulnerability exists in the `process_commit_decision_message` function where epoch and round values are extracted and used to make critical state decisions before signature verification occurs. [1](#0-0) 

The `epoch()` function directly extracts the epoch value from the unverified `LedgerInfo` without any cryptographic validation. This extracted value is then used in the message processing logic: [2](#0-1) 

The code first uses these unverified values to determine whether to drop the message: [3](#0-2) 

Then checks if the commit decision is for the **current** epoch, and only verifies signatures in that case: [4](#0-3) 

However, if the unverified epoch is **higher** than the current epoch, the code bypasses verification entirely and proceeds to update state and trigger synchronization: [5](#0-4) 

Note the TODO comment explicitly acknowledging this gap. The `update_blocks_for_state_sync_commit` function updates the node's root ledger info to the unverified commit proof: [6](#0-5) 

This fundamentally violates the cryptographic verification invariant that epoch states must be verified before use: [7](#0-6) 

**Attack Scenario:**
1. Attacker crafts a `LedgerInfoWithSignatures` with epoch = 999999 and invalid/empty BLS signatures
2. Wraps it in a `CommitDecision` message
3. Sends via network to consensus observer
4. Node extracts epoch 999999 (line 449) without verification
5. Node compares 999999 > current_epoch (line 503) → TRUE
6. Node updates root to unverified ledger info (line 522)
7. Node triggers state sync to impossible target (line 526)
8. Node wastes resources attempting to sync to non-existent epoch
9. Attacker repeats to prevent recovery

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

- **Validator node slowdowns**: The node enters state sync mode trying to reach an invalid epoch, consuming CPU, memory, and network bandwidth while making no progress. State sync will continuously attempt to fetch data for the non-existent epoch.

- **Significant protocol violations**: The node's root ledger info is corrupted with an unverified value, violating the fundamental invariant that all ledger info must be cryptographically verified before acceptance.

- **Resource exhaustion**: Each malicious message triggers expensive state sync operations. An attacker can send these messages repeatedly at minimal cost, forcing the node to continuously waste resources.

- **Consensus observer denial of service**: While state syncing to an invalid target, the node cannot process legitimate consensus messages, effectively removing it from the observer pool.

The vulnerability does not reach Critical severity because:
- No funds are directly lost or stolen
- Full consensus is not broken (only observer nodes affected)
- Recovery is possible by restarting the node
- No permanent state corruption requiring hardfork

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of exploitation:

**Attacker Requirements:**
- Network connectivity to send messages to consensus observer nodes
- Ability to craft basic Rust data structures (LedgerInfoWithSignatures)
- No validator privileges, stake, or special access required

**Attack Complexity:**
- Low complexity - straightforward message crafting
- No timing requirements or race conditions
- Deterministic outcome - attack succeeds reliably
- Can be automated for repeated exploitation

**Detection Difficulty:**
- Malicious messages appear similar to legitimate future-epoch messages
- Metrics and logs will show manipulated epoch values
- Defenders may not immediately recognize this as an attack vs. network issues

**Deployment:**
- Any public consensus observer node is vulnerable
- Attackers can target multiple nodes simultaneously
- No patch deployment possible without code changes

## Recommendation

**Immediate Fix:** Verify commit proof signatures **before** extracting and using epoch/round values for any state decisions.

```rust
fn process_commit_decision_message(
    &mut self,
    peer_network_id: PeerNetworkId,
    message_received_time: Instant,
    commit_decision: CommitDecision,
) {
    // Get the current epoch state
    let epoch_state = self.get_epoch_state();
    
    // VERIFY THE COMMIT PROOF FIRST - before extracting any values
    if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
        // If current epoch verification fails, check if this might be a future epoch
        let commit_epoch = commit_decision.epoch();
        
        // Only proceed to state sync if the epoch is reasonably close to current
        // (e.g., within 1-2 epochs) to prevent DoS via extreme epoch values
        if commit_epoch > epoch_state.epoch + 2 {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Commit decision epoch too far in future: {:?} vs current {:?}. Ignoring.",
                    commit_epoch, epoch_state.epoch
                ))
            );
            increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
            return;
        }
        
        // For near-future epochs, we can proceed to state sync
        // but should validate against trusted waypoints or epoch change proofs
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Commit decision for future epoch: {:?}. Current epoch: {:?}. Starting state sync.",
                commit_epoch, epoch_state.epoch
            ))
        );
    }
    
    // Extract values AFTER verification
    let commit_epoch = commit_decision.epoch();
    let commit_round = commit_decision.round();
    
    // ... rest of the function
}
```

**Additional Hardening:**
1. Implement epoch bounds checking - reject messages claiming epochs more than N ahead of current
2. Require epoch change proofs for future-epoch commit decisions
3. Add rate limiting on state sync requests from commit decisions
4. Monitor and alert on state sync requests to abnormal epoch values

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        aggregate_signature::AggregateSignature,
    };

    #[tokio::test]
    async fn test_unverified_epoch_dos_attack() {
        // Setup: Create a consensus observer instance
        let (mut observer, _rx) = create_test_consensus_observer().await;
        
        // Attack: Craft malicious CommitDecision with high epoch and invalid signatures
        let malicious_epoch = 999999u64;
        let malicious_block_info = BlockInfo::new(
            malicious_epoch,
            0, // round
            HashValue::zero(),
            HashValue::zero(),
            0, // version
            0, // timestamp
            None, // epoch_state
        );
        
        let malicious_ledger_info = LedgerInfo::new(
            malicious_block_info,
            HashValue::zero(),
        );
        
        // Create LedgerInfoWithSignatures with EMPTY/INVALID signatures
        let malicious_commit_proof = LedgerInfoWithSignatures::new(
            malicious_ledger_info,
            AggregateSignature::empty(), // No valid signatures!
        );
        
        let malicious_commit_decision = CommitDecision::new(malicious_commit_proof);
        
        // Get initial state
        let initial_root_epoch = observer.observer_block_data.lock().root().ledger_info().epoch();
        
        // Send malicious message
        observer.process_commit_decision_message(
            PeerNetworkId::random(),
            Instant::now(),
            malicious_commit_decision,
        );
        
        // Verify vulnerability: root was updated to unverified high epoch
        let new_root_epoch = observer.observer_block_data.lock().root().ledger_info().epoch();
        
        // VULNERABILITY CONFIRMED: root epoch changed from current to malicious value
        assert_eq!(new_root_epoch, malicious_epoch);
        assert!(new_root_epoch > initial_root_epoch + 1000); // Impossibly high
        
        // Verify node entered state sync to invalid target
        assert!(observer.state_sync_manager.is_syncing_to_commit());
        assert!(observer.state_sync_manager.is_syncing_through_epoch());
        
        // Repeated attacks can keep node permanently in invalid state sync
        println!("VULNERABILITY CONFIRMED: Node accepted unverified epoch {} and entered state sync", 
                 malicious_epoch);
    }
}
```

## Notes

The vulnerability is explicitly acknowledged by the development team via the TODO comment, but remains unpatched. The core issue is a time-of-check-time-of-use (TOCTOU) vulnerability where epoch values are extracted before cryptographic verification, allowing attackers to manipulate node state through forged commit decisions. This breaks the fundamental invariant that all consensus messages must be cryptographically verified before affecting node state.

### Citations

**File:** consensus/src/consensus_observer/network/observer_message.rs (L351-354)
```rust
    /// Returns the epoch of the commit proof
    pub fn epoch(&self) -> u64 {
        self.commit_proof.ledger_info().epoch()
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L448-450)
```rust
        // Get the commit decision epoch and round
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L453-461)
```rust
        let get_highest_committed_epoch_round = self
            .observer_block_data
            .lock()
            .get_highest_committed_epoch_round();
        if (commit_epoch, commit_round) <= get_highest_committed_epoch_round {
            // Update the metrics for the dropped commit decision
            update_metrics_for_dropped_commit_decision_message(peer_network_id, &commit_decision);
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L467-482)
```rust
        let epoch_state = self.get_epoch_state();
        if commit_epoch == epoch_state.epoch {
            // Verify the commit decision
            if let Err(error) = commit_decision.verify_commit_proof(&epoch_state) {
                // Log the error and update the invalid message counter
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Failed to verify commit decision! Ignoring: {:?}, from peer: {:?}. Error: {:?}",
                        commit_decision.proof_block_info(),
                        peer_network_id,
                        error
                    ))
                );
                increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
                return;
            }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L497-527)
```rust
        // TODO: identify the best way to handle an invalid commit decision
        // for a future epoch. In such cases, we currently rely on state sync.

        // Otherwise, we failed to process the commit decision. If the commit
        // is for a future epoch or round, we need to state sync.
        let last_block = self.observer_block_data.lock().get_last_ordered_block();
        let epoch_changed = commit_epoch > last_block.epoch();
        if epoch_changed || commit_round > last_block.round() {
            // If we're waiting for state sync to transition into a new epoch,
            // we should just wait and not issue a new state sync request.
            if self.state_sync_manager.is_syncing_through_epoch() {
                info!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Already waiting for state sync to reach new epoch: {:?}. Dropping commit decision: {:?}!",
                        self.observer_block_data.lock().root().commit_info(),
                        commit_decision.proof_block_info()
                    ))
                );
                return;
            }

            // Otherwise, we should start the state sync process for the commit.
            // Update the block data (to the commit decision).
            self.observer_block_data
                .lock()
                .update_blocks_for_state_sync_commit(&commit_decision);

            // Start state syncing to the commit decision
            self.state_sync_manager
                .sync_to_commit(commit_decision, epoch_changed);
        }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L275-282)
```rust
    pub fn update_blocks_for_state_sync_commit(&mut self, commit_decision: &CommitDecision) {
        // Get the commit proof, epoch and round
        let commit_proof = commit_decision.commit_proof();
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();

        // Update the root
        self.update_root(commit_proof.clone());
```

**File:** types/src/epoch_state.rs (L41-50)
```rust
    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        ensure!(
            self.epoch == ledger_info.ledger_info().epoch(),
            "LedgerInfo has unexpected epoch {}, expected {}",
            ledger_info.ledger_info().epoch(),
            self.epoch
        );
        ledger_info.verify_signatures(&self.verifier)?;
        Ok(())
    }
```
