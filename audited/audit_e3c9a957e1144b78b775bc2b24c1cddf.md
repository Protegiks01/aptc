# Audit Report

## Title
Consensus Observer Denial of Service via Unverified Future Epoch Commit Decision

## Summary
The consensus observer's `process_commit_decision_message()` function accepts `CommitDecision` messages for future epochs without cryptographic verification. When such an unverified commit decision triggers state sync, the node enters an irrecoverable stuck state if state sync fails, causing permanent denial of service until the node is restarted.

## Finding Description

The vulnerability exists in the commit decision processing logic where epoch verification is bypassed for future epochs: [1](#0-0) 

When a `CommitDecision` arrives for a future epoch (e.g., epoch N+1 when the node is in epoch N), the epoch check at line 468 fails, causing the `verify_commit_proof()` validation (lines 470-482) to be **completely skipped**. The unverified commit decision proceeds to line 503 where it triggers state synchronization.

Before state sync begins, the node commits to the unverified state: [2](#0-1) 

The `update_blocks_for_state_sync_commit()` call updates the node's root to point to the unverified commit proof and clears all pending blocks: [3](#0-2) 

The state sync task is spawned, but critically, when it fails (because the invalid commit doesn't exist on peer nodes), it returns without sending a completion notification: [4](#0-3) 

This leaves the node in a permanently broken state because:

1. The `sync_to_commit_handle` remains set, causing `is_syncing_to_commit()` to return true
2. Progress checks are bypassed: [5](#0-4) 

3. New commit decisions are dropped: [6](#0-5) 

4. New ordered blocks are not finalized: [7](#0-6) 

The fallback detection mechanism is never reached because the early return at line 187 prevents the fallback manager's `check_syncing_progress()` from being called.

## Impact Explanation

This is **Critical Severity** under the Aptos bug bounty criteria:

- **Total loss of liveness**: The affected consensus observer node cannot process any new blocks and becomes permanently stuck
- **Non-recoverable without intervention**: The node requires a manual restart to recover, as there is no automatic recovery mechanism
- **Network availability impact**: Consensus observer nodes play a critical role in the Aptos network. Widespread exploitation could degrade network health and availability
- **No authentication required**: Any network peer can send the malicious message without validator privileges

The attack violates the **Consensus Safety** and **Cryptographic Correctness** invariants by accepting unverified commit proofs and breaks the **State Consistency** invariant by pointing the root to an invalid state.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
1. No special privileges or validator keys required
2. Attacker only needs network connectivity to send consensus observer messages
3. The malicious `CommitDecision` structure is simple to construct (just a `LedgerInfoWithSignatures` with epoch N+1 and empty/invalid signatures)
4. No rate limiting or sender authentication prevents repeated attacks
5. The vulnerability is always present when the consensus observer is running

The attack succeeds 100% of the time because:
- Future epoch commit decisions always bypass verification
- State sync will always fail for invalid commits
- The error handling always fails to notify the observer
- No recovery mechanism exists

## Recommendation

**Fix 1: Verify future epoch commit decisions against next epoch state**

Implement verification of commit decisions for future epochs by buffering them until the epoch transition occurs, then verifying against the new epoch state before processing.

**Fix 2: Add error notification for failed state sync**

Modify the state sync error handling to send a failure notification:

```rust
// In state_sync_manager.rs, around line 223
if let Err(error) = execution_client
    .clone()
    .sync_to_target(commit_decision.commit_proof().clone())
    .await
{
    error!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Failed to sync to commit decision: {:?}! Error: {:?}",
            commit_decision, error
        ))
    );
    
    // Send failure notification to allow recovery
    let _ = sync_notification_sender.send(
        StateSyncNotification::commit_sync_failed(commit_decision.commit_proof().clone())
    );
    return;
}
```

**Fix 3: Add timeout-based recovery**

Implement timeout tracking in `check_progress()` to detect stuck state sync operations and trigger fallback mode after a threshold period.

**Fix 4: Reject unverifiable commit decisions**

The simplest fix is to reject commit decisions for future epochs entirely:

```rust
// In process_commit_decision_message(), before line 503
if commit_epoch > epoch_state.epoch {
    warn!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Rejecting commit decision for future epoch: {:?}. Current epoch: {:?}",
            commit_epoch, epoch_state.epoch
        ))
    );
    increment_invalid_message_counter(&peer_network_id, metrics::COMMIT_DECISION_LABEL);
    return;
}
```

## Proof of Concept

```rust
// This PoC demonstrates the attack flow (pseudo-code for clarity)
use aptos_types::{ledger_info::LedgerInfo, aggregate_signature::AggregateSignature};

#[tokio::test]
async fn test_future_epoch_commit_dos_attack() {
    // Setup: Create a consensus observer node in epoch 10
    let mut observer = setup_consensus_observer_at_epoch(10).await;
    
    // Attack: Craft a malicious CommitDecision for future epoch 11
    let malicious_block_info = BlockInfo::new(
        11,  // Future epoch
        100, // Some round
        HashValue::random(),
        HashValue::random(),
        0,
        0,
        None,
    );
    
    let malicious_commit = CommitDecision::new(LedgerInfoWithSignatures::new(
        LedgerInfo::new(malicious_block_info, HashValue::random()),
        AggregateSignature::empty(), // Invalid/missing signatures
    ));
    
    // Send the malicious commit decision to the observer
    observer.process_commit_decision_message(
        peer_network_id,
        Instant::now(),
        malicious_commit,
    );
    
    // Verify the attack succeeded:
    // 1. State sync was triggered and failed silently
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    // 2. Node is now stuck - cannot process new valid commit decisions
    let valid_commit = create_valid_commit_for_epoch(10);
    observer.process_commit_decision_message(
        peer_network_id,
        Instant::now(),
        valid_commit,
    );
    
    // 3. Verify the valid commit was dropped (node is stuck)
    assert!(observer.state_sync_manager.is_syncing_to_commit());
    assert!(observer.observer_block_data.lock().get_all_ordered_blocks().is_empty());
    
    // Node remains stuck until manual restart
}
```

## Notes

This vulnerability demonstrates a critical gap in the consensus observer's security model. The TODO comment at line 497-498 explicitly acknowledges this issue but relies on state sync as a mitigation. However, the lack of proper error handling in state sync creates a worse outcome than the original problem. [8](#0-7) 

The vulnerability is particularly severe because it affects the consensus observer subsystem, which is designed to improve network resilience. Instead, this bug allows a single malicious message to permanently disable observer nodes, potentially degrading the network's overall health.

### Citations

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L179-188)
```rust
        // If state sync is syncing to a commit decision, we should wait for it to complete
        if self.state_sync_manager.is_syncing_to_commit() {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Waiting for state sync to reach commit decision: {:?}!",
                    self.observer_block_data.lock().root().commit_info()
                ))
            );
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L466-495)
```rust
        // If the commit decision is for the current epoch, verify and process it
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

            // Update the latency metrics for commit processing
            update_message_processing_latency_metrics(
                message_received_time,
                &peer_network_id,
                metrics::COMMIT_DECISION_LABEL,
            );

            // Update the pending blocks with the commit decision
            if self.process_commit_decision_for_pending_block(&commit_decision) {
                return; // The commit decision was successfully processed
            }
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L497-498)
```rust
        // TODO: identify the best way to handle an invalid commit decision
        // for a future epoch. In such cases, we currently rely on state sync.
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L505-516)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L518-527)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L789-792)
```rust
            // If state sync is not syncing to a commit, finalize the ordered blocks
            if !self.state_sync_manager.is_syncing_to_commit() {
                self.finalize_ordered_block(ordered_block).await;
            }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L275-290)
```rust
    pub fn update_blocks_for_state_sync_commit(&mut self, commit_decision: &CommitDecision) {
        // Get the commit proof, epoch and round
        let commit_proof = commit_decision.commit_proof();
        let commit_epoch = commit_decision.epoch();
        let commit_round = commit_decision.round();

        // Update the root
        self.update_root(commit_proof.clone());

        // Update the block payload store
        self.block_payload_store
            .remove_blocks_for_epoch_round(commit_epoch, commit_round);

        // Update the ordered block store
        self.ordered_block_store
            .remove_blocks_for_commit(commit_proof);
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L218-231)
```rust
                // Sync to the commit decision
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
                {
                    error!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to sync to commit decision: {:?}! Error: {:?}",
                            commit_decision, error
                        ))
                    );
                    return;
                }
```
