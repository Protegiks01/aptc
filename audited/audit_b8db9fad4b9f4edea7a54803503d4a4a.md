# Audit Report

## Title
Consensus Observer State Divergence Due to Publish-Before-Persist Race Condition

## Summary
The buffer manager publishes commit decisions to consensus observers before validating that persistence completed successfully. If persistence fails after publishing, observers will commit blocks that the validator never persisted, causing permanent state divergence between validators and observers.

## Finding Description

The vulnerability exists in the `advance_head()` function where commit decisions are published to observers before the persistence operation completes and its result is validated.

**The vulnerable sequence is:**

1. At lines 514-518, the validator publishes the commit decision message to consensus observers: [1](#0-0) 

2. At lines 523-529, the validator sends the persist request to the persisting phase: [2](#0-1) 

3. The persisting phase calls `wait_for_commit_ledger()` which ignores all errors: [3](#0-2) 

4. The `wait_for_commit_ledger()` implementation discards the result with `let _ =`: [4](#0-3) 

5. The persisting phase always returns `Ok(round)` regardless of whether commit_ledger succeeded: [5](#0-4) 

6. The actual persistence happens in `executor.commit_ledger()` which can fail: [6](#0-5) 

**Meanwhile, on the observer side:**

1. Observers receive the commit decision message and verify the commit proof: [7](#0-6) 

2. Observers update their local state with the commit decision: [8](#0-7) 

3. Observers forward the commit decision to their local execution pipeline: [9](#0-8) 

4. The observer's execution pipeline commits the block locally: [10](#0-9) 

**Failure scenarios that trigger the bug:**

The `executor.commit_ledger()` can fail due to:
- Database write errors (disk full, I/O errors)
- Block tree inconsistencies
- Database corruption
- Resource exhaustion
- Injected errors via fail_point for testing [11](#0-10) [12](#0-11) 

When any of these failures occur after the validator has already published the commit decision to observers, the observers will have committed the block in their local database while the validator has not, creating permanent state divergence.

**This violates critical invariants:**
- **Consensus Safety**: Different nodes have different committed states
- **State Consistency**: Observers and validators diverge permanently  
- **Deterministic Execution**: Identical consensus should produce identical state

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria for "Significant protocol violations")

This vulnerability causes:

1. **State Divergence**: Observers have blocks marked as committed that validators don't have persisted. This breaks the fundamental assumption that all honest nodes converge on the same committed state.

2. **Data Integrity Violation**: Observers will serve incorrect data to clients, returning blocks and transactions that were never actually committed by validators.

3. **Cascading Failures**: Once one block fails to persist, all subsequent blocks will also fail (because `parent_block_commit_fut.await?` propagates errors), but these failures remain hidden: [13](#0-12) 

4. **No Automatic Recovery**: There is no mechanism to detect this specific divergence scenario or automatically recover from it. The observer's fallback manager monitors sync progress but cannot detect that the validator's database is missing committed blocks while the validator's `highest_committed_round` counter continues to advance.

5. **Consensus Safety Violation**: This breaks the AptosBFT safety guarantee that all honest nodes agree on the committed chain.

The buffer manager pattern matches on `Some(Ok(round))` when receiving persisting phase responses: [14](#0-13) 

But there is no handling for the `Err` case because the persisting phase never returns errors.

## Likelihood Explanation

**Likelihood: Medium**

While database write failures are relatively uncommon in well-maintained systems, they do occur due to:
- Disk space exhaustion
- Hardware failures (disk I/O errors)
- Database corruption
- Resource contention
- File system issues

The presence of a dedicated fail_point for testing commit failures indicates this is a recognized failure mode that the system should handle gracefully. The current implementation fails to do so.

The vulnerability is automatically triggered whenever:
1. Consensus is reached on a block (normal operation)
2. Any persistence failure occurs after the publish step
3. No special attacker capabilities required

## Recommendation

**Fix the error handling in the persistence pipeline:**

1. **Make `wait_for_commit_ledger()` return the Result instead of discarding it:**

```rust
// In consensus/consensus-types/src/pipelined_block.rs
pub async fn wait_for_commit_ledger(&self) -> ExecutorResult<()> {
    if let Some(fut) = self.pipeline_futs() {
        fut.commit_ledger_fut.await
            .map(|_| ())
            .map_err(|e| ExecutorError::InternalError {
                error: format!("Commit ledger failed: {}", e),
            })
    } else {
        Err(ExecutorError::InternalError {
            error: "Pipeline aborted".to_string(),
        })
    }
}
```

2. **Propagate errors in the persisting phase:**

```rust
// In consensus/src/pipeline/persisting_phase.rs
async fn process(&self, req: PersistingRequest) -> PersistingResponse {
    let PersistingRequest {
        blocks,
        commit_ledger_info,
    } = req;

    for b in &blocks {
        if let Some(tx) = b.pipeline_tx().lock().as_mut() {
            tx.commit_proof_tx
                .take()
                .map(|tx| tx.send(commit_ledger_info.clone()));
        }
        // CHECK THE RESULT!
        b.wait_for_commit_ledger().await?;
    }

    let response = Ok(blocks.last().expect("Blocks can't be empty").round());
    if commit_ledger_info.ledger_info().ends_epoch() {
        self.commit_msg_tx
            .send_epoch_change(EpochChangeProof::new(vec![commit_ledger_info], false))
            .await;
    }
    response
}
```

3. **Handle errors in buffer manager and only publish after successful persistence:**

```rust
// In consensus/src/pipeline/buffer_manager.rs
async fn advance_head(&mut self, target_block_id: HashValue) {
    let mut blocks_to_persist: Vec<Arc<PipelinedBlock>> = vec![];
    // ... existing code to collect blocks ...
    
    let commit_proof = aggregated_item.commit_proof.clone();
    
    // SEND PERSIST REQUEST FIRST
    for block in &blocks_to_persist {
        self.pending_commit_blocks.insert(block.round(), block.clone());
    }
    self.persisting_phase_tx
        .send(self.create_new_request(PersistingRequest {
            blocks: blocks_to_persist,
            commit_ledger_info: aggregated_item.commit_proof.clone(),
        }))
        .await
        .expect("Failed to send persist request");
    
    // WAIT FOR PERSISTENCE CONFIRMATION via the persisting_phase_rx
    // and ONLY THEN publish to observers
    
    // Or alternatively, move the observer publish to happen 
    // after receiving Ok(round) from persisting_phase_rx
}
```

4. **Add error handling for persistence failures:**

```rust
// In buffer_manager::start() main loop
Some(Err(e)) = self.persisting_phase_rx.next() => {
    error!("Persistence failed: {:?}. Triggering recovery.", e);
    // Trigger state sync or panic to prevent state divergence
    panic!("Fatal: Block persistence failed");
}
```

## Proof of Concept

```rust
// Test case demonstrating the vulnerability
#[tokio::test]
async fn test_observer_divergence_on_persistence_failure() {
    // Setup validator and observer nodes
    let (validator, observer) = setup_validator_and_observer().await;
    
    // Enable fail_point to inject persistence error
    fail::cfg("executor::commit_blocks", "return").unwrap();
    
    // Submit block to validator
    let block = create_test_block();
    validator.process_block(block.clone()).await;
    
    // Validator reaches consensus and publishes commit decision
    // This happens at buffer_manager.rs:514-518
    
    // Observer receives commit decision
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Check state:
    // Observer has block committed
    let observer_committed = observer.get_committed_blocks().await;
    assert!(observer_committed.contains(&block.id()));
    
    // Validator does NOT have block committed (persistence failed)
    let validator_committed = validator.get_committed_blocks_from_db().await;
    assert!(!validator_committed.contains(&block.id()));
    
    // STATE DIVERGENCE DETECTED!
    // Observer and validator have different committed states
}
```

**Notes**

The vulnerability is exacerbated by the fact that subsequent blocks will also fail to commit in a cascade, but the system continues to update `highest_committed_round` as if commits are succeeding. This creates an increasingly large divergence between the validator's logical commit state (tracked by `highest_committed_round`) and its actual persisted state in the database.

### Citations

**File:** consensus/src/pipeline/buffer_manager.rs (L514-518)
```rust
                if let Some(consensus_publisher) = &self.consensus_publisher {
                    let message =
                        ConsensusObserverMessage::new_commit_decision_message(commit_proof.clone());
                    consensus_publisher.publish_message(message);
                }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L523-529)
```rust
                self.persisting_phase_tx
                    .send(self.create_new_request(PersistingRequest {
                        blocks: blocks_to_persist,
                        commit_ledger_info: aggregated_item.commit_proof,
                    }))
                    .await
                    .expect("Failed to send persist request");
```

**File:** consensus/src/pipeline/buffer_manager.rs (L968-972)
```rust
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
```

**File:** consensus/src/pipeline/persisting_phase.rs (L71-71)
```rust
            b.wait_for_commit_ledger().await;
```

**File:** consensus/src/pipeline/persisting_phase.rs (L74-74)
```rust
        let response = Ok(blocks.last().expect("Blocks can't be empty").round());
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L562-567)
```rust
    pub async fn wait_for_commit_ledger(&self) {
        // may be aborted (e.g. by reset)
        if let Some(fut) = self.pipeline_futs() {
            // this may be cancelled
            let _ = fut.commit_ledger_fut.await;
        }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1087-1087)
```rust
        parent_block_commit_fut.await?;
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1098-1104)
```rust
        tokio::task::spawn_blocking(move || {
            executor
                .commit_ledger(ledger_info_with_sigs_clone)
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L305-327)
```rust
    fn forward_commit_decision(&self, commit_decision: CommitDecision) {
        // Create a dummy RPC message
        let (response_sender, _response_receiver) = oneshot::channel();
        let commit_request = IncomingCommitRequest {
            req: CommitMessage::Decision(pipeline::commit_decision::CommitDecision::new(
                commit_decision.commit_proof().clone(),
            )),
            protocol: ProtocolId::ConsensusDirectSendCompressed,
            response_sender,
        };

        // Send the message to the execution client
        if let Err(error) = self
            .execution_client
            .send_commit_msg(AccountAddress::ONE, commit_request)
        {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to send commit decision to the execution pipeline! Error: {:?}",
                    error
                ))
            )
        };
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L469-482)
```rust
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

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L550-552)
```rust
                self.observer_block_data
                    .lock()
                    .update_ordered_block_commit_decision(commit_decision);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L562-562)
```rust
                    self.forward_commit_decision(commit_decision.clone());
```

**File:** execution/executor/src/block_executor/mod.rs (L383-385)
```rust
        fail_point!("executor::commit_blocks", |_| {
            Err(anyhow::anyhow!("Injected error in commit_blocks.").into())
        });
```

**File:** execution/executor/src/block_executor/mod.rs (L388-390)
```rust
        self.db
            .writer
            .commit_ledger(target_version, Some(&ledger_info_with_sigs), None)?;
```
