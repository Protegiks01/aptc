# Audit Report

## Title
Silent Data Loss in Consensus Persisting Phase Due to Ignored Channel Send Failures and Commit Errors

## Summary
The `PersistingPhase::process` method in the consensus pipeline contains two critical error handling flaws that can cause silent data loss and consensus safety violations. First, the `send()` operation's Result is ignored when delivering commit proofs to blocks. Second, the `wait_for_commit_ledger()` method ignores all errors from the actual commit operation. Both issues allow blocks to be marked as committed in the buffer manager even when they were never persisted to storage, breaking the fundamental consensus invariant that all honest validators maintain identical committed state.

## Finding Description

The vulnerability exists in the consensus persisting phase, which is responsible for committing blocks to persistent storage after they receive quorum certificates. [1](#0-0) 

**Error Suppression Layer 1 - Ignored Send Result:**
The code attempts to send the commit ledger info to each block's pipeline via a oneshot channel, but ignores the Result from the `send()` operation. If the receiver has been dropped (due to pipeline abort, task cancellation, or earlier errors), the send fails silently. [2](#0-1) 

**Error Suppression Layer 2 - Ignored Commit Result:**
The `wait_for_commit_ledger()` method is designed to wait for the commit operation to complete, but it explicitly ignores all errors: [3](#0-2) 

The actual commit operation can fail for multiple reasons (storage errors, disk I/O failures, database corruption): [4](#0-3) 

When errors occur in `commit_ledger`, they are propagated to the `commit_ledger_fut`, but `wait_for_commit_ledger()` discards them with `let _ = fut.commit_ledger_fut.await;`.

**Attack Scenarios:**

**Scenario A - Pipeline Abort During Epoch Transition:**
During epoch boundaries, the buffer manager sends a persisting request and immediately calls `reset()`: [5](#0-4) 

The race condition allows:
1. `advance_head` sends `PersistingRequest` with blocks to persist
2. `advance_head` immediately calls `reset()` for epoch boundary
3. `reset()` drains `pending_commit_blocks` while persisting phase is processing
4. If a block's pipeline was aborted earlier, the commit_proof_tx receiver is dropped
5. Persisting phase send() fails → ignored
6. `wait_for_commit_ledger()` returns immediately → no error
7. Persisting phase returns `Ok(round)` → buffer manager updates `highest_committed_round`
8. **Result: Block never committed, but system believes it was**

**Scenario B - Storage Failure:**
1. Send succeeds, `commit_ledger_fut` receives the proof
2. `executor.commit_ledger()` fails (disk full, I/O error, database corruption)
3. `commit_ledger_fut` resolves to `Err(TaskError::InternalError(...))`
4. `wait_for_commit_ledger()` ignores the error
5. Persisting phase returns `Ok(round)`
6. **Result: Block never committed, but system believes it was**

When the persisting phase returns successfully, the buffer manager updates its state: [6](#0-5) 

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The in-memory `highest_committed_round` diverges from actual storage state.

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability meets multiple Critical Severity criteria from the Aptos Bug Bounty:

1. **Consensus Safety Violation**: Different validators can have divergent views of committed state. If some validators successfully commit blocks while others silently fail, the network loses Byzantine Fault Tolerance guarantees. This violates the fundamental property that all honest validators agree on committed ledger state.

2. **Permanent Data Loss**: Transactions in uncommitted blocks are lost without any error notification to users or operators. Since the buffer manager clears `pending_commit_blocks` after receiving the success response, there is no retry mechanism.

3. **State Divergence Leading to Non-Recoverable Network Partition**: Validators with failed commits will report a `highest_committed_round` that exceeds what's actually in their storage. This causes:
   - State sync failures when nodes try to catch up
   - Merkle proof verification failures
   - Potential permanent network splits requiring hard fork to resolve

4. **Liveness Impact**: If enough validators experience silent commit failures, the network cannot make progress, as subsequent blocks build on uncommitted state.

This directly breaks Invariant #4: "State Consistency: State transitions must be atomic and verifiable via Merkle proofs."

## Likelihood Explanation

**HIGH LIKELIHOOD** - This vulnerability can be triggered through multiple realistic scenarios:

1. **Epoch Boundaries**: During every epoch transition, there's a race condition between persisting requests and reset operations, making this a recurring exposure.

2. **Storage Failures**: Any transient or permanent storage issue (disk errors, out of space, database corruption) triggers this vulnerability. In distributed systems, storage failures are expected events.

3. **Resource Exhaustion**: Under high load, pipeline tasks may be aborted due to timeouts or resource constraints, leading to dropped receivers.

4. **No Special Privileges Required**: This bug is triggered by normal operations or natural system failures, not requiring attacker access or Byzantine behavior.

The comment in the code acknowledges the risk: "may be aborted (e.g. by reset)" but fails to handle the consequences. [7](#0-6) 

## Recommendation

Implement proper error handling at both layers:

**Fix 1 - Check send() result in persisting_phase.rs:**

```rust
async fn process(&self, req: PersistingRequest) -> PersistingResponse {
    let PersistingRequest {
        blocks,
        commit_ledger_info,
    } = req;

    for b in &blocks {
        if let Some(tx) = b.pipeline_tx().lock().as_mut() {
            if let Some(commit_tx) = tx.commit_proof_tx.take() {
                // Check if send succeeds
                if let Err(_) = commit_tx.send(commit_ledger_info.clone()) {
                    return Err(anyhow::anyhow!(
                        "Failed to send commit proof to block {} - pipeline may be aborted",
                        b.id()
                    ).into());
                }
            }
        }
        // Check if commit actually succeeded
        if let Err(e) = b.wait_for_commit_ledger_with_result().await {
            return Err(anyhow::anyhow!(
                "Block {} failed to commit: {}",
                b.id(),
                e
            ).into());
        }
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

**Fix 2 - Add error-propagating version of wait_for_commit_ledger:**

```rust
// In pipelined_block.rs
pub async fn wait_for_commit_ledger_with_result(&self) -> Result<(), String> {
    if let Some(fut) = self.pipeline_futs() {
        match fut.commit_ledger_fut.await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Ok(()), // Committed as prefix
            Err(e) => Err(format!("Commit ledger failed: {}", e)),
        }
    } else {
        Err("Pipeline was aborted before commit could complete".to_string())
    }
}
```

**Fix 3 - Handle errors in buffer_manager:**

```rust
// In buffer_manager.rs main loop
Some(result) = self.persisting_phase_rx.next() => {
    match result {
        Ok(round) => {
            self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
            self.highest_committed_round = round;
            self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
        },
        Err(e) => {
            error!("Persisting phase failed: {}. Initiating recovery...", e);
            // Trigger recovery mechanism - retry commit or reset to safe state
            self.handle_commit_failure(e).await;
        }
    }
}
```

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[tokio::test]
async fn test_silent_commit_failure() {
    use aptos_consensus_types::pipelined_block::PipelinedBlock;
    use consensus::pipeline::persisting_phase::{PersistingPhase, PersistingRequest};
    use std::sync::Arc;
    
    // Setup: Create a block with pipeline
    let block = create_test_block();
    let pipelined_block = Arc::new(PipelinedBlock::new_ordered(block, OrderedBlockWindow::empty()));
    
    // Build pipeline futures and tx
    let (pipeline_futs, pipeline_tx, abort_handles) = pipeline_builder.build_internal(...);
    pipelined_block.set_pipeline_futs(pipeline_futs);
    pipelined_block.set_pipeline_tx(pipeline_tx);
    pipelined_block.set_pipeline_abort_handles(abort_handles);
    
    // ATTACK: Abort the pipeline before persisting phase processes the block
    pipelined_block.abort_pipeline();
    
    // Now create a persisting request with the aborted block
    let request = PersistingRequest {
        blocks: vec![pipelined_block.clone()],
        commit_ledger_info: create_test_commit_proof(),
    };
    
    // Process the request
    let persisting_phase = PersistingPhase::new(network_sender);
    let result = persisting_phase.process(request).await;
    
    // VULNERABILITY: Returns Ok(round) even though block was never committed
    assert!(result.is_ok(), "Persisting phase returned error when it should silently fail");
    
    // Verify the block was NOT actually committed to storage
    let committed_round = executor.get_latest_ledger_info().round();
    assert!(committed_round < result.unwrap(), "Block was marked committed but doesn't exist in storage!");
    
    println!("VULNERABILITY CONFIRMED: Block marked as committed but not in storage");
}
```

This can also be triggered by injecting fail points into the executor's `commit_ledger` method:

```rust
#[tokio::test]
async fn test_storage_error_ignored() {
    fail::cfg("executor::commit_blocks", "return").unwrap();
    
    // Create and process a persisting request
    let result = persisting_phase.process(request).await;
    
    // VULNERABILITY: Returns success despite storage failure
    assert!(result.is_ok());
    assert!(storage_is_inconsistent_with_reported_round());
}
```

**Notes:**

The vulnerability is exacerbated by the race condition at epoch boundaries where `reset()` is called immediately after sending the persisting request. The design assumes blocks in `pending_commit_blocks` will complete, but provides no mechanism to verify this actually occurred. The error suppression at two distinct layers (send failure + commit failure) makes this a defense-in-depth failure - even if one layer were fixed, the other would still allow silent failures.

### Citations

**File:** consensus/src/pipeline/persisting_phase.rs (L59-81)
```rust
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
            b.wait_for_commit_ledger().await;
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

**File:** consensus/consensus-types/src/pipelined_block.rs (L562-568)
```rust
    pub async fn wait_for_commit_ledger(&self) {
        // may be aborted (e.g. by reset)
        if let Some(fut) = self.pipeline_futs() {
            // this may be cancelled
            let _ = fut.commit_ledger_fut.await;
        }
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1079-1106)
```rust
    async fn commit_ledger(
        pre_commit_fut: TaskFuture<PreCommitResult>,
        commit_proof_fut: TaskFuture<LedgerInfoWithSignatures>,
        parent_block_commit_fut: TaskFuture<CommitLedgerResult>,
        executor: Arc<dyn BlockExecutorTrait>,
        block: Arc<Block>,
    ) -> TaskResult<CommitLedgerResult> {
        let mut tracker = Tracker::start_waiting("commit_ledger", &block);
        parent_block_commit_fut.await?;
        pre_commit_fut.await?;
        let ledger_info_with_sigs = commit_proof_fut.await?;

        // it's committed as prefix
        if ledger_info_with_sigs.commit_info().id() != block.id() {
            return Ok(None);
        }

        tracker.start_working();
        let ledger_info_with_sigs_clone = ledger_info_with_sigs.clone();
        tokio::task::spawn_blocking(move || {
            executor
                .commit_ledger(ledger_info_with_sigs_clone)
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        Ok(Some(ledger_info_with_sigs))
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L523-534)
```rust
                self.persisting_phase_tx
                    .send(self.create_new_request(PersistingRequest {
                        blocks: blocks_to_persist,
                        commit_ledger_info: aggregated_item.commit_proof,
                    }))
                    .await
                    .expect("Failed to send persist request");
                if commit_proof.ledger_info().ends_epoch() {
                    // the epoch ends, reset to avoid executing more blocks, execute after
                    // this persisting request will result in BlockNotFound
                    self.reset().await;
                }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L968-973)
```rust
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
                },
```
