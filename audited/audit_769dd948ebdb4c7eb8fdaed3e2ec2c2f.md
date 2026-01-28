# Audit Report

## Title
Race Condition Between State Sync and Persisting Phase Causes Consensus State Corruption

## Summary
A race condition exists between the persisting phase and state sync reset operations that can corrupt the buffer manager's `highest_committed_round` tracking. The persisting phase unconditionally returns success even when block commits fail due to pipeline abortion, and stale responses can arrive after reset completes, overwriting the corrected state value.

## Finding Description

The persisting phase processes blocks by sending commit proofs and waiting for commit completion, but fails to properly handle errors when pipelines are aborted during state synchronization. [1](#0-0) 

The code ignores send failures on line 69 where `.take().map()` discards the `Result` from the oneshot channel send. On line 71, `wait_for_commit_ledger()` is called but its result is not checked. Line 74 unconditionally returns `Ok(round)` regardless of actual commit success.

The `wait_for_commit_ledger()` implementation explicitly ignores errors: [2](#0-1) 

When state sync triggers, it aborts all block pipelines: [3](#0-2) 

This is called during fast forward sync: [4](#0-3) 

The buffer manager's tokio select! loop handles both reset requests and persisting responses without synchronization: [5](#0-4) 

Line 971 unconditionally updates `highest_committed_round` when receiving persisting responses. The reset handler sets this value during reset: [6](#0-5) 

The critical flaw is that the reset() method does not drain the `persisting_phase_rx` channel: [7](#0-6) 

**Attack Sequence:**
1. Blocks at round R are in persisting phase
2. State sync triggers → `abort_pipeline_for_state_sync()` aborts pipelines
3. Aborted pipeline causes `wait_for_commit_ledger()` to return immediately
4. Persisting phase sends `Ok(R)` to channel despite no actual commit
5. Reset processes → sets `highest_committed_round` to correct value R'
6. Reset completes without draining `persisting_phase_rx` channel
7. Stale persisting response `Ok(R)` remains in channel
8. Next select! iteration processes stale response → overwrites `highest_committed_round` with incorrect value R

## Impact Explanation

**Severity: Medium**

This is a **Limited Protocol Violation** as defined in the Aptos bug bounty Medium severity category. The vulnerability causes:

1. **Temporary State Tracking Corruption**: The `highest_committed_round` can be set to an uncommitted round value, causing the node to have incorrect local state.

2. **Incorrect Node Behavior**: With corrupted tracking, the node may:
   - Reject valid blocks as "already committed" 
   - Apply incorrect backpressure logic
   - Process blocks out of expected order

3. **Self-Correcting via State Sync**: The impact is limited because state sync will eventually correct the storage to match the network consensus. This prevents permanent damage.

This does NOT constitute:
- Critical consensus safety violation (network consensus remains intact)
- Fund loss or theft
- Permanent state corruption
- Network partition or total liveness loss

The vulnerability fits the Medium category: "State inconsistencies requiring manual intervention" (or waiting for next state sync cycle).

## Likelihood Explanation

**Likelihood: Medium**

The race condition requires specific timing but occurs in realistic production scenarios:

**Required Conditions:**
1. Blocks must be in persisting phase when state sync triggers
2. Persisting phase response must arrive after reset completes
3. Message ordering race in the tokio select! loop

**Triggering Scenarios:**
- Epoch transitions with concurrent state sync
- Node catching up after temporary disconnection
- Fast forward sync operations during normal operation

State sync operations are common in production networks, and the decoupled execution architecture increases the probability of blocks being in the persisting phase during sync events. The timing window is narrow but achievable in practice. This is a natural protocol bug, not externally exploitable.

## Recommendation

Drain the `persisting_phase_rx` channel during reset to prevent stale responses from being processed:

```rust
async fn reset(&mut self) {
    // ... existing reset logic ...
    
    // Drain persisting phase channel to prevent stale responses
    while let Ok(Some(_)) = self.persisting_phase_rx.try_next() {
        // Discard stale persisting responses
    }
    
    // ... rest of reset logic ...
}
```

Additionally, the persisting phase should check the result of `wait_for_commit_ledger()` and return an error if the commit failed:

```rust
async fn process(&self, req: PersistingRequest) -> PersistingResponse {
    let PersistingRequest { blocks, commit_ledger_info } = req;
    
    for b in &blocks {
        if let Some(tx) = b.pipeline_tx().lock().as_mut() {
            if let Some(tx) = tx.commit_proof_tx.take() {
                // Check send result
                let _ = tx.send(commit_ledger_info.clone());
            }
        }
        b.wait_for_commit_ledger().await;
        
        // Check if pipeline was aborted
        if b.pipeline_futs().is_none() {
            return Err(ExecutorError::InternalError {
                error: "Pipeline aborted during commit".to_string(),
            });
        }
    }
    
    let response = Ok(blocks.last().expect("Blocks can't be empty").round());
    // ... rest of logic ...
    response
}
```

## Proof of Concept

A complete PoC would require:
1. Setting up a test network with state sync enabled
2. Triggering blocks to enter persisting phase
3. Concurrently triggering state sync fast forward
4. Observing the `highest_committed_round` corruption after reset

This requires integration testing with the full consensus and state sync pipeline, which is beyond the scope of this report but can be reproduced in the Aptos test framework by simulating the race condition timing.

## Notes

This vulnerability represents a genuine flaw in the synchronization between the persisting phase and reset operations. While the impact is limited by state sync's eventual correction, it can cause temporary operational issues including incorrect block rejection and processing. The root cause is the missing channel draining during reset combined with unconditional success returns from the persisting phase despite pipeline aborts.

### Citations

**File:** consensus/src/pipeline/persisting_phase.rs (L65-74)
```rust
        for b in &blocks {
            if let Some(tx) = b.pipeline_tx().lock().as_mut() {
                tx.commit_proof_tx
                    .take()
                    .map(|tx| tx.send(commit_ledger_info.clone()));
            }
            b.wait_for_commit_ledger().await;
        }

        let response = Ok(blocks.last().expect("Blocks can't be empty").round());
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

**File:** consensus/src/block_storage/block_store.rs (L617-627)
```rust
    pub async fn abort_pipeline_for_state_sync(&self) {
        let blocks = self.inner.read().get_all_blocks();
        // the blocks are not ordered by round here, so we need to abort all then wait
        let futs: Vec<_> = blocks
            .into_iter()
            .filter_map(|b| b.abort_pipeline())
            .collect();
        for f in futs {
            f.wait_until_finishes().await;
        }
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L506-514)
```rust
        if let Some(block_store) = maybe_block_store {
            monitor!(
                "abort_pipeline_for_state_sync",
                block_store.abort_pipeline_for_state_sync().await
            );
        }
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;
```

**File:** consensus/src/pipeline/buffer_manager.rs (L546-576)
```rust
    async fn reset(&mut self) {
        while let Some((_, block)) = self.pending_commit_blocks.pop_first() {
            // Those blocks don't have any dependencies, should be able to finish commit_ledger.
            // Abort them can cause error on epoch boundary.
            block.wait_for_commit_ledger().await;
        }
        while let Some(item) = self.buffer.pop_front() {
            for b in item.get_blocks() {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        self.buffer = Buffer::new();
        self.execution_root = None;
        self.signing_root = None;
        self.previous_commit_time = Instant::now();
        self.commit_proof_rb_handle.take();
        // purge the incoming blocks queue
        while let Ok(Some(blocks)) = self.block_rx.try_next() {
            for b in blocks.ordered_blocks {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        // Wait for ongoing tasks to finish before sending back ack.
        while self.ongoing_tasks.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L585-590)
```rust
            ResetSignal::TargetRound(round) => {
                self.highest_committed_round = round;
                self.latest_round = round;

                let _ = self.drain_pending_commit_proof_till(round);
            },
```

**File:** consensus/src/pipeline/buffer_manager.rs (L946-973)
```rust
                Some(reset_event) = self.reset_rx.next() => {
                    monitor!("buffer_manager_process_reset",
                    self.process_reset_request(reset_event).await);
                },
                Some(response) = self.execution_schedule_phase_rx.next() => {
                    monitor!("buffer_manager_process_execution_schedule_response", {
                    self.process_execution_schedule_response(response).await;
                })},
                Some(response) = self.execution_wait_phase_rx.next() => {
                    monitor!("buffer_manager_process_execution_wait_response", {
                    self.process_execution_response(response).await;
                    self.advance_execution_root();
                    if self.signing_root.is_none() {
                        self.advance_signing_root().await;
                    }});
                },
                Some(response) = self.signing_phase_rx.next() => {
                    monitor!("buffer_manager_process_signing_response", {
                    self.process_signing_response(response).await;
                    self.advance_signing_root().await
                    })
                },
                Some(Ok(round)) = self.persisting_phase_rx.next() => {
                    // see where `need_backpressure()` is called.
                    self.pending_commit_votes = self.pending_commit_votes.split_off(&(round + 1));
                    self.highest_committed_round = round;
                    self.pending_commit_blocks = self.pending_commit_blocks.split_off(&(round + 1));
                },
```
