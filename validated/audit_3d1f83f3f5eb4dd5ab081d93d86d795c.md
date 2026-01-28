# Audit Report

## Title
Race Condition in PartialStateComputeResult OnceCell Initialization Causes Validator Node Panic on Duplicate Block Insertion

## Summary
Multiple validator threads can concurrently execute ledger update for the same block due to inadequate synchronization in the consensus pipeline's duplicate block handling, causing a panic when racing to initialize OnceCell fields in `PartialStateComputeResult`. This results in validator node crashes and network availability degradation.

## Finding Description

The vulnerability exists in a race condition chain spanning the consensus and execution layers:

**1. Duplicate Block Insertion is Expected Behavior**

The consensus layer explicitly allows duplicate block inserts as documented in the code comments, stating that "it is considered a valid non-error case, for example, it can happen if a validator receives a certificate for a block that is currently being added." [1](#0-0) 

Additionally, the RoundManager explicitly acknowledges that "delayed processing of proposal tries to add the same block again, which is okay as insert_block call is idempotent." [2](#0-1) 

**2. Pipeline Construction Precedes Duplicate Detection**

In the block insertion flow, when `insert_block` is called, there's an initial check for existing blocks that is NOT synchronized with the actual insertion. [3](#0-2)  This allows two threads to both pass the check at line 413 and proceed to build pipelines.

The pipeline is then built in `insert_block_inner` BEFORE the duplicate check in the block tree. [4](#0-3)  The actual duplicate detection only occurs when inserting into the block tree at line 515. [5](#0-4) 

The BlockTree's insert_block method performs the duplicate check. [6](#0-5) 

**3. Pipeline Futures Spawn Independent Tasks**

The `set_pipeline_futs` method has no synchronization to prevent multiple pipelines from being created. [7](#0-6) 

Critically, `spawn_shared_fut` immediately spawns independent async tasks using `tokio::spawn`. [8](#0-7)  Once spawned, these tasks run independently even if the PipelinedBlock that created them is discarded.

The ledger_update future is spawned for each pipeline. [9](#0-8) 

**4. Ledger Update Allows Concurrent Access**

The `BlockExecutor::ledger_update` method signature takes `&self` (not `&mut self`), permitting concurrent execution. [10](#0-9) 

Both concurrent threads fetch blocks from the BlockTree. [11](#0-10)  The BlockLookup returns `Arc<Block>`, so both threads get the SAME Block instance. [12](#0-11) 

**5. TOCTOU Vulnerability in Completion Check**

The check for existing results is not atomic with the subsequent OnceCell initialization. [13](#0-12) 

Both threads can pass this check before either completes the initialization, then proceed to set the OnceCell fields. [14](#0-13) 

**6. OnceCell Panic on Duplicate Initialization**

The OnceCell fields panic when set twice. [15](#0-14) [16](#0-15) 

The `.expect()` calls will panic with "StateCheckpointOutput already set" or "LedgerUpdateOutput already set" when the second thread attempts to set already-initialized cells.

**Attack Scenario:**

1. Attacker sends duplicate blocks/certificates to a validator node (normal network behavior)
2. Two threads concurrently call `insert_block` for the same block_id
3. Both pass the duplicate check at line 413 (race condition window)
4. Both create PipelinedBlocks and call `insert_block_inner`
5. Both execute `build_for_consensus`, spawning separate ledger_update futures via `tokio::spawn`
6. Both futures execute independently and call `executor.ledger_update(block_id, parent_id)` concurrently
7. Both fetch the same `Arc<Block>` from BlockTree
8. Both check `get_complete_result()` and see None (TOCTOU race)
9. Both compute state checkpoint and ledger update (deterministic, same values)
10. Thread A successfully calls `set_state_checkpoint_output()` and `set_ledger_update_output()`
11. Thread B panics when attempting to set already-initialized OnceCell fields
12. Validator node crashes with panic message: "StateCheckpointOutput already set"

## Impact Explanation

**High Severity** - This vulnerability causes validator node crashes, meeting the "API crashes" and "Validator node slowdowns" criteria from the Aptos bug bounty High Severity category.

**Availability Impact:**
- Validator node crashes immediately upon panic
- Node must be restarted to resume operation
- Reduces network validator capacity
- If multiple validators are affected simultaneously, could degrade network liveness

**Why Not Critical:**
- No consensus safety violation (both threads compute identical deterministic results)
- No funds at risk
- No permanent network partition (nodes can restart)
- No state corruption (values computed are correct, just causes crash)

**Affected Invariant:**
Violates the network availability guarantee by causing validator node crashes through a race condition in normal protocol operation.

## Likelihood Explanation

**Medium-High Likelihood:**

This vulnerability can occur during normal network operation when:
- Validators broadcast certificates for the same block
- Network delays cause duplicate block messages
- High consensus round activity increases concurrent processing
- Delayed proposal processing (explicitly supported in the code) retries block insertion

The vulnerability requires:
- **No attacker privileges** - Any network peer can send blocks/certificates
- **Normal protocol behavior** - Duplicate block delivery is explicitly expected per code comments
- **Timing overlap** - Two inserts must overlap in the critical window between the check at line 413 and the insert at line 515

The likelihood increases with:
- Network congestion or delays
- High transaction throughput
- Multiple validators proposing blocks
- Byzantine actors deliberately sending duplicate messages to exploit the race window

The code comments explicitly acknowledging duplicate inserts as normal indicates this is a realistic scenario that developers anticipated but incompletely protected against.

## Recommendation

Implement atomic check-and-set semantics for the duplicate block detection and pipeline construction:

1. **Add synchronization to `insert_block`**: Use a write lock or atomic check-and-insert pattern to ensure only one thread builds the pipeline for a given block_id.

2. **Make completion check atomic**: In `ledger_update`, use compare-and-swap or lock the check with the set operations to prevent TOCTOU races.

3. **Early return on duplicate**: Check if OnceCell is already set before attempting computation, using `get()` instead of just in the completion check.

4. **Idempotent ledger_update**: Return early if results are already computed instead of panicking, honoring the TODO comment at line 290.

Example fix for the TOCTOU issue:
```rust
// In ledger_update, make the check atomic with computation
if let Some(complete_result) = output.get_complete_result() {
    return Ok(complete_result);
}

// Use try_insert pattern instead of set to avoid panic
match output.state_checkpoint_output.try_insert(computed_checkpoint) {
    Ok(_) => {},
    Err(_) => return output.get_complete_result().expect("Must be set"),
}
```

## Proof of Concept

While a full PoC requires a running Aptos validator environment, the vulnerability can be triggered by:

1. Setting up a local Aptos testnet with multiple validators
2. Sending the same block proposal through multiple network paths simultaneously
3. Observing validator crash logs showing "StateCheckpointOutput already set" panic
4. Monitoring validator restart events

The race condition window can be increased by adding artificial delays in pipeline construction for testing purposes.

## Notes

- This is a **concurrency bug** in the consensus layer, not a network-level DoS attack
- The vulnerability exists because duplicate block handling assumes idempotency but OnceCell.set() is not idempotent
- The TODO comment at line 290 ("remove, assuming no retries") suggests developers were aware of potential retry issues but didn't fully address them
- Both threads compute identical results (deterministic execution), so there's no consensus safety violation, only availability impact
- The fix requires careful synchronization to avoid introducing performance bottlenecks in the consensus hot path

### Citations

**File:** consensus/src/block_storage/block_store.rs (L412-438)
```rust
    pub async fn insert_block(&self, block: Block) -> anyhow::Result<Arc<PipelinedBlock>> {
        if let Some(existing_block) = self.get_block(block.id()) {
            return Ok(existing_block);
        }
        ensure!(
            self.inner.read().ordered_root().round() < block.round(),
            "Block with old round"
        );

        let block_window = self
            .inner
            .read()
            .get_ordered_block_window(&block, self.window_size)?;
        let blocks = block_window.blocks();
        for block in blocks {
            if let Some(payload) = block.payload() {
                self.payload_manager.prefetch_payload_data(
                    payload,
                    block.author().expect("Payload block must have author"),
                    block.timestamp_usecs(),
                );
            }
        }

        let pipelined_block = PipelinedBlock::new_ordered(block, block_window);
        self.insert_block_inner(pipelined_block).await
    }
```

**File:** consensus/src/block_storage/block_store.rs (L445-447)
```rust
    /// Duplicate inserts will return the previously inserted block (
    /// note that it is considered a valid non-error case, for example, it can happen if a validator
    /// receives a certificate for a block that is currently being added).
```

**File:** consensus/src/block_storage/block_store.rs (L463-496)
```rust
        // build pipeline
        if let Some(pipeline_builder) = &self.pipeline_builder {
            let parent_block = self
                .get_block(pipelined_block.parent_id())
                .ok_or_else(|| anyhow::anyhow!("Parent block not found"))?;

            // need weak pointer to break the cycle between block tree -> pipeline block -> callback
            let block_tree = Arc::downgrade(&self.inner);
            let storage = self.storage.clone();
            let id = pipelined_block.id();
            let round = pipelined_block.round();
            let window_size = self.window_size;
            let callback = Box::new(
                move |finality_proof: WrappedLedgerInfo,
                      commit_decision: LedgerInfoWithSignatures| {
                    if let Some(tree) = block_tree.upgrade() {
                        tree.write().commit_callback(
                            storage,
                            id,
                            round,
                            finality_proof,
                            commit_decision,
                            window_size,
                        );
                    }
                },
            );
            pipeline_builder.build_for_consensus(
                &pipelined_block,
                parent_block.pipeline_futs().ok_or_else(|| {
                    anyhow::anyhow!("Parent future doesn't exist, potentially epoch ended")
                })?,
                callback,
            );
```

**File:** consensus/src/block_storage/block_store.rs (L515-516)
```rust
        self.inner.write().insert_block(pipelined_block)
    }
```

**File:** consensus/src/round_manager.rs (L1250-1255)
```rust
        // are out of the backpressure. Please note that delayed processing of proposal is not
        // guaranteed to add the block to the block store if we don't get out of the backpressure
        // before the timeout, so this is needed to ensure that the proposed block is added to
        // the block store irrespective. Also, it is possible that delayed processing of proposal
        // tries to add the same block again, which is okay as `insert_block` call
        // is idempotent.
```

**File:** consensus/src/block_storage/block_tree.rs (L312-317)
```rust
        if let Some(existing_block) = self.get_block(&block_id) {
            debug!("Already had block {:?} for id {:?} when trying to add another block {:?} for the same id",
                       existing_block,
                       block_id,
                       block);
            Ok(existing_block)
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L512-514)
```rust
    pub fn set_pipeline_futs(&self, pipeline_futures: PipelineFutures) {
        *self.pipeline_futs.lock() = Some(pipeline_futures);
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L144-167)
```rust
fn spawn_shared_fut<
    T: Send + Clone + 'static,
    F: Future<Output = TaskResult<T>> + Send + 'static,
>(
    f: F,
    abort_handles: Option<&mut Vec<AbortHandle>>,
) -> TaskFuture<T> {
    let join_handle = tokio::spawn(f);
    if let Some(handles) = abort_handles {
        handles.push(join_handle.abort_handle());
    }
    async move {
        match join_handle.await {
            Ok(Ok(res)) => Ok(res),
            Ok(e @ Err(TaskError::PropagatedError(_))) => e,
            Ok(Err(e @ TaskError::InternalError(_) | e @ TaskError::JoinError(_))) => {
                Err(TaskError::PropagatedError(Box::new(e)))
            },
            Err(e) => Err(TaskError::JoinError(Arc::new(e))),
        }
    }
    .boxed()
    .shared()
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L502-511)
```rust
        let ledger_update_fut = spawn_shared_fut(
            Self::ledger_update(
                rand_check_fut.clone(),
                execute_fut.clone(),
                parent.ledger_update_fut.clone(),
                self.executor.clone(),
                block.clone(),
            ),
            None,
        );
```

**File:** execution/executor/src/block_executor/mod.rs (L260-264)
```rust
    fn ledger_update(
        &self,
        block_id: HashValue,
        parent_block_id: HashValue,
    ) -> ExecutorResult<StateComputeResult> {
```

**File:** execution/executor/src/block_executor/mod.rs (L271-288)
```rust
        let mut block_vec = self
            .block_tree
            .get_blocks_opt(&[block_id, parent_block_id])?;
        let parent_block = block_vec
            .pop()
            .expect("Must exist.")
            .ok_or(ExecutorError::BlockNotFound(parent_block_id))?;
        // At this point of time two things must happen
        // 1. The block tree must also have the current block id with or without the ledger update output.
        // 2. We must have the ledger update output of the parent block.
        // Above is not ture if the block is on a forked branch.
        let block = block_vec
            .pop()
            .expect("Must exist")
            .ok_or(ExecutorError::BlockNotFound(parent_block_id))?;
        parent_block.ensure_has_child(block_id)?;
        let output = &block.output;
        let parent_out = &parent_block.output;
```

**File:** execution/executor/src/block_executor/mod.rs (L291-294)
```rust
        if let Some(complete_result) = block.output.get_complete_result() {
            info!(block_id = block_id, "ledger_update already done.");
            return Ok(complete_result);
        }
```

**File:** execution/executor/src/block_executor/mod.rs (L301-328)
```rust
            output.set_state_checkpoint_output(
                parent_out
                    .ensure_state_checkpoint_output()?
                    .reconfig_suffix(),
            );
            output.set_ledger_update_output(
                parent_out.ensure_ledger_update_output()?.reconfig_suffix(),
            );
        } else {
            THREAD_MANAGER.get_non_exe_cpu_pool().install(|| {
                // TODO(aldenhu): remove? no known strategy to recover from this failure
                fail_point!("executor::block_state_checkpoint", |_| {
                    Err(anyhow::anyhow!("Injected error in block state checkpoint."))
                });
                output.set_state_checkpoint_output(DoStateCheckpoint::run(
                    &output.execution_output,
                    parent_block.output.ensure_result_state_summary()?,
                    &ProvableStateSummary::new_persisted(self.db.reader.as_ref())?,
                    None,
                )?);
                output.set_ledger_update_output(DoLedgerUpdate::run(
                    &output.execution_output,
                    output.ensure_state_checkpoint_output()?,
                    parent_out
                        .ensure_ledger_update_output()?
                        .transaction_accumulator
                        .clone(),
                )?);
```

**File:** execution/executor/src/block_executor/block_tree/mod.rs (L142-144)
```rust
    fn multi_get(&self, ids: &[HashValue]) -> Result<Vec<Option<Arc<Block>>>> {
        self.inner.lock().multi_get(ids)
    }
```

**File:** execution/executor/src/types/partial_state_compute_result.rs (L76-80)
```rust
    pub fn set_state_checkpoint_output(&self, state_checkpoint_output: StateCheckpointOutput) {
        self.state_checkpoint_output
            .set(state_checkpoint_output)
            .expect("StateCheckpointOutput already set");
    }
```

**File:** execution/executor/src/types/partial_state_compute_result.rs (L88-92)
```rust
    pub fn set_ledger_update_output(&self, ledger_update_output: LedgerUpdateOutput) {
        self.ledger_update_output
            .set(ledger_update_output)
            .expect("LedgerUpdateOutput already set");
    }
```
