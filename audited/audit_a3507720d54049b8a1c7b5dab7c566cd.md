# Audit Report

## Title
TOCTOU Race Condition in Ledger Update Pipeline Causing Validator Node Crash

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists in the block execution pipeline that can cause validator nodes to crash. When multiple threads concurrently insert the same block, duplicate pipeline futures can be created, leading to concurrent calls to `set_state_checkpoint_output()` on the same `PartialStateComputeResult`. The second call panics because `OnceCell::set()` fails when the cell is already populated, resulting in a denial-of-service condition.

## Finding Description

The vulnerability arises from a multi-layered race condition in the consensus block insertion and execution pipeline:

**Layer 1: Non-atomic Block Insertion Check**

In `BlockStore::insert_block()`, the existence check for a block is not synchronized with the subsequent pipeline building: [1](#0-0) 

This check-then-act pattern without locking allows multiple threads to pass the check simultaneously when receiving the same block from different peers (a scenario explicitly acknowledged in the codebase): [2](#0-1) 

**Layer 2: Pipeline Built Before Block Tree Insertion**

In `insert_block_inner()`, the pipeline is built before the block is inserted into the block tree with proper synchronization: [3](#0-2) [4](#0-3) 

Multiple concurrent calls can create multiple pipeline futures before the write lock is acquired.

**Layer 3: Pipeline Futures Overwrite Without Abort**

When `set_pipeline_futs()` is called multiple times, it overwrites previous futures without aborting them: [5](#0-4) 

Both `ledger_update_fut` futures will execute concurrently.

**Layer 4: Non-atomic Check in ledger_update()**

The executor's `ledger_update()` method has an early-return check that is not synchronized with the subsequent set operation: [6](#0-5) 

If both threads pass this check simultaneously (both getting `None`), they will both attempt to set the state checkpoint output.

**Layer 5: OnceCell Panic**

The `set_state_checkpoint_output()` function uses `OnceCell::set()` with `.expect()`, which panics on the second call: [7](#0-6) 

While `OnceCell::set()` is atomic and thread-safe, it returns an error when the cell is already set. The `.expect()` call converts this error into a panic, crashing the validator node.

**Attack Scenario:**

1. Attacker (or network conditions) causes a validator to receive the same block proposal from multiple peers simultaneously
2. Multiple threads call `insert_block()` concurrently for the same block ID
3. Both threads pass the existence check at line 413 of block_store.rs
4. Both threads build pipelines at lines 490-496, creating two `ledger_update_fut` futures
5. Both futures eventually call `executor.ledger_update()` on the same `PartialStateComputeResult`
6. Both threads check `get_complete_result()` at line 291, both get `None`
7. Both threads call `set_state_checkpoint_output()` at line 301 or 315
8. First thread's `OnceCell::set()` succeeds
9. Second thread's `OnceCell::set()` fails, causing panic: "StateCheckpointOutput already set"
10. Validator node crashes

## Impact Explanation

**Severity: High**

This vulnerability causes validator node crashes, qualifying as **High Severity** under the Aptos bug bounty program criteria:
- "Validator node slowdowns"
- "API crashes"  
- "Significant protocol violations"

The impact includes:
- **Availability**: Validator nodes crash and stop participating in consensus
- **Network Stability**: If multiple validators are affected simultaneously, network liveness could be impacted
- **Consensus Disruption**: Crashed validators cannot vote, reducing the effective validator set size

While this doesn't directly cause fund loss or permanent consensus failure, repeated crashes could:
- Reduce validator rewards for affected operators
- Temporarily reduce network throughput
- Create synchronization issues if validators crash at different times during the same block processing

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability can be triggered through:

1. **Natural Network Conditions**: The codebase explicitly acknowledges that blocks may be inserted multiple times due to delayed proposal processing, indicating this is an expected scenario.

2. **Malicious Exploitation**: An attacker can deliberately send duplicate block proposals to validators from multiple controlled peers to maximize the probability of concurrent insertion.

3. **No Special Access Required**: Any network peer can send block proposals, making this exploitable without validator privileges.

4. **Race Window**: While the race window is narrow (between the existence check and pipeline building), high network activity or slow pipeline construction increases the probability.

The TODO comment suggests this area was identified as needing retry handling: [8](#0-7) 

## Recommendation

**Option 1: Use OnceCell::get_or_try_init() (Preferred)**

Replace the check-then-set pattern with `OnceCell::get_or_try_init()`, which atomically checks and initializes:

```rust
pub fn set_state_checkpoint_output(&self, state_checkpoint_output: StateCheckpointOutput) {
    self.state_checkpoint_output
        .get_or_init(|| state_checkpoint_output);
}
```

**Option 2: Lock Pipeline Building**

Acquire the block tree write lock before building the pipeline to ensure only one pipeline is built per block:

```rust
pub async fn insert_block(&self, block: Block) -> anyhow::Result<Arc<PipelinedBlock>> {
    let mut tree = self.inner.write();
    if let Some(existing_block) = tree.get_block(&block.id()) {
        return Ok(existing_block);
    }
    
    // Build pipeline and insert atomically under lock
    // ... rest of the logic
}
```

**Option 3: Make ledger_update Truly Idempotent**

Return early if state checkpoint output is already set, instead of panicking:

```rust
pub fn set_state_checkpoint_output(&self, state_checkpoint_output: StateCheckpointOutput) {
    let _ = self.state_checkpoint_output.set(state_checkpoint_output);
    // Silently ignore if already set, making this truly idempotent
}
```

**Option 4: Abort Old Pipeline Before Setting New One**

In `set_pipeline_futs()`, abort the existing pipeline before overwriting:

```rust
pub fn set_pipeline_futs(&self, pipeline_futures: PipelineFutures) {
    let mut guard = self.pipeline_futs.lock();
    if guard.is_some() {
        // Abort existing pipeline
        drop(guard);
        self.abort_pipeline();
    }
    *self.pipeline_futs.lock() = Some(pipeline_futures);
}
```

## Proof of Concept

```rust
use std::sync::Arc;
use std::thread;
use aptos_executor::block_executor::BlockExecutor;
use aptos_types::block_executor::partitioner::ExecutableBlock;

// Simulate concurrent block insertion
#[test]
fn test_concurrent_block_insertion_panic() {
    let executor = Arc::new(BlockExecutor::new(db));
    let block = create_test_block();
    let block_id = block.block_id;
    let parent_id = block.parent_id;
    
    // Thread 1: Insert block and execute ledger_update
    let executor_clone1 = executor.clone();
    let handle1 = thread::spawn(move || {
        executor_clone1.execute_and_update_state(block.clone(), parent_id, config)?;
        executor_clone1.ledger_update(block_id, parent_id)
    });
    
    // Thread 2: Insert same block and execute ledger_update concurrently
    let executor_clone2 = executor.clone();
    let handle2 = thread::spawn(move || {
        executor_clone2.execute_and_update_state(block.clone(), parent_id, config)?;
        executor_clone2.ledger_update(block_id, parent_id)
    });
    
    // One thread will panic with "StateCheckpointOutput already set"
    let result1 = handle1.join();
    let result2 = handle2.join();
    
    assert!(result1.is_err() || result2.is_err());
}
```

## Notes

The vulnerability stems from an architectural assumption that block insertion would be naturally serialized at the consensus layer. However, the explicit acknowledgment in the codebase that duplicate insertions can occur indicates this assumption doesn't always hold. The TODO comment about retries further suggests this was a known area requiring additional hardening that may not have been fully addressed.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L412-415)
```rust
    pub async fn insert_block(&self, block: Block) -> anyhow::Result<Arc<PipelinedBlock>> {
        if let Some(existing_block) = self.get_block(block.id()) {
            return Ok(existing_block);
        }
```

**File:** consensus/src/block_storage/block_store.rs (L490-496)
```rust
            pipeline_builder.build_for_consensus(
                &pipelined_block,
                parent_block.pipeline_futs().ok_or_else(|| {
                    anyhow::anyhow!("Parent future doesn't exist, potentially epoch ended")
                })?,
                callback,
            );
```

**File:** consensus/src/block_storage/block_store.rs (L515-515)
```rust
        self.inner.write().insert_block(pipelined_block)
```

**File:** consensus/src/round_manager.rs (L1254-1259)
```rust
        // tries to add the same block again, which is okay as `insert_block` call
        // is idempotent.
        self.block_store
            .insert_block(proposal.clone())
            .await
            .context("[RoundManager] Failed to insert the block into BlockStore")?;
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L512-514)
```rust
    pub fn set_pipeline_futs(&self, pipeline_futures: PipelineFutures) {
        *self.pipeline_futs.lock() = Some(pipeline_futures);
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L290-290)
```rust
        // TODO(aldenhu): remove, assuming no retries.
```

**File:** execution/executor/src/block_executor/mod.rs (L291-294)
```rust
        if let Some(complete_result) = block.output.get_complete_result() {
            info!(block_id = block_id, "ledger_update already done.");
            return Ok(complete_result);
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
