# Audit Report

## Title
Memory Leak via Unreleased Consensus Layer References During Repeated State Synchronization

## Summary
The `executor.finish()` call in `sync_for_duration()` does not guarantee that all in-memory SparseMerkleTree (SMT) resources are freed because the consensus layer maintains independent references to execution outputs through `PipelinedBlock` instances, which are not cleared during state synchronization operations. [1](#0-0) 

## Finding Description

When `sync_for_duration()` is called, it invokes `executor.finish()` with the explicit intent to "free the in-memory SMT held by the BlockExecutor to prevent a memory leak": [2](#0-1) 

However, `executor.finish()` only drops the executor's internal `BlockExecutorInner` structure: [3](#0-2) 

The problem is that the consensus layer maintains a **separate** `BlockTree` that stores `Arc<PipelinedBlock>` instances: [4](#0-3) 

Each `PipelinedBlock` contains a `StateComputeResult`: [5](#0-4) 

The `StateComputeResult` holds `ExecutionOutput` and `StateCheckpointOutput`, both wrapped in `Arc<DropHelper<Inner>>`: [6](#0-5) [7](#0-6) 

These structures eventually contain `LedgerStateSummary` which holds multiple `SparseMerkleTree` instances: [8](#0-7) 

When `executor.finish()` is called, it drops the executor's `BlockTree`, but the consensus layer's `BlockTree` still maintains `Arc` references to the `PipelinedBlock` instances. As long as these `Arc` references exist, the reference counts for the `ExecutionOutput` and `StateCheckpointOutput` remain non-zero, preventing the `DropHelper` from freeing the large SMT structures.

During repeated state sync operations (e.g., a node repeatedly falling behind), the consensus `BlockTree` is not cleared in `sync_for_duration()`: [9](#0-8) 

The function only manages the executor's state, not the consensus layer's block storage.

## Impact Explanation

This constitutes a **Medium severity** vulnerability under the Aptos Bug Bounty program's "State inconsistencies requiring intervention" category. 

Under repeated state synchronization scenarios, large SparseMerkleTree structures accumulate in memory through consensus layer references that are not cleared by `executor.finish()`. While the async dropper provides backpressure (blocking after 32 queued tasks), this doesn't prevent the underlying issue: consensus blocks with their associated execution state remain in memory even after the executor claims to have freed SMT resources. [10](#0-9) 

In scenarios where a validator node repeatedly falls behind and syncs (due to network issues, resource constraints, or operational conditions), memory consumption grows beyond expected bounds, potentially leading to:
- Out-of-memory crashes requiring node restarts
- Performance degradation affecting consensus participation
- Unexpected resource exhaustion during critical operations

## Likelihood Explanation

This issue occurs under realistic operational conditions:

1. **Validator nodes that intermittently lag**: Nodes with marginal resources or temporary network issues frequently trigger state sync
2. **Network partitions**: Nodes rejoining after disconnections perform state sync
3. **High-throughput periods**: Nodes struggling to keep up may repeatedly sync

The likelihood is **moderate** because:
- State sync operations are common in validator operations
- The consensus layer's block retention policy may not align with executor resource cleanup expectations
- No explicit consensus block cleanup occurs during `sync_for_duration()`

## Recommendation

Implement explicit consensus layer state cleanup when state synchronization completes. Two approaches:

**Option 1: Clear consensus BlockTree on sync** - Add a method to clear speculative consensus blocks when entering state sync:

```rust
async fn sync_for_duration(
    &self,
    duration: Duration,
) -> Result<LedgerInfoWithSignatures, StateSyncError> {
    let mut latest_logical_time = self.write_mutex.lock().await;
    
    // Clear consensus layer blocks before sync
    if let Some(inner) = self.state.read().as_ref() {
        inner.network_sender.clear_speculative_state();
    }
    
    self.executor.finish();
    // ... rest of function
}
```

**Option 2: Verify complete cleanup** - Add verification that all Arc references are dropped:

```rust
fn finish(&self) {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);
    
    if let Some(inner) = self.inner.write().take() {
        // Wait for async drops to complete
        DEFAULT_DROPPER.wait_for_backlog_drop(0);
        drop(inner);
    }
}
```

**Option 3: Document limitation** - If the current behavior is intentional, update the comment to clarify that only executor-owned SMT resources are freed, not consensus layer references.

## Proof of Concept

```rust
// Conceptual test demonstrating the issue
// This would require access to both consensus and executor internals

#[tokio::test]
async fn test_repeated_sync_memory_accumulation() {
    let executor = create_test_executor();
    let consensus_block_store = create_test_block_store();
    
    // Simulate blocks being added to consensus
    for i in 0..100 {
        let block = create_block_with_large_state(i);
        consensus_block_store.insert_block(block);
    }
    
    // First sync
    executor.finish();
    let memory_after_first_sync = get_memory_usage();
    executor.reset().unwrap();
    
    // Add more blocks
    for i in 100..200 {
        let block = create_block_with_large_state(i);
        consensus_block_store.insert_block(block);
    }
    
    // Second sync
    executor.finish();
    let memory_after_second_sync = get_memory_usage();
    
    // Memory should not accumulate beyond expected bounds
    // But due to consensus references, it does:
    assert!(
        memory_after_second_sync < memory_after_first_sync * 1.5,
        "Memory accumulated beyond expected: {} vs {}",
        memory_after_second_sync,
        memory_after_first_sync
    );
}
```

**Notes:**
- The actual memory leak depends on how long consensus blocks are retained
- The DropHelper's async dropping with backpressure mitigates but doesn't eliminate the issue
- The comment at line 140 of `consensus/src/state_computer.rs` creates a false expectation that all SMT memory is freed

### Citations

**File:** consensus/src/state_computer.rs (L132-174)
```rust
    async fn sync_for_duration(
        &self,
        duration: Duration,
    ) -> Result<LedgerInfoWithSignatures, StateSyncError> {
        // Grab the logical time lock
        let mut latest_logical_time = self.write_mutex.lock().await;

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by the BlockExecutor to prevent a memory leak.
        self.executor.finish();

        // Inject an error for fail point testing
        fail_point!("consensus::sync_for_duration", |_| {
            Err(anyhow::anyhow!("Injected error in sync_for_duration").into())
        });

        // Invoke state sync to synchronize for the specified duration. Here, the
        // ChunkExecutor will process chunks and commit to storage. However, after
        // block execution and commits, the internal state of the ChunkExecutor may
        // not be up to date. So, it is required to reset the cache of the
        // ChunkExecutor in state sync when requested to sync.
        let result = monitor!(
            "sync_for_duration",
            self.state_sync_notifier.sync_for_duration(duration).await
        );

        // Update the latest logical time
        if let Ok(latest_synced_ledger_info) = &result {
            let ledger_info = latest_synced_ledger_info.ledger_info();
            let synced_logical_time = LogicalTime::new(ledger_info.epoch(), ledger_info.round());
            *latest_logical_time = synced_logical_time;
        }

        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        // Return the result
        result.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
            anyhow_error.into()
        })
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L151-155)
```rust
    fn finish(&self) {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "finish"]);

        *self.inner.write() = None;
    }
```

**File:** consensus/src/block_storage/block_tree.rs (L73-100)
```rust
pub struct BlockTree {
    /// All the blocks known to this replica (with parent links)
    id_to_block: HashMap<HashValue, LinkableBlock>,
    /// Root of the tree. This is the root of ordering phase
    ordered_root_id: HashValue,
    /// Commit Root id: this is the root of commit phase
    commit_root_id: HashValue,
    /// Window Root id: this is the first item in the [`OrderedBlockWindow`](OrderedBlockWindow)
    window_root_id: HashValue,
    /// A certified block id with highest round
    highest_certified_block_id: HashValue,

    /// The quorum certificate of highest_certified_block
    highest_quorum_cert: Arc<QuorumCert>,
    /// The highest 2-chain timeout certificate (if any).
    highest_2chain_timeout_cert: Option<Arc<TwoChainTimeoutCertificate>>,
    /// The quorum certificate that has highest commit info.
    highest_ordered_cert: Arc<WrappedLedgerInfo>,
    /// The quorum certificate that has highest commit decision info.
    highest_commit_cert: Arc<WrappedLedgerInfo>,
    /// Map of block id to its completed quorum certificate (2f + 1 votes)
    id_to_quorum_cert: HashMap<HashValue, Arc<QuorumCert>>,
    /// To keep the IDs of the elements that have been pruned from the tree but not cleaned up yet.
    pruned_block_ids: VecDeque<HashValue>,
    /// Num pruned blocks to keep in memory.
    max_pruned_blocks_in_mem: usize,
    /// Round to Block index. We expect only one block per round.
    round_to_ids: BTreeMap<Round, HashValue>,
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L208-208)
```rust
    state_compute_result: Mutex<StateComputeResult>,
```

**File:** execution/executor-types/src/execution_output.rs (L26-29)
```rust
pub struct ExecutionOutput {
    #[deref]
    inner: Arc<DropHelper<Inner>>,
}
```

**File:** execution/executor-types/src/state_checkpoint_output.rs (L13-17)
```rust
#[derive(Clone, Debug, Deref)]
pub struct StateCheckpointOutput {
    #[deref]
    inner: Arc<DropHelper<Inner>>,
}
```

**File:** storage/storage-interface/src/state_store/state_summary.rs (L30-37)
```rust
#[derive(Clone, Debug)]
pub struct StateSummary {
    /// The next version. If this is 0, the state is the "pre-genesis" empty state.
    next_version: Version,
    pub hot_state_summary: SparseMerkleTree,
    pub global_state_summary: SparseMerkleTree,
    hot_state_config: HotStateConfig,
}
```

**File:** crates/aptos-drop-helper/src/async_concurrent_dropper.rs (L112-119)
```rust
    fn inc(&self) {
        let mut num_tasks = self.lock.lock();
        while *num_tasks >= self.max_tasks {
            num_tasks = self.cvar.wait(num_tasks).expect("lock poisoned.");
        }
        *num_tasks += 1;
        GAUGE.set_with(&[self.name, "num_tasks"], *num_tasks as i64);
    }
```
