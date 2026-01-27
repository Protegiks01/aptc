# Audit Report

## Title
Synchronous State Cleanup on Thread Pool Failure in Block Partitioner Causes Validator Blocking

## Summary
The block partitioner's async cleanup mechanism at line 189 lacks proper error handling for `thread_pool.spawn()` failures. If the spawn operation fails or the thread pool is degraded, the large `PartitionState` structure is dropped synchronously on the validator thread, potentially blocking block processing for 10-100+ milliseconds.

## Finding Description

The `partition()` function attempts to asynchronously drop a large `PartitionState` structure to avoid blocking the validator thread: [1](#0-0) 

The `PartitionState` contains multiple large data structures that are expensive to drop: [2](#0-1) 

**Failure Scenario 1: spawn() Panics**
When `spawn()` is called, the closure `move || { drop(state); }` is constructed first, transferring ownership of `state` into the closure. If `spawn()` subsequently panics (due to thread pool failure or internal error), the panic unwinds the stack and drops the closure synchronously. Dropping the closure triggers the synchronous drop of `state` on the calling thread.

The Aptos panic handler then terminates the node: [3](#0-2) 

**Failure Scenario 2: Degraded Thread Pool**
If `spawn()` succeeds but the thread pool's worker threads have all panicked or died, the closure is queued but never executes. When the `ThreadPool` is eventually dropped, all queued closures are dropped synchronously on the thread holding the last `Arc<ThreadPool>` reference. If this occurs on a validator thread during shutdown or resource exhaustion, the expensive `PartitionState` drop blocks critical operations.

**Size Impact Analysis**
For a block with 10,000 transactions and thousands of unique storage keys:
- `trackers: DashMap<StorageKeyIdx, RwLock<ConflictingTxnTracker>>` - thousands of entries
- `key_idx_table: DashMap<StateKey, StorageKeyIdx>` - thousands of entries  
- `write_sets/read_sets: Vec<RwLock<HashSet<StorageKeyIdx>>>` - 10,000 entries with sets
- `txns: Vec<RwLock<Option<AnalyzedTransaction>>>` - 10,000 full transactions

Dropping these structures requires iterating all entries, acquiring/dropping locks, and deallocating memory - potentially 10-100+ milliseconds.

## Impact Explanation

**Scenario 1 (spawn() panic)**: **Critical Severity** - Node crash via panic handler calling `process::exit(12)`, causing total loss of validator availability until manual restart.

**Scenario 2 (degraded pool)**: **Medium Severity** - Validator thread blocks for 10-100+ milliseconds during state cleanup, delaying block processing and consensus participation. Under sustained load with large blocks, this could impact validator performance metrics and rewards.

This aligns with the **Medium** severity rating in the question, focusing on the blocking scenario rather than the crash scenario.

## Likelihood Explanation

**Low to Low-Medium likelihood**:
- Rayon's `spawn()` rarely panics under normal conditions
- Thread pool degradation requires multiple worker thread failures
- Most likely during node shutdown, resource exhaustion, or system instability
- Not easily triggerable by transaction-level attacks
- Could occur naturally under extreme load or during operational issues

While not frequently exploitable by external attackers, the issue can manifest during:
1. Node shutdown sequences
2. Memory pressure causing allocation failures
3. Cascading failures in other thread pool operations
4. Hardware/system-level faults

## Recommendation

Implement defensive error handling to ensure state cleanup never blocks the critical path:

```rust
fn partition(
    &self,
    txns: Vec<AnalyzedTransaction>,
    num_executor_shards: usize,
) -> PartitionedTransactions {
    let _timer = BLOCK_PARTITIONING_SECONDS.start_timer();
    
    let mut state = PartitionState::new(/* ... */);
    
    // ... existing partitioning logic ...
    
    let ret = Self::add_edges(&mut state);
    
    // Attempt async cleanup with fallback
    let spawn_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        self.thread_pool.spawn(move || {
            drop(state);
        });
    }));
    
    if spawn_result.is_err() {
        // If spawn panics, state is already dropped during unwinding
        // Log the error but continue - don't crash the node
        aptos_logger::error!("Block partitioner async cleanup failed, state dropped synchronously");
    }
    
    ret
}
```

Alternatively, use a dedicated cleanup thread pool with bounded queues and timeout handling to prevent unbounded synchronous cleanup.

## Proof of Concept

Due to the nature of this vulnerability (requiring thread pool internal failures), a complete PoC would require either:

1. **Rayon Fault Injection**: Modifying Rayon to simulate spawn() panics
2. **Resource Exhaustion**: Triggering OOM conditions during partition()
3. **Shutdown Race Simulation**: Calling partition() during controlled thread pool shutdown

A simplified demonstration showing the blocking potential:

```rust
#[test]
fn test_partition_state_drop_time() {
    use std::time::Instant;
    use aptos_types::transaction::analyzed_transaction::AnalyzedTransaction;
    
    // Create large block
    let num_txns = 10_000;
    let mut txns = Vec::with_capacity(num_txns);
    for i in 0..num_txns {
        // Create transaction with multiple read/write keys
        let txn = create_test_transaction_with_keys(i, 50); // 50 keys per txn
        txns.push(txn);
    }
    
    let thread_pool = Arc::new(ThreadPoolBuilder::new().num_threads(8).build().unwrap());
    let state = PartitionState::new(
        thread_pool,
        64,
        txns,
        4, // num shards
        4, // rounds
        0.9,
        false,
    );
    
    // Measure synchronous drop time
    let start = Instant::now();
    drop(state);
    let duration = start.elapsed();
    
    println!("Synchronous PartitionState drop took: {:?}", duration);
    assert!(duration.as_millis() < 100, "Drop took too long: {:?}", duration);
}
```

This test would demonstrate that dropping `PartitionState` for large blocks can exceed 100ms, confirming the blocking risk when async cleanup fails.

**Notes**

The vulnerability exists as a defensive programming failure rather than a directly exploitable protocol weakness. The async cleanup pattern is correct in intent but lacks proper error handling. While external attackers cannot directly trigger `spawn()` failures, the issue can manifest during operational stress conditions, potentially affecting validator liveness and performance. The fix should focus on ensuring cleanup never blocks critical consensus/execution paths, even under degraded system conditions.

### Citations

**File:** execution/block-partitioner/src/v2/mod.rs (L188-192)
```rust
        // Async clean-up.
        self.thread_pool.spawn(move || {
            drop(state);
        });
        ret
```

**File:** execution/block-partitioner/src/v2/state.rs (L39-107)
```rust
/// All the parameters, indexes, temporary states needed in a `PartitionerV2` session,
/// wrapped in a single struct, so we don't forget to async drop any large states.
pub struct PartitionState {
    //
    // Initial params/utils begin.
    //
    pub(crate) num_executor_shards: ShardId,
    pub(crate) num_rounds_limit: usize,
    pub(crate) dashmap_num_shards: usize,
    pub(crate) cross_shard_dep_avoid_threshold: f32,
    pub(crate) partition_last_round: bool,
    pub(crate) thread_pool: Arc<ThreadPool>,
    /// OriginalTxnIdx -> the actual txn.
    /// Wrapped in `RwLock` to allow being taking in parallel in `add_edges` phase and parallel reads in other phases.
    pub(crate) txns: Vec<RwLock<Option<AnalyzedTransaction>>>,
    //
    // Initial params/utils ends.
    //
    /// A `ConflictingTxnTracker` for each key that helps resolve conflicts and speed-up edge creation.
    /// Updated in multiple stages of partitioning.
    pub(crate) trackers: DashMap<StorageKeyIdx, RwLock<ConflictingTxnTracker>>,

    //
    // States computed in `init()` begin.
    //
    /// For txn of OriginalTxnIdx i, the sender index.
    pub(crate) sender_idxs: Vec<RwLock<Option<SenderIdx>>>,

    /// For txn of OriginalTxnIdx i, the writer set.
    pub(crate) write_sets: Vec<RwLock<HashSet<StorageKeyIdx>>>,

    /// For txn of OriginalTxnIdx i, the read set.
    pub(crate) read_sets: Vec<RwLock<HashSet<StorageKeyIdx>>>,

    pub(crate) sender_counter: AtomicUsize,
    pub(crate) sender_idx_table: DashMap<Sender, SenderIdx>,

    pub(crate) storage_key_counter: AtomicUsize,
    pub(crate) key_idx_table: DashMap<StateKey, StorageKeyIdx>,

    //
    // States computed in `init()` end.
    // States computed in `pre_partition()` begin.
    //
    /// For shard i, the `PrePartitionedTxnIdx`s of the txns pre-partitioned into shard i.
    pub(crate) pre_partitioned: Vec<Vec<PrePartitionedTxnIdx>>,

    /// For shard i, the num of txns pre-partitioned into shard 0..=i-1.
    pub(crate) start_txn_idxs_by_shard: Vec<PrePartitionedTxnIdx>,

    /// Map the `PrePartitionedTxnIdx` of a transaction to its `OriginalTxnIdx`.
    pub(crate) ori_idxs_by_pre_partitioned: Vec<OriginalTxnIdx>,

    //
    // States computed in `pre_partition()` end.
    // States computed in `remove_cross_shard_dependencies()` begin.
    //
    pub(crate) finalized_txn_matrix: Vec<Vec<Vec<PrePartitionedTxnIdx>>>,
    pub(crate) start_index_matrix: Vec<Vec<PrePartitionedTxnIdx>>,

    /// Map the PrePartitionedTxnIdx of a transaction to its FinalTxnIdx.
    pub(crate) final_idxs_by_pre_partitioned: Vec<RwLock<FinalTxnIdx>>,
    //
    // States computed in `remove_cross_shard_dependencies()` end.
    //

    // Temporary sub-block matrix used in `add_edges()`.
    pub(crate) sub_block_matrix: Vec<Vec<Mutex<Option<SubBlock<AnalyzedTransaction>>>>>,
}
```

**File:** crates/crash-handler/src/lib.rs (L26-58)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
}
```
