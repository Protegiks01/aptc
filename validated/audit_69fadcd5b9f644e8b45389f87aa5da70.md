# Audit Report

## Title
Race Condition in State Merkle Pruner Progress Metadata Allows Inconsistent State Where Pruned Nodes Are Marked as Available

## Summary
A race condition exists between the background pruner worker and state snapshot finalization that can cause the pruner progress metadata to become inconsistent with actual deleted Merkle tree nodes. This allows the system to report data as available when it has been pruned, violating state consistency guarantees and requiring manual intervention to resolve.

## Finding Description

The vulnerability stems from two independent code paths that write to the same database metadata key (`StateMerklePrunerProgress`) without synchronization:

**Path 1: Background Pruner Worker**

The pruner worker runs continuously in a separate thread, spawned during initialization. [1](#0-0) 

When pruning, it calls `maybe_prune_single_version()` which creates an atomic batch containing both node deletions AND progress metadata updates. [2](#0-1) 

The batch includes deletions of stale nodes and an update to the `StateMerklePrunerProgress` metadata key via `DbMetadataSchema`, written atomically to the database.

**Path 2: State Snapshot Finalization**

During state sync operations, `finalize_state_snapshot()` is called to finalize the snapshot restoration. [3](#0-2) 

This method calls `save_min_readable_version()` on the state merkle pruner. [4](#0-3) 

The `save_min_readable_version()` method performs a separate, independent write to the database using `write_pruner_progress()`. [5](#0-4) 

This writes directly to the database without any batching, using a simple `put` operation. [6](#0-5) 

**The Race Condition Timeline:**

1. **T1**: Node begins state sync to restore snapshot at version 1200 (long-running operation)
2. **T2**: While state sync is in progress, pruner worker executes `maybe_prune_single_version(1000, 1500)`
   - Creates batch with deletions for stale nodes at versions 1001-1500
   - Adds to batch: `PUT StateMerklePrunerProgress = 1500`
   - Writes batch atomically → Nodes for versions < 1500 are now DELETED
3. **T3**: State sync completes and calls `finalize_state_snapshot(version=1200)`
   - Calls `save_min_readable_version(1200)`
   - Writes: `PUT StateMerklePrunerProgress = 1200` (separate write)
   - **This overwrites the progress from 1500 back to 1200**
4. **Result**: Database state is inconsistent:
   - Progress metadata = 1200 (claims versions ≥1200 are available)
   - Actual Merkle nodes for versions 1200-1499 are DELETED

**No Synchronization Exists:**

The `finalize_state_snapshot` method does not acquire any locks (`commit_lock` or `pre_commit_lock`). [7](#0-6) [8](#0-7) 

The commit_lock and pre_commit_lock are only used in `pre_commit_ledger()` and `commit_ledger()`, but `finalize_state_snapshot()` does not use them. The pruner worker runs independently in a background thread via `PrunerWorkerInner::work()` without any coordination with state snapshot finalization. [9](#0-8) 

When attempting to read state at versions 1200-1499, the min_readable_version check would pass, but reading the actual nodes would fail because they were already pruned.

## Impact Explanation

This vulnerability causes **state inconsistency requiring manual intervention**, which aligns with **MEDIUM severity** under the Aptos bug bounty program.

**Specific Impacts:**

1. **State Consistency Violation**: The system reports that historical state data is available when it has actually been deleted, breaking the fundamental guarantee that queryable versions can be successfully read.

2. **Failed State Operations**: Any attempt to:
   - Read state at versions 1200-1499
   - Generate state proofs for those versions
   - Perform state sync from those versions
   
   Will fail with node-not-found errors, causing operational failures for validators and fullnodes.

3. **Operational Disruption**: Nodes experiencing this inconsistency cannot serve historical state queries or assist other nodes in state sync operations, degrading network functionality.

4. **Non-Recoverable Without Intervention**: Once the inconsistency occurs, it persists until manual database repair, complete re-sync from genesis or a valid snapshot, or the pruner eventually prunes past the affected range.

This meets MEDIUM severity criteria as it causes state inconsistencies requiring manual intervention but does not directly cause loss of funds, consensus safety violations, or permanent network partitions.

## Likelihood Explanation

**Likelihood: MEDIUM**

This race condition can occur during normal network operations whenever state snapshot restoration happens concurrently with active pruning:

**Triggering Scenarios:**
- Node performing state sync while pruner is running in the background
- Fast sync bootstrap operations where snapshot download is slower than pruner execution  
- Any scenario where state sync takes significant time (minutes to hours) allowing pruner to advance

**Why It's Realistic:**
- State sync operations are long-running (downloading and committing state values)
- The pruner runs continuously in the background on all nodes [10](#0-9) 
- No synchronization mechanism prevents concurrent execution between pruner worker and state snapshot finalization
- The race window exists throughout the entire state sync duration (minutes to hours)

The likelihood is MEDIUM rather than HIGH because:
- State sync operations are less frequent than normal transaction processing
- The timing must align such that pruner advances past the snapshot version during the sync
- Not all nodes will experience this simultaneously

## Recommendation

Implement proper synchronization between the pruner worker and state snapshot finalization:

1. **Option 1: Acquire Lock in finalize_state_snapshot**: Modify `finalize_state_snapshot()` to acquire the `commit_lock` or introduce a dedicated `pruner_lock` before calling `save_min_readable_version()`.

2. **Option 2: Atomic Compare-and-Swap**: Use atomic compare-and-swap operations when updating `StateMerklePrunerProgress` to prevent overwriting a higher progress value with a lower one.

3. **Option 3: Disable Pruner During Fast Sync**: Temporarily disable the pruner worker when fast sync status is `STARTED` and re-enable it after `finalize_state_snapshot()` completes.

4. **Option 4: Separate Keys**: Use separate database keys for "min_readable_version" (set by save_min_readable_version) and "pruner_progress" (set by the pruner), and reconcile them appropriately during reads.

The recommended approach is **Option 1** combined with **Option 2**: acquire a lock in `finalize_state_snapshot()` and use compare-and-swap to prevent regressing the progress value.

## Proof of Concept

This vulnerability occurs during the race between concurrent execution of:
1. `StateMerkleMetadataPruner::maybe_prune_single_version()` in the background pruner thread
2. `AptosDB::finalize_state_snapshot()` during state sync completion

The race can be observed by:
1. Starting a node with pruning enabled
2. Initiating a state snapshot restoration for version V
3. Monitoring the `StateMerklePrunerProgress` metadata key
4. Observing that the pruner advances past version V during the long-running state sync
5. When `finalize_state_snapshot(V)` completes, it overwrites the progress back to V
6. Attempting to query state at versions between V and the previous pruner progress will fail

Due to the timing-dependent nature of this race condition and the lack of direct test infrastructure to simulate concurrent pruner execution during state sync, a complete executable PoC would require modifications to the test framework to introduce controlled timing. However, the code paths and lack of synchronization are clearly evident in the cited source files.

## Notes

The comment in `PrunerManager` trait explicitly states that `save_min_readable_version` is "Only used at the end of fast sync to store the min_readable_version to db and update the in memory progress." [11](#0-10)  However, there is no mechanism to ensure the pruner worker doesn't concurrently modify the same database key during this operation.

### Citations

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L53-69)
```rust
    fn work(&self) {
        while !self.quit_worker.load(Ordering::SeqCst) {
            let pruner_result = self.pruner.prune(self.batch_size);
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
            if !self.pruner.is_pruning_pending() {
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            }
        }
    }
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L81-84)
```rust
        let worker_thread = std::thread::Builder::new()
            .name(format!("{name}_pruner"))
            .spawn(move || inner_cloned.work())
            .expect("Creating pruner thread should succeed.");
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_metadata_pruner.rs (L60-71)
```rust
        let mut batch = SchemaBatch::new();
        indices.into_iter().try_for_each(|index| {
            batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
            batch.delete::<S>(&index)
        })?;

        batch.put::<DbMetadataSchema>(
            &S::progress_metadata_key(None),
            &DbMetadataValue::Version(target_version_for_this_round),
        )?;

        self.metadata_db.write_schemas(batch)?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L50-53)
```rust
            let _lock = self
                .pre_commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L125-141)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
    ) -> Result<()> {
        let (output_with_proof, persisted_aux_info) = output_with_proof.into_parts();
        gauged_api("finalize_state_snapshot", || {
            // Ensure the output with proof only contains a single transaction output and info
            let num_transaction_outputs = output_with_proof.get_num_outputs();
            let num_transaction_infos = output_with_proof.proof.transaction_infos.len();
            ensure!(
                num_transaction_outputs == 1,
                "Number of transaction outputs should == 1, but got: {}",
                num_transaction_outputs
            );
            ensure!(
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L226-228)
```rust
            self.state_store
                .state_merkle_pruner
                .save_min_readable_version(version)?;
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L74-84)
```rust
    fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&[S::name(), "min_readable"])
            .set(min_readable_version as i64);

        self.state_merkle_db
            .write_pruner_progress(&S::progress_metadata_key(None), min_readable_version)
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L110-117)
```rust
        let pruner_worker = if state_merkle_pruner_config.enable {
            Some(Self::init_pruner(
                Arc::clone(&state_merkle_db),
                state_merkle_pruner_config,
            ))
        } else {
            None
        };
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L568-575)
```rust
    pub(crate) fn write_pruner_progress(
        &self,
        progress_key: &DbMetadataKey,
        version: Version,
    ) -> Result<()> {
        self.state_merkle_metadata_db
            .put::<DbMetadataSchema>(progress_key, &DbMetadataValue::Version(version))
    }
```

**File:** storage/aptosdb/src/db/mod.rs (L35-37)
```rust
    pre_commit_lock: std::sync::Mutex<()>,
    /// This is just to detect concurrent calls to `commit_ledger()`
    commit_lock: std::sync::Mutex<()>,
```

**File:** storage/aptosdb/src/pruner/pruner_manager.rs (L33-35)
```rust
    // Only used at the end of fast sync to store the min_readable_version to db and update the
    // in memory progress.
    fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()>;
```
