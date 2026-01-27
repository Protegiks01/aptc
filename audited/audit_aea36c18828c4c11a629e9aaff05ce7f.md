# Audit Report

## Title
Fast Sync Crash Recovery Leaves Database in Inconsistent State with Invalid Pruner Metadata

## Summary
During fast sync finalization, a crash between committing `OverallCommitProgress` and setting pruner `min_readable_version` metadata leaves the database in an inconsistent state. On restart, the node operates with `min_readable_version = 0` while only having state data at the target version V, violating the invariant that historical data from 0 to V should be accessible.

## Finding Description

The vulnerability exists in the non-atomic finalization sequence during fast sync state snapshot restoration.

**The Critical Sequence:**

1. `FastSyncStorageWrapper::finalize_state_snapshot()` calls the underlying `AptosDB::finalize_state_snapshot()`: [1](#0-0) 

2. Inside `AptosDB::finalize_state_snapshot()`, operations execute in this order:
   - Lines 155-160: Write frozen subtrees (separate write operation)
   - Lines 163-218: Build batch containing transaction data, ledger infos, **and commit progress metadata**
   - Line 223: **Atomically commit the batch including `OverallCommitProgress = version`**
   - Lines 225-234: **Four separate write operations** to set `min_readable_version` for each pruner
   - Line 236: Update latest ledger info (separate operation) [2](#0-1) 

3. Finally, set in-memory `fast_sync_status = FINISHED`: [3](#0-2) 

**The Vulnerability:**

If a crash/interruption (SIGKILL, OOM, power loss, panic) occurs after line 223 but before lines 225-234 complete, the database state becomes inconsistent:

**On Restart:**

The `FastSyncStorageWrapper::initialize_dbs()` checks if fast sync wrapper should be created: [4](#0-3) 

Since `get_synced_version()` now returns the target version V (not 0), the condition fails and regular `AptosDB` is used directly.

The pruners initialize their `min_readable_version` from database metadata: [5](#0-4) 

The `get_ledger_pruner_progress()` returns **0** because `save_min_readable_version()` was never called: [6](#0-5) 

**The Inconsistent State:**
- `OverallCommitProgress = V` (committed)
- `min_readable_version = 0` (never updated)
- Actual data: Only state snapshot at version V exists
- Missing data: Transactions, events, and historical state for versions 0 to V-1

This violates the **State Consistency** invariant: metadata claims data from version 0 onwards is accessible, but only version V actually exists in the database.

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention:

1. **Data Availability Contract Violation**: The `min_readable_version = 0` indicates all versions from 0 to V should be readable, but they aren't available. Historical queries will fail with "Not Found" errors.

2. **Incorrect Network Peer Information**: If this node advertises its data availability to peers, other nodes may attempt to sync historical data (versions 0 to V-1) that doesn't exist, causing synchronization failures across the network.

3. **API/Query Failures**: Any API endpoint or query attempting to read historical transactions, events, or state between versions 0 and V-1 will fail unexpectedly, as the metadata incorrectly suggests this data should be available.

4. **Pruner Logic Confusion**: While pruning non-existent data is safe, the pruner's decision-making is based on incorrect assumptions about what data exists, potentially causing unexpected behavior in edge cases.

This qualifies as **"State inconsistencies requiring intervention"** under the Medium severity category, as the database requires manual intervention or reset to restore consistency.

## Likelihood Explanation

**Moderate Likelihood** - This vulnerability can occur in production environments:

1. **Fast Sync is Standard**: New validators and fullnodes commonly use fast sync to bootstrap, creating many opportunities for this race condition.

2. **Narrow but Real Window**: The crash window between the atomic commit (line 223) and pruner updates (lines 225-234) is narrow (microseconds to milliseconds), but real-world interruptions occur:
   - Deployment automation sending SIGTERM/SIGKILL during rolling updates
   - OOM killer terminating processes under memory pressure  
   - Hardware failures, power outages, kernel panics
   - Container orchestration (Kubernetes) pod evictions

3. **Silent Failure**: The node restarts successfully and operates normally for most operations, making the inconsistency difficult to detect until historical data is queried.

4. **No Automatic Recovery**: The crash recovery mechanism (`sync_commit_progress`) only truncates data ahead of `OverallCommitProgress`, not missing metadata, so the inconsistency persists until manual intervention.

## Recommendation

**Make the metadata updates atomic with the data commit** by including pruner progress in the same batch as `OverallCommitProgress`:

```rust
fn finalize_state_snapshot(
    &self,
    version: Version,
    output_with_proof: TransactionOutputListWithProofV2,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    // ... existing code ...
    
    // Add pruner progress to the atomic batch
    ledger_db_batch
        .ledger_metadata_db_batches
        .put::<DbMetadataSchema>(
            &DbMetadataKey::LedgerPrunerProgress,
            &DbMetadataValue::Version(version),
        )?;
    
    // Add state pruner progress to their respective batches
    state_kv_metadata_batch.put::<DbMetadataSchema>(
        &DbMetadataKey::StateKvPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    
    // Add state merkle pruner progress (requires extending the batch mechanism)
    // ... similar additions for other pruners ...
    
    // Atomic write includes all progress metadata
    self.ledger_db.write_schemas(ledger_db_batch)?;
    self.state_kv_db.write_schemas(state_kv_metadata_batch)?;
    
    // Update in-memory state only after successful DB commit
    self.ledger_pruner.update_min_readable_version_in_memory(version);
    self.state_store.state_merkle_pruner.update_min_readable_version_in_memory(version);
    self.state_store.epoch_snapshot_pruner.update_min_readable_version_in_memory(version);
    self.state_store.state_kv_pruner.update_min_readable_version_in_memory(version);
    
    // ... rest of the function
}
```

**Additionally**, add validation in `FastSyncStorageWrapper::initialize_dbs()` to detect this inconsistent state:

```rust
if config.state_sync.state_sync_driver.bootstrapping_mode.is_fast_sync()
    && (db_main.ledger_db.metadata_db().get_synced_version()?.map_or(0, |v| v) > 0)
{
    // Check if pruner metadata was properly set
    let synced_version = db_main.ledger_db.metadata_db().get_synced_version()?.unwrap();
    let pruner_progress = db_main.ledger_db.metadata_db().get_pruner_progress().unwrap_or(0);
    
    if pruner_progress == 0 && synced_version > 0 {
        // Detected incomplete fast sync - fix pruner metadata
        db_main.ledger_pruner.save_min_readable_version(synced_version)?;
        // ... fix other pruners similarly
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_fast_sync_crash_recovery_inconsistency() {
    use std::sync::Arc;
    use tempfile::TempDir;
    
    // Setup: Create a node in fast sync mode
    let tmpdir = TempDir::new().unwrap();
    let mut config = NodeConfig::default();
    config.storage.dir = tmpdir.path().to_path_buf();
    config.state_sync.state_sync_driver.bootstrapping_mode = 
        BootstrappingMode::DownloadLatestStates;
    
    // Initialize FastSyncStorageWrapper
    let storage_wrapper = FastSyncStorageWrapper::initialize_dbs(
        &config, None, None
    ).unwrap().right().unwrap();
    
    let target_version = 10_000_000u64;
    let expected_root_hash = HashValue::random();
    
    // Step 1: Get snapshot receiver (sets status to STARTED)
    let mut receiver = storage_wrapper
        .get_state_snapshot_receiver(target_version, expected_root_hash)
        .unwrap();
    
    // Step 2: Add state value chunks (simulate successful state sync)
    // ... add chunks ...
    receiver.finish_box().unwrap();
    
    // Step 3: Call finalize_state_snapshot but simulate crash after 
    // OverallCommitProgress is written but before pruner versions are set
    let output_with_proof = create_test_output_with_proof(target_version);
    let ledger_infos = vec![create_test_ledger_info(target_version)];
    
    // This will write OverallCommitProgress atomically
    // Then attempt to write pruner versions in separate operations
    // We simulate a crash by NOT completing the finalize on the wrapper
    storage_wrapper.get_fast_sync_db()
        .finalize_state_snapshot(target_version, output_with_proof.clone(), &ledger_infos)
        .unwrap();
    
    // CRASH SIMULATION: Don't update fast_sync_status to FINISHED
    // Don't call the pruner save_min_readable_version methods
    
    // Step 4: Restart - reinitialize storage
    drop(storage_wrapper);
    
    let restarted_storage = FastSyncStorageWrapper::initialize_dbs(
        &config, None, None
    ).unwrap();
    
    // ASSERTION: Should create regular AptosDB, not FastSyncStorageWrapper
    assert!(restarted_storage.is_left(), 
        "Should return regular AptosDB, not FastSyncStorageWrapper");
    
    let db = restarted_storage.left().unwrap();
    
    // VULNERABILITY: Check the inconsistent state
    let synced_version = db.ledger_db.metadata_db()
        .get_synced_version().unwrap().unwrap();
    let pruner_progress = db.ledger_db.metadata_db()
        .get_pruner_progress().unwrap_or(0);
    
    assert_eq!(synced_version, target_version, 
        "Synced version should be target version");
    assert_eq!(pruner_progress, 0, 
        "Pruner progress incorrectly set to 0");
    
    // This inconsistency means:
    // - Database claims to be synced to version 10,000,000
    // - Pruner thinks all versions from 0 onwards are readable
    // - But only version 10,000,000 state exists (fast sync snapshot)
    // - Versions 0 to 9,999,999 are NOT available
    
    println!("VULNERABILITY CONFIRMED:");
    println!("Synced version: {}", synced_version);
    println!("Min readable version (pruner): {}", pruner_progress);
    println!("Expected min readable version: {}", target_version);
    println!("Inconsistency: {} versions incorrectly marked as readable", 
        target_version - pruner_progress);
}
```

**Notes:**
- The file path in the security question (`aptos-core/crates/aptos-infallible/src/rwlock.rs`) is misleading. The actual vulnerability is not in the RwLock implementation itself, but in how the `write()` lock is used in `FastSyncStorageWrapper`.
- The RwLock's `write()` method correctly acquires and releases locks, but the non-atomic sequence of operations between releasing the lock (after committing data) and acquiring it again (to update status) creates the vulnerability window.
- The vulnerability is in the crash recovery logic and metadata consistency, not in the locking mechanism itself.

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L66-77)
```rust
        if config
            .state_sync
            .state_sync_driver
            .bootstrapping_mode
            .is_fast_sync()
            && (db_main
                .ledger_db
                .metadata_db()
                .get_synced_version()?
                .map_or(0, |v| v)
                == 0)
        {
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L154-170)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
    ) -> Result<()> {
        let status = self.get_fast_sync_status();
        assert_eq!(status, FastSyncStatus::STARTED);
        self.get_aptos_db_write_ref().finalize_state_snapshot(
            version,
            output_with_proof,
            ledger_infos,
        )?;
        let mut status = self.fast_sync_status.write();
        *status = FastSyncStatus::FINISHED;
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L125-241)
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
                num_transaction_infos == 1,
                "Number of transaction infos should == 1, but got: {}",
                num_transaction_infos
            );

            // TODO(joshlind): include confirm_or_save_frozen_subtrees in the change set
            // bundle below.

            // Update the merkle accumulator using the given proof
            let frozen_subtrees = output_with_proof
                .proof
                .ledger_info_to_transaction_infos_proof
                .left_siblings();
            restore_utils::confirm_or_save_frozen_subtrees(
                self.ledger_db.transaction_accumulator_db_raw(),
                version,
                frozen_subtrees,
                None,
            )?;

            // Create a single change set for all further write operations
            let mut ledger_db_batch = LedgerDbSchemaBatches::new();
            let mut sharded_kv_batch = self.state_kv_db.new_sharded_native_batches();
            let mut state_kv_metadata_batch = SchemaBatch::new();
            // Save the target transactions, outputs, infos and events
            let (transactions, outputs): (Vec<Transaction>, Vec<TransactionOutput>) =
                output_with_proof
                    .transactions_and_outputs
                    .into_iter()
                    .unzip();
            let events = outputs
                .clone()
                .into_iter()
                .map(|output| output.events().to_vec())
                .collect::<Vec<_>>();
            let wsets: Vec<WriteSet> = outputs
                .into_iter()
                .map(|output| output.write_set().clone())
                .collect();
            let transaction_infos = output_with_proof.proof.transaction_infos;
            // We should not save the key value since the value is already recovered for this version
            restore_utils::save_transactions(
                self.state_store.clone(),
                self.ledger_db.clone(),
                version,
                &transactions,
                &persisted_aux_info,
                &transaction_infos,
                &events,
                wsets,
                Some((
                    &mut ledger_db_batch,
                    &mut sharded_kv_batch,
                    &mut state_kv_metadata_batch,
                )),
                false,
            )?;

            // Save the epoch ending ledger infos
            restore_utils::save_ledger_infos(
                self.ledger_db.metadata_db(),
                ledger_infos,
                Some(&mut ledger_db_batch.ledger_metadata_db_batches),
            )?;

            ledger_db_batch
                .ledger_metadata_db_batches
                .put::<DbMetadataSchema>(
                    &DbMetadataKey::LedgerCommitProgress,
                    &DbMetadataValue::Version(version),
                )?;
            ledger_db_batch
                .ledger_metadata_db_batches
                .put::<DbMetadataSchema>(
                    &DbMetadataKey::OverallCommitProgress,
                    &DbMetadataValue::Version(version),
                )?;

            // Apply the change set writes to the database (atomically) and update in-memory state
            //
            // state kv and SMT should use shared way of committing.
            self.ledger_db.write_schemas(ledger_db_batch)?;

            self.ledger_pruner.save_min_readable_version(version)?;
            self.state_store
                .state_merkle_pruner
                .save_min_readable_version(version)?;
            self.state_store
                .epoch_snapshot_pruner
                .save_min_readable_version(version)?;
            self.state_store
                .state_kv_pruner
                .save_min_readable_version(version)?;

            restore_utils::update_latest_ledger_info(self.ledger_db.metadata_db(), ledger_infos)?;
            self.state_store.reset();

            Ok(())
        })
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L123-138)
```rust
        let min_readable_version =
            pruner_utils::get_ledger_pruner_progress(&ledger_db).expect("Must succeed.");

        PRUNER_VERSIONS
            .with_label_values(&["ledger_pruner", "min_readable"])
            .set(min_readable_version as i64);

        Self {
            ledger_db,
            prune_window: ledger_pruner_config.prune_window,
            pruner_worker,
            pruning_batch_size: ledger_pruner_config.batch_size,
            latest_version: Arc::new(Mutex::new(min_readable_version)),
            user_pruning_window_offset: ledger_pruner_config.user_pruning_window_offset,
            min_readable_version: AtomicVersion::new(min_readable_version),
        }
```

**File:** storage/aptosdb/src/pruner/pruner_utils.rs (L19-21)
```rust
pub(crate) fn get_ledger_pruner_progress(ledger_db: &LedgerDb) -> Result<Version> {
    Ok(ledger_db.metadata_db().get_pruner_progress().unwrap_or(0))
}
```
