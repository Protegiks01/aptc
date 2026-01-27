# Audit Report

## Title
Non-Atomic Checkpoint Creation Across Multiple RocksDB Databases Leads to Unusable Partial Checkpoints

## Summary
AptosDB's checkpoint creation is not atomic across its multiple constituent RocksDB databases (LedgerDb, StateKvDb, StateMerkleDb). Sequential checkpoint operations can be interrupted, creating partial checkpoints that cause node startup failure when restoration is attempted.

## Finding Description

AptosDB consists of multiple separate RocksDB database instances that are checkpointed sequentially rather than atomically. The checkpoint creation process executes as follows: [1](#0-0) 

When `create_checkpoint()` is called, it sequentially invokes checkpoint operations on:
1. LedgerDb (line 181)
2. StateKvDb (line 183, if sharding enabled)  
3. StateMerkleDb hot (lines 184-189, if sharding enabled)
4. StateMerkleDb cold (lines 191-196)

Each database's checkpoint operation is implemented separately: [2](#0-1) [3](#0-2) 

Within each database, the underlying RocksDB checkpoint API provides atomicity for all column families. However, there is no transactional mechanism ensuring all databases are checkpointed atomically as a unit.

**Vulnerability Scenario:**

If the checkpoint process is interrupted (system crash, kill signal, resource exhaustion) after completing some but not all database checkpoints, a partial checkpoint remains on disk. When attempting to restore from this checkpoint: [4](#0-3) 

With `create_if_missing=true` (default for non-readonly mode), RocksDB creates new empty databases for missing checkpoint components. During StateStore initialization, the synchronization check executes: [5](#0-4) [6](#0-5) 

The system expects StateKvCommitProgress metadata to exist and panics if it's absent (line 434), causing node startup failure.

## Impact Explanation

This issue meets **Medium Severity** criteria under the Aptos bug bounty program as "State inconsistencies requiring intervention." While the panic prevents actual state corruption (fail-safe behavior), it creates operational impact:

1. **Backup Integrity Compromise**: Partial checkpoints cannot be used for disaster recovery
2. **Extended Downtime Risk**: If a partial checkpoint is the only available backup during catastrophic failure, node recovery becomes impossible without alternative data sources
3. **Operational Reliability**: Checkpoint operations lack the transactional guarantees expected from critical backup infrastructure

The impact is limited to Medium rather than Critical because:
- The system fails safely (panics) rather than allowing silent state inconsistency
- No fund loss or consensus violation occurs
- Recovery is possible with proper operational procedures (retrying checkpoint creation)

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability manifests under the following conditions:
1. Operator initiates checkpoint creation (routine maintenance operation)
2. Process interruption occurs during the multi-second checkpoint window (system crash, OOM kill, manual termination, hardware failure)
3. Operator attempts to use the partial checkpoint for node restoration

While checkpoint operations are typically fast, the sequential processing of multiple large databases creates a window of vulnerability. System crashes during maintenance operations are not uncommon in production environments, particularly during high-load periods or resource constraints.

The issue is NOT exploitable by external attackers as it requires operator-level access to trigger checkpoint creation. However, it represents a reliability vulnerability in critical disaster recovery infrastructure.

## Recommendation

Implement atomic checkpoint creation across all AptosDB databases using a two-phase approach:

1. **Create checkpoints in a staging directory** with temporary naming
2. **Verify all checkpoints completed successfully**
3. **Atomically rename/move to final checkpoint directory**

Pseudocode fix:

```rust
pub fn create_checkpoint(
    db_path: impl AsRef<Path>,
    cp_path: impl AsRef<Path>,
    sharding: bool,
) -> Result<()> {
    let start = Instant::now();
    let temp_path = cp_path.as_ref().with_extension(".tmp");
    
    // Create checkpoints in temporary directory
    std::fs::create_dir_all(&temp_path)?;
    
    LedgerDb::create_checkpoint(db_path.as_ref(), &temp_path, sharding)?;
    if sharding {
        StateKvDb::create_checkpoint(db_path.as_ref(), &temp_path)?;
        StateMerkleDb::create_checkpoint(db_path.as_ref(), &temp_path, sharding, true)?;
    }
    StateMerkleDb::create_checkpoint(db_path.as_ref(), &temp_path, sharding, false)?;
    
    // Verify checkpoint completeness
    verify_checkpoint_completeness(&temp_path, sharding)?;
    
    // Atomic rename
    std::fs::rename(&temp_path, cp_path.as_ref())?;
    
    info!("Made atomic AptosDB checkpoint.");
    Ok(())
}

fn verify_checkpoint_completeness(path: &Path, sharding: bool) -> Result<()> {
    // Verify expected database directories exist
    ensure!(path.join("ledger_db").exists(), "LedgerDb checkpoint missing");
    if sharding {
        ensure!(path.join("state_kv_db").exists(), "StateKvDb checkpoint missing");
        ensure!(path.join("state_merkle_db").exists(), "StateMerkleDb checkpoint missing");
    }
    Ok(())
}
```

Additionally, add checkpoint validation before attempting restoration to provide clear error messages rather than panics.

## Proof of Concept

```rust
// Simulating interrupted checkpoint creation
use std::fs;
use std::path::PathBuf;

#[test]
fn test_partial_checkpoint_causes_startup_failure() {
    let source_db = PathBuf::from("/tmp/test_source_db");
    let checkpoint_dir = PathBuf::from("/tmp/test_checkpoint");
    
    // Setup: Create a populated AptosDB at source_db
    // (assume helper function creates DB with version 1000)
    let db = create_populated_test_db(&source_db, 1000);
    drop(db);
    
    // Simulate partial checkpoint: only LedgerDb
    fs::create_dir_all(&checkpoint_dir).unwrap();
    LedgerDb::create_checkpoint(&source_db, &checkpoint_dir, true).unwrap();
    // Simulate crash: StateKvDb and StateMerkleDb checkpoints NOT created
    
    // Attempt to open from partial checkpoint
    let result = AptosDB::open(
        StorageDirPaths::from_path(&checkpoint_dir),
        false, // not readonly
        NO_OP_STORAGE_PRUNER_CONFIG,
        RocksdbConfigs { enable_storage_sharding: true, ..Default::default() },
        false, // no indexer
        1000,
        1000,
        None,
        HotStateConfig::default(),
    );
    
    // Expected: Panic during sync_commit_progress due to missing StateKvCommitProgress
    assert!(result.is_err() || std::panic::catch_unwind(|| result.unwrap()).is_err());
}
```

## Notes

While this issue causes operational problems rather than security compromise, it violates the atomicity guarantees expected from checkpoint infrastructure critical for disaster recovery. The fail-safe panic behavior prevents actual state inconsistency, but the lack of atomic checkpoint creation remains a design limitation requiring architectural improvement for production-grade backup reliability.

### Citations

**File:** storage/aptosdb/src/db/mod.rs (L172-205)
```rust
    pub fn create_checkpoint(
        db_path: impl AsRef<Path>,
        cp_path: impl AsRef<Path>,
        sharding: bool,
    ) -> Result<()> {
        let start = Instant::now();

        info!(sharding = sharding, "Creating checkpoint for AptosDB.");

        LedgerDb::create_checkpoint(db_path.as_ref(), cp_path.as_ref(), sharding)?;
        if sharding {
            StateKvDb::create_checkpoint(db_path.as_ref(), cp_path.as_ref())?;
            StateMerkleDb::create_checkpoint(
                db_path.as_ref(),
                cp_path.as_ref(),
                sharding,
                /* is_hot = */ true,
            )?;
        }
        StateMerkleDb::create_checkpoint(
            db_path.as_ref(),
            cp_path.as_ref(),
            sharding,
            /* is_hot = */ false,
        )?;

        info!(
            db_path = db_path.as_ref(),
            cp_path = cp_path.as_ref(),
            time_ms = %start.elapsed().as_millis(),
            "Made AptosDB checkpoint."
        );
        Ok(())
    }
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L311-370)
```rust
    pub(crate) fn create_checkpoint(
        db_root_path: impl AsRef<Path>,
        cp_root_path: impl AsRef<Path>,
        sharding: bool,
    ) -> Result<()> {
        let rocksdb_configs = RocksdbConfigs {
            enable_storage_sharding: sharding,
            ..Default::default()
        };
        let env = None;
        let block_cache = None;
        let ledger_db = Self::new(
            db_root_path,
            rocksdb_configs,
            env,
            block_cache,
            /*readonly=*/ false,
        )?;
        let cp_ledger_db_folder = cp_root_path.as_ref().join(LEDGER_DB_FOLDER_NAME);

        info!(
            sharding = sharding,
            "Creating ledger_db checkpoint at: {cp_ledger_db_folder:?}"
        );

        std::fs::remove_dir_all(&cp_ledger_db_folder).unwrap_or(());
        if sharding {
            std::fs::create_dir_all(&cp_ledger_db_folder).unwrap_or(());
        }

        ledger_db
            .metadata_db()
            .create_checkpoint(Self::metadata_db_path(cp_root_path.as_ref(), sharding))?;

        if sharding {
            ledger_db
                .event_db()
                .create_checkpoint(cp_ledger_db_folder.join(EVENT_DB_NAME))?;
            ledger_db
                .persisted_auxiliary_info_db()
                .create_checkpoint(cp_ledger_db_folder.join(PERSISTED_AUXILIARY_INFO_DB_NAME))?;
            ledger_db
                .transaction_accumulator_db()
                .create_checkpoint(cp_ledger_db_folder.join(TRANSACTION_ACCUMULATOR_DB_NAME))?;
            ledger_db
                .transaction_auxiliary_data_db()
                .create_checkpoint(cp_ledger_db_folder.join(TRANSACTION_AUXILIARY_DATA_DB_NAME))?;
            ledger_db
                .transaction_db()
                .create_checkpoint(cp_ledger_db_folder.join(TRANSACTION_DB_NAME))?;
            ledger_db
                .transaction_info_db()
                .create_checkpoint(cp_ledger_db_folder.join(TRANSACTION_INFO_DB_NAME))?;
            ledger_db
                .write_set_db()
                .create_checkpoint(cp_ledger_db_folder.join(WRITE_SET_DB_NAME))?;
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L224-259)
```rust
    pub(crate) fn create_checkpoint(
        db_root_path: impl AsRef<Path>,
        cp_root_path: impl AsRef<Path>,
    ) -> Result<()> {
        // TODO(grao): Support path override here.
        let state_kv_db = Self::open_sharded(
            &StorageDirPaths::from_path(db_root_path),
            RocksdbConfig::default(),
            None,
            None,
            false,
        )?;
        let cp_state_kv_db_path = cp_root_path.as_ref().join(STATE_KV_DB_FOLDER_NAME);

        info!("Creating state_kv_db checkpoint at: {cp_state_kv_db_path:?}");

        std::fs::remove_dir_all(&cp_state_kv_db_path).unwrap_or(());
        std::fs::create_dir_all(&cp_state_kv_db_path).unwrap_or(());

        state_kv_db
            .metadata_db()
            .create_checkpoint(Self::metadata_db_path(cp_root_path.as_ref()))?;

        // TODO(HotState): should handle hot state as well.
        for shard_id in 0..NUM_STATE_SHARDS {
            state_kv_db
                .db_shard(shard_id)
                .create_checkpoint(Self::db_shard_path(
                    cp_root_path.as_ref(),
                    shard_id,
                    /* is_hot = */ false,
                ))?;
        }

        Ok(())
    }
```

**File:** storage/rocksdb-options/src/lib.rs (L38-41)
```rust
    if !readonly {
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L353-360)
```rust
        if !hack_for_tests && !empty_buffered_state_for_restore {
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
        }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L430-436)
```rust
            let state_kv_commit_progress = state_kv_db
                .metadata_db()
                .get::<DbMetadataSchema>(&DbMetadataKey::StateKvCommitProgress)
                .expect("Failed to read state K/V commit progress.")
                .expect("State K/V commit progress cannot be None.")
                .expect_version();
            assert_ge!(state_kv_commit_progress, overall_commit_progress);
```
