# Audit Report

## Title
Non-Atomic Checkpoint Creation Enables Data Loss During Disaster Recovery

## Summary
The `LedgerDb::create_checkpoint()` function unconditionally deletes existing checkpoint directories before creating new checkpoints, with no verification of the old checkpoint's validity or atomicity guarantees for the replacement operation. This creates a window where both old and new recovery data can be permanently lost if checkpoint creation fails.

## Finding Description

The vulnerability exists in the checkpoint creation flow: [1](#0-0) 

The critical flaw is at line 336, where existing checkpoint directories are unconditionally deleted using `.unwrap_or(())`, which silently ignores deletion failures. This occurs **before** any verification that:
1. The new checkpoint creation will succeed
2. The old checkpoint is corrupt or should be replaced
3. Sufficient disk space exists for the new checkpoint

After deletion, the function attempts to create checkpoints for 8 separate sub-databases (metadata, events, transactions, etc.). If **any** of these operations fail due to:
- Disk space exhaustion
- I/O errors (network storage failures, hardware errors)
- Permission issues
- Process crashes or kills
- System resource limits

The old checkpoint is already permanently deleted, leaving the system with **no valid recovery checkpoint**.

This pattern is replicated across all checkpoint creation functions: [2](#0-1) [3](#0-2) [4](#0-3) 

Notably, the CLI wrapper in `db_debugger` implements a safety check that the core functions lack: [5](#0-4) 

However, this protection only exists in the CLI tool, not in the underlying checkpoint creation logic.

## Impact Explanation

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." While checkpoints are not part of the live blockchain state, they are critical for disaster recovery scenarios.

**Medium Severity** per Aptos Bug Bounty criteria - "State inconsistencies requiring intervention":
- If a validator's primary database becomes corrupted and the checkpoint was destroyed during a failed checkpoint creation, the validator cannot recover locally
- While the continuous backup service provides redundancy, checkpoints are the **primary local recovery mechanism** for fast disaster recovery
- Loss of checkpoints forces reliance on slower state sync from network peers or remote backup restoration
- In scenarios where both the primary DB and checkpoint are lost (e.g., during the checkpoint creation failure), validator downtime is significantly extended

The `truncate` module demonstrates the criticality of checkpoints for disaster recovery: [6](#0-5) 

## Likelihood Explanation

**Moderate-to-High Likelihood** in production environments:

1. **Disk Space Exhaustion**: Common in long-running blockchain nodes with growing state
2. **I/O Errors**: Network-attached storage, hardware degradation, filesystem issues
3. **Process Crashes**: OOM kills, system updates, operator errors
4. **Concurrent Operations**: Multiple processes attempting checkpoint operations

The checkpoint creation is invoked in several contexts: [7](#0-6) 

Automated checkpoint processes or operator scripts could trigger this vulnerability during normal operations.

## Recommendation

Implement atomic checkpoint creation with proper verification:

```rust
pub(crate) fn create_checkpoint(
    db_root_path: impl AsRef<Path>,
    cp_root_path: impl AsRef<Path>,
    sharding: bool,
) -> Result<()> {
    let cp_ledger_db_folder = cp_root_path.as_ref().join(LEDGER_DB_FOLDER_NAME);
    
    // Create temporary checkpoint directory
    let temp_cp_folder = cp_root_path.as_ref().join(format!("{}.tmp", LEDGER_DB_FOLDER_NAME));
    
    // Remove any stale temporary directories from previous failed attempts
    std::fs::remove_dir_all(&temp_cp_folder).unwrap_or(());
    
    if sharding {
        std::fs::create_dir_all(&temp_cp_folder)?;
    }
    
    // Create checkpoint in temporary location
    let rocksdb_configs = RocksdbConfigs {
        enable_storage_sharding: sharding,
        ..Default::default()
    };
    let ledger_db = Self::new(db_root_path, rocksdb_configs, None, None, false)?;
    
    // Create all sub-database checkpoints in temp directory
    ledger_db.metadata_db().create_checkpoint(
        Self::metadata_db_path(&temp_cp_folder, sharding)
    )?;
    
    if sharding {
        ledger_db.event_db().create_checkpoint(temp_cp_folder.join(EVENT_DB_NAME))?;
        // ... other sub-databases
    }
    
    // Verify checkpoint validity before replacing old one
    verify_checkpoint_integrity(&temp_cp_folder)?;
    
    // Atomically replace old checkpoint with new one
    if cp_ledger_db_folder.exists() {
        let backup_folder = cp_root_path.as_ref().join(format!("{}.old", LEDGER_DB_FOLDER_NAME));
        std::fs::rename(&cp_ledger_db_folder, &backup_folder)?;
        match std::fs::rename(&temp_cp_folder, &cp_ledger_db_folder) {
            Ok(_) => {
                // New checkpoint successfully installed, remove old
                std::fs::remove_dir_all(&backup_folder).unwrap_or(());
            }
            Err(e) => {
                // Rollback: restore old checkpoint
                std::fs::rename(&backup_folder, &cp_ledger_db_folder)?;
                return Err(e.into());
            }
        }
    } else {
        std::fs::rename(&temp_cp_folder, &cp_ledger_db_folder)?;
    }
    
    Ok(())
}
```

Key improvements:
1. Create checkpoint in temporary directory first
2. Verify checkpoint integrity before replacing
3. Use atomic `rename()` operations for replacement
4. Rollback mechanism if new checkpoint installation fails
5. Proper error handling instead of `.unwrap_or(())`

## Proof of Concept

```rust
#[test]
fn test_checkpoint_creation_failure_destroys_recovery_data() {
    use tempfile::TempDir;
    use std::fs;
    
    let db_dir = TempDir::new().unwrap();
    let cp_dir = TempDir::new().unwrap();
    
    // Create initial database and first checkpoint
    let db = AptosDB::new_for_test(&db_dir);
    db.save_transactions_for_test(/* ... some transactions ... */);
    AptosDB::create_checkpoint(
        db_dir.path(),
        cp_dir.path(),
        true, // sharding enabled
    ).unwrap();
    drop(db);
    
    // Verify first checkpoint exists and is valid
    assert!(cp_dir.path().join("ledger_db").exists());
    
    // Simulate disk space exhaustion by making checkpoint directory read-only
    // This will cause the new checkpoint creation to fail partway through
    let cp_ledger_folder = cp_dir.path().join("ledger_db");
    let mut perms = fs::metadata(&cp_ledger_folder).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&cp_ledger_folder, perms).unwrap();
    
    // Attempt second checkpoint creation - this should fail
    let result = AptosDB::create_checkpoint(
        db_dir.path(),
        cp_dir.path(),
        true,
    );
    
    // The operation fails, but the old checkpoint is already deleted!
    assert!(result.is_err());
    
    // VULNERABILITY: Old checkpoint is gone, new checkpoint failed to create
    // No valid recovery checkpoint exists
    assert!(!cp_dir.path().join("ledger_db/metadata").exists());
    
    // If the main DB now becomes corrupted, recovery is impossible
    // without falling back to slow state sync or remote backup restoration
}
```

## Notes

While checkpoints are primarily an operational tool rather than a direct attack surface, their loss during disaster recovery scenarios can lead to extended validator downtime, which impacts network liveness and validator rewards. The lack of atomicity and verification violates defensive programming principles for critical infrastructure code handling persistent state.

### Citations

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

**File:** storage/aptosdb/src/state_merkle_db.rs (L217-217)
```rust
        std::fs::remove_dir_all(&cp_state_merkle_db_path).unwrap_or(());
```

**File:** storage/aptosdb/src/state_kv_db.rs (L240-241)
```rust
        std::fs::remove_dir_all(&cp_state_kv_db_path).unwrap_or(());
        std::fs::create_dir_all(&cp_state_kv_db_path).unwrap_or(());
```

**File:** consensus/src/consensusdb/mod.rs (L34-34)
```rust
    std::fs::remove_dir_all(&consensus_db_checkpoint_path).unwrap_or(());
```

**File:** storage/aptosdb/src/db_debugger/checkpoint/mod.rs (L21-21)
```rust
        ensure!(!self.output_dir.exists(), "Output dir already exists.");
```

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L49-65)
```rust
        if !self.opt_out_backup_checkpoint {
            let backup_checkpoint_dir = self.backup_checkpoint_dir.unwrap();
            ensure!(
                !backup_checkpoint_dir.exists(),
                "Backup dir already exists."
            );
            println!("Creating backup at: {:?}", &backup_checkpoint_dir);
            fs::create_dir_all(&backup_checkpoint_dir)?;
            AptosDB::create_checkpoint(
                &self.db_dir,
                backup_checkpoint_dir,
                self.sharding_config.enable_storage_sharding,
            )?;
            println!("Done!");
        } else {
            println!("Opted out backup creation!.");
        }
```

**File:** aptos-node/src/storage.rs (L150-166)
```rust
    AptosDB::create_checkpoint(
        &source_dir,
        &checkpoint_dir,
        node_config.storage.rocksdb_configs.enable_storage_sharding,
    )
    .expect("AptosDB checkpoint creation failed.");

    // Create a consensus db checkpoint
    aptos_consensus::create_checkpoint(&source_dir, &checkpoint_dir)
        .expect("ConsensusDB checkpoint creation failed.");

    // Create a state sync db checkpoint
    let state_sync_db =
        aptos_state_sync_driver::metadata_storage::PersistentMetadataStorage::new(&source_dir);
    state_sync_db
        .create_checkpoint(&checkpoint_dir)
        .expect("StateSyncDB checkpoint creation failed.");
```
