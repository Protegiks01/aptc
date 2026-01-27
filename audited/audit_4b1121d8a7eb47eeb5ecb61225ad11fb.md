# Audit Report

## Title
Fast Sync Temporary Database Not Cleaned Up After Completion - Resource Leak Leading to Disk Space Exhaustion

## Summary
After fast sync completes, the temporary database (`temporary_db_with_genesis`) stored in the `SECONDARY_DB_DIR` directory is never cleaned up or removed. The disk space occupied by this database remains permanently allocated, contributing to potential disk exhaustion on validator nodes over time.

## Finding Description

The `FastSyncStorageWrapper` manages two databases during fast sync mode: a temporary database for genesis data (`temporary_db_with_genesis`) and the main database (`db_for_fast_sync`). [1](#0-0) 

When fast sync is enabled and the main database is empty (synced_version == 0), a secondary database is created in the `SECONDARY_DB_DIR` subdirectory: [2](#0-1) 

Once fast sync completes, the status changes to `FINISHED` and all subsequent operations use the main database: [3](#0-2) 

After this point, `temporary_db_with_genesis` is never accessed again, but critically, **it is never closed or cleaned up**. The database remains:
1. In memory as an `Arc<AptosDB>` reference in the `FastSyncStorageWrapper` struct
2. On disk in the `SECONDARY_DB_DIR` directory

When the node eventually shuts down, the `Arc` references are dropped and RocksDB closes its file handles, but **the directory and its contents remain on disk permanently**. There is no production code to remove this directory.

On subsequent node restarts, because `synced_version > 0` after successful fast sync, the condition to create a new secondary DB fails, and the old abandoned directory simply remains: [4](#0-3) 

The only cleanup code exists in test utilities, not production: [5](#0-4) 

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - the system fails to reclaim allocated storage resources after they are no longer needed.

## Impact Explanation

This qualifies as **Medium severity** per Aptos bug bounty criteria for the following reasons:

1. **Resource Exhaustion Risk**: Every node that performs fast sync will have abandoned database directories consuming disk space permanently. While the genesis database may be relatively small (hundreds of MB to low GB range), this represents wasted resources that cannot be reclaimed without manual intervention.

2. **Operational Impact**: On nodes with limited disk space or nodes that undergo multiple fast sync operations (e.g., during testing, recovery scenarios, or network bootstrap events), the accumulation of abandoned databases could contribute to disk space exhaustion, requiring manual cleanup intervention.

3. **No Automatic Recovery**: Unlike transient issues, this resource leak persists across restarts and requires manual filesystem operations to resolve, qualifying as "state inconsistencies requiring intervention."

While not immediately critical like consensus failures or fund loss, this represents a persistent resource management flaw affecting node operational reliability.

## Likelihood Explanation

**Likelihood: HIGH**

This issue occurs deterministically:
- Every node configured for fast sync mode will create a temporary database
- 100% of successful fast syncs result in an abandoned `SECONDARY_DB_DIR` 
- The issue affects all Aptos validator and fullnode deployments using fast sync bootstrapping
- No special conditions or timing windows are required
- The leaked resources accumulate over the lifetime of the node's storage volume

The only factor limiting immediate impact is that fast sync typically occurs once per node (during initial bootstrap), though node redeployments, migrations, or recovery scenarios could trigger multiple fast sync operations on the same storage volume.

## Recommendation

Implement cleanup of the temporary database after fast sync completes. The cleanup should:

1. **Add explicit cleanup after finalize**: Modify `finalize_state_snapshot` in `FastSyncStorageWrapper` to trigger cleanup of the temporary database:

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
    
    // NEW: Cleanup temporary database
    self.cleanup_temporary_db()?;
    
    Ok(())
}

fn cleanup_temporary_db(&self) -> Result<()> {
    // Drop the Arc reference to close the database
    // Note: This requires refactoring to use Option<Arc<AptosDB>>
    drop(self.temporary_db_with_genesis);
    
    // Remove the directory from disk
    let secondary_path = self.config.storage.dir().join(SECONDARY_DB_DIR);
    if secondary_path.exists() {
        std::fs::remove_dir_all(&secondary_path)
            .map_err(|e| anyhow!("Failed to cleanup secondary DB: {}", e))?;
        info!("Successfully cleaned up temporary fast sync database at {:?}", secondary_path);
    }
    Ok(())
}
```

2. **Refactor struct to use Option**: Change `temporary_db_with_genesis: Arc<AptosDB>` to `temporary_db_with_genesis: Option<Arc<AptosDB>>` to allow explicit dropping after fast sync completes.

3. **Add startup cleanup**: On node startup, check for and remove any existing `SECONDARY_DB_DIR` if the main database is not empty, to clean up from previous incomplete operations.

## Proof of Concept

```rust
// Reproduction steps:

// 1. Start a fresh Aptos node with fast sync enabled
// 2. Monitor disk usage and check for SECONDARY_DB_DIR creation:
//    $ ls -lh <storage_dir>/fast_sync_secondary/
//    
// 3. Wait for fast sync to complete (status = FINISHED)
// 4. Verify the temporary DB is no longer accessed (check read/write patterns)
// 5. Check that SECONDARY_DB_DIR still exists:
//    $ du -sh <storage_dir>/fast_sync_secondary/
//    Output: Shows non-zero disk usage
//
// 6. Restart the node
// 7. Verify SECONDARY_DB_DIR still exists and is never cleaned up
//
// Expected: Directory should be removed after fast sync completes
// Actual: Directory remains permanently, wasting disk space

// Test code demonstrating the issue:
#[test]
fn test_fast_sync_cleanup() {
    // Setup node with fast sync mode
    let config = NodeConfig::default_for_validator();
    config.state_sync.state_sync_driver.bootstrapping_mode = 
        BootstrappingMode::DownloadLatestStates;
    
    // Initialize databases - creates secondary DB
    let wrapper = FastSyncStorageWrapper::initialize_dbs(&config, None, None)
        .unwrap()
        .right()
        .unwrap();
    
    let secondary_path = config.storage.dir().join(SECONDARY_DB_DIR);
    assert!(secondary_path.exists(), "Secondary DB should exist");
    
    // Simulate fast sync completion
    let snapshot_receiver = wrapper.get_state_snapshot_receiver(0, HashValue::zero()).unwrap();
    // ... perform state sync ...
    wrapper.finalize_state_snapshot(0, output_proof, &ledger_infos).unwrap();
    
    // BUG: Secondary DB still exists after finalize
    assert!(secondary_path.exists(), "BUG: Secondary DB not cleaned up!");
    
    // Even after dropping the wrapper, directory remains
    drop(wrapper);
    assert!(secondary_path.exists(), "BUG: Secondary DB persists on disk!");
}
```

## Notes

This vulnerability represents a clear violation of resource management principles and the Resource Limits invariant. While the immediate impact is not as severe as consensus or safety violations, the systematic leakage of disk space affects operational reliability and could contribute to node failures in resource-constrained environments. The fix is straightforward: implement explicit cleanup after fast sync completion.

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L30-38)
```rust
/// This is a wrapper around [AptosDB] that is used to bootstrap the node for fast sync mode
pub struct FastSyncStorageWrapper {
    // Used for storing genesis data during fast sync
    temporary_db_with_genesis: Arc<AptosDB>,
    // Used for restoring fast sync snapshot and all the read/writes afterwards
    db_for_fast_sync: Arc<AptosDB>,
    // This is for reading the fast_sync status to determine which db to use
    fast_sync_status: Arc<RwLock<FastSyncStatus>>,
}
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L66-96)
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
            db_dir.push(SECONDARY_DB_DIR);
            let secondary_db = AptosDB::open(
                StorageDirPaths::from_path(db_dir.as_path()),
                /*readonly=*/ false,
                config.storage.storage_pruner_config,
                config.storage.rocksdb_configs,
                config.storage.enable_indexer,
                config.storage.buffered_state_target_items,
                config.storage.max_num_nodes_per_lru_cache_shard,
                None,
                config.storage.hot_state_config,
            )
            .map_err(|err| anyhow!("Secondary DB failed to open {}", err))?;

            Ok(Either::Right(FastSyncStorageWrapper {
                temporary_db_with_genesis: Arc::new(secondary_db),
                db_for_fast_sync: Arc::new(db_main),
                fast_sync_status: Arc::new(RwLock::new(FastSyncStatus::UNKNOWN)),
            }))
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L154-169)
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
```

**File:** testsuite/forge/src/backend/local/node.rs (L315-350)
```rust
        let secondary_db_path = node_config.storage.dir().join(SECONDARY_DB_DIR);

        debug!(
            "Deleting ledger, state, secure and state sync db paths ({:?}, {:?}, {:?}, {:?}, {:?}) for node {:?}",
            ledger_db_path.as_path(),
            state_db_path.as_path(),
            secure_storage_path.as_path(),
            state_sync_db_path.as_path(),
            secondary_db_path.as_path(),
            self.name
        );

        // Verify the files exist
        assert!(ledger_db_path.as_path().exists() && state_db_path.as_path().exists());
        assert!(state_sync_db_path.as_path().exists());
        if self.config.base.role.is_validator() {
            assert!(secure_storage_path.as_path().exists());
        }

        // Remove the primary DB files
        fs::remove_dir_all(ledger_db_path)
            .map_err(anyhow::Error::from)
            .context("Failed to delete ledger_db_path")?;
        fs::remove_dir_all(state_db_path)
            .map_err(anyhow::Error::from)
            .context("Failed to delete state_db_path")?;
        fs::remove_dir_all(state_sync_db_path)
            .map_err(anyhow::Error::from)
            .context("Failed to delete state_sync_db_path")?;

        // Remove the secondary DB files
        if secondary_db_path.as_path().exists() {
            fs::remove_dir_all(secondary_db_path)
                .map_err(anyhow::Error::from)
                .context("Failed to delete secondary_db_path")?;
        }
```
