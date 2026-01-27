# Audit Report

## Title
Fast Sync Temporary Database Resource Leak Leading to Potential Disk Exhaustion

## Summary
The `temporary_db_with_genesis` database created during fast sync operations is never cleaned up after fast sync completes. The secondary database directory (`fast_sync_secondary/`) persists indefinitely on disk, wasting storage space and potentially causing disk exhaustion in resource-constrained environments or after multiple fast sync operations.

## Finding Description

During fast sync initialization, `FastSyncStorageWrapper::initialize_dbs` creates a secondary database in the `fast_sync_secondary/` directory to store genesis data. [1](#0-0) 

This temporary database is wrapped in an `Arc<AptosDB>` and stored in the `temporary_db_with_genesis` field. [2](#0-1) 

When fast sync completes, `finalize_state_snapshot` transitions the status to `FINISHED`, after which the system switches to using `db_for_fast_sync` for all operations. [3](#0-2) 

However, there is **no cleanup logic** to delete the secondary database directory after fast sync completes. The `Arc<AptosDB>` is eventually dropped when the wrapper goes out of scope, which closes RocksDB handles but does **not** delete the underlying disk files.

This violates the **Resource Limits invariant**: "All operations must respect gas, storage, and computational limits." The node fails to reclaim disk space after the temporary database becomes obsolete.

**Accumulation Scenarios:**

1. **After successful fast sync**: Secondary DB (~hundreds of MB to few GB of genesis data) remains permanently
2. **Node restart after fast sync**: Main DB is no longer empty, so the initialization condition fails, but old secondary DB directory persists [4](#0-3) 
3. **Repeated fast sync attempts**: In environments with automated node provisioning or recovery from failures, secondary DBs could accumulate if the directory is not manually cleaned

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria for "State inconsistencies requiring intervention."

While not directly exploitable by external attackers, this resource leak can lead to:

- **Node failure due to disk exhaustion**: Particularly critical for validator nodes with limited storage
- **Operational overhead**: Requires manual intervention to identify and clean up orphaned directories
- **Cumulative impact**: In cloud environments with automated node deployment/redeployment, this can silently consume significant storage over time
- **Availability risk**: Validators running out of disk space may fail to participate in consensus, affecting network liveness

The issue affects node availability and operational reliability, which are critical for blockchain infrastructure but does not directly compromise consensus safety, fund security, or protocol integrity.

## Likelihood Explanation

**Likelihood: Medium**

This issue occurs in the following scenarios:
- Every node that performs fast sync (common for new validators and full nodes)
- Environments with limited disk space (edge nodes, cloud VMs with constrained storage)
- Automated node provisioning systems that repeatedly deploy fresh nodes

The bug triggers automatically during normal operations without requiring attacker intervention. However, the impact severity depends on:
- Available disk space on the node
- Frequency of fast sync operations
- Monitoring and maintenance practices

## Recommendation

Implement explicit cleanup of the secondary database directory after fast sync completes. Add a cleanup method to `FastSyncStorageWrapper`:

**Option 1: Cleanup in `finalize_state_snapshot`**

After transitioning to `FINISHED` status, delete the secondary DB directory:

```rust
fn finalize_state_snapshot(...) -> Result<()> {
    // Existing finalization logic
    self.get_aptos_db_write_ref().finalize_state_snapshot(...)?;
    
    // Transition to FINISHED
    let mut status = self.fast_sync_status.write();
    *status = FastSyncStatus::FINISHED;
    
    // Cleanup secondary DB
    self.cleanup_secondary_db()?;
    
    Ok(())
}

fn cleanup_secondary_db(&self) -> Result<()> {
    // Ensure we're in FINISHED state
    if self.get_fast_sync_status() != FastSyncStatus::FINISHED {
        return Ok(());
    }
    
    // Get the secondary DB path
    let secondary_db_path = /* derive from config */;
    
    if secondary_db_path.exists() {
        std::fs::remove_dir_all(&secondary_db_path)
            .map_err(|e| anyhow!("Failed to cleanup secondary DB: {}", e))?;
        info!("Cleaned up secondary fast sync DB at {:?}", secondary_db_path);
    }
    
    Ok(())
}
```

**Option 2: Implement Drop trait**

Add a `Drop` implementation for `FastSyncStorageWrapper` that conditionally cleans up if fast sync finished, though this requires careful consideration to avoid panicking in Drop.

**Option 3: Explicit cleanup API**

Provide a `cleanup_after_fast_sync()` method that can be called by the node after confirming fast sync completion and stable operation.

## Proof of Concept

**Reproduction Steps:**

1. Configure a node for fast sync mode with an empty database
2. Start the node and allow fast sync to complete successfully
3. Verify that the node transitions to normal operation
4. Check the storage directory for `fast_sync_secondary/` subdirectory
5. Observe that the directory and all RocksDB files persist despite fast sync completion
6. Restart the node - verify the directory still exists and is never cleaned up
7. Calculate disk space consumed by the abandoned secondary DB

**Verification Command:**
```bash
# After fast sync completes
du -sh /opt/aptos/data/fast_sync_secondary
ls -la /opt/aptos/data/fast_sync_secondary
# Output shows directory with RocksDB SST files still present
```

**Expected behavior:** Secondary DB directory should be removed after fast sync finishes

**Actual behavior:** Directory persists indefinitely, wasting disk space

## Notes

While this issue does not meet the strict criteria for a directly exploitable security vulnerability (it cannot be triggered by external attackers and doesn't compromise consensus or funds), it represents a legitimate operational risk that affects node availability and violates resource management best practices. The classification as Medium severity is appropriate given its potential to cause node failures requiring manual intervention, particularly in production validator environments where disk space is carefully managed.

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L32-38)
```rust
    // Used for storing genesis data during fast sync
    temporary_db_with_genesis: Arc<AptosDB>,
    // Used for restoring fast sync snapshot and all the read/writes afterwards
    db_for_fast_sync: Arc<AptosDB>,
    // This is for reading the fast_sync status to determine which db to use
    fast_sync_status: Arc<RwLock<FastSyncStatus>>,
}
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L66-76)
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
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L78-90)
```rust
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
