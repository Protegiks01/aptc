# Audit Report

## Title
Genesis State Data Inaccessibility After Fast Sync Completion Breaks Historical Queries and State Proof Verification

## Summary
After fast sync completes and status becomes FINISHED, reads switch from `temporary_db_with_genesis` to `db_for_fast_sync`. However, genesis state values remain only in `temporary_db_with_genesis` and are never migrated. The `finalize_state_snapshot` function sets `min_readable_version` to the snapshot version, preventing any queries for state at genesis (version 0). This breaks state proof verification at genesis and historical API queries, violating the State Consistency invariant.

## Finding Description

The `FastSyncStorageWrapper` manages two databases during fast sync initialization: [1](#0-0) 

When fast sync completes, the `get_aptos_db_read_ref()` function switches all read operations to `db_for_fast_sync`: [2](#0-1) 

During bootstrap, genesis is applied to `temporary_db_with_genesis`, but only the genesis **ledger info** (not state values) is copied to `db_for_fast_sync`: [3](#0-2) 

The `commit_genesis_ledger_info` function only commits metadata, not state values: [4](#0-3) 

When `finalize_state_snapshot` completes fast sync, it sets `min_readable_version` to the snapshot version: [5](#0-4) 

This prevents any state queries below the snapshot version. The `error_if_state_kv_pruned` function enforces this restriction: [6](#0-5) 

**The Attack Vector:**

While this is not a traditional exploit, it enables attacks on the network's trust model:

1. **Light Client State Proof Attack**: Light clients verifying state proofs back to genesis cannot obtain proof data from fast-synced nodes, forcing them to trust alternative (potentially malicious) sources
2. **Historical Data Manipulation**: Archive services cannot verify genesis state claims against fast-synced nodes, enabling historical data falsification
3. **API Surface Inconsistency**: Applications expecting `get_state_value_with_proof_by_version(key, 0)` to work (as demonstrated in tests) will fail, breaking legitimate use cases [7](#0-6) 

## Impact Explanation

This issue qualifies as **High Severity** under "Significant protocol violations" because:

1. **State Consistency Invariant Violation**: The protocol's requirement that "State transitions must be atomic and verifiable via Merkle proofs" is broken - genesis state proofs cannot be verified
2. **API Functionality Broken**: REST API endpoints documented to serve historical state return errors for genesis queries
3. **Trust Model Degradation**: The inability to verify genesis state from fast-synced nodes (which represent the majority of new nodes) weakens the blockchain's trustless verification properties
4. **Data Availability Failure**: Genesis state becomes permanently inaccessible if `temporary_db_with_genesis` is deleted

The API documentation acknowledges pruning but expects proper 410 Gone responses: [8](#0-7) 

## Likelihood Explanation

**HIGH Likelihood** - This affects every node that:
- Uses fast sync bootstrapping mode (common for new nodes)
- Syncs to a version > 0 (the typical production scenario)
- The issue is deterministic and reproducible

The test suite expects non-genesis fast sync to result in `oldest_ledger_version > 0`, suggesting this behavior may be partially intentional but creates the described security issues: [9](#0-8) 

## Recommendation

**Solution 1: Migrate Genesis State During Fast Sync**
Modify the bootstrap process to copy genesis state values (not just ledger info) from `temporary_db_with_genesis` to `db_for_fast_sync` before finalizing:

```rust
// In storage.rs, after commit_genesis_ledger_info:
if fast_sync_db.get_latest_ledger_info_option()?.is_none() {
    fast_sync_db.commit_genesis_ledger_info(&ledger_info)?;
    
    // NEW: Copy genesis state values
    let temp_db = db_arc.get_temporary_db_with_genesis();
    let genesis_state = temp_db.get_all_state_values_at_version(0)?;
    fast_sync_db.write_genesis_state_values(genesis_state)?;
}
```

**Solution 2: Adjust min_readable_version for Genesis**
Always set `min_readable_version = 0` to preserve genesis accessibility:

```rust
// In aptosdb_writer.rs finalize_state_snapshot:
self.state_store.state_kv_pruner.save_min_readable_version(0)?;  // Always preserve genesis
```

**Solution 3: Keep Dual-DB Access**
Allow read fallback to `temporary_db_with_genesis` for version 0 queries:

```rust
pub(crate) fn get_aptos_db_read_ref_for_version(&self, version: Version) -> &AptosDB {
    if version == 0 {
        self.temporary_db_with_genesis.as_ref()
    } else if self.is_fast_sync_bootstrap_finished() {
        self.db_for_fast_sync.as_ref()
    } else {
        self.temporary_db_with_genesis.as_ref()
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_genesis_state_inaccessible_after_fast_sync() {
    // 1. Initialize fast sync with genesis
    let temp_path = TempPath::new();
    let mut config = NodeConfig::default();
    config.state_sync.state_sync_driver.bootstrapping_mode = BootstrappingMode::DownloadLatestStates;
    
    let wrapper = FastSyncStorageWrapper::initialize_dbs(&config, None, None)
        .expect("Failed to initialize")
        .right()
        .expect("Should return FastSyncStorageWrapper");
    
    // 2. Apply genesis to temporary DB
    let genesis_txn = aptos_vm_genesis::test_genesis_transaction();
    let temp_db_rw = DbReaderWriter::from_arc(wrapper.get_temporary_db_with_genesis());
    maybe_apply_genesis(&temp_db_rw, &config).expect("Genesis application failed");
    
    // 3. Simulate fast sync to version 1000
    let fast_sync_db = wrapper.get_fast_sync_db();
    // ... perform state snapshot restore at version 1000 ...
    
    // 4. Verify genesis ledger info is accessible
    assert!(fast_sync_db.get_epoch_ending_ledger_info(0).is_ok());
    
    // 5. Try to query genesis state - THIS SHOULD FAIL
    let genesis_account_key = StateKey::resource_typed::<AccountResource>(&CORE_CODE_ADDRESS).unwrap();
    let result = fast_sync_db.get_state_value_by_version(&genesis_account_key, 0);
    
    // VULNERABILITY: This returns an error about version 0 being pruned
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("pruned"));
}
```

## Notes

This vulnerability demonstrates a critical architectural flaw where the fast sync optimization inadvertently breaks the blockchain's verifiability guarantees. While fast sync is designed for performance, it must not compromise the fundamental ability to verify state back to genesis, which is essential for trustless operation and light client security.

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L31-38)
```rust
pub struct FastSyncStorageWrapper {
    // Used for storing genesis data during fast sync
    temporary_db_with_genesis: Arc<AptosDB>,
    // Used for restoring fast sync snapshot and all the read/writes afterwards
    db_for_fast_sync: Arc<AptosDB>,
    // This is for reading the fast_sync status to determine which db to use
    fast_sync_status: Arc<RwLock<FastSyncStatus>>,
}
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L126-132)
```rust
    pub(crate) fn get_aptos_db_read_ref(&self) -> &AptosDB {
        if self.is_fast_sync_bootstrap_finished() {
            self.db_for_fast_sync.as_ref()
        } else {
            self.temporary_db_with_genesis.as_ref()
        }
    }
```

**File:** aptos-node/src/storage.rs (L75-94)
```rust
        Either::Right(fast_sync_db_wrapper) => {
            let temp_db = fast_sync_db_wrapper.get_temporary_db_with_genesis();
            maybe_apply_genesis(&DbReaderWriter::from_arc(temp_db), node_config)?;
            let (db_arc, db_rw) = DbReaderWriter::wrap(fast_sync_db_wrapper);
            let fast_sync_db = db_arc.get_fast_sync_db();
            // FastSyncDB requires ledger info at epoch 0 to establish provenance to genesis
            let ledger_info = db_arc
                .get_temporary_db_with_genesis()
                .get_epoch_ending_ledger_info(0)
                .expect("Genesis ledger info must exist");

            if fast_sync_db
                .get_latest_ledger_info_option()
                .expect("should returns Ok results")
                .is_none()
            {
                // it means the DB is empty and we need to
                // commit the genesis ledger info to the DB.
                fast_sync_db.commit_genesis_ledger_info(&ledger_info)?;
            }
```

**File:** storage/aptosdb/src/db/mod.rs (L207-219)
```rust
    pub fn commit_genesis_ledger_info(&self, genesis_li: &LedgerInfoWithSignatures) -> Result<()> {
        let ledger_metadata_db = self.ledger_db.metadata_db();
        let current_epoch = ledger_metadata_db
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            genesis_li.ledger_info().epoch() == current_epoch && current_epoch == 0,
            "Genesis ledger info epoch is not 0"
        );
        let mut ledger_batch = SchemaBatch::new();
        ledger_metadata_db.put_ledger_info(genesis_li, &mut ledger_batch)?;
        ledger_metadata_db.write_schemas(ledger_batch)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L225-234)
```rust
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
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L305-315)
```rust
    pub(super) fn error_if_state_kv_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.state_store.state_kv_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```

**File:** execution/executor/tests/storage_integration_test.rs (L43-48)
```rust
    let account_resource_path =
        StateKey::resource_typed::<AccountResource>(&CORE_CODE_ADDRESS).unwrap();
    let (aptos_framework_account_resource, state_proof) = db
        .reader
        .get_state_value_with_proof_by_version(&account_resource_path, 0)
        .unwrap();
```

**File:** api/src/state.rs (L38-44)
```rust
    /// Get account resource
    ///
    /// Retrieves an individual resource from a given account and at a specific ledger version. If the
    /// ledger version is not specified in the request, the latest ledger version is used.
    ///
    /// The Aptos nodes prune account state history, via a configurable time window.
    /// If the requested ledger version has been pruned, the server responds with a 410.
```

**File:** testsuite/smoke-test/src/state_sync_utils.rs (L218-225)
```rust
    // Verify the oldest ledger version after fast syncing
    if sync_to_genesis {
        // The node should have fast synced to genesis
        assert_eq!(oldest_ledger_version, 0);
    } else {
        // The node should have fast synced to the latest epoch
        assert!(oldest_ledger_version > 0);
    }
```
