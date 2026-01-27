# Audit Report

## Title
Validator Permanent Liveness Loss Due to Panic on Missing Ledger Info During Recovery

## Summary
The consensus recovery mechanism in `StorageWriteProxy::start()` uses `.expect()` when calling `get_latest_ledger_info()`, causing a panic if the ledger info is missing or corrupted in the database. This prevents the validator from restarting, resulting in permanent liveness loss until manual intervention.

## Finding Description
The vulnerability exists in the validator startup and recovery path where database state is reconstructed from persistent storage. [1](#0-0) 

During validator startup, the `start()` method retrieves the latest ledger info with an unconditional `.expect()` call. If `get_latest_ledger_info()` fails, the entire validator process panics and terminates.

The underlying issue is that `get_latest_ledger_info()` can legitimately fail when: [2](#0-1) 

The method returns an error when `get_latest_ledger_info_option()` returns `None`, which happens when the ledger metadata database cache is empty: [3](#0-2) 

The cache is initialized from the database at startup: [4](#0-3) 

If the database has no ledger info entries (returns `Ok(None)`), the cache remains `None`, and subsequent calls to `get_latest_ledger_info()` will fail.

**Attack Scenario:**
1. Validator experiences disk corruption affecting the LedgerInfo column family in RocksDB
2. OR validator crashes during genesis commit, leaving the database in a partially initialized state  
3. OR manual database manipulation accidentally removes ledger info data
4. On restart, `LedgerMetadataDb::new()` initializes with `None` cached ledger info
5. When `EpochManager::start_new_epoch_with_jolteon()` calls `storage.start()`: [5](#0-4) 

6. The panic occurs, terminating the validator process
7. Every subsequent restart attempt hits the same panic
8. Validator remains offline until operator manually repairs the database or restores from backup

Additionally, the same panic pattern exists in the `recover_from_ledger()` method: [6](#0-5) 

And in the fast-forward sync path: [7](#0-6) 

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria:
- **Validator node crashes**: The panic prevents any validator startup, causing a complete crash
- **Significant protocol violations**: Permanent unavailability violates the liveness guarantee

While not Critical severity because it only affects individual validator nodes (not the entire network), the impact is severe:
- **Permanent liveness loss**: Affected validator cannot participate in consensus
- **Manual recovery required**: No automatic recovery mechanism exists
- **Stake at risk**: Validator misses block proposals and votes, potentially facing penalties
- **Network impact**: If multiple validators hit this issue simultaneously (e.g., due to a common software bug in database handling), the network could lose liveness

The code explicitly has error handling for recovery failures that returns `PartialRecoveryData`: [8](#0-7) 

However, this error handling is never reached because the panic occurs before it.

## Likelihood Explanation
The likelihood is **Medium to High** because:

**Realistic Triggers:**
- Disk corruption (hardware failures, power loss during writes)
- Software bugs in database pruning or cleanup operations
- Race conditions during crash recovery
- Operator error during database maintenance
- Partial commits during node crashes (as documented in the codebase recovery mechanisms)

**Evidence of Concern:**
The codebase already implements extensive crash recovery mechanisms, indicating these scenarios are expected: [9](#0-8) 

The initialization itself has an `.expect()` for DB read failures, suggesting the developers are aware these operations can fail.

## Recommendation
Replace all `.expect()` calls with proper error handling that allows graceful degradation or recovery:

**For `start()` method** - The error handling infrastructure already exists but is bypassed:
```rust
fn start(&self, order_vote_enabled: bool, window_size: Option<u64>) -> LivenessStorageData {
    info!("Start consensus recovery.");
    
    // Remove .expect() and handle error gracefully
    let latest_ledger_info = match self.aptos_db.get_latest_ledger_info() {
        Ok(info) => info,
        Err(e) => {
            error!(error = ?e, "Failed to get latest ledger info, returning partial recovery data");
            // Return partial recovery data to trigger network sync
            return LivenessStorageData::PartialRecoveryData(
                LedgerRecoveryData::new(
                    // Use a safe default or trigger state sync from network
                    self.get_genesis_or_sync_from_network()
                )
            );
        }
    };
    
    // Continue with normal flow...
}
```

**For `recover_from_ledger()` method** - Return a Result instead of panicking:
```rust
fn recover_from_ledger(&self) -> Result<LedgerRecoveryData> {
    let latest_ledger_info = self
        .aptos_db
        .get_latest_ledger_info()
        .context("Failed to get latest ledger info during recovery")?;
    Ok(LedgerRecoveryData::new(latest_ledger_info))
}
```

**For `sync_manager.rs`** - Handle the PartialRecoveryData case:
```rust
let recovery_data = match storage.start(order_vote_enabled, window_size) {
    LivenessStorageData::FullRecoveryData(recovery_data) => recovery_data,
    LivenessStorageData::PartialRecoveryData(ledger_data) => {
        // Trigger another round of sync instead of panicking
        warn!("Partial recovery data after sync, re-syncing from network");
        return self.sync_from_network(ledger_data).await;
    }
};
```

The key insight is that the `PartialRecoveryData` path exists specifically for cases where full recovery isn't possible, allowing the node to sync from the network. The panics prevent this recovery mechanism from working.

## Proof of Concept
```rust
#[test]
fn test_panic_on_missing_ledger_info() {
    use aptos_db::AptosDB;
    use aptos_temppath::TempPath;
    use aptos_storage_interface::DbReader;
    use consensus::persistent_liveness_storage::{PersistentLivenessStorage, StorageWriteProxy};
    use std::sync::Arc;
    
    // Create empty database (no genesis committed)
    let tmp_dir = TempPath::new();
    let db = Arc::new(AptosDB::new_for_test(&tmp_dir));
    
    // Verify database has no ledger info
    assert!(db.get_latest_ledger_info_option().unwrap().is_none());
    
    // Create storage proxy
    let config = NodeConfig::default();
    let storage = StorageWriteProxy::new(&config, db);
    
    // This will panic with "Failed to get latest ledger info."
    // In production, this terminates the validator process
    let result = std::panic::catch_unwind(|| {
        storage.start(false, None);
    });
    
    assert!(result.is_err(), "Expected panic but function succeeded");
    
    // Validator cannot restart - every attempt will hit the same panic
    // Manual intervention required to fix database or restore from backup
}
```

To reproduce in a real environment:
1. Start a validator node and let it sync
2. Stop the node
3. Use `aptos-db-tool` to corrupt or delete LedgerInfo entries from the database
4. Attempt to restart the validator
5. Observe the panic: "Failed to get latest ledger info."
6. Observe that repeated restart attempts all fail with the same panic

**Notes**
This is a genuine availability vulnerability that violates the fault tolerance expectations of a production blockchain validator. The panic-based error handling prevents the existing recovery mechanisms (partial recovery, network sync) from functioning, forcing operators to manually intervene. The fix is straightforward: replace panics with proper error propagation, allowing the already-implemented fallback paths to execute.

### Citations

**File:** consensus/src/persistent_liveness_storage.rs (L511-517)
```rust
    fn recover_from_ledger(&self) -> LedgerRecoveryData {
        let latest_ledger_info = self
            .aptos_db
            .get_latest_ledger_info()
            .expect("Failed to get latest ledger info.");
        LedgerRecoveryData::new(latest_ledger_info)
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L549-552)
```rust
        let latest_ledger_info = self
            .aptos_db
            .get_latest_ledger_info()
            .expect("Failed to get latest ledger info.");
```

**File:** consensus/src/persistent_liveness_storage.rs (L591-595)
```rust
            Err(e) => {
                error!(error = ?e, "Failed to construct recovery data");
                LivenessStorageData::PartialRecoveryData(ledger_recovery_data)
            },
        }
```

**File:** storage/storage-interface/src/lib.rs (L526-530)
```rust
    fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        self.get_latest_ledger_info_option().and_then(|opt| {
            opt.ok_or_else(|| AptosDbError::Other("Latest LedgerInfo not found.".to_string()))
        })
    }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L26-30)
```rust
fn get_latest_ledger_info_in_db_impl(db: &DB) -> Result<Option<LedgerInfoWithSignatures>> {
    let mut iter = db.iter::<LedgerInfoSchema>()?;
    iter.seek_to_last();
    Ok(iter.next().transpose()?.map(|(_, v)| v))
}
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L43-50)
```rust
    pub(super) fn new(db: Arc<DB>) -> Self {
        let latest_ledger_info = get_latest_ledger_info_in_db_impl(&db).expect("DB read failed.");
        let latest_ledger_info = ArcSwap::from(Arc::new(latest_ledger_info));

        Self {
            db,
            latest_ledger_info,
        }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L94-98)
```rust
    pub(crate) fn get_latest_ledger_info_option(&self) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }
```

**File:** consensus/src/epoch_manager.rs (L1383-1386)
```rust
        match self.storage.start(
            consensus_config.order_vote_enabled(),
            consensus_config.window_size(),
        ) {
```

**File:** consensus/src/block_storage/sync_manager.rs (L519-522)
```rust
        let recovery_data = match storage.start(order_vote_enabled, window_size) {
            LivenessStorageData::FullRecoveryData(recovery_data) => recovery_data,
            _ => panic!("Failed to construct recovery data after fast forward sync"),
        };
```
