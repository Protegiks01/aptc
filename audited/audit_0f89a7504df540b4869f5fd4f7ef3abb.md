# Audit Report

## Title
Version Consistency Invariant Violation During State Snapshot Finalization Causes Node Liveness Failure

## Summary
The `finalize_state_snapshot` function in AptosDB can create an inconsistent state where `get_lowest_available_version()` returns a value greater than `get_highest_synced_epoch_and_version()`, violating the fundamental invariant that highest >= lowest. This occurs when restoring a state snapshot from an older epoch but newer version, causing the storage service to fail when creating data summaries and effectively halting the node's ability to participate in state synchronization.

## Finding Description

The peer-monitoring-service defines two critical storage interface methods that must maintain the invariant highest_version >= lowest_version: [1](#0-0) 

These methods are implemented by querying AptosDB:
- `get_highest_synced_epoch_and_version()` retrieves the latest ledger info version
- `get_lowest_available_version()` retrieves the ledger pruner's minimum readable version [2](#0-1) 

The vulnerability manifests during state snapshot restoration in the `finalize_state_snapshot` function. This function performs two critical operations in sequence: [3](#0-2) 

First, it unconditionally sets the minimum readable version for all pruners to the snapshot version. Second, it calls `update_latest_ledger_info` to update the latest ledger info. However, this update function has a conditional check based on **epochs**, not versions: [4](#0-3) 

The critical flaw is on lines 66-68: if the existing ledger info's epoch is **greater** than the new ledger info's epoch, the function returns early **without updating** the latest ledger info. This creates a dangerous inconsistency:

**Attack Scenario:**
1. Node has `latest_ledger_info` at epoch 11, version 500
2. Operator restores state snapshot from epoch 10, version 1000 (older epoch, newer version)
3. `save_min_readable_version(1000)` sets `min_readable_version = 1000` 
4. `update_latest_ledger_info` sees epoch 11 > epoch 10, returns early
5. Result: `min_readable_version = 1000`, `latest_ledger_info.version() = 500`
6. **Invariant violated: 500 < 1000**

This invariant violation propagates to the storage service layer. When the storage service attempts to create a data summary, it calls `fetch_transaction_range`: [5](#0-4) 

This function attempts to create a `CompleteDataRange` with `first_transaction_version` (from `get_first_txn_version()`, which returns `min_readable_version`) and `latest_version` (from latest ledger info). The `CompleteDataRange::new()` constructor validates the invariant: [6](#0-5) 

When `lowest > highest` (1000 > 500), the validation on line 963 **fails**, returning a `DegenerateRangeError`. This error prevents the storage service from creating a valid data summary, which is required for serving state sync requests.

## Impact Explanation

**Severity: HIGH**

This vulnerability causes **node liveness failure**, meeting the High severity criteria from the Aptos bug bounty program: "Validator node slowdowns" and "Significant protocol violations."

**Specific Impacts:**
1. **Storage Service Failure**: The node cannot create valid storage server summaries, blocking all state sync operations
2. **Peer Synchronization Blocked**: Other nodes cannot fetch data from the affected node
3. **State Sync Degradation**: The network's state sync capability is reduced
4. **Manual Intervention Required**: The node requires database reset or manual correction to recover

The impact is not Critical severity because:
- No funds are lost or stolen
- Consensus safety is not violated (the node simply cannot participate)
- The network can continue operating without this node
- No permanent state corruption occurs

However, it is High severity because:
- Any node performing certain restore operations becomes non-functional
- The node cannot serve its role in the network
- Recovery requires manual database intervention
- Multiple nodes could be affected if they use the same restore procedure

## Likelihood Explanation

**Likelihood: LOW to MEDIUM**

The vulnerability requires specific conditions:
1. A node performing state snapshot restoration (not routine operation)
2. Restoring from a snapshot with an older epoch but higher version than current database state
3. This scenario could occur during:
   - Database recovery from partial corruption
   - Testing/debugging with snapshot restoration
   - Manual database manipulation by operators
   - Edge cases in backup/restore procedures

While the conditions are somewhat unusual, they are not impossible. Database restore operations are performed during node maintenance, disaster recovery, or when bootstrapping from snapshots. The fact that the code **allows** this operation but doesn't handle it correctly makes this a legitimate vulnerability.

## Recommendation

Add validation to prevent the invariant violation. The fix should be implemented in `finalize_state_snapshot`:

**Option 1: Add Version Check to `update_latest_ledger_info`**
Modify the update logic to also consider versions when deciding whether to update:

```rust
pub(crate) fn update_latest_ledger_info(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    if let Some(li) = ledger_metadata_db.get_latest_ledger_info_option() {
        let new_ledger_info = ledger_infos.last().unwrap().ledger_info();
        // Only skip update if BOTH epoch is older AND version is not newer
        if li.ledger_info().epoch() > new_ledger_info.epoch() 
            && li.ledger_info().version() >= new_ledger_info.version() {
            return Ok(());
        }
    }
    ledger_metadata_db.set_latest_ledger_info(ledger_infos.last().unwrap().clone());
    Ok(())
}
```

**Option 2: Add Validation in `finalize_state_snapshot`**
Add explicit validation before setting min_readable_version:

```rust
// Validate that we're not creating an inconsistent state
let current_latest = self.ledger_db.metadata_db().get_latest_ledger_info_option();
if let Some(current_li) = current_latest {
    if current_li.ledger_info().epoch() > ledger_infos.last().unwrap().ledger_info().epoch()
        && current_li.ledger_info().version() < version {
        return Err(AptosDbError::Other(format!(
            "Cannot finalize snapshot at version {} from epoch {} when database has epoch {} at version {}",
            version, ledger_infos.last().unwrap().ledger_info().epoch(),
            current_li.ledger_info().epoch(), current_li.ledger_info().version()
        )));
    }
}
```

**Option 3: Force Latest Ledger Info Update During Snapshot Finalization**
In restoration scenarios, always update the latest ledger info regardless of epoch comparison, as snapshot finalization is an explicit operator action that should override normal epoch-based logic.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_version_invariant_violation_during_restore() {
    use aptos_storage_interface::DbWriter;
    
    // Setup: Create a database with initial state
    let (db, _) = AptosDB::new_for_test();
    
    // Commit initial transactions up to epoch 11, version 500
    // (test setup code would commit ledger info at epoch 11, version 500)
    
    // Simulate restore of state snapshot from epoch 10, version 1000
    let snapshot_version = 1000;
    let snapshot_epoch = 10;
    let snapshot_ledger_infos = vec![/* LedgerInfoWithSignatures at epoch 10, version 1000 */];
    
    // Call finalize_state_snapshot
    let result = db.finalize_state_snapshot(
        snapshot_version,
        output_with_proof, // Contains transaction output at version 1000
        &snapshot_ledger_infos
    );
    
    // After finalization:
    let min_readable = db.ledger_pruner.get_min_readable_version();
    let latest_info = db.get_latest_ledger_info().unwrap();
    let latest_version = latest_info.ledger_info().version();
    
    // Verify invariant violation
    assert!(min_readable > latest_version, 
        "Invariant violated: min_readable ({}) > latest_version ({})",
        min_readable, latest_version
    );
    
    // Demonstrate storage service failure
    let storage = StorageReader::new(Arc::new(db));
    let summary_result = storage.get_data_summary();
    
    // This should fail with DegenerateRangeError
    assert!(summary_result.is_err());
    assert!(summary_result.unwrap_err().to_string().contains("DegenerateRangeError"));
}
```

## Notes

This vulnerability demonstrates a subtle but critical consistency issue in the database restore path. While the normal commit path (via `post_commit`) maintains the invariant by updating both pruner state and ledger info atomically, the restore path has divergent logic that can break this invariant. The root cause is the epoch-based comparison in `update_latest_ledger_info` which doesn't account for version ordering when epochs differ.

### Citations

**File:** peer-monitoring-service/server/src/storage.rs (L12-19)
```rust
    /// Returns the highest synced epoch and version
    fn get_highest_synced_epoch_and_version(&self) -> Result<(u64, u64), Error>;

    /// Returns the ledger timestamp of the blockchain in microseconds
    fn get_ledger_timestamp_usecs(&self) -> Result<u64, Error>;

    /// Returns the lowest available version in storage
    fn get_lowest_available_version(&self) -> Result<u64, Error>;
```

**File:** peer-monitoring-service/server/src/storage.rs (L45-63)
```rust
    fn get_highest_synced_epoch_and_version(&self) -> Result<(u64, u64), Error> {
        let latest_ledger_info = self.get_latest_ledger_info()?;
        Ok((latest_ledger_info.epoch(), latest_ledger_info.version()))
    }

    fn get_ledger_timestamp_usecs(&self) -> Result<u64, Error> {
        let latest_ledger_info = self.get_latest_ledger_info()?;
        Ok(latest_ledger_info.timestamp_usecs())
    }

    fn get_lowest_available_version(&self) -> Result<u64, Error> {
        let maybe_lowest_available_version = self
            .storage
            .get_first_txn_version()
            .map_err(|error| Error::StorageErrorEncountered(error.to_string()))?;
        maybe_lowest_available_version.ok_or_else(|| {
            Error::StorageErrorEncountered("get_first_txn_version() returned None!".into())
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L225-236)
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

            restore_utils::update_latest_ledger_info(self.ledger_db.metadata_db(), ledger_infos)?;
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L61-74)
```rust
pub(crate) fn update_latest_ledger_info(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    if let Some(li) = ledger_metadata_db.get_latest_ledger_info_option() {
        if li.ledger_info().epoch() > ledger_infos.last().unwrap().ledger_info().epoch() {
            // No need to update latest ledger info.
            return Ok(());
        }
    }
    ledger_metadata_db.set_latest_ledger_info(ledger_infos.last().unwrap().clone());

    Ok(())
}
```

**File:** state-sync/storage-service/server/src/storage.rs (L179-192)
```rust
    fn fetch_transaction_range(
        &self,
        latest_version: Version,
    ) -> aptos_storage_service_types::Result<Option<CompleteDataRange<Version>>, Error> {
        let first_transaction_version = self.storage.get_first_txn_version()?;
        if let Some(first_transaction_version) = first_transaction_version {
            let transaction_range =
                CompleteDataRange::new(first_transaction_version, latest_version)
                    .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
            Ok(Some(transaction_range))
        } else {
            Ok(None)
        }
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L962-968)
```rust
    pub fn new(lowest: T, highest: T) -> crate::Result<Self, Error> {
        if lowest > highest || range_length_checked(lowest, highest).is_err() {
            Err(DegenerateRangeError)
        } else {
            Ok(Self { lowest, highest })
        }
    }
```
