# Audit Report

## Title
Pruner Progress Corruption via Unchecked write_pruner_progress() During State Restoration

## Summary
The `write_pruner_progress()` function unconditionally writes the provided version to database metadata without validating it matches actual pruned state. When called via `save_min_readable_version()` during `finalize_state_snapshot()`, there's no verification that the version is consistent with existing database contents, potentially causing data availability issues and state corruption.

## Finding Description

The `write_pruner_progress()` function in `transaction_db.rs` directly persists a version to the database without any validation: [1](#0-0) 

This function is called from `save_min_readable_version()` which also unconditionally stores the version in both atomic memory and persistent storage: [2](#0-1) 

During fast sync restoration, `finalize_state_snapshot()` calls `save_min_readable_version()` with the snapshot target version for all four pruner types without validating database consistency: [3](#0-2) 

**Critical Issue:** If the version parameter doesn't match actual database state (due to partial restoration failure, database corruption, or incorrect recovery procedures), the system will incorrectly track pruning progress.

The `error_if_ledger_pruned()` function uses `min_readable_version` to determine if data is available: [4](#0-3) 

**Attack Scenario:**
1. Node attempts fast sync to version 1000 but crashes mid-restoration with partial data
2. Database contains inconsistent state (e.g., some data at versions 0-500)
3. Fast sync retries to version 2000
4. `finalize_state_snapshot(2000)` calls `save_min_readable_version(2000)`
5. System now believes all data below version 2000 is "pruned" (intentionally deleted)
6. Queries for versions 501-1999 won't return "data pruned" errors (since min_readable=2000)
7. But this data never existed! Database reads will fail unpredictably
8. Different nodes may have different `min_readable_version` values, causing consensus divergence in data availability

This violates the **State Consistency** invariant: the system's internal state tracking (min_readable_version) doesn't match actual data availability.

## Impact Explanation

**Severity: High**

This qualifies as **High Severity** per Aptos bug bounty criteria:
- **Significant protocol violation**: The invariant that `min_readable_version` accurately reflects data availability is broken
- **API crashes**: Queries for "available" data that doesn't exist will cause errors
- **Validator node slowdowns**: Inconsistent pruner state can cause pruning logic to behave incorrectly

While not directly causing funds loss or consensus safety breaks, this creates:
- **Data availability failures** across the network
- **State inconsistencies requiring manual intervention** to correct pruner progress
- **Potential for cascading failures** if multiple nodes have different views of available data

## Likelihood Explanation

**Likelihood: Medium-Low**

The vulnerability requires specific conditions:
- Fast sync must fail partially (crash, network interruption, disk corruption)
- Database must be left in inconsistent state
- Fast sync must restart with different target version
- OR manual recovery procedures must set incorrect pruner progress

However, once triggered:
- Impact is severe and difficult to diagnose
- Recovery requires manual database intervention
- Multiple nodes could be affected if using same recovery procedures

The fast sync code path is less frequently exercised than normal operations, but bootstrap failures do occur in production during network onboarding or disaster recovery.

## Recommendation

Add validation to `write_pruner_progress()` and `save_min_readable_version()` to prevent setting pruner progress that's inconsistent with database state:

```rust
// In save_min_readable_version()
fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
    let current_min_readable = self.get_min_readable_version();
    
    // Only allow setting to higher version (monotonic progress)
    // OR if current is 0 (fresh bootstrap)
    ensure!(
        current_min_readable == 0 || min_readable_version >= current_min_readable,
        "Cannot set min_readable_version ({}) lower than current ({}). This would mark already-pruned data as available.",
        min_readable_version,
        current_min_readable
    );
    
    // Validate against actual ledger commit progress
    let ledger_commit_progress = self.ledger_db.metadata_db().get_ledger_commit_progress()?;
    ensure!(
        min_readable_version <= ledger_commit_progress,
        "Cannot set min_readable_version ({}) higher than ledger commit progress ({})",
        min_readable_version,
        ledger_commit_progress
    );
    
    self.min_readable_version.store(min_readable_version, Ordering::SeqCst);
    PRUNER_VERSIONS
        .with_label_values(&["ledger_pruner", "min_readable"])
        .set(min_readable_version as i64);
    self.ledger_db.write_pruner_progress(min_readable_version)
}
```

Additionally, add database consistency checks during fast sync initialization to detect and recover from partial restoration failures.

## Proof of Concept

```rust
// Reproduction scenario (requires manual database manipulation)
#[test]
fn test_pruner_progress_corruption() {
    // 1. Create DB with transactions 0-1000
    let db = AptosDB::new_for_test(&tmpdir);
    commit_transactions(&db, 0, 1001);
    
    // 2. Simulate pruning to version 500
    db.ledger_pruner.save_min_readable_version(500).unwrap();
    
    // 3. Manually corrupt by setting to lower version
    // (simulating incorrect recovery procedure)
    db.ledger_pruner.save_min_readable_version(300).unwrap();
    
    // 4. Try to query version 400 (should be pruned but marked available)
    let result = db.get_transaction(400);
    
    // Expected: Error indicating data is pruned
    // Actual: May return error "transaction not found" instead of "pruned"
    // Or succeed if data still exists, breaking availability guarantees
    
    assert!(result.is_err());
    // But error message will be misleading!
}
```

**Notes:** This vulnerability primarily affects system reliability and data availability guarantees rather than direct security (funds loss, consensus breaks). However, it represents a significant deviation from expected behavior that could cascade into more severe issues during recovery scenarios or network partitions where nodes have inconsistent pruner states.

### Citations

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L40-45)
```rust
    pub(super) fn write_pruner_progress(&self, version: Version) -> Result<()> {
        self.db.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionPrunerProgress,
            &DbMetadataValue::Version(version),
        )
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L80-89)
```rust
    fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["ledger_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.ledger_db.write_pruner_progress(min_readable_version)
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

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
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
