# Audit Report

## Title
Race Condition in Ledger Pruner Progress Metadata Writes Causing Cross-Database Inconsistency

## Summary
The `LedgerDb::write_pruner_progress()` method writes pruner progress metadata to 8 separate sub-databases sequentially without atomic guarantees across all writes. If multiple `LedgerPrunerManager` instances share the same `Arc<LedgerDb>` and call `save_min_readable_version()` concurrently, the non-atomic sequence of writes can result in inconsistent pruner progress values across different sub-databases, violating the State Consistency invariant.

## Finding Description

The vulnerability exists in the `write_pruner_progress()` method which sequentially writes to 8 different database instances: [1](#0-0) 

Each sub-database write is individually atomic, but the sequence as a whole is not. The method is called through: [2](#0-1) 

When called from state sync operations: [3](#0-2) 

There is no synchronization mechanism (mutex, lock, or atomic transaction) protecting the 8-database write sequence. Each sub-database writes to a different metadata key (e.g., `EventPrunerProgress`, `TransactionPrunerProgress`, etc.): [4](#0-3) [5](#0-4) 

**Attack Scenario:**

If Thread A calls `write_pruner_progress(version=100)` and Thread B concurrently calls `write_pruner_progress(version=200)`, the following interleaving can occur:

1. Thread A writes v100 to event_db
2. Thread B writes v200 to event_db (overwrites)
3. Thread B writes v200 to persisted_auxiliary_info_db
4. Thread A writes v100 to persisted_auxiliary_info_db (overwrites with stale value)
5. Thread A writes v100 to transaction_accumulator_db
6. Thread B writes v200 to transaction_accumulator_db (overwrites)
7. ...continues with unpredictable interleaving

**Result:** Different sub-databases end up with different pruner progress values, creating metadata inconsistency.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program: "State inconsistencies requiring intervention."

**Specific Impacts:**
- **Storage Invariant Violation**: Different ledger sub-databases report different pruner progress, violating the assumption that all components track the same pruned version
- **Pruning Logic Confusion**: Subsequent pruning operations may make incorrect decisions based on inconsistent progress values
- **Recovery Issues**: During node restart or crash recovery, inconsistent metadata could cause initialization failures or data integrity checks to fail
- **Data Availability Problems**: Some data might be incorrectly pruned while other data remains, potentially causing query failures

The impact does not reach Critical/High severity because:
- No direct fund loss or consensus violation
- Does not cause permanent network partition
- Recoverable through manual intervention (database repair)

## Likelihood Explanation

**Likelihood: Low**

The question itself notes that multiple `LedgerPrunerManager` instances are "unlikely." Analysis shows:

1. **Architectural Protection**: Normally only one `LedgerPrunerManager` instance exists per `AptosDB`: [6](#0-5) 

2. **Intended Usage**: The comment indicates this should only be used during fast sync completion: [7](#0-6) 

3. **Required Conditions**:
   - Multiple `LedgerPrunerManager` instances must exist (configuration error, testing scenario, or initialization bug)
   - Concurrent calls to `finalize_state_snapshot()` must occur (violates design assumption of serialized state sync)

4. **No Direct Attacker Control**: An unprivileged attacker cannot directly trigger concurrent `write_pruner_progress()` calls; this would require exploiting a separate bug in state sync orchestration or node initialization

However, the lack of defensive synchronization means this vulnerability could be triggered by:
- Future code changes that allow concurrent state sync
- Testing scenarios with multiple DB instances
- Race conditions in node initialization logic

## Recommendation

Add a mutex to protect the multi-database write sequence. Modify `LedgerDb` to include synchronization:

```rust
pub struct LedgerDb {
    // ... existing fields ...
    pruner_progress_lock: std::sync::Mutex<()>,
}

pub(crate) fn write_pruner_progress(&self, version: Version) -> Result<()> {
    let _guard = self.pruner_progress_lock.lock().unwrap();
    
    info!("Fast sync is done, writing pruner progress {version} for all ledger sub pruners.");
    self.event_db.write_pruner_progress(version)?;
    self.persisted_auxiliary_info_db.write_pruner_progress(version)?;
    self.transaction_accumulator_db.write_pruner_progress(version)?;
    self.transaction_auxiliary_data_db.write_pruner_progress(version)?;
    self.transaction_db.write_pruner_progress(version)?;
    self.transaction_info_db.write_pruner_progress(version)?;
    self.write_set_db.write_pruner_progress(version)?;
    self.ledger_metadata_db.write_pruner_progress(version)?;
    
    Ok(())
}
```

**Alternative Solution**: Use a single atomic batch write across all databases if the underlying storage supports cross-database transactions.

**Additional Hardening**: Add assertions or validation to detect and fail-fast on inconsistent pruner progress values during startup.

## Proof of Concept

```rust
use std::sync::Arc;
use std::thread;
use aptos_types::transaction::Version;

// Simulated test demonstrating the race condition
#[test]
fn test_concurrent_pruner_progress_corruption() {
    // Setup: Create shared LedgerDb instance
    let ledger_db = Arc::new(create_test_ledger_db());
    
    // Create two threads that concurrently write different versions
    let db1 = Arc::clone(&ledger_db);
    let handle1 = thread::spawn(move || {
        for _ in 0..100 {
            db1.write_pruner_progress(100).unwrap();
        }
    });
    
    let db2 = Arc::clone(&ledger_db);
    let handle2 = thread::spawn(move || {
        for _ in 0..100 {
            db2.write_pruner_progress(200).unwrap();
        }
    });
    
    handle1.join().unwrap();
    handle2.join().unwrap();
    
    // Verify: Check if all sub-databases have consistent progress
    let event_progress = ledger_db.event_db().get_pruner_progress().unwrap();
    let txn_progress = ledger_db.transaction_db().get_pruner_progress().unwrap();
    let metadata_progress = ledger_db.metadata_db().get_pruner_progress().unwrap();
    
    // This assertion may fail due to race condition
    assert_eq!(event_progress, txn_progress, "Inconsistent pruner progress detected!");
    assert_eq!(txn_progress, metadata_progress, "Inconsistent pruner progress detected!");
}
```

**Expected Result**: With the current implementation, the test may intermittently fail, demonstrating that different sub-databases can end up with different pruner progress values (100 vs 200) due to the race condition.

**Notes**

While the architectural design normally prevents this issue through single-instance constraints, the lack of defensive synchronization represents a violation of defensive programming principles. The code should be robust against future changes that might introduce concurrent access patterns. The Medium severity rating reflects the low likelihood balanced against the non-trivial impact of metadata corruption requiring manual intervention to resolve.

### Citations

**File:** storage/aptosdb/src/ledger_db/mod.rs (L372-388)
```rust
    // Only expect to be used by fast sync when it is finished.
    pub(crate) fn write_pruner_progress(&self, version: Version) -> Result<()> {
        info!("Fast sync is done, writing pruner progress {version} for all ledger sub pruners.");
        self.event_db.write_pruner_progress(version)?;
        self.persisted_auxiliary_info_db
            .write_pruner_progress(version)?;
        self.transaction_accumulator_db
            .write_pruner_progress(version)?;
        self.transaction_auxiliary_data_db
            .write_pruner_progress(version)?;
        self.transaction_db.write_pruner_progress(version)?;
        self.transaction_info_db.write_pruner_progress(version)?;
        self.write_set_db.write_pruner_progress(version)?;
        self.ledger_metadata_db.write_pruner_progress(version)?;

        Ok(())
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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L225-225)
```rust
            self.ledger_pruner.save_min_readable_version(version)?;
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L47-52)
```rust
    pub(super) fn write_pruner_progress(&self, version: Version) -> Result<()> {
        self.db.put::<DbMetadataSchema>(
            &DbMetadataKey::EventPrunerProgress,
            &DbMetadataValue::Version(version),
        )
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L40-45)
```rust
    pub(super) fn write_pruner_progress(&self, version: Version) -> Result<()> {
        self.db.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionPrunerProgress,
            &DbMetadataValue::Version(version),
        )
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L86-90)
```rust
        let ledger_pruner = LedgerPrunerManager::new(
            Arc::clone(&ledger_db),
            pruner_config.ledger_pruner_config,
            internal_indexer_db,
        );
```
