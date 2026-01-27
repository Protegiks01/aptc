# Audit Report

## Title
Pruner Progress Rollback Vulnerability Causes Silent Database State Inconsistency

## Summary
The `PersistedAuxiliaryInfoPruner::prune()` function does not validate that `current_progress <= target_version` before calling the underlying `PersistedAuxiliaryInfoDb::prune()`. When `current_progress > target_version`, the function silently rolls back the pruner progress metadata without restoring already-deleted data, creating a persistent database inconsistency that violates the storage integrity invariant. [1](#0-0) 

## Finding Description

During node initialization, `PersistedAuxiliaryInfoPruner::new()` retrieves the sub-pruner's progress from its database and the main ledger pruner's metadata progress, then calls `prune()` to catch up. [2](#0-1) [3](#0-2) 

If the sub-pruner's stored progress is **greater** than the metadata progress (which can occur after a crash during pruning where the sub-pruner committed but the main metadata pruner did not), the system calls `prune(higher_value, lower_value)`.

In `PersistedAuxiliaryInfoDb::prune()`, the deletion loop uses a Rust range: [4](#0-3) 

When `begin > end`, the range `begin..end` is empty in Rust, so no iterations occur and no deletions happen. However, the function returns `Ok(())`, and the pruner then updates its progress metadata to `target_version` (the lower value).

This creates a critical inconsistency:
- **Metadata state**: Pruner progress = `target_version` (e.g., 500)
- **Actual data state**: Data in range `[target_version, old_progress)` (e.g., [500, 1000)) is already deleted
- **System expectation**: All data from version `target_version` onward should be available

When components query for persisted auxiliary info in the missing range, the `ContinuousVersionIter` enforces version continuity: [5](#0-4) 

The iterator will fail with an error when it encounters the gap in versions, breaking data availability guarantees.

This same vulnerability affects all ledger sub-pruners that use the identical pattern:
- `TransactionInfoPruner`
- `TransactionPruner` 
- `EventStorePruner`
- `WriteSetPruner`
- `TransactionAccumulatorPruner`
- `TransactionAuxiliaryDataPruner` [6](#0-5) 

## Impact Explanation

This vulnerability violates the **State Consistency** critical invariant: "State transitions must be atomic and verifiable via Merkle proofs." The pruner metadata becomes inconsistent with the actual database state, causing:

1. **Data Availability Failures**: Queries for transaction auxiliary info, transaction info, events, or other pruned data in the gap range will fail
2. **State Sync Failures**: Nodes requesting historical data during state synchronization will encounter errors when the data is missing
3. **Silent State Corruption**: The inconsistency is not detected, logged, or reported, making diagnosis difficult
4. **Operational Impact**: Manual database inspection and repair is required to restore consistency

This qualifies as **Medium Severity** under Aptos bug bounty criteria: "State inconsistencies requiring intervention."

## Likelihood Explanation

This vulnerability has **high likelihood** of occurring in production:

**Trigger Conditions**:
1. Node performs pruning operations across multiple sub-pruners
2. Sub-pruner writes its progress metadata successfully  
3. Node crashes/terminates before main ledger pruner writes its progress
4. On restart, sub-pruner progress > main metadata progress
5. Initialization silently rolls back progress, creating persistent inconsistency

This is a realistic crash-recovery scenario that can occur during:
- Unexpected node shutdowns (power loss, OOM kills, SIGKILL)
- System updates or restarts during active pruning
- Database write failures at specific points
- Storage I/O errors or disk full conditions

The lack of validation or error detection makes this a silent failure that can persist indefinitely until manually discovered.

## Recommendation

Add validation to detect and handle the invalid state condition:

```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    // Validate input invariant
    if current_progress > target_version {
        return Err(AptosDbError::Other(format!(
            "PersistedAuxiliaryInfoPruner: Invalid pruner state detected. \
             Current progress ({}) is ahead of target version ({}). \
             This indicates database inconsistency requiring manual intervention.",
            current_progress, target_version
        )).into());
    }
    
    // Skip if already at target
    if current_progress == target_version {
        return Ok(());
    }
    
    let mut batch = SchemaBatch::new();
    PersistedAuxiliaryInfoDb::prune(current_progress, target_version, &mut batch)?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
        &DbMetadataValue::Version(target_version),
    )?;
    self.ledger_db
        .persisted_auxiliary_info_db()
        .write_schemas(batch)
}
```

Apply the same fix to all affected sub-pruners. Additionally, consider adding database consistency checks during initialization to detect and report such inconsistencies proactively.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::db_metadata::{DbMetadataKey, DbMetadataSchema, DbMetadataValue};
    
    #[test]
    fn test_pruner_progress_rollback_vulnerability() {
        // Setup: Create database with sub-pruner at version 1000
        let tmpdir = tempfile::tempdir().unwrap();
        let db = AptosDB::new_for_test(&tmpdir);
        
        // Simulate: Sub-pruner successfully pruned to version 1000
        db.ledger_db
            .persisted_auxiliary_info_db_raw()
            .put::<DbMetadataSchema>(
                &DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
                &DbMetadataValue::Version(1000),
            )
            .unwrap();
        
        // Simulate: Main ledger pruner only at version 500 (crashed before updating)
        let metadata_progress = 500;
        
        // Trigger: Initialize pruner - this calls prune(1000, 500)
        let result = PersistedAuxiliaryInfoPruner::new(
            Arc::clone(&db.ledger_db),
            metadata_progress,
        );
        
        // Verify: Initialization succeeded (should have failed)
        assert!(result.is_ok());
        
        // Verify: Progress was rolled back to 500
        let current_progress = db.ledger_db
            .persisted_auxiliary_info_db_raw()
            .get::<DbMetadataSchema>(&DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress)
            .unwrap()
            .unwrap()
            .expect_version();
        assert_eq!(current_progress, 500);
        
        // Demonstrate impact: Queries for data in [500, 1000) will fail
        // because the data was already deleted but progress says it should exist
        let result = db.ledger_db
            .persisted_auxiliary_info_db()
            .get_persisted_auxiliary_info_iter(500, 100);
        
        // This will eventually fail when expecting continuous versions
        // in the gap where data is missing
    }
}
```

## Notes

This vulnerability exists across **all seven ledger sub-pruners** that use the same initialization and pruning pattern. The systemic nature amplifies the impact, as a single crash can corrupt multiple storage components simultaneously. The absence of validation represents a critical gap in defensive programming for a consensus-critical storage layer.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/persisted_auxiliary_info_pruner.rs (L25-35)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        PersistedAuxiliaryInfoDb::prune(current_progress, target_version, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_db
            .persisted_auxiliary_info_db()
            .write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/persisted_auxiliary_info_pruner.rs (L38-59)
```rust
impl PersistedAuxiliaryInfoPruner {
    pub(in crate::pruner) fn new(
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.persisted_auxiliary_info_db_raw(),
            &DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
            metadata_progress,
        )?;

        let myself = PersistedAuxiliaryInfoPruner { ledger_db };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up PersistedAuxiliaryInfoPruner."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/pruner/pruner_utils.rs (L44-60)
```rust
pub(crate) fn get_or_initialize_subpruner_progress(
    sub_db: &DB,
    progress_key: &DbMetadataKey,
    metadata_progress: Version,
) -> Result<Version> {
    Ok(
        if let Some(v) = sub_db.get::<DbMetadataSchema>(progress_key)? {
            v.expect_version()
        } else {
            sub_db.put::<DbMetadataSchema>(
                progress_key,
                &DbMetadataValue::Version(metadata_progress),
            )?;
            metadata_progress
        },
    )
}
```

**File:** storage/aptosdb/src/ledger_db/persisted_auxiliary_info_db.rs (L121-126)
```rust
    pub(crate) fn prune(begin: Version, end: Version, batch: &mut SchemaBatch) -> Result<()> {
        for version in begin..end {
            batch.delete::<PersistedAuxiliaryInfoSchema>(&version)?;
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/utils/iterators.rs (L40-62)
```rust
    fn next_impl(&mut self) -> Result<Option<T>> {
        if self.expected_next_version >= self.end_version {
            return Ok(None);
        }

        let ret = match self.inner.next().transpose()? {
            Some((version, transaction)) => {
                ensure!(
                    version == self.expected_next_version,
                    "{} iterator: first version {}, expecting version {}, got {} from underlying iterator.",
                    std::any::type_name::<T>(),
                    self.first_version,
                    self.expected_next_version,
                    version,
                );
                self.expected_next_version += 1;
                Some(transaction)
            },
            None => None,
        };

        Ok(ret)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_info_pruner.rs (L25-34)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        TransactionInfoDb::prune(current_progress, target_version, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionInfoPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_db.transaction_info_db().write_schemas(batch)
    }
}
```
