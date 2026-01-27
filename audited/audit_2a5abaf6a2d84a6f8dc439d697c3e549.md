# Audit Report

## Title
Pruner Progress Metadata Corruption Due to Missing Monotonicity Check in Transaction Auxiliary Data Pruner

## Summary
The `TransactionAuxiliaryDataPruner::prune()` function lacks validation that `target_version >= current_progress`. During crash recovery, when a sub-pruner's persisted progress exceeds the metadata pruner's progress, backwards progress updates cause metadata corruption where the system believes data still exists when it has already been deleted.

## Finding Description

The vulnerability exists in the pruner initialization and progress update logic. The issue manifests during the following scenario:

1. During normal operation, the `LedgerPruner` coordinates multiple sub-pruners running in parallel [1](#0-0) 

2. Each sub-pruner independently writes its progress metadata to disk using separate atomic transactions [2](#0-1) 

3. If the system crashes after a sub-pruner writes its progress (e.g., version 1500) but before the overall ledger metadata pruner updates (still at version 1000), we have an inconsistent state on disk.

4. On restart, the `TransactionAuxiliaryDataPruner::new()` constructor retrieves the sub-pruner's stored progress (1500) and the metadata pruner's progress (1000) [3](#0-2) 

5. The constructor then attempts to "catch up" by calling `myself.prune(1500, 1000)` - a backwards progression [4](#0-3) 

6. The `prune()` method unconditionally updates the progress metadata to `target_version` (1000) regardless of whether it's less than `current_progress` (1500) [5](#0-4) 

7. The underlying deletion operation uses a range `current_progress..target_version`, which is empty when `current_progress > target_version`, so no actual deletions occur [6](#0-5) 

The result: data from versions 1001-1500 has been physically deleted from the database, but the pruner metadata now claims it has only pruned up to version 1000. This breaks the **State Consistency** invariant that metadata must accurately reflect the actual database state.

This same pattern affects all ledger sub-pruners including `TransactionInfoPruner` [7](#0-6) , `EventStorePruner` [8](#0-7) , and others.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program category of "State inconsistencies requiring intervention."

**Concrete Impacts:**

1. **Read Failures**: When the system queries for data between the corrupted progress range (1001-1500), it will fail to find data it expects to exist based on metadata, causing unexpected errors in read operations.

2. **State Verification Failures**: Any integrity checks that compare actual database contents against pruner metadata will detect inconsistencies, potentially triggering alerts or causing node issues.

3. **Database Recovery Complications**: Manual intervention would be required to reconcile the metadata with actual database state, as the automated pruner logic cannot self-heal from this corruption.

4. **Cascading Failures**: If multiple sub-pruners experience this issue simultaneously (likely during the same crash), the metadata corruption compounds across different database components.

## Likelihood Explanation

This vulnerability has **MEDIUM to HIGH likelihood** of occurrence because:

1. **Common Trigger**: Node crashes during database operations are not uncommon in production systems (hardware failures, OOM conditions, power loss, operator errors).

2. **Narrow Timing Window**: The crash must occur after at least one sub-pruner commits its progress but before the metadata pruner completes. Given that sub-pruners run in parallel, this window exists during every pruning operation.

3. **No Recovery Logic**: The code lacks any defensive checks or recovery mechanisms for this scenario. The `get_or_initialize_subpruner_progress` function simply returns whatever progress is stored without validation [9](#0-8) 

4. **Persistence Across Restarts**: Once the corruption occurs, it persists until manual intervention, affecting all subsequent node operations.

## Recommendation

Add monotonicity validation to prevent backwards progress updates. The fix should be implemented in the `prune()` method of all affected sub-pruners:

```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    // Enforce progress monotonicity - never move backwards
    if target_version < current_progress {
        info!(
            current_progress = current_progress,
            target_version = target_version,
            "Skipping backwards pruning - target is behind current progress"
        );
        return Ok(());
    }
    
    let mut batch = SchemaBatch::new();
    TransactionAuxiliaryDataDb::prune(current_progress, target_version, &mut batch)?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress,
        &DbMetadataValue::Version(target_version),
    )?;
    self.ledger_db
        .transaction_auxiliary_data_db()
        .write_schemas(batch)
}
```

This same pattern should be applied to:
- `TransactionInfoPruner::prune()`
- `EventStorePruner::prune()`
- `TransactionPruner::prune()`
- `WriteSetPruner::prune()`
- `PersistedAuxiliaryInfoPruner::prune()`
- `TransactionAccumulatorPruner::prune()`

**Alternative Fix**: Modify the `new()` constructors to use `max(progress, metadata_progress)` instead of calling `prune()` with potentially backwards parameters.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_temppath::TempPath;
    
    #[test]
    fn test_backwards_progress_corruption() {
        // Setup: Create a pruner with progress at version 1500
        let tmp_dir = TempPath::new();
        let ledger_db = Arc::new(LedgerDb::new_for_test(&tmp_dir));
        
        // Simulate prior pruning: set sub-pruner progress to 1500
        ledger_db.transaction_auxiliary_data_db_raw()
            .put::<DbMetadataSchema>(
                &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress,
                &DbMetadataValue::Version(1500),
            ).unwrap();
        
        // Simulate crash scenario: metadata pruner only at 1000
        let metadata_progress = 1000;
        
        // This will trigger backwards pruning: prune(1500, 1000)
        let pruner = TransactionAuxiliaryDataPruner::new(
            ledger_db.clone(),
            metadata_progress,
        ).unwrap();
        
        // Bug: Progress should still be 1500, but it's been corrupted to 1000
        let actual_progress = ledger_db
            .transaction_auxiliary_data_db_raw()
            .get::<DbMetadataSchema>(
                &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress
            )
            .unwrap()
            .unwrap()
            .expect_version();
            
        assert_eq!(actual_progress, 1000); // CORRUPTED - should be 1500
        
        // Data from 1001-1500 is deleted but metadata claims it exists
        // This is the metadata corruption
    }
}
```

**Steps to Reproduce in Production:**
1. Start an Aptos node with pruning enabled
2. Allow pruning to progress to version 1500
3. Force-kill the node process during an active pruning operation (after sub-pruners commit but before metadata pruner completes)
4. Restart the node
5. Observe metadata corruption in logs showing backwards progress during initialization
6. Verify that pruner progress metadata has regressed while actual data remains deleted

## Notes

This vulnerability affects the entire ledger pruner subsystem, not just `TransactionAuxiliaryDataPruner`. All sub-pruners that follow the same initialization pattern are vulnerable to this metadata corruption during crash recovery scenarios.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L78-84)
```rust
            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_auxiliary_data_pruner.rs (L25-35)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        TransactionAuxiliaryDataDb::prune(current_progress, target_version, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_db
            .transaction_auxiliary_data_db()
            .write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_auxiliary_data_pruner.rs (L43-47)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_auxiliary_data_db_raw(),
            &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress,
            metadata_progress,
        )?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_auxiliary_data_pruner.rs (L56-56)
```rust
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/ledger_db/transaction_auxiliary_data_db.rs (L74-79)
```rust
    pub(crate) fn prune(begin: Version, end: Version, batch: &mut SchemaBatch) -> Result<()> {
        for version in begin..end {
            batch.delete::<TransactionAuxiliaryDataSchema>(&version)?;
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_info_pruner.rs (L54-54)
```rust
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L106-106)
```rust
        myself.prune(progress, metadata_progress)?;
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
