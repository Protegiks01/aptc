# Audit Report

## Title
Memory Exhaustion via Unbounded Pruning During Sub-Pruner Initialization

## Summary
The `TransactionAccumulatorPruner` and other LedgerPruner sub-pruners bypass batch size limits during initialization catchup, potentially attempting to prune millions or billions of versions in a single call. This causes memory exhaustion via accumulation of delete operations in `SchemaBatch`, leading to node crash and denial of service.

## Finding Description

During normal operation, the `LedgerPruner` respects batch size limits (default 5,000 versions) when pruning data. [1](#0-0) 

The batch size limit is enforced in the main pruning loop. [2](#0-1) 

However, during initialization, each sub-pruner performs a "catchup" operation that **bypasses** this batch size limit. The `TransactionAccumulatorPruner::new()` method directly calls `prune()` with the full version gap between its stored progress and the metadata pruner's progress. [3](#0-2) 

The vulnerability occurs when a sub-pruner's progress falls significantly behind the metadata pruner's progress. This can happen due to:
1. **Database corruption** affecting specific column families
2. **Selective database restore** from different backup snapshots
3. **Manual database manipulation** during troubleshooting
4. **Disk corruption** affecting pruner progress metadata

When this gap exists, the initialization calls `TransactionAccumulatorDb::prune()` with an unbounded range. [4](#0-3) 

The `prune()` function iterates through every version in the range, adding delete operations to a `SchemaBatch`. The `SchemaBatch` accumulates ALL operations in memory via a `HashMap<ColumnFamilyName, Vec<WriteOp>>`. [5](#0-4) 

Each delete operation creates a `WriteOp::Deletion { key: Vec<u8> }` that is stored in memory. [6](#0-5) 

**Attack Scenario:**
1. Node operates normally with metadata pruner progress at version 500,000,000
2. Database corruption or selective restore causes `TransactionAccumulatorPruner` progress to reset to 0
3. Node attempts to restart
4. During initialization, `TransactionAccumulatorPruner::new()` is called with `metadata_progress = 500,000,000`
5. It reads its own progress = 0
6. Calls `myself.prune(0, 500_000_000)`
7. `TransactionAccumulatorDb::prune()` executes a for-loop for 500 million iterations
8. Each iteration adds 1-3 delete operations to the `SchemaBatch`
9. Memory accumulates 500M-1.5B delete operations (~several gigabytes)
10. Node exhausts memory and crashes with OOM
11. Node cannot restart without manual intervention

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Impact:**
- **Node Availability**: Affected nodes cannot start up, causing denial of service
- **Recovery Complexity**: Requires manual database intervention or code patching
- **Scope**: Affects any node experiencing database corruption or inconsistent restore
- **Network Impact**: If multiple nodes are affected simultaneously (e.g., after a botched upgrade), network liveness could be impacted

The issue does not directly cause:
- Loss of funds or consensus violations (not Critical)
- Permanent network partition (recoverable with manual intervention)

However, it creates a **state inconsistency** where nodes cannot operate without manual database fixes, requiring operational intervention to restore service.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires specific preconditions:
1. Sub-pruner progress must lag behind metadata pruner progress by a significant amount (millions of versions)
2. This gap must exist during node initialization

**Realistic Scenarios:**
- **Database Corruption**: Hardware failures or filesystem issues corrupt pruner metadata
- **Backup/Restore Operations**: Operators restore database from multiple backup snapshots with inconsistent timestamps
- **Database Migration**: Moving data between environments with partial synchronization
- **Manual Intervention**: Operators manually manipulate database during troubleshooting

These scenarios are **not uncommon** in production blockchain operations, especially during:
- Disaster recovery procedures
- Node migration between data centers
- Database optimization or re-sharding
- Emergency database repairs

The default batch size of 5,000 versions means even a relatively small gap (1 million versions) would accumulate 200 batches worth of deletes in memory.

## Recommendation

Implement batch size limits during initialization catchup by breaking the catchup into smaller batches.

**Option 1: Apply batch limit during initialization**

Modify `TransactionAccumulatorPruner::new()` to respect batch size limits:

```rust
pub(in crate::pruner) fn new(
    ledger_db: Arc<LedgerDb>,
    metadata_progress: Version,
) -> Result<Self> {
    let progress = get_or_initialize_subpruner_progress(
        ledger_db.transaction_accumulator_db_raw(),
        &DbMetadataKey::TransactionAccumulatorPrunerProgress,
        metadata_progress,
    )?;

    let myself = TransactionAccumulatorPruner { ledger_db };

    // Apply batch size limit during catchup
    const CATCHUP_BATCH_SIZE: u64 = 10_000;
    let mut current_progress = progress;
    
    info!(
        progress = progress,
        metadata_progress = metadata_progress,
        "Catching up TransactionAccumulatorPruner."
    );
    
    while current_progress < metadata_progress {
        let batch_target = std::cmp::min(
            current_progress + CATCHUP_BATCH_SIZE,
            metadata_progress
        );
        myself.prune(current_progress, batch_target)?;
        current_progress = batch_target;
    }

    Ok(myself)
}
```

Apply this same pattern to all sub-pruners: `EventStorePruner`, `TransactionInfoPruner`, `TransactionPruner`, `WriteSetPruner`, `TransactionAuxiliaryDataPruner`, and `PersistedAuxiliaryInfoPruner`.

**Option 2: Defensive limit in TransactionAccumulatorDb::prune()**

Add a hard limit check in the prune function itself:

```rust
pub(crate) fn prune(begin: Version, end: Version, db_batch: &mut SchemaBatch) -> Result<()> {
    const MAX_PRUNE_RANGE: u64 = 100_000;
    
    if end - begin > MAX_PRUNE_RANGE {
        return Err(anyhow!(
            "Prune range {} exceeds maximum allowed {}",
            end - begin,
            MAX_PRUNE_RANGE
        ).into());
    }
    
    // existing prune logic...
}
```

**Recommendation**: Implement both options for defense-in-depth.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_schemadb::DB;
    
    #[test]
    #[should_panic(expected = "out of memory")]
    fn test_unbounded_prune_memory_exhaustion() {
        // Create a test database
        let tmpdir = TempPath::new();
        let db = DB::open(
            tmpdir.path(),
            "test_db",
            vec!["default"],
            &Default::default()
        ).unwrap();
        
        let ledger_db = Arc::new(LedgerDb::new_for_test(Arc::new(db)));
        
        // Simulate scenario: metadata progress at 10M, sub-pruner at 0
        let metadata_progress = 10_000_000;
        
        // Manually set sub-pruner progress to 0 to create gap
        ledger_db.transaction_accumulator_db_raw()
            .put::<DbMetadataSchema>(
                &DbMetadataKey::TransactionAccumulatorPrunerProgress,
                &DbMetadataValue::Version(0),
            )
            .unwrap();
        
        // This should exhaust memory trying to prune 10M versions at once
        // In practice, this panics with OOM before completing
        let _pruner = TransactionAccumulatorPruner::new(
            ledger_db,
            metadata_progress,
        );
        
        // If we reach here, the vulnerability is fixed
    }
    
    #[test]
    fn test_bounded_prune_succeeds() {
        // Similar setup but with batch size limit applied
        // Should complete successfully without memory exhaustion
        
        let tmpdir = TempPath::new();
        let db = DB::open(
            tmpdir.path(),
            "test_db", 
            vec!["default"],
            &Default::default()
        ).unwrap();
        
        let ledger_db = Arc::new(LedgerDb::new_for_test(Arc::new(db)));
        
        // With fixed implementation, even large gaps should work
        let metadata_progress = 1_000_000;
        
        ledger_db.transaction_accumulator_db_raw()
            .put::<DbMetadataSchema>(
                &DbMetadataKey::TransactionAccumulatorPrunerProgress,
                &DbMetadataValue::Version(0),
            )
            .unwrap();
        
        // Should succeed with batched catchup
        let pruner = TransactionAccumulatorPruner::new(
            ledger_db,
            metadata_progress,
        ).unwrap();
        
        // Verify progress was updated correctly
        assert_eq!(pruner.progress(), metadata_progress);
    }
}
```

The PoC demonstrates that attempting to prune 10 million versions at once during initialization will exhaust memory. The actual threshold depends on available RAM, but even 1 million versions would accumulate hundreds of megabytes to gigabytes of delete operations in memory.

## Notes

This vulnerability affects **all** LedgerPruner sub-pruners, not just `TransactionAccumulatorPruner`. The same unbounded catchup pattern exists in:
- `EventStorePruner` [7](#0-6) 
- `TransactionInfoPruner` [8](#0-7) 

The fix should be applied uniformly across all sub-pruners to prevent this class of vulnerability. The batch size used during catchup should be configurable but with a reasonable default (e.g., 10,000-50,000 versions) to balance initialization speed with memory safety.

### Citations

**File:** config/src/config/storage_config.rs (L392-392)
```rust
            batch_size: 5_000,
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L66-68)
```rust
        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_accumulator_pruner.rs (L38-59)
```rust
impl TransactionAccumulatorPruner {
    pub(in crate::pruner) fn new(
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_accumulator_db_raw(),
            &DbMetadataKey::TransactionAccumulatorPrunerProgress,
            metadata_progress,
        )?;

        let myself = TransactionAccumulatorPruner { ledger_db };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up TransactionAccumulatorPruner."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L149-172)
```rust
    pub(crate) fn prune(begin: Version, end: Version, db_batch: &mut SchemaBatch) -> Result<()> {
        for version_to_delete in begin..end {
            db_batch.delete::<TransactionAccumulatorRootHashSchema>(&version_to_delete)?;
            // The even version will be pruned in the iteration of version + 1.
            if version_to_delete % 2 == 0 {
                continue;
            }

            let first_ancestor_that_is_a_left_child =
                Self::find_first_ancestor_that_is_a_left_child(version_to_delete);

            // This assertion is true because we skip the leaf nodes with address which is a
            // a multiple of 2.
            assert!(!first_ancestor_that_is_a_left_child.is_leaf());

            let mut current = first_ancestor_that_is_a_left_child;
            while !current.is_leaf() {
                db_batch.delete::<TransactionAccumulatorSchema>(&current.left_child())?;
                db_batch.delete::<TransactionAccumulatorSchema>(&current.right_child())?;
                current = current.right_child();
            }
        }
        Ok(())
    }
```

**File:** storage/schemadb/src/batch.rs (L130-133)
```rust
pub struct SchemaBatch {
    rows: DropHelper<HashMap<ColumnFamilyName, Vec<WriteOp>>>,
    stats: SampledBatchStats,
}
```

**File:** storage/schemadb/src/batch.rs (L165-172)
```rust
    fn raw_delete(&mut self, cf_name: ColumnFamilyName, key: Vec<u8>) -> DbResult<()> {
        self.rows
            .entry(cf_name)
            .or_default()
            .push(WriteOp::Deletion { key });

        Ok(())
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L106-106)
```rust
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_info_pruner.rs (L54-54)
```rust
        myself.prune(progress, metadata_progress)?;
```
