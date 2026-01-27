# Audit Report

## Title
Partial Pruning Failure Causes Inconsistent Database State Leading to State Sync Failures

## Summary
The parallel execution of sub-pruners in `LedgerPruner::prune()` lacks atomic commit coordination. When some sub-pruners successfully prune data while others fail, the database enters an inconsistent state where queries for supposedly available versions fail, breaking state synchronization.

## Finding Description

The `LedgerPruner` executes multiple sub-pruners (WriteSetPruner, TransactionInfoPruner, EventStorePruner, etc.) in parallel using `par_iter()`. Each sub-pruner independently writes its batch and updates its progress metadata. When a pruning operation attempts to delete versions `[X, Y)`: [1](#0-0) 

If some sub-pruners succeed while others fail (due to I/O errors, resource limits, disk space exhaustion), the successful sub-pruners have already committed their deletions. The overall `LedgerPruner` progress remains at X (not updated due to error), making `min_readable_version = X`. This violates **State Consistency Invariant #4** - state transitions must be atomic.

Each sub-pruner follows this pattern: [2](#0-1) [3](#0-2) 

When `get_transaction_outputs()` queries data, it checks `error_if_ledger_pruned()` which validates against the overall `min_readable_version`, then fetches from multiple sub-databases: [4](#0-3) [5](#0-4) 

**Scenario:**
1. LedgerPruner progress = 100, min_readable_version = 100
2. Pruning attempts [100, 200)
3. WriteSetPruner succeeds, deletes versions [100, 200), updates progress to 200
4. TransactionInfoPruner fails due to disk error
5. LedgerPruner progress remains 100, min_readable_version = 100
6. Query `get_transaction_outputs(150)` passes `error_if_ledger_pruned(150)` but fails on `get_write_set(150)` with NotFound

## Impact Explanation

**Medium Severity** - State inconsistencies requiring intervention:
- Breaks state synchronization for affected version ranges
- Nodes attempting to sync from these versions receive NotFound errors
- Impacts network health as new nodes cannot join via state sync from affected nodes
- Violates data availability guarantees (versions marked as available are partially missing)

The issue auto-recovers on node restart through the catch-up mechanism, preventing permanent damage. However, during the inconsistent state window, the node cannot properly serve state sync requests. [6](#0-5) 

## Likelihood Explanation

**Medium Likelihood** - Occurs from natural system failures:
- Disk space exhaustion during pruning operations
- I/O errors on specific column families
- Resource limit violations (file descriptors, memory)
- Process crashes during pruning

Not directly exploitable by unprivileged attackers without causing DoS (out of scope), but can occur naturally in production environments with resource constraints.

## Recommendation

Implement two-phase commit pattern or progress validation:

1. **Option A - Defer Progress Updates**: Collect all sub-pruner batches, validate all succeed, then write progress atomically
2. **Option B - Pre-flight Validation**: Before pruning, verify all sub-pruners can write, then execute in parallel with rollback on any failure
3. **Option C - Consistency Check**: On startup and periodically, validate all sub-pruner progress values are synchronized, truncate any ahead of metadata_progress

Example fix for Option A:
```rust
// In LedgerPruner::prune()
let batches: Result<Vec<_>> = self.sub_pruners
    .par_iter()
    .map(|sub_pruner| sub_pruner.prepare_batch(progress, target))
    .collect();

let batches = batches?; // Fail if any batch preparation fails

// Now commit all batches - this ensures atomicity
for (sub_pruner, batch) in self.sub_pruners.iter().zip(batches) {
    sub_pruner.commit_batch(batch)?;
}
```

## Proof of Concept

```rust
// Test demonstrating inconsistent state
#[test]
fn test_partial_pruning_failure() {
    // Setup: Create ledger DB with data at versions [0, 200)
    let tmpdir = TempPath::new();
    let db = AptosDB::new_for_test(&tmpdir);
    
    // Commit transactions
    for version in 0..200 {
        db.save_transactions(...);
    }
    
    // Simulate partial pruning: inject failure in TransactionInfoPruner
    // while allowing WriteSetPruner to succeed
    let ledger_pruner = LedgerPruner::new(...);
    
    // Inject fault: make transaction_info_db fail on write
    inject_io_error_on_next_write(db.ledger_db.transaction_info_db());
    
    // Attempt pruning [0, 100)
    let result = ledger_pruner.prune(100);
    assert!(result.is_err()); // Pruning fails
    
    // Verify inconsistent state:
    assert_eq!(ledger_pruner.progress(), 0); // Overall progress unchanged
    assert_eq!(min_readable_version, 0);
    
    // WriteSet was pruned
    assert!(db.ledger_db.write_set_db().get_write_set(50).is_err());
    
    // But TransactionInfo still exists
    assert!(db.ledger_db.transaction_info_db().get_transaction_info(50).is_ok());
    
    // Query fails even though min_readable_version = 0
    let result = db.get_transaction_outputs(50, 10, 199);
    assert!(result.is_err()); // NotFound due to missing write sets
}
```

**Notes:**
- This vulnerability requires system-level failures (I/O errors, resource exhaustion) and is not directly exploitable by unprivileged attackers
- The issue auto-recovers on node restart when sub-pruners synchronize during initialization
- During the inconsistent state window, state sync queries fail for affected versions, impacting network availability
- All seven sub-pruners (EventStorePruner, PersistedAuxiliaryInfoPruner, TransactionAccumulatorPruner, TransactionAuxiliaryDataPruner, TransactionInfoPruner, TransactionPruner, WriteSetPruner) share this pattern and are vulnerable

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/write_set_pruner.rs (L25-33)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        WriteSetDb::prune(current_progress, target_version, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::WriteSetPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_db.write_set_db().write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/write_set_pruner.rs (L37-57)
```rust
    pub(in crate::pruner) fn new(
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.write_set_db_raw(),
            &DbMetadataKey::WriteSetPrunerProgress,
            metadata_progress,
        )?;

        let myself = WriteSetPruner { ledger_db };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up WriteSetPruner."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_info_pruner.rs (L25-33)
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
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L374-399)
```rust
    fn get_transaction_outputs(
        &self,
        start_version: Version,
        limit: u64,
        ledger_version: Version,
    ) -> Result<TransactionOutputListWithProofV2> {
        gauged_api("get_transaction_outputs", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

            if start_version > ledger_version || limit == 0 {
                return Ok(TransactionOutputListWithProofV2::new_empty());
            }

            self.error_if_ledger_pruned("Transaction", start_version)?;

            let limit = std::cmp::min(limit, ledger_version - start_version + 1);

            let (txn_infos, txns_and_outputs, persisted_aux_info) = (start_version
                ..start_version + limit)
                .map(|version| {
                    let txn_info = self
                        .ledger_db
                        .transaction_info_db()
                        .get_transaction_info(version)?;
                    let events = self.ledger_db.event_db().get_events_by_version(version)?;
                    let write_set = self.ledger_db.write_set_db().get_write_set(version)?;
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
