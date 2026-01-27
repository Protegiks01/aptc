# Audit Report

## Title
DBSubPruner Initialization Bypasses Historical Data Pruning Leading to Storage Bloat

## Summary
The `get_or_initialize_subpruner_progress` function violates the DBSubPruner trait contract by prematurely committing pruner progress metadata before actual pruning occurs. During first-time initialization, this causes all sub-pruners to skip pruning historical data, resulting in unbounded storage growth and eventual node unavailability.

## Finding Description

The DBSubPruner trait contract implicitly requires that a pruner's progress metadata accurately reflects what data has been pruned from the database. The parent `LedgerPruner` relies on this contract to coordinate pruning across multiple sub-pruners. [1](#0-0) 

The vulnerability exists in the `get_or_initialize_subpruner_progress` utility function: [2](#0-1) 

When a sub-pruner's progress doesn't exist in the database (first-time initialization), this function immediately writes `metadata_progress` to the database using a direct `put` operation (line 53-56). This write is NOT part of a SchemaBatch and commits immediately to disk.

The function then returns `metadata_progress`, which equals the value just written. In the pruner's initialization code: [3](#0-2) 

At line 56, `myself.prune(progress, metadata_progress)` is called. Since `progress == metadata_progress`, this becomes `prune(N, N)`, which prunes the range `[N, N)` - an empty range that performs no actual pruning.

The actual prune implementation confirms this: [4](#0-3) 

The loop `for version in begin..end` (line 122) iterates zero times when `begin == end`.

**Contract Violation**: The progress metadata now indicates the pruner has processed up to version N, but historical data from version 0 to N-1 remains unpruned in the database. The parent pruner makes incorrect assumptions: [5](#0-4) 

At lines 78-84, the parent pruner calls each sub-pruner's `prune()` method starting from the current progress. Since the sub-pruner's progress was incorrectly set to `metadata_progress`, it will only prune versions beyond that point, never returning to prune the historical range [0, metadata_progress).

**Attack Scenarios**:

1. **Software Upgrade**: If Aptos adds a new pruner (e.g., `PersistedAuxiliaryInfoPruner` in a new release) and existing nodes upgrade:
   - Nodes have historical PersistedAuxiliaryInfo data for versions 0-1,000,000
   - LedgerMetadataPruner has metadata_progress = 800,000
   - New pruner initializes with progress = 800,000 (no actual pruning)
   - Versions 0-799,999 remain unpruned forever

2. **Database Restoration**: When restoring from backup with missing or corrupted pruner progress metadata, historical data won't be pruned.

This pattern affects ALL sub-pruners that use `get_or_initialize_subpruner_progress`:
- EventStorePruner
- PersistedAuxiliaryInfoPruner  
- TransactionAccumulatorPruner
- TransactionAuxiliaryDataPruner
- TransactionInfoPruner
- TransactionPruner
- WriteSetPruner

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Storage Bloat**: Historical data accumulates indefinitely, consuming disk space at a rate proportional to network activity. For a high-throughput network processing thousands of transactions per second, unpruned historical data can consume hundreds of gigabytes or terabytes over time.

**Operational Impact**: When disk space is exhausted, validator nodes cannot commit new blocks, causing node unavailability. This requires manual intervention to either:
- Provision additional storage (expensive, temporary solution)
- Manually prune historical data (requires downtime)
- Restore from a consistent backup (data loss risk)

**Inconsistent Cluster State**: Different nodes may have different amounts of historical data depending on when they were initialized, upgrade timing, or restoration events. This complicates cluster management and debugging.

While this doesn't directly affect consensus or allow fund theft (historical data doesn't impact current state verification), it breaks the **State Consistency** invariant by creating a divergence between progress metadata and actual pruned state.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability manifests in specific but realistic operational scenarios:

1. **Software Upgrades Adding New Pruners**: HIGH likelihood if Aptos adds new pruning components. Historical evidence from the codebase structure suggests new pruners are periodically added as the system evolves.

2. **Database Migrations/Restorations**: MEDIUM likelihood during disaster recovery, database migration between environments, or backup restoration procedures.

3. **Initial Network Deployments**: LOW likelihood for completely fresh nodes (no historical data exists).

The bug is deterministic - it WILL occur when the conditions are met. The frequency depends on operational patterns:
- Active development adding new storage components: High exposure
- Mature, stable deployment: Lower exposure

All Aptos validator operators are potentially affected during major version upgrades that introduce new pruners.

## Recommendation

**Root Cause**: The `get_or_initialize_subpruner_progress` function incorrectly writes progress before pruning occurs, violating atomicity.

**Solution**: Modify the initialization logic to set initial progress to 0 (or earliest version in database) instead of metadata_progress, allowing the catch-up prune to execute properly.

**Fixed Implementation for `pruner_utils.rs`**:

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
            // Return 0 instead of metadata_progress for first-time initialization
            // The caller will prune from 0 to metadata_progress and update progress atomically
            0
        },
    )
}
```

**Alternative Solution** (if version 0 is not always valid):

```rust
pub(crate) fn get_or_initialize_subpruner_progress(
    sub_db: &DB,
    progress_key: &DbMetadataKey,
    metadata_progress: Version,
) -> Result<Version> {
    if let Some(v) = sub_db.get::<DbMetadataSchema>(progress_key)? {
        Ok(v.expect_version())
    } else {
        // Find the earliest version in the database, or use 0 if empty
        let earliest_version = /* determine from schema iterator */ 0;
        Ok(earliest_version)
    }
    // Do NOT write progress here - let the prune() method write it atomically
}
```

This ensures the catch-up prune at line 56 of `persisted_auxiliary_info_pruner.rs` actually performs work: `prune(0, metadata_progress)` will prune all historical data and update progress atomically.

## Proof of Concept

```rust
// Reproduction steps for validator operators or developers:

// 1. Start with a node that has accumulated historical PersistedAuxiliaryInfo data
//    Versions 0-1000 exist in persisted_auxiliary_info_db

// 2. LedgerMetadataPruner has metadata_progress = 800

// 3. Simulate first-time initialization of PersistedAuxiliaryInfoPruner
//    (e.g., by deleting PersistedAuxiliaryInfoPrunerProgress from db_metadata)

// 4. Initialize the pruner:
use aptos_aptosdb::{LedgerDb, PersistedAuxiliaryInfoPruner};

let ledger_db = Arc::new(LedgerDb::open(/* path */)?);
let metadata_progress = 800;

// Verify progress doesn't exist
let progress_exists = ledger_db
    .persisted_auxiliary_info_db_raw()
    .get::<DbMetadataSchema>(&DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress)?
    .is_some();
assert!(!progress_exists); // Should be None for first-time init

// Initialize the pruner
let pruner = PersistedAuxiliaryInfoPruner::new(ledger_db.clone(), metadata_progress)?;

// 5. Verify the bug: progress is now 800, but data still exists for versions 0-799
let actual_progress = ledger_db
    .persisted_auxiliary_info_db_raw()
    .get::<DbMetadataSchema>(&DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress)?
    .unwrap()
    .expect_version();
assert_eq!(actual_progress, 800); // Progress claims 800

// But historical data still exists:
for version in 0..800 {
    let data = ledger_db
        .persisted_auxiliary_info_db()
        .get_persisted_auxiliary_info(version)?;
    // BUG: This should be None (pruned), but it still exists!
    assert!(data.is_some(), "Historical data was not pruned at version {}", version);
}

// Result: 800 versions of unpruned data consuming disk space
// This will accumulate indefinitely over time as the node continues operation
```

**Notes**

This vulnerability demonstrates a subtle atomicity violation where metadata updates and data modifications are not properly coordinated. The parent LedgerPruner cannot detect this inconsistency because each sub-pruner appears to have valid progress metadata. Only by examining the actual database contents can the unpruned historical data be discovered.

The fix is straightforward but requires careful testing to ensure no existing nodes experience issues during the upgrade. A migration script may be needed to detect and repair nodes that already have this inconsistency in production.

### Citations

**File:** storage/aptosdb/src/pruner/db_sub_pruner.rs (L6-14)
```rust
/// Defines the trait for sub-pruner of a parent DB pruner
pub trait DBSubPruner {
    /// Returns the name of the sub pruner.
    fn name(&self) -> &str;

    /// Performs the actual pruning, a target version is passed, which is the target the pruner
    /// tries to prune.
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()>;
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

**File:** storage/aptosdb/src/pruner/ledger_pruner/persisted_auxiliary_info_pruner.rs (L38-60)
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
}
```

**File:** storage/aptosdb/src/ledger_db/persisted_auxiliary_info_db.rs (L120-126)
```rust
    /// Deletes the persisted auxiliary info between a range of version in [begin, end)
    pub(crate) fn prune(begin: Version, end: Version, batch: &mut SchemaBatch) -> Result<()> {
        for version in begin..end {
            batch.delete::<PersistedAuxiliaryInfoSchema>(&version)?;
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L62-92)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning ledger data."
            );
            self.ledger_metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning ledger data is done.");
        }

        Ok(target_version)
    }
```
