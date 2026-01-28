# Audit Report

## Title
Non-Atomic Pruner Progress Updates Cause Node Initialization Failures and State Inconsistencies

## Summary
The `write_pruner_progress()` function in LedgerDb updates pruner progress across 8 sub-databases using sequential, non-atomic write operations. Partial failures during this process leave sub-databases with inconsistent pruning boundaries, causing node initialization failures when EventStorePruner and other sub-pruners attempt to "catch up" with invalid version ranges.

## Finding Description

The vulnerability exists in the ledger pruner progress persistence mechanism. When `save_min_readable_version()` is called after fast sync completion, it invokes `LedgerDb::write_pruner_progress()`, which performs sequential, non-atomic updates across 8 sub-databases. [1](#0-0) 

Each `write_pruner_progress()` call is a separate database operation using the `?` operator, causing early return on any failure and leaving subsequent databases unupdated. This violates atomicity requirements for state transitions.

**Critical Failure Scenario:**

1. Fast sync completes at version 1000
2. `save_min_readable_version(1000)` is called from the restore path: [2](#0-1) 

3. Sequential updates begin, but a crash/disk full/I/O error occurs mid-sequence:
   - event_db writes progress = 1000 ✓
   - persisted_auxiliary_info_db writes progress = 1000 ✓
   - **[SYSTEM FAILURE]**
   - transaction_db remains at old value (e.g., 800)
   - ledger_metadata_db remains at 800

4. On restart, `LedgerPruner::new()` reads the metadata progress: [3](#0-2) 

5. Each sub-pruner initializes and attempts to catch up to the metadata progress. For example, EventStorePruner: [4](#0-3) 

6. **Critical Bug**: EventStorePruner finds its own progress = 1000, but metadata_progress = 800. It calls `prune(1000, 800)`, which leads to: [5](#0-4) 

The expression `(end - start) as usize` where end=800 and start=1000 causes integer underflow, wrapping to approximately `u64::MAX - 199`. When passed to `get_events_by_version_iter()`, the `checked_add` at line 111 detects overflow and returns an error, causing initialization to fail.

**Inconsistent Validation:**

TransactionPruner has proper safeguards: [6](#0-5) 

However, EventStorePruner and other sub-pruners lack this validation, leading to the underflow condition during catch-up.

## Impact Explanation

**High Severity** - This vulnerability causes complete node initialization failure, meeting the "Validator node slowdowns" category in the Aptos bug bounty program.

1. **Total Node Initialization Failure**: Nodes experiencing partial pruner progress updates cannot restart successfully. The integer underflow causes `get_events_by_version_iter()` to fail with an overflow error during the catch-up phase, preventing LedgerPruner initialization.

2. **State Query Inconsistencies**: If the node remains operational despite inconsistent pruner states (e.g., in sharded mode with delayed initialization), the system advertises `min_readable_version = 800` based on metadata, but events for versions 800-1000 may already be pruned while transactions haven't, causing query failures.

3. **Operational Risk**: The vulnerability requires manual database intervention to resolve, as there is no automatic recovery mechanism. The TODO comment acknowledges this: [7](#0-6) 

This meets **High Severity** criteria: complete validator node initialization failure prevents the node from serving any requests or participating in consensus.

## Likelihood Explanation

**High Likelihood** - This vulnerability can occur in multiple realistic operational scenarios:

1. **Disk Space Exhaustion**: During fast sync operations when disk space fills up after some sub-databases successfully update
2. **I/O Errors**: Hardware failures, network filesystem disconnections, or storage controller failures during the write sequence
3. **Process Termination**: Node crashes, OOM kills, or SIGKILL signals during the update window
4. **Resource Contention**: Heavy disk I/O load causing individual write operations to timeout

The vulnerability window is small (milliseconds for 8 sequential writes), but fast sync operations are common when:
- New validators join the network
- Existing validators recover from downtime
- Nodes perform state synchronization after network partitions

Storage sharding increases vulnerability surface area since each sub-database is a separate physical RocksDB instance, multiplying potential failure points.

## Recommendation

Implement atomic batch writes for all pruner progress updates:

```rust
pub(crate) fn write_pruner_progress(&self, version: Version) -> Result<()> {
    info!("Fast sync is done, writing pruner progress {version} for all ledger sub pruners.");
    
    // Create a single atomic batch for all updates
    let mut batch = SchemaBatch::new();
    
    // Add all progress updates to the batch
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::EventPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::PersistedAuxiliaryInfoPrunerProgress,
        &DbMetadataValue::Version(version),
    )?;
    // ... add all other sub-database progress updates to batch ...
    
    // Atomic commit
    self.ledger_metadata_db.write_schemas(batch)?;
    
    Ok(())
}
```

Additionally, add validation in all sub-pruners:

```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    ensure!(target_version >= current_progress, 
            "target_version {} must be >= current_progress {}", 
            target_version, current_progress);
    // ... rest of prune logic
}
```

## Proof of Concept

While a full reproduction requires simulating system failures during database writes, the vulnerability can be demonstrated by manually creating inconsistent pruner progress states in a test database and observing the initialization failure when EventStorePruner attempts to catch up with an invalid range.

**Notes:**
- The actual failure mode is a fast error from `checked_add` overflow detection rather than infinite iteration, but the core impact (initialization failure) remains
- The vulnerability affects all sub-pruners lacking validation, not just EventStorePruner
- Manual database repair is required to recover from this state

### Citations

**File:** storage/aptosdb/src/ledger_db/mod.rs (L281-281)
```rust
        // TODO(grao): Handle data inconsistency.
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L373-388)
```rust
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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L225-225)
```rust
            self.ledger_pruner.save_min_readable_version(version)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L129-129)
```rust
        let metadata_progress = ledger_metadata_pruner.progress()?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L90-106)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.event_db_raw(),
            &DbMetadataKey::EventPrunerProgress,
            metadata_progress,
        )?;

        let myself = EventStorePruner {
            ledger_db,
            internal_indexer_db,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up EventStorePruner."
        );
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L202-202)
```rust
        for events in self.get_events_by_version_iter(start, (end - start) as usize)? {
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L111-111)
```rust
        ensure!(end >= start, "{} must be >= {}", end, start);
```
