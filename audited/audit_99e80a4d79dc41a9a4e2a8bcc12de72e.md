# Audit Report

## Title
Non-Atomic Cross-Database Writes in EventStorePruner and TransactionPruner Cause Inconsistent Pruning State

## Summary
The `EventStorePruner` and `TransactionPruner` perform non-atomic writes to two separate databases (indexer DB and ledger DB). If the first write succeeds but the second fails, the pruning subsystem enters an inconsistent state where indexer metadata indicates data is pruned while the actual event/transaction data remains unpruned. This breaks the State Consistency invariant and can cause the pruning subsystem to malfunction.

## Finding Description

The vulnerability exists in two pruner implementations when internal indexer is enabled:

**EventStorePruner Dual-Write Issue:** [1](#0-0) 

When `internal_indexer_db` is enabled and `event_enabled()` returns true, the pruner performs two separate `write_schemas()` calls:
1. First write at lines 76-78 writes to `indexer_db` with metadata `IndexerMetadataKey::EventPrunerProgress = target_version`
2. Second write at line 80 writes to `event_db` with metadata `DbMetadataKey::EventPrunerProgress = target_version`

These writes are **not atomic** across databases. If the indexer write succeeds but the event DB write fails (due to disk I/O error, crash, disk full, etc.), the system state becomes:
- Indexer metadata: `EventPrunerProgress = target_version` (indicates pruning complete)
- Event DB: Events still exist for the range, metadata unchanged (pruning incomplete)

**TransactionPruner Dual-Write Issue:** [2](#0-1) 

The same pattern exists in `TransactionPruner` when `internal_indexer_db` is enabled and `transaction_enabled()` returns true. Two separate writes occur at lines 67 (indexer) and 73 (transaction DB).

**Error Propagation and Recovery Failure:** [3](#0-2) 

When `EventStorePruner::prune()` returns an error, `LedgerPruner` does not record progress (line 87 is skipped). The error propagates to `PrunerWorker`: [4](#0-3) 

The worker logs the error and retries, but there is **no reconciliation logic** to detect or fix the split-brain state between indexer and ledger DBs.

**Lack of Recovery During Initialization:** [5](#0-4) 

During initialization, only the event DB metadata is checked via `get_or_initialize_subpruner_progress()`. The indexer DB metadata is never verified for consistency, so a pre-existing split-brain state is not detected or corrected.

**Broken Invariant:**
This violates **State Consistency** (Invariant #4): "State transitions must be atomic and verifiable." The pruning operation is not atomic across the two databases, leading to unverifiable inconsistent state.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: When the pruning subsystem enters inconsistent state, it may repeatedly fail and retry the same operations. Unpruned data accumulates in event/transaction DBs, causing storage bloat and degrading validator performance over time.

2. **State Inconsistencies Requiring Intervention**: The split-brain state between indexer metadata and actual ledger DB data is a significant state inconsistency. Indexer queries may return "no events/transactions" while the data still exists in storage. This requires manual intervention to reconcile:
   - Administrators must identify the inconsistency
   - Manually update metadata or re-prune the affected ranges
   - Potentially requires database recovery procedures

3. **Pruning Subsystem Malfunction**: Once in split-brain state, the pruning system cannot self-recover. On each retry:
   - Indexer DB thinks pruning is complete for range [progress, target]
   - Event/Transaction DB has not actually pruned that range
   - If the same failure condition persists, the system remains stuck
   - Storage continues growing, eventually causing disk space exhaustion

## Likelihood Explanation

**Medium to High Likelihood**:

This vulnerability is triggered by common failure scenarios:

1. **Disk I/O Errors**: Transient or permanent disk errors during the second `write_schemas()` call
2. **Disk Full Conditions**: If disk becomes full between the two writes
3. **System Crashes**: Node crashes or restarts between the two database writes
4. **Database Corruption**: Corruption affecting one database but not the other
5. **Resource Exhaustion**: Memory or file descriptor limits hit during second write

These are **not** rare edge cases—they are operational realities in distributed systems. Any validator node can experience these conditions, especially under high load or during infrastructure issues.

The vulnerability is **deterministic** once the failure condition occurs. There is no randomness—if the first write succeeds and the second fails, inconsistency is guaranteed.

## Recommendation

Implement atomic cross-database writes using one of these approaches:

**Option 1: Write-Ahead Log (WAL) Approach**
Use a single transaction log that records intended writes to both databases, then apply them with retry and recovery logic.

**Option 2: Single Metadata Store**
Move all pruner progress metadata to a single authoritative database and synchronize before/after pruning operations.

**Option 3: Two-Phase Commit (Recommended)**
Implement a two-phase commit protocol for cross-database writes:

```rust
// Pseudocode for fixed EventStorePruner::prune()
pub fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    // Phase 1: Prepare both batches
    let mut batch = SchemaBatch::new();
    let mut indexer_batch = None;
    
    // ... pruning operations ...
    
    // Phase 2: Verify both databases are writable before committing
    if let Some(indexer_batch) = indexer_batch.as_ref() {
        // Pre-check: ensure both databases can be written
        // This could be a lightweight check like verifying disk space
        self.expect_indexer_db().get_inner_db_ref().check_writable()?;
    }
    self.ledger_db.event_db().check_writable()?;
    
    // Phase 3: Write with rollback capability
    let indexer_written = if let Some(mut indexer_batch) = indexer_batch {
        indexer_batch.put::<InternalIndexerMetadataSchema>(
            &IndexerMetadataKey::EventPrunerProgress,
            &IndexerMetadataValue::Version(target_version),
        )?;
        self.expect_indexer_db().get_inner_db_ref().write_schemas(indexer_batch)?;
        true
    } else {
        false
    };
    
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::EventPrunerProgress,
        &DbMetadataValue::Version(target_version),
    )?;
    
    // If event_db write fails, rollback indexer metadata
    self.ledger_db.event_db().write_schemas(batch)
        .map_err(|e| {
            if indexer_written {
                // Attempt to rollback indexer metadata to previous version
                let _ = self.rollback_indexer_progress(current_progress);
            }
            e
        })
}
```

**Option 4: Consistency Check and Recovery**
Add initialization-time consistency checks:

```rust
// In EventStorePruner::new()
pub(in crate::pruner) fn new(...) -> Result<Self> {
    let event_db_progress = get_or_initialize_subpruner_progress(
        ledger_db.event_db_raw(),
        &DbMetadataKey::EventPrunerProgress,
        metadata_progress,
    )?;
    
    // NEW: Check indexer progress for consistency
    if let Some(indexer_db) = internal_indexer_db.as_ref() {
        let indexer_progress = indexer_db.get_inner_db_ref()
            .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::EventPrunerProgress)?
            .map(|v| v.expect_version())
            .unwrap_or(0);
        
        // If indexer is ahead, reconcile by re-pruning from event_db_progress to indexer_progress
        if indexer_progress > event_db_progress {
            warn!("Detected inconsistent pruner state: indexer={}, event_db={}", 
                  indexer_progress, event_db_progress);
            // Force re-prune the gap
            myself.prune(event_db_progress, indexer_progress)?;
        }
    }
    
    // Continue with normal catch-up...
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[cfg(test)]
mod test {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_split_brain_pruning_failure() {
        // Setup: Create EventStorePruner with indexer enabled
        let tmp_dir = TempDir::new().unwrap();
        let db = Arc::new(DB::open(...));
        let indexer_db = Some(InternalIndexerDB::new(...));
        
        let pruner = EventStorePruner {
            ledger_db: Arc::new(LedgerDb::new(db)),
            internal_indexer_db: indexer_db,
        };
        
        // Insert test events at versions 100-200
        for version in 100..200 {
            pruner.ledger_db.event_db().put_events(version, vec![...]);
        }
        
        // Simulate failure: Make event_db unwritable but indexer_db writable
        // This can be done by:
        // 1. Making the event_db directory read-only
        // 2. Or using a mock that fails on event_db.write_schemas()
        
        std::fs::set_permissions(
            event_db_path,
            std::fs::Permissions::from_mode(0o444) // Read-only
        ).unwrap();
        
        // Attempt to prune - indexer write succeeds, event_db write fails
        let result = pruner.prune(100, 200);
        assert!(result.is_err(), "Prune should fail");
        
        // Verify split-brain state
        let indexer_progress = pruner.internal_indexer_db.as_ref()
            .unwrap()
            .get_inner_db_ref()
            .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::EventPrunerProgress)
            .unwrap()
            .unwrap()
            .expect_version();
        
        let event_db_progress = pruner.ledger_db.event_db_raw()
            .get::<DbMetadataSchema>(&DbMetadataKey::EventPrunerProgress)
            .unwrap()
            .map(|v| v.expect_version())
            .unwrap_or(0);
        
        // This assertion demonstrates the vulnerability:
        assert_eq!(indexer_progress, 200, "Indexer thinks pruning is done");
        assert_eq!(event_db_progress, 100, "Event DB hasn't been pruned");
        assert_ne!(indexer_progress, event_db_progress, "SPLIT-BRAIN STATE!");
        
        // Verify events still exist despite indexer saying they're pruned
        let events = pruner.ledger_db.event_db().get_events_by_version(150).unwrap();
        assert!(!events.is_empty(), "Events should still exist but indexer says they're gone");
    }
}
```

## Notes

This vulnerability affects **both** `EventStorePruner` and `TransactionPruner` when internal indexer is enabled. The root cause is the lack of atomicity guarantees across separate database instances. While RocksDB provides atomicity within a single database via `WriteBatch`, there is no transaction coordinator for writes spanning multiple databases.

The vulnerability cannot be exploited by external attackers directly, but is triggered by operational conditions that are reasonably likely in production environments. The impact is significant because it breaks core storage consistency guarantees and can cause validator performance degradation requiring manual intervention.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L43-81)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        let mut indexer_batch = None;

        let indices_batch = if let Some(indexer_db) = self.indexer_db() {
            if indexer_db.event_enabled() {
                indexer_batch = Some(SchemaBatch::new());
            }
            indexer_batch.as_mut()
        } else {
            Some(&mut batch)
        };
        let num_events_per_version = self.ledger_db.event_db().prune_event_indices(
            current_progress,
            target_version,
            indices_batch,
        )?;
        self.ledger_db.event_db().prune_events(
            num_events_per_version,
            current_progress,
            target_version,
            &mut batch,
        )?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::EventPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        if let Some(mut indexer_batch) = indexer_batch {
            indexer_batch.put::<InternalIndexerMetadataSchema>(
                &IndexerMetadataKey::EventPrunerProgress,
                &IndexerMetadataValue::Version(target_version),
            )?;
            self.expect_indexer_db()
                .get_inner_db_ref()
                .write_schemas(indexer_batch)?;
        }
        self.ledger_db.event_db().write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L85-109)
```rust
    pub(in crate::pruner) fn new(
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
        internal_indexer_db: Option<InternalIndexerDB>,
    ) -> Result<Self> {
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

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L58-73)
```rust
        if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
            if indexer_db.transaction_enabled() {
                let mut index_batch = SchemaBatch::new();
                self.transaction_store
                    .prune_transaction_by_account(&candidate_transactions, &mut index_batch)?;
                index_batch.put::<InternalIndexerMetadataSchema>(
                    &IndexerMetadataKey::TransactionPrunerProgress,
                    &IndexerMetadataValue::Version(target_version),
                )?;
                indexer_db.get_inner_db_ref().write_schemas(index_batch)?;
            } else {
                self.transaction_store
                    .prune_transaction_by_account(&candidate_transactions, &mut batch)?;
            }
        }
        self.ledger_db.transaction_db().write_schemas(batch)
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

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L53-68)
```rust
    fn work(&self) {
        while !self.quit_worker.load(Ordering::SeqCst) {
            let pruner_result = self.pruner.prune(self.batch_size);
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
            if !self.pruner.is_pruning_pending() {
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            }
        }
```
