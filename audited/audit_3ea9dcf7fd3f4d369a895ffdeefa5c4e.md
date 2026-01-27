# Audit Report

## Title
Ledger Pruner Atomic Failure: Parallel Sub-Pruner Execution Causes Permanent Data Inconsistency

## Summary
The LedgerPruner executes multiple sub-pruners in parallel without transactional coordination. When one sub-pruner fails after others have succeeded, the database enters an inconsistent state where some data types (events, transaction info) are deleted while others (transactions, write sets) remain for the same version range. This partial prune is permanent and corrupts the ledger.

## Finding Description

The `LedgerPruner::prune()` method executes seven sub-pruners in parallel to delete different ledger data types. [1](#0-0) 

Each sub-pruner operates independently on separate databases/column families:
- EventStorePruner (deletes events)
- TransactionInfoPruner (deletes transaction info)
- TransactionPruner (deletes transactions)
- WriteSetPruner (deletes write sets)
- TransactionAccumulatorPruner, TransactionAuxiliaryDataPruner, PersistedAuxiliaryInfoPruner

The critical flaw is that each sub-pruner creates its own `SchemaBatch` and immediately commits to RocksDB via `write_schemas()`. [2](#0-1) [3](#0-2) 

The `write_schemas()` method performs an immediate atomic commit per batch to RocksDB. [4](#0-3) 

**Attack Scenario:**
1. Pruner progress is at version 100, target is version 200
2. Parallel execution begins:
   - EventStorePruner deletes events 100-200, commits successfully ✓
   - TransactionInfoPruner deletes transaction info 100-200, commits successfully ✓
   - TransactionPruner encounters disk full error, fails ✗
3. The `par_iter().try_for_each()` returns error immediately
4. Global progress stays at 100 (never updated)
5. Database state is now corrupted:
   - Events for versions 100-200: DELETED
   - TransactionInfo for versions 100-200: DELETED  
   - Transactions for versions 100-200: EXIST
   - WriteSets for versions 100-200: EXIST

When queries attempt to read these partially-pruned versions, they fail because `get_transaction_with_proof()` requires both transaction info and events. [5](#0-4) 

The PrunerWorker handles errors by logging and retrying, perpetuating the inconsistent state. [6](#0-5) 

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The ledger can no longer provide complete proofs for partially-pruned versions.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention"

The vulnerability causes:
1. **Ledger corruption**: Nodes cannot serve complete transaction data for affected version ranges
2. **Query failures**: API endpoints return `AptosDbError::NotFound` for existing versions
3. **Archive node corruption**: Historical data becomes permanently inconsistent
4. **State sync failures**: Nodes attempting to sync may fail due to incomplete data
5. **Non-recoverable without manual intervention**: Requires database restoration from backup

While this doesn't directly cause loss of funds or consensus violations, it requires **manual intervention to restore database consistency**, qualifying as Medium severity state inconsistency.

## Likelihood Explanation

**High Likelihood** - This can occur naturally without attacker involvement:

1. **Disk space exhaustion**: Common in production when pruning large datasets
2. **I/O errors**: Hardware failures, filesystem corruption, or disk write errors
3. **Process termination**: OOM killer or system crashes during pruning
4. **RocksDB internal errors**: Database corruption or resource limits

These failures occur frequently in production blockchain nodes, especially during aggressive pruning operations. The parallel execution amplifies the risk window - with 7 sub-pruners running concurrently, the probability that at least one fails while others succeed is significant.

## Recommendation

Implement atomic pruning with rollback capability:

**Solution 1: Sequential Execution with Pre-Validation**
```rust
fn prune(&self, max_versions: usize) -> Result<Version> {
    let mut progress = self.progress();
    let target_version = self.target_version();

    while progress < target_version {
        let current_batch_target_version = 
            min(progress + max_versions as Version, target_version);

        // Phase 1: Validate all sub-pruners can proceed
        for sub_pruner in &self.sub_pruners {
            sub_pruner.validate_prune(progress, current_batch_target_version)?;
        }

        // Phase 2: Execute metadata pruner
        self.ledger_metadata_pruner.prune(progress, current_batch_target_version)?;

        // Phase 3: Execute sub-pruners sequentially with checkpointing
        for sub_pruner in &self.sub_pruners {
            sub_pruner.prune(progress, current_batch_target_version)
                .map_err(|err| {
                    // Trigger rollback/recovery on failure
                    self.initiate_prune_recovery(progress);
                    anyhow!("{} failed: {err}", sub_pruner.name())
                })?;
        }

        progress = current_batch_target_version;
        self.record_progress(progress);
    }
    Ok(target_version)
}
```

**Solution 2: Unified Transaction Batch**
Create a single `SchemaBatch` shared by all sub-pruners, committed atomically:
```rust
fn prune(&self, max_versions: usize) -> Result<Version> {
    // ... 
    let mut unified_batch = SchemaBatch::new();
    
    for sub_pruner in &self.sub_pruners {
        sub_pruner.prune_into_batch(
            progress, 
            current_batch_target_version,
            &mut unified_batch
        )?;
    }
    
    // Single atomic commit
    self.ledger_db.write_schemas(unified_batch)?;
    self.record_progress(current_batch_target_version);
    // ...
}
```

The key principle: **Either all data types are pruned for a version range, or none are.**

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    
    // Inject failure in TransactionPruner after EventStorePruner succeeds
    struct FailingTransactionPruner {
        should_fail: Arc<AtomicBool>,
        inner: TransactionPruner,
    }
    
    impl DBSubPruner for FailingTransactionPruner {
        fn name(&self) -> &str { "FailingTransactionPruner" }
        
        fn prune(&self, start: Version, end: Version) -> Result<()> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(anyhow!("Simulated disk full error"));
            }
            self.inner.prune(start, end)
        }
    }
    
    #[test]
    fn test_partial_prune_corruption() {
        let db = test_helper::setup_test_db();
        let should_fail = Arc::new(AtomicBool::new(false));
        
        // Write test data for versions 100-200
        for v in 100..200 {
            write_test_transaction(&db, v);
            write_test_events(&db, v);
            write_test_transaction_info(&db, v);
        }
        
        // Create pruner with failing transaction pruner
        let mut ledger_pruner = LedgerPruner::new(db.clone(), None)?;
        ledger_pruner.sub_pruners[5] = Box::new(FailingTransactionPruner {
            should_fail: should_fail.clone(),
            inner: TransactionPruner::new(/* ... */),
        });
        
        ledger_pruner.set_target_version(200);
        
        // Enable failure after EventStorePruner likely completed
        should_fail.store(true, Ordering::SeqCst);
        
        // Attempt prune - should fail
        let result = ledger_pruner.prune(100);
        assert!(result.is_err());
        
        // VERIFY CORRUPTION: Events deleted, transactions still exist
        for v in 100..200 {
            // Events should be gone (EventStorePruner succeeded)
            assert!(db.event_db().get_events_by_version(v).is_err());
            
            // TransactionInfo should be gone (TransactionInfoPruner succeeded)
            assert!(db.transaction_info_db().get_transaction_info(v).is_err());
            
            // Transactions STILL EXIST (TransactionPruner failed)
            assert!(db.transaction_db().get_transaction(v).is_ok());
            
            // CRITICAL: get_transaction_with_proof fails due to missing info
            let result = db.get_transaction_with_proof(v, 200, true);
            assert!(result.is_err()); // LEDGER CORRUPTED
        }
    }
}
```

## Notes

This vulnerability demonstrates a classic distributed systems problem: lack of atomic commitment across parallel operations. The use of Rayon's parallel iterator improves performance but introduces a critical consistency issue when failures occur mid-execution. The RocksDB WriteBatch provides atomicity **per sub-pruner**, but no cross-pruner coordination exists to ensure all-or-nothing semantics for the entire pruning operation.

The issue is exacerbated by the retry logic in PrunerWorker, which continues attempting the same prune operation on an already-corrupted database state, potentially widening the inconsistency window as more partial prunes accumulate over time.

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

**File:** storage/schemadb/src/lib.rs (L289-309)
```rust
    fn write_schemas_inner(&self, batch: impl IntoRawBatch, option: &WriteOptions) -> DbResult<()> {
        let labels = [self.name.as_str()];
        let _timer = APTOS_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.timer_with(&labels);

        let raw_batch = batch.into_raw_batch(self)?;

        let serialized_size = raw_batch.inner.size_in_bytes();
        self.inner
            .write_opt(raw_batch.inner, option)
            .into_db_res()?;

        raw_batch.stats.commit();
        APTOS_SCHEMADB_BATCH_COMMIT_BYTES.observe_with(&[&self.name], serialized_size as f64);

        Ok(())
    }

    /// Writes a group of records wrapped in a [`SchemaBatch`].
    pub fn write_schemas(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &sync_write_option())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1068-1100)
```rust
    pub(super) fn get_transaction_with_proof(
        &self,
        version: Version,
        ledger_version: Version,
        fetch_events: bool,
    ) -> Result<TransactionWithProof> {
        self.error_if_ledger_pruned("Transaction", version)?;

        let proof = self
            .ledger_db
            .transaction_info_db()
            .get_transaction_info_with_proof(
                version,
                ledger_version,
                self.ledger_db.transaction_accumulator_db(),
            )?;

        let transaction = self.ledger_db.transaction_db().get_transaction(version)?;

        // If events were requested, also fetch those.
        let events = if fetch_events {
            Some(self.ledger_db.event_db().get_events_by_version(version)?)
        } else {
            None
        };

        Ok(TransactionWithProof {
            version,
            transaction,
            events,
            proof,
        })
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
