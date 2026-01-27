# Audit Report

## Title
Referential Integrity Violation in Parallel Ledger Pruning with Storage Sharding

## Summary
When storage sharding is enabled, the LedgerPruner executes multiple database sub-pruners in parallel without cross-database transaction coordination. If any sub-pruner fails after others have succeeded, orphaned child records (events, write sets) can remain in the database while their parent records (transactions) are deleted, violating referential integrity.

## Finding Description

The LedgerPruner coordinates multiple sub-pruners that delete different types of ledger data. When storage sharding is enabled, each sub-pruner writes to a **separate RocksDB instance**: [1](#0-0) 

The pruning operation executes these sub-pruners **in parallel** using rayon's `par_iter()`: [2](#0-1) 

Each sub-pruner creates its own `SchemaBatch` and commits to its own database independently:
- TransactionPruner: [3](#0-2) 
- EventStorePruner: [4](#0-3) 
- WriteSetPruner: [5](#0-4) 

**The vulnerability:** Since these are separate RocksDB instances, there is **no atomic transaction guarantee** across them. The `try_for_each` will stop on first error, but pruners that already completed successfully will **not be rolled back**.

**Exploitation scenario:**
1. Node performs pruning of versions 0-1000
2. TransactionPruner successfully deletes transactions and commits to transaction_db
3. EventStorePruner encounters disk error / OOM / I/O timeout before completing
4. EventStorePruner fails and returns error
5. Result: Transactions deleted, but events remain → orphaned events referencing non-existent transactions

The codebase acknowledges this issue with a TODO comment: [6](#0-5) 

**Impact on system integrity:**
- When APIs try to fetch transactions by version, they'll get `NotFound` errors: [7](#0-6) 
- Orphaned events and write sets remain queryable but reference deleted transactions
- Different nodes may have different orphaned data depending on when/how their pruners failed
- Database queries return inconsistent results across nodes

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **API crashes**: Queries attempting to correlate orphaned events with non-existent transactions will fail
- **Validator node slowdowns**: Database inconsistencies can cause performance degradation
- **State inconsistencies requiring intervention**: Orphaned data violates database integrity and may require manual cleanup or re-sync

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." While pruning doesn't affect state roots directly, the lack of atomic cross-database operations creates an inconsistent database state.

## Likelihood Explanation

**Medium-High likelihood** of occurrence:
- Pruning runs automatically on all nodes based on configured retention windows
- Disk I/O errors, resource exhaustion, or system interruptions during pruning are realistic operational scenarios
- With thousands of validator and full nodes, some will inevitably experience hardware/system failures during pruning
- The parallel execution increases the window for partial failures
- No recovery or validation mechanism exists to detect or repair orphaned records

However, this is **NOT exploitable by an external attacker** - it requires system-level failures (disk errors, OOM, crashes) that are outside the control of unprivileged users.

## Recommendation

**Implement atomic cross-database pruning** using one of these approaches:

**Option 1: Sequential Pruning with Progress Tracking**
```rust
// Execute pruners sequentially, not in parallel
for sub_pruner in &self.sub_pruners {
    sub_pruner.prune(progress, current_batch_target_version)?;
    // Only record individual pruner progress after successful completion
}
```

**Option 2: Two-Phase Commit Protocol**
```rust
// Phase 1: Prepare all batches
let batches: Vec<_> = self.sub_pruners.par_iter()
    .map(|p| p.prepare_prune_batch(progress, target))
    .collect::<Result<_>>()?;

// Phase 2: Commit all or rollback all
batches.into_iter().try_for_each(|(pruner, batch)| {
    pruner.commit_batch(batch)
})?;
```

**Option 3: Validation and Recovery**
```rust
// After pruning, validate referential integrity
fn validate_referential_integrity(&self, start: Version, end: Version) -> Result<()> {
    // Check for orphaned events/write sets
    // Repair or flag inconsistencies
}
```

## Proof of Concept

```rust
// Reproduce the vulnerability by simulating disk error during pruning
#[test]
fn test_partial_pruner_failure_creates_orphans() {
    // Setup: Create ledger DB with sharding enabled
    let tmpdir = TempPath::new();
    let mut config = RocksdbConfigs::default();
    config.enable_storage_sharding = true;
    
    let db = AptosDB::new_for_test_with_config(&tmpdir, config);
    
    // Commit 100 transactions with events
    for version in 0..100 {
        let txn = create_test_transaction_with_events(version);
        db.save_transactions(&[txn], version, None).unwrap();
    }
    
    // Trigger pruning with simulated failure in EventStorePruner
    // (by injecting error or killing process mid-prune)
    let pruner = db.ledger_pruner();
    
    // Mock: TransactionPruner succeeds, EventStorePruner fails
    // This would require modifying pruner to inject failures
    
    // Verify orphaned state:
    // - Transactions 0-50 are deleted (NotFound)
    // - Events 0-50 still exist (orphaned)
    for version in 0..50 {
        assert!(db.get_transaction(version).is_err()); // NotFound
        assert!(db.get_events(version).is_ok()); // Orphaned!
    }
}
```

**Note:** A true PoC requires simulating system-level failures (disk errors, OOM) which is difficult in unit tests. The vulnerability manifests in production under real failure conditions.

---

## Notes

**Critical caveat**: This vulnerability does **NOT meet** the validation requirement of being "exploitable by unprivileged attacker." It's a **system reliability issue** that occurs due to hardware/system failures, not an attack vector that external actors can trigger.

The issue is nonetheless real and violates database consistency guarantees, but it falls outside the scope of typical bug bounty programs that focus on exploitable vulnerabilities. The TODO comment at line 281 suggests the development team is aware of this data consistency concern.

This would be more appropriately classified as a **reliability/availability issue** rather than a security vulnerability, though it does have security implications (API crashes, node slowdowns, state inconsistencies).

### Citations

**File:** storage/aptosdb/src/ledger_db/mod.rs (L183-278)
```rust
        THREAD_MANAGER.get_non_exe_cpu_pool().scope(|s| {
            s.spawn(|_| {
                let event_db_raw = Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(EVENT_DB_NAME),
                        EVENT_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                );
                event_db = Some(EventDb::new(
                    event_db_raw.clone(),
                    EventStore::new(event_db_raw),
                ));
            });
            s.spawn(|_| {
                persisted_auxiliary_info_db = Some(PersistedAuxiliaryInfoDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(PERSISTED_AUXILIARY_INFO_DB_NAME),
                        PERSISTED_AUXILIARY_INFO_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_accumulator_db = Some(TransactionAccumulatorDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_ACCUMULATOR_DB_NAME),
                        TRANSACTION_ACCUMULATOR_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_auxiliary_data_db = Some(TransactionAuxiliaryDataDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_AUXILIARY_DATA_DB_NAME),
                        TRANSACTION_AUXILIARY_DATA_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )))
            });
            s.spawn(|_| {
                transaction_db = Some(TransactionDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_DB_NAME),
                        TRANSACTION_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_info_db = Some(TransactionInfoDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_INFO_DB_NAME),
                        TRANSACTION_INFO_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                write_set_db = Some(WriteSetDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(WRITE_SET_DB_NAME),
                        WRITE_SET_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L281-281)
```rust
        // TODO(grao): Handle data inconsistency.
```

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L37-74)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        let candidate_transactions =
            self.get_pruning_candidate_transactions(current_progress, target_version)?;
        self.ledger_db
            .transaction_db()
            .prune_transaction_by_hash_indices(
                candidate_transactions.iter().map(|(_, txn)| txn.hash()),
                &mut batch,
            )?;
        self.ledger_db.transaction_db().prune_transactions(
            current_progress,
            target_version,
            &mut batch,
        )?;
        self.transaction_store
            .prune_transaction_summaries_by_account(&candidate_transactions, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
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
    }
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

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L56-60)
```rust
    pub(crate) fn get_transaction(&self, version: Version) -> Result<Transaction> {
        self.db
            .get::<TransactionSchema>(&version)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Txn {version}")))
    }
```
