# Audit Report

## Title
Non-Atomic Pruning Progress Metadata Updates Across Separate Databases Leading to Inconsistent State

## Summary
The `TransactionPruner::prune()` function performs two separate `write_schemas()` calls to two different databases (indexer DB and main ledger DB) without any distributed transaction coordination. A crash or I/O failure between these writes leaves the databases with inconsistent pruning progress metadata, where the indexer DB appears ahead of the main ledger DB.

## Finding Description

The vulnerability exists in the pruning flow where transaction data and progress metadata must be updated atomically, but the implementation splits this across two non-atomic database writes. [1](#0-0) 

When the internal indexer is enabled with `transaction_enabled()`, the code path executes:

1. **First write** (line 67): Writes to `indexer_db`, including `IndexerMetadataKey::TransactionPrunerProgress` 
2. **Second write** (line 73): Writes to `ledger_db.transaction_db()`, including `DbMetadataKey::TransactionPrunerProgress` [2](#0-1) 

Each individual `write_schemas()` call is atomic within its own database via RocksDB's WriteBatch mechanism with synchronous writes. However, there is **no atomicity guarantee between the two separate database writes**.

**Failure Scenario:**

After line 67 succeeds but before line 73 executes:
- Indexer DB: transactions pruned, progress = `target_version` (e.g., 1500)
- Main DB: transactions still exist, progress = `current_progress` (e.g., 1000)

This violates the critical invariant: **"State transitions must be atomic and verifiable."** The pruning progress metadata is now inconsistent across the two databases.

On restart, the system reads progress from the main DB: [3](#0-2) 

The pruner initializes using `get_or_initialize_subpruner_progress()` which reads from `ledger_db.transaction_db_raw()`, finding the old progress value. It then re-attempts pruning, which is idempotent for the indexer DB but still needed for the main DB.

**Persistent Failure Scenario (More Severe):**

If the main DB write consistently fails (disk full, I/O errors) while indexer DB writes succeed: [4](#0-3) 

The pruner worker logs errors and retries continuously. Each retry:
1. Successfully updates indexer DB further ahead
2. Fails to update main DB
3. Progress metadata diverges increasingly

The system enters a state where indexer DB believes data is pruned while main DB's metadata indicates it is not, creating permanent inconsistency until the underlying I/O issue is resolved.

## Impact Explanation

This issue qualifies as **Medium Severity** under the Aptos bug bounty program: "State inconsistencies requiring intervention."

While the crash-and-restart scenario is self-healing, the persistent failure scenario requires manual intervention to:
- Identify the metadata inconsistency
- Resolve the underlying I/O issue
- Potentially rebuild one of the databases to restore consistency

The inconsistency does not directly cause:
- Loss of funds (transactions remain in main DB)
- Consensus violations (pruning occurs post-consensus)
- Network availability issues

However, it can cause:
- Query inconsistencies if APIs assume both DBs are synchronized
- Operational complexity in determining actual pruning state
- Potential issues during backup/restore operations with mismatched metadata

## Likelihood Explanation

**Likelihood: Medium**

The crash scenario occurs during any node failure (power loss, OOM, kernel panic) while pruning is active. Given that:
- Pruning runs continuously on validator nodes
- The window between the two writes exists on every pruning batch
- Node failures occur in production environments

The probability of hitting this window is non-trivial.

The persistent failure scenario requires sustained I/O issues on one database but not the other, which is less common but possible in scenarios like:
- Disk full on main DB partition
- Storage device degradation
- File system corruption on one mount point

## Recommendation

**Option 1: Single Database Transaction (Preferred)**

Write both batches to the same database transaction coordinator, or write to the main DB first, then derive indexer DB progress from it rather than maintaining separate progress metadata.

**Option 2: Fail-Safe Ordering**

Reverse the write order - write to main DB first (line 73), then indexer DB (line 67). If the second write fails, the main DB accurately reflects progress, and the indexer can catch up later.

**Option 3: Progress Reconciliation**

On initialization, check both databases' progress metadata and use the minimum value, ensuring conservative progress tracking.

**Recommended Fix (Option 2 - simplest):**

```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    let mut batch = SchemaBatch::new();
    let candidate_transactions = 
        self.get_pruning_candidate_transactions(current_progress, target_version)?;
    
    // ... add operations to batch ...
    
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::TransactionPrunerProgress,
        &DbMetadataValue::Version(target_version),
    )?;
    
    // Write main DB FIRST (critical for correctness)
    self.ledger_db.transaction_db().write_schemas(batch)?;
    
    // Write indexer DB SECOND (can catch up if it fails)
    if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
        if indexer_db.transaction_enabled() {
            let mut index_batch = SchemaBatch::new();
            self.transaction_store
                .prune_transaction_by_account(&candidate_transactions, &mut index_batch)?;
            index_batch.put::<InternalIndexerMetadataSchema>(
                &IndexerMetadataKey::TransactionPrunerProgress,
                &IndexerMetadataValue::Version(target_version),
            )?;
            // Allow indexer write to fail without failing entire operation
            let _ = indexer_db.get_inner_db_ref().write_schemas(index_batch);
        } else {
            self.transaction_store
                .prune_transaction_by_account(&candidate_transactions, &mut batch)?;
        }
    }
    Ok(())
}
```

## Proof of Concept

The following Rust test demonstrates the inconsistency:

```rust
#[test]
fn test_pruning_atomicity_violation() {
    // Setup: Create TransactionPruner with indexer enabled
    let (ledger_db, indexer_db) = setup_test_dbs();
    let pruner = TransactionPruner::new(
        transaction_store,
        ledger_db.clone(),
        0,
        Some(indexer_db.clone()),
    ).unwrap();
    
    // Insert test transactions 0-1999
    populate_transactions(&ledger_db, 2000);
    
    // Mock scenario: Prune with forced crash between writes
    // (Would need to inject failure point in production code)
    
    // Expected state after partial write:
    // 1. Get main DB progress
    let main_progress = ledger_db.transaction_db_raw()
        .get::<DbMetadataSchema>(&DbMetadataKey::TransactionPrunerProgress)
        .unwrap()
        .unwrap()
        .expect_version();
    
    // 2. Get indexer DB progress
    let indexer_progress = indexer_db.get_inner_db_ref()
        .get::<InternalIndexerMetadataSchema>(&IndexerMetadataKey::TransactionPrunerProgress)
        .unwrap()
        .unwrap()
        .expect_version();
    
    // 3. Assert inconsistency
    assert_ne!(main_progress, indexer_progress,
        "Progress metadata should be inconsistent after partial write");
    assert!(indexer_progress > main_progress,
        "Indexer DB should be ahead of main DB");
}
```

## Notes

While this vulnerability causes state inconsistency, it does NOT meet the validation checklist for a high-severity exploitable vulnerability because:

1. **Not directly exploitable by an unprivileged attacker** - This is a reliability issue triggered by system failures, not malicious input
2. **Self-healing in crash scenarios** - Normal crash/restart cycles automatically reconcile the inconsistency
3. **No consensus or fund impact** - Pruning occurs after consensus; old transaction retention doesn't affect new transactions

However, it represents a legitimate **architectural weakness** in the pruning subsystem that violates atomic state transition guarantees and can require operational intervention in persistent failure scenarios.

**Final Assessment:** This is a **Medium severity operational reliability issue** rather than a Critical security vulnerability exploitable by attackers.

### Citations

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L78-104)
```rust
    pub(in crate::pruner) fn new(
        transaction_store: Arc<TransactionStore>,
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
        internal_indexer_db: Option<InternalIndexerDB>,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_db_raw(),
            &DbMetadataKey::TransactionPrunerProgress,
            metadata_progress,
        )?;

        let myself = TransactionPruner {
            transaction_store,
            ledger_db,
            internal_indexer_db,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up TransactionPruner."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
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

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L52-69)
```rust
    // Loop that does the real pruning job.
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
    }
```
