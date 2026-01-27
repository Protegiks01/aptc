# Audit Report

## Title
Non-Atomic Cross-Database Writes in Transaction Pruner Leading to Temporary State Inconsistency

## Summary
The `prune()` function in `TransactionPruner` performs two separate atomic write operations to two different RocksDB instances (indexer DB and ledger DB). If the first write succeeds but the second fails, partial changes are committed, creating a temporary inconsistency between the databases until retry or restart recovery occurs.

## Finding Description

The security question asks whether the SchemaBatch operations are atomic. Within a **single** SchemaBatch, the answer is yes - RocksDB's WriteBatch guarantees atomicity. [1](#0-0) 

However, the pruning operation involves **two separate databases** with **two separate atomic writes**: [2](#0-1) 

The execution flow is:
1. Lines 41-57: Build `batch` for ledger DB (TransactionSchema, TransactionByHashSchema, TransactionSummariesByAccountSchema, progress metadata)
2. Lines 61-66: Build `index_batch` for indexer DB (OrderedTransactionByAccountSchema, progress metadata)  
3. **Line 67**: Write `index_batch` to indexer DB (separate RocksDB instance)
4. **Line 73**: Write `batch` to ledger DB (separate RocksDB instance)

If line 67 succeeds but line 73 fails (disk full, IO error, process crash), the result is:
- **Indexer DB**: Transactions pruned, progress marker updated to `target_version`
- **Ledger DB**: Transactions NOT pruned, progress marker still at `current_progress` [3](#0-2) 

The indexer DB is a physically separate RocksDB instance, not part of the same atomic transaction as the ledger DB.

## Impact Explanation

**Severity: Medium (bordering on Low)**

This does NOT constitute a Critical or High severity issue because:
- **No consensus violation**: Pruning is a background maintenance operation
- **No fund loss**: Transaction data is not corrupted, only pruning metadata diverges
- **Self-healing**: The retry mechanism handles transient errors [4](#0-3) , and restart recovery re-prunes from the authoritative ledger DB progress marker [5](#0-4) 

However, it qualifies as **Medium severity** under "State inconsistencies requiring intervention" in specific failure scenarios:
- During the inconsistency window, queries using `OrderedTransactionByAccountSchema` return incomplete results while queries using `TransactionSummariesByAccountSchema` succeed
- If the ledger DB write failure is permanent (corruption, permission error), manual intervention is required

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability manifests when:
1. Transient errors occur (disk full, IO timeout) - **Medium likelihood** in production
2. Process crashes between lines 67 and 73 - **Low likelihood** (microsecond window)
3. Permanent ledger DB failure - **Very low likelihood**

The retry mechanism significantly reduces impact duration from prolonged to milliseconds/seconds. The same pattern exists in `EventStorePruner` [6](#0-5) , indicating this is a systemic design pattern.

## Recommendation

Implement one of the following solutions:

**Option 1: Write-Ahead Log (WAL) Pattern**
```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    let mut batch = SchemaBatch::new();
    // ... build batch ...
    
    if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
        if indexer_db.transaction_enabled() {
            let mut index_batch = SchemaBatch::new();
            // ... build index_batch ...
            
            // Write ledger DB FIRST (authoritative source)
            self.ledger_db.transaction_db().write_schemas(batch)?;
            
            // Then write indexer DB (can be rebuilt from ledger if fails)
            indexer_db.get_inner_db_ref().write_schemas(index_batch)?;
            return Ok(());
        }
    }
    self.ledger_db.transaction_db().write_schemas(batch)
}
```

**Option 2: Progress Reconciliation on Startup**
Add validation that checks both DBs have consistent progress markers on initialization and re-prunes if divergence detected.

**Option 3: Single Database Design**
Store all indices in the ledger DB to eliminate cross-database atomicity concerns (requires architectural change).

## Proof of Concept

The vulnerability can be demonstrated by:

1. **Setup**: Enable internal indexer with transaction indexing
2. **Inject Failure**: Mock the ledger DB write to fail after indexer DB write succeeds
3. **Verify Inconsistency**: Query both databases and observe divergent states

```rust
// Simplified PoC structure (would need test harness):
#[test]
fn test_partial_prune_commit() {
    // Setup pruner with indexer enabled
    let pruner = setup_transaction_pruner_with_indexer();
    
    // Mock ledger DB to fail write
    inject_write_failure_after_indexer_commit();
    
    // Attempt prune
    let result = pruner.prune(0, 100);
    assert!(result.is_err());
    
    // Verify indexer DB shows progress = 100
    let indexer_progress = read_indexer_progress();
    assert_eq!(indexer_progress, 100);
    
    // Verify ledger DB shows progress = 0 (old value)
    let ledger_progress = read_ledger_progress();
    assert_eq!(ledger_progress, 0);
    
    // Demonstrate query inconsistency
    let indexer_data = query_via_ordered_transaction_by_account();
    let ledger_data = query_via_transaction_schema();
    assert_ne!(indexer_data.len(), ledger_data.len());
}
```

## Notes

While this is a legitimate atomicity concern in the codebase, its practical security impact is limited due to:
- Automatic retry and recovery mechanisms that restore consistency
- Short inconsistency windows in normal operation  
- No path to financial exploitation or consensus manipulation

The issue is more of a robustness concern than an actively exploitable security vulnerability. However, it violates the atomicity principle and could cause operational issues in edge cases requiring manual intervention.

### Citations

**File:** storage/schemadb/src/batch.rs (L127-128)
```rust
/// `SchemaBatch` holds a collection of updates that can be applied to a DB atomically. The updates
/// will be applied in the order in which they are added to the `SchemaBatch`.
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

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L84-88)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_db_raw(),
            &DbMetadataKey::TransactionPrunerProgress,
            metadata_progress,
        )?;
```

**File:** storage/indexer/src/db_indexer.rs (L80-88)
```rust
pub struct InternalIndexerDB {
    pub db: Arc<DB>,
    config: InternalIndexerDBConfig,
}

impl InternalIndexerDB {
    pub fn new(db: Arc<DB>, config: InternalIndexerDBConfig) -> Self {
        Self { db, config }
    }
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L53-69)
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
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L71-81)
```rust
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
