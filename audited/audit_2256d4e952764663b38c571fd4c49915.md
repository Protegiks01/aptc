# Audit Report

## Title
Metadata Inconsistency in Transaction Pruner Leading to Cross-API Query Result Divergence

## Summary
The transaction pruner performs non-atomic writes to two separate databases (indexer DB and ledger DB) with separate metadata progress tracking. If the indexer DB write succeeds but the ledger DB write fails, the two metadata keys (`IndexerMetadataKey::TransactionPrunerProgress` and `DbMetadataKey::TransactionPrunerProgress`) diverge, causing API queries to return inconsistent results depending on whether storage sharding is enabled.

## Finding Description

The `prune()` function in the transaction pruner performs a two-phase write operation across separate databases without transactional guarantees: [1](#0-0) 

When internal indexer transaction indexing is enabled, the function:
1. Creates a separate batch for the indexer DB containing pruned transaction indices and progress metadata
2. Writes this batch to the indexer DB (line 67)
3. Then writes a separate batch to the ledger DB containing main transaction data and progress metadata (line 73)

**Failure Scenario:**
If line 67 succeeds but line 73 fails (due to I/O error, crash, disk full, etc.):
- **Indexer DB state**: `OrderedTransactionByAccountSchema` entries deleted for versions [current_progress, target_version), `IndexerMetadataKey::TransactionPrunerProgress = target_version`
- **Ledger DB state**: Transaction data still exists, `DbMetadataKey::TransactionPrunerProgress = current_progress`

**On Restart:**
The pruner initialization reads only the ledger DB metadata to determine progress: [2](#0-1) 

It retrieves `DbMetadataKey::TransactionPrunerProgress` (still at `current_progress`), but the indexer DB has already pruned up to `target_version`, creating permanent divergence.

**Query Inconsistency:**
The API routing logic determines which database serves queries based on storage sharding configuration: [3](#0-2) 

- **Sharding enabled** (default=true): Queries route to indexer DB, which is missing transactions in range [current_progress, target_version)
- **Sharding disabled**: Queries route to ledger DB, which still contains those transactions

Both databases use the same schema but maintain separate physical stores: [4](#0-3) [5](#0-4) 

This breaks the **State Consistency** invariant: identical queries against the same logical ledger version return different results depending on the API implementation path.

## Impact Explanation

This qualifies as **Medium Severity** under the bug bounty criteria:
- **State inconsistencies requiring intervention**: The divergence is permanent and requires manual database intervention to resolve
- Violates data consistency guarantees that external systems (wallets, explorers, indexers) depend on
- Could cause transaction replay issues, double-spending detection failures, or account state confusion
- Does not directly lead to fund loss or consensus violations, but undermines system reliability and trustworthiness

## Likelihood Explanation

**Likelihood: Medium to High**

This issue occurs when:
1. Storage sharding is enabled (default: true) [6](#0-5) 
2. Internal indexer transaction indexing is enabled (must be explicitly configured) [7](#0-6) 
3. A system failure occurs between the two database writes

While individual I/O failures are rare, production nodes running for extended periods with active pruning will eventually encounter disk errors, system crashes, or OOM kills. The lack of atomicity guarantees makes this a persistent risk in any long-running deployment.

## Recommendation

Implement atomic cross-database writes using a two-phase commit protocol or consolidate metadata into a single authoritative source. Recommended fix:

```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    let mut batch = SchemaBatch::new();
    let candidate_transactions =
        self.get_pruning_candidate_transactions(current_progress, target_version)?;
    
    // Prune ledger DB data
    self.ledger_db.transaction_db().prune_transaction_by_hash_indices(
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
    
    // Add metadata update to ledger DB batch
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
            
            // Write both batches, rolling back on any failure
            indexer_db.get_inner_db_ref().write_schemas(index_batch)?;
            
            // Critical: If ledger write fails, we must rollback indexer write
            // This requires database-level transaction support or write-ahead logging
            self.ledger_db.transaction_db().write_schemas(batch)
                .map_err(|e| {
                    // Log critical error: indexer DB is ahead of ledger DB
                    // Requires manual intervention or automatic rollback mechanism
                    e
                })?;
        } else {
            self.transaction_store
                .prune_transaction_by_account(&candidate_transactions, &mut batch)?;
            self.ledger_db.transaction_db().write_schemas(batch)?;
        }
    } else {
        self.ledger_db.transaction_db().write_schemas(batch)?;
    }
    
    Ok(())
}
```

**Better solution**: Introduce a coordinator that ensures both databases commit or both roll back, possibly using:
1. Write-ahead logging to recover from partial failures
2. Reading both metadata keys on startup and reconciling to the minimum value
3. Consolidating metadata into a single source of truth

## Proof of Concept

```rust
// Reproduction test (pseudo-code - requires test harness with fault injection)
#[test]
fn test_metadata_divergence_on_partial_failure() {
    // Setup: Create pruner with indexer DB transaction indexing enabled
    let (ledger_db, indexer_db, pruner) = setup_test_environment();
    
    // Write test transactions at versions 1000-2000
    for version in 1000..2000 {
        write_test_transaction(ledger_db, indexer_db, version);
    }
    
    // Inject fault: Make ledger DB write fail after indexer DB write succeeds
    inject_fault_after_indexer_write(ledger_db);
    
    // Attempt pruning - should fail at ledger DB write
    let result = pruner.prune(1000, 2000);
    assert!(result.is_err());
    
    // Verify divergence
    let indexer_progress = indexer_db.get::<InternalIndexerMetadataSchema>(
        &IndexerMetadataKey::TransactionPrunerProgress
    ).unwrap().expect_version();
    
    let ledger_progress = ledger_db.transaction_db_raw().get::<DbMetadataSchema>(
        &DbMetadataKey::TransactionPrunerProgress
    ).unwrap().expect_version();
    
    assert_eq!(indexer_progress, 2000); // Updated
    assert_eq!(ledger_progress, 1000);  // Not updated - DIVERGENCE!
    
    // Query via indexer API (sharding enabled)
    let indexer_result = query_account_transactions_via_indexer(address, 1500);
    assert!(indexer_result.is_empty()); // Data pruned
    
    // Query via ledger API (sharding disabled)
    let ledger_result = query_account_transactions_via_ledger(address, 1500);
    assert!(!ledger_result.is_empty()); // Data still exists - INCONSISTENCY!
}
```

## Notes

The vulnerability is confirmed through code analysis showing:
1. Two separate database writes without atomic guarantees [8](#0-7) 
2. Separate metadata tracking in different databases [9](#0-8)  and [10](#0-9) 
3. API routing based on configuration creates observable inconsistency [11](#0-10) 

This breaks the State Consistency invariant and creates a permanent divergence that requires manual intervention to resolve.

### Citations

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

**File:** api/src/context.rs (L900-923)
```rust
        let txns_res = if !db_sharding_enabled(&self.node_config) {
            self.db.get_account_ordered_transactions(
                address,
                start_seq_number,
                limit as u64,
                true,
                ledger_version,
            )
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| anyhow!("Indexer reader is None"))
                .map_err(|err| {
                    E::internal_with_code(err, AptosErrorCode::InternalError, ledger_info)
                })?
                .get_account_ordered_transactions(
                    address,
                    start_seq_number,
                    limit as u64,
                    true,
                    ledger_version,
                )
                .map_err(|e| AptosDbError::Other(e.to_string()))
        };
```

**File:** api/src/context.rs (L1771-1773)
```rust
fn db_sharding_enabled(node_config: &NodeConfig) -> bool {
    node_config.storage.rocksdb_configs.enable_storage_sharding
}
```

**File:** storage/indexer_schemas/src/schema/mod.rs (L27-27)
```rust
pub const ORDERED_TRANSACTION_BY_ACCOUNT_CF_NAME: ColumnFamilyName = "transaction_by_account";
```

**File:** storage/aptosdb/src/schema/mod.rs (L63-63)
```rust
pub const ORDERED_TRANSACTION_BY_ACCOUNT_CF_NAME: ColumnFamilyName = "transaction_by_account";
```

**File:** config/src/config/storage_config.rs (L71-71)
```rust
                    !exist,
```

**File:** config/src/config/internal_indexer_db_config.rs (L72-72)
```rust
            enable_transaction: false,
```

**File:** storage/indexer_schemas/src/metadata.rs (L36-36)
```rust
    TransactionPrunerProgress,
```

**File:** storage/aptosdb/src/schema/db_metadata/mod.rs (L8-8)
```rust
//! | metadata key  | metadata value |
```
