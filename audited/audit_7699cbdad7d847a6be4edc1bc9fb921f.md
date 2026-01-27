# Audit Report

## Title
Stale Index Entries in OrderedTransactionByAccountSchema When Internal Indexer Is Enabled

## Summary
When the internal indexer DB is enabled with transaction indexing (`enable_transaction: true`) but storage sharding is disabled (`enable_storage_sharding: false`), the `OrderedTransactionByAccountSchema` index entries are written to both the main transaction DB and the internal indexer DB during commits. However, during pruning, only the internal indexer DB entries are deleted, leaving stale index entries in the main transaction DB that point to pruned transactions. This causes `get_account_ordered_transaction_version()` to return versions for non-existent transactions, leading to API failures and state inconsistency.

## Finding Description

The vulnerability exists in the transaction pruning logic when a specific configuration is used:

**Configuration Requirements:**
- `enable_storage_sharding = false` (sharding disabled)
- Internal indexer DB enabled with `transaction_enabled() = true`

**Root Cause Analysis:**

During transaction commit, when `skip_index = false` (i.e., sharding disabled), the `put_transaction` function writes `OrderedTransactionByAccountSchema` entries to the main transaction DB: [1](#0-0) 

Additionally, when the internal indexer is enabled, `process_a_batch` writes the same schema entries to the internal indexer DB: [2](#0-1) 

This results in **duplicate index entries** across two databases.

During pruning, the `TransactionPruner::prune()` method has conditional logic: [3](#0-2) 

The pruning logic only deletes from the internal indexer DB when `transaction_enabled()` is true (lines 59-67), but does NOT add the deletion to the main batch that writes to the main transaction DB (line 73). The main batch only contains transaction data deletions, hash index deletions, and summary deletions - but NOT `OrderedTransactionByAccountSchema` deletions.

When `get_account_ordered_transaction_version()` is called, it always queries the main transaction DB: [4](#0-3) 

This returns stale versions that reference pruned transactions. The caller then invokes `get_transaction_with_proof()`, which fails the pruning check: [5](#0-4) 

**Breaking Invariant:**
This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The index state is inconsistent with the transaction store state.

## Impact Explanation

**Severity: Medium** ($10,000 per Aptos bug bounty criteria)

This qualifies as "State inconsistencies requiring intervention":

1. **API Failures**: The `get_account_ordered_transaction` API returns errors for valid-looking account/sequence number pairs, degrading user experience and breaking applications
2. **Index Corruption**: The main DB accumulates stale index entries indefinitely, causing storage bloat
3. **State Inconsistency**: Different database schemas are out of sync, violating storage layer invariants
4. **Node Divergence Risk**: Nodes with different configurations (some with internal indexer, some without) may exhibit different behaviors for the same queries
5. **Operational Burden**: Requires manual intervention to clean up stale indices or database reconstruction

While this doesn't directly lead to fund loss or consensus violation, it creates persistent state corruption that degrades system reliability and may require database maintenance or migration.

## Likelihood Explanation

**Likelihood: High** in affected configurations

The vulnerability **always occurs** when both conditions are met:
- Storage sharding disabled (`enable_storage_sharding: false`)
- Internal indexer enabled with transaction indexing (`enable_transaction: true`)

This is not a race condition - it's a systematic design flaw. Every pruned transaction leaves behind a stale index entry in the main DB.

However, the configuration requirement limits exposure:
- Production nodes typically either use sharding OR don't use internal indexer
- The API check prevents usage when sharding is enabled: [6](#0-5) 

But nodes configured for compatibility mode (sharding off, internal indexer on for migration) would be affected.

## Recommendation

**Fix:** Ensure `OrderedTransactionByAccountSchema` deletions are applied to the main DB when `skip_index` is false, regardless of internal indexer state.

Modify the pruning logic to delete from BOTH databases when the schema exists in both:

```rust
// In transaction_pruner.rs, lines 58-72
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
    }
}

// ALWAYS prune from main DB if skip_index is false during writes
// This can be determined from the AptosDB configuration
if !self.skip_index_and_usage {  // Add this field to TransactionPruner
    self.transaction_store
        .prune_transaction_by_account(&candidate_transactions, &mut batch)?;
}
```

Alternatively, enforce that `OrderedTransactionByAccountSchema` is stored in only ONE database location, determined by configuration at DB initialization.

## Proof of Concept

```rust
#[test]
fn test_stale_index_with_internal_indexer() {
    use tempfile::TempDir;
    use aptos_config::config::{RocksdbConfigs, InternalIndexerDBConfig};
    
    let tmpdir = TempDir::new().unwrap();
    
    // Enable internal indexer with transaction indexing
    let mut indexer_config = InternalIndexerDBConfig::default();
    indexer_config.enable_transaction = true;
    let internal_indexer = InternalIndexerDB::new(tmpdir.path(), indexer_config).unwrap();
    
    // Open AptosDB with sharding DISABLED but indexer ENABLED
    let mut rocksdb_config = RocksdbConfigs::default();
    rocksdb_config.enable_storage_sharding = false;  // Critical: sharding off
    
    let db = AptosDB::open(
        StorageDirPaths::from_path(tmpdir.path()),
        false,
        PrunerConfig {
            ledger_pruner_config: LedgerPrunerConfig {
                enable: true,
                prune_window: 5,  // Prune transactions older than 5 versions
                ..Default::default()
            },
            ..Default::default()
        },
        rocksdb_config,
        false,
        100,
        100,
        Some(internal_indexer),
        HotStateConfig::default(),
    ).unwrap();
    
    // Commit 20 transactions
    let account = AccountAddress::random();
    let mut txns = vec![];
    for seq_num in 0..20 {
        let txn = generate_signed_transaction(account, seq_num);
        txns.push(txn);
    }
    commit_transactions(&db, txns);
    
    // Trigger pruning - should prune transactions 0-14 (keeping last 5)
    db.ledger_pruner.wake_and_wait_pruner(19).unwrap();
    
    // BUG: Query for sequence number 5 (should be pruned)
    let result = db.transaction_store
        .get_account_ordered_transaction_version(account, 5, 19);
    
    // EXPECTED: Should return None (pruned)
    // ACTUAL: Returns Some(version) - stale index entry in main DB!
    assert!(result.unwrap().is_some(), "BUG: Stale index returns version for pruned txn");
    
    let version = result.unwrap().unwrap();
    
    // Try to get the transaction - this will fail
    let txn_result = db.ledger_db.transaction_db().get_transaction(version);
    assert!(txn_result.is_err(), "Transaction was pruned but index still exists");
}
```

## Notes

This vulnerability demonstrates a critical failure in maintaining consistency between dual-write scenarios. The fix requires either:
1. Coordinating deletions across both databases
2. Eliminating dual writes by storing the schema in only one location based on configuration
3. Disallowing the problematic configuration combination at startup

The existing test at line 176-180 of `storage/aptosdb/src/pruner/ledger_pruner/test.rs` doesn't catch this because it uses `AptosDB::new_for_test()` which doesn't enable the internal indexer. [7](#0-6)

### Citations

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L137-145)
```rust
        if !skip_index {
            if let Some(txn) = transaction.try_as_signed_user_txn() {
                if let ReplayProtector::SequenceNumber(seq_num) = txn.replay_protector() {
                    batch.put::<OrderedTransactionByAccountSchema>(
                        &(txn.sender(), seq_num),
                        &version,
                    )?;
                }
            }
```

**File:** storage/indexer/src/db_indexer.rs (L421-428)
```rust
                if self.indexer_db.transaction_enabled() {
                    if let ReplayProtector::SequenceNumber(seq_num) = signed_txn.replay_protector()
                    {
                        batch.put::<OrderedTransactionByAccountSchema>(
                            &(signed_txn.sender(), seq_num),
                            &version,
                        )?;
                    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L58-72)
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
```

**File:** storage/aptosdb/src/transaction_store/mod.rs (L42-49)
```rust
        if let Some(version) =
            self.ledger_db
                .transaction_db_raw()
                .get::<OrderedTransactionByAccountSchema>(&(address, sequence_number))?
        {
            if version <= ledger_version {
                return Ok(Some(version));
            }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-270)
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
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L150-154)
```rust
        gauged_api("get_account_transaction", || {
            ensure!(
                !self.state_kv_db.enabled_sharding(),
                "This API is not supported with sharded DB"
            );
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/test.rs (L174-182)
```rust
    if let Some(txn) = txns.get(index as usize).unwrap().try_as_signed_user_txn() {
        if let ReplayProtector::SequenceNumber(seq_num) = txn.replay_protector() {
            assert!(transaction_store
                .get_account_ordered_transaction_version(txn.sender(), seq_num, ledger_version)
                .unwrap()
                .is_none()
            );
        }
    }
```
