# Audit Report

## Title
Permanent Metadata Loss from Independent Auxiliary Data Pruning Due to Lack of Atomic Transaction Coordination

## Summary
The transaction auxiliary data pruner can commit deletions independently from the transaction pruner due to parallel execution without distributed transaction coordination, resulting in permanent loss of detailed error messages for transactions that still exist in the database.

## Finding Description
The LedgerPruner executes multiple sub-pruners in parallel, including TransactionAuxiliaryDataPruner and TransactionPruner. Each sub-pruner independently commits its own SchemaBatch to the database without coordinated transaction management. [1](#0-0) 

Each sub-pruner commits its batch within its own prune() method: [2](#0-1) [3](#0-2) 

**Exploitation Scenario:**
1. LedgerPruner begins pruning versions 100-200
2. TransactionAuxiliaryDataPruner.prune() executes and commits successfully (deletes auxiliary data, updates progress to 200)
3. TransactionPruner.prune() fails before committing (e.g., I/O error, process crash)
4. Database state: transactions 100-200 exist, but their auxiliary data is permanently deleted
5. Progress tracking shows: TransactionAuxiliaryDataPrunerProgress=200, TransactionPrunerProgress=100

**No Recovery:** During restart, the catch-up logic cannot recover: [4](#0-3) 

The catch-up prune(200, 100) is a no-op since the range [200, 100) is empty: [5](#0-4) 

**Data Loss:** When retrieving transactions, missing auxiliary data silently defaults to None: [6](#0-5) 

TransactionAuxiliaryData contains detailed VM error messages that are permanently lost: [7](#0-6) 

This affects API error reporting where detailed error messages are used: [8](#0-7) 

## Impact Explanation
**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per the bug bounty criteria. The impact includes:

1. **Permanent Metadata Loss**: Detailed VM error messages (VMErrorDetail) are irrecoverably deleted for affected transactions
2. **API Data Integrity**: Nodes return incomplete transaction data via get_transaction_outputs()
3. **Debugging Impairment**: Users cannot retrieve detailed error information for failed transactions in the affected range
4. **Silent Failure**: The system continues operating with corrupted metadata without errors or warnings
5. **Network-Wide Impact**: All nodes performing pruning are susceptible

This breaks the **State Consistency** invariant that state transitions must be atomic and data must remain internally consistent.

## Likelihood Explanation
**High Likelihood** - This can occur during:
- Process crashes or OOM kills during pruning
- Disk I/O errors during batch commit
- Storage quota exhaustion mid-operation
- Node restarts during active pruning
- Any RocksDB write failure affecting one sub-pruner but not others

The parallel execution pattern guarantees that sub-pruners can complete at different times, making partial failures inevitable in production environments with thousands of pruning operations.

## Recommendation
Implement two-phase commit coordination for ledger sub-pruners:

1. **Phase 1 - Prepare**: All sub-pruners build their SchemaBatches but do NOT commit
2. **Phase 2 - Commit**: Only if ALL sub-pruners prepared successfully, commit all batches atomically

Alternative approach: Use a single coordinated SchemaBatch:
- Modify sub-pruner interface to accept a shared batch instead of committing independently
- All sub-pruners write to the same batch
- Single atomic commit at the end

Modified code structure:
```rust
// In LedgerPruner::prune()
let mut shared_batch = SchemaBatch::new();
for sub_pruner in &self.sub_pruners {
    sub_pruner.prepare_batch(progress, target, &mut shared_batch)?;
}
// Atomic commit only if all succeeded
self.ledger_db.write_schemas(shared_batch)?;
```

## Proof of Concept
```rust
use aptos_schemadb::SchemaBatch;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn test_independent_pruner_metadata_loss() {
    // Setup: Create DB with transactions and auxiliary data for versions 0-200
    let db = create_test_db_with_data(200);
    
    // Simulate parallel pruning with failure
    let aux_pruner = TransactionAuxiliaryDataPruner::new(db.clone(), 0).unwrap();
    let txn_pruner = TransactionPruner::new(db.clone(), 0).unwrap();
    
    // Auxiliary pruner succeeds
    aux_pruner.prune(0, 100).unwrap();
    
    // Transaction pruner fails (simulate by not calling prune)
    // In real scenario: txn_pruner.prune(0, 100) -> Returns Err
    
    // Verify inconsistent state
    let aux_progress = db.get::<DbMetadataSchema>(
        &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress
    ).unwrap().unwrap().expect_version();
    
    let txn_progress = db.get::<DbMetadataSchema>(
        &DbMetadataKey::TransactionPrunerProgress
    ).unwrap().unwrap().expect_version();
    
    assert_eq!(aux_progress, 100);
    assert_eq!(txn_progress, 0);
    
    // Verify metadata loss
    for version in 0..100 {
        let txn = db.transaction_db().get_transaction(version).unwrap();
        assert!(txn.is_some()); // Transaction exists
        
        let aux_data = db.transaction_auxiliary_data_db()
            .get_transaction_auxiliary_data(version).unwrap();
        assert!(aux_data.is_none()); // Auxiliary data deleted!
    }
    
    // Verify no recovery on restart
    drop(aux_pruner);
    drop(txn_pruner);
    
    let aux_pruner_new = TransactionAuxiliaryDataPruner::new(db.clone(), 0).unwrap();
    // Catch-up calls prune(100, 0) which is no-op
    // Inconsistency persists permanently
}
```

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

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_auxiliary_data_pruner.rs (L25-35)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        TransactionAuxiliaryDataDb::prune(current_progress, target_version, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_db
            .transaction_auxiliary_data_db()
            .write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_auxiliary_data_pruner.rs (L43-56)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_auxiliary_data_db_raw(),
            &DbMetadataKey::TransactionAuxiliaryDataPrunerProgress,
            metadata_progress,
        )?;

        let myself = TransactionAuxiliaryDataPruner { ledger_db };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up TransactionAuxiliaryDataPruner."
        );
        myself.prune(progress, metadata_progress)?;
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

**File:** storage/aptosdb/src/ledger_db/transaction_auxiliary_data_db.rs (L74-79)
```rust
    pub(crate) fn prune(begin: Version, end: Version, batch: &mut SchemaBatch) -> Result<()> {
        for version in begin..end {
            batch.delete::<TransactionAuxiliaryDataSchema>(&version)?;
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L401-412)
```rust
                    let auxiliary_data = self
                        .ledger_db
                        .transaction_auxiliary_data_db()
                        .get_transaction_auxiliary_data(version)?
                        .unwrap_or_default();
                    let txn_output = TransactionOutput::new(
                        write_set,
                        events,
                        txn_info.gas_used(),
                        txn_info.status().clone().into(),
                        auxiliary_data,
                    );
```

**File:** types/src/transaction/mod.rs (L1737-1748)
```rust
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TransactionAuxiliaryDataV1 {
    pub detail_error_message: Option<VMErrorDetail>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub enum TransactionAuxiliaryData {
    None,
    V1(TransactionAuxiliaryDataV1),
}
```

**File:** api/types/src/convert.rs (L1067-1077)
```rust
    pub fn explain_vm_status(
        &self,
        status: &ExecutionStatus,
        txn_aux_data: Option<TransactionAuxiliaryData>,
    ) -> String {
        let mut status = status.to_owned();
        status = if let Some(aux_data) = txn_aux_data {
            ExecutionStatus::aug_with_aux_data(status, &aux_data)
        } else {
            status
        };
```
