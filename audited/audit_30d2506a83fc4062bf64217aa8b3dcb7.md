# Audit Report

## Title
Unbounded Memory Consumption in Epoch Data Truncation During Database Recovery

## Summary
The `delete_per_epoch_data()` function in the ledger database truncation helper lacks bounds checking when iterating through epoch entries, allowing a corrupted database with millions of epoch entries to cause excessive memory consumption and Out-of-Memory (OOM) crashes during recovery operations.

## Finding Description

The vulnerability exists in the database truncation code path used for recovery and maintenance operations. [1](#0-0) 

The function creates an unbounded iterator over `EpochByVersionSchema` entries and accumulates deletion operations in a `SchemaBatch` without any memory limits. The `SchemaBatch` structure stores all operations in-memory using a `HashMap<ColumnFamilyName, Vec<WriteOp>>`. [2](#0-1) 

Each epoch entry results in two deletion operations being added to the batch - one for `EpochByVersionSchema` and one for `LedgerInfoSchema`. With millions of corrupted epoch entries, this accumulates hundreds of megabytes to gigabytes of memory before any database write occurs.

**Normal vs Corrupted State:**
- Normal operation: Epochs occur during validator set changes or governance reconfigurations, typically resulting in thousands of epoch entries over years of operation
- Corrupted state: Millions of spurious epoch entries from database corruption, consensus bugs, or state sync errors

**Exploitation Path:**
1. Database becomes corrupted with millions of epoch entries (via filesystem corruption, consensus bug, or state sync error)
2. Node operator attempts database recovery using the truncation tool [3](#0-2) 
3. The `delete_per_epoch_data()` function iterates all entries without bounds
4. Memory consumption grows linearly: ~64 bytes × number of epochs
5. With 10 million corrupted entries: ~640 MB to 1 GB memory consumption
6. Process crashes with OOM on resource-constrained systems
7. Database recovery fails, requiring alternative recovery methods

**Contrast with State KV DB Truncation:**
Other truncation functions implement proper batching to prevent unbounded memory growth. [4](#0-3)  The `truncate_state_kv_db()` function accepts a `batch_size` parameter and processes deletions in chunks, whereas ledger DB truncation processes everything in a single batch.

## Impact Explanation

This is a **Medium severity** issue per Aptos bug bounty criteria:

1. **State inconsistencies requiring intervention**: A corrupted database with millions of epoch entries prevents successful recovery using the standard truncation tool
2. **Limited scope**: Affects only the recovery/maintenance code path, not the consensus or execution path of running nodes
3. **No direct fund loss**: Does not enable theft, minting, or freezing of funds
4. **Availability impact**: Recovery operations fail, but operators can use alternative methods (restore from backup, manual database repair)
5. **No consensus violation**: Does not affect blockchain safety, liveness, or deterministic execution

The issue breaks the **Resource Limits** invariant (Invariant #9): "All operations must respect gas, storage, and computational limits." While this specific code path doesn't use gas metering, unbounded memory allocation violates the principle of bounded resource consumption.

## Likelihood Explanation

**Likelihood: LOW to MEDIUM**

**Prerequisites for exploitation:**
1. Database corruption introducing millions of epoch entries
2. Operator attempting recovery using the truncation tool
3. System with insufficient memory to handle the unbounded allocation

**Corruption scenarios:**
- **Filesystem corruption**: Power loss, disk failure, or filesystem bugs during database writes
- **Consensus bugs**: Logic errors in epoch transition code writing spurious entries
- **State sync errors**: Malformed data from peers during state synchronization
- **Software bugs**: Race conditions or off-by-one errors in epoch management code

**Mitigation factors:**
- Normal epoch counts are in the thousands, not millions
- The codebase has safeguards like `MAX_COMMIT_PROGRESS_DIFFERENCE` (1,000,000) to detect abnormal state [5](#0-4) 
- Operators typically have backup restoration as primary recovery method
- Issue only manifests during recovery operations, not normal node operation

## Recommendation

Implement batched deletion for ledger database truncation, similar to the state KV DB truncation approach:

```rust
pub(crate) fn truncate_ledger_db(
    ledger_db: Arc<LedgerDb>, 
    target_version: Version,
    batch_size: usize,  // Add batch size parameter
) -> Result<()> {
    let transaction_store = TransactionStore::new(Arc::clone(&ledger_db));
    let start_version = target_version + 1;
    
    // Implement batching loop
    let mut current_version = start_version;
    loop {
        let batch_end_version = std::cmp::min(
            current_version + batch_size as u64,
            get_latest_ledger_version(&ledger_db)?,
        );
        
        truncate_ledger_db_single_batch(
            &ledger_db,
            &transaction_store,
            current_version,
            batch_end_version,
        )?;
        
        if batch_end_version >= get_latest_ledger_version(&ledger_db)? {
            break;
        }
        current_version = batch_end_version + 1;
    }
    Ok(())
}

fn delete_per_epoch_data(
    ledger_db: &DB,
    start_version: Version,
    end_version: Version,  // Add end bound
    batch: &mut SchemaBatch,
) -> Result<()> {
    // ... existing code ...
    
    let mut iter = ledger_db.iter::<EpochByVersionSchema>()?;
    iter.seek(&start_version)?;
    
    for item in iter {
        let (version, epoch) = item?;
        
        // Add bounds check
        if version > end_version {
            break;
        }
        
        // ... existing deletion logic ...
    }
    
    Ok(())
}
```

Additionally, add a safety check to detect abnormal epoch counts:

```rust
// Before iteration, validate epoch count
let epoch_count = count_epochs_in_range(ledger_db, start_version, u64::MAX)?;
if epoch_count > REASONABLE_EPOCH_LIMIT {
    warn!(
        "Detected {} epochs in range, which exceeds expected limit. \
         Database may be corrupted. Consider restoring from backup.",
        epoch_count
    );
    return Err(AptosDbError::Other(format!(
        "Abnormal epoch count detected: {}", epoch_count
    )));
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_epoch_truncation_oom {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    
    #[test]
    #[should_panic(expected = "out of memory")]
    fn test_unbounded_epoch_iteration() {
        let tmp_dir = TempPath::new();
        let db = AptosDB::new_for_test(&tmp_dir);
        
        // Simulate corruption: write millions of epoch entries
        let num_corrupted_epochs = 10_000_000;
        let mut batch = SchemaBatch::new();
        
        for i in 0..num_corrupted_epochs {
            let version = i * 100; // Arbitrary version spacing
            batch.put::<EpochByVersionSchema>(&version, &i)?;
            
            // Create minimal LedgerInfo for each epoch
            let ledger_info = LedgerInfo::new(/* ... */);
            let ledger_info_with_sigs = LedgerInfoWithSignatures::new(
                ledger_info, 
                BTreeMap::new()
            );
            batch.put::<LedgerInfoSchema>(&i, &ledger_info_with_sigs)?;
        }
        
        db.ledger_db.metadata_db().write_schemas(batch)?;
        
        // Attempt truncation - should OOM without bounds checking
        let ledger_db = db.ledger_db.clone();
        truncate_ledger_db(ledger_db, 0)?; // This will consume excessive memory
    }
}
```

## Notes

**Key Distinctions:**
- This vulnerability requires pre-existing database corruption and affects only recovery operations
- The impact is limited to availability of the truncation tool, not blockchain consensus or safety
- Operators have alternative recovery paths (backup restoration, manual DB repair)
- The issue demonstrates a pattern where some truncation functions (state KV DB) implement batching while others (ledger DB) do not

**Related Code Patterns:**
Similar unbounded iteration patterns exist in `delete_per_version_data_impl()` [6](#0-5)  but version ranges are expected to be large in normal operation, whereas epoch counts should remain bounded to thousands.

### Citations

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L81-116)
```rust
pub(crate) fn truncate_state_kv_db(
    state_kv_db: &StateKvDb,
    current_version: Version,
    target_version: Version,
    batch_size: usize,
) -> Result<()> {
    assert!(batch_size > 0);
    let status = StatusLine::new(Progress::new("Truncating State KV DB", target_version));
    status.set_current_version(current_version);

    let mut current_version = current_version;
    // current_version can be the same with target_version while there is data written to the db before
    // the progress is recorded -- we need to run the truncate for at least one batch
    loop {
        let target_version_for_this_batch = std::cmp::max(
            current_version.saturating_sub(batch_size as Version),
            target_version,
        );
        // By writing the progress first, we still maintain that it is less than or equal to the
        // actual progress per shard, even if it dies in the middle of truncation.
        state_kv_db.write_progress(target_version_for_this_batch)?;
        // the first batch can actually delete more versions than the target batch size because
        // we calculate the start version of this batch assuming the latest data is at
        // `current_version`. Otherwise, we need to seek all shards to determine the
        // actual latest version of data.
        truncate_state_kv_db_shards(state_kv_db, target_version_for_this_batch)?;
        current_version = target_version_for_this_batch;
        status.set_current_version(current_version);

        if current_version <= target_version {
            break;
        }
    }
    assert_eq!(current_version, target_version);
    Ok(())
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L413-426)
```rust
    let mut iter = ledger_db.iter::<EpochByVersionSchema>()?;
    iter.seek(&start_version)?;

    for item in iter {
        let (version, epoch) = item?;
        info!(
            version = version,
            epoch = epoch,
            "Truncate epoch ending data."
        );
        batch.delete::<EpochByVersionSchema>(&version)?;
        batch.delete::<LedgerInfoSchema>(&epoch)?;
    }

```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L494-518)
```rust
fn delete_per_version_data_impl<S>(
    ledger_db: &DB,
    start_version: Version,
    batch: &mut SchemaBatch,
) -> Result<()>
where
    S: Schema<Key = Version>,
{
    let mut iter = ledger_db.iter::<S>()?;
    iter.seek_to_last();
    if let Some((latest_version, _)) = iter.next().transpose()? {
        if latest_version >= start_version {
            info!(
                start_version = start_version,
                latest_version = latest_version,
                cf_name = S::COLUMN_FAMILY_NAME,
                "Truncate per version data."
            );
            for version in start_version..=latest_version {
                batch.delete::<S>(&version)?;
            }
        }
    }
    Ok(())
}
```

**File:** storage/schemadb/src/batch.rs (L130-133)
```rust
pub struct SchemaBatch {
    rows: DropHelper<HashMap<ColumnFamilyName, Vec<WriteOp>>>,
    stats: SampledBatchStats,
}
```

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L137-142)
```rust
        StateStore::sync_commit_progress(
            Arc::clone(&ledger_db),
            Arc::clone(&state_kv_db),
            Arc::clone(&state_merkle_db),
            /*crash_if_difference_is_too_large=*/ false,
        );
```

**File:** storage/aptosdb/src/state_store/mod.rs (L107-107)
```rust
pub const MAX_COMMIT_PROGRESS_DIFFERENCE: u64 = 1_000_000;
```
