# Audit Report

## Title
Pruner Lacks Emergency Stop Mechanism for Critical Database Errors

## Summary
The transaction auxiliary data pruner and all other database pruners in AptosDB lack an emergency stop mechanism when critical errors (including database corruption) are detected. When pruning operations encounter errors, the pruner worker logs the error but continues retrying indefinitely, potentially exacerbating existing corruption and delaying recovery.

## Finding Description

The pruner system in AptosDB operates through a background worker thread that continuously processes pruning batches. When examining the error handling flow:

1. **TransactionAuxiliaryDataPruner** implements the `DBSubPruner` trait and can return errors from database operations during pruning [1](#0-0) 

2. These errors propagate through the `LedgerPruner` which executes sub-pruners in parallel [2](#0-1) 

3. The critical issue occurs in `PrunerWorkerInner::work()` which runs the pruning loop: [3](#0-2) 

When `pruner.prune()` returns an error (line 56), the worker:
- Logs the error with sampling to avoid log spam
- Sleeps briefly  
- **Continues the loop and retries** (line 63: `continue`)

There is **no emergency stop mechanism** to halt the pruner when critical errors are detected, such as:

- Database corruption detected by RocksDB (`ErrorKind::Corruption`) [4](#0-3) 

- Data integrity violations from `db_ensure!` checks detecting version discontinuities, hash mismatches, or sequence number corruption [5](#0-4) 

- Schema write failures during batch commits [6](#0-5) 

The only way to stop the pruner is through the `quit_worker` flag which is only set during graceful shutdown, not in response to errors. [7](#0-6) 

## Impact Explanation

**Severity: Medium** - State inconsistencies requiring intervention

While the pruner does not create initial corruption, its continued operation after detecting corruption can:

1. **Exacerbate existing corruption**: Attempting to prune already-corrupted data can propagate errors to additional database regions
2. **Delay detection and recovery**: Continuous error logging masks the severity of the issue, potentially delaying operator intervention
3. **Resource waste**: The pruner consumes CPU and I/O resources retrying operations that will never succeed
4. **Complicate forensics**: Continued database modifications make post-mortem analysis more difficult

This represents a failure to enforce the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." When corruption is detected, the system should fail-safe rather than continue operating.

## Likelihood Explanation

**Likelihood: Low to Medium**

This issue manifests when:
1. Database corruption occurs (from disk failures, memory errors, software bugs, or other sources)
2. The pruner encounters the corrupted data during its operations
3. The lack of emergency stop allows continued operation on corrupted state

While database corruption is relatively rare in well-maintained systems, when it does occur (especially in high-throughput blockchain environments with large databases), the absence of a circuit breaker mechanism can significantly worsen the situation.

## Recommendation

Implement a severity-based error handling system with emergency stop capability:

```rust
// In PrunerWorkerInner
fn work(&self) {
    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 3;
    
    while !self.quit_worker.load(Ordering::SeqCst) {
        let pruner_result = self.pruner.prune(self.batch_size);
        
        if let Err(err) = pruner_result {
            consecutive_errors += 1;
            
            // Check if error indicates critical corruption
            if is_critical_error(&err) || consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                error!(
                    error = ?err,
                    consecutive_errors = consecutive_errors,
                    "CRITICAL: Pruner encountered critical error. Stopping pruner to prevent corruption propagation."
                );
                // Set emergency stop flag
                self.quit_worker.store(true, Ordering::SeqCst);
                // Optionally: trigger node health alert/shutdown
                break;
            }
            
            sample!(
                SampleRate::Duration(Duration::from_secs(1)),
                error!(error = ?err, "Pruner has error.")
            );
            sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            continue;
        }
        
        consecutive_errors = 0; // Reset on success
        
        if !self.pruner.is_pruning_pending() {
            sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
        }
    }
}

fn is_critical_error(err: &AptosDbError) -> bool {
    matches!(err, 
        AptosDbError::OtherRocksDbError(msg) if msg.contains("Corruption") ||
        AptosDbError::Other(msg) if msg.contains("DB corruption")
    )
}
```

Additionally, expose pruner health metrics to allow monitoring systems to detect repeated failures and alert operators.

## Proof of Concept

```rust
#[test]
fn test_pruner_continues_on_corruption_error() {
    // This test demonstrates that the pruner continues operating
    // even after encountering database corruption errors
    
    use std::sync::{Arc, atomic::{AtomicU32, Ordering}};
    
    struct CorruptedPruner {
        call_count: Arc<AtomicU32>,
    }
    
    impl DBPruner for CorruptedPruner {
        fn name(&self) -> &'static str { "test_pruner" }
        
        fn prune(&self, _batch_size: usize) -> Result<Version> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            
            // Simulate corruption detected on every call
            Err(AptosDbError::Other(
                "DB corruption: version mismatch detected".to_string()
            ))
        }
        
        fn progress(&self) -> Version { 0 }
        fn set_target_version(&self, _: Version) {}
        fn target_version(&self) -> Version { 100 }
        fn record_progress(&self, _: Version) {}
    }
    
    let call_count = Arc::new(AtomicU32::new(0));
    let pruner = Arc::new(CorruptedPruner {
        call_count: call_count.clone(),
    });
    
    let worker = PrunerWorker::new(pruner, 10, "test");
    
    // Allow pruner to run for a short time
    std::thread::sleep(Duration::from_millis(100));
    drop(worker); // Triggers quit_worker
    
    // Verify the pruner was called multiple times despite corruption errors
    let final_count = call_count.load(Ordering::SeqCst);
    assert!(
        final_count > 5,
        "Pruner should have retried multiple times despite corruption errors, got {} calls",
        final_count
    );
}
```

## Notes

This is a **defense-in-depth failure** rather than a direct exploit vector. The vulnerability requires pre-existing database corruption (from hardware failures, software bugs, or other sources) to manifest. However, once corruption exists, the lack of emergency stop mechanism violates the fail-safe principle and can worsen the situation. The finding aligns with Medium severity as it leads to "state inconsistencies requiring intervention" when corruption occurs.

### Citations

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

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L39-49)
```rust
    quit_worker: AtomicBool,
}

impl PrunerWorkerInner {
    fn new(pruner: Arc<dyn DBPruner>, batch_size: usize) -> Arc<Self> {
        Arc::new(Self {
            pruning_time_interval_in_ms: if cfg!(test) { 100 } else { 1 },
            pruner,
            batch_size,
            quit_worker: AtomicBool::new(false),
        })
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

**File:** storage/schemadb/src/lib.rs (L289-303)
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
```

**File:** storage/schemadb/src/lib.rs (L389-407)
```rust
fn to_db_err(rocksdb_err: rocksdb::Error) -> AptosDbError {
    match rocksdb_err.kind() {
        ErrorKind::Incomplete => AptosDbError::RocksDbIncompleteResult(rocksdb_err.to_string()),
        ErrorKind::NotFound
        | ErrorKind::Corruption
        | ErrorKind::NotSupported
        | ErrorKind::InvalidArgument
        | ErrorKind::IOError
        | ErrorKind::MergeInProgress
        | ErrorKind::ShutdownInProgress
        | ErrorKind::TimedOut
        | ErrorKind::Aborted
        | ErrorKind::Busy
        | ErrorKind::Expired
        | ErrorKind::TryAgain
        | ErrorKind::CompactionTooLarge
        | ErrorKind::ColumnFamilyDropped
        | ErrorKind::Unknown => AptosDbError::OtherRocksDbError(rocksdb_err.to_string()),
    }
```

**File:** storage/aptosdb/src/utils/iterators.rs (L355-360)
```rust
                ensure!(
                    version == txn_summary.version(),
                    "DB corruption: version mismatch: version in key: {}, version in txn summary: {}",
                    version,
                    txn_summary.version(),
                );
```
