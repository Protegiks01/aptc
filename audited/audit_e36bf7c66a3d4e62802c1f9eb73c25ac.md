# Audit Report

## Title
Time-Of-Check to Time-Of-Use Race Condition in Transaction Accumulator Proof Generation During Concurrent Pruning

## Summary
A race condition exists between the `error_if_ledger_pruned` validation check and the actual data reads during transaction accumulator proof generation. While the pruner runs asynchronously in a background thread, API requests can pass the pruning check but then fail when attempting to read accumulator nodes that have been deleted mid-operation, causing API responses to crash with "does not exist" errors.

## Finding Description
The vulnerability manifests in the following execution flow:

**Step 1: API Request Initiated**
When an API client requests transaction proofs (e.g., `get_transaction_with_proof`), the system first validates the requested version hasn't been pruned. [1](#0-0) 

**Step 2: Pruning Check**
The validation atomically reads `min_readable_version` from the pruner manager and checks if the requested version is still available. [2](#0-1) 

**Step 3: Concurrent Pruner Updates**
In a separate background thread, the pruner manager can update `min_readable_version` and trigger deletion of accumulator data. [3](#0-2) 

**Step 4: Pruner Deletes Data**
The pruner worker asynchronously executes deletion operations, removing both root hashes and accumulator tree nodes. [4](#0-3) 

**Step 5: Proof Generation Attempts Read**
After the check passes, proof generation proceeds by reading individual accumulator positions to construct Merkle proofs. [5](#0-4) 

**Step 6: Read Failure**
When attempting to read a deleted accumulator position, the database returns `None`, causing an error to be raised. [6](#0-5) 

**Critical Gap:**
The reads are not performed atomically with respect to the pruning check. Database reads use RocksDB's default `get_cf` without snapshot isolation. [7](#0-6) 

The pruner worker runs continuously in a background thread without coordination with ongoing read operations. [8](#0-7) 

## Impact Explanation
This qualifies as **HIGH severity** under the Aptos bug bounty criteria:

**API Crashes**: Transaction proof API calls fail unexpectedly with "position does not exist" errors even though the version passed the pruning validation check. This breaks the contract that data at versions >= `min_readable_version` should be accessible.

**Service Disruption**: 
- State sync protocols rely on transaction proofs and can fail during synchronization
- Light clients cannot verify historical transactions
- Backup and restore operations may encounter errors
- Archival nodes serving historical data experience intermittent failures

**Invariant Violation**: Breaks the "State Consistency" invariant that "State transitions must be atomic and verifiable via Merkle proofs" - if a version is deemed readable, all data necessary to generate its proofs must remain accessible for the duration of the operation.

## Likelihood Explanation
This race condition has **MEDIUM to HIGH likelihood** of occurring in production:

**Triggering Conditions:**
- Pruning must be enabled (common in production for disk space management)
- API must receive requests for versions near the pruning boundary
- Timing window: between the `error_if_ledger_pruned` check and completion of all accumulator node reads

**Probability Factors:**
- Higher under load when API request rate is high
- More frequent with aggressive pruning (small `prune_window`, large `batch_size`)
- Depends on RocksDB commit latency and thread scheduling
- The window is small but non-zero for each proof generation request

**Evidence from Codebase:**
Test infrastructure uses `wake_and_wait_pruner` which explicitly waits for pruning to complete before performing reads, suggesting concurrent access was not tested. [9](#0-8) 

## Recommendation
Implement snapshot-based reads for proof generation to ensure atomic consistency:

**Solution 1: Use RocksDB Snapshots (Recommended)**
Create a RocksDB snapshot after the `error_if_ledger_pruned` check and use it for all subsequent reads during proof generation. This ensures a consistent point-in-time view of the database.

**Solution 2: Read-Write Lock**
Add a reader-writer lock where:
- Proof generation acquires read lock
- Pruning operations acquire write lock
This serializes pruning with respect to ongoing proof reads but may impact performance.

**Solution 3: Retry Logic with Verification**
If a read fails with "does not exist", re-check `min_readable_version`. If the version is still claimed to be readable, retry the entire proof generation. If it's been pruned, return appropriate error. This is less elegant but avoids architectural changes.

**Solution 4: Pessimistic Locking**
Update `min_readable_version` only AFTER the pruning batch is committed to disk, not before. This ensures the check is conservative but may cause some reads to succeed that could have been rejected earlier.

## Proof of Concept

```rust
// Rust test demonstrating the race condition
#[test]
fn test_concurrent_pruning_race() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use std::thread;
    use std::time::Duration;
    
    let tmp_dir = TempPath::new();
    let db = Arc::new(AptosDB::new_for_test(&tmp_dir));
    
    // Setup: Write 10000 transactions
    let num_txns = 10000u64;
    setup_test_transactions(&db, num_txns);
    
    // Enable aggressive pruning
    let pruner = Arc::new(LedgerPrunerManager::new(
        Arc::clone(&db.ledger_db),
        LedgerPrunerConfig {
            enable: true,
            prune_window: 1000, // Keep only last 1000 versions
            batch_size: 100,
            user_pruning_window_offset: 0,
        },
    ));
    
    let error_occurred = Arc::new(AtomicBool::new(false));
    let should_stop = Arc::new(AtomicBool::new(false));
    
    // Thread 1: Continuously trigger pruning
    let pruner_clone = Arc::clone(&pruner);
    let stop_clone1 = Arc::clone(&should_stop);
    let pruner_thread = thread::spawn(move || {
        let mut version = 2000u64;
        while !stop_clone1.load(Ordering::SeqCst) {
            pruner_clone.maybe_set_pruner_target_db_version(version);
            version += 100;
            thread::sleep(Duration::from_millis(10));
        }
    });
    
    // Thread 2: Continuously request proofs at the boundary
    let db_clone = Arc::clone(&db);
    let error_clone = Arc::clone(&error_occurred);
    let stop_clone2 = Arc::clone(&should_stop);
    let reader_thread = thread::spawn(move || {
        let mut version = 1000u64;
        while !stop_clone2.load(Ordering::SeqCst) {
            // Request proof for version at/near pruning boundary
            match db_clone.get_transaction_with_proof(
                version,
                num_txns - 1, // ledger version
                false, // fetch_events
            ) {
                Ok(_) => {
                    // Success - version not pruned
                }
                Err(e) => {
                    let err_msg = format!("{:?}", e);
                    // Check if error is "does not exist" during proof generation
                    // rather than expected "pruned" error
                    if err_msg.contains("does not exist") {
                        error_clone.store(true, Ordering::SeqCst);
                        eprintln!("RACE DETECTED: {}", err_msg);
                        break;
                    }
                }
            }
            version += 10;
            if version > 1900 {
                version = 1000; // Loop back
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
    
    // Run for 10 seconds or until race detected
    for _ in 0..100 {
        if error_occurred.load(Ordering::SeqCst) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    
    should_stop.store(true, Ordering::SeqCst);
    pruner_thread.join().unwrap();
    reader_thread.join().unwrap();
    
    assert!(
        error_occurred.load(Ordering::SeqCst),
        "Race condition should be detected: proof generation failed \
         with 'does not exist' despite passing pruning check"
    );
}
```

**Expected Result:** The test will eventually detect the race condition where `get_transaction_with_proof` returns a "does not exist" error for an accumulator position, even though the version passed the `error_if_ledger_pruned` check. This demonstrates that concurrent pruning can delete data between the validation check and the actual reads.

## Notes
This vulnerability exists because the system treats `error_if_ledger_pruned` as a sufficient guard, but it only provides a point-in-time check without ensuring atomicity of subsequent operations. The lack of snapshot isolation or locking means the database state can change between the check and the use, creating a classic TOCTOU vulnerability. The fix requires either transaction-level isolation (snapshots) or explicit synchronization primitives.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1074-1074)
```rust
        self.error_if_ledger_pruned("Transaction", version)?;
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
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
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L162-176)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());
        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["ledger_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.pruner_worker
            .as_ref()
            .unwrap()
            .set_target_db_version(min_readable_version);
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L149-172)
```rust
    pub(crate) fn prune(begin: Version, end: Version, db_batch: &mut SchemaBatch) -> Result<()> {
        for version_to_delete in begin..end {
            db_batch.delete::<TransactionAccumulatorRootHashSchema>(&version_to_delete)?;
            // The even version will be pruned in the iteration of version + 1.
            if version_to_delete % 2 == 0 {
                continue;
            }

            let first_ancestor_that_is_a_left_child =
                Self::find_first_ancestor_that_is_a_left_child(version_to_delete);

            // This assertion is true because we skip the leaf nodes with address which is a
            // a multiple of 2.
            assert!(!first_ancestor_that_is_a_left_child.is_leaf());

            let mut current = first_ancestor_that_is_a_left_child;
            while !current.is_leaf() {
                db_batch.delete::<TransactionAccumulatorSchema>(&current.left_child())?;
                db_batch.delete::<TransactionAccumulatorSchema>(&current.right_child())?;
                current = current.right_child();
            }
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L196-200)
```rust
    fn get(&self, position: Position) -> Result<HashValue, anyhow::Error> {
        self.db
            .get::<TransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| anyhow!("{} does not exist.", position))
    }
```

**File:** storage/accumulator/src/lib.rs (L334-347)
```rust
    fn get_hash(&self, position: Position) -> Result<HashValue> {
        let idx = self.rightmost_leaf_index();
        if position.is_placeholder(idx) {
            Ok(*ACCUMULATOR_PLACEHOLDER_HASH)
        } else if position.is_freezable(idx) {
            self.reader.get(position)
        } else {
            // non-frozen non-placeholder node
            Ok(Self::hash_internal_node(
                self.get_hash(position.left_child())?,
                self.get_hash(position.right_child())?,
            ))
        }
    }
```

**File:** storage/schemadb/src/lib.rs (L216-232)
```rust
    pub fn get<S: Schema>(&self, schema_key: &S::Key) -> DbResult<Option<S::Value>> {
        let _timer = APTOS_SCHEMADB_GET_LATENCY_SECONDS.timer_with(&[S::COLUMN_FAMILY_NAME]);

        let k = <S::Key as KeyCodec<S>>::encode_key(schema_key)?;
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        let result = self.inner.get_cf(cf_handle, k).into_db_res()?;
        APTOS_SCHEMADB_GET_BYTES.observe_with(
            &[S::COLUMN_FAMILY_NAME],
            result.as_ref().map_or(0.0, |v| v.len() as f64),
        );

        result
            .map(|raw_value| <S::Value as ValueCodec<S>>::decode_value(&raw_value))
            .transpose()
            .map_err(Into::into)
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

**File:** storage/aptosdb/src/pruner/pruner_manager.rs (L43-71)
```rust
    fn wake_and_wait_pruner(&self, latest_version: Version) -> Result<()> {
        self.maybe_set_pruner_target_db_version(latest_version);
        self.wait_for_pruner()
    }

    #[cfg(test)]
    fn wait_for_pruner(&self) -> Result<()> {
        use aptos_storage_interface::{db_other_bail, AptosDbError};
        use std::{
            thread::sleep,
            time::{Duration, Instant},
        };

        if !self.is_pruner_enabled() {
            return Ok(());
        }

        // Assuming no big pruning chunks will be issued by a test.
        const TIMEOUT: Duration = Duration::from_secs(60);
        let end = Instant::now() + TIMEOUT;

        while Instant::now() < end {
            if !self.is_pruning_pending() {
                return Ok(());
            }
            sleep(Duration::from_millis(1));
        }
        db_other_bail!("Timeout waiting for pruner worker.");
    }
```
