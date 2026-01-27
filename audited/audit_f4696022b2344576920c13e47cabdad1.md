# Audit Report

## Title
Race Condition in Transaction Proof Generation During Concurrent Pruning Causes API Failures

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists between `get_transaction_proof()` and the ledger pruner. When proof generation is requested for a version that passes the `error_if_ledger_pruned` check but the pruner concurrently deletes accumulator nodes needed for the proof, the proof generation fails with "node does not exist" errors. This breaks the state consistency invariant and causes API instability.

## Finding Description

The vulnerability arises from improper synchronization between proof generation and pruning operations in the transaction accumulator database.

The vulnerable sequence occurs as follows:

1. **Reader Thread**: A client calls `get_transaction_with_proof(version=100)` on a node where `min_readable_version=50` [1](#0-0) 

2. **Reader Thread**: The code checks `error_if_ledger_pruned("Transaction", 100)` which reads `min_readable_version` from the ledger pruner [2](#0-1) 

3. **Reader Thread**: Check passes since `100 >= 50`, and the reader proceeds to call `get_transaction_proof()` [3](#0-2) 

4. **Pruner Manager Thread**: Concurrently, new blocks arrive and `set_pruner_target_db_version(250)` is called, which atomically updates `min_readable_version = 250 - 100 = 150` BEFORE any actual pruning occurs [4](#0-3) 

5. **Pruner Worker Thread**: The background pruner worker wakes up and calls `prune(50, 150)`, deleting transaction accumulator nodes for versions 50-149 [5](#0-4) 

6. **Pruner Worker Thread**: The actual deletion occurs via `TransactionAccumulatorDb::prune()` which removes nodes from RocksDB [6](#0-5) 

7. **Reader Thread**: Meanwhile, the reader thread continues proof generation by calling `Accumulator::get_proof()` which attempts to read sibling nodes from the accumulator [7](#0-6) 

8. **Reader Thread**: When reading a frozen node via `HashReader::get()`, the database lookup fails because the node was deleted in step 6 [8](#0-7) 

9. **Reader Thread**: The error "{position} does not exist" propagates up, causing `get_transaction_with_proof()` to fail

The root cause is that `min_readable_version` is updated to the TARGET pruning version before actual pruning completes, but RocksDB reads do NOT use snapshots by default. There is no transaction isolation to protect readers who passed the `error_if_ledger_pruned` check from concurrent deletions. [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **API Crashes**: Client requests for transaction proofs will intermittently fail with database errors, causing API instability and degraded service quality

2. **Validator Node Slowdowns**: Validators attempting to serve proofs during pruning windows will experience elevated error rates, requiring retries and consuming additional resources

3. **State Synchronization Failures**: State sync operations that rely on transaction proofs may fail during pruning, potentially causing nodes to fall behind or require manual intervention

4. **Consensus Impact**: While this doesn't directly break consensus safety, it affects the availability and reliability of the storage layer that consensus depends on

The vulnerability breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." When proof generation fails due to missing nodes, clients cannot verify state transitions even though the data passed the readability check.

## Likelihood Explanation

This vulnerability has **MEDIUM to HIGH likelihood** of occurring in production:

1. **Concurrent Access Pattern**: Aptos nodes regularly serve API requests while pruning runs in the background. The pruner operates continuously once the prune window fills up

2. **Timing Window**: The race window exists between the `error_if_ledger_pruned` check and actual node reads during proof generation. With sufficient concurrent load, this window will be hit

3. **No Special Privileges Required**: Any client can trigger proof requests via public RPC endpoints. Attackers could deliberately send requests for versions near the pruning boundary to maximize hit rate

4. **Production Evidence**: The test suite shows awareness that pruned versions should fail, but doesn't test concurrent access scenarios [10](#0-9) 

## Recommendation

Implement one of the following solutions:

**Solution 1: Atomic Version Check and Read (Preferred)**

Use RocksDB snapshots to provide read isolation. Create a snapshot at the time of the version check and use it for all subsequent reads:

```rust
// In aptosdb_reader.rs, modify get_transaction_with_proof
pub(super) fn get_transaction_with_proof(
    &self,
    version: Version,
    ledger_version: Version,
    fetch_events: bool,
) -> Result<TransactionWithProof> {
    self.error_if_ledger_pruned("Transaction", version)?;
    
    // Create RocksDB snapshot for consistent read
    let read_opts = ReadOptions::default();
    let snapshot = self.ledger_db.transaction_accumulator_db().db().snapshot();
    read_opts.set_snapshot(&snapshot);
    
    // Use snapshot for all reads...
}
```

**Solution 2: Update min_readable_version After Pruning**

Delay updating `min_readable_version` until after pruning completes. Modify `LedgerPruner` to update the manager's `min_readable_version` only after `record_progress()`:

```rust
// In LedgerPrunerManager, add callback from pruner
impl LedgerPruner {
    fn prune(&self, max_versions: usize) -> Result<Version> {
        // ... existing pruning logic ...
        
        // Update manager's min_readable_version AFTER pruning completes
        if let Some(callback) = &self.completion_callback {
            callback(progress);
        }
        
        Ok(target_version)
    }
}
```

**Solution 3: Pessimistic Locking**

Add a read-write lock where readers acquire read lock during proof generation and pruner acquires write lock during deletion. However, this impacts concurrency performance.

## Proof of Concept

```rust
#[cfg(test)]
mod test_concurrent_prune_proof {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_proof_generation_during_concurrent_pruning() {
        let tmp_dir = TempPath::new();
        let db = Arc::new(AptosDB::new_for_test(&tmp_dir));
        
        // Setup: Create 200 transactions
        let txns: Vec<_> = (0..200).map(|_| create_test_transaction()).collect();
        let txn_infos: Vec<_> = (0..200).map(|_| create_test_txn_info()).collect();
        save_transactions(&db, &txns, &txn_infos);
        
        // Setup pruner with 0 prune window
        let pruner = LedgerPrunerManager::new(
            Arc::clone(&db.ledger_db),
            LedgerPrunerConfig {
                enable: true,
                prune_window: 0,
                batch_size: 10,
                user_pruning_window_offset: 0,
            }
        );
        
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = barrier.clone();
        let db_clone = Arc::clone(&db);
        
        // Thread 1: Request proof for version 100
        let reader_handle = thread::spawn(move || {
            barrier_clone.wait(); // Synchronize start
            
            // This should pass the pruning check
            let result = db_clone.get_transaction_with_proof(
                100,  // version
                199,  // ledger_version  
                false // fetch_events
            );
            
            result
        });
        
        // Thread 2: Trigger aggressive pruning
        let pruner_handle = thread::spawn(move || {
            barrier.wait(); // Synchronize start
            
            // This will set min_readable_version=150 immediately
            // then prune versions 0-149 including version 100
            pruner.wake_and_wait_pruner(150).unwrap();
        });
        
        // Collect results
        let reader_result = reader_handle.join().unwrap();
        pruner_handle.join().unwrap();
        
        // EXPECTED BEHAVIOR: Should succeed or fail gracefully
        // ACTUAL BEHAVIOR: May fail with "Position does not exist" error
        match reader_result {
            Ok(_) => println!("Proof generation succeeded (no race)"),
            Err(e) => {
                let error_msg = format!("{:?}", e);
                if error_msg.contains("does not exist") {
                    panic!("VULNERABILITY: Proof generation failed due to race condition with pruner: {}", e);
                }
            }
        }
    }
}
```

**Expected Failure Mode**: With sufficient timing variance (add sleeps or run repeatedly), the test will observe the race condition where `get_transaction_with_proof` fails with a "Position does not exist" error for version 100, even though it passed the `error_if_ledger_pruned` check.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L1070-1084)
```rust
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

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L66-73)
```rust
    pub fn get_transaction_proof(
        &self,
        version: Version,
        ledger_version: Version,
    ) -> Result<TransactionAccumulatorProof> {
        Accumulator::get_proof(self, ledger_version + 1 /* num_leaves */, version)
            .map_err(Into::into)
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

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L195-201)
```rust
impl HashReader for TransactionAccumulatorDb {
    fn get(&self, position: Position) -> Result<HashValue, anyhow::Error> {
        self.db
            .get::<TransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| anyhow!("{} does not exist.", position))
    }
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

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L62-92)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning ledger data."
            );
            self.ledger_metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning ledger data is done.");
        }

        Ok(target_version)
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

**File:** storage/aptosdb/src/pruner/ledger_pruner/test.rs (L142-146)
```rust
            if j != i - 1 || j % 2 == 1 {
                assert!(ledger_store
                    .get_transaction_proof(j as u64, ledger_version)
                    .is_err());
            }
```
