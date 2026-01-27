# Audit Report

## Title
Mock QuorumStoreDB Hides Critical Epoch Rollback Validation Leading to Permanent Node Denial of Service

## Summary
The `MockQuorumStoreDB` test implementation bypasses critical epoch validation logic in `clean_and_get_batch_id()`, hiding a potential permanent node crash scenario when epoch state becomes inconsistent with the QuorumStoreDB. While the mock always returns a hardcoded value for testing, the real implementation contains an assertion that will panic if the database contains batch IDs from future epochs, creating an unrecoverable crash loop.

## Finding Description

The `clean_and_get_batch_id()` method in the real `QuorumStoreDB` implementation contains a critical assertion: [1](#0-0) 

This assertion enforces that the current epoch must be greater than or equal to ALL epochs stored in the database. However, the mock implementation completely bypasses this validation: [2](#0-1) 

All `BatchGenerator` tests rely exclusively on `MockQuorumStoreDB`: [3](#0-2) 

The vulnerability scenario occurs when:

1. A validator node operates normally at epoch N, and `BatchGenerator` saves batch_id for epoch N to the QuorumStoreDB (persistent storage): [4](#0-3) 

2. The node experiences state corruption, database recovery issues, or backup restoration problems where the main AptosDB is restored to epoch M (where M < N), but the QuorumStoreDB remains intact with epoch N data

3. On restart, `EpochManager` initializes with the recovered epoch M: [5](#0-4) 

4. When `clean_and_get_batch_id(M)` executes, it finds the entry for epoch N in the database, and the assertion `assert!(M >= N)` fails, causing an immediate panic

5. The node enters a permanent crash loop - every restart attempt hits the same assertion failure

The mock-based tests never exercise this code path because the mock returns a constant value regardless of database state or epoch parameters.

## Impact Explanation

This qualifies as **Medium Severity** based on the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The node cannot self-recover and requires manual deletion of the QuorumStoreDB directory
- **Validator node availability impact**: Affected validators cannot participate in consensus until manual intervention occurs
- **Limited scope**: Requires pre-existing state corruption or operational error; not directly exploitable by unprivileged attackers

While not directly exploitable as an attack vector, this represents a fragility in the system where operational issues (database corruption, improper backup restoration, or bugs in epoch recovery logic) can cause permanent node unavailability. The mock testing approach provides false confidence by never validating this critical error handling path.

## Likelihood Explanation

**Likelihood: Low to Medium**

While this scenario requires specific preconditions (epoch state mismatch between AptosDB and QuorumStoreDB), several realistic triggers exist:

1. **Database corruption**: Hardware failures affecting AptosDB while QuorumStoreDB remains intact
2. **Partial backup restoration**: Operators restoring AptosDB from an old backup while QuorumStoreDB persists newer data
3. **State sync bugs**: Issues in state synchronization logic that could provide stale epoch information during recovery
4. **Concurrent database access**: Race conditions during crash scenarios where writes complete to one database but not the other

The fact that `QuorumStoreDB` and `AptosDB` are separate persistent databases increases the risk of inconsistency during failure scenarios. The existing smoke test demonstrates partial database wiping: [6](#0-5) 

However, no test validates the assertion failure case or epoch rollback scenarios.

## Recommendation

**1. Add comprehensive integration tests that use the real `QuorumStoreDB`:**

Create tests that validate epoch transition edge cases, including:
- Attempting to initialize with an epoch lower than stored batch IDs (should fail gracefully)
- Verifying cleanup of old epoch data works correctly
- Testing database recovery scenarios

**2. Replace the panic assertion with graceful error handling:**

Instead of panicking, the implementation should return an error and allow the system to handle it appropriately (e.g., by wiping the QuorumStoreDB and reinitializing):

```rust
fn clean_and_get_batch_id(&self, current_epoch: u64) -> Result<Option<BatchId>, DbError> {
    let mut iter = self.db.iter::<BatchIdSchema>()?;
    iter.seek_to_first();
    let epoch_batch_id = iter
        .map(|res| res.map_err(Into::into))
        .collect::<Result<HashMap<u64, BatchId>>>()?;
    let mut ret = None;
    for (epoch, batch_id) in epoch_batch_id {
        if epoch > current_epoch {
            // Return error instead of panicking
            return Err(DbError::Other(format!(
                "Database contains batch_id for future epoch {}. Current epoch: {}. QuorumStoreDB may need to be wiped.",
                epoch, current_epoch
            )));
        }
        if epoch < current_epoch {
            self.delete_batch_id(epoch)?;
        } else {
            ret = Some(batch_id);
        }
    }
    Ok(ret)
}
```

**3. Add epoch validation at the QuorumStore initialization level:**

Implement a database integrity check that validates epoch consistency before starting the `BatchGenerator`, with automatic cleanup or clear error reporting.

**4. Document the epoch rollback scenario and recovery procedure:**

Provide clear operator guidance on how to recover from epoch mismatch scenarios.

## Proof of Concept

This PoC demonstrates how the assertion failure can be triggered (theoretical reproduction):

```rust
#[test]
#[should_panic(expected = "assertion failed")]
fn test_epoch_rollback_causes_panic() {
    use tempfile::TempDir;
    use aptos_types::quorum_store::BatchId;
    
    let tmp_dir = TempDir::new().unwrap();
    let db = QuorumStoreDB::new(&tmp_dir);
    
    // Simulate normal operation at epoch 100
    let epoch_100 = 100u64;
    let batch_id_100 = BatchId::new_for_test(5);
    db.save_batch_id(epoch_100, batch_id_100).expect("save failed");
    
    // Simulate restart with rolled-back epoch (e.g., from old backup)
    let epoch_95 = 95u64;
    
    // This should panic due to assertion failure: assert!(95 >= 100)
    // In production, this causes permanent crash loop
    let result = db.clean_and_get_batch_id(epoch_95);
    
    // Will never reach here - panics above
    assert!(result.is_err());
}
```

**Notes:**
- The mock's hardcoded return value provides no test coverage for this critical validation path
- The assertion on line 171 should be replaced with proper error handling to prevent permanent node unavailability
- Integration tests should verify epoch transition scenarios with the real database implementation
- This issue demonstrates how mock-based testing can hide important edge cases in production code paths

### Citations

**File:** consensus/src/quorum_store/quorum_store_db.rs (L163-179)
```rust
    fn clean_and_get_batch_id(&self, current_epoch: u64) -> Result<Option<BatchId>, DbError> {
        let mut iter = self.db.iter::<BatchIdSchema>()?;
        iter.seek_to_first();
        let epoch_batch_id = iter
            .map(|res| res.map_err(Into::into))
            .collect::<Result<HashMap<u64, BatchId>>>()?;
        let mut ret = None;
        for (epoch, batch_id) in epoch_batch_id {
            assert!(current_epoch >= epoch);
            if epoch < current_epoch {
                self.delete_batch_id(epoch)?;
            } else {
                ret = Some(batch_id);
            }
        }
        Ok(ret)
    }
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L227-229)
```rust
        fn clean_and_get_batch_id(&self, _: u64) -> Result<Option<BatchId>, DbError> {
            Ok(Some(BatchId::new_for_test(0)))
        }
```

**File:** consensus/src/quorum_store/tests/batch_generator_test.rs (L100-108)
```rust
    let mut batch_generator = BatchGenerator::new(
        0,
        author,
        config,
        Arc::new(MockQuorumStoreDB::new()),
        Arc::new(MockBatchWriter::new()),
        quorum_store_to_mempool_tx,
        1000,
    );
```

**File:** consensus/src/quorum_store/batch_generator.rs (L87-101)
```rust
        let batch_id = if let Some(mut id) = db
            .clean_and_get_batch_id(epoch)
            .expect("Could not read from db")
        {
            // If the node shut down mid-batch, then this increment is needed
            id.increment();
            id
        } else {
            BatchId::new(aptos_infallible::duration_since_epoch().as_micros() as u64)
        };
        debug!("Initialized with batch_id of {}", batch_id);
        let mut incremented_batch_id = batch_id;
        incremented_batch_id.increment();
        db.save_batch_id(epoch, incremented_batch_id)
            .expect("Could not save to db");
```

**File:** consensus/src/epoch_manager.rs (L738-755)
```rust
            info!("Building QuorumStore");
            QuorumStoreBuilder::QuorumStore(InnerBuilder::new(
                self.epoch(),
                self.author,
                epoch_state.verifier.len() as u64,
                quorum_store_config,
                self.quorum_store_txn_filter_config.clone(),
                consensus_to_quorum_store_rx,
                self.quorum_store_to_mempool_sender.clone(),
                self.config.mempool_txn_pull_timeout_ms,
                self.storage.aptos_db().clone(),
                network_sender,
                epoch_state.verifier.clone(),
                self.proof_cache.clone(),
                self.quorum_store_storage.clone(),
                !consensus_config.is_dag_enabled(),
                consensus_key,
            ))
```

**File:** testsuite/smoke-test/src/consensus/quorum_store_fault_tolerance.rs (L192-203)
```rust
    if do_wipe_db {
        let node0_config = swarm.validator(node_to_restart).unwrap().config().clone();
        let db_dir = node0_config.storage.dir();
        let quorum_store_db_dir = db_dir.join(QUORUM_STORE_DB_NAME);
        info!(
            "wipe only quorum store db: {}",
            quorum_store_db_dir.display()
        );
        fs::remove_dir_all(quorum_store_db_dir).unwrap();
    } else {
        info!("don't do anything to quorum store db");
    }
```
