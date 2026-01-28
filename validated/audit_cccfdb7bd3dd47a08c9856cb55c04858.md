Based on my comprehensive analysis of the Aptos Core codebase, I must validate the technical claims in this report.

# Audit Report

## Title
TOCTOU Race Condition in Latest Ledger Info Update Causes Epoch Regression

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition in `update_latest_ledger_info()` allows the in-memory latest ledger info to regress to an earlier state when concurrent database operations occur. The non-atomic check-then-update pattern enables interleaving between state snapshot finalization and consensus commits, potentially causing nodes to have inconsistent views of the current epoch.

## Finding Description

The vulnerability exists in the `update_latest_ledger_info()` function which performs a non-atomic check-then-update operation: [1](#0-0) 

The race condition occurs because:

1. **Non-atomic check-then-update**: The function reads the current latest ledger info (line 65), checks epochs (line 66), then updates (line 71). These operations are not atomic as a whole.

2. **ArcSwap limitations**: The `latest_ledger_info` field uses `ArcSwap<Option<LedgerInfoWithSignatures>>` for lock-free reads: [2](#0-1) 

While ArcSwap provides atomic individual operations, it does NOT provide atomic check-then-update semantics: [3](#0-2) [4](#0-3) 

3. **Unsynchronized callers**: `finalize_state_snapshot()` calls `update_latest_ledger_info()` without holding any locks: [5](#0-4) 

The call occurs at line 236 with no lock protection.

4. **Bypass path**: `commit_ledger()` holds the `commit_lock` but its `post_commit()` method directly calls `set_latest_ledger_info()` without epoch validation: [6](#0-5) [7](#0-6) 

The `post_commit()` function at lines 662-665 directly updates the cache, bypassing the epoch comparison check that `update_latest_ledger_info()` performs.

**Race Scenario:**
- Thread A (state sync): Calls `finalize_state_snapshot()` with ledger infos
- Thread B (consensus): Calls `commit_ledger()` then `post_commit()` 
- Thread A reads current latest ledger info at a stale state
- Thread B updates to a newer version via `set_latest_ledger_info()`
- Thread A's epoch check passes using stale data
- Thread A overwrites Thread B's update with older information

This violates state consistency invariants as the cached latest ledger info can regress to earlier versions or epochs.

## Impact Explanation

**Severity: High**

This vulnerability has significant implications:

1. **State Inconsistency**: The in-memory cache of latest ledger info serves read requests. Regression causes nodes to serve stale or incorrect blockchain state information.

2. **Epoch Confusion**: If a ledger info with `next_block_epoch = N+1` is overwritten by one with `next_block_epoch = N`, the node believes it's in epoch N when the network is in epoch N+1.

3. **Validator Coordination Issues**: Validators querying this cached state for epoch-dependent operations may use incorrect epoch information, potentially affecting block validation or voting behavior.

4. **State Sync Errors**: Nodes attempting to sync may receive inconsistent responses from different nodes, complicating synchronization logic.

This qualifies as **High Severity** under Aptos bug bounty criteria as it represents a significant protocol-level state inconsistency that can affect validator operations, even though it doesn't directly enable fund theft or guaranteed consensus splits.

## Likelihood Explanation

**Likelihood: Medium**

The race condition can occur during normal operational transitions:

1. **Architectural Handover Period**: The code comments indicate "Consensus and state sync must hand over to each other" but this is not enforced by locks. The handover period creates a race window.

2. **Node State Transitions**: When nodes finish state snapshot synchronization and begin consensus participation, both code paths may briefly execute concurrently.

3. **No Mutual Exclusion**: `finalize_state_snapshot()` takes no locks while `commit_ledger()` only holds `commit_lock`, providing no protection against concurrent finalization.

4. **Natural Occurrence**: This requires no external attacker - it can occur during node startup, recovery from network partitions, or fast-sync operations.

The race window is narrow but exists during every state sync to consensus transition, making it a reliability concern rather than an easily exploitable attack vector.

## Recommendation

Implement atomic update semantics for latest ledger info updates:

**Option 1**: Add a mutex around the check-then-update sequence in `update_latest_ledger_info()`:
```rust
pub(crate) fn update_latest_ledger_info(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    // Acquire exclusive lock for check-then-update
    let _guard = ledger_metadata_db.latest_ledger_info_lock.lock();
    
    if let Some(li) = ledger_metadata_db.get_latest_ledger_info_option() {
        if li.ledger_info().epoch() > ledger_infos.last().unwrap().ledger_info().epoch() {
            return Ok(());
        }
    }
    ledger_metadata_db.set_latest_ledger_info(ledger_infos.last().unwrap().clone());
    Ok(())
}
```

**Option 2**: Use compare-and-swap semantics with ArcSwap:
```rust
pub(crate) fn update_latest_ledger_info(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    let new_li = ledger_infos.last().unwrap().clone();
    
    loop {
        let current = ledger_metadata_db.latest_ledger_info.load();
        if let Some(ref li) = **current {
            if li.ledger_info().epoch() > new_li.ledger_info().epoch() {
                return Ok(());
            }
        }
        
        // Attempt atomic compare-and-swap
        if ledger_metadata_db.latest_ledger_info
            .compare_and_swap(&current, Arc::new(Some(new_li.clone())))
            .is_ok() {
            break;
        }
        // CAS failed, retry
    }
    Ok(())
}
```

**Option 3**: Enforce mutual exclusion between `finalize_state_snapshot()` and `commit_ledger()` by having `finalize_state_snapshot()` acquire the `commit_lock`.

## Proof of Concept

The vulnerability can be demonstrated through concurrent execution tracing. A Rust test demonstrating the race:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_toctou_race_condition() {
    // Setup: Create AptosDB instance
    let db = create_test_db();
    
    // Initial state: epoch 99
    let initial_li = create_ledger_info(99, 1000);
    db.ledger_db.metadata_db().set_latest_ledger_info(initial_li);
    
    // Spawn Thread A: finalize_state_snapshot with epoch 100
    let db_clone = db.clone();
    let handle_a = tokio::spawn(async move {
        let epoch_100_lis = vec![create_ledger_info(100, 1500)];
        // This will read current (epoch 99), check, then update
        restore_utils::update_latest_ledger_info(
            db_clone.ledger_db.metadata_db(),
            &epoch_100_lis
        ).unwrap();
    });
    
    // Spawn Thread B: commit_ledger with epoch 101
    let db_clone = db.clone();
    let handle_b = tokio::spawn(async move {
        let epoch_101_li = create_ledger_info(101, 2000);
        // This directly sets without epoch check
        db_clone.ledger_db.metadata_db()
            .set_latest_ledger_info(epoch_101_li);
    });
    
    // Wait for both
    handle_a.await.unwrap();
    handle_b.await.unwrap();
    
    // Race result: may have epoch 100 instead of expected epoch 101
    let final_li = db.ledger_db.metadata_db().get_latest_ledger_info().unwrap();
    
    // Depending on interleaving, epoch may have regressed
    assert_eq!(final_li.ledger_info().epoch(), 101); // May fail due to race
}
```

The race manifests when Thread A's read at line 65 observes stale state before Thread B's update, causing Thread A to overwrite Thread B's newer value.

## Notes

- The vulnerability affects the in-memory cache used to serve read requests, not the persistent database storage
- While both threads write correctly to the database, the cached view can diverge
- The impact is limited to query responses and epoch-dependent coordination logic
- This is a reliability and consistency issue rather than a directly exploitable attack vector
- The architectural expectation that state sync and consensus "hand over" is not enforced by synchronization primitives

### Citations

**File:** storage/aptosdb/src/backup/restore_utils.rs (L61-74)
```rust
pub(crate) fn update_latest_ledger_info(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    if let Some(li) = ledger_metadata_db.get_latest_ledger_info_option() {
        if li.ledger_info().epoch() > ledger_infos.last().unwrap().ledger_info().epoch() {
            // No need to update latest ledger info.
            return Ok(());
        }
    }
    ledger_metadata_db.set_latest_ledger_info(ledger_infos.last().unwrap().clone());

    Ok(())
}
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L39-39)
```rust
    latest_ledger_info: ArcSwap<Option<LedgerInfoWithSignatures>>,
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L94-98)
```rust
    pub(crate) fn get_latest_ledger_info_option(&self) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L180-183)
```rust
    pub(crate) fn set_latest_ledger_info(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) {
        self.latest_ledger_info
            .store(Arc::new(Some(ledger_info_with_sigs)));
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L78-112)
```rust
    fn commit_ledger(
        &self,
        version: Version,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        chunk_opt: Option<ChunkToCommit>,
    ) -> Result<()> {
        gauged_api("commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_ledger"]);

            let old_committed_ver = self.get_and_check_commit_range(version)?;

            let mut ledger_batch = SchemaBatch::new();
            // Write down LedgerInfo if provided.
            if let Some(li) = ledger_info_with_sigs {
                self.check_and_put_ledger_info(version, li, &mut ledger_batch)?;
            }
            // Write down commit progress
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
            self.ledger_db.metadata_db().write_schemas(ledger_batch)?;

            // Notify the pruners, invoke the indexer, and update in-memory ledger info.
            self.post_commit(old_committed_ver, version, ledger_info_with_sigs, chunk_opt)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L125-241)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
    ) -> Result<()> {
        let (output_with_proof, persisted_aux_info) = output_with_proof.into_parts();
        gauged_api("finalize_state_snapshot", || {
            // Ensure the output with proof only contains a single transaction output and info
            let num_transaction_outputs = output_with_proof.get_num_outputs();
            let num_transaction_infos = output_with_proof.proof.transaction_infos.len();
            ensure!(
                num_transaction_outputs == 1,
                "Number of transaction outputs should == 1, but got: {}",
                num_transaction_outputs
            );
            ensure!(
                num_transaction_infos == 1,
                "Number of transaction infos should == 1, but got: {}",
                num_transaction_infos
            );

            // TODO(joshlind): include confirm_or_save_frozen_subtrees in the change set
            // bundle below.

            // Update the merkle accumulator using the given proof
            let frozen_subtrees = output_with_proof
                .proof
                .ledger_info_to_transaction_infos_proof
                .left_siblings();
            restore_utils::confirm_or_save_frozen_subtrees(
                self.ledger_db.transaction_accumulator_db_raw(),
                version,
                frozen_subtrees,
                None,
            )?;

            // Create a single change set for all further write operations
            let mut ledger_db_batch = LedgerDbSchemaBatches::new();
            let mut sharded_kv_batch = self.state_kv_db.new_sharded_native_batches();
            let mut state_kv_metadata_batch = SchemaBatch::new();
            // Save the target transactions, outputs, infos and events
            let (transactions, outputs): (Vec<Transaction>, Vec<TransactionOutput>) =
                output_with_proof
                    .transactions_and_outputs
                    .into_iter()
                    .unzip();
            let events = outputs
                .clone()
                .into_iter()
                .map(|output| output.events().to_vec())
                .collect::<Vec<_>>();
            let wsets: Vec<WriteSet> = outputs
                .into_iter()
                .map(|output| output.write_set().clone())
                .collect();
            let transaction_infos = output_with_proof.proof.transaction_infos;
            // We should not save the key value since the value is already recovered for this version
            restore_utils::save_transactions(
                self.state_store.clone(),
                self.ledger_db.clone(),
                version,
                &transactions,
                &persisted_aux_info,
                &transaction_infos,
                &events,
                wsets,
                Some((
                    &mut ledger_db_batch,
                    &mut sharded_kv_batch,
                    &mut state_kv_metadata_batch,
                )),
                false,
            )?;

            // Save the epoch ending ledger infos
            restore_utils::save_ledger_infos(
                self.ledger_db.metadata_db(),
                ledger_infos,
                Some(&mut ledger_db_batch.ledger_metadata_db_batches),
            )?;

            ledger_db_batch
                .ledger_metadata_db_batches
                .put::<DbMetadataSchema>(
                    &DbMetadataKey::LedgerCommitProgress,
                    &DbMetadataValue::Version(version),
                )?;
            ledger_db_batch
                .ledger_metadata_db_batches
                .put::<DbMetadataSchema>(
                    &DbMetadataKey::OverallCommitProgress,
                    &DbMetadataValue::Version(version),
                )?;

            // Apply the change set writes to the database (atomically) and update in-memory state
            //
            // state kv and SMT should use shared way of committing.
            self.ledger_db.write_schemas(ledger_db_batch)?;

            self.ledger_pruner.save_min_readable_version(version)?;
            self.state_store
                .state_merkle_pruner
                .save_min_readable_version(version)?;
            self.state_store
                .epoch_snapshot_pruner
                .save_min_readable_version(version)?;
            self.state_store
                .state_kv_pruner
                .save_min_readable_version(version)?;

            restore_utils::update_latest_ledger_info(self.ledger_db.metadata_db(), ledger_infos)?;
            self.state_store.reset();

            Ok(())
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L603-672)
```rust
    fn post_commit(
        &self,
        old_committed_version: Option<Version>,
        version: Version,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        chunk_opt: Option<ChunkToCommit>,
    ) -> Result<()> {
        // If commit succeeds and there are at least one transaction written to the storage, we
        // will inform the pruner thread to work.
        if old_committed_version.is_none() || version > old_committed_version.unwrap() {
            let first_version = old_committed_version.map_or(0, |v| v + 1);
            let num_txns = version + 1 - first_version;

            COMMITTED_TXNS.inc_by(num_txns);
            LATEST_TXN_VERSION.set(version as i64);
            if let Some(update_sender) = &self.update_subscriber {
                update_sender
                    .send((Instant::now(), version))
                    .map_err(|err| {
                        AptosDbError::Other(format!("Failed to send update to subscriber: {}", err))
                    })?;
            }
            // Activate the ledger pruner and state kv pruner.
            // Note the state merkle pruner is activated when state snapshots are persisted
            // in their async thread.
            self.ledger_pruner
                .maybe_set_pruner_target_db_version(version);
            self.state_store
                .state_kv_pruner
                .maybe_set_pruner_target_db_version(version);

            // Note: this must happen after txns have been saved to db because types can be newly
            // created in this same chunk of transactions.
            if let Some(indexer) = &self.indexer {
                let _timer = OTHER_TIMERS_SECONDS.timer_with(&["indexer_index"]);
                // n.b. txns_to_commit can be partial, when the control was handed over from consensus to state sync
                // where state sync won't send the pre-committed part to the DB again.
                if let Some(chunk) = chunk_opt
                    && chunk.len() == num_txns as usize
                {
                    let write_sets = chunk
                        .transaction_outputs
                        .iter()
                        .map(|t| t.write_set())
                        .collect_vec();
                    indexer.index(self.state_store.clone(), first_version, &write_sets)?;
                } else {
                    let write_sets: Vec<_> = self
                        .ledger_db
                        .write_set_db()
                        .get_write_set_iter(first_version, num_txns as usize)?
                        .try_collect()?;
                    let write_set_refs = write_sets.iter().collect_vec();
                    indexer.index(self.state_store.clone(), first_version, &write_set_refs)?;
                };
            }
        }

        // Once everything is successfully persisted, update the latest in-memory ledger info.
        if let Some(x) = ledger_info_with_sigs {
            self.ledger_db
                .metadata_db()
                .set_latest_ledger_info(x.clone());

            LEDGER_VERSION.set(x.ledger_info().version() as i64);
            NEXT_BLOCK_EPOCH.set(x.ledger_info().next_block_epoch() as i64);
        }

        Ok(())
    }
```
