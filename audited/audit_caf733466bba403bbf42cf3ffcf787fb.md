# Audit Report

## Title
Race Condition Between Consensus Commit and State Sync Finalization Allows DB-Cache Inconsistency

## Summary
A race condition exists between `commit_ledger()` and `finalize_state_snapshot()` in AptosDB where both functions write to the same database key and update the same in-memory cache without mutual exclusion. This can cause validators to have inconsistent database and cache states, potentially leading to divergent chain views.

## Finding Description

The vulnerability stems from insufficient synchronization between two critical storage operations: [1](#0-0) 

The `commit_ledger()` function acquires a `commit_lock` to serialize consensus commits, but: [2](#0-1) 

The `finalize_state_snapshot()` function does NOT acquire this lock, yet performs the same critical operations:
1. Writing ledger info to the database (keyed by epoch)
2. Updating the in-memory `latest_ledger_info` cache

The race manifests when:
- Consensus calls `commit_ledger()` and writes to DB at line 107
- Before cache update at line 665 (via `post_commit`), state sync calls `finalize_state_snapshot()`  
- State sync writes to the same DB key at line 223, potentially overwriting
- Both attempt cache updates via different code paths

The cache update mechanism in state sync has an additional flaw: [3](#0-2) 

The `update_latest_ledger_info()` function only validates that the cached epoch is not greater than the new epoch (line 66), but does NOT check version ordering within the same epoch. This allows an older version to overwrite a newer version if they're in the same epoch.

Critical validation in `commit_ledger` depends on cached state: [4](#0-3) 

The epoch continuity check at line 575 reads from the potentially stale cache via `get_latest_ledger_info_option()`, which uses the ArcSwap cache: [5](#0-4) 

## Impact Explanation

**Severity: Critical** (potential consensus split)

This violates **Critical Invariant #2 (Consensus Safety)** and **Invariant #4 (State Consistency)**. 

If validators experience this race condition during concurrent consensus and state sync operations:
1. Different validators may cache different "latest" ledger infos for the same epoch
2. Validators make consensus decisions based on cached state (line 575 validation)
3. Inconsistent cache states → different validation results → potential chain fork
4. DB-cache inconsistency persists until node restart (cache reloads from DB)

This matches the **Critical Severity** category: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: Low to Medium** (depends on handover coordination)

The code comments explicitly state the design assumption: [6](#0-5) 

Under correct operation, consensus and state sync should not overlap. However:
- No lock enforcement exists at the storage layer (finalize_state_snapshot lacks commit_lock)
- If handover coordination has a timing bug or fails during edge cases (crash recovery, epoch transitions, network partitions)
- The race window exists whenever DB write (line 107 or 223) precedes cache update (line 665 or 236)

The likelihood increases during:
- Rapid epoch transitions
- Network instability causing frequent state sync invocations  
- High validator churn
- Recovery from crashes during commits

## Recommendation

Add mutual exclusion between consensus commits and state sync finalization at the storage layer:

**Option 1: Acquire commit_lock in finalize_state_snapshot**
```rust
pub fn finalize_state_snapshot(...) -> Result<()> {
    gauged_api("finalize_state_snapshot", || {
        let _lock = self
            .commit_lock
            .try_lock()
            .expect("Concurrent committing detected.");
        
        // ... rest of implementation
    })
}
```

**Option 2: Add version ordering check in update_latest_ledger_info**
```rust
pub(crate) fn update_latest_ledger_info(...) -> Result<()> {
    if let Some(li) = ledger_metadata_db.get_latest_ledger_info_option() {
        let cached_epoch = li.ledger_info().epoch();
        let new_epoch = ledger_infos.last().unwrap().ledger_info().epoch();
        let cached_version = li.ledger_info().version();
        let new_version = ledger_infos.last().unwrap().ledger_info().version();
        
        if cached_epoch > new_epoch || 
           (cached_epoch == new_epoch && cached_version >= new_version) {
            return Ok(());
        }
    }
    ledger_metadata_db.set_latest_ledger_info(ledger_infos.last().unwrap().clone());
    Ok(())
}
```

**Recommended: Both options for defense-in-depth**

## Proof of Concept

The race cannot be easily reproduced in a test environment because it requires precise timing and violating the design assumption. However, the following demonstrates the vulnerable code paths:

```rust
// Thread 1: Consensus path
async fn consensus_commit_path() {
    // storage/aptosdb/src/db/aptosdb_writer.rs:78-112
    db.commit_ledger(version, Some(&ledger_info), None)?;
    // Line 107: DB write
    // Line 110: post_commit → line 665: cache update
}

// Thread 2: State sync path (NO LOCK!)
async fn state_sync_path() {
    // storage/aptosdb/src/db/aptosdb_writer.rs:125-241  
    db.finalize_state_snapshot(version, output, ledger_infos)?;
    // Line 223: DB write (can overwrite Thread 1!)
    // Line 236: cache update (can conflict with Thread 1!)
}

// Race condition: If both execute concurrently:
// - DB may have Thread 2's write
// - Cache may have Thread 1's write  
// - Result: Inconsistent state
```

To observe the race in production, monitor for:
- Database version != cached version (requires instrumentation)
- Validators diverging on epoch boundaries
- Failed epoch continuity checks with inconsistent error messages

## Notes

This vulnerability exists due to a defense-in-depth failure: the storage layer assumes higher-level coordination prevents concurrent access, but provides no enforcement. The `commit_lock` mechanism only serializes `commit_ledger` calls among themselves, not against `finalize_state_snapshot`.

While the higher-level handover protocol (via `write_mutex` in ExecutionProxy) is designed to prevent this, storage-layer protection is critical for safety even if coordination bugs exist. The lack of mutual exclusion combined with weak version ordering checks creates a latent race condition that could manifest during edge cases or coordination failures.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L46-49)
```rust
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L571-582)
```rust
        // Verify epoch continuity.
        let current_epoch = self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            ledger_info_with_sig.ledger_info().epoch() == current_epoch,
            "Gap in epoch history. Trying to put in LedgerInfo in epoch: {}, current epoch: {}",
            ledger_info_with_sig.ledger_info().epoch(),
            current_epoch,
        );
```

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

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L94-98)
```rust
    pub(crate) fn get_latest_ledger_info_option(&self) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }
```
