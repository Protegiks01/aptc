# Audit Report

## Title
Race Condition in finalize_state_snapshot() Causes Validator Node Crash on Restart

## Summary
The `finalize_state_snapshot()` function writes database commit progress markers without acquiring the synchronization locks used by normal consensus commits, creating a race condition that corrupts progress metadata. This causes validator nodes to crash with an assertion failure on restart, requiring manual database intervention.

## Finding Description

The vulnerability exists in the interaction between two commit pathways:

**Normal Consensus Commit Path:** [1](#0-0) 

The normal commit uses a two-phase protocol with explicit locks to prevent concurrent commits, writing `LedgerCommitProgress` first, then `OverallCommitProgress` separately. [2](#0-1) [3](#0-2) 

**State Snapshot Finalization Path:** [4](#0-3) 

Critically, `finalize_state_snapshot()` does NOT acquire either `pre_commit_lock` or `commit_lock`, but writes BOTH progress markers atomically: [5](#0-4) 

**The Race Condition:**

When state sync triggers while normal commits are in progress:

1. Normal commit: `pre_commit_ledger(1000)` writes `LedgerCommitProgress = 1000`, releases `pre_commit_lock`
2. State sync: `finalize_state_snapshot(500)` (NO lock) overwrites `LedgerCommitProgress = 500`  
3. State sync: writes `OverallCommitProgress = 500`
4. Normal commit: `commit_ledger(1000)` writes `OverallCommitProgress = 1000`, overwrites 500

**Result:** `LedgerCommitProgress = 500`, `OverallCommitProgress = 1000`

**The Crash:**

On node restart, the database synchronization code enforces a critical invariant: [6](#0-5) 

The assertion `assert_ge!(ledger_commit_progress, overall_commit_progress)` expects that ledger progress is always >= overall progress (the source of truth). With corrupted metadata where `500 < 1000`, this assertion **fails immediately**, causing the node to panic and crash. [7](#0-6) 

This synchronization happens during `StateStore` initialization, before the node can accept any operations.

## Impact Explanation

**Severity: High** per Aptos Bug Bounty criteria.

This vulnerability causes:
- **Validator node unavailability**: Node crashes on restart and cannot recover automatically
- **Requires manual intervention**: Database must be manually truncated or restored from backup
- **Validator penalties**: Downtime leads to missed blocks and potential slashing
- **Network impact**: If multiple validators are affected, could reduce network participation

While this doesn't directly violate consensus safety or cause fund loss, it meets the **High Severity** criteria of "Validator node slowdowns" and "API crashes" - this is complete node unavailability requiring manual recovery.

The invariant broken is **State Consistency**: The storage system's atomic state transitions are compromised, with progress markers becoming inconsistent across the two-phase commit boundary.

## Likelihood Explanation

**Likelihood: Medium**

The race requires specific timing:
- State sync must be triggered (via `finalize_state_snapshot()`) while normal consensus commits are between the pre-commit and commit phases
- This can occur during:
  - Fast-forward sync when a node falls behind
  - Bootstrap from snapshot
  - Network partition recovery
  - Epoch transitions with concurrent sync operations

The window is narrow (microseconds to milliseconds between pre-commit and commit), but state sync operations are relatively slow (seconds to minutes), increasing collision probability.

**Trigger conditions:**
- Node falls significantly behind (fast-forward sync activates)
- Network delivers sync messages during active commit window  
- No privileged access required - normal network conditions can trigger this

The comment at lines 85-88 acknowledges the handover requirement but the lack of locks in `finalize_state_snapshot()` means it's not enforced: [8](#0-7) 

## Recommendation

`finalize_state_snapshot()` must acquire the same synchronization locks as normal commits to prevent race conditions:

```rust
fn finalize_state_snapshot(
    &self,
    version: Version,
    output_with_proof: TransactionOutputListWithProofV2,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    // Acquire commit lock to prevent races with normal commits
    let _lock = self
        .commit_lock
        .try_lock()
        .expect("Cannot finalize snapshot during concurrent commits.");
    
    // ... rest of existing implementation
}
```

Alternatively, ensure state sync only runs when consensus is completely paused and all pending commits are drained from the pipeline before calling `finalize_state_snapshot()`.

## Proof of Concept

```rust
// Reproduction test demonstrating the race condition
#[test]
fn test_finalize_snapshot_commit_race() {
    use std::sync::Arc;
    use std::thread;
    
    let db = setup_test_db();
    
    // Thread 1: Normal consensus commit to version 1000
    let db_clone1 = Arc::clone(&db);
    let commit_thread = thread::spawn(move || {
        let chunk = create_test_chunk(1000);
        db_clone1.pre_commit_ledger(chunk, false).unwrap();
        // Small delay to widen race window
        thread::sleep(Duration::from_millis(10));
        db_clone1.commit_ledger(1000, None, None).unwrap();
    });
    
    // Thread 2: State sync finalization to version 500
    let db_clone2 = Arc::clone(&db);
    let sync_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(5)); // Start mid-commit
        let output = create_test_output(500);
        db_clone2.finalize_state_snapshot(500, output, &[]).unwrap();
    });
    
    commit_thread.join().unwrap();
    sync_thread.join().unwrap();
    
    // Check for corruption
    let ledger_progress = db.ledger_db.metadata_db()
        .get_ledger_commit_progress().unwrap();
    let overall_progress = db.ledger_db.metadata_db()
        .get_synced_version().unwrap().unwrap();
    
    // This may show: ledger_progress = 500, overall_progress = 1000
    // Which will cause crash on next restart during sync_commit_progress()
    assert!(ledger_progress >= overall_progress, 
        "Race detected: ledger={}, overall={}", ledger_progress, overall_progress);
}
```

To demonstrate the crash, restart the node after this race occurs - the `sync_commit_progress()` assertion will fail during `StateStore` initialization.

## Notes

The vulnerability is subtle because it requires understanding the distributed coordination between consensus, state sync, and the storage layer. The locks exist (`pre_commit_lock`, `commit_lock`) but `finalize_state_snapshot()` was likely implemented separately without awareness of the two-phase commit protocol's synchronization requirements. The comment acknowledges handover is required but the implementation doesn't enforce it at the storage layer.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L44-76)
```rust
    fn pre_commit_ledger(&self, chunk: ChunkToCommit, sync_commit: bool) -> Result<()> {
        gauged_api("pre_commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .pre_commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["pre_commit_ledger"]);

            chunk
                .state_summary
                .latest()
                .global_state_summary
                .log_generation("db_save");

            self.pre_commit_validation(&chunk)?;
            let _new_root_hash =
                self.calculate_and_commit_ledger_and_state_kv(&chunk, self.skip_index_and_usage)?;

            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions__others"]);

            self.state_store.buffered_state().lock().update(
                chunk.result_ledger_state_with_summary(),
                chunk.estimated_total_state_updates(),
                sync_commit || chunk.is_reconfig,
            )?;

            Ok(())
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L85-88)
```rust
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L103-106)
```rust
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L125-130)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
    ) -> Result<()> {
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L207-218)
```rust
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
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L360-365)
```rust
        ledger_metadata_batch
            .put::<DbMetadataSchema>(
                &DbMetadataKey::LedgerCommitProgress,
                &DbMetadataValue::Version(chunk.expect_last_version()),
            )
            .unwrap();
```

**File:** storage/aptosdb/src/state_store/mod.rs (L354-360)
```rust
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
        }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L408-428)
```rust
    // We commit the overall commit progress at the last, and use it as the source of truth of the
    // commit progress.
    pub fn sync_commit_progress(
        ledger_db: Arc<LedgerDb>,
        state_kv_db: Arc<StateKvDb>,
        state_merkle_db: Arc<StateMerkleDb>,
        crash_if_difference_is_too_large: bool,
    ) {
        let ledger_metadata_db = ledger_db.metadata_db();
        if let Some(overall_commit_progress) = ledger_metadata_db
            .get_synced_version()
            .expect("DB read failed.")
        {
            info!(
                overall_commit_progress = overall_commit_progress,
                "Start syncing databases..."
            );
            let ledger_commit_progress = ledger_metadata_db
                .get_ledger_commit_progress()
                .expect("Failed to read ledger commit progress.");
            assert_ge!(ledger_commit_progress, overall_commit_progress);
```
