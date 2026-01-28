Based on my thorough analysis of the Aptos Core codebase, I can confirm this is a **VALID MEDIUM SEVERITY VULNERABILITY**.

# Audit Report

## Title
TOCTOU Vulnerability in ChunkExecutor's Pre-Commit Tracking Bypasses Safety Mechanism

## Summary
The `has_pending_pre_commit` flag in `ChunkExecutorInner` is checked before database operations execute, creating a Time-of-Check-Time-of-Use (TOCTOU) vulnerability. When `pre_commit_ledger()` succeeds but `commit_ledger()` fails, the system does not panic as designed, violating the documented safety guarantee for handling pending pre-committed data. [1](#0-0) 

## Finding Description

The vulnerability exists in the `with_inner()` method's error handling logic. The method loads the `has_pending_pre_commit` flag at the start (before operations execute), then executes the provided function. If an error occurs, it checks the flag value that was captured before the operation. [2](#0-1) 

The critical issue occurs when `commit_chunk_impl()` calls `save_transactions()`, which consists of two sequential phases: [3](#0-2) 

**Exploitation Scenario:**

1. Initial state: `has_pending_pre_commit = false` (no pending data in database)
2. `with_inner()` loads flag, sees `false`
3. `commit_chunk_impl()` calls `save_transactions()`
4. `pre_commit_ledger()` succeeds - writes data to database, updates `LedgerCommitProgress` [4](#0-3) 

5. `commit_ledger()` fails - error occurs during commit (I/O error, validation failure, etc.) [5](#0-4) 

6. Error propagates to `with_inner()` error handler
7. Handler checks flag value from step 2 (still `false`)
8. Does NOT panic (should panic per documentation) [6](#0-5) 

9. Line 397 never executes, flag remains `false` [7](#0-6) 

**Result:** Database has pending pre-committed data (`LedgerCommitProgress` > `OverallCommitProgress`), but the flag is `false`. The safety mechanism that should trigger a panic is bypassed.

The flag is only set to `true` at initialization when detecting leftover data, and only set to `false` after successful commits - never set to `true` during runtime when new pending data is created: [8](#0-7) 

## Impact Explanation

**Severity: Medium**

This qualifies as **Medium Severity** under "State inconsistencies requiring manual intervention" per Aptos bug bounty criteria.

**Specific Impacts:**

1. **Safety Mechanism Bypass**: The documented requirement that the system "needs to panic, resulting in a reboot of the node where the DB will truncate the unconfirmed data" is violated.

2. **State Inconsistency Risk**: Pre-committed data remains in the database without proper runtime tracking, though the system will correctly detect this on restart.

3. **Reduced Fault Tolerance**: If subsequent errors occur before restart, the compounding failures may not trigger the safety panic as designed.

This does NOT directly enable fund theft, consensus breaks, or network partitions. The system is designed to recover on restart when it recalculates the flag from database state. However, it degrades the system's ability to handle cascading failures before restart.

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires `commit_ledger()` to fail after `pre_commit_ledger()` succeeds. This can occur due to:
- Disk I/O errors during metadata writes
- Database corruption during commit phase  
- Resource exhaustion (disk full)
- Validation failures in `check_and_put_ledger_info()`

While rare under normal operation, these conditions become more likely during high-load periods, hardware degradation, or resource constraints. The issue is NOT directly exploitable by external attackers but represents a robustness failure during operational stress.

## Recommendation

Set the `has_pending_pre_commit` flag to `true` immediately after `pre_commit_ledger()` succeeds, before attempting `commit_ledger()`. This ensures the flag accurately reflects the current database state during error handling.

Alternative: Re-check the database state in the error handler instead of relying on the pre-loaded flag value.

## Proof of Concept

The vulnerability can be demonstrated by injecting a failure in `commit_ledger()` after `pre_commit_ledger()` succeeds. The fail point at line 274 in `mod.rs` demonstrates the intended error injection pattern: [9](#0-8) 

A complete PoC would require modifying `save_transactions()` to inject a failure after `pre_commit_ledger()` but before `commit_ledger()`, then verifying that the panic does not occur despite pending pre-committed data existing in the database.

## Notes

- The root cause is a TOCTOU (Time-of-Check-Time-of-Use) vulnerability, not specifically a memory ordering issue. The Acquire/Release ordering is appropriate for the atomic operations, but the timing of the check is incorrect.
- On node restart, the system will correctly detect and handle the pending data by recalculating the flag from database state.
- This is a reliability/robustness issue rather than a critical security vulnerability, as it does not enable direct fund theft or consensus manipulation.

### Citations

**File:** execution/executor/src/chunk_executor/mod.rs (L89-106)
```rust
    fn with_inner<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&ChunkExecutorInner<V>) -> Result<T>,
    {
        let locked = self.inner.read();
        let inner = locked.as_ref().expect("not reset");

        let has_pending_pre_commit = inner.has_pending_pre_commit.load(Ordering::Acquire);
        f(inner).map_err(|error| {
            if has_pending_pre_commit {
                panic!(
                    "Hit error with pending pre-committed ledger, panicking. {:?}",
                    error,
                );
            }
            error
        })
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L236-249)
```rust
    pub fn new(db: DbReaderWriter) -> Result<Self> {
        let commit_queue = ChunkCommitQueue::new_from_db(&db.reader)?;

        let next_pre_committed_version = commit_queue.expecting_version();
        let next_synced_version = db.reader.get_synced_version()?.map_or(0, |v| v + 1);
        assert!(next_synced_version <= next_pre_committed_version);
        let has_pending_pre_commit = next_synced_version < next_pre_committed_version;

        Ok(Self {
            db,
            commit_queue: Mutex::new(commit_queue),
            has_pending_pre_commit: AtomicBool::new(has_pending_pre_commit),
            _phantom: PhantomData,
        })
```

**File:** execution/executor/src/chunk_executor/mod.rs (L274-276)
```rust
            fail_point!("executor::commit_chunk", |_| {
                Err(anyhow::anyhow!("Injected error in commit_chunk"))
            });
```

**File:** execution/executor/src/chunk_executor/mod.rs (L394-409)
```rust
    fn commit_chunk(&self) -> Result<ChunkCommitNotification> {
        let _timer = COMMIT_CHUNK.start_timer();
        let executed_chunk = self.commit_chunk_impl()?;
        self.has_pending_pre_commit.store(false, Ordering::Release);

        let commit_notification = {
            let _timer =
                CHUNK_OTHER_TIMERS.timer_with(&["commit_chunk__into_chunk_commit_notification"]);
            executed_chunk
                .output
                .expect_complete_result()
                .make_chunk_commit_notification()
        };

        Ok(commit_notification)
    }
```

**File:** storage/storage-interface/src/lib.rs (L608-628)
```rust
    fn save_transactions(
        &self,
        chunk: ChunkToCommit,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        sync_commit: bool,
    ) -> Result<()> {
        // For reconfig suffix.
        if ledger_info_with_sigs.is_none() && chunk.is_empty() {
            return Ok(());
        }

        if !chunk.is_empty() {
            self.pre_commit_ledger(chunk.clone(), sync_commit)?;
        }
        let version_to_commit = if let Some(ledger_info_with_sigs) = ledger_info_with_sigs {
            ledger_info_with_sigs.ledger_info().version()
        } else {
            chunk.expect_last_version()
        };
        self.commit_ledger(version_to_commit, ledger_info_with_sigs, Some(chunk))
    }
```

**File:** storage/storage-interface/src/lib.rs (L630-638)
```rust
    /// Optimistically persist transactions to the ledger.
    ///
    /// Called by consensus to pre-commit blocks before execution result is agreed on by the
    /// validators.
    ///
    ///   If these blocks are later confirmed to be included in the ledger, commit_ledger should be
    ///       called with a `LedgerInfoWithSignatures`.
    ///   If not, the consensus needs to panic, resulting in a reboot of the node where the DB will
    ///       truncate the unconfirmed data.
```

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
