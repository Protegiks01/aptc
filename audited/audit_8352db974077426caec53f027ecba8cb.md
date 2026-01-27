# Audit Report

## Title
Checkpoint State Visibility Before Commit Finalization Allows Clients to Observe Rollback-Vulnerable State

## Summary
The storage layer exposes checkpoint state to clients immediately after pre-commit completes, before the block is officially committed via `OverallCommitProgress`. Async checkpoint persistence combined with this early visibility window allows clients to query state and obtain Merkle proofs for blocks that can be rolled back on crash, violating state consistency guarantees.

## Finding Description

The Aptos consensus pipeline implements a two-phase commit process where blocks transition through `pre_commit` and then `commit_ledger` phases. During `pre_commit`, state data is written to disk and the `current_state` is updated immediately, making the checkpoint visible to external queries. However, the block is not officially committed until `OverallCommitProgress` is updated in `commit_ledger`. [1](#0-0) 

During pre-commit, `buffered_state.update()` is called, which immediately updates the shared `current_state`: [2](#0-1) [3](#0-2) 

The `current_state` is shared with external APIs and becomes immediately visible at line 175. The checkpoint is sent for async Merkle tree persistence (line 176), but the block is not yet committed.

External clients can query this pre-committed state: [4](#0-3) [5](#0-4) 

Notice that `get_state_value_by_version` only checks for pruning, not whether the version is committed. Clients can query any version up to `get_pre_committed_version()`, including blocks that haven't completed `commit_ledger`.

If a crash occurs between pre-commit and commit completion, the system performs truncation on restart: [6](#0-5) 

This truncates all data back to `OverallCommitProgress`, invalidating state and proofs that clients may have already received for the pre-committed but not yet fully committed blocks.

## Impact Explanation

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." Clients can observe and store Merkle proofs for state that is later rolled back, leading to the following impacts:

1. **Client Decision Inconsistency**: External services (wallets, dApps, bridges) making decisions based on queried state may act on data that gets rolled back, leading to incorrect off-chain state.

2. **Proof Invalidation**: Clients storing Merkle proofs for auditing or verification purposes will have cryptographically valid proofs for state versions that no longer exist in the committed chain after truncation.

3. **Version Reuse with Different State**: After truncation and re-execution, the same version number can contain different state, making previously obtained proofs for that version misleading.

This qualifies as **MEDIUM severity** per the Aptos bug bounty criteria: "State inconsistencies requiring intervention" - while not directly causing fund loss, it breaks state query guarantees and could lead to incorrect client behavior requiring manual intervention.

## Likelihood Explanation

**Likelihood: Medium-High**

This issue can occur during normal operation under the following conditions:

1. **Validator Crash During Commit Window**: Any validator crash between `pre_commit_block` completing and `commit_ledger` completing will trigger the vulnerability
2. **No Malicious Actor Required**: This is a race condition inherent to the system design, not requiring active exploitation
3. **Client Query Timing**: Clients querying state immediately after block execution (seeking low latency) are most affected

The window is relatively short but occurs for every block. Given validator restarts due to crashes, upgrades, or network issues, this scenario will occur in production.

## Recommendation

Implement version-based access control in state query APIs to prevent clients from querying uncommitted state:

```rust
fn get_state_value_by_version(
    &self,
    state_store_key: &StateKey,
    version: Version,
) -> Result<Option<StateValue>> {
    gauged_api("get_state_value_by_version", || {
        // Add committed version check
        let committed_version = self.ledger_db.metadata_db().get_synced_version()?
            .ok_or_else(|| AptosDbError::NotFound("No committed version".to_string()))?;
        
        ensure!(
            version <= committed_version,
            "Cannot query uncommitted version {}. Latest committed: {}",
            version,
            committed_version
        );
        
        self.error_if_state_kv_pruned("StateValue", version)?;
        self.state_store.get_state_value_by_version(state_store_key, version)
    })
}
```

Apply the same check to `get_state_value_with_proof_by_version_ext` and `get_state_proof_by_version_ext`.

Alternatively, if pre-committed state access is required for performance, introduce explicit API variants (e.g., `get_state_value_by_version_uncommitted`) with clear documentation that returned data may be rolled back, and return a finality indicator with query results.

## Proof of Concept

This requires integration testing with consensus to demonstrate:

```rust
// Pseudo-code for reproduction
#[test]
fn test_checkpoint_rollback_visibility() {
    // 1. Start validator node
    let (executor, storage) = setup_test_node();
    
    // 2. Execute and pre-commit block N
    executor.execute_and_update_state(block_n, parent_id, config)?;
    executor.ledger_update(block_n_id, parent_id)?;
    executor.pre_commit_block(block_n_id)?;
    
    // 3. Query state at version N (should succeed)
    let pre_committed_version = storage.get_pre_committed_version()?.unwrap();
    assert_eq!(pre_committed_version, version_n);
    
    let (value, proof) = storage.get_state_value_with_proof_by_version_ext(
        &key_hash,
        version_n,
        root_depth,
        false
    )?;
    assert!(value.is_some());
    
    // 4. Simulate crash before commit_ledger completes
    // (by not calling executor.commit_ledger)
    drop(executor);
    
    // 5. Restart node - triggers truncation
    let storage_after_restart = reopen_storage();
    
    // 6. Committed version should be N-1
    let committed_version = storage_after_restart.get_synced_version()?.unwrap();
    assert_eq!(committed_version, version_n - 1);
    
    // 7. Proof obtained in step 3 is now invalid for the committed chain
    // The version N either doesn't exist or has different state after re-execution
}
```

## Notes

The vulnerability stems from the deliberate design choice to expose pre-committed state for performance optimization (reducing query latency). The system provides both `get_synced_version()` and `get_pre_committed_version()` APIs, but state query methods don't enforce that queries are restricted to the synced version. This creates a consistency gap where checkpoints become observable before official commit, violating atomicity from an external observer's perspective.

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L336-360)
```rust
    fn pre_commit_block(&self, block_id: HashValue) -> ExecutorResult<()> {
        let _timer = COMMIT_BLOCKS.start_timer();
        info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
            "pre_commit_block",
        );

        let block = self.block_tree.get_block(block_id)?;

        fail_point!("executor::pre_commit_block", |_| {
            Err(anyhow::anyhow!("Injected error in pre_commit_block.").into())
        });

        let output = block.output.expect_complete_result();
        let num_txns = output.num_transactions_to_commit();
        if num_txns != 0 {
            let _timer = SAVE_TRANSACTIONS.start_timer();
            self.db
                .writer
                .pre_commit_ledger(output.as_chunk_to_commit(), false)?;
            TRANSACTIONS_SAVED.observe(num_txns as f64);
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L68-72)
```rust
            self.state_store.buffered_state().lock().update(
                chunk.result_ledger_state_with_summary(),
                chunk.estimated_total_state_updates(),
                sync_commit || chunk.is_reconfig,
            )?;
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L156-179)
```rust
    pub fn update(
        &mut self,
        new_state: LedgerStateWithSummary,
        estimated_new_items: usize,
        sync_commit: bool,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["buffered_state___update"]);

        let old_state = self.current_state_locked().clone();
        assert!(new_state.is_descendant_of(&old_state));

        self.estimated_items += estimated_new_items;
        let version = new_state.last_checkpoint().version();

        let last_checkpoint = new_state.last_checkpoint().clone();
        // Commit state only if there is a new checkpoint, eases testing and make estimated
        // buffer size a tad more realistic.
        let checkpoint_to_commit_opt =
            (old_state.next_version() < last_checkpoint.next_version()).then_some(last_checkpoint);
        *self.current_state_locked() = new_state;
        self.maybe_commit(checkpoint_to_commit_opt, sync_commit);
        Self::report_last_checkpoint_version(version);
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L137-141)
```rust
    fn get_pre_committed_version(&self) -> Result<Option<Version>> {
        gauged_api("get_pre_committed_version", || {
            Ok(self.state_store.current_state_locked().version())
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L631-642)
```rust
    fn get_state_value_by_version(
        &self,
        state_store_key: &StateKey,
        version: Version,
    ) -> Result<Option<StateValue>> {
        gauged_api("get_state_value_by_version", || {
            self.error_if_state_kv_pruned("StateValue", version)?;

            self.state_store
                .get_state_value_by_version(state_store_key, version)
        })
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L410-449)
```rust
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

            let state_kv_commit_progress = state_kv_db
                .metadata_db()
                .get::<DbMetadataSchema>(&DbMetadataKey::StateKvCommitProgress)
                .expect("Failed to read state K/V commit progress.")
                .expect("State K/V commit progress cannot be None.")
                .expect_version();
            assert_ge!(state_kv_commit_progress, overall_commit_progress);

            // LedgerCommitProgress was not guaranteed to commit after all ledger changes finish,
            // have to attempt truncating every column family.
            info!(
                ledger_commit_progress = ledger_commit_progress,
                "Attempt ledger truncation...",
            );
            let difference = ledger_commit_progress - overall_commit_progress;
            if crash_if_difference_is_too_large {
                assert_le!(difference, MAX_COMMIT_PROGRESS_DIFFERENCE);
            }
            truncate_ledger_db(ledger_db.clone(), overall_commit_progress)
                .expect("Failed to truncate ledger db.");
```
