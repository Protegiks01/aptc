# Audit Report

## Title
State Snapshot Race Condition: Snapshots Can Be Persisted Before Ledger Commit Completes

## Summary
A race condition exists between asynchronous state snapshot persistence and synchronous ledger commit operations. For non-epoch-ending blocks, state snapshots can be fully persisted to disk and become queryable before the corresponding `LedgerInfo` and `OverallCommitProgress` metadata are written, creating a window where the database contains snapshots for uncommitted versions.

## Finding Description

The vulnerability occurs in the consensus pipeline's persisting phase. When `wait_for_commit_ledger()` is called, it waits for the ledger commit to complete, but state snapshots are persisted asynchronously in background threads without synchronization.

**The flow:**

1. **Pre-commit phase**: `pre_commit_ledger()` is called with `sync_commit=false` for non-epoch-ending blocks [1](#0-0) 

2. **Async snapshot enqueueing**: The snapshot is enqueued to `BufferedState` but NOT waited on when `sync_commit=false` [2](#0-1) 

3. **Parallel execution**: While the consensus pipeline proceeds to `wait_for_commit_ledger()`, the background `StateSnapshotCommitter` and `StateMerkleBatchCommitter` threads process and persist the snapshot to disk [3](#0-2) 

4. **Snapshot persistence**: The snapshot is written to the Jellyfish Merkle database and becomes queryable via `get_state_snapshot_before()` [4](#0-3) 

5. **Delayed ledger commit**: Only after the snapshot may already be persisted does `commit_ledger()` write the `LedgerInfo` and `OverallCommitProgress` [5](#0-4) 

**Key evidence of the race:**
- `get_state_snapshot_before()` queries the Merkle database directly without validating against committed versions [6](#0-5) 

- The check for epoch-ending blocks explicitly waits for snapshot persistence, revealing awareness that regular blocks don't have this guarantee [7](#0-6) 

## Impact Explanation

This qualifies as **Medium Severity** per the Aptos bug bounty criteria ("State inconsistencies requiring intervention"):

1. **Backup Corruption Risk**: Backup operations calling `get_state_snapshot_before()` during the race window could capture snapshots for versions not yet committed. If the node crashes before `commit_ledger()` completes, the backup contains an invalid snapshot that cannot be restored against the actual committed ledger. [8](#0-7) 

2. **State Sync Inconsistency**: During the race window, one node could serve a state snapshot for version V to a syncing peer while its own `LedgerInfo` still reflects version V-1. This violates the invariant that queryable snapshots should only exist for committed versions.

3. **Orphaned Snapshots on Crash**: If a node crashes after snapshot persistence but before ledger commit, the database contains orphaned snapshots (versions > `OverallCommitProgress`). While these are eventually ignored during recovery, they represent wasted storage and potential confusion in debugging.

4. **Query Inconsistency**: External services querying both `get_state_snapshot_before()` and `get_latest_ledger_info()` simultaneously may observe that snapshot_version > ledger_version, violating consistency expectations.

## Likelihood Explanation

**Likelihood: High**

This race occurs on every non-epoch-ending block commit in normal operation:
- The async snapshot pipeline has buffer sizes of 1 (BufferedState) and 0 (rendezvous channel to batch committer), but this only provides backpressure, not synchronization [9](#0-8) [10](#0-9) 

- On high-throughput networks, the race window can be substantial as blocks are committed rapidly
- The vulnerability requires no attacker action—it's an inherent timing issue in the design
- Backup operations, state sync requests, or query APIs can observe the inconsistency at any time

## Recommendation

**Option 1: Synchronous Commit for Critical Blocks**
Extend the synchronous commit guarantee (currently only for epoch-ending blocks) to all blocks that will be exposed via backup/state-sync APIs. Modify the `pre_commit_ledger` call to pass `sync_commit=true` for such blocks.

**Option 2: Deferred Snapshot Visibility**
Add a version check in `get_state_snapshot_before()` to ensure returned snapshots don't exceed the committed version from `OverallCommitProgress`:

```rust
fn get_state_snapshot_before(
    &self,
    next_version: Version,
) -> Result<Option<(Version, HashValue)>> {
    let committed_version = self.ledger_db.metadata_db().get_synced_version()?;
    let capped_next_version = next_version.min(committed_version.map_or(0, |v| v + 1));
    
    self.state_merkle_db
        .get_state_snapshot_version_before(capped_next_version)?
        .map(|ver| Ok((ver, self.state_merkle_db.get_root_hash(ver)?)))
        .transpose()
}
```

**Option 3: Atomic Commit Guarantee**
Modify `commit_ledger` to wait for the snapshot persistence to complete before returning:
```rust
// In commit_ledger, after writing LedgerInfo
if let Some(li) = ledger_info_with_sigs {
    // Ensure snapshot is persisted before completing commit
    self.state_store.buffered_state().lock().sync_commit();
}
```

## Proof of Concept

While this is a timing-based race condition difficult to reproduce deterministically in a test, the vulnerability can be demonstrated through code inspection and the following scenario:

1. Deploy a validator node with instrumentation logging snapshot persistence and ledger commit times
2. Submit blocks at high throughput to maximize the race window
3. Run concurrent backup operations via `get_state_snapshot_before()` while blocks are committing
4. Observe that backup captures snapshot at version V while `get_latest_ledger_info()` returns version V-1
5. Simulate crash (kill -9) during this window
6. On restart, verify that orphaned snapshot exists but `OverallCommitProgress` shows earlier version

The code paths clearly show the race:
- Async enqueueing without wait: [11](#0-10) 
- Independent persistence thread: [12](#0-11) 
- No version validation in queries: [13](#0-12) 

## Notes

The vulnerability is mitigated for epoch-ending blocks where `sync_commit` is forced to true, ensuring snapshot persistence completes before ledger commit proceeds. This indicates the developers were aware of the ordering requirement for critical blocks but chose async commits for performance on regular blocks. The security question correctly identifies this as a Medium severity state consistency issue rather than a Critical consensus or funds-at-risk vulnerability.

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L350-360)
```rust
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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L103-107)
```rust
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
            self.ledger_db.metadata_db().write_schemas(ledger_batch)?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L584-594)
```rust
        // Ensure that state tree at the end of the epoch is persisted.
        if ledger_info_with_sig.ledger_info().ends_epoch() {
            let state_snapshot = self.state_store.get_state_snapshot_before(version + 1)?;
            ensure!(
                state_snapshot.is_some() && state_snapshot.as_ref().unwrap().0 == version,
                "State checkpoint not persisted at the end of the epoch, version {}, next_epoch {}, snapshot in db: {:?}",
                version,
                ledger_info_with_sig.ledger_info().next_block_epoch(),
                state_snapshot,
            );
        }
```

**File:** consensus/src/pipeline/persisting_phase.rs (L65-72)
```rust
        for b in &blocks {
            if let Some(tx) = b.pipeline_tx().lock().as_mut() {
                tx.commit_proof_tx
                    .take()
                    .map(|tx| tx.send(commit_ledger_info.clone()));
            }
            b.wait_for_commit_ledger().await;
        }
```

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L52-115)
```rust
    pub fn run(self) {
        while let Ok(msg) = self.state_merkle_batch_receiver.recv() {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["batch_committer_work"]);
            match msg {
                CommitMessage::Data(StateMerkleCommit {
                    snapshot,
                    hot_batch,
                    cold_batch,
                }) => {
                    let base_version = self.persisted_state.get_state_summary().version();
                    let current_version = snapshot
                        .version()
                        .expect("Current version should not be None");

                    // commit jellyfish merkle nodes
                    let _timer =
                        OTHER_TIMERS_SECONDS.timer_with(&["commit_jellyfish_merkle_nodes"]);
                    if let Some(hot_state_merkle_batch) = hot_batch {
                        self.commit(
                            self.state_db
                                .hot_state_merkle_db
                                .as_ref()
                                .expect("Hot state merkle db must exist."),
                            current_version,
                            hot_state_merkle_batch,
                        )
                        .expect("Hot state merkle nodes commit failed.");
                    }
                    self.commit(&self.state_db.state_merkle_db, current_version, cold_batch)
                        .expect("State merkle nodes commit failed.");

                    info!(
                        version = current_version,
                        base_version = base_version,
                        root_hash = snapshot.summary().root_hash(),
                        hot_root_hash = snapshot.summary().hot_root_hash(),
                        "State snapshot committed."
                    );
                    LATEST_SNAPSHOT_VERSION.set(current_version as i64);
                    // TODO(HotState): no pruning for hot state right now, since we always reset it
                    // upon restart.
                    self.state_db
                        .state_merkle_pruner
                        .maybe_set_pruner_target_db_version(current_version);
                    self.state_db
                        .epoch_snapshot_pruner
                        .maybe_set_pruner_target_db_version(current_version);

                    self.check_usage_consistency(&snapshot).unwrap();

                    snapshot
                        .summary()
                        .global_state_summary
                        .log_generation("buffered_state_commit");
                    self.persisted_state.set(snapshot);
                },
                CommitMessage::Sync(finish_sender) => finish_sender.send(()).unwrap(),
                CommitMessage::Exit => {
                    break;
                },
            }
        }
        trace!("State merkle batch committing thread exit.")
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L149-158)
```rust
    /// Returns the latest state snapshot strictly before `next_version` if any.
    fn get_state_snapshot_before(
        &self,
        next_version: Version,
    ) -> Result<Option<(Version, HashValue)>> {
        self.state_merkle_db
            .get_state_snapshot_version_before(next_version)?
            .map(|ver| Ok((ver, self.state_merkle_db.get_root_hash(ver)?)))
            .transpose()
    }
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L132-137)
```rust
    pub fn get_state_snapshot_before(
        &self,
        version: Version,
    ) -> Result<Option<(Version, HashValue)>> {
        self.aptosdb.get_state_snapshot_before(version)
    }
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L28-29)
```rust
pub(crate) const ASYNC_COMMIT_CHANNEL_BUFFER_SIZE: u64 = 1;
pub(crate) const TARGET_SNAPSHOT_INTERVAL_IN_VERSION: u64 = 100_000;
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L123-134)
```rust
    fn enqueue_commit(&mut self, checkpoint: StateWithSummary) {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["buffered_state___enqueue_commit"]);

        self.state_commit_sender
            .send(CommitMessage::Data(checkpoint.clone()))
            .unwrap();
        // n.b. if the latest state is not a (the latest) checkpoint, the items between them are
        // not counted towards the next commit. If this becomes a concern we can count the items
        // instead of putting it 0 here.
        self.estimated_items = 0;
        self.last_snapshot = checkpoint;
    }
```

**File:** storage/aptosdb/src/state_store/state_snapshot_committer.rs (L51-65)
```rust
    const CHANNEL_SIZE: usize = 0;

    pub fn new(
        state_db: Arc<StateDb>,
        state_snapshot_commit_receiver: Receiver<CommitMessage<StateWithSummary>>,
        last_snapshot: StateWithSummary,
        persisted_state: PersistedState,
    ) -> Self {
        // Note: This is to ensure we cache nodes in memory from previous batches before they get committed to DB.
        const_assert!(
            StateSnapshotCommitter::CHANNEL_SIZE < VersionedNodeCache::NUM_VERSIONS_TO_CACHE
        );
        // Rendezvous channel
        let (state_merkle_batch_commit_sender, state_merkle_batch_commit_receiver) =
            mpsc::sync_channel(Self::CHANNEL_SIZE);
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L323-348)
```rust
    pub fn get_state_snapshot_version_before(
        &self,
        next_version: Version,
    ) -> Result<Option<Version>> {
        if next_version > 0 {
            let max_possible_version = next_version - 1;
            let mut iter = self.metadata_db().rev_iter::<JellyfishMerkleNodeSchema>()?;
            iter.seek_for_prev(&NodeKey::new_empty_path(max_possible_version))?;
            if let Some((key, _node)) = iter.next().transpose()? {
                let version = key.version();
                if self
                    .metadata_db()
                    .get::<JellyfishMerkleNodeSchema>(&NodeKey::new_empty_path(version))?
                    .is_some()
                {
                    return Ok(Some(version));
                }
                // Since we split state merkle commit into multiple batches, it's possible that
                // the root is not committed yet. In this case we need to look at the previous
                // root.
                return self.get_state_snapshot_version_before(version);
            }
        }
        // No version before genesis.
        Ok(None)
    }
```
