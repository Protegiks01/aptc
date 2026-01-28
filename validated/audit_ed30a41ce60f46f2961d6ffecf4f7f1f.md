# Audit Report

## Title
TOCTOU Race Condition in State Snapshot Backup Endpoint Allows Iterator Failure on Pruned Data

## Summary
The backup service's `state_snapshot` endpoint creates a Jellyfish Merkle tree iterator without validating that the requested version is still readable (not pruned). If the state merkle pruner runs concurrently and deletes nodes between iterator creation and consumption, the iterator will fail with `AptosDbError::NotFound` during traversal, causing backup failures and potential service disruption.

## Finding Description

The vulnerability exists in the backup service's state snapshot functionality, which provides HTTP endpoints for retrieving state data at specific versions. The critical flaw is a missing version validation check combined with concurrent pruning operations that can delete data mid-stream.

**Code Flow:**

1. The `state_snapshot` endpoint accepts a version parameter and calls `get_state_item_iter` on the backup handler. [1](#0-0) 

2. `BackupHandler::get_state_item_iter` directly calls `StateStore::get_state_key_and_value_iter` without any version validation. [2](#0-1) 

3. `StateStore::get_state_key_and_value_iter` creates a `JellyfishMerkleIterator` directly without checking `min_readable_version`. [3](#0-2) 

4. During iteration, the `JellyfishMerkleIterator` calls `reader.get_node()` to traverse the tree. [4](#0-3) 

5. The `TreeReader::get_node_with_tag` method returns `AptosDbError::NotFound` if nodes are missing from the database. [5](#0-4) 

**The Race Condition:**

The state merkle pruner runs in a background worker thread that continuously prunes old data. [6](#0-5) 

The pruner manager updates `min_readable_version` atomically and then instructs the worker to delete nodes. [7](#0-6) 

The actual node deletion happens in batches via `batch.delete::<JellyfishMerkleNodeSchema>`. [8](#0-7) 

Between the iterator creation and its consumption (which happens in a spawned blocking task), the pruner can delete the exact nodes the iterator needs to traverse, causing mid-stream failures. [9](#0-8) 

**Missing Protection:**

The proper AptosDB reader interface performs version validation before creating iterators. For example, `get_state_value_chunk_iter` calls `error_if_state_merkle_pruned` before accessing state data. [10](#0-9) 

The `error_if_state_merkle_pruned` function checks both the state merkle pruner and epoch snapshot pruner's minimum readable versions. [11](#0-10) 

However, the backup handler bypasses this protection by directly accessing `StateStore`, which lacks version validation.

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria)

This vulnerability qualifies as HIGH severity under the "API crashes" category because:

1. **Backup Service Disruption**: The backup service will fail mid-stream when iterating over pruned versions, returning errors to clients and potentially causing incomplete backups.

2. **Disaster Recovery Impact**: Backup failures undermine disaster recovery capabilities, which are critical for validator operations and network resilience.

3. **Exploitable for DoS**: An attacker can intentionally request versions near the prune boundary to trigger consistent failures, effectively disrupting the backup service.

4. **No Graceful Degradation**: The error occurs mid-stream during HTTP response streaming, not at request validation time, leading to poor user experience and wasted resources.

While this doesn't directly affect consensus or cause fund loss, it significantly impacts the availability and reliability of critical infrastructure services.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to occur in production environments because:

1. **Normal Operations**: Pruning is enabled by default with a 1,000,000 version window and actively runs in background threads during normal validator operation.

2. **Common Backup Patterns**: Backup services request state snapshots at regular intervals. Even requests for recent versions can be affected if the blockchain advances rapidly and the pruner catches up during the lengthy iteration process.

3. **No Synchronization**: There is no lock or synchronization mechanism preventing the pruner from deleting data while iterators are actively traversing.

4. **Wide Race Window**: Iterating over large state trees can take significant time (potentially minutes), providing ample opportunity for the race condition to manifest as the prune window advances.

5. **Concurrent Architecture**: The backup service uses `tokio::task::spawn_blocking` for streaming responses, and the pruner runs in separate worker threads, creating natural concurrency without coordination.

## Recommendation

Add version validation at the backup handler level before creating iterators:

```rust
pub fn get_state_item_iter(
    &self,
    version: Version,
    start_idx: usize,
    limit: usize,
) -> Result<impl Iterator<Item = Result<(StateKey, StateValue)>> + Send + use<>> {
    // Add validation before creating iterator
    self.error_if_state_merkle_pruned("State snapshot", version)?;
    
    let iterator = self
        .state_store
        .get_state_key_and_value_iter(version, start_idx)?
        .take(limit)
        .enumerate()
        .map(move |(idx, res)| {
            BACKUP_STATE_SNAPSHOT_VERSION.set(version as i64);
            BACKUP_STATE_SNAPSHOT_LEAF_IDX.set((start_idx + idx) as i64);
            res
        });
    Ok(Box::new(iterator))
}
```

The `error_if_state_merkle_pruned` method should be accessible to the `BackupHandler`, either by adding it as a method or by providing access to the necessary pruner managers.

## Proof of Concept

While a full PoC would require setting up a running Aptos node with pruning enabled, the vulnerability can be demonstrated by:

1. Starting a backup service with pruning enabled (default configuration)
2. Requesting a state snapshot at a version near the prune boundary
3. Ensuring the iteration takes significant time (e.g., large state tree)
4. Allowing the blockchain to advance and the pruner to catch up
5. Observing the `AptosDbError::NotFound` error mid-stream during iteration

The race condition is inherent in the concurrent architecture with no synchronization between backup operations and pruning.

## Notes

The vulnerability is valid because:
- All affected files are in the in-scope `storage/` directory
- The issue can be triggered through normal API usage without requiring trusted role compromise
- It qualifies as "API crashes" under HIGH severity in the Aptos bug bounty program
- The missing validation is a clear deviation from the proper validation pattern used elsewhere in the codebase
- The concurrent architecture creates a natural race condition with high likelihood of occurrence in production environments

### Citations

**File:** storage/backup/backup-service/src/handlers/mod.rs (L49-56)
```rust
    let state_snapshot = warp::path!(Version)
        .map(move |version| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT, move |bh, sender| {
                bh.get_state_item_iter(version, 0, usize::MAX)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L145-162)
```rust
    pub fn get_state_item_iter(
        &self,
        version: Version,
        start_idx: usize,
        limit: usize,
    ) -> Result<impl Iterator<Item = Result<(StateKey, StateValue)>> + Send + use<>> {
        let iterator = self
            .state_store
            .get_state_key_and_value_iter(version, start_idx)?
            .take(limit)
            .enumerate()
            .map(move |(idx, res)| {
                BACKUP_STATE_SNAPSHOT_VERSION.set(version as i64);
                BACKUP_STATE_SNAPSHOT_LEAF_IDX.set((start_idx + idx) as i64);
                res
            });
        Ok(Box::new(iterator))
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1064-1081)
```rust
    pub fn get_state_key_and_value_iter(
        self: &Arc<Self>,
        version: Version,
        start_idx: usize,
    ) -> Result<impl Iterator<Item = Result<(StateKey, StateValue)>> + Send + Sync + use<>> {
        let store = Arc::clone(self);
        Ok(JellyfishMerkleIterator::new_by_index(
            Arc::clone(&self.state_merkle_db),
            version,
            start_idx,
        )?
        .map(move |res| match res {
            Ok((_hashed_key, (key, version))) => {
                Ok((key.clone(), store.expect_value_by_version(&key, version)?))
            },
            Err(err) => Err(err),
        }))
    }
```

**File:** storage/jellyfish-merkle/src/iterator/mod.rs (L207-255)
```rust
    pub fn new_by_index(reader: Arc<R>, version: Version, start_idx: usize) -> Result<Self> {
        let mut parent_stack = vec![];

        let mut current_node_key = NodeKey::new_empty_path(version);
        let mut current_node = reader.get_node(&current_node_key)?;
        if start_idx >= current_node.leaf_count() {
            return Ok(Self {
                reader,
                version,
                parent_stack,
                done: true,
                phantom_value: PhantomData,
            });
        }

        let mut leaves_skipped = 0;
        for _ in 0..=ROOT_NIBBLE_HEIGHT {
            match current_node {
                Node::Leaf(_) => {
                    ensure!(
                        leaves_skipped == start_idx,
                        "Bug: The leaf should be the exact one we are looking for.",
                    );
                    return Ok(Self {
                        reader,
                        version,
                        parent_stack,
                        done: false,
                        phantom_value: PhantomData,
                    });
                },
                Node::Internal(internal_node) => {
                    let (nibble, child) =
                        Self::skip_leaves(&internal_node, &mut leaves_skipped, start_idx)?;
                    let next_node_key = current_node_key.gen_child_node_key(child.version, nibble);
                    parent_stack.push(NodeVisitInfo::new_next_child_to_visit(
                        current_node_key,
                        internal_node,
                        nibble,
                    ));
                    current_node_key = next_node_key;
                },
                Node::Null => unreachable!("Null node has leaf count 0 so here is unreachable"),
            };
            current_node = reader.get_node(&current_node_key)?;
        }

        db_other_bail!("Bug: potential infinite loop.");
    }
```

**File:** storage/jellyfish-merkle/src/lib.rs (L126-129)
```rust
    fn get_node_with_tag(&self, node_key: &NodeKey, tag: &str) -> Result<Node<K>> {
        self.get_node_option(node_key, tag)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Missing node at {:?}.", node_key)))
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

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L159-174)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());

        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&[S::name(), "min_readable"])
            .set(min_readable_version as i64);

        self.pruner_worker
            .as_ref()
            .unwrap()
            .set_target_db_version(min_readable_version);
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L73-76)
```rust
            indices.into_iter().try_for_each(|index| {
                batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
                batch.delete::<S>(&index)
            })?;
```

**File:** storage/backup/backup-service/src/handlers/utils.rs (L46-65)
```rust
pub(super) fn reply_with_bytes_sender<F>(
    backup_handler: &BackupHandler,
    endpoint: &'static str,
    f: F,
) -> Box<dyn Reply>
where
    F: FnOnce(BackupHandler, &mut bytes_sender::BytesSender) -> DbResult<()> + Send + 'static,
{
    let (sender, stream) = bytes_sender::BytesSender::new(endpoint);

    // spawn and forget, error propagates through the `stream: TryStream<_>`
    let bh = backup_handler.clone();
    let _join_handle = tokio::task::spawn_blocking(move || {
        let _timer =
            BACKUP_TIMER.timer_with(&[&format!("backup_service_bytes_sender_{}", endpoint)]);
        abort_on_error(f)(bh, sender)
    });

    Box::new(Response::new(Body::wrap_stream(stream)))
}
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L893-909)
```rust
    fn get_state_value_chunk_iter(
        &self,
        version: Version,
        first_index: usize,
        chunk_size: usize,
    ) -> Result<Box<dyn Iterator<Item = Result<(StateKey, StateValue)>> + '_>> {
        gauged_api("get_state_value_chunk_iter", || {
            self.error_if_state_merkle_pruned("State merkle", version)?;
            let state_value_chunk_iter =
                self.state_store
                    .get_value_chunk_iter(version, first_index, chunk_size)?;
            Ok(Box::new(state_value_chunk_iter)
                as Box<
                    dyn Iterator<Item = Result<(StateKey, StateValue)>> + '_,
                >)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L273-303)
```rust
    pub(super) fn error_if_state_merkle_pruned(
        &self,
        data_type: &str,
        version: Version,
    ) -> Result<()> {
        let min_readable_version = self
            .state_store
            .state_db
            .state_merkle_pruner
            .get_min_readable_version();
        if version >= min_readable_version {
            return Ok(());
        }

        let min_readable_epoch_snapshot_version = self
            .state_store
            .state_db
            .epoch_snapshot_pruner
            .get_min_readable_version();
        if version >= min_readable_epoch_snapshot_version {
            self.ledger_db.metadata_db().ensure_epoch_ending(version)
        } else {
            bail!(
                "{} at version {} is pruned. snapshots are available at >= {}, epoch snapshots are available at >= {}",
                data_type,
                version,
                min_readable_version,
                min_readable_epoch_snapshot_version,
            )
        }
    }
```
