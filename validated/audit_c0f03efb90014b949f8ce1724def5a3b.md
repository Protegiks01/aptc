# Audit Report

## Title
Atomic Violation in State Merkle Tree Restore Leading to Unrecoverable Database Corruption

## Summary
The state restore mechanism performs non-atomic sequential writes across 16 separate RocksDB database shards without transactional coordination. When I/O errors, crashes, or disk exhaustion occur during these writes, some shards are permanently committed while others remain unwritten, creating database corruption that requires manual deletion and restart.

## Finding Description

This vulnerability exists in the state snapshot restoration flow where frozen Merkle tree nodes are written to 16 physically separate RocksDB databases sequentially without any distributed transaction coordinator.

**Technical Flow:**

When `async_commit` is enabled, `add_chunk_impl()` spawns an asynchronous write operation that calls `write_node_batch()`. [1](#0-0) 

The `write_node_batch()` method splits nodes into a top-level batch and 16 shard batches based on each node's shard ID, then calls `commit_no_progress()`. [2](#0-1) 

The critical vulnerability is in `commit_no_progress()`, which is explicitly "only used by fast sync / restore". This method writes to 16 separate database shards sequentially in a loop using the `?` operator. [3](#0-2) 

Each shard is a physically separate RocksDB database instance, confirmed by the initialization code that opens 16 distinct databases with separate paths. [4](#0-3) 

**Why Atomicity is Violated:**

Each `write_schemas()` call is atomic only for that specific RocksDB database. There is NO distributed transaction coordinator across the 16 separate databases. When an error occurs at shard N, the `?` operator causes immediate return, but shards 0 through N-1 have already been durably committed by RocksDB and CANNOT be rolled back.

**Why Recovery Fails:**

The `commit_no_progress` method explicitly does not track progress metadata (unlike the regular `commit()` method). [5](#0-4) 

The database initialization includes a truncation mechanism that checks for overall commit progress and truncates shards accordingly. However, when `get_state_merkle_commit_progress()` returns `None` (which it will during restore since no progress is tracked), the truncation is completely skipped. [6](#0-5) 

The crash recovery mechanism `recover_partial_nodes()` attempts to reconstruct the tree state by walking up from the rightmost leaf and scanning for existing nodes in storage. [7](#0-6) 

With partial shard writes, some child nodes exist (in written shards) while siblings are missing (in unwritten shards). The recovery scans each possible child position and includes whatever exists, creating a structurally inconsistent tree. [8](#0-7) 

The `StateStore::reset()` method only recreates in-memory state from disk without cleaning up corrupted on-disk data. [9](#0-8) 

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring manual intervention" per Aptos bug bounty criteria:

1. **Non-Recoverable Without Manual Intervention**: The partial commit creates permanently corrupted storage. The database contains some nodes in certain shards but not in others, violating Merkle tree structure invariants. No automatic recovery mechanism exists.

2. **Requires Manual Database Deletion**: Affected validators must manually delete all state merkle data directories and restart state restore from scratch, potentially taking hours to days.

3. **Operational Impact**: Any validator performing state restore is vulnerable during initial node setup, disaster recovery, or state snapshot operations.

This does NOT qualify as Critical because:
- It does not enable fund theft
- It does not cause permanent network halts  
- It does not directly break consensus (only affects validators in restore mode, not participating in consensus)
- It is recoverable through manual intervention

## Likelihood Explanation

**Moderate Likelihood:**

1. **Realistic Triggers**: Disk space exhaustion during multi-GB state sync, storage hardware I/O errors, process crashes, network storage disconnections, or out-of-memory conditions are all realistic scenarios that require no attacker action.

2. **Wide Surface**: Affects any validator performing initial sync, disaster recovery, or regular state backup/restore operations.

3. **No Protection Mechanisms**: The code has no retry logic, no two-phase commit, no post-write integrity verification, and progress tracking is explicitly disabled by design.

## Recommendation

Implement one of the following solutions:

1. **Add Progress Tracking**: Modify `commit_no_progress` to record progress metadata before writing each shard, enabling the existing truncation mechanism to clean up partial writes on restart.

2. **Atomic Batch Write**: Implement a two-phase commit protocol across all 16 shard databases, or use RocksDB's transaction API if all shards can be consolidated into column families of a single database.

3. **Write-Ahead Logging**: Record intended writes in a separate log before executing them, allowing detection and rollback of partial writes during recovery.

4. **Integrity Verification**: Add verification after each `commit_no_progress` call to detect partial writes and automatically trigger cleanup before continuing.

## Proof of Concept

This vulnerability can be reproduced by:

1. Starting a state restore operation with `async_commit=true`
2. Injecting an I/O error or killing the process during sequential shard writes in `commit_no_progress()`
3. Restarting the restore process
4. Observing that `recover_partial_nodes()` reconstructs an inconsistent tree from partial shard data
5. Verification failures on subsequent chunks due to corrupted tree structure

The technical flow has been validated through codebase analysis showing the sequential non-atomic writes, lack of progress tracking, and inability of the recovery mechanism to handle partial shard states.

### Citations

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L267-334)
```rust
    fn recover_partial_nodes(
        store: &dyn TreeReader<K>,
        version: Version,
        rightmost_leaf_node_key: NodeKey,
    ) -> Result<Vec<InternalInfo<K>>> {
        ensure!(
            !rightmost_leaf_node_key.nibble_path().is_empty(),
            "Root node would not be written until entire restoration process has completed \
             successfully.",
        );

        // Start from the parent of the rightmost leaf. If this internal node exists in storage, it
        // is not a partial node. Go to the parent node and repeat until we see a node that does
        // not exist. This node and all its ancestors will be the partial nodes.
        let mut node_key = rightmost_leaf_node_key.gen_parent_node_key();
        while store.get_node_option(&node_key, "restore")?.is_some() {
            node_key = node_key.gen_parent_node_key();
        }

        // Next we reconstruct all the partial nodes up to the root node, starting from the bottom.
        // For all of them, we scan all its possible child positions and see if there is one at
        // each position. If the node is not the bottom one, there is additionally a partial node
        // child at the position `previous_child_index`.
        let mut partial_nodes = vec![];
        // Initialize `previous_child_index` to `None` for the first iteration of the loop so the
        // code below treats it differently.
        let mut previous_child_index = None;

        loop {
            let mut internal_info = InternalInfo::new_empty(node_key.clone());

            for i in 0..previous_child_index.unwrap_or(16) {
                let child_node_key = node_key.gen_child_node_key(version, (i as u8).into());
                if let Some(node) = store.get_node_option(&child_node_key, "restore")? {
                    let child_info = match node {
                        Node::Internal(internal_node) => ChildInfo::Internal {
                            hash: Some(internal_node.hash()),
                            leaf_count: Some(internal_node.leaf_count()),
                        },
                        Node::Leaf(leaf_node) => ChildInfo::Leaf(leaf_node),
                        Node::Null => unreachable!("Child cannot be Null"),
                    };
                    internal_info.set_child(i, child_info);
                }
            }

            // If this is not the lowest partial node, it will have a partial node child at
            // `previous_child_index`. Set the hash of this child to `None` because it is a
            // partial node and we do not know its hash yet. For the lowest partial node, we just
            // find all its known children from storage in the loop above.
            if let Some(index) = previous_child_index {
                internal_info.set_child(index, ChildInfo::Internal {
                    hash: None,
                    leaf_count: None,
                });
            }

            partial_nodes.push(internal_info);
            if node_key.nibble_path().is_empty() {
                break;
            }
            previous_child_index = node_key.nibble_path().last().map(|x| u8::from(x) as usize);
            node_key = node_key.gen_parent_node_key();
        }

        partial_nodes.reverse();
        Ok(partial_nodes)
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L394-410)
```rust
        if self.async_commit {
            self.wait_for_async_commit()?;
            let (tx, rx) = channel();
            self.async_commit_result = Some(rx);

            let mut frozen_nodes = HashMap::new();
            std::mem::swap(&mut frozen_nodes, &mut self.frozen_nodes);
            let store = self.store.clone();

            IO_POOL.spawn(move || {
                let res = store.write_node_batch(&frozen_nodes);
                tx.send(res).unwrap();
            });
        } else {
            self.store.write_node_batch(&self.frozen_nodes)?;
            self.frozen_nodes.clear();
        }
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L147-171)
```rust
    pub(crate) fn commit(
        &self,
        version: Version,
        top_levels_batch: impl IntoRawBatch,
        batches_for_shards: Vec<impl IntoRawBatch + Send>,
    ) -> Result<()> {
        ensure!(
            batches_for_shards.len() == NUM_STATE_SHARDS,
            "Shard count mismatch."
        );
        THREAD_MANAGER.get_io_pool().install(|| {
            batches_for_shards
                .into_par_iter()
                .enumerate()
                .for_each(|(shard_id, batch)| {
                    self.db_shard(shard_id)
                        .write_schemas(batch)
                        .unwrap_or_else(|err| {
                            panic!("Failed to commit state merkle shard {shard_id}: {err}")
                        });
                })
        });

        self.commit_top_levels(version, top_levels_batch)
    }
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L173-190)
```rust
    /// Only used by fast sync / restore.
    pub(crate) fn commit_no_progress(
        &self,
        top_level_batch: SchemaBatch,
        batches_for_shards: Vec<SchemaBatch>,
    ) -> Result<()> {
        ensure!(
            batches_for_shards.len() == NUM_STATE_SHARDS,
            "Shard count mismatch."
        );
        let mut batches = batches_for_shards.into_iter();
        for shard_id in 0..NUM_STATE_SHARDS {
            let state_merkle_batch = batches.next().unwrap();
            self.state_merkle_db_shards[shard_id].write_schemas(state_merkle_batch)?;
        }

        self.state_merkle_metadata_db.write_schemas(top_level_batch)
    }
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L633-658)
```rust
        let state_merkle_db_shards = (0..NUM_STATE_SHARDS)
            .into_par_iter()
            .map(|shard_id| {
                let shard_root_path = if is_hot {
                    db_paths.hot_state_merkle_db_shard_root_path(shard_id)
                } else {
                    db_paths.state_merkle_db_shard_root_path(shard_id)
                };
                let db = Self::open_shard(
                    shard_root_path,
                    shard_id,
                    &state_merkle_db_config,
                    env,
                    block_cache,
                    readonly,
                    is_hot,
                    delete_on_restart,
                )
                .unwrap_or_else(|e| {
                    panic!("Failed to open state merkle db shard {shard_id}: {e:?}.")
                });
                Arc::new(db)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L668-677)
```rust
        if !readonly {
            if let Some(overall_state_merkle_commit_progress) =
                get_state_merkle_commit_progress(&state_merkle_db)?
            {
                truncate_state_merkle_db_shards(
                    &state_merkle_db,
                    overall_state_merkle_commit_progress,
                )?;
            }
        }
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L918-932)
```rust
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["tree_writer_write_batch"]);
        // Get the top level batch and sharded batch from raw NodeBatch
        let mut top_level_batch = SchemaBatch::new();
        let mut jmt_shard_batches: Vec<SchemaBatch> = Vec::with_capacity(NUM_STATE_SHARDS);
        jmt_shard_batches.resize_with(NUM_STATE_SHARDS, SchemaBatch::new);
        node_batch.iter().try_for_each(|(node_key, node)| {
            if let Some(shard_id) = node_key.get_shard_id() {
                jmt_shard_batches[shard_id].put::<JellyfishMerkleNodeSchema>(node_key, node)
            } else {
                top_level_batch.put::<JellyfishMerkleNodeSchema>(node_key, node)
            }
        })?;
        self.commit_no_progress(top_level_batch, jmt_shard_batches)
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L707-719)
```rust
    pub fn reset(&self) {
        self.buffered_state.lock().quit();
        *self.buffered_state.lock() = Self::create_buffered_state_from_latest_snapshot(
            &self.state_db,
            self.buffered_state_target_items,
            false,
            true,
            self.current_state.clone(),
            self.persisted_state.clone(),
            self.hot_state_config,
        )
        .expect("buffered state creation failed.");
    }
```
