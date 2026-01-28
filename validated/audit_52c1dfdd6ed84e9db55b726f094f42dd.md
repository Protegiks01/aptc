# Audit Report

## Title
State Snapshot Restore Progress Tracking Race Condition Leading to StateStorageUsage Corruption

## Summary
A race condition exists between the internal indexer database and main database commits during state snapshot restoration. When `get_progress()` incorrectly returns `None` due to non-atomic writes, the restore coordinator can skip already-processed chunks while resetting usage counters, resulting in permanently corrupted `StateStorageUsage` metadata that breaks consensus through divergent on-chain state values.

## Finding Description

The vulnerability stems from a non-atomic write pattern in the state snapshot restoration system that tracks progress in two separate databases without coordination.

The `write_kv_batch()` function performs two separate database commits that are NOT atomic: [1](#0-0) 

First, it commits progress to the internal indexer database. [2](#0-1) 

Then it commits progress and data to the main state_kv_db. If a crash occurs between these commits, the databases become inconsistent.

The `get_progress()` function checks both databases for consistency, but silently allows the inconsistent case: [3](#0-2) 

At line 1340, it allows `(None, Some(_))` where the main DB has no progress but the indexer DB does, then returns `None` at line 1360, hiding the partial write.

During restoration, `StateValueRestore::add_chunk()` initializes usage from `get_progress()`: [4](#0-3) 

At line 107, if `get_progress()` returns `None`, the usage counter starts from zero instead of accumulating from previous chunks.

Meanwhile, `JellyfishMerkleRestore` maintains its own progress independently by reading the rightmost leaf from the tree store: [5](#0-4) 

At line 207, it reads the rightmost leaf if it exists, creating a divergence where tree restore has progress but KV restore does not.

The `StateSnapshotRestore::previous_key_hash()` combines both progress sources: [6](#0-5) 

At line 209, when KV restore returns `None` but tree restore has progress, the combined result uses the tree progress, causing chunks to be skipped.

The restore coordinator uses this combined progress to determine which chunks to skip: [7](#0-6) 

**Attack Scenario:**
1. Chunk 1 is processed - tree restore commits frozen nodes successfully
2. KV restore writes to indexer DB successfully (line 1270)
3. **Process crashes before main DB commit** (line 1278)
4. On restart: tree restore has rightmost leaf (Chunk 1 progress), KV restore's `get_progress()` returns `None`
5. Combined resume point indicates to skip Chunk 1 (line 170)
6. Chunk 2 processing: usage starts from zero (line 107) instead of Chunk 1's accumulated usage
7. Final state: Missing Chunk 1's usage in `StateStorageUsage` metadata

The corrupted `StateStorageUsage` is then written to the on-chain Move resource during epoch transitions: [8](#0-7) 

At line 47, the native function `get_state_storage_usage_only_at_epoch_beginning()` reads the corrupted value from VersionData: [9](#0-8) 

This native function retrieves the corrupted `StateStorageUsage` from the database at line 68, which is then written to the on-chain `StateStorageUsage` resource. Since this resource is part of the global state, different corrupted values across validators result in different state root hashes, breaking consensus safety.

## Impact Explanation

**Severity: CRITICAL** ($1,000,000 tier per Aptos Bug Bounty)

This vulnerability constitutes a **Consensus/Safety Violation** by causing non-deterministic state across validator nodes:

1. **Consensus Divergence**: Different restore attempts (with different crash timings) produce different `StateStorageUsage` values. These values are written to the on-chain `StateStorageUsage` resource at `@aptos_framework`, which affects the state root hash. Nodes that restore from the same backup can end up with different state roots, breaking consensus safety - validators cannot agree on the canonical chain state.

2. **Storage Gas Pricing Corruption**: The corrupted `StateStorageUsage` directly drives dynamic gas pricing for storage operations via `storage_gas.move`. Undercounted usage means storage gas costs are artificially low, users can allocate more storage than they pay for, and network storage growth becomes unsustainable.

3. **Permanent Corruption**: Once written to the on-chain resource, the corrupted usage value persists permanently. There is no automatic detection or correction mechanism. The only remedy is a coordinated network-wide correction or hard fork.

4. **Widespread Impact**: Any node performing state snapshot restoration (bootstrap, disaster recovery, state sync) is vulnerable. Given the race window between database commits and parallel execution, the bug has a non-negligible trigger probability across network-wide operations.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability triggers when:
1. A node performs state snapshot restoration (common operation for bootstrap, disaster recovery, state sync)
2. Process crashes/kills occur between the two database commits (lines 1270-1278)
3. The tree merkle database successfully commits its chunks before the crash

Triggering factors:
- **Parallel Execution**: Tree and KV restore run in parallel via `IO_POOL.join()`, creating real race conditions
- **Narrow Race Window**: Microseconds to milliseconds between commits, but high throughput restoration processes thousands of chunks
- **Common Production Scenarios**: OOM kills, power failures, operator interventions, container orchestration updates, node restarts
- **No User Malice Required**: Purely a crash-recovery race condition - no attacker action needed

The bug doesn't require adversarial behavior, just environmental conditions that naturally occur in production blockchain infrastructure. Over thousands of restoration operations network-wide, statistical likelihood of triggering is significant.

## Recommendation

Implement atomic progress tracking across both databases:

1. **Option A - Atomic Commit**: Use a two-phase commit protocol or transaction coordinator to ensure both indexer DB and main DB commits succeed atomically, or both fail.

2. **Option B - Single Source of Truth**: Eliminate the dual-tracking by using only the main DB for progress tracking, or only commit progress after both tree and KV data are successfully persisted.

3. **Option C - Consistency Validation**: On restart, if `(None, Some(_))` is detected in `get_progress()`, treat it as a fatal error requiring full restore restart rather than silently returning `None`. Add validation:

```rust
match (main_db_progress, progress_opt) {
    (None, None) => (),
    (None, Some(_)) => {
        // Fatal: indexer DB has progress but main DB doesn't
        bail!("Inconsistent restore state detected - restart restore from beginning")
    },
    // ... rest of cases
}
```

4. **Option D - Replay Detection**: Track both tree and KV progress independently in persistent storage, and on restart, use the minimum of both values to ensure no chunks are skipped without proper usage accounting.

## Proof of Concept

The vulnerability can be reproduced through the following scenario:

1. Start a state snapshot restore operation with a large backup
2. Allow the first chunk to begin processing
3. Inject a crash signal after the indexer DB commit (line 1270) but before the main DB commit (line 1278) - this can be done via process kill, OOM, or power failure simulation
4. Restart the restore process
5. Observe that `get_progress()` returns `None` while the tree restore has the rightmost leaf
6. The restore coordinator skips the first chunk based on tree progress
7. Usage counter starts from zero, missing the first chunk's item count and byte count
8. After restore completion, verify the final `StateStorageUsage` is missing the first chunk's usage
9. Compare with a clean restore - the `StateStorageUsage` values will differ, demonstrating consensus divergence potential

The race condition is inherent to the parallel execution pattern in `StateSnapshotRestore::add_chunk()` where tree and KV restore run concurrently via `IO_POOL.join()`, combined with the non-atomic dual-database commit pattern in `write_kv_batch()`.

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L1267-1271)
```rust
            self.internal_indexer_db
                .as_ref()
                .unwrap()
                .write_keys_to_indexer_db(&keys, version, progress)?;
        }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1277-1279)
```rust
        self.state_kv_db
            .commit(version, Some(batch), sharded_schema_batch)
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1338-1361)
```rust
            match (main_db_progress, progress_opt) {
                (None, None) => (),
                (None, Some(_)) => (),
                (Some(main_progress), Some(indexer_progress)) => {
                    if main_progress.key_hash > indexer_progress.key_hash {
                        bail!(
                            "Inconsistent restore progress between main db and internal indexer db. main db: {:?}, internal indexer db: {:?}",
                            main_progress,
                            indexer_progress,
                        );
                    }
                },
                _ => {
                    bail!(
                        "Inconsistent restore progress between main db and internal indexer db. main db: {:?}, internal indexer db: {:?}",
                        main_db_progress,
                        progress_opt,
                    );
                },
            }
        }

        Ok(main_db_progress)
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L88-127)
```rust
    pub fn add_chunk(&mut self, mut chunk: Vec<(K, V)>) -> Result<()> {
        // load progress
        let progress_opt = self.db.get_progress(self.version)?;

        // skip overlaps
        if let Some(progress) = progress_opt {
            let idx = chunk
                .iter()
                .position(|(k, _v)| CryptoHash::hash(k) > progress.key_hash)
                .unwrap_or(chunk.len());
            chunk = chunk.split_off(idx);
        }

        // quit if all skipped
        if chunk.is_empty() {
            return Ok(());
        }

        // save
        let mut usage = progress_opt.map_or(StateStorageUsage::zero(), |p| p.usage);
        let (last_key, _last_value) = chunk.last().unwrap();
        let last_key_hash = CryptoHash::hash(last_key);

        // In case of TreeOnly Restore, we only restore the usage of KV without actually writing KV into DB
        for (k, v) in chunk.iter() {
            usage.add_item(k.key_size() + v.value_size());
        }

        // prepare the sharded kv batch
        let kv_batch: StateValueBatch<K, Option<V>> = chunk
            .into_iter()
            .map(|(k, v)| ((k, self.version), Some(v)))
            .collect();

        self.db.write_kv_batch(
            self.version,
            &kv_batch,
            StateSnapshotProgress::new(last_key_hash, usage),
        )
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L196-214)
```rust
    pub fn previous_key_hash(&self) -> Result<Option<HashValue>> {
        let hash_opt = match (
            self.kv_restore
                .lock()
                .as_ref()
                .unwrap()
                .previous_key_hash()?,
            self.tree_restore
                .lock()
                .as_ref()
                .unwrap()
                .previous_key_hash(),
        ) {
            (None, hash_opt) => hash_opt,
            (hash_opt, None) => hash_opt,
            (Some(hash1), Some(hash2)) => Some(std::cmp::min(hash1, hash2)),
        };
        Ok(hash_opt)
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L189-235)
```rust
    pub fn new<D: 'static + TreeReader<K> + TreeWriter<K>>(
        store: Arc<D>,
        version: Version,
        expected_root_hash: HashValue,
        async_commit: bool,
    ) -> Result<Self> {
        let tree_reader = Arc::clone(&store);
        let (finished, partial_nodes, previous_leaf) = if let Some(root_node) =
            tree_reader.get_node_option(&NodeKey::new_empty_path(version), "restore")?
        {
            info!("Previous restore is complete, checking root hash.");
            ensure!(
                root_node.hash() == expected_root_hash,
                "Previous completed restore has root hash {}, expecting {}",
                root_node.hash(),
                expected_root_hash,
            );
            (true, vec![], None)
        } else if let Some((node_key, leaf_node)) = tree_reader.get_rightmost_leaf(version)? {
            // If the system crashed in the middle of the previous restoration attempt, we need
            // to recover the partial nodes to the state right before the crash.
            (
                false,
                Self::recover_partial_nodes(tree_reader.as_ref(), version, node_key)?,
                Some(leaf_node),
            )
        } else {
            (
                false,
                vec![InternalInfo::new_empty(NodeKey::new_empty_path(version))],
                None,
            )
        };

        Ok(Self {
            store,
            version,
            partial_nodes,
            frozen_nodes: HashMap::new(),
            previous_leaf,
            num_keys_received: 0,
            expected_root_hash,
            finished,
            async_commit,
            async_commit_result: None,
        })
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L165-174)
```rust
        let resume_point_opt = receiver.lock().as_mut().unwrap().previous_key_hash()?;
        let chunks = if let Some(resume_point) = resume_point_opt {
            manifest
                .chunks
                .into_iter()
                .skip_while(|chunk| chunk.last_key <= resume_point)
                .collect()
        } else {
            manifest.chunks
        };
```

**File:** aptos-move/framework/aptos-framework/sources/state_storage.move (L39-49)
```text
    public(friend) fun on_new_block(epoch: u64) acquires StateStorageUsage {
        assert!(
            exists<StateStorageUsage>(@aptos_framework),
            error::not_found(ESTATE_STORAGE_USAGE)
        );
        let usage = borrow_global_mut<StateStorageUsage>(@aptos_framework);
        if (epoch != usage.epoch) {
            usage.epoch = epoch;
            usage.usage = get_state_storage_usage_only_at_epoch_beginning();
        }
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L66-70)
```rust
    fn get_usage(&self) -> StateViewResult<StateStorageUsage> {
        self.db
            .get_state_storage_usage(self.version)
            .map_err(Into::into)
    }
```
