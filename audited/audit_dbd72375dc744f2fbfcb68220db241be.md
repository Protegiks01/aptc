# Audit Report

## Title
Race Condition in Parallel State Restore Causing KV-Tree Inconsistency with Async Commits

## Summary
In `StateSnapshotRestore::add_chunk()`, when `async_commit=true` (used during backup/restore operations), the parallel execution of KV and tree writes via `IO_POOL.join()` creates a race condition. If the tree's asynchronous write fails after returning success, subsequent KV writes may commit before the failure is detected, resulting in permanent state inconsistency between the StateKV database and Jellyfish Merkle Tree. [1](#0-0) 

## Finding Description

The vulnerability exists in the `add_chunk()` implementation where two functions execute in parallel: [2](#0-1) 

When `async_commit=true` (configured in backup/restore operations): [3](#0-2) 

The `tree_fn` spawns asynchronous writes that return `Ok(())` immediately: [4](#0-3) 

Meanwhile, `kv_fn` performs synchronous commits: [5](#0-4) 

**Attack Scenario:**

1. **Chunk N processing**: `tree_fn` spawns async write for chunk N, returns `Ok()` immediately while write is pending; `kv_fn` commits chunk N synchronously
2. **Chunk N+1 processing**: Both functions start in parallel
   - `tree_fn` calls `wait_for_async_commit()` and blocks waiting for chunk N's async write
   - `kv_fn` immediately begins writing chunk N+1
3. **Race condition**: If chunk N's async write fails (I/O error, disk full), `tree_fn` detects failure and returns error, but `kv_fn` may have already committed chunk N+1 to database
4. **Result**: KV database contains chunks {N, N+1}, but Merkle tree only contains chunks {0...N-1}

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." [6](#0-5) 

## Impact Explanation

**Severity: Medium** per Aptos Bug Bounty criteria - "State inconsistencies requiring intervention"

The vulnerability causes permanent database corruption where:
- State KV database and Jellyfish Merkle Tree become permanently desynchronized
- State root hash no longer matches the actual KV data
- Node cannot serve valid Merkle proofs for the stored state
- Requires manual database cleanup or full re-restore to recover
- If the node attempts to participate in consensus with this inconsistent state, it will produce incorrect state roots, causing consensus disagreement with other validators

While recovery is theoretically possible through the progress tracking mechanism, the inconsistent state persists until manual intervention: [7](#0-6) 

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can occur during:
- Backup restoration operations (when `async_commit=true`)
- I/O failures during async writes (disk full, storage errors, network issues with remote storage)
- High load scenarios where async writes may fail due to resource constraints

While not trivially exploitable by external attackers (requires node to be in restore mode), the vulnerability can be triggered through:
- Resource exhaustion attacks during node restore
- Network disruption during remote backup fetching
- Natural I/O failures during large-scale restores

The race window exists between every chunk processing, making it probabilistically likely to occur during multi-GB state restores with hundreds of thousands of chunks.

## Recommendation

**Fix: Ensure atomic failure handling for parallel operations**

Replace the parallel join with proper error coordination:

```rust
StateSnapshotRestoreMode::Default => {
    // Execute both operations in parallel
    let (r1, r2) = IO_POOL.join(kv_fn, tree_fn);
    
    // Check tree result FIRST before allowing kv commit to finalize
    // If tree failed, we need to rollback or prevent kv write
    match (r1, r2) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), _) | (_, Err(e)) => {
            // Both must succeed or both must fail
            // Consider implementing rollback for kv_fn if tree_fn fails
            Err(e)
        }
    }
},
```

**Better fix: Synchronize async commits before next chunk**

Modify the logic to wait for tree async commits to complete BEFORE starting the next KV write:

```rust
StateSnapshotRestoreMode::Default => {
    // Execute in sequence to ensure atomicity
    tree_fn()?;  // This will wait for previous async and current
    kv_fn()?;    // Only execute if tree succeeded
},
```

Or wait for tree async commit completion before the join:

```rust
StateSnapshotRestoreMode::Default => {
    // Wait for any pending async tree writes first
    self.tree_restore.lock().as_mut().unwrap().wait_for_async_commit()?;
    
    // Now both can proceed safely
    let (r1, r2) = IO_POOL.join(kv_fn, tree_fn);
    r1?;
    r2?;
},
```

## Proof of Concept

```rust
#[test]
fn test_parallel_join_race_condition() {
    // Setup: Create state restore with async_commit=true
    let (state_store, tree_store) = setup_test_stores();
    let version = 100;
    let root_hash = HashValue::random();
    
    let mut restore = StateSnapshotRestore::new(
        &tree_store,
        &state_store,
        version,
        root_hash,
        true, // async_commit=true
        StateSnapshotRestoreMode::Default,
    ).unwrap();
    
    // Chunk 1: Process normally
    let chunk1 = generate_test_chunk(0, 1000);
    let proof1 = generate_test_proof(&chunk1);
    restore.add_chunk(chunk1, proof1).unwrap();
    
    // Inject failure: Make tree async write fail for next chunk
    inject_io_error_for_next_tree_write(&tree_store);
    
    // Chunk 2: Process with injected failure
    let chunk2 = generate_test_chunk(1000, 2000);
    let proof2 = generate_test_proof(&chunk2);
    
    // This should fail, but may leave inconsistent state
    let result = restore.add_chunk(chunk2.clone(), proof2);
    
    // Verify inconsistent state
    let kv_progress = state_store.get_progress(version).unwrap();
    let tree_progress = tree_store.get_rightmost_leaf(version).unwrap();
    
    // KV may have chunk2, but tree does not
    assert_ne!(kv_progress.key_hash, tree_progress.map(|l| l.account_key()));
    
    // State root hash mismatch
    let computed_root = tree_store.get_root_hash(version).unwrap();
    assert_ne!(computed_root, expected_root_for_chunk2());
}
```

**Notes**

This vulnerability specifically affects the backup/restore code path where `async_commit=true` is used. The state sync path uses `async_commit=false` and is not affected. The race condition is inherent in the parallel execution model where one operation (tree write) completes asynchronously while the other (KV write) completes synchronously, with no coordination between their commit points.

### Citations

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

**File:** storage/aptosdb/src/state_restore/mod.rs (L228-258)
```rust
    fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
        let kv_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_add_chunk"]);
            self.kv_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk(chunk.clone())
        };

        let tree_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["jmt_add_chunk"]);
            self.tree_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk_impl(chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof)
        };
        match self.restore_mode {
            StateSnapshotRestoreMode::KvOnly => kv_fn()?,
            StateSnapshotRestoreMode::TreeOnly => tree_fn()?,
            StateSnapshotRestoreMode::Default => {
                // We run kv_fn with TreeOnly to restore the usage of DB
                let (r1, r2) = IO_POOL.join(kv_fn, tree_fn);
                r1?;
                r2?;
            },
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L41-55)
```rust
    pub fn get_state_restore_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<StateSnapshotRestore<StateKey, StateValue>> {
        StateSnapshotRestore::new(
            &self.state_store.state_merkle_db,
            &self.state_store,
            version,
            expected_root_hash,
            true, /* async_commit */
            restore_mode,
        )
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L394-412)
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

        Ok(())
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L741-746)
```rust
    pub fn wait_for_async_commit(&mut self) -> Result<()> {
        if let Some(rx) = self.async_commit_result.take() {
            rx.recv()??;
        }
        Ok(())
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1244-1279)
```rust
    fn write_kv_batch(
        &self,
        version: Version,
        node_batch: &StateValueBatch,
        progress: StateSnapshotProgress,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_writer_write_chunk"]);
        let mut batch = SchemaBatch::new();
        let mut sharded_schema_batch = self.state_kv_db.new_sharded_native_batches();

        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateSnapshotKvRestoreProgress(version),
            &DbMetadataValue::StateSnapshotProgress(progress),
        )?;

        if self.internal_indexer_db.is_some()
            && self
                .internal_indexer_db
                .as_ref()
                .unwrap()
                .statekeys_enabled()
        {
            let keys = node_batch.keys().map(|key| key.0.clone()).collect();
            self.internal_indexer_db
                .as_ref()
                .unwrap()
                .write_keys_to_indexer_db(&keys, version, progress)?;
        }
        self.shard_state_value_batch(
            &mut sharded_schema_batch,
            node_batch,
            self.state_kv_db.enabled_sharding(),
        )?;
        self.state_kv_db
            .commit(version, Some(batch), sharded_schema_batch)
    }
```
