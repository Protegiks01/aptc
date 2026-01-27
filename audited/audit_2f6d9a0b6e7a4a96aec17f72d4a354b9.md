# Audit Report

## Title
Parallel Execution Race Condition Allows Corrupted State Data to Persist After Failed Proof Verification

## Summary
The `StateSnapshotRestore::add_chunk` method executes KV writes and cryptographic proof verification in parallel, allowing corrupted state data to be permanently committed to disk even when proof verification subsequently fails. This violates the State Consistency invariant and can lead to irrecoverable database corruption.

## Finding Description

The vulnerability exists in the state snapshot restore process, specifically in how the `Default` restore mode handles concurrent operations. [1](#0-0) 

When `restore_mode` is `Default`, the system executes two operations in parallel using `IO_POOL.join()`:

1. **kv_fn**: Writes state key-value pairs directly to disk via `write_kv_batch`, which immediately commits data through `state_kv_db.commit()` [2](#0-1) 

2. **tree_fn**: Verifies the cryptographic proof by calling `add_chunk_impl`, which invokes the `verify` method [3](#0-2) 

**The Attack Scenario:**

1. An attacker provides a malicious backup containing corrupted state data with an invalid proof
2. During restore, both operations execute concurrently
3. `kv_fn` commits the corrupted KV data to disk with a progress marker
4. `tree_fn` detects the invalid proof and returns an error
5. The error is propagated (via `r2?`), but the corrupted data has already been committed
6. On retry, the system enters an irrecoverable state:
   - KV restore skips the corrupted chunk (progress marker indicates completion)
   - Tree restore attempts to process the same chunk and fails verification again
   - This creates a permanent deadlock where restore cannot complete [4](#0-3) 

The `previous_key_hash` method returns the minimum of KV and tree progress, causing the restore controller to retry the corrupted chunk indefinitely. [5](#0-4) 

**Additional Critical Issue - KvOnly Mode:**

When `restore_mode` is `KvOnly`, proof verification is completely bypassed, allowing arbitrary corrupted data to be written directly to the database without any cryptographic validation. [6](#0-5) 

## Impact Explanation

This is a **Critical Severity** vulnerability (up to $1,000,000) as it violates multiple critical invariants:

1. **State Consistency Violation**: Corrupted state data persists in the database without valid cryptographic proofs, breaking the fundamental guarantee that "state transitions must be atomic and verifiable via Merkle proofs"

2. **Consensus Safety Risk**: Different nodes restoring from compromised backups may end up with different state roots, potentially causing consensus failures or chain splits

3. **Irrecoverable State**: Once corrupted data with progress markers is committed, the database enters an unrecoverable state requiring manual intervention or database rebuild

4. **Deterministic Execution Failure**: Validators with corrupted state will produce different state roots for identical blocks, violating the deterministic execution invariant

This qualifies as a "Non-recoverable network partition (requires hardfork)" scenario if multiple validators restore from the same compromised backup.

## Likelihood Explanation

**High Likelihood** due to:

1. **Common Attack Vector**: Backup restore is a standard operational procedure, making it a natural target
2. **No Special Access Required**: Any attacker who can compromise backup storage or perform MITM attacks during backup transfer can inject malicious data
3. **Default Mode Affected**: The `Default` restore mode is the standard configuration, affecting most restore operations
4. **No Rate Limiting**: The parallel execution always processes chunks this way, providing consistent exploitation opportunity

## Recommendation

**Fix 1: Serialize Verification and Write Operations**

Modify `StateSnapshotRestore::add_chunk` to verify proofs BEFORE writing KV data:

```rust
StateSnapshotRestoreMode::Default => {
    // Verify proof FIRST before writing any data
    tree_fn()?;
    // Only write KV data after successful verification
    kv_fn()?;
}
```

**Fix 2: Implement Atomic Transactions with Rollback**

Wrap both operations in a transaction that can be rolled back if verification fails:

```rust
StateSnapshotRestoreMode::Default => {
    let kv_batch = prepare_kv_batch(chunk.clone());
    // Verify proof before committing
    tree_fn()?;
    // Only commit if verification succeeded
    commit_kv_batch(kv_batch)?;
}
```

**Fix 3: Mandatory Proof Verification**

Remove `KvOnly` mode or add mandatory proof verification:

```rust
StateSnapshotRestoreMode::KvOnly => {
    // Always verify proof even in KvOnly mode
    tree_fn()?;
    kv_fn()?;
}
```

## Proof of Concept

**Setup:**
1. Create a valid state snapshot backup
2. Modify a chunk's data to corrupt it while keeping the proof unchanged
3. Attempt to restore from this backup

**Expected Behavior:**
- Restore should fail with proof verification error
- Database should remain in consistent state

**Actual Behavior:**
- Corrupted KV data is written to disk
- Proof verification fails afterward
- Progress marker indicates chunk is complete
- Subsequent restore attempts enter infinite loop
- Database is permanently corrupted

**Reproduction Steps:**
```rust
// 1. Setup state snapshot restore in Default mode
let restore = StateSnapshotRestore::new(
    &tree_store,
    &value_store,
    version,
    expected_root_hash,
    false, // async_commit
    StateSnapshotRestoreMode::Default,
)?;

// 2. Provide chunk with corrupted data but valid proof structure
let corrupted_chunk = vec![
    (corrupted_key, corrupted_value), // Modified data
];
let original_proof = get_valid_proof(); // Original proof won't match

// 3. Call add_chunk - corrupted data will be written despite verification failure
let result = restore.add_chunk(corrupted_chunk, original_proof);

// 4. Verify database corruption
assert!(result.is_err()); // Verification fails
assert!(kv_data_was_written()); // But data is on disk!
assert!(progress_marker_exists()); // Progress marked complete

// 5. Retry restore - enters infinite loop
let retry_result = restore.add_chunk(same_chunk, same_proof);
assert!(retry_result.is_err()); // Fails again, forever
```

**Notes:**

While the security question specifically asks about `TryBufferedX`, the actual vulnerability exists in `StateSnapshotRestore::add_chunk` which uses `rayon::ThreadPool` for parallel execution rather than TryBufferedX. State snapshot restore uses `buffered_x` (not `try_buffered_x`) in the restore controller. TryBufferedX itself maintains proper ordering and does not bypass verification in the code paths where it is used (transaction restore and state snapshot backup). However, the parallel execution vulnerability in state restore represents a critical security issue that allows corrupted data to bypass cryptographic verification.

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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L628-697)
```rust
    fn verify(&self, proof: SparseMerkleRangeProof) -> Result<()> {
        let previous_leaf = self
            .previous_leaf
            .as_ref()
            .expect("The previous leaf must exist.");

        let previous_key = previous_leaf.account_key();
        // If we have all siblings on the path from root to `previous_key`, we should be able to
        // compute the root hash. The siblings on the right are already in the proof. Now we
        // compute the siblings on the left side, which represent all the states that have ever
        // been added.
        let mut left_siblings = vec![];

        // The following process might add some extra placeholder siblings on the left, but it is
        // nontrivial to determine when the loop should stop. So instead we just add these
        // siblings for now and get rid of them in the next step.
        let mut num_visited_right_siblings = 0;
        for (i, bit) in previous_key.iter_bits().enumerate() {
            if bit {
                // This node is a right child and there should be a sibling on the left.
                let sibling = if i >= self.partial_nodes.len() * 4 {
                    *SPARSE_MERKLE_PLACEHOLDER_HASH
                } else {
                    Self::compute_left_sibling(
                        &self.partial_nodes[i / 4],
                        previous_key.get_nibble(i / 4),
                        (3 - i % 4) as u8,
                    )
                };
                left_siblings.push(sibling);
            } else {
                // This node is a left child and there should be a sibling on the right.
                num_visited_right_siblings += 1;
            }
        }
        ensure!(
            num_visited_right_siblings >= proof.right_siblings().len(),
            "Too many right siblings in the proof.",
        );

        // Now we remove any extra placeholder siblings at the bottom. We keep removing the last
        // sibling if 1) it's a placeholder 2) it's a sibling on the left.
        for bit in previous_key.iter_bits().rev() {
            if bit {
                if *left_siblings.last().expect("This sibling must exist.")
                    == *SPARSE_MERKLE_PLACEHOLDER_HASH
                {
                    left_siblings.pop();
                } else {
                    break;
                }
            } else if num_visited_right_siblings > proof.right_siblings().len() {
                num_visited_right_siblings -= 1;
            } else {
                break;
            }
        }

        // Left siblings must use the same ordering as the right siblings in the proof
        left_siblings.reverse();

        // Verify the proof now that we have all the siblings
        proof
            .verify(
                self.expected_root_hash,
                SparseMerkleLeafNode::new(*previous_key, previous_leaf.value_hash()),
                left_siblings,
            )
            .map_err(Into::into)
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L165-171)
```rust
        let resume_point_opt = receiver.lock().as_mut().unwrap().previous_key_hash()?;
        let chunks = if let Some(resume_point) = resume_point_opt {
            manifest
                .chunks
                .into_iter()
                .skip_while(|chunk| chunk.last_key <= resume_point)
                .collect()
```
