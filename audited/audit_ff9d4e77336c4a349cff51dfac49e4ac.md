# Audit Report

## Title
State Restoration Accepts Incomplete Data Due to Missing Final Root Hash Validation

## Summary
The `JellyfishMerkleRestore::finish_impl()` method completes state restoration without validating that the final reconstructed tree's root hash matches the expected root hash from the signed `LedgerInfo`. This allows incomplete state snapshots with missing chunks to pass validation, resulting in nodes accepting corrupted state that renders them unable to participate in consensus.

## Finding Description

The state restoration process in Aptos uses `SparseMerkleRangeProof` to validate individual chunks during restoration. However, there is a critical gap in the validation logic:

**Per-chunk validation** (in `add_chunk_impl`): Each chunk is validated against the expected root hash using the `verify()` method, which proves the chunk is cryptographically consistent. [1](#0-0) 

**Missing final validation** (in `finish_impl`): When restoration completes, the method freezes all partial nodes and writes them to storage WITHOUT verifying that the final root hash matches `expected_root_hash`. [2](#0-1) 

The `expected_root_hash` field exists and is used during per-chunk verification: [3](#0-2) 

But is never validated against the final reconstructed tree's root in `finish_impl()`.

**Attack Scenario:**

If a state snapshot backup has missing trailing chunks:
1. Backup manifest lists chunks 1-10, but only chunks 1-8 are provided
2. Each chunk (1-8) is added and verified individually - passes ✓
3. Chunk proofs contain right siblings accounting for the missing data, so verification succeeds
4. `finish()` is called, which calls `finish_impl()` 
5. All partial nodes are frozen and written to storage
6. Method returns `Ok()` without checking final root hash

The restored state is now incomplete but marked as successfully restored. When loaded, the node has an incorrect state root hash that doesn't match the network's expected state root. [4](#0-3) 

Additionally, there is no validation in the restore controller that chunks are contiguous: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

1. **Significant Protocol Violation**: Nodes accept invalid state that doesn't match the expected state root hash, violating the fundamental invariant that "State transitions must be atomic and verifiable via Merkle proofs."

2. **Validator Node Dysfunction**: Affected nodes cannot participate in consensus because their state root doesn't match what the network expects from the signed `LedgerInfo`. This causes:
   - Inability to propose or validate blocks
   - Query responses with incorrect state
   - Potential network partitioning if multiple nodes restore from the same corrupted backup

3. **State Inconsistency Requiring Intervention**: Node operators must manually detect the issue (through failed consensus participation or state sync errors) and perform a full re-synchronization, requiring significant downtime.

While this doesn't directly cause fund loss, it represents a critical failure in state integrity verification that could be exploited to cause widespread node failures if a popular backup source is compromised or buggy.

## Likelihood Explanation

**Medium to High Likelihood:**

1. **Backup Source Compromise**: If an attacker compromises a popular backup hosting service or performs a DNS hijack, they can serve incomplete backups to new nodes joining the network.

2. **Backup Generation Bugs**: Race conditions, disk failures, or bugs in the backup generation logic could create incomplete backups. The restore process should reject these, but currently accepts them.

3. **No Defense in Depth**: The missing final validation represents a single point of failure - if any step in the backup/restore pipeline has issues, incomplete state is accepted.

The attack requires:
- Control over backup source OR exploitation of backup generation bugs
- Victim node operator downloading and restoring from the compromised source
- No validator-level privileges required

## Recommendation

Add final root hash validation in `finish_impl()` before returning success:

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    
    // ... existing special case handling ...
    
    self.freeze(0);
    self.store.write_node_batch(&self.frozen_nodes)?;
    
    // **ADD: Validate final root hash**
    let root_node_key = NodeKey::new_empty_path(self.version);
    let root_node = self.frozen_nodes.get(&root_node_key)
        .ok_or_else(|| anyhow!("Root node not found after freeze"))?;
    let actual_root_hash = root_node.hash();
    
    ensure!(
        actual_root_hash == self.expected_root_hash,
        "State restoration failed: final root hash mismatch. Expected: {:?}, Got: {:?}",
        self.expected_root_hash,
        actual_root_hash
    );
    
    Ok(())
}
```

Additionally, add chunk contiguity validation in the restore controller to detect gaps early:

```rust
// In StateSnapshotRestoreController::run_impl
for i in 1..chunks.len() {
    ensure!(
        chunks[i-1].last_idx + 1 == chunks[i].first_idx,
        "Gap detected: chunk {} ends at {}, chunk {} starts at {}",
        i-1, chunks[i-1].last_idx, i, chunks[i].first_idx
    );
}
```

## Proof of Concept

**Reproduction Steps:**

1. Generate a legitimate state snapshot backup with chunks covering keys 0-1000
2. Modify the manifest to remove the last chunk (keys 900-1000)  
3. Start a fresh node and restore from this modified backup
4. Observe that restoration completes successfully despite missing data
5. Attempt to sync or participate in consensus - node will fail due to incorrect state root

**Test Case** (pseudocode for `storage/jellyfish-merkle/src/restore/mod.rs`):

```rust
#[test]
fn test_incomplete_restore_missing_final_validation() {
    let db = MockTreeStore::new();
    let expected_root = compute_root_hash_for_keys(0..1000);
    
    let mut restore = JellyfishMerkleRestore::new(
        db.clone(),
        version,
        expected_root,
        false
    ).unwrap();
    
    // Add chunks covering only keys 0-800 (missing 801-1000)
    for chunk in generate_chunks(0..800) {
        restore.add_chunk_impl(chunk.data, chunk.proof).unwrap();
    }
    
    // BUG: This succeeds even though we're missing keys 801-1000
    assert!(restore.finish_impl().is_ok());
    
    // The actual root hash doesn't match expected
    let actual_root = db.get_root_hash(version).unwrap();
    assert_ne!(actual_root, expected_root); // This should have been caught!
}
```

The test demonstrates that `finish_impl()` returns `Ok()` even when the final state is incomplete and has a different root hash than expected.

### Citations

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L176-176)
```rust
    expected_root_hash: HashValue,
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L339-413)
```rust
    pub fn add_chunk_impl(
        &mut self,
        mut chunk: Vec<(&K, HashValue)>,
        proof: SparseMerkleRangeProof,
    ) -> Result<()> {
        if self.finished {
            info!("State snapshot restore already finished, ignoring entire chunk.");
            return Ok(());
        }

        if let Some(prev_leaf) = &self.previous_leaf {
            let skip_until = chunk
                .iter()
                .find_position(|(key, _hash)| key.hash() > *prev_leaf.account_key());
            chunk = match skip_until {
                None => {
                    info!("Skipping entire chunk.");
                    return Ok(());
                },
                Some((0, _)) => chunk,
                Some((num_to_skip, next_leaf)) => {
                    info!(
                        num_to_skip = num_to_skip,
                        next_leaf = next_leaf,
                        "Skipping leaves."
                    );
                    chunk.split_off(num_to_skip)
                },
            }
        };
        if chunk.is_empty() {
            return Ok(());
        }

        for (key, value_hash) in chunk {
            let hashed_key = key.hash();
            if let Some(ref prev_leaf) = self.previous_leaf {
                ensure!(
                    &hashed_key > prev_leaf.account_key(),
                    "State keys must come in increasing order.",
                )
            }
            self.previous_leaf.replace(LeafNode::new(
                hashed_key,
                value_hash,
                (key.clone(), self.version),
            ));
            self.add_one(key, value_hash);
            self.num_keys_received += 1;
        }

        // Verify what we have added so far is all correct.
        self.verify(proof)?;

        // Write the frozen nodes to storage.
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
    }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L750-789)
```rust
    pub fn finish_impl(mut self) -> Result<()> {
        self.wait_for_async_commit()?;
        // Deal with the special case when the entire tree has a single leaf or null node.
        if self.partial_nodes.len() == 1 {
            let mut num_children = 0;
            let mut leaf = None;
            for i in 0..16 {
                if let Some(ref child_info) = self.partial_nodes[0].children[i] {
                    num_children += 1;
                    if let ChildInfo::Leaf(node) = child_info {
                        leaf = Some(node.clone());
                    }
                }
            }

            match num_children {
                0 => {
                    let node_key = NodeKey::new_empty_path(self.version);
                    assert!(self.frozen_nodes.is_empty());
                    self.frozen_nodes.insert(node_key, Node::Null);
                    self.store.write_node_batch(&self.frozen_nodes)?;
                    return Ok(());
                },
                1 => {
                    if let Some(node) = leaf {
                        let node_key = NodeKey::new_empty_path(self.version);
                        assert!(self.frozen_nodes.is_empty());
                        self.frozen_nodes.insert(node_key, node.into());
                        self.store.write_node_batch(&self.frozen_nodes)?;
                        return Ok(());
                    }
                },
                _ => (),
            }
        }

        self.freeze(0);
        self.store.write_node_batch(&self.frozen_nodes)?;
        Ok(())
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L260-273)
```rust
    fn finish(self) -> Result<()> {
        match self.restore_mode {
            StateSnapshotRestoreMode::KvOnly => self.kv_restore.lock().take().unwrap().finish()?,
            StateSnapshotRestoreMode::TreeOnly => {
                self.tree_restore.lock().take().unwrap().finish_impl()?
            },
            StateSnapshotRestoreMode::Default => {
                // for tree only mode, we also need to write the usage to DB
                self.kv_restore.lock().take().unwrap().finish()?;
                self.tree_restore.lock().take().unwrap().finish_impl()?
            },
        }
        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L187-226)
```rust
        let futs_iter = chunks.into_iter().enumerate().map(|(chunk_idx, chunk)| {
            let storage = storage.clone();
            async move {
                tokio::spawn(async move {
                    let blobs = Self::read_state_value(&storage, chunk.blobs.clone()).await?;
                    let proof = storage.load_bcs_file(&chunk.proof).await?;
                    Result::<_>::Ok((chunk_idx, chunk, blobs, proof))
                })
                .await?
            }
        });
        let con = self.concurrent_downloads;
        let mut futs_stream = stream::iter(futs_iter).buffered_x(con * 2, con);
        let mut start = None;
        while let Some((chunk_idx, chunk, mut blobs, proof)) = futs_stream.try_next().await? {
            start = start.or_else(|| Some(Instant::now()));
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["add_state_chunk"]);
            let receiver = receiver.clone();
            if self.validate_modules {
                blobs = tokio::task::spawn_blocking(move || {
                    Self::validate_modules(&blobs);
                    blobs
                })
                .await?;
            }
            tokio::task::spawn_blocking(move || {
                receiver.lock().as_mut().unwrap().add_chunk(blobs, proof)
            })
            .await??;
            leaf_idx.set(chunk.last_idx as i64);
            info!(
                chunk = chunk_idx,
                chunks_to_add = chunks_to_add,
                last_idx = chunk.last_idx,
                values_per_second = ((chunk.last_idx + 1 - start_idx) as f64
                    / start.as_ref().unwrap().elapsed().as_secs_f64())
                    as u64,
                "State chunk added.",
            );
        }
```
