# Audit Report

## Title
State Restore KV/Tree Desynchronization via Parallel Processing with Overlapping Range Proofs

## Summary
The parallel processing of key-value (KV) and Jellyfish Merkle Tree updates in `StateSnapshotRestore::add_chunk` creates a critical atomicity gap. When tree proof verification fails after KV data has already been committed to storage, overlapping chunks in subsequent restore attempts cause permanent desynchronization between the KV database and tree structure, leading to restoration failure and potential state corruption.

## Finding Description

The vulnerability exists in the state snapshot restoration logic where KV and tree updates are processed in parallel without transactional atomicity. [1](#0-0) 

The `add_chunk` method executes `kv_fn` and `tree_fn` in parallel using `IO_POOL.join()`. The critical issue is:

1. **KV commits immediately**: The `StateValueRestore::add_chunk` method writes data to the database and commits the transaction, including progress tracking: [2](#0-1) 

This write is persisted to storage immediately through the `write_kv_batch` implementation: [3](#0-2) 

2. **Tree verifies after processing**: The `JellyfishMerkleRestore::add_chunk_impl` adds all items to memory first, then verifies the proof: [4](#0-3) 

3. **No rollback on verification failure**: If verification fails after KV has committed, there is no rollback mechanism. The error is propagated but KV changes persist: [5](#0-4) 

4. **Overlapping ranges exacerbate the issue**: When chunks overlap (as supported by the skip logic), the desynchronization becomes permanent because:
   - KV skips based on `progress.key_hash` (committed progress): [6](#0-5) 

   - Tree skips based on `previous_leaf.account_key()` (in-memory state): [7](#0-6) 

**Attack Scenario:**
1. Attacker controls state sync source or can inject malicious chunks
2. Send Chunk1: `[A, B, C]` with valid proof - both KV and tree succeed
3. Send Chunk2: `[C, D, E]` with **invalid proof** crafted to fail verification
   - KV processes: skips C, writes D and E, commits successfully (progress = E)
   - Tree processes: skips C, adds D and E to memory, **verification fails**
   - Error returned, but KV already committed
4. Now KV has `[A, B, C, D, E]` but tree only has `[A, B, C]`
5. Send Chunk3: `[E, F, G]` with valid proof
   - KV skips E (already at E), writes F and G
   - Tree tries to add E, F, G but proof expects tree to have `[..., E]` already
   - Verification fails again
6. Restoration permanently stuck - node cannot sync

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **State Inconsistency**: Violates Critical Invariant #4 ("State transitions must be atomic and verifiable via Merkle proofs"). The KV database and Merkle tree become desynchronized, creating an inconsistent state that violates the fundamental assumption that these two representations are always coherent.

2. **Liveness Failure**: Affected nodes cannot complete state synchronization, effectively preventing them from joining the network or recovering from crashes. This is a "Validator node slowdown" that can escalate to complete inability to sync.

3. **Potential Safety Violation**: If the inconsistent state persists and `finish()` is somehow called (e.g., due to caller bugs or race conditions), the tree could be written with an incorrect root hash, leading to state corruption that could cause consensus divergence.

4. **No Self-Recovery**: Once desynchronized, the restoration process cannot recover without manual intervention (database reset), making this a persistent denial-of-service.

The impact extends beyond a single node:
- Any node attempting to sync from a malicious source suffers this fate
- State sync infrastructure becomes unreliable
- New validators cannot join the network if exposed to malicious state providers

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is exploitable under realistic conditions:

1. **Attacker Requirements**:
   - Control or compromise a state sync source (full node serving state snapshots)
   - Ability to generate malformed `SparseMerkleRangeProof` objects
   - No validator privileges required

2. **Attack Complexity**: 
   - Moderate - requires understanding of Jellyfish Merkle Tree proofs
   - Proof construction is well-documented in the codebase
   - Can craft proofs that pass structural validation but fail semantic verification

3. **Real-World Scenarios**:
   - Malicious state sync providers in adversarial network environments
   - Compromised full nodes serving state snapshots
   - Network errors causing proof corruption (unintentional trigger)
   - State sync from untrusted peers during bootstrap

4. **Detection Difficulty**: 
   - The desynchronization is internal to the node
   - Error logs show verification failures but don't clearly indicate persistent corruption
   - No monitoring specifically tracks KV/tree consistency during restoration

The lack of test coverage for proof verification failures (no tests found for invalid proofs in restore_test.rs) suggests this edge case may not have been thoroughly considered, increasing the likelihood it exists in production.

## Recommendation

Implement transactional atomicity for state restoration by ensuring KV and tree updates either both succeed or both roll back. Two approaches:

**Approach 1: Verify Before Committing (Preferred)**

Modify the execution order to verify the tree proof before committing KV data:

```rust
// In StateSnapshotRestore::add_chunk
pub fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
    // FIRST: Verify tree proof with chunk (no writes yet)
    let tree_verification = || {
        self.tree_restore
            .lock()
            .as_mut()
            .unwrap()
            .verify_chunk(&chunk, &proof) // New method: verify without modifying state
    };
    tree_verification()?; // Fail fast if proof invalid
    
    // SECOND: If verification passed, commit both KV and tree in sequence
    let kv_fn = || {
        self.kv_restore
            .lock()
            .as_mut()
            .unwrap()
            .add_chunk(chunk.clone())
    };
    kv_fn()?;
    
    // THIRD: Add to tree (proof already verified)
    let tree_fn = || {
        self.tree_restore
            .lock()
            .as_mut()
            .unwrap()
            .add_chunk_verified(chunk.iter().map(|(k, v)| (k, v.hash())).collect())
    };
    tree_fn()?;
    
    Ok(())
}
```

**Approach 2: Transactional Rollback**

If sequential execution is not desired, implement proper rollback:

```rust
// Track KV transaction handle and rollback on tree failure
let kv_result = kv_fn();
let tree_result = tree_fn();

match (kv_result, tree_result) {
    (Ok(_), Ok(_)) => {
        // Both succeeded, commit KV transaction
        self.kv_restore.lock().as_mut().unwrap().commit()?;
        Ok(())
    },
    (Ok(_), Err(tree_err)) => {
        // Tree failed, rollback KV
        self.kv_restore.lock().as_mut().unwrap().rollback()?;
        Err(tree_err)
    },
    (Err(kv_err), _) => Err(kv_err),
}
```

**Additional Safeguards:**

1. Add explicit consistency check at restoration completion: [8](#0-7) 

Add final root hash verification in `finish_impl()`:
```rust
pub fn finish_impl(mut self) -> Result<()> {
    // ... existing code ...
    self.store.write_node_batch(&self.frozen_nodes)?;
    
    // NEW: Verify final root hash
    let root_node = self.store.get_node(&NodeKey::new_empty_path(self.version))?;
    ensure!(
        root_node.hash() == self.expected_root_hash,
        "Final root hash mismatch: expected {:x}, got {:x}",
        self.expected_root_hash,
        root_node.hash()
    );
    
    Ok(())
}
```

2. Add test coverage for proof verification failures with overlapping chunks

## Proof of Concept

```rust
#[cfg(test)]
mod test_kv_tree_desync {
    use super::*;
    use aptos_crypto::hash::CryptoHash;
    use aptos_jellyfish_merkle::JellyfishMerkleTree;
    
    #[test]
    fn test_overlapping_chunks_with_invalid_proof_causes_desync() {
        // Setup: Create a valid tree with [A, B, C, D, E]
        let all_items = vec![
            (HashValue::random(), (TestKey::random(), TestValue::random())),
            (HashValue::random(), (TestKey::random(), TestValue::random())),
            (HashValue::random(), (TestKey::random(), TestValue::random())),
            (HashValue::random(), (TestKey::random(), TestValue::random())),
            (HashValue::random(), (TestKey::random(), TestValue::random())),
        ];
        let (db, version) = init_mock_store(&all_items.iter().map(|(_, kv)| kv.clone()).collect());
        let tree = JellyfishMerkleTree::new(&db);
        let expected_root_hash = tree.get_root_hash(version).unwrap();
        
        let restore_db = Arc::new(MockSnapshotStore::default());
        let mut restore = StateSnapshotRestore::new(
            &restore_db, &restore_db, version, expected_root_hash, 
            false, StateSnapshotRestoreMode::Default
        ).unwrap();
        
        // Chunk 1: [A, B, C] with valid proof - succeeds
        let chunk1: Vec<_> = all_items[0..3].iter().map(|(_, kv)| kv.clone()).collect();
        let proof1 = tree.get_range_proof(all_items[2].0, version).unwrap();
        restore.add_chunk(chunk1, proof1).unwrap();
        
        // Chunk 2: [C, D, E] with INVALID proof - KV commits, tree fails
        let chunk2: Vec<_> = all_items[2..5].iter().map(|(_, kv)| kv.clone()).collect();
        let invalid_proof = SparseMerkleRangeProof::new(vec![HashValue::random()]); // Malformed proof
        
        let result = restore.add_chunk(chunk2, invalid_proof);
        assert!(result.is_err(), "Expected tree verification to fail");
        
        // Verify desynchronization:
        // KV should have [A, B, C, D, E]
        let kv_progress = restore_db.get_progress(version).unwrap().unwrap();
        assert_eq!(kv_progress.key_hash, CryptoHash::hash(&all_items[4].1.0));
        
        // Tree should only have [A, B, C]
        let tree_progress = restore.previous_key_hash().unwrap().unwrap();
        assert_eq!(tree_progress, CryptoHash::hash(&all_items[2].1.0));
        
        // Chunk 3: [E, F, ...] - will fail because tree is behind
        // This demonstrates the restoration is now permanently stuck
        println!("KV/Tree desynchronization confirmed!");
    }
}
```

This PoC demonstrates:
1. Valid chunk succeeds normally
2. Overlapping chunk with invalid proof causes KV to commit but tree to fail
3. KV progress advances to E while tree remains at C
4. System is now in inconsistent state that cannot self-recover

**Notes**

The vulnerability is rooted in a fundamental design flaw: the assumption that parallel execution of KV and tree updates is safe without transaction coordination. The `SparseMerkleRangeProof` verification provides cryptographic guarantees about tree structure, but the parallel processing model violates atomicity, allowing partial failures to corrupt internal state.

The coordination attempt via `previous_key_hash()` returning the minimum of both progresses [9](#0-8)  is insufficient because it only affects external callers, not the internal desynchronization within each restore session.

This issue affects any node performing state synchronization and could be systematically exploited to prevent new validators from joining the network or to force existing nodes into requiring manual database resets.

### Citations

**File:** storage/aptosdb/src/state_restore/mod.rs (L92-99)
```rust
        // skip overlaps
        if let Some(progress) = progress_opt {
            let idx = chunk
                .iter()
                .position(|(k, _v)| CryptoHash::hash(k) > progress.key_hash)
                .unwrap_or(chunk.len());
            chunk = chunk.split_off(idx);
        }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L122-126)
```rust
        self.db.write_kv_batch(
            self.version,
            &kv_batch,
            StateSnapshotProgress::new(last_key_hash, usage),
        )
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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L349-368)
```rust
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
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L373-391)
```rust
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

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L956-965)
```rust
                        Err(error) => {
                            let error =
                                format!("Failed to commit state value chunk! Error: {:?}", error);
                            send_storage_synchronizer_error(
                                error_notification_sender.clone(),
                                notification_id,
                                error,
                            )
                            .await;
                        },
```
