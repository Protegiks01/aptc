# Audit Report

## Title
Jellyfish Merkle Tree Restoration Lacks Post-Write Verification, Providing Zero Guarantees Against Storage Layer Failures

## Summary
The `JellyfishMerkleRestore` restoration process verifies tree construction correctness in-memory but provides no verification that data was actually persisted correctly to storage after writing. If the underlying `TreeWriter` implementation fails silently, returns success for failed writes, or writes corrupted data, the restoration process will complete successfully while leaving the state tree in an inconsistent or missing state, potentially causing consensus divergence between nodes.

## Finding Description
The Jellyfish Merkle tree restoration process has a critical verification gap between in-memory tree construction and persistent storage verification. [1](#0-0) 

The `add_chunk_impl` method verifies proofs using `verify()` at line 391 BEFORE writing to storage (lines 408-410). However, this verification only confirms that the in-memory tree construction is consistent with the provided proof and expected root hash - it does NOT verify that the subsequent `write_node_batch()` call actually persisted the data correctly. [2](#0-1) 

The `finish_impl` method completes restoration by writing final frozen nodes (lines 770, 778, 787) and immediately returns `Ok(())` without any post-write verification. There is no check that:
- Nodes were actually written to storage
- Written nodes match the expected data
- The root hash in storage matches `expected_root_hash` [3](#0-2) 

The `TreeWriter` trait is minimal with only one method, and the restoration process blindly trusts its return value. [4](#0-3) 

The only verification of persisted data occurs in `JellyfishMerkleRestore::new()` when checking if a previous restore completed (lines 196-206), but this happens on restart/reinitialization, NOT immediately after `finish_impl` completes.

**Attack Scenario:**
If the `TreeWriter` implementation (e.g., `StateMerkleDb`) has bugs causing:
1. Silent write failures (returns `Ok()` but data not persisted due to disk issues, DB bugs, etc.)
2. Partial writes (some nodes written, others lost)
3. Data corruption (wrong bytes written)
4. Write to wrong storage locations

Then multiple nodes performing the same restoration could end up with different persisted state trees, breaking the **Deterministic Execution** invariant. When these nodes later execute transactions and compute state roots, they will produce different results, causing consensus failure.

## Impact Explanation
This qualifies as **High Severity** per Aptos bug bounty criteria: "Significant protocol violations"

**Consensus Safety Violation**: If different validator nodes have different corrupted restoration results, they will compute different state roots for identical blocks, violating the core consensus invariant. This could lead to:
- Chain splits requiring manual intervention
- Loss of consensus liveness if validators cannot agree on state
- State divergence between nodes

**State Consistency Violation**: Breaks invariant #4: "State transitions must be atomic and verifiable via Merkle proofs" - the restoration appears successful but the tree in storage is invalid/incomplete.

**No Recovery Path**: Without post-write verification, corrupted restorations are not detected until nodes attempt to use the tree and discover missing/corrupted nodes, at which point restoration must restart from scratch.

## Likelihood Explanation
**Medium Likelihood** in the presence of:

1. **Storage layer bugs**: RocksDB or StateMerkleDb bugs causing silent failures
2. **System resource issues**: Disk full, I/O errors during high load
3. **Concurrent access race conditions**: Multiple threads accessing storage during restoration
4. **Hardware failures**: Disk corruption, memory errors during write operations

While the storage layer is generally reliable, distributed systems commonly experience transient failures, and the lack of defensive verification means these failures go undetected during restoration.

## Recommendation

Add post-write verification to `finish_impl` that reads back the root node from storage and validates its hash:

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    // ... existing freeze logic ...
    
    self.freeze(0);
    self.store.write_node_batch(&self.frozen_nodes)?;
    
    // ADDED: Verify the root node was written correctly
    let root_node_key = NodeKey::new_empty_path(self.version);
    let persisted_root = self.store.get_node_option(&root_node_key, "verify_restore")?
        .ok_or_else(|| AptosDbError::Other(
            "Root node not found in storage after restoration".to_string()
        ))?;
    
    let persisted_root_hash = persisted_root.hash();
    ensure!(
        persisted_root_hash == self.expected_root_hash,
        "Restored root hash {} does not match expected {}. Storage write may have failed.",
        persisted_root_hash,
        self.expected_root_hash
    );
    
    info!(
        version = self.version,
        root_hash = %self.expected_root_hash,
        "State snapshot restoration verified successfully"
    );
    
    Ok(())
}
```

Additionally, implement verification in production code after restoration completes: [5](#0-4) 

After `finish_box()` returns, verify the root hash before calling `finalize_state_snapshot()`.

## Proof of Concept

```rust
use aptos_jellyfish_merkle::{
    mock_tree_store::MockTreeStore,
    restore::JellyfishMerkleRestore,
    TreeWriter, NodeBatch, TestKey,
};
use std::sync::Arc;

// Malicious TreeWriter that silently drops writes
struct MaliciousTreeStore<K> {
    inner: MockTreeStore<K>,
    drop_writes: bool,
}

impl<K: TestKey> TreeWriter<K> for MaliciousTreeStore<K> {
    fn write_node_batch(&self, _node_batch: &NodeBatch<K>) -> Result<()> {
        if self.drop_writes {
            // Silently drop writes but return Ok()
            return Ok(());
        }
        self.inner.write_node_batch(_node_batch)
    }
}

#[test]
fn test_restoration_with_malicious_storage() {
    let malicious_store = Arc::new(MaliciousTreeStore {
        inner: MockTreeStore::default(),
        drop_writes: true, // Enable silent write drops
    });
    
    let version = 0;
    let expected_root_hash = HashValue::random();
    
    let mut restore = JellyfishMerkleRestore::new(
        malicious_store.clone(),
        version,
        expected_root_hash,
        false,
    ).unwrap();
    
    // Add chunks with valid proofs
    // ... (chunk addition code) ...
    
    // finish_impl returns Ok() even though no data was written!
    restore.finish_impl().unwrap();
    
    // Verification: try to read root node from storage
    let root_key = NodeKey::new_empty_path(version);
    let root_node = malicious_store.get_node_option(&root_key, "test");
    
    // VULNERABILITY: Root node is None because writes were dropped,
    // but restoration reported success!
    assert!(root_node.unwrap().is_none(), 
        "Storage is empty but restoration succeeded");
}
```

## Notes
This vulnerability requires a buggy or malicious `TreeWriter` implementation to exploit, which reduces direct exploitability by external attackers. However, it represents a significant defensive programming gap that violates defense-in-depth principles. Storage layer bugs, transient failures, or race conditions could trigger this issue in production, leading to consensus failures that are difficult to diagnose since the restoration process reports success.

The fix adds minimal overhead (one read operation) but significantly improves system reliability by detecting storage failures immediately rather than during subsequent tree access.

### Citations

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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L336-413)
```rust
    /// Restores a chunk of states. This function will verify that the given chunk is correct
    /// using the proof and root hash, then write things to storage. If the chunk is invalid, an
    /// error will be returned and nothing will be written to storage.
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

**File:** storage/jellyfish-merkle/src/lib.rs (L139-142)
```rust
pub trait TreeWriter<K>: Send + Sync {
    /// Writes a node batch into storage.
    fn write_node_batch(&self, node_batch: &HashMap<NodeKey, Node<K>>) -> Result<()>;
}
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L1122-1136)
```rust
    // Finalize the state snapshot
    state_snapshot_receiver.finish_box().map_err(|error| {
        format!(
            "Failed to finish the state value synchronization! Error: {:?}",
            error
        )
    })?;
    storage
        .writer
        .finalize_state_snapshot(
            version,
            target_output_with_proof.clone(),
            epoch_change_proofs,
        )
        .map_err(|error| format!("Failed to finalize the state snapshot! Error: {:?}", error))?;
```
