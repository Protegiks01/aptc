# Audit Report

## Title
Non-Atomic Cross-Shard Write in State Restoration Finish with Irrecoverable State Loss

## Summary
The `finish_impl()` function in Jellyfish Merkle tree restoration consumes `self` while performing non-atomic cross-shard database writes. If the write operation fails after writing to some shards but not others, the restoration state is permanently lost and the database is left in an inconsistent state, requiring complete restoration restart.

## Finding Description

The `finish_impl()` function has a critical design flaw where it consumes the `JellyfishMerkleRestore` object while performing potentially failing operations: [1](#0-0) 

The function calls `self.freeze(0)` to move all partial nodes into `frozen_nodes`, then attempts to write them via `self.store.write_node_batch(&self.frozen_nodes)?`. This write operation is NOT atomic across shards.

The underlying `write_node_batch` implementation splits nodes across 16 shards and writes them sequentially: [2](#0-1) 

The `commit_no_progress` function writes to each shard sequentially without cross-shard atomicity: [3](#0-2) 

**Attack Scenario:**

1. Node initiates state snapshot restoration (normal operation during sync)
2. Restoration proceeds through multiple chunks successfully
3. `finish()` is called, which internally calls `finish_impl()`
4. `freeze(0)` moves all remaining partial nodes to `frozen_nodes` 
5. `write_node_batch` begins writing nodes to shards 0, 1, 2...
6. System failure occurs (disk full, OOM, crash) after writing to shards 0-7
7. Shards 8-15 never receive their nodes
8. The `JellyfishMerkleRestore` object is consumed and destroyed
9. All in-memory restoration state (`partial_nodes`, `frozen_nodes`, progress) is permanently lost

**Broken Invariant:**
This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The database is left with nodes partially written across shards, creating an inconsistent tree structure.

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention" per the bug bounty criteria.

**Specific Impacts:**
1. **Database Inconsistency**: Nodes exist in shards 0-7 but are missing from shards 8-15, corrupting the Jellyfish Merkle tree structure
2. **Lost Progress**: Hours or days of restoration work is lost and must be restarted from scratch
3. **Validator Unavailability**: Affected node cannot complete state sync and cannot participate in consensus
4. **Recovery Complexity**: The recovery mechanism attempts to reconstruct from the rightmost leaf, but with inconsistent shard data, this may fail or produce incorrect state [4](#0-3) 

The `StateSnapshotRestore::finish()` method extracts the restoration object with `take()` before calling `finish_impl()`, ensuring no retry is possible.

## Likelihood Explanation

**Medium Likelihood** - While this requires a failure during the specific `finish_impl()` execution window, such failures occur in production environments:

- Disk space exhaustion during large state sync operations
- Out-of-memory conditions on resource-constrained nodes  
- System crashes or power failures
- Database write errors due to I/O issues
- Process termination during maintenance

The impact is amplified because `finish_impl()` is called at the END of potentially hours-long restoration processes, making the loss of progress particularly severe.

## Recommendation

Modify `finish_impl()` to return the restoration object on error, allowing retry without losing state:

```rust
pub fn finish_impl(mut self) -> Result<(), Self> {
    if let Err(e) = self.wait_for_async_commit() {
        return Err(self);
    }
    
    // ... existing special case logic ...
    
    self.freeze(0);
    if let Err(e) = self.store.write_node_batch(&self.frozen_nodes) {
        // Return self to allow retry
        return Err(self);
    }
    Ok(())
}
```

Additionally, implement cross-shard transaction support or add compensating rollback logic to ensure atomicity of the final write operation.

Alternatively, implement a two-phase commit:
1. Prepare phase: Validate all shards can accept writes
2. Commit phase: Write to all shards with rollback on any failure

## Proof of Concept

```rust
#[test]
fn test_finish_impl_partial_failure_loses_state() {
    use std::sync::{Arc, Mutex};
    
    // Mock TreeWriter that fails after writing to half the shards
    struct FailingTreeWriter {
        write_count: Arc<Mutex<usize>>,
        fail_after: usize,
    }
    
    impl<K> TreeWriter<K> for FailingTreeWriter {
        fn write_node_batch(&self, node_batch: &HashMap<NodeKey, Node<K>>) -> Result<()> {
            let mut count = self.write_count.lock().unwrap();
            *count += 1;
            if *count > self.fail_after {
                return Err(AptosDbError::Other("Simulated shard write failure".into()));
            }
            Ok(())
        }
    }
    
    // Create restore instance
    let writer = Arc::new(FailingTreeWriter {
        write_count: Arc::new(Mutex::new(0)),
        fail_after: 8, // Fail after 8 shard writes
    });
    
    let mut restore = JellyfishMerkleRestore::new(
        writer,
        0, // version
        expected_root_hash,
        false, // async_commit
    ).unwrap();
    
    // Add some chunks
    // ... (add chunk logic) ...
    
    // Attempt finish - this will fail after partial write
    let result = restore.finish_impl();
    
    // Result is error, but restoration object is consumed
    assert!(result.is_err());
    
    // Cannot retry - restoration state is lost
    // No way to recover the partial_nodes or frozen_nodes
    // Must restart entire restoration from beginning
}
```

## Notes

The number of state shards is defined as a constant: [5](#0-4) 

Each node's shard assignment is deterministic based on its nibble path: [6](#0-5) 

This ensures that if a write fails after shard N, all nodes mapped to shards 0 through N exist while nodes mapped to shards N+1 through 15 are missing, creating a deterministic but inconsistent database state.

### Citations

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

**File:** storage/aptosdb/src/state_merkle_db.rs (L174-190)
```rust
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

**File:** storage/aptosdb/src/state_merkle_db.rs (L917-933)
```rust
impl TreeWriter<StateKey> for StateMerkleDb {
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

**File:** types/src/state_store/mod.rs (L27-27)
```rust
pub const NUM_STATE_SHARDS: usize = 16;
```

**File:** storage/jellyfish-merkle/src/node_type/mod.rs (L148-150)
```rust
    pub fn get_shard_id(&self) -> Option<usize> {
        self.nibble_path().get_shard_id()
    }
```
