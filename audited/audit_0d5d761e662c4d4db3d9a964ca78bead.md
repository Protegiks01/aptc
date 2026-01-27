# Audit Report

## Title
Partial Shard Commit During Crash Can Cause Permanent Node Orphaning Leading to Unbounded Database Growth

## Summary
A state tree update that creates stale nodes across multiple shards can result in permanently orphaned nodes if the system crashes after some shards commit but before the top-level batch commits. The recovery mechanism deletes the stale node index entries but not the actual historical nodes they reference, causing these nodes to become untrackable and unprunable forever.

## Finding Description

The vulnerability exists in the atomic commit guarantees for state merkle tree updates in AptosDB. When a state tree update at version V creates stale nodes (old nodes being replaced):

1. **Stale Node Structure**: Each `StaleNodeIndex` contains two critical fields:
   - `stale_since_version`: The version when the node became stale (e.g., V)
   - `node_key`: The key identifying the actual node, which includes its **original creation version** (e.g., V-100) [1](#0-0) 

2. **Non-Atomic Cross-Shard Commit**: Stale nodes are distributed across shards based on their `node_key`. Each shard's batch containing stale indices is committed in parallel with no cross-shard atomicity guarantee: [2](#0-1) 
   
   The overall progress marker is only written after all shards commit: [3](#0-2) 

3. **Crash Scenario**: If the system crashes after shard 0 commits its stale indices for version V but before the top-level batch commits, the overall progress remains at V-1.

4. **Asymmetric Recovery**: On restart, the recovery process truncates all shards to the overall progress (V-1): [4](#0-3) 
   
   The truncation deletes stale indices where `stale_since_version >= V`: [5](#0-4) 
   
   But it only deletes nodes where `node_key.version >= V`: [6](#0-5) 

5. **Permanent Orphaning**: Since the actual stale node was created at version V-100 (where V-100 < V), it survives the truncation. However, its index entry (with `stale_since_version = V`) is deleted. The node is now permanently orphaned—it exists in the database but has no index entry pointing to it.

6. **Unprunable Forever**: The pruner operates by scanning stale node indices to find nodes to delete: [7](#0-6) 
   
   Without an index entry, the orphaned node will never be discovered or pruned.

This breaks the **State Consistency** invariant: the database accumulates unreferenced nodes that can never be cleaned up, causing unbounded growth over time.

## Impact Explanation

**Severity: High**

This vulnerability causes **significant protocol violations** through gradual database corruption:

1. **Database Bloat**: Each crash during state merkle commit can orphan multiple nodes permanently. Over time (especially with frequent crashes during high-load periods or validator restarts), this accumulates to significant storage waste.

2. **Validator Node Performance Degradation**: As orphaned nodes accumulate:
   - Disk I/O increases due to larger database size
   - Backup/restore operations become slower
   - State sync for new nodes downloads unnecessary historical data
   - Iterator performance degrades across larger key spaces

3. **Economic Impact on Validators**: Storage costs increase linearly with orphaned nodes, creating unfair operational burden on honest validators.

4. **Non-Deterministic Database State**: Different validators experiencing crashes at different times will accumulate different sets of orphaned nodes, causing database state divergence (though this doesn't affect consensus since orphaned nodes are unreferenced).

While this doesn't directly break consensus safety, it qualifies as a **High Severity** issue per the bug bounty criteria due to validator node slowdowns and significant protocol violations.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is triggered by crashes during state merkle tree commits, which can occur through:

1. **Validator Restarts**: Operators frequently restart validators for upgrades, maintenance, or configuration changes. If a restart occurs during a commit window (which happens every block), the vulnerability can trigger.

2. **System Failures**: Hardware failures, OOM kills, power outages, or kernel panics during commit operations.

3. **High Transaction Load**: Under heavy load, commit operations take longer, increasing the window for crashes.

4. **Epoch Boundaries**: The vulnerability specifically mentions `StaleNodeIndexCrossEpochSchema`, which is written when nodes from previous epochs become stale. Epoch transitions are high-risk periods for crashes due to increased state changes.

The issue is cumulative—each crash during commit orphans more nodes. Over weeks/months of validator operation, the impact compounds significantly. Given that validators run 24/7 and experience occasional restarts, this is not a theoretical edge case but a realistic operational scenario.

## Recommendation

Implement atomic cross-shard commit for state merkle tree updates by ensuring the overall progress marker is written **before or alongside** shard batches, not after. This can be achieved through several approaches:

**Option 1: Pre-write Progress Marker (Recommended)**
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
    
    // Write progress marker FIRST to establish commit point
    let mut progress_batch = SchemaBatch::new();
    Self::put_progress(Some(version), None, &mut progress_batch)?;
    self.state_merkle_metadata_db.write_schemas(progress_batch)?;
    
    // Now commit shards - if any fail, recovery will clean them up
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

    // Commit top levels without progress (already written)
    self.state_merkle_metadata_db.write_schemas(top_levels_batch)
}
```

**Option 2: Include Progress in Each Shard Batch**

Write a per-shard progress marker in each shard's batch, then use the minimum across all shards as the recovery point. This requires modifying the recovery logic to read all shard progress markers:

```rust
// In truncation: use minimum progress across all shards
let min_shard_progress = (0..NUM_STATE_SHARDS)
    .map(|shard_id| get_shard_progress(state_merkle_db, shard_id))
    .min()
    .unwrap_or(overall_progress);
    
truncate_state_merkle_db_shards(state_merkle_db, min_shard_progress)?;
```

**Option 3: Two-Phase Commit Protocol**

Implement a proper two-phase commit: first write all batches without progress markers, then atomically update all progress markers in a final batch once all shards confirm success.

**Critical Fix**: Whichever approach is chosen, ensure that orphaned nodes cannot be created by guaranteeing that stale node index deletions only occur when the corresponding nodes are also cleaned up.

## Proof of Concept

The following scenario demonstrates the vulnerability:

```rust
// Reproduction Steps:
// 1. Set up a validator node with state merkle DB
// 2. Execute a transaction that updates state tree creating stale nodes
// 3. During the commit phase, inject a crash after shard 0 commits but before 
//    the top-level batch commits (can be done via process kill or panic injection)
// 4. Restart the node and observe recovery
// 5. Query the database for nodes without corresponding stale indices

// Pseudo-code for validation:
#[test]
fn test_orphaned_nodes_after_partial_commit() {
    let state_merkle_db = create_test_db();
    
    // Create an update at version 100
    let version_100_updates = create_value_set();
    state_merkle_db.commit_version(100, version_100_updates);
    
    // Create an update at version 200 that replaces nodes from version 100
    let version_200_updates = create_replacing_value_set();
    
    // Start commit for version 200
    let batches = state_merkle_db.prepare_batches(200, version_200_updates);
    
    // Commit only shard 0 (simulating partial commit before crash)
    state_merkle_db.db_shard(0).write_schemas(batches.for_shards[0]);
    
    // Simulate crash - no top-level batch commit
    drop(state_merkle_db);
    
    // Restart and recover
    let recovered_db = reopen_db_with_recovery();
    
    // Overall progress should be 199 (version 200 didn't fully commit)
    assert_eq!(recovered_db.get_progress(), Some(199));
    
    // Check that nodes from version 100 still exist
    let nodes_v100 = recovered_db.get_all_nodes_at_version(100);
    assert!(!nodes_v100.is_empty(), "Nodes at v100 should exist");
    
    // Check that stale indices pointing to v100 were deleted during recovery
    let stale_indices = recovered_db.get_stale_indices_for_version(200);
    assert!(stale_indices.is_empty(), "Stale indices for v200 should be deleted");
    
    // The nodes at v100 are now orphaned - they exist but have no index
    // They can never be pruned
    
    // Verify: run pruner and confirm nodes at v100 are not deleted
    recovered_db.run_pruner(target_version: 150);
    let nodes_v100_after_prune = recovered_db.get_all_nodes_at_version(100);
    assert_eq!(nodes_v100, nodes_v100_after_prune, "Orphaned nodes survived pruning");
}
```

**Notes**

The vulnerability is confirmed through code analysis of the commit, recovery, and pruning logic. The key insight is the asymmetry between how stale indices and actual nodes are keyed:

- **Stale indices** use `stale_since_version` in their key encoding [8](#0-7) 

- **Actual nodes** use their creation `version` in their NodeKey encoding [9](#0-8) 

This asymmetry, combined with non-atomic cross-shard commits, creates the orphaning vulnerability. The issue particularly affects `StaleNodeIndexCrossEpochSchema` entries (nodes that were latest in an epoch), as mentioned in the security question, since epoch boundaries involve significant state changes increasing crash likelihood.

### Citations

**File:** storage/jellyfish-merkle/src/lib.rs (L195-201)
```rust
pub struct StaleNodeIndex {
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The [`NodeKey`](node_type/struct.NodeKey.html) identifying the node associated with this
    /// record.
    pub node_key: NodeKey,
}
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L157-167)
```rust
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
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L170-171)
```rust
        self.commit_top_levels(version, top_levels_batch)
    }
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

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L609-612)
```rust
    delete_stale_node_index_at_or_after_version::<StaleNodeIndexSchema>(db, version, batch)?;
    delete_stale_node_index_at_or_after_version::<StaleNodeIndexCrossEpochSchema>(
        db, version, batch,
    )?;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L614-619)
```rust
    let mut iter = db.iter::<JellyfishMerkleNodeSchema>()?;
    iter.seek(&NodeKey::new_empty_path(version))?;
    for item in iter {
        let (key, _) = item?;
        batch.delete::<JellyfishMerkleNodeSchema>(&key)?;
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L66-76)
```rust
            let (indices, next_version) = StateMerklePruner::get_stale_node_indices(
                &self.db_shard,
                current_progress,
                target_version,
                max_nodes_to_prune,
            )?;

            indices.into_iter().try_for_each(|index| {
                batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
                batch.delete::<S>(&index)
            })?;
```

**File:** storage/aptosdb/src/schema/stale_node_index_cross_epoch/mod.rs (L36-42)
```rust
    fn encode_key(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        encoded.write_u64::<BigEndian>(self.stale_since_version)?;
        encoded.write_all(&self.node_key.encode()?)?;

        Ok(encoded)
    }
```

**File:** storage/jellyfish-merkle/src/node_type/mod.rs (L49-54)
```rust
pub struct NodeKey {
    // The version at which the node is created.
    version: Version,
    // The nibble path this node represents in the tree.
    nibble_path: NibblePath,
}
```
