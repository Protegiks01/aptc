# Audit Report

## Title
Truncation Ordering Vulnerability Causes Orphaned Jellyfish Merkle Nodes Leading to Permanent Storage Bloat

## Summary

The `delete_nodes_and_stale_indices_at_or_after_version` function in the StateMerkleDb truncation logic deletes stale node indices before their corresponding JellyfishMerkleNodes. This ordering bug creates orphaned nodes when an index pointing to an older version node is deleted, but the node itself is not, resulting in permanent storage bloat requiring manual intervention.

## Finding Description

The vulnerability exists in the database truncation logic executed during crash recovery. The `delete_nodes_and_stale_indices_at_or_after_version` function performs deletions in this order: [1](#0-0) 

First, it deletes all `StaleNodeIndexSchema` and `StaleNodeIndexCrossEpochSchema` entries where `stale_since_version >= target_version`, then deletes `JellyfishMerkleNode` entries where `node.version >= target_version`.

The core issue stems from the structure of `StaleNodeIndex`: [2](#0-1) 

A `StaleNodeIndex` contains both `stale_since_version` (when the node became stale) and `node_key` (identifying the stale node). The `node_key` includes the node's original version, which is always less than `stale_since_version` because a node created at version V can only become stale at a later version W > V.

**Exploitation Scenario:**

When truncating to version 150, consider a stale index with `stale_since_version=200` pointing to a node with `node_key.version=100`:

1. The stale index is deleted (200 >= 150) ✓
2. The node at version 100 is NOT deleted (100 < 150) ✗
3. Result: Orphaned node with no index pointing to it

This is especially problematic for cross-epoch nodes tracked in `StaleNodeIndexCrossEpochSchema`: [3](#0-2) 

Nodes from earlier epochs (with `version <= previous_epoch_ending_version`) are tracked in the cross-epoch schema and are particularly vulnerable to this bug.

**Contrast with Correct Pruner Logic:**

The regular state merkle pruner correctly deletes nodes by directly using the node key from each index: [4](#0-3) 

This ensures the actual node version is used for deletion, regardless of when it became stale.

**Trigger Path:**

Truncation is triggered during crash recovery: [5](#0-4) 

When `sync_commit_progress` detects inconsistent commit progress between database components, it calls `truncate_state_merkle_db`, which invokes the vulnerable deletion function.

## Impact Explanation

**Severity: Medium**

This vulnerability qualifies as Medium severity under Aptos bug bounty criteria for "State inconsistencies requiring manual intervention":

- **Permanent Storage Bloat**: Orphaned nodes accumulate indefinitely with no automatic cleanup mechanism. Each truncation event during crash recovery can orphan multiple nodes.

- **Operational Impact**: Over time, database size grows unnecessarily, leading to increased disk I/O, slower database operations, higher infrastructure costs, and potentially degraded validator performance.

- **Manual Intervention Required**: The orphaned nodes cannot be cleaned up by normal pruning operations and require manual database maintenance or custom tooling.

The impact does not reach High/Critical because:
- No consensus violations occur (state roots remain valid)
- No fund loss (state values are correct)
- Network continues operating normally

However, on production validators experiencing frequent restarts or operating in unstable environments, this issue compounds over months, potentially adding gigabytes of uncleanable storage.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability manifests under realistic production conditions:

1. **Trigger Frequency**: Crash recovery occurs whenever validators experience unclean shutdowns, process crashes, or infrastructure failures - common in production environments.

2. **Cross-Epoch Nodes**: Epoch transitions occur regularly (~2 hours on mainnet), creating frequent opportunities for cross-epoch stale nodes that are vulnerable to this bug.

3. **Permanence**: Each truncation event creates more orphaned nodes with no recovery mechanism, causing the issue to compound over time.

4. **Test Coverage Gap**: The existing test suite does not catch this bug: [6](#0-5) 

Tests only verify that remaining entries satisfy version constraints (`stale_since_version <= target_version` and `node.version <= target_version`), not that all stale nodes are properly cleaned up. The tests do not check for orphaned nodes.

## Recommendation

Fix the truncation ordering to match the pruner's approach. Instead of deleting nodes based on their version, delete nodes referenced by the stale indices being removed:

```rust
fn delete_nodes_and_stale_indices_at_or_after_version(
    db: &DB,
    version: Version,
    shard_id: Option<usize>,
    batch: &mut SchemaBatch,
) -> Result<()> {
    // Collect indices to delete
    let mut indices_to_delete = Vec::new();
    
    let mut iter = db.iter::<StaleNodeIndexSchema>()?;
    iter.seek(&version)?;
    for item in iter {
        let (index, _) = item?;
        indices_to_delete.push(index);
    }
    
    let mut iter = db.iter::<StaleNodeIndexCrossEpochSchema>()?;
    iter.seek(&version)?;
    for item in iter {
        let (index, _) = item?;
        indices_to_delete.push(index);
    }
    
    // Delete nodes first using index.node_key, then delete indices
    for index in indices_to_delete.iter() {
        batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
    }
    
    for index in indices_to_delete {
        // Delete from appropriate schema based on type
        batch.delete::<StaleNodeIndexSchema>(&index)?;
        batch.delete::<StaleNodeIndexCrossEpochSchema>(&index)?;
    }
    
    // Then delete any remaining nodes with version >= target_version
    // that weren't already deleted above
    let mut iter = db.iter::<JellyfishMerkleNodeSchema>()?;
    iter.seek(&NodeKey::new_empty_path(version))?;
    for item in iter {
        let (key, _) = item?;
        batch.delete::<JellyfishMerkleNodeSchema>(&key)?;
    }

    StateMerkleDb::put_progress(version.checked_sub(1), shard_id, batch)
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a validator node with epoch transitions
2. Generating cross-epoch stale nodes (nodes from version V that become stale at version W > V after an epoch boundary)
3. Simulating a crash requiring truncation to a version between V and W
4. Observing that nodes at version V remain in the database despite having no corresponding stale indices

The existing test at `storage/aptosdb/src/db_debugger/truncate/mod.rs:194-393` passes despite the bug because it only validates version constraints, not the absence of orphaned nodes. A proper test would need to verify that every `JellyfishMerkleNode` in the database either:
- Is the current node at its version, OR
- Has a corresponding `StaleNodeIndex` entry pointing to it

The absence of such verification allows orphaned nodes to persist undetected.

### Citations

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L609-619)
```rust
    delete_stale_node_index_at_or_after_version::<StaleNodeIndexSchema>(db, version, batch)?;
    delete_stale_node_index_at_or_after_version::<StaleNodeIndexCrossEpochSchema>(
        db, version, batch,
    )?;

    let mut iter = db.iter::<JellyfishMerkleNodeSchema>()?;
    iter.seek(&NodeKey::new_empty_path(version))?;
    for item in iter {
        let (key, _) = item?;
        batch.delete::<JellyfishMerkleNodeSchema>(&key)?;
    }
```

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

**File:** storage/aptosdb/src/state_merkle_db.rs (L378-385)
```rust
            if previous_epoch_ending_version.is_some()
                && row.node_key.version() <= previous_epoch_ending_version.unwrap()
            {
                batch.put::<StaleNodeIndexCrossEpochSchema>(row, &())
            } else {
                // These are processed by the state merkle pruner.
                batch.put::<StaleNodeIndexSchema>(row, &())
            }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_metadata_pruner.rs (L61-64)
```rust
        indices.into_iter().try_for_each(|index| {
            batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
            batch.delete::<S>(&index)
        })?;
```

**File:** storage/aptosdb/src/state_store/mod.rs (L490-497)
```rust
            if state_merkle_target_version < state_merkle_max_version {
                info!(
                    state_merkle_max_version = state_merkle_max_version,
                    target_version = state_merkle_target_version,
                    "Start state merkle truncation..."
                );
                truncate_state_merkle_db(&state_merkle_db, state_merkle_target_version)
                    .expect("Failed to truncate state merkle db.");
```

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L340-352)
```rust
            let mut iter = state_merkle_db.metadata_db().iter::<StaleNodeIndexCrossEpochSchema>().unwrap();
            iter.seek_to_first();
            for item in iter {
                let version = item.unwrap().0.stale_since_version;
                prop_assert!(version <= target_version);
            }

            let mut iter = state_merkle_db.metadata_db().iter::<JellyfishMerkleNodeSchema>().unwrap();
            iter.seek_to_first();
            for item in iter {
                let version = item.unwrap().0.version();
                prop_assert!(version <= target_version);
            }
```
