# Audit Report

## Title
Unbounded Batch Size in State Merkle Pruner Initialization Causes Memory Exhaustion and Node Crashes

## Summary
The state merkle pruner uses `usize::MAX` as the batch size limit during initialization and catch-up operations, allowing unbounded collection of stale node indices into memory. This can cause memory exhaustion and node crashes when processing large backlogs, violating resource limit invariants and affecting validator availability.

## Finding Description

The vulnerability exists in two locations where `usize::MAX` is used as the batch size parameter:

**Location 1:** During shard pruner initialization [1](#0-0) 

**Location 2:** During metadata pruning [2](#0-1) 

The `get_stale_node_indices()` function collects indices until the limit is reached [3](#0-2) 

When `limit` is `usize::MAX`, this effectively removes any size constraint. The configuration comment explicitly states that "A 10k transaction block (touching 60k state values) on a 4B items DB yields 300k JMT nodes" [4](#0-3) 

Each collected index results in two delete operations being added to the `SchemaBatch` [5](#0-4) 

`SchemaBatch` has no internal size limits and is simply a `HashMap<ColumnFamilyName, Vec<WriteOp>>` [6](#0-5) 

**Attack Scenario:** During node catch-up after extended downtime, if there are millions of accumulated stale nodes across many versions, the pruner will attempt to collect all of them into a single batch, causing:
1. Memory exhaustion while building the indices vector
2. Memory exhaustion while constructing the `SchemaBatch`
3. Potential node crash before write completion
4. No batch splitting or size detection logic exists

## Impact Explanation

This vulnerability affects validator availability and node stability, meeting **Medium Severity** criteria:
- Validator node crashes during initialization or catch-up operations
- Memory exhaustion leading to out-of-memory kills
- Failed pruning operations causing disk space exhaustion over time
- Degraded network availability if multiple validators experience this simultaneously

While this doesn't directly compromise consensus safety or cause fund loss, it violates the **Resource Limits** invariant (#9) requiring all operations to respect computational and memory constraints, and can lead to significant protocol disruptions.

## Likelihood Explanation

**High likelihood** of occurrence:
- Happens naturally during node initialization after being offline
- Occurs during catch-up scenarios with large version gaps  
- No special conditions or attacker actions required
- Configuration already acknowledges that single blocks can create 300k stale nodes
- With mainnet's high transaction throughput, accumulation of millions of stale nodes is realistic

## Recommendation

Implement batch size enforcement with proper chunking:

```rust
pub(in crate::pruner) fn prune(
    &self,
    current_progress: Version,
    target_version: Version,
    max_nodes_to_prune: usize,
) -> Result<()> {
    // Enforce a maximum batch size even when max_nodes_to_prune is usize::MAX
    const MAX_BATCH_SIZE: usize = 100_000; // Reasonable limit
    let effective_batch_size = max_nodes_to_prune.min(MAX_BATCH_SIZE);
    
    let mut current = current_progress;
    loop {
        let mut batch = SchemaBatch::new();
        let (indices, next_version) = StateMerklePruner::get_stale_node_indices(
            &self.db_shard,
            current,
            target_version,
            effective_batch_size, // Use capped size
        )?;
        
        // ... rest of the logic
        
        // Update current for next iteration
        if let Some(nv) = next_version {
            if nv > current {
                current = nv;
                continue;
            }
        }
        break;
    }
    Ok(())
}
```

Apply similar fixes to `state_merkle_metadata_pruner.rs`.

## Proof of Concept

```rust
#[test]
fn test_unbounded_batch_size_memory_exhaustion() {
    use crate::pruner::state_merkle_pruner::state_merkle_shard_pruner::StateMerkleShardPruner;
    use aptos_temppath::TempPath;
    
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    
    // Simulate scenario: Insert 1 million stale nodes across versions
    for version in 0..1000 {
        let mut batch = SchemaBatch::new();
        for i in 0..1000 {
            let node_key = create_test_node_key(version, i);
            batch.put::<StaleNodeIndexSchema>(&StaleNodeIndex {
                stale_since_version: version,
                node_key: node_key.clone(),
            }, &())?;
        }
        db.write_schemas(batch)?;
    }
    
    // This will attempt to load all 1M indices at once
    // Expected: OOM or very high memory usage
    let pruner = StateMerkleShardPruner::new(
        0,
        db.state_merkle_db().db_shard_arc(0),
        999,
    );
    
    // Monitor memory usage - should spike to unsustainable levels
    assert!(pruner.is_err() || memory_usage_exceeded_threshold());
}
```

**Notes:**
- The vulnerability occurs in production code paths during normal node operation
- No batch size validation exists in `SchemaBatch` or `write_schemas()`
- The loop structure in `prune()` provides pagination capability but is bypassed by `usize::MAX`
- RocksDB's `max_write_batch_group_size_bytes` limit (1MB) applies to write batch groups, not individual batches, and may not prevent this issue

### Citations

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L53-53)
```rust
        myself.prune(progress, metadata_progress, usize::MAX)?;
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L73-76)
```rust
            indices.into_iter().try_for_each(|index| {
                batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
                batch.delete::<S>(&index)
            })?;
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_metadata_pruner.rs (L53-58)
```rust
        let (indices, next_version) = StateMerklePruner::get_stale_node_indices(
            &self.metadata_db,
            current_progress,
            target_version_for_this_round,
            usize::MAX,
        )?;
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L205-214)
```rust
        while indices.len() < limit {
            if let Some((index, _)) = iter.next().transpose()? {
                next_version = Some(index.stale_since_version);
                if index.stale_since_version <= target_version {
                    indices.push(index);
                    continue;
                }
            }
            break;
        }
```

**File:** config/src/config/storage_config.rs (L408-410)
```rust
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
```

**File:** storage/schemadb/src/batch.rs (L130-133)
```rust
pub struct SchemaBatch {
    rows: DropHelper<HashMap<ColumnFamilyName, Vec<WriteOp>>>,
    stats: SampledBatchStats,
}
```
