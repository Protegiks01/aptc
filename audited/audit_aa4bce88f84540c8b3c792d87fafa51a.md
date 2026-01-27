# Audit Report

## Title
Unbounded Memory Consumption During State Merkle Shard Pruner Initialization Leads to OOM Crashes

## Summary
The `StateMerkleShardPruner::new()` function calls `prune()` with `usize::MAX` as the `max_nodes_to_prune` parameter during initialization, bypassing the configured batch size limit. When a node has accumulated a large backlog of stale Jellyfish Merkle tree nodes (due to downtime, high load, or pruning lag), the initialization attempts to load all stale nodes into memory at once, causing out-of-memory crashes and node unavailability. [1](#0-0) 

## Finding Description
During initialization, each `StateMerkleShardPruner` performs a "catch-up" operation to synchronize with the metadata pruner's progress. This breaks the **Resource Limits** invariant which requires "all operations must respect gas, storage, and computational limits."

The vulnerability manifests through this execution flow:

1. **Node initialization**: When `AptosDB` is opened, `StateMerklePrunerManager::new()` is called for state merkle and epoch snapshot pruners. [2](#0-1) 

2. **Pruner creation**: The manager calls `StateMerklePruner::new()`, which initializes shard pruners. [3](#0-2) 

3. **Shard initialization**: For each shard, `StateMerkleShardPruner::new()` calls `prune()` with `usize::MAX`, attempting to catch up all pending work in a single operation. [4](#0-3) 

4. **Unbounded memory allocation**: The `get_stale_node_indices()` function iterates and collects stale nodes into a `Vec` until the limit is reached. With `limit = usize::MAX`, it attempts to load all backlogged stale nodes into memory. [5](#0-4) 

5. **Memory exhaustion**: Each `StaleNodeIndex` contains a `Version` (8 bytes) and a `NodeKey` (which includes another `Version` and a `NibblePath` with heap-allocated bytes), totaling approximately 80-100 bytes per entry. [6](#0-5) [7](#0-6) 

According to the codebase documentation, "A 10k transaction block (touching 60k state values) yields 300k JMT nodes". If a node falls behind by:
- 100k transactions = ~3M stale nodes = ~300MB RAM
- 1M transactions = ~30M stale nodes = ~3GB RAM  
- 10M transactions = ~300M stale nodes = ~30GB RAM [8](#0-7) 

The configured `batch_size` (default 1,000) is specifically designed to prevent this issue during normal operation but is completely bypassed during initialization. [9](#0-8) 

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria:

- **Validator node slowdowns**: The initialization phase can take excessive time and resources, degrading node performance
- **API crashes**: Nodes crash with OOM errors, becoming completely unavailable and unable to participate in consensus

The impact extends beyond individual node crashes:
- Validators experiencing this issue cannot rejoin the network after restarts
- API nodes become unavailable, disrupting user access to blockchain data
- If multiple nodes restart simultaneously (e.g., after a network-wide upgrade or coordinated maintenance), the network could experience significant degradation
- Critical node operations (validator participation, state sync, API services) are completely blocked until manual intervention

## Likelihood Explanation
This vulnerability has **HIGH likelihood** of occurring in production environments:

**Triggering Conditions** (any of these):
1. Node downtime/crashes with automatic restart
2. Deliberate node restarts for maintenance or upgrades
3. Pruning falling behind due to high transaction throughput
4. Resource constraints preventing pruner from keeping up
5. Temporary pruner misconfiguration or disablement

**Real-world Scenarios**:
- High-traffic periods create large backlogs that persist through restarts
- Validator operators perform rolling upgrades across the network
- New nodes joining the network with partial state synchronization
- Emergency node restarts after detecting issues

The vulnerability is **silent** until triggered - nodes accumulate stale nodes normally, and the problem only manifests during initialization, making it difficult to detect and prevent proactively.

## Recommendation
Replace `usize::MAX` with the configured `batch_size` during initialization. The catch-up operation should respect the same memory limits as regular pruning operations:

**Modified `StateMerkleShardPruner::new()` signature and implementation**:

```rust
pub(in crate::pruner) fn new(
    shard_id: usize,
    db_shard: Arc<DB>,
    metadata_progress: Version,
    batch_size: usize,  // Add batch_size parameter
) -> Result<Self> {
    let progress = get_or_initialize_subpruner_progress(
        &db_shard,
        &S::progress_metadata_key(Some(shard_id)),
        metadata_progress,
    )?;
    let myself = Self {
        shard_id,
        db_shard,
        _phantom: PhantomData,
    };

    info!(
        progress = progress,
        metadata_progress = metadata_progress,
        "Catching up {} shard {shard_id}.",
        S::name(),
    );
    // Use batch_size instead of usize::MAX
    myself.prune(progress, metadata_progress, batch_size)?;

    Ok(myself)
}
```

**Update caller in `StateMerklePruner::new()`**:

```rust
for shard_id in 0..num_shards {
    shard_pruners.push(StateMerkleShardPruner::new(
        shard_id,
        state_merkle_db.db_shard_arc(shard_id),
        metadata_progress,
        state_merkle_pruner_config.batch_size,  // Pass batch_size from config
    )?);
}
```

This ensures initialization respects the same memory bounds as regular operation, preventing OOM crashes while still allowing the pruner to catch up through multiple batched iterations.

## Proof of Concept

```rust
#[cfg(test)]
mod test_oom_vulnerability {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_types::transaction::Version;
    use std::sync::Arc;
    
    #[test]
    fn test_initialization_oom_with_large_backlog() {
        // Setup: Create a database with a large backlog of stale nodes
        let tmpdir = TempPath::new();
        let db = DB::open(
            tmpdir.path(),
            "test_db",
            &RocksdbConfig::default(),
        ).unwrap();
        let db = Arc::new(db);
        
        // Simulate a large backlog: Insert 10 million stale node indices
        // In a real scenario, these accumulate over time due to state updates
        let mut batch = SchemaBatch::new();
        let start_version: Version = 0;
        let end_version: Version = 10_000_000;
        
        for version in start_version..end_version {
            let stale_index = StaleNodeIndex {
                stale_since_version: version,
                node_key: NodeKey::new_empty_path(version),
            };
            batch.put::<StaleNodeIndexSchema>(&stale_index, &()).unwrap();
            
            // Commit in chunks to avoid memory issues during setup
            if version % 10_000 == 0 {
                db.write_schemas(batch).unwrap();
                batch = SchemaBatch::new();
            }
        }
        db.write_schemas(batch).unwrap();
        
        // Set metadata progress ahead to create a backlog
        let metadata_progress = end_version;
        
        // Attempt to initialize - this will try to load all 10M indices 
        // into memory at once with usize::MAX limit, causing OOM
        let result = StateMerkleShardPruner::<StaleNodeIndexSchema>::new(
            0,
            db,
            metadata_progress,
        );
        
        // In vulnerable version: This either crashes with OOM or takes 
        // excessive time/memory (10M * ~100 bytes = ~1GB minimum)
        // Expected: Should fail gracefully or complete with bounded memory
        
        match result {
            Ok(_) => println!("Completed but likely consumed excessive memory"),
            Err(e) => println!("Failed with error: {}", e),
        }
    }
}
```

**To observe the vulnerability**:
1. Run the test on a system with memory limits (e.g., Docker container with 2GB RAM)
2. Monitor memory usage during initialization - it will spike dramatically
3. On systems with insufficient memory, the process will be killed by the OOM killer
4. Even on systems with sufficient memory, the initialization takes excessive time and resources

**Notes**

This vulnerability is particularly dangerous because it's a **time bomb** - the issue only manifests during node restarts, potentially during critical moments when operators need nodes to come back online quickly. The use of `usize::MAX` during initialization is inconsistent with the carefully chosen `batch_size` configuration used during normal operation, creating an unnecessary availability risk for validator and API nodes.

### Citations

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L31-56)
```rust
    pub(in crate::pruner) fn new(
        shard_id: usize,
        db_shard: Arc<DB>,
        metadata_progress: Version,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            &db_shard,
            &S::progress_metadata_key(Some(shard_id)),
            metadata_progress,
        )?;
        let myself = Self {
            shard_id,
            db_shard,
            _phantom: PhantomData,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up {} shard {shard_id}.",
            S::name(),
        );
        myself.prune(progress, metadata_progress, usize::MAX)?;

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L60-67)
```rust
        let state_merkle_pruner = StateMerklePrunerManager::new(
            Arc::clone(&state_merkle_db),
            pruner_config.state_merkle_pruner_config,
        );
        let epoch_snapshot_pruner = StateMerklePrunerManager::new(
            Arc::clone(&state_merkle_db),
            pruner_config.epoch_snapshot_pruner_config.into(),
        );
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L135-157)
```rust
    fn init_pruner(
        state_merkle_db: Arc<StateMerkleDb>,
        state_merkle_pruner_config: StateMerklePrunerConfig,
    ) -> PrunerWorker {
        let pruner = Arc::new(
            StateMerklePruner::<S>::new(Arc::clone(&state_merkle_db))
                .expect("Failed to create state merkle pruner."),
        );

        PRUNER_WINDOW
            .with_label_values(&[S::name()])
            .set(state_merkle_pruner_config.prune_window as i64);

        PRUNER_BATCH_SIZE
            .with_label_values(&[S::name()])
            .set(state_merkle_pruner_config.batch_size as i64);

        PrunerWorker::new(
            pruner,
            state_merkle_pruner_config.batch_size,
            "state_merkle",
        )
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L191-217)
```rust
    pub(in crate::pruner::state_merkle_pruner) fn get_stale_node_indices(
        state_merkle_db_shard: &DB,
        start_version: Version,
        target_version: Version,
        limit: usize,
    ) -> Result<(Vec<StaleNodeIndex>, Option<Version>)> {
        let mut indices = Vec::new();
        let mut iter = state_merkle_db_shard.iter::<S>()?;
        iter.seek(&StaleNodeIndex {
            stale_since_version: start_version,
            node_key: NodeKey::new_empty_path(0),
        })?;

        let mut next_version = None;
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

        Ok((indices, next_version))
    }
```

**File:** storage/jellyfish-merkle/src/lib.rs (L192-201)
```rust
/// Indicates a node becomes stale since `stale_since_version`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct StaleNodeIndex {
    /// The version since when the node is overwritten and becomes stale.
    pub stale_since_version: Version,
    /// The [`NodeKey`](node_type/struct.NodeKey.html) identifying the node associated with this
    /// record.
    pub node_key: NodeKey,
}
```

**File:** storage/jellyfish-merkle/src/node_type/mod.rs (L46-54)
```rust
/// The unique key of each node.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct NodeKey {
    // The version at which the node is created.
    version: Version,
    // The nibble path this node represents in the tree.
    nibble_path: NibblePath,
}
```

**File:** config/src/config/storage_config.rs (L398-412)
```rust
impl Default for StateMerklePrunerConfig {
    fn default() -> Self {
        StateMerklePrunerConfig {
            enable: true,
            // This allows a block / chunk being executed to have access to a non-latest state tree.
            // It needs to be greater than the number of versions the state committing thread is
            // able to commit during the execution of the block / chunk. If the bad case indeed
            // happens due to this being too small, a node restart should recover it.
            // Still, defaulting to 1M to be super safe.
            prune_window: 1_000_000,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
        }
    }
```
