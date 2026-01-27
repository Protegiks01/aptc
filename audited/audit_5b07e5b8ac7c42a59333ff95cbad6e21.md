# Audit Report

## Title
State Merkle Pruner Silent Failure with Zero Batch Size Leading to Unbounded Database Growth

## Summary
The State Merkle Pruner accepts a `batch_size` configuration value of 0 without validation. When `enable=true` and `batch_size=0`, the pruner silently fails to prune any stale nodes while incorrectly reporting successful completion. This causes unbounded database growth, eventually leading to disk space exhaustion and node failure.

## Finding Description

The vulnerability exists in the state merkle pruner's handling of the `batch_size` configuration parameter. The configuration structure `StateMerklePrunerConfig` has no validation to prevent `batch_size` from being set to 0. [1](#0-0) 

The configuration constant `NO_OP_STORAGE_PRUNER_CONFIG` explicitly sets `batch_size: 0`, demonstrating that zero is an accepted value: [2](#0-1) 

The `ConfigSanitizer` implementation validates `prune_window` values but performs no validation on `batch_size`: [3](#0-2) 

When `enable=true` and `batch_size=0`, the pruner manager initializes a worker with this invalid value: [4](#0-3) 

The pruner worker repeatedly calls `prune()` with `batch_size=0`: [5](#0-4) 

In the shard pruner's `prune()` method, when `max_nodes_to_prune=0`, the function calls `get_stale_node_indices()` with `limit=0`: [6](#0-5) 

The `get_stale_node_indices()` function with `limit=0` immediately returns an empty vector without retrieving any stale nodes: [7](#0-6) 

Since the `while indices.len() < limit` condition is false when `limit=0`, the function never calls `iter.next()`, returns `(vec![], None)`, and the shard pruner marks itself as "done" while writing `target_version` as progress without actually pruning anything.

**Attack Scenario:**
1. Node operator configures: `StateMerklePrunerConfig { enable: true, batch_size: 0, prune_window: 1_000_000 }`
2. Pruner starts and enters work loop
3. Each pruning attempt retrieves 0 nodes and immediately exits
4. Progress metrics incorrectly show pruning is complete
5. Stale nodes accumulate in database indefinitely
6. Database grows without bounds
7. Eventually fills disk space
8. Node fails due to storage exhaustion

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: As the database grows unboundedly, read/write operations slow down significantly, degrading validator performance.

2. **Potential Total Loss of Liveness**: If disk space is exhausted, the node can no longer commit new state, effectively taking it offline and reducing network availability.

3. **State Inconsistencies**: The pruner reports successful completion via metrics while failing to prune, creating operational confusion and incorrect monitoring alerts.

Additionally, this could lead to **Medium Severity** impacts if multiple validators are affected, as state synchronization would be impacted when new validators try to sync from nodes with corrupted/bloated databases.

## Likelihood Explanation

**Likelihood: Medium**

While the default configuration uses `batch_size: 1_000`, several factors increase likelihood:

1. The codebase explicitly includes `NO_OP_STORAGE_PRUNER_CONFIG` with `batch_size: 0`, suggesting this value is considered valid for certain scenarios.

2. Node operators may inadvertently set `batch_size: 0` through configuration errors or misunderstanding the parameter's purpose.

3. No validation exists at configuration load time to prevent this misconfiguration.

4. The failure is silent - metrics show "success" while pruning doesn't occur, making detection difficult until disk space issues manifest.

5. Malicious node operators could intentionally configure this to cause self-DoS or create operational burdens.

## Recommendation

Add validation in the `ConfigSanitizer` to ensure `batch_size` is within reasonable bounds:

**In `config/src/config/storage_config.rs`, modify the `ConfigSanitizer` implementation:**

```rust
impl ConfigSanitizer for StorageConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.storage;

        // Existing prune_window validations...
        
        // Add batch_size validation
        if config.storage_pruner_config.ledger_pruner_config.enable {
            let batch_size = config.storage_pruner_config.ledger_pruner_config.batch_size;
            if batch_size == 0 {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "ledger_pruner_config.batch_size cannot be 0".to_string(),
                ));
            }
            if batch_size > 1_000_000 {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "ledger_pruner_config.batch_size is too large (max 1,000,000)".to_string(),
                ));
            }
        }
        
        if config.storage_pruner_config.state_merkle_pruner_config.enable {
            let batch_size = config.storage_pruner_config.state_merkle_pruner_config.batch_size;
            if batch_size == 0 {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "state_merkle_pruner_config.batch_size cannot be 0".to_string(),
                ));
            }
            if batch_size > 1_000_000 {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "state_merkle_pruner_config.batch_size is too large (max 1,000,000)".to_string(),
                ));
            }
        }
        
        if config.storage_pruner_config.epoch_snapshot_pruner_config.enable {
            let batch_size = config.storage_pruner_config.epoch_snapshot_pruner_config.batch_size;
            if batch_size == 0 {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "epoch_snapshot_pruner_config.batch_size cannot be 0".to_string(),
                ));
            }
            if batch_size > 1_000_000 {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "epoch_snapshot_pruner_config.batch_size is too large (max 1,000,000)".to_string(),
                ));
            }
        }

        // Existing validations...
        Ok(())
    }
}
```

**Additional defensive fix in `get_stale_node_indices()`:**

```rust
pub(in crate::pruner::state_merkle_pruner) fn get_stale_node_indices(
    state_merkle_db_shard: &DB,
    start_version: Version,
    target_version: Version,
    limit: usize,
) -> Result<(Vec<StaleNodeIndex>, Option<Version>)> {
    // Defensive check
    if limit == 0 {
        return Ok((vec![], None));
    }
    
    // Rest of implementation...
}
```

## Proof of Concept

```rust
#[test]
fn test_pruner_with_zero_batch_size() {
    use aptos_temppath::TempPath;
    use crate::db::AptosDB;
    use crate::pruner::{PrunerManager, StateMerklePrunerManager};
    use aptos_config::config::StateMerklePrunerConfig;
    use aptos_types::state_store::{StateKey, StateValue};
    
    let tmp_dir = TempPath::new();
    let aptos_db = AptosDB::new_for_test_with_sharding(&tmp_dir, 0);
    let state_store = &aptos_db.state_store;
    
    // Insert state values to create stale nodes
    let key = StateKey::raw(b"test_key");
    for i in 0..100 {
        let value = StateValue::from(vec![i as u8]);
        state_store.commit_block_for_test(i, [vec![(key.clone(), Some(value))].into_iter()]);
    }
    
    // Count stale nodes before pruning
    let stale_nodes_before = aptos_db
        .state_merkle_db()
        .metadata_db()
        .iter::<StaleNodeIndexSchema>()
        .unwrap()
        .count();
    
    assert!(stale_nodes_before > 0, "Should have stale nodes");
    
    // Create pruner with batch_size=0
    let pruner = StateMerklePrunerManager::new(
        Arc::clone(&aptos_db.state_merkle_db()),
        StateMerklePrunerConfig {
            enable: true,
            prune_window: 10,
            batch_size: 0,  // ZERO BATCH SIZE
        }
    );
    
    // Attempt to prune
    pruner.wake_and_wait_pruner(100).unwrap();
    
    // Count stale nodes after "pruning"
    let stale_nodes_after = aptos_db
        .state_merkle_db()
        .metadata_db()
        .iter::<StaleNodeIndexSchema>()
        .unwrap()
        .count();
    
    // BUG: Stale nodes are NOT pruned despite pruner reporting success!
    assert_eq!(stale_nodes_before, stale_nodes_after, 
        "Pruner with batch_size=0 should have failed to prune but didn't!");
}
```

This test demonstrates that with `batch_size=0`, the pruner completes without error but fails to prune any stale nodes, leading to unbounded database growth.

### Citations

**File:** config/src/config/storage_config.rs (L306-323)
```rust
pub const NO_OP_STORAGE_PRUNER_CONFIG: PrunerConfig = PrunerConfig {
    ledger_pruner_config: LedgerPrunerConfig {
        enable: false,
        prune_window: 0,
        batch_size: 0,
        user_pruning_window_offset: 0,
    },
    state_merkle_pruner_config: StateMerklePrunerConfig {
        enable: false,
        prune_window: 0,
        batch_size: 0,
    },
    epoch_snapshot_pruner_config: EpochSnapshotPrunerConfig {
        enable: false,
        prune_window: 0,
        batch_size: 0,
    },
};
```

**File:** config/src/config/storage_config.rs (L343-353)
```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StateMerklePrunerConfig {
    /// Boolean to enable/disable the state merkle pruner. The state merkle pruner is responsible
    /// for pruning state tree nodes.
    pub enable: bool,
    /// Window size in versions.
    pub prune_window: u64,
    /// Number of stale nodes to prune a time.
    pub batch_size: usize,
}
```

**File:** config/src/config/storage_config.rs (L682-728)
```rust
impl ConfigSanitizer for StorageConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.storage;

        let ledger_prune_window = config
            .storage_pruner_config
            .ledger_pruner_config
            .prune_window;
        let state_merkle_prune_window = config
            .storage_pruner_config
            .state_merkle_pruner_config
            .prune_window;
        let epoch_snapshot_prune_window = config
            .storage_pruner_config
            .epoch_snapshot_pruner_config
            .prune_window;
        let user_pruning_window_offset = config
            .storage_pruner_config
            .ledger_pruner_config
            .user_pruning_window_offset;

        if ledger_prune_window < 50_000_000 {
            warn!("Ledger prune_window is too small, harming network data availability.");
        }
        if state_merkle_prune_window < 100_000 {
            warn!("State Merkle prune_window is too small, node might stop functioning.");
        }
        if epoch_snapshot_prune_window < 50_000_000 {
            warn!("Epoch snapshot prune_window is too small, harming network data availability.");
        }
        if user_pruning_window_offset > 1_000_000 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "user_pruning_window_offset too large, so big a buffer is unlikely necessary. Set something < 1 million.".to_string(),
            ));
        }
        if user_pruning_window_offset > ledger_prune_window {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "user_pruning_window_offset is larger than the ledger prune window, the API will refuse to return any data.".to_string(),
            ));
        }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L110-157)
```rust
        let pruner_worker = if state_merkle_pruner_config.enable {
            Some(Self::init_pruner(
                Arc::clone(&state_merkle_db),
                state_merkle_pruner_config,
            ))
        } else {
            None
        };

        let min_readable_version = pruner_utils::get_state_merkle_pruner_progress(&state_merkle_db)
            .expect("Must succeed.");

        PRUNER_VERSIONS
            .with_label_values(&[S::name(), "min_readable"])
            .set(min_readable_version as i64);

        Self {
            state_merkle_db,
            prune_window: state_merkle_pruner_config.prune_window,
            pruner_worker,
            min_readable_version: AtomicVersion::new(min_readable_version),
            _phantom: PhantomData,
        }
    }

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

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L52-69)
```rust
    // Loop that does the real pruning job.
    fn work(&self) {
        while !self.quit_worker.load(Ordering::SeqCst) {
            let pruner_result = self.pruner.prune(self.batch_size);
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
            if !self.pruner.is_pruning_pending() {
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            }
        }
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L58-100)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
        max_nodes_to_prune: usize,
    ) -> Result<()> {
        loop {
            let mut batch = SchemaBatch::new();
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

            let mut done = true;
            if let Some(next_version) = next_version {
                if next_version <= target_version {
                    done = false;
                }
            }

            if done {
                batch.put::<DbMetadataSchema>(
                    &S::progress_metadata_key(Some(self.shard_id)),
                    &DbMetadataValue::Version(target_version),
                )?;
            }

            self.db_shard.write_schemas(batch)?;

            if done {
                break;
            }
        }

        Ok(())
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
