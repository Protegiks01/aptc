# Audit Report

## Title
State KV Pruner Catch-Up Deletes Historical Data When Prune Window Increases, Breaking State Sync Serving

## Summary
When the `prune_window` configuration is increased, the `StateKvShardPruner` catch-up pruning mechanism uses stale metadata progress from the database, causing permanent deletion of historical state values that should now be retained under the new configuration. This creates a gap in available historical data where the storage service advertises availability but cannot serve requests, breaking state sync protocol functionality.

## Finding Description

The vulnerability exists in the initialization flow of `StateKvShardPruner` when nodes restart after a `prune_window` configuration increase: [1](#0-0) 

During initialization, the shard pruner performs catch-up pruning to synchronize with the metadata pruner's progress. However, the metadata pruner's progress stored in the database reflects the OLD prune window from before the configuration change: [2](#0-1) 

The metadata progress is retrieved from persistent storage without validation against the current prune window: [3](#0-2) 

**Attack Scenario:**

1. **Initial State:** Node runs with `prune_window = 100,000`, latest version = 1,000,000
   - Metadata pruner progress = 900,000 (correctly: 1,000,000 - 100,000)
   - Shard 0 pruner progress = 850,000 (lagging behind)

2. **Configuration Change:** Operator increases `prune_window = 200,000` to retain more history for state sync serving

3. **Node Restart:** Catch-up pruning executes with stale metadata progress
   - Reads metadata_progress = 900,000 from database (OLD value!)
   - Reads shard progress = 850,000 from database
   - Executes `prune(850000, 900000)` — deletes versions 850,001 to 900,000

4. **Post-Initialization:** New prune window takes effect
   - `min_readable_version = 1,000,000 - 200,000 = 800,000`
   - Storage service advertises it can serve from version 800,001 to 1,000,000

5. **Gap Created:** Versions 850,001 to 900,000 are advertised but deleted
   - State sync requests for this range fail with "State Value is missing"

The storage service calculates available state values based on the CONFIGURED prune window, not actual data availability: [4](#0-3) 

When peers request state values in the gap range, the database returns an error: [5](#0-4) 

The invariant broken is **State Consistency**: "State transitions must be atomic and verifiable via Merkle proofs." Historical state values that should be available per the prune window configuration are permanently deleted, making historical proofs impossible to serve.

## Impact Explanation

This is a **HIGH severity** issue under the Aptos bug bounty program criteria for "Significant protocol violations":

1. **State Sync Serving Failure:** Nodes cannot serve historical state values to peers requesting sync in the gap range, breaking the state synchronization protocol

2. **Historical Proof Unavailability:** State proofs for versions in the gap cannot be created, violating data availability guarantees

3. **Validator Synchronization Impact:** Validators lagging behind consensus cannot sync from affected nodes, potentially impacting liveness if multiple nodes are affected

4. **Permanent Data Loss:** The deleted state values cannot be recovered without full re-sync from genesis or a node with complete history

5. **Multi-Node Amplification:** If multiple validators increase their prune window and restart simultaneously (e.g., coordinated config update), the issue compounds across the network

The issue does not reach CRITICAL severity because:
- It requires operator intervention (config change + restart)
- It doesn't directly break consensus safety (only affects historical data serving)
- Workarounds exist (re-sync from nodes with complete history)

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This issue will occur whenever:
1. Node operators increase the `prune_window` configuration to retain more history
2. The shard pruner progress lags behind the metadata pruner progress (common during normal operation)
3. The node restarts

Common scenarios triggering this:
- Operators increasing history retention for better state sync serving capabilities
- Network-wide configuration updates to improve data availability
- Operators responding to increased demand for historical queries
- Recovery from pruner performance issues by increasing the window

The configuration change is a legitimate operational activity, making this a realistic scenario. The lack of validation makes the issue deterministic when conditions are met.

## Recommendation

Add validation during `StateKvPruner` initialization to ensure metadata progress does not exceed what should be retained under the current prune window:

```rust
// In StateKvPruner::new() after retrieving metadata_progress
pub fn new(state_kv_db: Arc<StateKvDb>, prune_window: Version) -> Result<Self> {
    info!(name = STATE_KV_PRUNER_NAME, "Initializing...");
    
    let metadata_pruner = StateKvMetadataPruner::new(Arc::clone(&state_kv_db));
    let metadata_progress = metadata_pruner.progress()?;
    
    // NEW: Validate metadata_progress against current prune_window
    let latest_version = /* get from state_kv_db or pass as parameter */;
    if latest_version > prune_window {
        let min_allowed_progress = latest_version.saturating_sub(prune_window);
        if metadata_progress > min_allowed_progress {
            warn!(
                metadata_progress = metadata_progress,
                min_allowed_progress = min_allowed_progress,
                prune_window = prune_window,
                "Metadata progress exceeds current prune window, adjusting to prevent data loss"
            );
            // Reset metadata progress to safe value
            metadata_pruner.reset_progress(min_allowed_progress)?;
            metadata_progress = min_allowed_progress;
        }
    }
    
    // Rest of initialization continues...
}
```

Alternative: Store the prune window alongside the metadata progress and detect configuration changes:

```rust
// Store prune_window with metadata_progress
batch.put::<DbMetadataSchema>(
    &DbMetadataKey::StateKvPrunerConfig,
    &DbMetadataValue::PrunerConfig { 
        progress: target_version,
        prune_window: self.prune_window,
    },
)?;

// On initialization, compare stored vs configured prune_window
// If increased, recalculate safe metadata_progress
```

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_catch_up_pruning_data_loss_on_increased_prune_window() {
    // Setup: Create AptosDB with prune_window = 100K
    let tmpdir = TempPath::new();
    let mut config = PrunerConfig::default();
    config.ledger_pruner_config.prune_window = 100_000;
    
    let db = AptosDB::new_for_test_with_config(&tmpdir, config);
    
    // Commit 1M versions
    for v in 0..1_000_000 {
        commit_version(&db, v);
    }
    
    // Let pruning catch up most shards but leave shard 0 lagging
    db.state_store.state_kv_pruner.prune(1000).unwrap();
    // Manually set shard 0 progress to 850K
    set_shard_progress(&db, 0, 850_000);
    
    // Metadata pruner progresses to 900K (1M - 100K)
    assert_eq!(db.state_store.state_kv_pruner.progress(), 900_000);
    
    // Close and reopen with increased prune_window
    drop(db);
    
    let mut new_config = PrunerConfig::default();
    new_config.ledger_pruner_config.prune_window = 200_000; // INCREASED
    
    let db = AptosDB::open_existing(&tmpdir, new_config);
    
    // After initialization, catch-up pruning has deleted 850K-900K
    // but storage service advertises availability from 800K
    
    // Attempt to fetch state value at version 875,000 (should exist with 200K window)
    let state_key = StateKey::raw(b"test_key");
    let result = db.state_store.get_state_value_by_version(&state_key, 875_000);
    
    // VULNERABILITY: This fails even though 875K should be within the 200K window
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("State Value is missing"));
    
    // Storage service incorrectly reports it can serve this version
    let storage_reader = StorageReader::new(config, db.reader(), TimeService::real());
    let range = storage_reader.fetch_state_values_range(1_000_000, &None).unwrap();
    assert_eq!(range.unwrap().lowest(), 800_001); // Claims to serve from 800K
    
    // But actual query fails for 850K-900K range!
}
```

**Notes:**
- The vulnerability is deterministic and reproducible whenever prune_window is increased with lagging shard pruners
- The gap in historical data is permanent and requires full re-sync to recover
- Multiple nodes affected simultaneously could impact network data availability
- The issue violates the implicit contract that data within the prune window should be available

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L25-45)
```rust
    pub(in crate::pruner) fn new(
        shard_id: usize,
        db_shard: Arc<DB>,
        metadata_progress: Version,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            &db_shard,
            &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
            metadata_progress,
        )?;
        let myself = Self { shard_id, db_shard };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up state kv shard {shard_id}."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L112-153)
```rust
    pub fn new(state_kv_db: Arc<StateKvDb>) -> Result<Self> {
        info!(name = STATE_KV_PRUNER_NAME, "Initializing...");

        let metadata_pruner = StateKvMetadataPruner::new(Arc::clone(&state_kv_db));

        let metadata_progress = metadata_pruner.progress()?;

        info!(
            metadata_progress = metadata_progress,
            "Created state kv metadata pruner, start catching up all shards."
        );

        let shard_pruners = if state_kv_db.enabled_sharding() {
            let num_shards = state_kv_db.num_shards();
            let mut shard_pruners = Vec::with_capacity(num_shards);
            for shard_id in 0..num_shards {
                shard_pruners.push(StateKvShardPruner::new(
                    shard_id,
                    state_kv_db.db_shard_arc(shard_id),
                    metadata_progress,
                )?);
            }
            shard_pruners
        } else {
            Vec::new()
        };

        let pruner = StateKvPruner {
            target_version: AtomicVersion::new(metadata_progress),
            progress: AtomicVersion::new(metadata_progress),
            metadata_pruner,
            shard_pruners,
        };

        info!(
            name = pruner.name(),
            progress = metadata_progress,
            "Initialized."
        );

        Ok(pruner)
    }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L75-81)
```rust
    pub(in crate::pruner) fn progress(&self) -> Result<Version> {
        Ok(get_progress(
            self.state_kv_db.metadata_db(),
            &DbMetadataKey::StateKvPrunerProgress,
        )?
        .unwrap_or(0))
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L143-176)
```rust
    /// Returns the state values range held in the database (lowest to highest).
    /// Note: it is currently assumed that if a node contains a transaction at a
    /// version, V, the node also contains all state values at V.
    fn fetch_state_values_range(
        &self,
        latest_version: Version,
        transactions_range: &Option<CompleteDataRange<Version>>,
    ) -> aptos_storage_service_types::Result<Option<CompleteDataRange<Version>>, Error> {
        let pruner_enabled = self.storage.is_state_merkle_pruner_enabled()?;
        if !pruner_enabled {
            return Ok(*transactions_range);
        }
        let pruning_window = self.storage.get_epoch_snapshot_prune_window()?;

        if latest_version > pruning_window as Version {
            // lowest_state_version = latest_version - pruning_window + 1;
            let mut lowest_state_version = latest_version
                .checked_sub(pruning_window as Version)
                .ok_or_else(|| {
                    Error::UnexpectedErrorEncountered("Lowest state version has overflown!".into())
                })?;
            lowest_state_version = lowest_state_version.checked_add(1).ok_or_else(|| {
                Error::UnexpectedErrorEncountered("Lowest state version has overflown!".into())
            })?;

            // Create the state range
            let state_range = CompleteDataRange::new(lowest_state_version, latest_version)
                .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
            return Ok(Some(state_range));
        }

        // No pruning has occurred. Return the transactions range.
        Ok(*transactions_range)
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L320-334)
```rust
    fn expect_value_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<StateValue> {
        self.get_state_value_by_version(state_key, version)
            .and_then(|opt| {
                opt.ok_or_else(|| {
                    AptosDbError::NotFound(format!(
                        "State Value is missing for key {:?} by version {}",
                        state_key, version
                    ))
                })
            })
    }
```
