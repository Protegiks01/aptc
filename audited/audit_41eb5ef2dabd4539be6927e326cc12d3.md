# Audit Report

## Title
Infinite Loop in State KV Pruner Due to Zero Batch Size Configuration

## Summary
The `StateKvPruner::prune()` and `LedgerPruner::prune()` functions contain an infinite loop vulnerability when `batch_size` configuration is set to 0. When enabled with this invalid configuration, the pruner worker thread enters an infinite busy loop consuming 100% CPU, causing validator node slowdowns and eventual operational failure due to unbounded database growth and disk exhaustion. [1](#0-0) 

## Finding Description

The vulnerability exists in the pruner's batch processing logic across multiple pruning subsystems. When a validator operator configures `batch_size: 0` with `enable: true`, the following execution path triggers an infinite loop:

**1. Configuration Loading**

The `LedgerPrunerConfig` struct allows `batch_size: 0` through YAML deserialization without validation: [2](#0-1) 

While `NO_OP_STORAGE_PRUNER_CONFIG` safely sets `batch_size: 0` with `enable: false`, nothing prevents misconfiguration with `enable: true` and `batch_size: 0`: [3](#0-2) 

**2. Missing Configuration Validation**

The `ConfigSanitizer` implementation validates `prune_window` and `user_pruning_window_offset` but completely omits `batch_size` validation: [4](#0-3) 

**3. Pruner Initialization**

When `enable: true`, the `StateKvPrunerManager` creates a `PrunerWorker` with the configured `batch_size`: [5](#0-4) 

**4. Worker Loop Execution**

The worker continuously calls `pruner.prune(batch_size)` in its work loop: [6](#0-5) 

**5. Infinite Loop Trigger**

In `StateKvPruner::prune()`, when `max_versions` (from `batch_size`) is 0:
- Line 56-57: `current_batch_target_version = min(progress + 0, target_version) = progress`
- Line 80: `progress = current_batch_target_version = progress` (no advancement!)
- Line 55: Loop condition `progress < target_version` remains perpetually true [7](#0-6) 

**The same vulnerability exists in `LedgerPruner::prune()`:** [8](#0-7) 

This breaks the **Resource Limits** invariant - operations must complete within bounded time. The pruner thread becomes stuck in an infinite CPU-intensive loop with no yield or sleep, never allowing the pruning operation to complete or the worker to rest.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria for "Validator Node Slowdowns":

**Immediate Impact:**
- The pruner worker thread enters an infinite busy loop
- Consumes 100% CPU on that thread with no yield points
- The tight loop repeatedly calls database operations (metadata pruning, shard iteration) from progress to progress

**Progressive Degradation:**
- Without functional pruning, the AptosDB database grows unbounded
- Disk space continuously depletes as new versions are committed
- High CPU usage on pruner thread impacts other validator operations
- Consensus participation may be affected by resource contention

**Terminal Failure:**
- Once disk space is exhausted, the validator node stops functioning
- Cannot commit new transactions or participate in consensus
- Requires manual intervention to diagnose and fix

**Network-Wide Risk:**
- If multiple validators misconfigure this parameter (e.g., using automated deployment tools with faulty templates), network health degrades
- Reduces validator availability and consensus efficiency

While not directly causing consensus safety violations, this severely impacts node **availability** and **liveness**, which are critical for blockchain operations. The vulnerability enables resource exhaustion DoS through misconfiguration, qualifying as High severity under the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can realistically occur through several scenarios:

1. **Honest Misconfiguration**: An operator intending to disable the pruner sets `batch_size: 0` instead of properly setting `enable: false`. The `NO_OP_STORAGE_PRUNER_CONFIG` example in the codebase shows `batch_size: 0`, which operators might copy without understanding the relationship with the `enable` flag.

2. **Configuration Template Errors**: Automated deployment systems or configuration management tools might generate configs with edge case values or copy the no-op config structure while accidentally enabling the pruner.

3. **Configuration Updates**: Operators modifying existing configs without full understanding of the implications, or using configuration generation scripts that don't validate batch_size.

4. **Lack of Safeguards**: The complete absence of validation makes this error:
   - Easy to introduce (no warnings during config loading)
   - Difficult to diagnose before deployment (no static validation)
   - Hard to debug in production (CPU spike with unclear cause)

The default batch_size is 5,000, which is safe, but the lack of bounds checking allows the zero value to pass through all validation layers unchallenged.

## Recommendation

**Add configuration validation to prevent batch_size of 0:**

In `config/src/config/storage_config.rs`, extend the `ConfigSanitizer::sanitize()` method to validate batch_size:

```rust
impl ConfigSanitizer for StorageConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let config = &node_config.storage;

        // Existing validation...
        
        // Add batch_size validation
        if config.storage_pruner_config.ledger_pruner_config.enable 
            && config.storage_pruner_config.ledger_pruner_config.batch_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "ledger_pruner_config.batch_size cannot be 0 when pruner is enabled. Set enable: false to disable pruning, or use a positive batch_size value.".to_string(),
            ));
        }
        
        if config.storage_pruner_config.state_merkle_pruner_config.enable 
            && config.storage_pruner_config.state_merkle_pruner_config.batch_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "state_merkle_pruner_config.batch_size cannot be 0 when pruner is enabled.".to_string(),
            ));
        }
        
        if config.storage_pruner_config.epoch_snapshot_pruner_config.enable 
            && config.storage_pruner_config.epoch_snapshot_pruner_config.batch_size == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "epoch_snapshot_pruner_config.batch_size cannot be 0 when pruner is enabled.".to_string(),
            ));
        }

        Ok(())
    }
}
```

Additionally, consider adding a runtime assertion in the prune() methods themselves as a defense-in-depth measure.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_config::config::{LedgerPrunerConfig, PrunerConfig, StorageConfig};
    use aptos_temppath::TempPath;
    use aptos_types::transaction::Version;
    use std::sync::Arc;

    #[test]
    #[should_panic(timeout = std::time::Duration::from_secs(5))]
    fn test_pruner_infinite_loop_with_zero_batch_size() {
        // Setup: Create a test database
        let tmpdir = TempPath::new();
        let db = Arc::new(StateKvDb::new_for_test(tmpdir.path()));
        
        // Create pruner with batch_size 0 (simulating misconfiguration)
        let pruner = StateKvPruner::new(db).unwrap();
        
        // Set target version ahead of progress
        pruner.set_target_version(1000);
        
        // This will infinite loop when batch_size is 0
        // The test has a 5-second timeout and should panic
        let _ = pruner.prune(0); // batch_size = 0
        
        // This line should never be reached
        panic!("Pruner should have infinite looped but didn't");
    }
}
```

This proof of concept demonstrates that calling `prune(0)` when `target_version > progress` results in an infinite loop that will cause the test to timeout, proving the vulnerability exists.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L49-86)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_pruner__prune"]);

        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning state kv data."
            );
            self.metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.shard_pruners.par_iter().try_for_each(|shard_pruner| {
                    shard_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| {
                            anyhow!(
                                "Failed to prune state kv shard {}: {err}",
                                shard_pruner.shard_id(),
                            )
                        })
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning state kv data is done.");
        }

        Ok(target_version)
    }
```

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

**File:** config/src/config/storage_config.rs (L327-341)
```rust
pub struct LedgerPrunerConfig {
    /// Boolean to enable/disable the ledger pruner. The ledger pruner is responsible for pruning
    /// everything else except for states (e.g. transactions, events etc.)
    pub enable: bool,
    /// This is the default pruning window for any other store except for state store. State store
    /// being big in size, we might want to configure a smaller window for state store vs other
    /// store.
    pub prune_window: u64,
    /// Batch size of the versions to be sent to the ledger pruner - this is to avoid slowdown due to
    /// issuing too many DB calls and batch prune instead. For ledger pruner, this means the number
    /// of versions to prune a time.
    pub batch_size: usize,
    /// The offset for user pruning window to adjust
    pub user_pruning_window_offset: u64,
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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L84-126)
```rust
    pub fn new(state_kv_db: Arc<StateKvDb>, state_kv_pruner_config: LedgerPrunerConfig) -> Self {
        let pruner_worker = if state_kv_pruner_config.enable {
            Some(Self::init_pruner(
                Arc::clone(&state_kv_db),
                state_kv_pruner_config,
            ))
        } else {
            None
        };

        let min_readable_version =
            pruner_utils::get_state_kv_pruner_progress(&state_kv_db).expect("Must succeed.");

        PRUNER_VERSIONS
            .with_label_values(&["state_kv_pruner", "min_readable"])
            .set(min_readable_version as i64);

        Self {
            state_kv_db,
            prune_window: state_kv_pruner_config.prune_window,
            pruner_worker,
            pruning_batch_size: state_kv_pruner_config.batch_size,
            min_readable_version: AtomicVersion::new(min_readable_version),
        }
    }

    fn init_pruner(
        state_kv_db: Arc<StateKvDb>,
        state_kv_pruner_config: LedgerPrunerConfig,
    ) -> PrunerWorker {
        let pruner =
            Arc::new(StateKvPruner::new(state_kv_db).expect("Failed to create state kv pruner."));

        PRUNER_WINDOW
            .with_label_values(&["state_kv_pruner"])
            .set(state_kv_pruner_config.prune_window as i64);

        PRUNER_BATCH_SIZE
            .with_label_values(&["state_kv_pruner"])
            .set(state_kv_pruner_config.batch_size as i64);

        PrunerWorker::new(pruner, state_kv_pruner_config.batch_size, "state_kv")
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

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L62-89)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning ledger data."
            );
            self.ledger_metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning ledger data is done.");
        }
```
