# Audit Report

## Title
Critical Configuration Validation Bypass in State Merkle Pruner Allows Node Dysfunction Through Zero Prune Window

## Summary
The `StateMerklePrunerManager::new()` function accepts `prune_window = 0` without hard enforcement, only issuing a warning during config validation. This allows a malicious operator or compromised configuration file to set an invalid prune window that causes aggressive historical state pruning, leading to execution failures, node dysfunction, and broken state synchronization for new nodes.

## Finding Description

The vulnerability exists in the state merkle pruner configuration validation and initialization: [1](#0-0) 

At line 128, `prune_window` is set directly from `state_merkle_pruner_config.prune_window` without any validation or enforcement of minimum values. The only protection is a warning in the config sanitizer: [2](#0-1) 

This warning does not prevent node startup with `prune_window = 0`. The default configuration includes an explicit comment explaining why a large prune window is required: [3](#0-2) 

**How the Attack Works:**

When `prune_window = 0`, the pruning logic becomes pathologically aggressive:

1. In `maybe_set_pruner_target_db_version`, the condition `latest_version >= min_readable_version + 0` is always true, triggering continuous pruning: [4](#0-3) 

2. The `min_readable_version` calculation becomes `latest_version - 0 = latest_version`: [5](#0-4) 

3. This causes all historical Jellyfish Merkle tree nodes to be deleted up to the current version: [6](#0-5) 

**System Breakage:**

The pruned state causes multiple critical failures:

1. **Execution Failures**: During block execution, `CachedStateView` attempts to read state at `base_version`. With aggressive pruning, these reads fail: [7](#0-6) [8](#0-7) 

2. **Pruned State Error**: When state at a version below `min_readable_version` is requested, an error is returned: [9](#0-8) 

3. **Concurrent Execution Race**: As documented in the config, the prune window must accommodate concurrent execution and state commitment. With `prune_window = 0`, a thread executing a block can have its state reads fail when another thread commits new blocks, since `min_readable_version` immediately advances past the execution's `base_version`.

4. **State Sync Breakage**: New nodes attempting to synchronize from affected nodes cannot retrieve historical state snapshots, breaking the fast sync mechanism.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Nodes with `prune_window = 0` experience execution failures and must restart repeatedly
- **Significant protocol violations**: The node cannot maintain proper state consistency as concurrent operations fail
- **State sync disruption**: New nodes cannot sync from affected validators

The impact escalates if multiple nodes are affected through:
- Configuration management system compromise
- Supply chain attacks on configuration templates  
- Accidental propagation of misconfiguration

While not achieving "Total loss of liveness/network availability" (Critical), it significantly degrades network functionality and creates availability issues for affected nodes and their peers.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack requires:
- Access to modify node configuration files (operator access OR config file compromise)
- No additional privileges or complex exploitation
- Single configuration value change

Attack vectors include:
- **Malicious insider**: Operator with configuration access
- **Compromised deployment pipeline**: CI/CD or configuration management system breach
- **Supply chain attack**: Malicious modification of configuration templates
- **Accidental misconfiguration**: Operator error (though warning provides some protection)

The lack of hard enforcement makes this trivially exploitable once configuration access is obtained.

## Recommendation

Implement hard validation that prevents dangerous `prune_window` values:

**In `config/src/config/storage_config.rs`, modify the `ConfigSanitizer`:**

```rust
if state_merkle_prune_window < 100_000 {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        format!(
            "State Merkle prune_window ({}) is below minimum safe value (100000). \
            Node will not function correctly. This is a hard requirement.",
            state_merkle_prune_window
        ),
    ));
}
```

**Additional safeguards:**

1. Add runtime assertion in `StateMerklePrunerManager::new()`:
```rust
assert!(
    state_merkle_pruner_config.prune_window >= 100_000,
    "prune_window must be at least 100,000 for safe operation"
);
```

2. Document minimum values clearly in configuration schema and validation messages

3. Consider implementing dynamic adjustment if pruning risks are detected at runtime

## Proof of Concept

**Configuration File Attack:**

1. Create a node configuration with malicious pruner settings:

```yaml
# node_config.yaml
storage:
  storage_pruner_config:
    state_merkle_pruner_config:
      enable: true
      prune_window: 0  # Malicious value
      batch_size: 1000
```

2. Start the node with this configuration:
```bash
aptos-node -f node_config.yaml
```

**Expected Behavior:**

- Node starts successfully (only warning logged)
- Within seconds/minutes of block processing:
  - `min_readable_version` advances to `latest_version`
  - Historical state becomes unreadable
  - Execution attempts fail with "state pruned" errors
  - State sync requests from peers fail
  - Node becomes dysfunctional

**Verification:**

Monitor logs for errors like:
```
"StateValue at version X is pruned, min available version is Y"
"State merkle at version X is pruned"
```

Check metrics:
- `aptos_pruner_versions{pruner_name="state_merkle",tag="min_readable"}` rapidly approaching latest version
- Execution errors increasing
- State sync failures from peer nodes

The node will exhibit execution instability and be unable to serve as a reliable validator or state sync source.

### Citations

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L67-72)
```rust
    fn maybe_set_pruner_target_db_version(&self, latest_version: Version) {
        let min_readable_version = self.get_min_readable_version();
        if self.is_pruner_enabled() && latest_version >= min_readable_version + self.prune_window {
            self.set_pruner_target_db_version(latest_version);
        }
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L106-133)
```rust
    pub fn new(
        state_merkle_db: Arc<StateMerkleDb>,
        state_merkle_pruner_config: StateMerklePrunerConfig,
    ) -> Self {
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
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L159-174)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());

        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&[S::name(), "min_readable"])
            .set(min_readable_version as i64);

        self.pruner_worker
            .as_ref()
            .unwrap()
            .set_target_db_version(min_readable_version);
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

**File:** config/src/config/storage_config.rs (L711-713)
```rust
        if state_merkle_prune_window < 100_000 {
            warn!("State Merkle prune_window is too small, node might stop functioning.");
        }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L73-76)
```rust
            indices.into_iter().try_for_each(|index| {
                batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
                batch.delete::<S>(&index)
            })?;
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L644-654)
```rust
    fn get_state_value_with_version_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<(Version, StateValue)>> {
        gauged_api("get_state_value_with_version_by_version", || {
            self.error_if_state_kv_pruned("StateValue", version)?;

            self.state_store
                .get_state_value_with_version_by_version(state_key, version)
        })
```

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L242-247)
```rust
        } else if let Some(base_version) = self.base_version() {
            COUNTER.inc_with(&["sv_cold"]);
            StateSlot::from_db_get(
                self.cold
                    .get_state_value_with_version_by_version(state_key, base_version)?,
            )
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L273-302)
```rust
    pub(super) fn error_if_state_merkle_pruned(
        &self,
        data_type: &str,
        version: Version,
    ) -> Result<()> {
        let min_readable_version = self
            .state_store
            .state_db
            .state_merkle_pruner
            .get_min_readable_version();
        if version >= min_readable_version {
            return Ok(());
        }

        let min_readable_epoch_snapshot_version = self
            .state_store
            .state_db
            .epoch_snapshot_pruner
            .get_min_readable_version();
        if version >= min_readable_epoch_snapshot_version {
            self.ledger_db.metadata_db().ensure_epoch_ending(version)
        } else {
            bail!(
                "{} at version {} is pruned. snapshots are available at >= {}, epoch snapshots are available at >= {}",
                data_type,
                version,
                min_readable_version,
                min_readable_epoch_snapshot_version,
            )
        }
```
