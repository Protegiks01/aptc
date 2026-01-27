# Audit Report

## Title
Aggressive Epoch Snapshot Pruning Prevents Fast Sync Node Bootstrapping

## Summary
The `prune_window` configuration for `EpochSnapshotPrunerConfig` can be set to arbitrarily low values with only a warning, causing epoch snapshots (state values at epoch boundaries) to be pruned before new fast sync nodes can use them for bootstrapping. This breaks network availability and prevents new nodes from joining.

## Finding Description

The vulnerability exists in the interaction between the epoch snapshot pruner configuration and the fast sync bootstrapping mechanism.

**Configuration Weakness:**
The `EpochSnapshotPrunerConfig` struct defines a `prune_window` field that controls how many versions of epoch snapshots are retained. [1](#0-0) 

The configuration sanitizer only issues a warning (not an error) when `prune_window` is set below 50,000,000 versions: [2](#0-1) 

This allows node operators to set `prune_window` to dangerously low values (e.g., 1,000,000 or even lower) without any hard enforcement preventing it.

**Pruning Mechanism:**
The `StateMerklePrunerManager` calculates the minimum readable version using `saturating_sub`: [3](#0-2) 

This means if a node has `latest_version = 100,000,000` and `prune_window = 1,000,000`, then:
- `min_readable_version = 100,000,000 - 1,000,000 = 99,000,000`
- All epoch snapshots before version 99,000,000 are pruned

**Data Availability Advertisement:**
Nodes advertise their available state range based on the pruning window: [4](#0-3) 

The advertised state range becomes `[99,000,001, 100,000,000]` in the example above.

**Fast Sync Failure:**
When a new fast sync node bootstraps, it:
1. Fetches epoch ending ledger infos (always available)
2. Identifies the highest epoch ending version to sync to
3. Attempts to fetch state snapshot at that version: [5](#0-4) 

The stream engine checks data availability before proceeding: [6](#0-5) 

If the requested epoch ending version is below `min_readable_version` for all available peers, the stream creation fails: [7](#0-6) 

**Attack Scenario:**
1. Critical nodes (validators, public fullnodes) are configured with `prune_window = 1,000,000`
2. Network advances to version 100,000,000
3. These nodes prune all epoch snapshots before version 99,000,001
4. New fast sync node tries to bootstrap by syncing to the most recent epoch ending version (e.g., at version 98,000,000)
5. No peers have the required snapshot → `DataIsUnavailable` error
6. Fast sync fails, node cannot join the network

## Impact Explanation

This is a **High Severity** vulnerability according to the Aptos bug bounty criteria:

- **Network Availability**: New nodes cannot join the network via fast sync, which is the primary method for bootstrapping new nodes
- **Decentralization Impact**: Reduces the ability for new validators and fullnodes to join, harming network decentralization
- **Protocol Violation**: Violates the design assumption that fast sync should be reliably available for node bootstrapping
- **Potential DoS**: If a significant portion of the network is misconfigured, fast sync becomes completely unavailable

The issue qualifies as a "Significant protocol violation" under High Severity criteria. While it doesn't directly cause loss of funds or consensus failure, it significantly impairs network functionality and availability.

## Likelihood Explanation

The likelihood is **Medium to High**:

**Factors increasing likelihood:**
- Node operators may deliberately set low `prune_window` values to save disk space, especially on resource-constrained systems
- The default of 80,000,000 versions requires substantial disk space for state storage
- Only a warning is issued, not an error, so operators may ignore it
- If even a subset of public fullnodes (which fast sync nodes typically connect to) are misconfigured, the issue manifests

**Factors decreasing likelihood:**
- The default value (80,000,000) is reasonable and should work for most deployments
- Requires explicit configuration change by node operators
- More sophisticated operators would understand the implications

However, in practice, cost-conscious operators running public fullnodes are likely to adjust this parameter to reduce storage costs, making this scenario realistic.

## Recommendation

**Short-term fix:** Enforce a hard minimum for `prune_window` in the configuration sanitizer:

```rust
// In config/src/config/storage_config.rs, update the sanitizer
const MIN_EPOCH_SNAPSHOT_PRUNE_WINDOW: u64 = 50_000_000;

if epoch_snapshot_prune_window < MIN_EPOCH_SNAPSHOT_PRUNE_WINDOW {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        format!(
            "Epoch snapshot prune_window ({}) is below the minimum required ({}) for network health. \
            This would prevent new fast sync nodes from bootstrapping.",
            epoch_snapshot_prune_window,
            MIN_EPOCH_SNAPSHOT_PRUNE_WINDOW
        ),
    ));
}
```

**Long-term improvements:**
1. Add dynamic coordination: Nodes should advertise their oldest available snapshot and fast sync should adapt to target the oldest available across the network
2. Implement fallback mechanisms: If fast sync fails due to unavailable snapshots, automatically fall back to transaction/output syncing
3. Add monitoring: Track network-wide snapshot availability and alert if coverage drops below safe thresholds

## Proof of Concept

**Reproduction Steps:**

1. **Configure Node 1 (peer) with aggressive pruning:**
```yaml
# node1_config.yaml
storage:
  storage_pruner_config:
    epoch_snapshot_pruner_config:
      enable: true
      prune_window: 1000000  # Aggressively low
      batch_size: 1000
```

2. **Start Node 1 and let it sync to a high version** (e.g., 100,000,000+)

3. **Wait for pruning to occur** - epoch snapshots before version ~99,000,000 will be pruned

4. **Start Node 2 (new fast sync node) attempting to bootstrap:**
```yaml
# node2_config.yaml
state_sync:
  state_sync_driver:
    bootstrapping_mode: DownloadLatestStates  # Fast sync mode
```

5. **Observe Node 2 logs:**
```
ERROR: DataIsUnavailable: Unable to satisfy stream engine: StateStreamEngine { version: 98000000 }, 
with advertised data: states: [99000001, 100000000]
```

6. **Result:** Node 2 fails to bootstrap via fast sync because the required epoch snapshot at version 98,000,000 has been pruned from all available peers.

**Expected Behavior vs Actual:**
- Expected: Fast sync should succeed, or fail gracefully with fallback
- Actual: Fast sync fails with `DataIsUnavailable`, node cannot bootstrap

This PoC demonstrates that the vulnerability is exploitable through simple misconfiguration, requiring no sophisticated attack or privileged access.

### Citations

**File:** config/src/config/storage_config.rs (L357-364)
```rust
pub struct EpochSnapshotPrunerConfig {
    pub enable: bool,
    /// Window size in versions, but only the snapshots at epoch ending versions are kept, because
    /// other snapshots are pruned by the state merkle pruner.
    pub prune_window: u64,
    /// Number of stale nodes to prune a time.
    pub batch_size: usize,
}
```

**File:** config/src/config/storage_config.rs (L714-716)
```rust
        if epoch_snapshot_prune_window < 50_000_000 {
            warn!("Epoch snapshot prune_window is too small, harming network data availability.");
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

**File:** state-sync/storage-service/server/src/storage.rs (L146-176)
```rust
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

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L544-548)
```rust
            } else {
                // No snapshot sync has started. Start a new sync for the highest known ledger info.
                self.fetch_missing_state_values(highest_known_ledger_info, false)
                    .await
            }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L287-293)
```rust
    fn is_remaining_data_available(&self, advertised_data: &AdvertisedData) -> Result<bool, Error> {
        Ok(AdvertisedData::contains_range(
            self.request.version,
            self.request.version,
            &advertised_data.states,
        ))
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L866-877)
```rust
    pub fn ensure_data_is_available(&self, advertised_data: &AdvertisedData) -> Result<(), Error> {
        if !self
            .stream_engine
            .is_remaining_data_available(advertised_data)?
        {
            return Err(Error::DataIsUnavailable(format!(
                "Unable to satisfy stream engine: {:?}, with advertised data: {:?}",
                self.stream_engine, advertised_data
            )));
        }
        Ok(())
    }
```
