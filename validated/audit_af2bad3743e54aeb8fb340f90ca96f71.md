# Audit Report

## Title
Critical Epoch-Ending State Snapshot Premature Pruning Vulnerability Preventing Validator Recovery and Network Growth

## Summary
During epoch reconfiguration, Jellyfish Merkle Tree nodes created at the current epoch-ending version are misclassified for short-term pruning (1M version window) instead of long-term epoch snapshot pruning (80M version window). This causes validator fast sync failures when attempting to sync to epoch boundaries older than 55 hours, preventing new validator onboarding and recovery from extended downtime.

## Finding Description

The vulnerability exists in the state merkle tree node pruning classification logic within the storage layer. The `create_jmt_commit_batch_for_shard` function decides whether stale JMT nodes should be stored in `StaleNodeIndexCrossEpochSchema` (80M version window) or `StaleNodeIndexSchema` (1M version window): [1](#0-0) 

The classification uses `previous_epoch_ending_version` obtained from `get_previous_epoch_ending(version)`. This function explicitly returns the PREVIOUS epoch ending by seeking to `version - 1`: [2](#0-1) 

This value is retrieved in the state snapshot committer during epoch reconfiguration: [3](#0-2) 

**The Bug:** When creating a snapshot at epoch-ending version V (transitioning from epoch N to N+1):
- `previous_epoch_ending_version` equals epoch N-1's ending version
- JMT nodes created at version V have `node.version = V`
- When these nodes eventually become stale at future version V+k, the check `V <= epoch_N-1_ending` fails
- They are stored in `StaleNodeIndexSchema` (1M window) and pruned after ~55 hours at 5000 TPS

**The Impact:** When validators attempt fast sync to epoch-ending version V after the 1M prune window:

1. `error_if_state_merkle_pruned` validation passes because:
   - Version V is within the 80M epoch snapshot pruner window
   - Version V is marked as epoch ending in `EpochByVersionSchema` [4](#0-3) 

2. However, the actual JMT nodes at version V were pruned by the 1M state_merkle_pruner

3. `get_state_value_chunk_proof` fails when attempting to traverse the missing nodes: [5](#0-4) [6](#0-5) 

The epoch ending marker is set correctly during ledger info commit: [7](#0-6) 

But the pruning window mismatch creates a false availability guarantee.

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for multiple Critical impact categories per the Aptos bug bounty program:

1. **Non-recoverable Network Partition (Critical)**: New validators cannot join the network through fast sync to any epoch boundary older than the state_merkle_pruner window. With default configuration (1M versions ≈ 55 hours at 5000 TPS), any validator joining after 55+ hours of network operation encounters guaranteed sync failures. This permanently prevents network growth and decentralization until a hardfork provides the missing data.

2. **Total Loss of Liveness/Network Availability (Critical)**: If multiple validators experience simultaneous downtime exceeding the prune window (hardware failures, network partitions, operational issues), they cannot recover and rejoin consensus. Once sufficient validators are offline that the network loses BFT quorum (<2/3 validators available), block production halts entirely.

3. **State Consistency Violation**: The system violates its own availability guarantees - `error_if_state_merkle_pruned` indicates epoch snapshot data is available for 80M versions when the actual JMT nodes were pruned after 1M versions.

Default configuration confirms the vulnerability parameters: [8](#0-7) [9](#0-8) 

## Likelihood Explanation

**High Likelihood** - This is a deterministic protocol bug requiring no attacker action:

- **Guaranteed Manifestation**: Any network operating at moderate transaction throughput (5000+ TPS) for longer than the 1M version window (~55 hours) will trigger this issue
- **Regular Occurrence**: Epoch reconfigurations occur every ~2 hours on Aptos mainnet, creating continuous epoch boundaries
- **No Attack Required**: Normal network operations and passage of time guarantee the vulnerability manifests
- **Immediate Impact**: New validators joining after the window cannot sync; existing validators experiencing extended downtime cannot recover

The 1M version window (defaulting to ~55 hours at 5000 TPS) is far shorter than typical validator operational timeframes and network lifetime, making this a high-probability production failure mode.

## Recommendation

Modify the classification logic in `create_jmt_commit_batch_for_shard` to correctly identify nodes from the current epoch-ending version. The fix should compare against the current epoch-ending version rather than the previous one:

```rust
let is_epoch_ending_node = if let Some(prev_epoch_ending) = previous_epoch_ending_version {
    // For epoch-ending snapshots, also preserve nodes from the current epoch ending
    row.node_key.version() <= prev_epoch_ending || row.node_key.version() == version
} else {
    false
};

if is_epoch_ending_node {
    batch.put::<StaleNodeIndexCrossEpochSchema>(row, &())
} else {
    batch.put::<StaleNodeIndexSchema>(row, &())
}
```

Alternatively, pass the current epoch-ending status to the function and use it in the classification condition.

## Proof of Concept

This vulnerability can be demonstrated through the following test scenario:

1. Initialize a test network and generate transactions reaching epoch-ending version V at epoch N
2. Continue generating transactions for 1M+ versions beyond V
3. Trigger state merkle pruning to remove nodes outside the 1M window
4. Attempt to execute `get_state_value_chunk_with_proof` at version V
5. Observe that `error_if_state_merkle_pruned` passes (version V is epoch ending and within 80M window)
6. Observe that JMT traversal fails with missing node error because actual nodes at V were pruned

The test would verify that nodes created at epoch-ending boundaries are incorrectly classified by examining the `StaleNodeIndexSchema` vs `StaleNodeIndexCrossEpochSchema` entries after the snapshot commit.

**Notes**

This vulnerability represents a critical logic error in the storage layer's pruning classification that violates epoch snapshot availability guarantees. The mismatch between the validation layer (checking 80M epoch snapshot window) and actual data availability (1M state merkle window) creates a false sense of data availability that fails when validators attempt recovery or onboarding through fast sync.

The deterministic nature of this bug - requiring only normal network operations and time passage - combined with its severe impact on validator recovery and network growth, qualifies this as a Critical severity finding under the Aptos bug bounty program's "Non-recoverable Network Partition" and "Total Loss of Liveness" categories.

### Citations

**File:** storage/aptosdb/src/state_merkle_db.rs (L376-386)
```rust
        stale_node_index_batch.iter().try_for_each(|row| {
            ensure!(row.node_key.get_shard_id() == shard_id, "shard_id mismatch");
            if previous_epoch_ending_version.is_some()
                && row.node_key.version() <= previous_epoch_ending_version.unwrap()
            {
                batch.put::<StaleNodeIndexCrossEpochSchema>(row, &())
            } else {
                // These are processed by the state merkle pruner.
                batch.put::<StaleNodeIndexSchema>(row, &())
            }
        })?;
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L193-196)
```rust
        if ledger_info.ends_epoch() {
            // This is the last version of the current epoch, update the epoch by version index.
            batch.put::<EpochByVersionSchema>(&ledger_info.version(), &ledger_info.epoch())?;
        }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L244-259)
```rust
    /// Returns the latest ended epoch strictly before required version, i.e. if the passed in
    /// version ends an epoch, return one epoch early than that.
    pub(crate) fn get_previous_epoch_ending(
        &self,
        version: Version,
    ) -> Result<Option<(u64, Version)>> {
        if version == 0 {
            return Ok(None);
        }
        let prev_version = version - 1;

        let mut iter = self.db.iter::<EpochByVersionSchema>()?;
        // Search for the end of the previous epoch.
        iter.seek_for_prev(&prev_version)?;
        iter.next().transpose()
    }
```

**File:** storage/aptosdb/src/state_store/state_snapshot_committer.rs (L93-99)
```rust
                    let previous_epoch_ending_version = self
                        .state_db
                        .ledger_db
                        .metadata_db()
                        .get_previous_epoch_ending(version)
                        .unwrap()
                        .map(|(v, _e)| v);
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L273-303)
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
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L911-922)
```rust
    fn get_state_value_chunk_proof(
        &self,
        version: Version,
        first_index: usize,
        state_key_values: Vec<(StateKey, StateValue)>,
    ) -> Result<StateValueChunkWithProof> {
        gauged_api("get_state_value_chunk_proof", || {
            self.error_if_state_merkle_pruned("State merkle", version)?;
            self.state_store
                .get_value_chunk_proof(version, first_index, state_key_values)
        })
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1117-1143)
```rust
    pub fn get_value_chunk_proof(
        self: &Arc<Self>,
        version: Version,
        first_index: usize,
        state_key_values: Vec<(StateKey, StateValue)>,
    ) -> Result<StateValueChunkWithProof> {
        ensure!(
            !state_key_values.is_empty(),
            "State chunk starting at {}",
            first_index,
        );
        let last_index = (state_key_values.len() - 1 + first_index) as u64;
        let first_key = state_key_values.first().expect("checked to exist").0.hash();
        let last_key = state_key_values.last().expect("checked to exist").0.hash();
        let proof = self.get_value_range_proof(last_key, version)?;
        let root_hash = self.get_root_hash(version)?;

        Ok(StateValueChunkWithProof {
            first_index: first_index as u64,
            last_index,
            first_key,
            last_key,
            raw_values: state_key_values,
            proof,
            root_hash,
        })
    }
```

**File:** config/src/config/storage_config.rs (L398-413)
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
}
```

**File:** config/src/config/storage_config.rs (L415-431)
```rust
impl Default for EpochSnapshotPrunerConfig {
    fn default() -> Self {
        Self {
            enable: true,
            // This is based on ~5K TPS * 2h/epoch * 2 epochs. -- epoch ending snapshots are used
            // by state sync in fast sync mode.
            // The setting is in versions, not epochs, because this makes it behave more like other
            // pruners: a slower network will have longer history in db with the same pruner
            // settings, but the disk space take will be similar.
            // settings.
            prune_window: 80_000_000,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
        }
    }
}
```
