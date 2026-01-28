# Audit Report

## Title
Epoch Snapshot Pruner Can Delete Required State Sync Data Due to Unbounded Progress Metadata

## Summary
The epoch snapshot pruner calculates its target version based on the latest state checkpoint version minus the prune window, without validating that this target doesn't exceed the latest epoch ending version. This allows the pruner to delete epoch ending snapshot data (stale merkle tree nodes) that are still needed for ongoing state synchronization, breaking the ability of new or recovering nodes to fast sync to recent epochs.

## Finding Description

The vulnerability exists in how the epoch snapshot pruner determines its target pruning version. The pruner is designed to maintain epoch ending snapshots for state sync, but it lacks bounds checking to ensure it doesn't prune beyond the latest epoch ending.

**Root Cause Flow:**

1. **Pruner Target Calculation**: The epoch snapshot pruner's target is set using the latest state checkpoint version without epoch boundary validation. [1](#0-0) 

2. **No Epoch Boundary Validation**: The target version is calculated as `latest_version.saturating_sub(self.prune_window)` without any check that this value doesn't exceed the latest epoch ending version. [2](#0-1) 

3. **Stale Node Classification**: Stale nodes with versions at or before the previous epoch ending are stored in `StaleNodeIndexCrossEpochSchema` based on the node's creation version, not when they became stale. [3](#0-2) 

4. **Unconditional Pruning**: The pruner deletes all stale nodes with `stale_since_version <= target_version` without verifying these aren't part of a needed epoch ending snapshot. [4](#0-3) [5](#0-4) 

**The Critical Logic Flaw:**

The pruner uses `stale_since_version` (when the node was overwritten) as the criterion for deletion, not the epoch the node belongs to. When nodes from an epoch ending snapshot are overwritten in subsequent epochs, they receive `stale_since_version` values that may fall within the prune window, causing them to be deleted even though they belong to an epoch snapshot that should be retained.

**Comparison with Test Expectations:**

The test suite demonstrates the intended behavior by manually ensuring the epoch snapshot pruner doesn't prune beyond required epoch endings: [6](#0-5) 

However, production code lacks this safeguard.

**State Sync Dependency:**

The design intent documented in the configuration states that "epoch ending snapshots are used by state sync in fast sync mode." [7](#0-6) 

When these nodes are deleted, the read-time validation will detect missing data but cannot prevent the prior deletion: [8](#0-7) 

## Impact Explanation

**Medium Severity** - This vulnerability causes protocol violations affecting network availability:

1. **State Sync Degradation**: Nodes attempting to fast sync to recent epochs will encounter errors when the serving node cannot retrieve required merkle tree nodes for epoch ending snapshots.

2. **Availability Impact**: New validators and full nodes must use slower synchronization methods (transaction replay) or wait for peers with longer history, increasing operational barriers and reducing network resilience.

3. **Operational Costs**: Node operators must maintain unnecessarily long history or risk being unable to serve state sync requests effectively.

The impact is **not** High/Critical because:
- Doesn't directly cause consensus failure or funds loss
- Nodes can still sync using transaction replay from genesis
- Doesn't cause permanent network partition or total liveness failure
- The error is detected and returned gracefully

This represents a **limited protocol violation** requiring manual intervention or workarounds, fitting the Medium severity category per Aptos bug bounty guidelines.

## Likelihood Explanation

**Likely** - This occurs naturally under normal network operation:

1. **Default Configuration Creates Vulnerability**: The default prune window is 80M versions. [9](#0-8) 

2. **Checkpoint-Epoch Timing Gap**: State checkpoints occur frequently, while epochs occur every ~2 hours. The latest checkpoint version naturally advances beyond epoch boundaries.

3. **No Validation Safeguards**: The pruning code path contains no checks to prevent pruning nodes from recent epoch snapshots. The vulnerability triggers automatically when state churn causes nodes from epoch snapshots to be overwritten within the prune window.

4. **State Churn**: As transactions modify state in the epochs following an epoch ending, nodes from the previous epoch snapshot become stale. Their `stale_since_version` values fall within the range that gets pruned.

## Recommendation

The epoch snapshot pruner should validate that the target version doesn't prune beyond epoch endings that need to be retained. Implement logic similar to the test suite:

1. Query the latest epoch ending version within the prune window
2. Calculate the minimum of (latest_version - prune_window) and (latest_epoch_ending_version)
3. Use this validated target for pruning

This ensures epoch ending snapshots are preserved according to the documented design intent.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Running a node through multiple epochs until it reaches version 120M
2. With default 80M prune window, the pruner target becomes 40M
3. If epoch 3 ended at version 30M, nodes from that epoch overwritten at versions 30M-40M will have `stale_since_version` in that range
4. These nodes will be pruned despite belonging to epoch 3's snapshot
5. A new node attempting to fast sync to epoch 3 will fail with "Missing node" errors

The discrepancy between the test's manual validation and production code's automatic calculation confirms this is a genuine logic flaw requiring a fix.

### Citations

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L95-98)
```rust
                        .maybe_set_pruner_target_db_version(current_version);
                    self.state_db
                        .epoch_snapshot_pruner
                        .maybe_set_pruner_target_db_version(current_version);
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

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_metadata_pruner.rs (L61-64)
```rust
        indices.into_iter().try_for_each(|index| {
            batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
            batch.delete::<S>(&index)
        })?;
```

**File:** storage/aptosdb/src/db/aptosdb_test.rs (L297-301)
```rust
        pruner.set_worker_target_version(*snapshots.first().unwrap());
        epoch_snapshot_pruner.set_worker_target_version(std::cmp::min(
            *snapshots.first().unwrap(),
            *epoch_snapshots.first().unwrap_or(&Version::MAX),
        ));
```

**File:** config/src/config/storage_config.rs (L415-430)
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
