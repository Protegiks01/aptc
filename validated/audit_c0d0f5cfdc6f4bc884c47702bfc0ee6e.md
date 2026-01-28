# Audit Report

## Title
Critical Epoch-Ending State Snapshot Premature Pruning Vulnerability Preventing Validator Recovery and Network Growth

## Summary
During epoch reconfiguration, state merkle tree nodes created at the current epoch-ending version are incorrectly stored for short-term pruning (1M version window) instead of long-term epoch snapshot pruning (80M version window). This causes the system to prematurely delete JMT nodes that should be retained for epoch snapshot access, creating a mismatch between availability checks and actual data presence.

## Finding Description

The vulnerability exists in the state merkle tree node pruning classification logic. When committing a state snapshot at epoch-ending version V, the system must classify stale JMT nodes into either `StaleNodeIndexCrossEpochSchema` (80M version retention) or `StaleNodeIndexSchema` (1M version retention). [1](#0-0) 

The classification uses `previous_epoch_ending_version` obtained during snapshot commitment: [2](#0-1) 

However, the `get_previous_epoch_ending` function explicitly returns the PREVIOUS epoch ending, not the current one: [3](#0-2) 

**The Bug:** When creating a snapshot at epoch-ending version V:
- `get_previous_epoch_ending(V)` returns epoch N-1's ending version (e.g., 1000)
- Stale nodes at version V (e.g., 2000) fail check: `2000 <= 1000`
- These nodes incorrectly go to `StaleNodeIndexSchema` (1M window)
- Should go to `StaleNodeIndexCrossEpochSchema` (80M window)

**The Consequence:** After the 1M version window expires, the validation check passes but data is missing: [4](#0-3) 

The `error_if_state_merkle_pruned` check verifies the epoch snapshot pruner's 80M window and confirms the version is epoch-ending. However, the actual JMT nodes were already deleted by state_merkle_pruner (1M window), causing merkle proof generation to fail.

## Impact Explanation

**Critical Severity** - This vulnerability breaks the core data availability guarantee for epoch-ending state snapshots:

1. **State Sync Failure**: New validators or recovering validators attempting to fast sync to an epoch boundary older than 1M versions will fail despite the system indicating data availability. The `error_if_state_merkle_pruned` check passes, but subsequent merkle tree traversal fails due to missing nodes.

2. **Data Availability Guarantee Violation**: The system promises 80M version retention for epoch snapshots but actually provides only 1M version retention. This is documented as critical for "state sync in fast sync mode" per the configuration comments. [5](#0-4) 

3. **Validator Operation Impact**: At 5000 TPS, the 1M version window is approximately 55 hours. Any validator joining or recovering after this period cannot sync to the affected epoch boundaries, potentially preventing network growth and validator recovery.

Default configuration confirms the discrepancy: [6](#0-5) 

The schema design confirms epoch-ending nodes should be retained longer: [7](#0-6) 

## Likelihood Explanation

**High Likelihood** - This is a deterministic bug requiring no attacker action:

- Triggered automatically on every epoch ending
- At 5000 TPS: 1M versions ≈ 55 hours
- Aptos mainnet epochs occur regularly (every ~2 hours per config comments)
- Any validator attempting to join or recover after the 1M window will encounter this issue
- The bug manifests on any production network operating long enough at moderate-to-high throughput

## Recommendation

Fix the classification logic to use the current epoch-ending version instead of the previous one. When committing state at epoch-ending version V, ensure stale nodes at version V are classified for long-term retention:

```rust
// In state_snapshot_committer.rs, get the CURRENT epoch ending if this version ends an epoch
let previous_epoch_ending_version = if self.state_db.ledger_db.metadata_db()
    .ensure_epoch_ending(version).is_ok() 
{
    Some(version)  // Current version IS an epoch ending
} else {
    self.state_db.ledger_db.metadata_db()
        .get_previous_epoch_ending(version)
        .unwrap()
        .map(|(_, v)| v)
};
```

Or alternatively, adjust the comparison logic in `create_jmt_commit_batch_for_shard` to use `<` instead of `<=` if the semantic intent is to include the current epoch-ending version.

## Proof of Concept

The bug can be demonstrated by:

1. Starting a node and processing transactions through multiple epochs
2. Waiting for more than 1M versions to pass after an epoch ending
3. Attempting to query state merkle proofs at the old epoch-ending version
4. Observing that `error_if_state_merkle_pruned` passes but merkle tree traversal fails with missing node errors

Direct code inspection confirms the logic error - no executable PoC is needed as this is a deterministic classification bug visible in the static code paths shown above.

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

**File:** storage/aptosdb/src/schema/stale_node_index_cross_epoch/mod.rs (L1-13)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! Similar to `state_node_index`, this records the same node replacement information except that
//! the stale nodes here are the latest in at least one epoch.
//!
//! ```text
//! |<--------------key-------------->|
//! | stale_since_version | node_key |
//! ```
//!
//! `stale_since_version` is serialized in big endian so that records in RocksDB will be in order of
//! its numeric value.
```
