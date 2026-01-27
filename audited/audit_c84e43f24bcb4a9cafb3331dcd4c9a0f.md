# Audit Report

## Title
TreeOnly State Restore Creates Inconsistent Database State Leading to Node Malfunction

## Summary
The `StateSnapshotRestoreMode::TreeOnly` mode in the state restore system can create a database state where the Merkle tree structure exists but corresponding key-value data is missing. This causes state queries to fail with "State Value is missing" errors, breaking node functionality for state sync, transaction execution, and API queries.

## Finding Description

The vulnerability exists in the state snapshot restore implementation. When `StateSnapshotRestoreMode::TreeOnly` is used, only the Merkle tree structure is restored without the corresponding key-value data. [1](#0-0) 

The restore process handles these modes differently in the `add_chunk` method: [2](#0-1) 

When `TreeOnly` mode is selected (line 248), only `tree_fn()` is executed, which adds data to the Merkle tree. The `kv_fn()` that would write key-value data is **never called**.

The designed workflow in the restore coordinator uses TreeOnly followed by transaction replay: [3](#0-2) 

However, if the restore process is interrupted after TreeOnly restore completes but before transaction replay finishes, and the node is then started, the database enters an inconsistent state.

When state queries are made, the system retrieves data using `get_state_value_with_proof_by_version_ext`: [4](#0-3) 

This method gets the Merkle tree proof (which succeeds since the tree was restored), but then calls `expect_value_by_version` to retrieve the actual value: [5](#0-4) 

Since the KV data was never written during TreeOnly restore, this returns an error: "State Value is missing for key {:?} by version {}".

Critical state sync operations depend on this failing path: [6](#0-5) 

The `get_value_chunk_iter` method (line 1110) calls `expect_value_by_version`, which will fail for all keys in the TreeOnly-restored snapshot.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Affected nodes cannot process state queries
- **API crashes**: State API endpoints fail with errors
- **Significant protocol violations**: Breaks the State Consistency invariant that "State transitions must be atomic and verifiable via Merkle proofs"

The impact includes:
1. State sync requests from other nodes fail, preventing them from syncing
2. Transaction execution fails when reading account state
3. API queries for state values return errors
4. The node becomes non-functional for normal operations

However, this is **NOT** a consensus violation - only the misconfigured node is affected, not the network.

## Likelihood Explanation

**Medium-High likelihood** in operational scenarios:

1. **Restore interruption**: If backup-restore CLI process crashes or is killed after TreeOnly restore but before transaction replay completes
2. **Operator error**: If an operator manually performs TreeOnly restore without understanding the requirement for transaction replay
3. **Infrastructure failure**: If the restore container/process terminates unexpectedly during the multi-phase restore

The restore coordinator includes resume capabilities, but there's no validation preventing a node from starting with incomplete restore: [7](#0-6) 

The initialization allows starting with a snapshot ahead of transactions (lines 611-617) without validating that the snapshot KV data exists.

## Recommendation

Add validation during node initialization to detect and prevent starting with incomplete TreeOnly restore:

1. **Add completion marker**: When state snapshot restore finishes, write a metadata marker indicating whether it was complete (Default/KvOnly) or incomplete (TreeOnly)

2. **Validate on startup**: During `create_buffered_state_from_latest_snapshot`, check if the latest snapshot has the completion marker. If it's marked as TreeOnly-incomplete, fail startup with a clear error message directing the operator to complete the restore.

3. **Sample-verify KV data**: For snapshots, randomly sample a few keys from the Merkle tree and verify the corresponding KV data exists in state_kv_db.

Example implementation:

```rust
// In state_store/mod.rs, add to create_buffered_state_from_latest_snapshot:
if let Some(snapshot_version) = latest_snapshot_version {
    // Check if this is an incomplete TreeOnly restore
    let restore_complete = state_db.ledger_db
        .metadata_db()
        .get::<DbMetadataSchema>(&DbMetadataKey::StateSnapshotRestoreComplete(snapshot_version))?;
    
    if !restore_complete.unwrap_or(true) {
        return Err(AptosDbError::Other(
            "Cannot start node with incomplete TreeOnly restore. \
             Please complete the restore process by running transaction replay.".to_string()
        ));
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_tree_only_restore_creates_inconsistent_state() {
    // 1. Setup a test database with some state
    let tmp_dir = TempPath::new();
    let db = AptosDB::new_for_test(&tmp_dir);
    
    // Create state at version 100
    let state_key = StateKey::raw(b"test_key");
    let state_value = StateValue::new_legacy(b"test_value".to_vec());
    // ... write state through normal transaction flow ...
    
    // 2. Take a state snapshot backup
    let backup_handler = db.get_backup_handler();
    let snapshot = backup_handler.get_state_snapshot(100);
    
    // 3. Create a new database and restore using TreeOnly mode
    let restore_dir = TempPath::new();
    let restore_db = AptosDB::new_for_test(&restore_dir);
    
    let state_restore = StateSnapshotRestore::new(
        &restore_db.state_merkle_db,
        &restore_db.state_kv_db,
        100,
        expected_root_hash,
        false,
        StateSnapshotRestoreMode::TreeOnly, // Only restore tree
    ).unwrap();
    
    // Restore the snapshot (only tree, no KV)
    for chunk in snapshot.chunks {
        state_restore.add_chunk(chunk.values, chunk.proof).unwrap();
    }
    state_restore.finish().unwrap();
    
    // 4. Try to start the node (initialize BufferedState)
    // This succeeds but creates inconsistent state!
    let state_store = restore_db.state_store.clone();
    
    // 5. Try to query state value with proof
    // This will FAIL with "State Value is missing"
    let result = state_store.get_state_value_with_proof_by_version_ext(
        &state_key.hash(),
        100,
        0,
        false,
    );
    
    // Expected: Err("State Value is missing for key ...")
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("State Value is missing"));
    
    // 6. Try state sync query (used by other nodes)
    let chunk_result = state_store.get_value_chunk_with_proof(100, 0, 10);
    
    // This also fails, breaking state sync for other nodes
    assert!(chunk_result.is_err());
}
```

---

**Notes:**

This vulnerability requires node operator-level access to trigger (ability to run restore operations and start the node). While it's classified as High severity due to causing node malfunction, it's fundamentally an **operational robustness issue** rather than a remotely exploitable attack vector. The designed workflow expects transaction replay to follow TreeOnly restore, but there's insufficient validation to prevent nodes from starting in the intermediate inconsistent state.

### Citations

**File:** storage/aptosdb/src/state_restore/mod.rs (L49-57)
```rust
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum StateSnapshotRestoreMode {
    /// Restore both KV and Tree by default
    Default,
    /// Only restore the state KV
    KvOnly,
    /// Only restore the state tree
    TreeOnly,
}
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L246-255)
```rust
        match self.restore_mode {
            StateSnapshotRestoreMode::KvOnly => kv_fn()?,
            StateSnapshotRestoreMode::TreeOnly => tree_fn()?,
            StateSnapshotRestoreMode::Default => {
                // We run kv_fn with TreeOnly to restore the usage of DB
                let (r1, r2) = IO_POOL.join(kv_fn, tree_fn);
                r1?;
                r2?;
            },
        }
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L316-351)
```rust
            if !tree_completed {
                // For boostrap DB to latest version, we want to use default mode
                let restore_mode_opt = if db_next_version > 0 {
                    if replay_all_mode {
                        None // the restore should already been done in the replay_all mode
                    } else {
                        Some(StateSnapshotRestoreMode::TreeOnly)
                    }
                } else {
                    Some(StateSnapshotRestoreMode::Default)
                };

                if let Some(restore_mode) = restore_mode_opt {
                    info!(
                        "Start restoring tree snapshot at {} with db_next_version {}",
                        tree_snapshot.version, db_next_version
                    );
                    StateSnapshotRestoreController::new(
                        StateSnapshotRestoreOpt {
                            manifest_handle: tree_snapshot.manifest.clone(),
                            version: tree_snapshot.version,
                            validate_modules: false,
                            restore_mode,
                        },
                        self.global_opt.clone(),
                        Arc::clone(&self.storage),
                        epoch_history.clone(),
                    )
                    .run()
                    .await?;
                }

                replay_version = Some((
                    tree_snapshot.version + 1,
                    false, /*replay entire txn including update tree and KV*/
                ));
```

**File:** storage/aptosdb/src/state_store/mod.rs (L209-236)
```rust
    fn get_state_value_with_proof_by_version_ext(
        &self,
        key_hash: &HashValue,
        version: Version,
        root_depth: usize,
        use_hot_state: bool,
    ) -> Result<(Option<StateValue>, SparseMerkleProofExt)> {
        let db = if use_hot_state {
            if self.state_merkle_db.sharding_enabled() {
                self.hot_state_merkle_db
                    .as_ref()
                    .ok_or(AptosDbError::HotStateError)?
            } else {
                // Unsharded unit tests still rely on this.
                &self.state_merkle_db
            }
        } else {
            &self.state_merkle_db
        };
        let (leaf_data, proof) = db.get_with_proof_ext(key_hash, version, root_depth)?;
        Ok((
            match leaf_data {
                Some((_val_hash, (key, ver))) => Some(self.expect_value_by_version(&key, ver)?),
                None => None,
            },
            proof,
        ))
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

**File:** storage/aptosdb/src/state_store/mod.rs (L602-617)
```rust
        // In some backup-restore tests we hope to open the db without consistency check.
        if hack_for_tests {
            return Ok(buffered_state);
        }

        // Make sure the committed transactions is ahead of the latest snapshot.
        let snapshot_next_version = latest_snapshot_version.map_or(0, |v| v + 1);

        // For non-restore cases, always snapshot_next_version <= num_transactions.
        if snapshot_next_version > num_transactions {
            info!(
                snapshot_next_version = snapshot_next_version,
                num_transactions = num_transactions,
                "snapshot is after latest transaction version. It should only happen in restore mode",
            );
        }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1095-1115)
```rust
    pub fn get_value_chunk_iter(
        self: &Arc<Self>,
        version: Version,
        first_index: usize,
        chunk_size: usize,
    ) -> Result<impl Iterator<Item = Result<(StateKey, StateValue)>> + Send + Sync + use<>> {
        let store = Arc::clone(self);
        let value_chunk_iter = JellyfishMerkleIterator::new_by_index(
            Arc::clone(&self.state_merkle_db),
            version,
            first_index,
        )?
        .take(chunk_size)
        .map(move |res| {
            res.and_then(|(_, (key, version))| {
                Ok((key.clone(), store.expect_value_by_version(&key, version)?))
            })
        });

        Ok(value_chunk_iter)
    }
```
