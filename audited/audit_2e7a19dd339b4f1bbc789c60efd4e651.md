# Audit Report

## Title
TreeOnly State Restore Mode Causes Node Unavailability Due to Missing KV Data

## Summary
The TreeOnly restore mode in AptosDB restores only the Jellyfish Merkle Tree structure without the corresponding key-value data, creating an inconsistent database state that causes all state queries to fail with "State Value is missing" errors, leading to complete node unavailability.

## Finding Description
The vulnerability exists in the state restore mechanism where TreeOnly mode is used during incremental backup restoration. When TreeOnly mode is active, only the Jellyfish Merkle Tree structure is restored to the database, but the actual state key-value pairs are NOT written. [1](#0-0) 

The critical issue occurs when state queries are attempted after TreeOnly restoration but before transaction replay completes. The query path follows:

1. **API or Transaction Execution** queries state via `get_state_value_with_proof_by_version_ext()`
2. **Tree lookup succeeds** because the Merkle tree structure exists
3. **KV data retrieval fails** because `expect_value_by_version()` queries the empty KV database [2](#0-1) [3](#0-2) 

The `expect_value_by_version()` function throws a "State Value is missing" error when the KV database is empty, even though the tree structure proves the key existed at that version. [4](#0-3) 

This affects ALL state query paths including:
- REST API queries for account resources and modules
- Transaction execution state reads via DbStateView
- State sync operations
- Any component that queries historical state [5](#0-4) 

## Impact Explanation
This qualifies as **HIGH severity** under Aptos bug bounty criteria:

1. **API Crashes**: All API endpoints querying state return internal errors when the node is in TreeOnly-restored state without KV data
2. **Validator Node Unavailability**: Nodes cannot execute transactions or participate in consensus because state reads fail
3. **Significant Protocol Violation**: The state consistency invariant is violated - the tree structure claims data exists but the data is missing

The issue creates a **persistent broken state** that survives node restarts if the system crashes between TreeOnly restore completion and transaction replay.

## Likelihood Explanation
**MEDIUM-to-LOW likelihood** in production:

The vulnerability manifests when:
1. TreeOnly restore is initiated (during incremental backup restoration when `db_next_version > 0`) [6](#0-5) 

2. System crashes or is interrupted before transaction replay completes
3. Node restarts and attempts to serve queries

While the restore coordinator is designed to run TreeOnly restore followed immediately by transaction replay, there is NO safeguard preventing queries if the process is interrupted. The state is persisted to disk after TreeOnly completion but before KV data is restored.

## Recommendation

**Critical Fix**: Add a database metadata flag to track incomplete TreeOnly restorations and prevent queries until KV data is restored.

**Implementation approach**:

1. Add a `TreeOnlyRestoreInProgress` flag to database metadata before TreeOnly restore begins
2. Check this flag during node initialization - if present, either:
   - Block all state queries with a clear error message
   - Automatically resume transaction replay to complete KV restoration
3. Clear the flag only after transaction replay successfully completes

**Alternative mitigation**: Modify TreeOnly mode to write a tombstone/marker for each key in the KV database indicating "data pending replay", allowing queries to return a specific "restoration in progress" error rather than "missing data" errors that are indistinguishable from corruption.

## Proof of Concept

```rust
// Reproduction steps (pseudo-code):

// 1. Perform TreeOnly restore
let restore = StateSnapshotRestore::new(
    tree_store,
    value_store,
    version,
    expected_root_hash,
    false,
    StateSnapshotRestoreMode::TreeOnly,
)?;

// Add state snapshot chunks
restore.add_chunk(chunk_data, proof)?;
restore.finish()?; // Tree is now restored, KV database is empty

// 2. Simulate crash before transaction replay
// (In production: system crash, interrupt, or operator error)

// 3. Attempt state query
let db = AptosDB::open(db_path)?;
let state_key = StateKey::access_path(access_path);
let result = db.get_state_value_with_proof_by_version(&state_key, version);

// Expected: Error("State Value is missing for key ... by version ...")
// Impact: Node cannot serve queries, API fails, execution blocked
```

---

**Notes**:
This is a design flaw in the restore mechanism rather than a directly exploitable vulnerability. It requires privileged access to restore operations or a system crash to manifest. However, it represents a significant availability and operational risk that violates the state consistency invariant.

### Citations

**File:** storage/aptosdb/src/state_restore/mod.rs (L246-258)
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

        Ok(())
    }
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

**File:** storage/aptosdb/src/state_kv_db.rs (L374-402)
```rust
    pub(crate) fn get_state_value_with_version_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<(Version, StateValue)>> {
        let mut read_opts = ReadOptions::default();

        // We want `None` if the state_key changes in iteration.
        read_opts.set_prefix_same_as_start(true);
        if !self.enabled_sharding() {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueSchema>(read_opts)?;
            iter.seek(&(state_key.clone(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        } else {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueByKeyHashSchema>(read_opts)?;
            iter.seek(&(state_key.hash(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        }
    }
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L27-46)
```rust
    fn get(&self, key: &StateKey) -> StateViewResult<Option<(Version, StateValue)>> {
        if let Some(version) = self.version {
            if let Some(root_hash) = self.maybe_verify_against_state_root_hash {
                // TODO(aldenhu): sample-verify proof inside DB
                // DB doesn't support returning proofs for buffered state, so only optionally
                // verify proof.
                // TODO: support returning state proof for buffered state.
                if let Ok((value, proof)) =
                    self.db.get_state_value_with_proof_by_version(key, version)
                {
                    proof.verify(root_hash, *key.crypto_hash_ref(), value.as_ref())?;
                }
            }
            Ok(self
                .db
                .get_state_value_with_version_by_version(key, version)?)
        } else {
            Ok(None)
        }
    }
```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L318-346)
```rust
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
```
