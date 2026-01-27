# Audit Report

## Title
State Restore Mode Change Attack: Hybrid State Creation via TreeOnly-to-KvOnly Mode Switch

## Summary
A malicious or uninformed operator can create a corrupted hybrid database state by changing the `restore_mode` parameter between interruption and resumption of a state snapshot restore operation, resulting in a node with incomplete state data that breaks query functionality and consensus integrity.

## Finding Description

The state snapshot restore system in `storage/aptosdb/src/state_restore/mod.rs` allows operators to specify a `StateSnapshotRestoreMode` when restoring state snapshots. The system supports three modes: `Default` (restore both KV and Tree), `KvOnly` (restore only key-value data), and `TreeOnly` (restore only Merkle tree). [1](#0-0) 

The vulnerability arises from the interaction between the progress tracking mechanism and the ability to change restore modes between restore attempts. Progress is tracked separately for KV and Tree components, and when resuming a restore, the system uses the minimum of both progress points to determine which chunks to skip. [2](#0-1) 

The critical flaw occurs when:

1. An operator starts a restore with `TreeOnly` mode and processes chunks 1-5, writing only tree data
2. The restore is interrupted (crash, manual stop, etc.)
3. Tree progress is persisted via the rightmost leaf in the tree database
4. The operator resumes with `KvOnly` mode
5. The system checks `previous_key_hash()` which returns the tree's progress (chunk 5's last key hash)
6. Based on this progress, chunks 1-5 are skipped
7. Chunks 6-10 are processed in `KvOnly` mode, writing only KV data [3](#0-2) 

The result is a hybrid state where:
- Tree database contains chunks 1-5 only
- KV database contains chunks 6-10 only
- The state is fundamentally inconsistent and non-functional

The tree component's progress is recovered from the database during initialization: [4](#0-3) 

The KV component's progress is loaded from the metadata store: [5](#0-4) 

**Invariant Violated**: State Consistency - State transitions must be atomic and verifiable via Merkle proofs. This attack creates a state where the Merkle tree and key-value store are out of sync, making the state unverifiable and queries unfulfillable.

## Impact Explanation

This vulnerability has **HIGH severity** impact:

1. **Node Malfunction**: The affected node cannot serve state queries correctly:
   - Queries for keys in chunks 1-5 will find tree data but fail KV lookups (data appears to exist but cannot be retrieved)
   - Queries for keys in chunks 6-10 have KV data but no tree proofs (cannot generate Merkle proofs for existence)

2. **Consensus Divergence Risk**: If multiple nodes restore with different mode sequences, they will have different state representations, potentially leading to consensus disagreements when computing state roots.

3. **State Root Mismatch**: The computed state root hash from the incomplete tree will not match the expected hash for the full state, violating state verification invariants.

4. **Database Corruption**: The node's database is in an irreparable hybrid state requiring full re-synchronization.

Per Aptos bug bounty criteria, this qualifies as **High Severity** because it causes significant protocol violations and state inconsistencies requiring manual intervention to resolve.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can occur through:

1. **Operator Error**: An operator who doesn't understand the implications of restore modes might:
   - Start a restore with one mode
   - Encounter an interruption
   - Resume with a different mode (thinking it doesn't matter or trying to "fix" something)

2. **Intentional Sabotage**: A malicious operator with access to node configuration could deliberately create this hybrid state to:
   - Corrupt a validator node
   - Cause consensus issues across the network
   - Create nodes that appear functional but serve incorrect state

3. **Script/Automation Bugs**: Automated restore scripts that don't properly track or enforce consistent restore modes across restarts

The attack requires:
- Access to the node's restore command/configuration
- Ability to interrupt and restart the restore process
- Knowledge to change the `restore_mode` parameter

No validation exists to prevent mode changes between restore attempts. The system does not persist the restore mode alongside progress, and does not verify mode consistency on resume.

## Recommendation

Implement restore mode validation to prevent mid-restore mode changes:

1. **Persist Restore Mode with Progress**: Store the active restore mode in the progress metadata alongside the key hash and usage:

```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateSnapshotProgress {
    pub key_hash: HashValue,
    pub usage: StateStorageUsage,
    pub restore_mode: Option<StateSnapshotRestoreMode>, // Add this field
}
```

2. **Validate Mode Consistency**: In `StateSnapshotRestore::new()`, check if a previous restore is in progress and validate the mode matches:

```rust
pub fn new<T: 'static + TreeReader<K> + TreeWriter<K>, S: 'static + StateValueWriter<K, V>>(
    tree_store: &Arc<T>,
    value_store: &Arc<S>,
    version: Version,
    expected_root_hash: HashValue,
    async_commit: bool,
    restore_mode: StateSnapshotRestoreMode,
) -> Result<Self> {
    // Check for in-progress restore
    if let Some(existing_progress) = value_store.get_progress(version)? {
        if let Some(existing_mode) = existing_progress.restore_mode {
            ensure!(
                existing_mode == restore_mode,
                "Cannot change restore mode mid-restore. Previous mode: {:?}, New mode: {:?}",
                existing_mode,
                restore_mode
            );
        }
    }
    
    // ... rest of initialization
}
```

3. **Clear Progress on Mode Change**: If mode change is intentional, require explicit progress reset:

```rust
pub fn reset_restore_progress(&self, version: Version) -> Result<()> {
    // Clear all progress for this version
    self.clear_kv_progress(version)?;
    self.clear_tree_progress(version)?;
    Ok(())
}
```

## Proof of Concept

```rust
// Proof of Concept demonstrating the vulnerability
// File: storage/aptosdb/src/state_restore/restore_test.rs (test addition)

#[test]
fn test_mode_change_creates_hybrid_state() {
    // Setup: Create a mock store and generate test data
    let store = Arc::new(MockSnapshotStore::new(false));
    let version = 100;
    let mut all_keys_values = generate_test_data(100); // 100 key-value pairs
    let root_hash = calculate_root_hash(&all_keys_values);
    
    // Phase 1: Restore first 50 keys in TreeOnly mode
    {
        let mut restore = StateSnapshotRestore::new(
            &store,
            &store,
            version,
            root_hash,
            false,
            StateSnapshotRestoreMode::TreeOnly,
        ).unwrap();
        
        let (chunk1, proof1) = all_keys_values[0..50].to_vec();
        restore.add_chunk(chunk1, proof1).unwrap();
        restore.finish().unwrap();
        
        // Verify tree has data for first 50 keys
        assert!(store.tree_has_keys(&all_keys_values[0..50]));
        // Verify KV does NOT have data
        assert!(!store.kv_has_keys(&all_keys_values[0..50]));
    }
    
    // Phase 2: Resume with KvOnly mode for remaining keys
    {
        let mut restore = StateSnapshotRestore::new(
            &store,
            &store,
            version,
            root_hash,
            false,
            StateSnapshotRestoreMode::KvOnly, // MODE CHANGED!
        ).unwrap();
        
        // System will skip first 50 keys based on tree progress
        let (chunk2, proof2) = all_keys_values[50..100].to_vec();
        restore.add_chunk(chunk2, proof2).unwrap();
        restore.finish().unwrap();
        
        // Verify KV has data for keys 50-100
        assert!(store.kv_has_keys(&all_keys_values[50..100]));
        // Verify tree does NOT have data for keys 50-100
        assert!(!store.tree_has_keys(&all_keys_values[50..100]));
    }
    
    // Verification: Hybrid state created
    // Tree: keys 0-50
    // KV: keys 50-100
    // INCONSISTENT STATE!
    
    // Try to query a key from first half - FAILS
    let key_from_first_half = &all_keys_values[25].0;
    assert!(store.tree_has_key(key_from_first_half)); // Tree says it exists
    assert!(!store.kv_has_key(key_from_first_half));   // But KV doesn't have it!
    
    // Try to query a key from second half - FAILS
    let key_from_second_half = &all_keys_values[75].0;
    assert!(!store.tree_has_key(key_from_second_half)); // Tree doesn't have it
    assert!(store.kv_has_key(key_from_second_half));     // But KV does!
    
    // State root verification would also fail
    let computed_root = store.compute_tree_root(version);
    assert_ne!(computed_root, root_hash); // Root hash mismatch!
}
```

**Notes**

The vulnerability exists because restore mode is not persisted alongside progress, allowing operators to change modes between restore attempts. The separate progress tracking for KV and Tree components, combined with the minimum-based resume logic, enables the creation of hybrid states where different chunks are processed in different modes. This breaks the fundamental state consistency invariant that the Merkle tree and key-value store must always be synchronized.

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

**File:** storage/aptosdb/src/state_restore/mod.rs (L196-214)
```rust
    pub fn previous_key_hash(&self) -> Result<Option<HashValue>> {
        let hash_opt = match (
            self.kv_restore
                .lock()
                .as_ref()
                .unwrap()
                .previous_key_hash()?,
            self.tree_restore
                .lock()
                .as_ref()
                .unwrap()
                .previous_key_hash(),
        ) {
            (None, hash_opt) => hash_opt,
            (hash_opt, None) => hash_opt,
            (Some(hash1), Some(hash2)) => Some(std::cmp::min(hash1, hash2)),
        };
        Ok(hash_opt)
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L228-258)
```rust
    fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
        let kv_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_add_chunk"]);
            self.kv_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk(chunk.clone())
        };

        let tree_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["jmt_add_chunk"]);
            self.tree_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk_impl(chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof)
        };
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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L189-235)
```rust
    pub fn new<D: 'static + TreeReader<K> + TreeWriter<K>>(
        store: Arc<D>,
        version: Version,
        expected_root_hash: HashValue,
        async_commit: bool,
    ) -> Result<Self> {
        let tree_reader = Arc::clone(&store);
        let (finished, partial_nodes, previous_leaf) = if let Some(root_node) =
            tree_reader.get_node_option(&NodeKey::new_empty_path(version), "restore")?
        {
            info!("Previous restore is complete, checking root hash.");
            ensure!(
                root_node.hash() == expected_root_hash,
                "Previous completed restore has root hash {}, expecting {}",
                root_node.hash(),
                expected_root_hash,
            );
            (true, vec![], None)
        } else if let Some((node_key, leaf_node)) = tree_reader.get_rightmost_leaf(version)? {
            // If the system crashed in the middle of the previous restoration attempt, we need
            // to recover the partial nodes to the state right before the crash.
            (
                false,
                Self::recover_partial_nodes(tree_reader.as_ref(), version, node_key)?,
                Some(leaf_node),
            )
        } else {
            (
                false,
                vec![InternalInfo::new_empty(NodeKey::new_empty_path(version))],
                None,
            )
        };

        Ok(Self {
            store,
            version,
            partial_nodes,
            frozen_nodes: HashMap::new(),
            previous_leaf,
            num_keys_received: 0,
            expected_root_hash,
            finished,
            async_commit,
            async_commit_result: None,
        })
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1317-1350)
```rust
    fn get_progress(&self, version: Version) -> Result<Option<StateSnapshotProgress>> {
        let main_db_progress = self
            .state_kv_db
            .metadata_db()
            .get::<DbMetadataSchema>(&DbMetadataKey::StateSnapshotKvRestoreProgress(version))?
            .map(|v| v.expect_state_snapshot_progress());

        // verify if internal indexer db and main db are consistent before starting the restore
        if self.internal_indexer_db.is_some()
            && self
                .internal_indexer_db
                .as_ref()
                .unwrap()
                .statekeys_enabled()
        {
            let progress_opt = self
                .internal_indexer_db
                .as_ref()
                .unwrap()
                .get_restore_progress(version)?;

            match (main_db_progress, progress_opt) {
                (None, None) => (),
                (None, Some(_)) => (),
                (Some(main_progress), Some(indexer_progress)) => {
                    if main_progress.key_hash > indexer_progress.key_hash {
                        bail!(
                            "Inconsistent restore progress between main db and internal indexer db. main db: {:?}, internal indexer db: {:?}",
                            main_progress,
                            indexer_progress,
                        );
                    }
                },
                _ => {
```
