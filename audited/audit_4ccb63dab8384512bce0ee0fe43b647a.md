# Audit Report

## Title
State Snapshot Restore Incomplete Restoration Attack - Missing Root Hash Validation Allows Empty State Commitment

## Summary
The `StateSnapshotRestoreController::run_impl()` function contains a critical vulnerability where if `previous_key_hash()` returns a hash value greater than all chunk `last_key` values, the `skip_while` loop skips all chunks, and the restore completes successfully with an empty/null state instead of the expected state data. The `finish()` method fails to validate that the final committed root hash matches the expected root hash, allowing state corruption to go undetected.

## Finding Description
The vulnerability exists in the state snapshot restoration logic that supports resuming interrupted restores. The code uses `previous_key_hash()` to determine which chunks have already been restored and skips them using a `skip_while` loop: [1](#0-0) 

When `resume_point` is greater than all `chunk.last_key` values in the manifest, ALL chunks are skipped. This can occur in several scenarios:
1. **Manifest Mismatch**: The restore process uses a different manifest than the one that created the original progress (e.g., backup was regenerated with different chunking)
2. **Wrong Manifest File**: An incorrect manifest file is provided during restore operations
3. **Database Corruption**: The progress tracking database returns an invalid high hash value

When all chunks are skipped, the while loop that processes chunks never executes: [2](#0-1) 

Subsequently, `finish()` is called on a `StateSnapshotReceiver` that has never had any chunks added: [3](#0-2) 

In `JellyfishMerkleRestore::finish_impl()`, when no chunks have been added, the partial_nodes remain in their initial state with a single empty root node and zero children. The code then creates a `Node::Null` and writes it to storage: [4](#0-3) 

A `Node::Null` has a hash value of `SPARSE_MERKLE_PLACEHOLDER_HASH`: [5](#0-4) 

**Critical Missing Validation**: The `finish_impl()` method does NOT validate that the final root hash matches the `expected_root_hash` that was passed during initialization: [6](#0-5) 

The expected_root_hash is stored but never checked at completion. Tests validate this externally after calling finish(), but the production code does not: [7](#0-6) 

This breaks the **State Consistency** invariant: State transitions must be atomic and verifiable via Merkle proofs. The node commits an empty state tree (hash = `SPARSE_MERKLE_PLACEHOLDER_HASH`) when it should have committed the actual state (hash = `expected_root_hash`), yet the restore operation reports success.

## Impact Explanation
**Severity: CRITICAL** (Consensus/Safety Violations)

This vulnerability enables state corruption that leads to consensus failure:

1. **Consensus Safety Violation**: Affected nodes have an incorrect state root hash for a specific version. When validators execute blocks at this version, they will produce different state roots, causing consensus to fail or fork.

2. **Deterministic Execution Broken**: The invariant that "all validators must produce identical state roots for identical blocks" is violated when some nodes have the correct state and others have the empty placeholder state.

3. **Transaction Execution Failures**: Any transaction execution or state query at the corrupted version will return incorrect results (empty state instead of actual data), causing transaction validation and execution to fail.

4. **Non-Recoverable Network State**: Depending on how many nodes are affected, this could require manual intervention or a hard fork to recover, as nodes will be unable to reach consensus on the correct chain state.

This meets the Critical severity criteria per the Aptos bug bounty program: "Consensus/Safety violations" and potentially "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation
**Likelihood: MEDIUM**

While the vulnerability requires specific operational conditions to trigger, these conditions can realistically occur:

1. **Operational Scenarios**: During disaster recovery or fast sync operations, operators may use backup files from different sources or time periods, causing manifest mismatches.

2. **Backup Infrastructure Compromise**: If backup storage servers are compromised, an attacker could substitute manifests to trigger this vulnerability when nodes restore from backups.

3. **State Sync Integration**: If the state sync protocol uses this restore code path and downloads manifests from peers, a malicious or compromised peer could provide a mismatched manifest.

4. **Configuration Errors**: In distributed deployments, configuration management issues could lead to nodes using inconsistent backup manifests.

The vulnerability does not require validator-level privileges but does require some level of influence over the backup/restore process (file access, backup server control, or state sync manipulation). It's not directly exploitable by external transaction senders but represents a significant operational security risk.

## Recommendation
Add explicit root hash validation in the `finish_impl()` method before writing the final state to storage:

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    
    // ... existing special case handling for single leaf/null node ...
    
    self.freeze(0);
    self.store.write_node_batch(&self.frozen_nodes)?;
    
    // ADDED: Validate the final root hash matches expectations
    let actual_root_hash = self.store.get_node_option(
        &NodeKey::new_empty_path(self.version), 
        "verify_root"
    )?.ok_or_else(|| anyhow!("Root node not found after restore"))?
    .hash();
    
    ensure!(
        actual_root_hash == self.expected_root_hash,
        "Root hash mismatch after restore. Expected: {}, Got: {}. \
         This indicates an incomplete or corrupted restoration.",
        self.expected_root_hash,
        actual_root_hash
    );
    
    Ok(())
}
```

Additionally, add a safety check in the restore controller to detect when all chunks are being skipped:

```rust
// After line 174 in restore.rs
if chunks.is_empty() && total_chunks > 0 {
    return Err(anyhow!(
        "All {} chunks would be skipped due to resume point {:?}. \
         This likely indicates a manifest mismatch or database corruption.",
        total_chunks,
        resume_point_opt
    ));
}
```

## Proof of Concept
```rust
#[test]
fn test_incomplete_restore_vulnerability() {
    use aptos_crypto::{HashValue, hash::CryptoHash};
    use std::collections::BTreeMap;
    
    // Setup: Create a valid state with data
    let mut state_data = BTreeMap::new();
    state_data.insert(HashValue::random(), (ValueBlob::from(vec![1]), ValueBlob::from(vec![2])));
    state_data.insert(HashValue::random(), (ValueBlob::from(vec![3]), ValueBlob::from(vec![4])));
    
    let (source_db, source_version) = init_mock_store(&state_data.values().cloned().collect());
    let tree = JellyfishMerkleTree::new(&source_db);
    let expected_root_hash = tree.get_root_hash(source_version).unwrap();
    
    // This should be a non-empty hash for valid state
    assert_ne!(expected_root_hash, *SPARSE_MERKLE_PLACEHOLDER_HASH);
    
    let restore_db = Arc::new(MockSnapshotStore::default());
    let target_version = 100;
    
    // Create restore with expected non-empty root hash
    let mut restore = StateSnapshotRestore::new(
        &restore_db,
        &restore_db,
        target_version,
        expected_root_hash, // Expecting non-empty state
        false,
        StateSnapshotRestoreMode::Default,
    ).unwrap();
    
    // Simulate the attack: Inject progress with a hash higher than all chunk last_keys
    // In production, this could happen via manifest mismatch or corruption
    let malicious_high_hash = HashValue::new([0xFF; HashValue::LENGTH]);
    let fake_progress = StateSnapshotProgress::new(
        malicious_high_hash,
        StateStorageUsage::zero(),
    );
    restore_db.progress_store.write().insert(target_version, fake_progress);
    
    // The restore controller would skip all chunks due to skip_while
    // and then call finish() with no chunks added
    
    // Call finish without adding any chunks - simulating all chunks skipped
    restore.finish().unwrap(); // ❌ This succeeds when it should fail!
    
    // Verify the vulnerability: The actual root hash is PLACEHOLDER (empty)
    // but expected_root_hash was non-empty
    let actual_root_hash = JellyfishMerkleTree::new(&*restore_db)
        .get_root_hash(target_version)
        .unwrap();
    
    // ❌ VULNERABILITY: actual_root_hash is SPARSE_MERKLE_PLACEHOLDER_HASH
    // but we expected a non-empty root hash
    assert_eq!(actual_root_hash, *SPARSE_MERKLE_PLACEHOLDER_HASH);
    assert_ne!(actual_root_hash, expected_root_hash);
    
    // The restore succeeded but committed the WRONG state!
    // Node now has corrupted state at this version.
}
```

## Notes
The vulnerability is confirmed through code analysis showing that:
1. The skip_while logic can skip all chunks when resume_point > all chunk.last_key values
2. The finish_impl() method does not validate the final root hash against expected_root_hash  
3. Tests perform external validation after finish() but production code does not
4. The stored expected_root_hash field is never checked during the finish process

This represents a critical missing validation in the state restoration code path that could lead to consensus failures in operational scenarios involving backup/restore operations or state sync.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L165-174)
```rust
        let resume_point_opt = receiver.lock().as_mut().unwrap().previous_key_hash()?;
        let chunks = if let Some(resume_point) = resume_point_opt {
            manifest
                .chunks
                .into_iter()
                .skip_while(|chunk| chunk.last_key <= resume_point)
                .collect()
        } else {
            manifest.chunks
        };
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L201-226)
```rust
        while let Some((chunk_idx, chunk, mut blobs, proof)) = futs_stream.try_next().await? {
            start = start.or_else(|| Some(Instant::now()));
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["add_state_chunk"]);
            let receiver = receiver.clone();
            if self.validate_modules {
                blobs = tokio::task::spawn_blocking(move || {
                    Self::validate_modules(&blobs);
                    blobs
                })
                .await?;
            }
            tokio::task::spawn_blocking(move || {
                receiver.lock().as_mut().unwrap().add_chunk(blobs, proof)
            })
            .await??;
            leaf_idx.set(chunk.last_idx as i64);
            info!(
                chunk = chunk_idx,
                chunks_to_add = chunks_to_add,
                last_idx = chunk.last_idx,
                values_per_second = ((chunk.last_idx + 1 - start_idx) as f64
                    / start.as_ref().unwrap().elapsed().as_secs_f64())
                    as u64,
                "State chunk added.",
            );
        }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L228-230)
```rust
        tokio::task::spawn_blocking(move || receiver.lock().take().unwrap().finish()).await??;
        self.run_mode.finish();
        Ok(())
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L176-176)
```rust
    expected_root_hash: HashValue,
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L750-771)
```rust
    pub fn finish_impl(mut self) -> Result<()> {
        self.wait_for_async_commit()?;
        // Deal with the special case when the entire tree has a single leaf or null node.
        if self.partial_nodes.len() == 1 {
            let mut num_children = 0;
            let mut leaf = None;
            for i in 0..16 {
                if let Some(ref child_info) = self.partial_nodes[0].children[i] {
                    num_children += 1;
                    if let ChildInfo::Leaf(node) = child_info {
                        leaf = Some(node.clone());
                    }
                }
            }

            match num_children {
                0 => {
                    let node_key = NodeKey::new_empty_path(self.version);
                    assert!(self.frozen_nodes.is_empty());
                    self.frozen_nodes.insert(node_key, Node::Null);
                    self.store.write_node_batch(&self.frozen_nodes)?;
                    return Ok(());
```

**File:** storage/jellyfish-merkle/src/node_type/mod.rs (L850-855)
```rust
    pub fn hash(&self) -> HashValue {
        match self {
            Node::Internal(internal_node) => internal_node.hash(),
            Node::Leaf(leaf_node) => leaf_node.hash(),
            Node::Null => *SPARSE_MERKLE_PLACEHOLDER_HASH,
        }
```

**File:** storage/aptosdb/src/state_restore/restore_test.rs (L251-252)
```rust
    let actual_root_hash = tree.get_root_hash(version).unwrap();
    assert_eq!(actual_root_hash, expected_root_hash);
```
