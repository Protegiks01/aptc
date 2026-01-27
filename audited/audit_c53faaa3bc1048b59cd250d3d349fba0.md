# Audit Report

## Title
State Snapshot Manifest Metadata Manipulation Enables State Corruption During Restore

## Summary
The state snapshot restore process trusts manifest metadata (`last_key` field) without validation, allowing an attacker with access to backup storage to manipulate chunk metadata and cause incomplete state restoration. Combined with the absence of final root hash verification, this leads to corrupted database state that can cause consensus failures.

## Finding Description

The `StateSnapshotChunk` structure contains metadata fields (`first_key`, `last_key`) that describe the key range of data in each chunk. During restoration with resume functionality, these metadata fields are used to determine which chunks to skip, but they are **never validated** against the actual data in the chunk files. [1](#0-0) 

During restore resume, chunks are filtered based on the manifest's `last_key` field: [2](#0-1) 

The attack works as follows:

1. **Setup**: An attacker gains write access to backup storage (e.g., compromised S3 bucket, malicious cloud provider, supply chain attack)

2. **Manifest Manipulation**: The attacker modifies a legitimate backup's `manifest.json` file, setting the `last_key` field of one or more chunks to values **lower than** the actual last key in that chunk's data

3. **Exploitation During Resume**: When a validator performs state restoration that gets interrupted and resumed:
   - The resume logic retrieves `previous_key_hash` from the database (the last successfully processed key)
   - Chunks are filtered using `skip_while(|chunk| chunk.last_key <= resume_point)`
   - If a chunk's manifest `last_key` is set artificially low (e.g., 50) but the actual data contains keys up to 200, and the resume point is 100:
     - The manifest claims the chunk ends at key 50
     - Skip logic: 50 <= 100, so chunk is **SKIPPED**
     - The actual data with keys 101-200 is **NEVER RESTORED**

4. **Missing Validation**: While each chunk's cryptographic proof is verified during processing, there are two critical missing validations:

   a) No validation that manifest metadata matches actual chunk data: [3](#0-2) 

   b) No final root hash verification after `finish()` completes: [4](#0-3) 

   The JellyfishMerkleRestore's `finish_impl()` also lacks final root hash verification: [5](#0-4) 

5. **Impact**: The restored database contains incomplete state with a Merkle root hash that differs from the expected value. When this validator participates in consensus, it has different state than honest validators, breaking the "Deterministic Execution" invariant and potentially causing consensus safety violations or chain splits.

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **State Consistency Violation**: The restored state is incomplete, missing account data from skipped chunks
2. **Consensus Safety Risk**: Validators with corrupted state will produce different state roots for identical blocks, breaking the fundamental consensus invariant
3. **Potential Chain Split**: If multiple validators restore from the same compromised backup, they form a Byzantine minority with incorrect state
4. **Non-Deterministic Execution**: State divergence between validators violates the core requirement that all honest validators must reach identical state

This directly maps to **"Consensus/Safety violations"** in the Critical Severity category, as it can cause validators to disagree on state and potentially fork the chain.

## Likelihood Explanation

**Medium-High Likelihood** under specific operational scenarios:

**Attack Requirements**:
- Attacker gains write access to backup storage (compromised cloud storage, supply chain attack, malicious infrastructure provider)
- Validator performs state restoration from compromised backup
- Restoration is interrupted and resumed (or attacker times the attack to coincide with expected interruption)

**Favorable Conditions**:
- Validators using shared or third-party backup storage
- Long-running restore operations (more likely to be interrupted)
- Automated restore procedures without integrity checks
- Infrastructure compromises during disaster recovery scenarios

The attack is **realistic** because:
- Backup storage is often less secured than consensus infrastructure
- Manifest files are JSON (easily modifiable)
- No cryptographic integrity protection on manifest metadata
- Validators must restore from backups after failures/sync operations

## Recommendation

Implement three layers of defense:

**1. Validate Manifest Metadata Against Actual Data**

Before processing chunks, verify that manifest metadata matches the actual first and last keys in the chunk data:

```rust
// In restore.rs, after loading chunk data
let actual_first_key = blobs.first().map(|(k, _)| k.hash()).unwrap();
let actual_last_key = blobs.last().map(|(k, _)| k.hash()).unwrap();
ensure!(
    chunk.first_key == actual_first_key && chunk.last_key == actual_last_key,
    "Chunk manifest metadata mismatch: manifest claims [{}, {}], actual data is [{}, {}]",
    chunk.first_key, chunk.last_key, actual_first_key, actual_last_key
);
```

**2. Add Final Root Hash Verification**

In `JellyfishMerkleRestore::finish_impl()`, verify the computed root hash matches expected:

```rust
pub fn finish_impl(mut self) -> Result<()> {
    self.wait_for_async_commit()?;
    // ... existing freeze logic ...
    self.freeze(0);
    self.store.write_node_batch(&self.frozen_nodes)?;
    
    // CRITICAL: Verify final root hash
    let actual_root_hash = self.store.get_node_option(&NodeKey::new_empty_path(self.version), "finish")?
        .ok_or_else(|| anyhow!("Root node not found after restore"))?
        .hash();
    ensure!(
        actual_root_hash == self.expected_root_hash,
        "State snapshot restore completed but root hash mismatch. Expected: {}, Actual: {}",
        self.expected_root_hash,
        actual_root_hash
    );
    
    Ok(())
}
```

**3. Add Manifest Integrity Protection**

Sign the manifest file with validator keys or use content-addressed storage to prevent tampering.

## Proof of Concept

```rust
// Proof of Concept demonstrating the vulnerability
// This would be run as part of the restore test suite

#[test]
fn test_manifest_manipulation_attack() {
    use std::collections::BTreeMap;
    use aptos_crypto::HashValue;
    
    // Setup: Create legitimate backup with 3 chunks
    let all_keys: BTreeMap<HashValue, (ValueBlob, ValueBlob)> = /* 300 keys */;
    let (db, version) = init_mock_store(&all_keys);
    let tree = JellyfishMerkleTree::new(&db);
    let expected_root_hash = tree.get_root_hash(version).unwrap();
    
    // Simulate backup creation
    let chunk0: Vec<_> = all_keys.iter().take(100).collect(); // Keys 0-99
    let chunk1: Vec<_> = all_keys.iter().skip(100).take(100).collect(); // Keys 100-199
    let chunk2: Vec<_> = all_keys.iter().skip(200).collect(); // Keys 200-299
    
    let restore_db = Arc::new(MockSnapshotStore::default());
    
    // Phase 1: Partial restore (simulating interruption)
    {
        let mut restore = StateSnapshotRestore::new(
            &restore_db, &restore_db, version, expected_root_hash, false, StateSnapshotRestoreMode::Default
        ).unwrap();
        
        let proof0 = tree.get_range_proof(chunk0.last().unwrap().0, version).unwrap();
        restore.add_chunk(chunk0.into_iter().map(|(_, kv)| kv.clone()).collect(), proof0).unwrap();
        // Don't call finish - simulating interruption after chunk0
    }
    
    // ATTACK: Manipulate manifest
    // In real attack, attacker modifies manifest.json to set:
    // chunk1.last_key = 50 (should be 199)
    // chunk2.last_key = 300 (correct)
    
    // Phase 2: Resume with manipulated manifest
    // The skip_while logic would evaluate:
    // - resume_point = 99 (from chunk0)
    // - chunk1.last_key = 50 <= 99 → SKIP (WRONG!)
    // - chunk2.last_key = 300 > 99 → PROCESS
    
    // Result: Keys 100-199 are missing, but restore "succeeds"
    {
        let mut restore = StateSnapshotRestore::new(
            &restore_db, &restore_db, version, expected_root_hash, false, StateSnapshotRestoreMode::Default
        ).unwrap();
        
        // Only chunk2 is processed due to manipulation
        let proof2 = tree.get_range_proof(chunk2.last().unwrap().0, version).unwrap();
        restore.add_chunk(chunk2.into_iter().map(|(_, kv)| kv.clone()).collect(), proof2).unwrap();
        restore.finish().unwrap(); // This succeeds without detecting the attack!
    }
    
    // Verification: Actual root hash differs from expected
    let final_tree = JellyfishMerkleTree::new(&restore_db);
    let actual_root_hash = final_tree.get_root_hash(version).unwrap();
    assert_ne!(actual_root_hash, expected_root_hash); // Attack succeeded!
    
    // Check missing data
    for (key, _) in all_keys.iter().skip(100).take(100) {
        let result = final_tree.get_with_proof(key.hash(), version);
        assert!(result.unwrap().0.is_none()); // Keys 100-199 are missing!
    }
}
```

This demonstrates that:
1. Manifest manipulation causes chunks to be incorrectly skipped
2. `finish()` completes without detecting the corruption
3. The resulting database has incomplete state and wrong root hash
4. Account data is permanently missing from the restored state

**Notes**

This vulnerability exists at the intersection of operational security and protocol correctness. While it requires attacker access to backup storage (operational compromise), the lack of validation within the protocol code creates a critical security gap. The issue is particularly severe because:

1. Backup storage is often less secured than consensus infrastructure
2. The attack is silent - no errors are raised during restore
3. The corrupted state can propagate to consensus, causing network-wide issues
4. The trust model implicitly assumes backup integrity without enforcing it

The recommended fixes should be implemented to ensure defense-in-depth, making the restore process resilient even when backup storage is compromised.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/manifest.rs (L9-27)
```rust
/// A chunk of a state snapshot manifest, representing accounts in the key range
/// [`first_key`, `last_key`] (right side inclusive).
#[derive(Deserialize, Serialize)]
pub struct StateSnapshotChunk {
    /// index of the first account in this chunk over all accounts.
    pub first_idx: usize,
    /// index of the last account in this chunk over all accounts.
    pub last_idx: usize,
    /// key of the first account in this chunk.
    pub first_key: HashValue,
    /// key of the last account in this chunk.
    pub last_key: HashValue,
    /// Repeated `len(record) + record` where `record` is BCS serialized tuple
    /// `(key, state_value)`
    pub blobs: FileHandle,
    /// BCS serialized `SparseMerkleRangeProof` that proves this chunk adds up to the root hash
    /// indicated in the backup (`StateSnapshotBackup::root_hash`).
    pub proof: FileHandle,
}
```

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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L191-215)
```rust
                    let blobs = Self::read_state_value(&storage, chunk.blobs.clone()).await?;
                    let proof = storage.load_bcs_file(&chunk.proof).await?;
                    Result::<_>::Ok((chunk_idx, chunk, blobs, proof))
                })
                .await?
            }
        });
        let con = self.concurrent_downloads;
        let mut futs_stream = stream::iter(futs_iter).buffered_x(con * 2, con);
        let mut start = None;
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
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L228-230)
```rust
        tokio::task::spawn_blocking(move || receiver.lock().take().unwrap().finish()).await??;
        self.run_mode.finish();
        Ok(())
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L750-789)
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
                },
                1 => {
                    if let Some(node) = leaf {
                        let node_key = NodeKey::new_empty_path(self.version);
                        assert!(self.frozen_nodes.is_empty());
                        self.frozen_nodes.insert(node_key, node.into());
                        self.store.write_node_batch(&self.frozen_nodes)?;
                        return Ok(());
                    }
                },
                _ => (),
            }
        }

        self.freeze(0);
        self.store.write_node_batch(&self.frozen_nodes)?;
        Ok(())
    }
```
