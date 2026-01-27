# Audit Report

## Title
State Snapshot Restore Accepts Empty Chunks Without Validation, Bypassing Merkle Proof Verification

## Summary
The state snapshot restore mechanism in `storage/jellyfish-merkle/src/restore/mod.rs` accepts chunks with empty blob data without verifying the associated Merkle proofs. When a `StateSnapshotChunk` has valid index metadata (first_idx, last_idx) but an empty blobs FileHandle, the restore process completes successfully without detecting that claimed accounts are missing from the restored state.

## Finding Description
The vulnerability exists in the backup/restore code path where state snapshot chunks are processed. The `StateSnapshotChunk` struct declares metadata about account ranges (first_idx, last_idx) alongside blob data and Merkle proofs. [1](#0-0) 

During restore, blobs are read from the FileHandle and passed to the state restore receiver: [2](#0-1) [3](#0-2) 

If the blobs file is empty, `read_state_value()` returns an empty Vec. This empty Vec is then passed to `add_chunk()`, which forwards it to the Jellyfish Merkle tree restore: [4](#0-3) 

**The Critical Flaw**: In `JellyfishMerkleRestore::add_chunk_impl()`, empty chunks trigger an early return that bypasses proof verification: [5](#0-4) 

The proof verification at line 391 is never reached: [6](#0-5) 

**Attack Scenario**:
1. Malicious backup contains a chunk with first_idx=0, last_idx=999, empty blobs file, and arbitrary proof file
2. During restore, empty Vec is passed to add_chunk
3. Both tree and KV restores accept empty chunk without validation
4. No state is written to storage
5. Manifest metadata claims 1000 accounts exist in indices 0-999, but actual state is empty/incomplete

**Broken Invariant**: State Consistency - "State transitions must be atomic and verifiable via Merkle proofs." Empty chunks bypass Merkle proof verification entirely.

## Impact Explanation
This qualifies as **Medium Severity** per Aptos bug bounty criteria because it causes "State inconsistencies requiring intervention."

The vulnerability enables:
- **Ghost Account Metadata**: Index metadata claims accounts exist when they don't
- **Incomplete State Restoration**: Restore completes "successfully" with missing data
- **Node Operation Failures**: Queries for claimed accounts fail, transactions depending on those accounts error
- **Potential Consensus Divergence**: If different nodes restore from different corrupted backups, they could diverge

While this doesn't directly cause fund loss or consensus breaks, it corrupts node state in a way that requires manual intervention to detect and fix. The node would appear to have successfully restored but would be operating on incorrect state.

## Likelihood Explanation
**Likelihood: Low**

Exploitation requires:
1. **Trusted Component Compromise**: Attacker must control or compromise the backup storage (S3, GCS, operator-controlled filesystem)
2. **Operator Action**: Node operator must explicitly run restore using the malicious backup
3. **No External Detection**: The validation gap is only exposed during manual restore operations, not during normal operation or state sync

The primary barrier is that backup sources are typically trusted components controlled by node operators or official Aptos infrastructure. An unprivileged external attacker cannot inject malicious backups into the restore process without first compromising operator infrastructure.

**However**, this represents a significant validation gap that violates defense-in-depth principles. Even trusted components should be validated to prevent accidental corruption or insider threats.

## Recommendation
Add validation that enforces chunk metadata consistency before accepting empty chunks:

```rust
pub fn add_chunk_impl(
    &mut self,
    mut chunk: Vec<(&K, HashValue)>,
    proof: SparseMerkleRangeProof,
) -> Result<()> {
    if self.finished {
        info!("State snapshot restore already finished, ignoring entire chunk.");
        return Ok(());
    }

    // Skip overlapping leaves
    if let Some(prev_leaf) = &self.previous_leaf {
        let skip_until = chunk
            .iter()
            .find_position(|(key, _hash)| key.hash() > *prev_leaf.account_key());
        chunk = match skip_until {
            None => {
                info!("Skipping entire chunk.");
                return Ok(());
            },
            Some((0, _)) => chunk,
            Some((num_to_skip, next_leaf)) => {
                info!(
                    num_to_skip = num_to_skip,
                    next_leaf = next_leaf,
                    "Skipping leaves."
                );
                chunk.split_off(num_to_skip)
            },
        }
    };
    
    // NEW VALIDATION: Empty chunks must still verify their proofs
    // This ensures that empty chunks represent genuinely empty ranges
    // rather than corrupted/missing data
    if chunk.is_empty() {
        // For truly empty ranges, verify the proof still produces expected root
        self.verify(proof)?;
        return Ok(());
    }

    // ... rest of function unchanged ...
}
```

Additionally, add validation in the restore controller to check blob count matches index range:

```rust
// In StateSnapshotRestoreController::run_impl, after reading blobs:
let blobs = Self::read_state_value(&storage, chunk.blobs.clone()).await?;
let expected_count = chunk.last_idx.checked_sub(chunk.first_idx)
    .and_then(|diff| diff.checked_add(1))
    .ok_or_else(|| anyhow!("Invalid chunk index range"))?;

ensure!(
    blobs.len() == expected_count,
    "Chunk blob count mismatch: expected {}, got {}",
    expected_count,
    blobs.len()
);
```

## Proof of Concept
Since this vulnerability requires access to backup infrastructure, a complete PoC requires operator privileges. However, the validation gap can be demonstrated with a unit test:

```rust
#[test]
fn test_empty_chunk_bypasses_verification() {
    let db = Arc::new(MockTreeStore::default());
    let version = 0;
    // Use wrong root hash to demonstrate verification is skipped
    let wrong_root_hash = HashValue::random();
    
    let mut restore = JellyfishMerkleRestore::new(
        db.clone(),
        version,
        wrong_root_hash,
        false,
    ).unwrap();
    
    // Create empty chunk with invalid proof
    let empty_chunk: Vec<(&ValueBlob, HashValue)> = vec![];
    let invalid_proof = SparseMerkleRangeProof::new(vec![]); // Invalid proof
    
    // This should fail verification but currently succeeds
    let result = restore.add_chunk_impl(empty_chunk, invalid_proof);
    assert!(result.is_ok()); // Bug: accepts empty chunk without verification
}
```

---

**Note**: While this represents a legitimate validation gap in the code, it does **not** meet the strict criteria for unprivileged exploitation required by the validation checklist, as it requires compromising trusted backup infrastructure. This is a defense-in-depth issue that should be fixed but has limited practical exploitability without insider access.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/manifest.rs (L12-27)
```rust
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L191-193)
```rust
                    let blobs = Self::read_state_value(&storage, chunk.blobs.clone()).await?;
                    let proof = storage.load_bcs_file(&chunk.proof).await?;
                    Result::<_>::Ok((chunk_idx, chunk, blobs, proof))
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L253-266)
```rust
    async fn read_state_value(
        storage: &Arc<dyn BackupStorage>,
        file_handle: FileHandle,
    ) -> Result<Vec<(StateKey, StateValue)>> {
        let mut file = storage.open_for_read(&file_handle).await?;

        let mut chunk = vec![];

        while let Some(record_bytes) = file.read_record_bytes().await? {
            chunk.push(bcs::from_bytes(&record_bytes)?);
        }

        Ok(chunk)
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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L369-371)
```rust
        if chunk.is_empty() {
            return Ok(());
        }
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L390-391)
```rust
        // Verify what we have added so far is all correct.
        self.verify(proof)?;
```
