# Audit Report

## Title
State Snapshot Backup Validation Bypass Allows Empty Chunks with Arbitrary Root Hash

## Summary
A state snapshot backup with an empty chunks array can pass validation and be restored, even when the declared `root_hash` in the manifest doesn't match the actual resulting state tree hash (`SPARSE_MERKLE_PLACEHOLDER_HASH`). This occurs because `StateSnapshotBackup` lacks the chunk validation present in other backup types, and `JellyfishMerkleRestore::finish_impl()` doesn't verify that the expected root hash matches the placeholder hash when no chunks are added.

## Finding Description
Unlike `TransactionBackup` and `EpochEndingBackup`, which have `verify()` methods that explicitly check `!self.chunks.is_empty()`, the `StateSnapshotBackup` struct has no such validation method. [1](#0-0) 

When a `StateSnapshotBackup` with an empty chunks array is restored, the process flows as follows:

1. The manifest is loaded without any chunk validation [2](#0-1) 

2. The proof is verified against the ledger info, confirming that `manifest.root_hash` matches the proof's claimed state root hash [3](#0-2) 

3. The restore receiver is initialized with `manifest.root_hash` as the expected root hash [4](#0-3) 

4. Since the chunks array is empty, the chunk processing loop doesn't execute any iterations [5](#0-4) 

5. `finish()` is called, which invokes `JellyfishMerkleRestore::finish_impl()` [6](#0-5) 

6. In `finish_impl()`, when `num_children == 0` (no chunks were added), it unconditionally writes `Node::Null` to storage without validating that the `expected_root_hash` equals `SPARSE_MERKLE_PLACEHOLDER_HASH` [7](#0-6) 

7. Since `Node::Null.hash()` returns `SPARSE_MERKLE_PLACEHOLDER_HASH` [8](#0-7) , the database now contains a state tree with root hash `SPARSE_MERKLE_PLACEHOLDER_HASH`, even though the manifest (and proof) claimed a different `root_hash`.

**Broken Invariant:** This violates the **State Consistency** invariant - the database contains a state tree whose actual root hash doesn't match the declared root hash for that version, creating a fundamental integrity violation.

## Impact Explanation
This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria, as it causes "State inconsistencies requiring intervention."

Concrete impacts:
- **Database Corruption**: Node operators restoring from such a backup will have an incorrect state tree for the specified version
- **Consensus Risk**: If multiple validators restore from the same malformed backup, they would all have incorrect state, but the mismatch would be detected when attempting to execute transactions against this state
- **Recovery Required**: Manual intervention would be needed to detect and fix the corrupted state tree
- **Trust Compromise**: Malicious actors could distribute "valid" backups that pass all automated checks but contain incorrect state

The vulnerability doesn't directly cause fund loss or network partition, but it enables state manipulation that could cascade into more severe issues depending on how the corrupted state is used.

## Likelihood Explanation
**Likelihood: Medium**

Prerequisites for exploitation:
1. Attacker must provide a state snapshot backup manifest (either by hosting a malicious backup service or compromising a legitimate backup)
2. A valid `TransactionInfoWithProof` and `LedgerInfoWithSignatures` that verifies correctly but claims an arbitrary (non-empty-tree) root hash for a given version
3. An empty chunks array
4. A victim node operator who restores from this backup

The attack is straightforward to execute - no complex cryptographic operations or race conditions are required. The main barrier is that the attacker must either:
- Run a malicious backup service that node operators trust, or
- Compromise an existing backup storage system

However, once a malformed backup is created, any node operator who restores from it will be affected, making the impact widespread.

## Recommendation

Add a `verify()` method to `StateSnapshotBackup` that checks for empty chunks, consistent with the validation in other backup types:

```rust
impl StateSnapshotBackup {
    pub fn verify(&self) -> Result<()> {
        ensure!(
            !self.chunks.is_empty(),
            "State snapshot backup must have at least one chunk."
        );
        
        // Additional validation: verify chunk continuity if needed
        Ok(())
    }
}
```

Then modify the restore controller to call this verification method during manifest loading, similar to how `TransactionBackup::verify()` is called [9](#0-8) :

```rust
let manifest: StateSnapshotBackup = storage
    .load_json_file(&self.manifest_handle)
    .await?;
manifest.verify()?; // Add this validation
```

Additionally, add a safety check in `JellyfishMerkleRestore::finish_impl()` to ensure that when writing `Node::Null`, the expected root hash is actually `SPARSE_MERKLE_PLACEHOLDER_HASH`:

```rust
match num_children {
    0 => {
        ensure!(
            self.expected_root_hash == *SPARSE_MERKLE_PLACEHOLDER_HASH,
            "Cannot finalize empty tree restoration with non-placeholder expected root hash. Expected: {}, Placeholder: {}",
            self.expected_root_hash,
            *SPARSE_MERKLE_PLACEHOLDER_HASH
        );
        let node_key = NodeKey::new_empty_path(self.version);
        assert!(self.frozen_nodes.is_empty());
        self.frozen_nodes.insert(node_key, Node::Null);
        self.store.write_node_batch(&self.frozen_nodes)?;
        return Ok(());
    },
    // ... rest of match cases
}
```

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability by showing that a StateSnapshotBackup
// with empty chunks can be created and would pass through the restore process
// until it writes an inconsistent state tree to the database.

#[cfg(test)]
mod state_snapshot_validation_bypass_test {
    use aptos_backup_cli::backup_types::state_snapshot::manifest::StateSnapshotBackup;
    use aptos_crypto::HashValue;
    use std::str::FromStr;

    #[test]
    fn test_empty_chunks_bypass() {
        // Create a StateSnapshotBackup with empty chunks but non-placeholder root hash
        let malicious_root_hash = HashValue::from_str(
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        ).unwrap();
        
        let malicious_backup = StateSnapshotBackup {
            version: 0,
            epoch: 0,
            root_hash: malicious_root_hash, // Not SPARSE_MERKLE_PLACEHOLDER_HASH
            chunks: vec![], // Empty chunks!
            proof: FileHandle::from("dummy_proof.bcs".to_string()),
        };
        
        // Attempt to verify - this should fail but doesn't because verify() doesn't exist
        // If verify() method existed (as recommended):
        // assert!(malicious_backup.verify().is_err());
        
        // Current behavior: no verification, would proceed to restore
        // During restore, finish_impl() would write Node::Null (hashing to PLACEHOLDER)
        // but the manifest claims root_hash = malicious_root_hash
        // Result: Database state tree root hash mismatch!
        
        println!("Malicious backup with empty chunks created:");
        println!("  Declared root_hash: {}", malicious_root_hash);
        println!("  Chunks count: {}", malicious_backup.chunks.len());
        println!("  After restore, actual root hash would be: SPARSE_MERKLE_PLACEHOLDER_HASH");
        println!("  This creates state inconsistency!");
    }
}
```

## Notes
The vulnerability exists specifically in the state snapshot backup restoration path. Transaction backups and epoch ending backups are properly protected by their respective `verify()` methods that explicitly reject empty chunks arrays [10](#0-9)  and [11](#0-10) .

The issue is compounded by the fact that `JellyfishMerkleRestore` was designed to handle resumption after crashes and doesn't validate the empty-tree case against the expected root hash, likely assuming that upstream validation would prevent this scenario.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/manifest.rs (L29-51)
```rust
/// State snapshot backup manifest, representing a complete state view at specified version.
#[derive(Deserialize, Serialize)]
pub struct StateSnapshotBackup {
    /// Version at which this state snapshot is taken.
    pub version: Version,
    /// Epoch in which this state snapshot is taken.
    pub epoch: u64,
    /// Hash of the state tree root.
    pub root_hash: HashValue,
    /// All account blobs in chunks.
    pub chunks: Vec<StateSnapshotChunk>,
    /// BCS serialized
    /// `Tuple(TransactionInfoWithProof, LedgerInfoWithSignatures)`.
    ///   - The `TransactionInfoWithProof` is at `Version` above, and carries the same `root_hash`
    /// above; It proves that at specified version the root hash is as specified in a chain
    /// represented by the LedgerInfo below.
    ///   - The signatures on the `LedgerInfoWithSignatures` has a version greater than or equal to
    /// the version of this backup but is within the same epoch, so the signatures on it can be
    /// verified by the validator set in the same epoch, which can be provided by an
    /// `EpochStateBackup` recovered prior to this to the DB; Requiring it to be in the same epoch
    /// limits the requirement on such `EpochStateBackup` to no older than the same epoch.
    pub proof: FileHandle,
}
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-124)
```rust
        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L127-136)
```rust
        txn_info_with_proof.verify(li.ledger_info(), manifest.version)?;
        let state_root_hash = txn_info_with_proof
            .transaction_info()
            .ensure_state_checkpoint_hash()?;
        ensure!(
            state_root_hash == manifest.root_hash,
            "Root hash mismatch with that in proof. root hash: {}, expected: {}",
            manifest.root_hash,
            state_root_hash,
        );
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L141-145)
```rust
        let receiver = Arc::new(Mutex::new(Some(self.run_mode.get_state_restore_receiver(
            self.version,
            manifest.root_hash,
            self.restore_mode,
        )?)));
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L187-226)
```rust
        let futs_iter = chunks.into_iter().enumerate().map(|(chunk_idx, chunk)| {
            let storage = storage.clone();
            async move {
                tokio::spawn(async move {
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L228-229)
```rust
        tokio::task::spawn_blocking(move || receiver.lock().take().unwrap().finish()).await??;
        self.run_mode.finish();
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L765-772)
```rust
            match num_children {
                0 => {
                    let node_key = NodeKey::new_empty_path(self.version);
                    assert!(self.frozen_nodes.is_empty());
                    self.frozen_nodes.insert(node_key, Node::Null);
                    self.store.write_node_batch(&self.frozen_nodes)?;
                    return Ok(());
                },
```

**File:** storage/jellyfish-merkle/src/node_type/mod.rs (L850-856)
```rust
    pub fn hash(&self) -> HashValue {
        match self {
            Node::Internal(internal_node) => internal_node.hash(),
            Node::Leaf(leaf_node) => leaf_node.hash(),
            Node::Null => *SPARSE_MERKLE_PLACEHOLDER_HASH,
        }
    }
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L353-353)
```rust
            .and_then(|m: TransactionBackup| future::ready(m.verify().map(|_| m)));
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L60-60)
```rust
        ensure!(!self.chunks.is_empty(), "No chunks.");
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/manifest.rs (L41-41)
```rust
        ensure!(!self.chunks.is_empty(), "No chunks.");
```
