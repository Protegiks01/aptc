# Audit Report

## Title
Missing Merkle Proof Verification in KvOnly State Snapshot Restore Mode Enables Invalid State Injection

## Summary
When restoring state snapshots in `StateSnapshotRestoreMode::KvOnly`, the system fails to cryptographically verify chunk Merkle proofs against the validated root hash. While the manifest proof and root hash are correctly verified against the validator-signed LedgerInfo, the individual chunk data bypasses Merkle proof verification, breaking the chain of cryptographic trust. This allows invalid state to be injected into AptosDB if backup files are compromised or corrupted, potentially leading to consensus failures and state inconsistencies.

## Finding Description

The state snapshot restore process involves two levels of verification:

1. **Manifest-level verification** (correctly implemented): The manifest contains a `TransactionInfoWithProof` and `LedgerInfoWithSignatures` that are cryptographically verified against validator signatures. The state root hash is extracted and verified. [1](#0-0) 

2. **Chunk-level verification** (missing in KvOnly mode): Each chunk should be verified against the validated root hash using its accompanying `SparseMerkleRangeProof`.

The `load_bcs_file()` function simply deserializes BCS data without any cryptographic verification: [2](#0-1) 

When chunks are loaded and processed, the behavior differs by restore mode: [3](#0-2) 

In `Default` or `TreeOnly` mode, the proof IS verified through the Jellyfish Merkle tree restoration: [4](#0-3) 

The tree restoration calls `add_chunk_impl()` which performs cryptographic verification: [5](#0-4) 

**However, in `KvOnly` mode**, only the KV restoration path is executed, which completely bypasses proof verification: [6](#0-5) 

The `StateValueRestore::add_chunk()` method accepts no proof parameter and performs no cryptographic verification - it directly writes data to the database.

**Attack Scenario:**

1. Attacker obtains or compromises backup files (via storage compromise, supply chain attack, or provides "trusted" public backups)
2. Attacker modifies chunk files to contain arbitrary KV data while keeping valid-looking (but cryptographically invalid) proofs
3. Operator performs restore using two-phase process (which internally uses `KvOnly` mode): [7](#0-6) 

4. Invalid state is written to AptosDB without verification
5. Subsequent transaction replay may not fully correct the corrupted base state
6. Node operates with inconsistent state that could cause consensus failures

## Impact Explanation

**Severity: Critical**

This vulnerability breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs."

The impact includes:

1. **Consensus Safety Violations**: A validator node with corrupted state could produce invalid blocks or disagree with other validators on state roots, potentially causing network partitioning or consensus failures.

2. **State Injection**: An attacker who can provide malicious backups can inject arbitrary state into nodes that restore from these backups, even though the manifest root hash was cryptographically verified against validator-signed LedgerInfo.

3. **Chain of Trust Violation**: The system correctly verifies the manifest root hash against the LedgerInfo (signed by validators), but fails to complete the verification chain by checking that chunk data matches this root hash. This defeats the entire purpose of including Merkle proofs in the backup format.

4. **Supply Chain Risk**: If operators download backups from third-party sources or cloud storage that could be compromised, they have no cryptographic guarantee that the chunk data matches the verified root hash.

Per Aptos bug bounty criteria, this qualifies as **Critical severity** due to potential "Consensus/Safety violations" and "State inconsistencies requiring intervention."

## Likelihood Explanation

**Likelihood: Medium**

The exploit requires:
1. Compromised or malicious backup files (medium difficulty - requires storage compromise, MitM, or supply chain attack)
2. Operator using these backups for restore (high probability for compromised infrastructure)
3. Two-phase restore triggering KvOnly mode (automatically happens in production code path)

While backup files are generally expected to be trusted, defense-in-depth principles require cryptographic verification even for trusted data sources. The code already performs the expensive verification of the manifest against LedgerInfo - failing to verify the final step (chunks against root hash) is an incomplete security implementation.

Real-world scenarios where this matters:
- Operators downloading "verified" public backups from potentially compromised sources
- Backup storage compromise (S3 buckets, GCS, etc.)
- Backup corruption during transfer or storage
- Insider threats with access to backup infrastructure

## Recommendation

Enforce Merkle proof verification in all restore modes, including `KvOnly`. The system should never write unverified state data to AptosDB when cryptographic proofs are available.

**Proposed Fix:**

Modify `StateValueRestore::add_chunk()` to accept and verify the proof parameter:

```rust
// In storage/aptosdb/src/state_restore/mod.rs

impl<K: Key + CryptoHash + Eq + Hash, V: Value> StateValueRestore<K, V> {
    pub fn add_chunk(&mut self, mut chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
        // load progress
        let progress_opt = self.db.get_progress(self.version)?;
        
        // skip overlaps
        if let Some(progress) = progress_opt {
            let idx = chunk
                .iter()
                .position(|(k, _v)| CryptoHash::hash(k) > progress.key_hash)
                .unwrap_or(chunk.len());
            chunk = chunk.split_off(idx);
        }
        
        // quit if all skipped
        if chunk.is_empty() {
            return Ok(());
        }
        
        // ADDED: Verify the proof before writing to database
        if let Some(last_item) = chunk.last() {
            let last_key_hash = CryptoHash::hash(&last_item.0);
            proof.verify(
                self.expected_root_hash, // Need to add this field to struct
                SparseMerkleLeafNode::new(last_key_hash, last_item.1.hash()),
                vec![], // Compute left siblings from progress
            )?;
        }
        
        // ... rest of existing code
    }
}
```

Alternatively, always use `Default` mode which includes verification, or explicitly verify proofs before calling `StateValueRestore::add_chunk()`.

## Proof of Concept

**Exploitation Steps:**

1. Create a valid state snapshot backup with legitimate manifest
2. Extract the manifest proof and root hash (which will pass verification)
3. Modify chunk files to contain arbitrary KV data
4. Generate invalid (but well-formed) Merkle proofs for the modified chunks
5. Configure a test node to restore from these modified backups using two-phase restore
6. Observe that KvOnly mode accepts the invalid chunks without verification
7. After restore completes, query the state and observe inconsistencies with the expected root hash

**Test Implementation:**

```rust
#[tokio::test]
async fn test_kvonly_bypass_merkle_verification() {
    // Setup: Create legitimate backup
    let (mut backup_storage, manifest, chunks) = create_test_backup().await;
    
    // Attack: Modify chunk data while keeping proof structure
    let malicious_chunk_data = vec![
        (StateKey::raw(b"malicious_key"), StateValue::new(b"malicious_value")),
    ];
    
    // Create invalid proof (will deserialize but fail verification)
    let invalid_proof = SparseMerkleRangeProof::new(vec![]); // Malformed proof
    
    // Save malicious chunk with invalid proof
    let malicious_chunk_handle = backup_storage
        .save_bcs_file("chunk_malicious", &(malicious_chunk_data, invalid_proof))
        .await
        .unwrap();
    
    // Trigger KvOnly restore
    let restore_opt = StateSnapshotRestoreOpt {
        manifest_handle: manifest,
        version: 100,
        validate_modules: false,
        restore_mode: StateSnapshotRestoreMode::KvOnly,
    };
    
    let controller = StateSnapshotRestoreController::new(
        restore_opt,
        global_opts,
        backup_storage,
        None,
    );
    
    // Execute restore - should fail but currently succeeds
    let result = controller.run().await;
    
    // In current implementation: succeeds (BUG)
    // In fixed implementation: should fail with proof verification error
    assert!(result.is_err()); // This will fail with current code
}
```

## Notes

This vulnerability represents a critical defense-in-depth failure. While backup files are typically from trusted sources, the system already performs the expensive operation of verifying the manifest root hash against validator-signed LedgerInfo. Failing to complete the verification chain by checking chunks against this root hash defeats the purpose of including cryptographic proofs in the backup format and creates an exploitable weakness in the trust boundary between backup storage and the live database.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L125-136)
```rust
        let (txn_info_with_proof, li): (TransactionInfoWithProof, LedgerInfoWithSignatures) =
            self.storage.load_bcs_file(&manifest.proof).await?;
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L192-193)
```rust
                    let proof = storage.load_bcs_file(&chunk.proof).await?;
                    Result::<_>::Ok((chunk_idx, chunk, blobs, proof))
```

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L31-33)
```rust
    async fn load_bcs_file<T: DeserializeOwned>(&self, file_handle: &FileHandleRef) -> Result<T> {
        Ok(bcs::from_bytes(&self.read_all(file_handle).await?)?)
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L88-127)
```rust
    pub fn add_chunk(&mut self, mut chunk: Vec<(K, V)>) -> Result<()> {
        // load progress
        let progress_opt = self.db.get_progress(self.version)?;

        // skip overlaps
        if let Some(progress) = progress_opt {
            let idx = chunk
                .iter()
                .position(|(k, _v)| CryptoHash::hash(k) > progress.key_hash)
                .unwrap_or(chunk.len());
            chunk = chunk.split_off(idx);
        }

        // quit if all skipped
        if chunk.is_empty() {
            return Ok(());
        }

        // save
        let mut usage = progress_opt.map_or(StateStorageUsage::zero(), |p| p.usage);
        let (last_key, _last_value) = chunk.last().unwrap();
        let last_key_hash = CryptoHash::hash(last_key);

        // In case of TreeOnly Restore, we only restore the usage of KV without actually writing KV into DB
        for (k, v) in chunk.iter() {
            usage.add_item(k.key_size() + v.value_size());
        }

        // prepare the sharded kv batch
        let kv_batch: StateValueBatch<K, Option<V>> = chunk
            .into_iter()
            .map(|(k, v)| ((k, self.version), Some(v)))
            .collect();

        self.db.write_kv_batch(
            self.version,
            &kv_batch,
            StateSnapshotProgress::new(last_key_hash, usage),
        )
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

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L339-392)
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
        if chunk.is_empty() {
            return Ok(());
        }

        for (key, value_hash) in chunk {
            let hashed_key = key.hash();
            if let Some(ref prev_leaf) = self.previous_leaf {
                ensure!(
                    &hashed_key > prev_leaf.account_key(),
                    "State keys must come in increasing order.",
                )
            }
            self.previous_leaf.replace(LeafNode::new(
                hashed_key,
                value_hash,
                (key.clone(), self.version),
            ));
            self.add_one(key, value_hash);
            self.num_keys_received += 1;
        }

        // Verify what we have added so far is all correct.
        self.verify(proof)?;

```

**File:** storage/backup/backup-cli/src/coordinators/restore.rs (L247-259)
```rust
                StateSnapshotRestoreController::new(
                    StateSnapshotRestoreOpt {
                        manifest_handle: kv_snapshot.manifest,
                        version: kv_snapshot.version,
                        validate_modules: false,
                        restore_mode: StateSnapshotRestoreMode::KvOnly,
                    },
                    self.global_opt.clone(),
                    Arc::clone(&self.storage),
                    epoch_history.clone(),
                )
                .run()
                .await?;
```
