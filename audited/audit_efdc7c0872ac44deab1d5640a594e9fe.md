# Audit Report

## Title
State Snapshot Restore Bypasses Cryptographic Validation in KvOnly Mode, Allowing Malicious Chunks from Compromised Backups

## Summary
The `StateSnapshotRestoreMode::KvOnly` mode in the state snapshot restore process skips Merkle proof validation of chunk data, allowing an attacker with compromised backup storage to inject malicious state data that gets written to the database without cryptographic verification. This breaks the State Consistency invariant and creates a vulnerable restoration path.

## Finding Description

The `run_impl()` function creates a state restore receiver using `self.restore_mode` to determine validation behavior. [1](#0-0) 

The `StateSnapshotRestoreMode` enum has three variants: `Default`, `KvOnly`, and `TreeOnly`. [2](#0-1) 

In the `StateSnapshotRestore::add_chunk()` method, when `restore_mode` is set to `KvOnly`, only the `kv_fn()` is executed, which writes key-value data directly to storage without any Merkle proof validation. [3](#0-2) 

In contrast, the `tree_fn()` path (used in `Default` and `TreeOnly` modes) calls `add_chunk_impl()` which performs cryptographic validation. [4](#0-3) 

The `add_chunk_impl()` method in `JellyfishMerkleRestore` explicitly calls `self.verify(proof)?` to cryptographically validate chunks against the expected root hash using `SparseMerkleRangeProof`. [5](#0-4) 

The verification method reconstructs the Merkle root from the chunk data and proofs, ensuring cryptographic integrity. [6](#0-5) 

However, this entire validation path is bypassed when using `KvOnly` mode, as only `kv_fn()` executes, which simply writes chunks to storage via `StateValueRestore::add_chunk()` without any cryptographic proof checks. [7](#0-6) 

**Attack Scenario:**
1. Attacker compromises backup storage or operates a malicious backup service
2. Attacker replaces chunk blob files with malicious state data while keeping manifest and proofs intact
3. The manifest's root hash is verified against the signed ledger info, so it appears legitimate [8](#0-7) 
4. When restore runs with `KvOnly` mode (either directly via CLI parameter or in coordinator's phase 1), malicious chunks are written without validation [9](#0-8) 
5. Corrupted state is persisted to the database, causing state inconsistency

The restore coordinator intentionally uses `KvOnly` mode for phase 1 KV snapshot restoration, followed by tree validation in phase 2. [10](#0-9)  However, if the KV snapshot chunks are malicious, they are accepted without validation, and subsequent transaction replay executes on corrupted base state, propagating the corruption forward.

## Impact Explanation

This vulnerability fits the **Medium Severity** category per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Specific Impacts:**
- **State Corruption**: Malicious state data written to database without cryptographic validation
- **Consensus Failure**: When the node processes blocks post-restore, incorrect state roots are computed, causing consensus verification failures
- **Node Inoperability**: The restored node becomes unable to participate in consensus or state synchronization
- **Manual Intervention Required**: Operators must manually identify the corruption and restore from a trusted backup source
- **Trust Model Violation**: The backup storage is treated as partially untrusted (evidenced by signature verification on ledger infos), yet chunk data validation is skipped in KvOnly mode

While this doesn't directly enable fund theft or permanent consensus breaks network-wide, it creates a significant availability and integrity issue for operators restoring from potentially compromised backups.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability is exploitable when:
1. **Backup storage is compromised** - Realistic for cloud storage misconfigurations, supply chain attacks on backup services, or insider threats
2. **KvOnly mode is used** - Occurs in two scenarios:
   - Operator manually specifies `--restore-mode kv_only` flag (less common)
   - Coordinator automatically uses it in phase 1 multi-phase restore (common for incremental restores)
3. **Detection is delayed** - The corruption isn't detected during restore, only at runtime when processing blocks

**Factors increasing likelihood:**
- The restore coordinator uses KvOnly mode by design for performance optimization
- Backup storage may be hosted on third-party infrastructure (AWS, GCP, etc.)
- No runtime warning that validation is being skipped in KvOnly mode
- The restore process completes successfully despite accepting malicious chunks

**Factors decreasing likelihood:**
- Requires attacker to have write access to backup storage
- Manifest signatures provide some defense in depth
- Detection eventually occurs at runtime, limiting long-term damage

## Recommendation

**Fix 1: Always Validate Chunks Cryptographically**

Modify `StateSnapshotRestore::add_chunk()` to ALWAYS validate chunks against Merkle proofs, regardless of restore mode. The restore mode should only control what gets *written* (KV, tree, or both), not what gets *validated*.

```rust
// In storage/aptosdb/src/state_restore/mod.rs, modify add_chunk():
pub fn add_chunk(&mut self, chunk: Vec<(K, V)>, proof: SparseMerkleRangeProof) -> Result<()> {
    // ALWAYS validate cryptographically first
    let tree_validation = || {
        self.tree_restore
            .lock()
            .as_mut()
            .unwrap()
            .verify_chunk(chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof.clone())
    };
    tree_validation()?; // Enforce validation
    
    // Then write based on restore_mode
    match self.restore_mode {
        StateSnapshotRestoreMode::KvOnly => {
            self.kv_restore.lock().as_mut().unwrap().add_chunk(chunk)?
        },
        StateSnapshotRestoreMode::TreeOnly => {
            self.tree_restore.lock().as_mut().unwrap().add_chunk_impl(
                chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof
            )?
        },
        StateSnapshotRestoreMode::Default => {
            let kv_fn = || self.kv_restore.lock().as_mut().unwrap().add_chunk(chunk.clone());
            let tree_fn = || self.tree_restore.lock().as_mut().unwrap().add_chunk_impl(
                chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof
            );
            let (r1, r2) = IO_POOL.join(kv_fn, tree_fn);
            r1?;
            r2?;
        },
    }
    Ok(())
}
```

**Fix 2: Add Explicit Validation Check in Coordinator**

Add a verification step after phase 1 KV restore to ensure KV data consistency before proceeding to phase 2:

```rust
// After KvOnly restore in coordinator, verify KV matches expected state
if kv_snapshot.is_some() {
    verify_kv_snapshot_integrity(&db, kv_snapshot.version, kv_snapshot.root_hash)?;
}
```

**Fix 3: Add Warning/Error for Standalone KvOnly Usage**

Prevent operators from accidentally using KvOnly mode without understanding the security implications:

```rust
// In StateSnapshotRestoreController::new()
if opt.restore_mode == StateSnapshotRestoreMode::KvOnly {
    warn!("KvOnly mode skips Merkle proof validation. Use only within coordinator context.");
    // Or make it an error for standalone usage:
    // bail!("KvOnly mode is for internal coordinator use only");
}
```

## Proof of Concept

```rust
// Proof of Concept: Demonstrate that KvOnly mode accepts invalid chunks
// File: storage/aptosdb/src/state_restore/restore_test.rs

#[test]
fn test_kvonly_mode_accepts_invalid_chunks() {
    use crate::state_restore::{StateSnapshotRestore, StateSnapshotRestoreMode};
    use aptos_crypto::HashValue;
    use aptos_types::state_store::{state_key::StateKey, state_value::StateValue};
    use aptos_types::proof::SparseMerkleRangeProof;
    
    // Setup mock stores
    let tree_store = Arc::new(MockTreeStore::new());
    let value_store = Arc::new(MockValueStore::new());
    let version = 100;
    let expected_root = HashValue::random(); // Arbitrary root hash
    
    // Create restore receiver with KvOnly mode
    let mut restore = StateSnapshotRestore::new(
        &tree_store,
        &value_store,
        version,
        expected_root,
        false, // no async commit
        StateSnapshotRestoreMode::KvOnly,
    ).unwrap();
    
    // Create MALICIOUS chunk with invalid data
    let malicious_key = StateKey::raw(b"malicious_key");
    let malicious_value = StateValue::from(b"malicious_data");
    let malicious_chunk = vec![(malicious_key, malicious_value)];
    
    // Create INVALID proof (empty siblings, won't validate against expected_root)
    let invalid_proof = SparseMerkleRangeProof::new(vec![]);
    
    // In KvOnly mode, this SUCCEEDS despite invalid proof
    let result = restore.add_chunk(malicious_chunk, invalid_proof);
    assert!(result.is_ok(), "KvOnly mode accepted invalid chunk without validation!");
    
    // In Default mode, this would FAIL validation
    let mut restore_default = StateSnapshotRestore::new(
        &tree_store,
        &value_store,
        version + 1,
        expected_root,
        false,
        StateSnapshotRestoreMode::Default,
    ).unwrap();
    
    let result_default = restore_default.add_chunk(
        vec![(malicious_key, malicious_value)],
        invalid_proof,
    );
    assert!(result_default.is_err(), "Default mode should reject invalid chunk");
}

// Demonstrate real-world attack: corrupted backup chunk accepted
#[test]
fn test_corrupted_backup_chunk_accepted_in_kvonly() {
    // Simulate legitimate manifest with correct root hash
    let legitimate_root = compute_legitimate_root_hash(/* ... */);
    
    // Attacker replaces chunk file content (keeps proof file unchanged)
    let corrupted_chunk = create_corrupted_state_chunk(/* ... */);
    let original_proof = load_proof_from_backup(/* ... */);
    
    // Restore with KvOnly mode (as used by coordinator phase 1)
    let mut restore = create_restore_receiver(
        legitimate_root,
        StateSnapshotRestoreMode::KvOnly,
    );
    
    // Corrupted chunk is ACCEPTED without cryptographic validation
    let result = restore.add_chunk(corrupted_chunk, original_proof);
    assert!(result.is_ok(), "Corrupted chunk was accepted!");
    
    // Verify malicious data was written to database
    let db_value = read_from_db(/* corrupted key */);
    assert_eq!(db_value, /* corrupted value */, "Malicious data persisted to DB");
}
```

## Notes

The fundamental issue is that `StateSnapshotRestoreMode::KvOnly` is a valid, documented mode that was designed for performance optimization in multi-phase restores, but it creates a security vulnerability by skipping cryptographic validation. This is a classic tradeoff between performance and security that has tipped too far toward performance at the expense of data integrity.

The vulnerability is exacerbated by:
1. Backup storage being potentially untrusted (evidenced by cryptographic verification of manifest signatures)
2. No explicit warning that validation is being bypassed
3. Detection only occurring at runtime rather than during restore
4. The coordinator using this mode automatically, making it a common code path

This represents a violation of the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs" - the KvOnly restore path accepts state data without Merkle proof verification.

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-136)
```rust
        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L141-145)
```rust
        let receiver = Arc::new(Mutex::new(Some(self.run_mode.get_state_restore_receiver(
            self.version,
            manifest.root_hash,
            self.restore_mode,
        )?)));
```

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

**File:** storage/aptosdb/src/state_restore/mod.rs (L238-244)
```rust
        let tree_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["jmt_add_chunk"]);
            self.tree_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk_impl(chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof)
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L246-248)
```rust
        match self.restore_mode {
            StateSnapshotRestoreMode::KvOnly => kv_fn()?,
            StateSnapshotRestoreMode::TreeOnly => tree_fn()?,
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L390-391)
```rust
        // Verify what we have added so far is all correct.
        self.verify(proof)?;
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L628-697)
```rust
    fn verify(&self, proof: SparseMerkleRangeProof) -> Result<()> {
        let previous_leaf = self
            .previous_leaf
            .as_ref()
            .expect("The previous leaf must exist.");

        let previous_key = previous_leaf.account_key();
        // If we have all siblings on the path from root to `previous_key`, we should be able to
        // compute the root hash. The siblings on the right are already in the proof. Now we
        // compute the siblings on the left side, which represent all the states that have ever
        // been added.
        let mut left_siblings = vec![];

        // The following process might add some extra placeholder siblings on the left, but it is
        // nontrivial to determine when the loop should stop. So instead we just add these
        // siblings for now and get rid of them in the next step.
        let mut num_visited_right_siblings = 0;
        for (i, bit) in previous_key.iter_bits().enumerate() {
            if bit {
                // This node is a right child and there should be a sibling on the left.
                let sibling = if i >= self.partial_nodes.len() * 4 {
                    *SPARSE_MERKLE_PLACEHOLDER_HASH
                } else {
                    Self::compute_left_sibling(
                        &self.partial_nodes[i / 4],
                        previous_key.get_nibble(i / 4),
                        (3 - i % 4) as u8,
                    )
                };
                left_siblings.push(sibling);
            } else {
                // This node is a left child and there should be a sibling on the right.
                num_visited_right_siblings += 1;
            }
        }
        ensure!(
            num_visited_right_siblings >= proof.right_siblings().len(),
            "Too many right siblings in the proof.",
        );

        // Now we remove any extra placeholder siblings at the bottom. We keep removing the last
        // sibling if 1) it's a placeholder 2) it's a sibling on the left.
        for bit in previous_key.iter_bits().rev() {
            if bit {
                if *left_siblings.last().expect("This sibling must exist.")
                    == *SPARSE_MERKLE_PLACEHOLDER_HASH
                {
                    left_siblings.pop();
                } else {
                    break;
                }
            } else if num_visited_right_siblings > proof.right_siblings().len() {
                num_visited_right_siblings -= 1;
            } else {
                break;
            }
        }

        // Left siblings must use the same ordering as the right siblings in the proof
        left_siblings.reverse();

        // Verify the proof now that we have all the siblings
        proof
            .verify(
                self.expected_root_hash,
                SparseMerkleLeafNode::new(*previous_key, previous_leaf.value_hash()),
                left_siblings,
            )
            .map_err(Into::into)
    }
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
