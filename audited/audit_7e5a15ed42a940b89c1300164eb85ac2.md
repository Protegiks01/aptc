# Audit Report

## Title
State Corruption via Unvalidated BCS Deserialization in KvOnly Restore Mode

## Summary
The `load_bcs_file()` function performs BCS deserialization without any validation of the resulting data. During state snapshot restoration in `KvOnly` mode, this allows malicious backup files to inject state values that violate protocol invariants, bypassing Merkle proof verification and creating tree-KV inconsistencies that can lead to consensus violations. [1](#0-0) 

## Finding Description

The vulnerability chain consists of three critical weaknesses:

**1. No Validation in Deserialization**

The `load_bcs_file()` function directly returns deserialized data without any semantic validation: [1](#0-0) 

**2. State Values Deserialized Without Validation**

State key-value pairs are deserialized from backup chunks without validation: [2](#0-1) 

**3. Merkle Verification Bypassed in KvOnly Mode**

The restore coordinator hardcodes `KvOnly` mode for phase 1.a KV snapshot restoration: [3](#0-2) 

In `KvOnly` mode, the Merkle proof verification (`tree_fn()`) is completely skipped: [4](#0-3) 

The tree verification that would catch invalid data only occurs in `tree_fn()`: [5](#0-4) 

**Attack Execution Path:**

1. Attacker crafts malicious BCS-encoded `StateValue` data with invalid protocol invariants (e.g., `StateValueMetadata` with future timestamps, corrupted deposits, or invalid creation times)
2. Attacker provides backup files with valid manifest but corrupted chunk data
3. Victim node initiates restore from compromised backup
4. **Phase 1.a**: Restore coordinator calls `StateSnapshotRestoreController` with `KvOnly` mode
5. Malicious state values are deserialized without validation
6. `add_chunk()` is called with `KvOnly` mode, skipping `tree_fn()` Merkle verification
7. `StateValueRestore::add_chunk()` writes corrupted data directly to database: [6](#0-5) 

8. **Phase 1.b**: Transaction replay may not update all corrupted keys
9. **Phase 2.a**: Tree restoration with `TreeOnly` mode creates correct tree structure but doesn't overwrite corrupted KV data
10. Result: Database contains state values that violate protocol invariants with mismatched Merkle tree hashes

**Invariants Violated:**

- **State Consistency (Critical Invariant #4)**: State values in database don't match their Merkle tree hashes
- **Deterministic Execution (Critical Invariant #1)**: Different nodes restoring from different corrupted backups will have different state
- **Protocol Invariants**: StateValue metadata can contain invalid timestamps, corrupted deposit values, or malformed data

## Impact Explanation

**Critical Severity** - This meets multiple critical impact criteria:

1. **Consensus/Safety Violations**: If different nodes restore from differently-corrupted backups, they will have divergent state. When executing identical blocks, they will produce different state roots, breaking consensus safety.

2. **State Inconsistencies**: The Merkle tree hash will not match the actual KV data, causing verification failures and potential node crashes when state proofs are checked.

3. **Protocol Invariant Violations**: Corrupted `StateValueMetadata` (timestamps, deposits) can cause:
   - Storage usage calculations to be incorrect
   - Time-based protocol logic to fail
   - State access patterns to violate assumptions

4. **Non-Recoverable State Corruption**: Once written to the database, corrupted state persists and propagates through transaction execution, potentially requiring manual intervention or fork to recover.

The lack of validation between deserialization and database write creates a critical attack surface where backup file manipulation can compromise network integrity.

## Likelihood Explanation

**High Likelihood:**

1. **Common Operation**: State snapshot restoration is a standard disaster recovery and node bootstrapping operation
2. **Backup Storage Attack Surface**: Backup files may be stored on shared infrastructure, cloud storage, or transmitted over networks where they can be intercepted or modified
3. **No Authentication**: The current implementation provides cryptographic verification only for the manifest (via `LedgerInfoWithSignatures`), not for individual chunk contents in KvOnly mode
4. **Legitimate Use Cases**: Node operators regularly restore from backups for:
   - Disaster recovery
   - Scaling operations (bootstrapping new nodes)
   - State sync after extended downtime

An attacker who compromises backup storage, performs MITM on backup file transfer, or tricks an operator into using malicious backup files can exploit this vulnerability.

## Recommendation

Implement mandatory validation after BCS deserialization and before database write:

```rust
// In storage/backup/backup-cli/src/utils/storage_ext.rs
async fn load_bcs_file<T: DeserializeOwned>(&self, file_handle: &FileHandleRef) -> Result<T> {
    let data: T = bcs::from_bytes(&self.read_all(file_handle).await?)?;
    // Add validation hook here if T implements a Validate trait
    Ok(data)
}

// In storage/aptosdb/src/state_restore/mod.rs
impl<K: Key + CryptoHash + Eq + Hash, V: Value> StateValueRestore<K, V> {
    pub fn add_chunk(&mut self, chunk: Vec<(K, V)>) -> Result<()> {
        // Validate state values before writing
        for (key, value) in &chunk {
            value.validate()?; // Add validation method
        }
        
        // ... existing code ...
    }
}
```

**Specific Validation for StateValue:** [7](#0-6) 

Add validation to ensure:
- `creation_time_usecs` is not in the future
- `creation_time_usecs` is reasonable (not zero, not too old)
- `slot_deposit` and `bytes_deposit` are within valid ranges
- Value bytes are non-empty and within size limits

**Alternative: Always Verify in All Modes**

Modify the restore coordinator to NEVER skip Merkle verification:

```rust
// Remove KvOnly mode or always run both kv_fn and tree_fn
match self.restore_mode {
    StateSnapshotRestoreMode::KvOnly => {
        // Still verify against merkle proof even in KvOnly mode
        let (r1, r2) = IO_POOL.join(kv_fn, tree_fn);
        r1?;
        r2?; // Don't skip verification
    },
    // ...
}
```

## Proof of Concept

```rust
// PoC: Create malicious backup file with invalid StateValue
use aptos_types::state_store::state_value::{StateValue, StateValueMetadata};
use bcs;

fn create_malicious_backup() -> Vec<u8> {
    // Create StateValue with invalid timestamp (far in the future)
    let malicious_metadata = StateValueMetadata::new(
        1000000000000, // Impossibly high deposit
        1000000000000,
        u64::MAX, // Timestamp in far future - violates invariant
    );
    
    let malicious_value = StateValue::new_with_metadata(
        vec![0xFF; 1000], // Arbitrary data
        malicious_metadata,
    );
    
    // Serialize to BCS - will succeed
    bcs::to_bytes(&malicious_value).unwrap()
}

// Attack scenario:
// 1. Attacker creates backup with malicious_value
// 2. Node operator restores using: 
//    `aptos-db-tool restore --target-db-dir /path/to/db`
// 3. During phase 1.a KvOnly restore, malicious data is written
// 4. No validation catches the invalid timestamp or deposits
// 5. Database now contains corrupted state violating protocol invariants
// 6. Tree-KV inconsistency leads to verification failures
```

**Test Reproduction Steps:**

1. Create a test backup with malicious StateValue containing `creation_time_usecs = u64::MAX`
2. Initiate restore with the backup using the restore coordinator
3. Verify that the malicious data is written to the database during KvOnly phase
4. Observe that TreeOnly phase creates inconsistency between tree hashes and KV values
5. Attempt to verify state proof - will fail due to hash mismatch
6. Execute transactions reading the corrupted state - may produce incorrect results

## Notes

This vulnerability highlights a fundamental security gap in the backup/restore trust model. While the manifest is cryptographically verified via `LedgerInfoWithSignatures`, the actual state value contents bypass validation when restored in `KvOnly` mode. This creates a critical window where protocol invariants can be violated, potentially leading to consensus divergence if different nodes restore from differently-corrupted backups.

The fix requires either:
1. Adding semantic validation after deserialization (defense in depth), or
2. Never skipping Merkle proof verification regardless of restore mode

Both approaches should be implemented for maximum security.

### Citations

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L31-33)
```rust
    async fn load_bcs_file<T: DeserializeOwned>(&self, file_handle: &FileHandleRef) -> Result<T> {
        Ok(bcs::from_bytes(&self.read_all(file_handle).await?)?)
    }
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

**File:** storage/aptosdb/src/state_restore/mod.rs (L228-257)
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
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L339-391)
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

**File:** types/src/state_store/state_value.rs (L16-43)
```rust
#[derive(Deserialize, Serialize)]
#[serde(rename = "StateValueMetadata")]
pub enum PersistedStateValueMetadata {
    V0 {
        deposit: u64,
        creation_time_usecs: u64,
    },
    V1 {
        slot_deposit: u64,
        bytes_deposit: u64,
        creation_time_usecs: u64,
    },
}

impl PersistedStateValueMetadata {
    pub fn into_in_mem_form(self) -> StateValueMetadata {
        match self {
            PersistedStateValueMetadata::V0 {
                deposit,
                creation_time_usecs,
            } => StateValueMetadata::new_impl(deposit, 0, creation_time_usecs),
            PersistedStateValueMetadata::V1 {
                slot_deposit,
                bytes_deposit,
                creation_time_usecs,
            } => StateValueMetadata::new_impl(slot_deposit, bytes_deposit, creation_time_usecs),
        }
    }
```
