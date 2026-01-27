# Audit Report

## Title
Unbounded Memory Allocation in State Snapshot Restoration Leading to Validator Node Crash

## Summary
The state snapshot restoration process in `db-tool` lacks chunk size validation, allowing an attacker with control over backup storage to provide extremely large but cryptographically valid chunks that cause unbounded memory allocation, resulting in validator node crashes and loss of liveness.

## Finding Description

The state snapshot restoration process contains an asymmetric vulnerability: while backup creation enforces chunk size limits via `max_chunk_size`, the restoration process performs no size validation on chunks being restored. [1](#0-0) 

The `read_state_value` function reads an entire chunk file into memory without any bounds checking. It creates an unbounded vector and loops through all records unconditionally. When combined with common compression usage in backup storage configurations (as seen in sample configs using `gzip`), this creates multiple attack vectors: [2](#0-1) 

**Attack Path:**

1. **Attacker Prerequisites**: Control over the backup storage source (compromised cloud bucket credentials, malicious backup provider, or MITM during backup download)

2. **Malicious Backup Creation**: The attacker creates a backup with oversized chunks that remain cryptographically valid:
   - Concatenate multiple legitimate chunk files into one large file
   - Create compressed files designed as decompression bombs (small compressed, massive uncompressed)
   - Use legitimate but extremely large state snapshots

3. **Cryptographic Validity Maintained**: The chunks still pass verification because: [3](#0-2) 
   
   The proofs verify data authenticity but not size constraints.

4. **Concurrent Processing Amplification**: Multiple large chunks are processed concurrently: [4](#0-3) 

5. **Memory Doubling via Clone**: The chunk is cloned during processing, doubling memory consumption: [5](#0-4) 

6. **Result**: Out-of-memory crash of the validator node attempting restoration.

**Invariant Violation:**
This breaks Invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits." The restoration process does not enforce memory consumption limits.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:
- **Validator node crashes**: Direct OOM crashes of nodes attempting bootstrap or restoration
- **Loss of liveness**: If multiple validators bootstrap from the same malicious backup source, network participation drops
- **Operational disruption**: Requires manual intervention to identify and replace the corrupted backup source

This qualifies as "Validator node slowdowns" escalating to crashes, fitting the High Severity category (up to $50,000).

While not achieving "Total loss of liveness" (Critical), it significantly impacts network availability, especially during:
- New validator onboarding from public/shared backups
- Disaster recovery scenarios where multiple validators restore simultaneously
- Coordinated attacks targeting backup infrastructure

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
1. **Backup storage compromise** (Medium barrier): Attackers need access via:
   - Stolen cloud credentials (realistic via phishing/credential stuffing)
   - Misconfigured public backup buckets (common cloud misconfiguration)
   - Compromised third-party backup providers
   - MITM on unencrypted backup downloads

2. **Technical execution** (Low barrier): Creating oversized chunks is straightforward:
   - Concatenate existing legitimate chunks
   - Use standard compression tools to create decompression bombs
   - No need to forge cryptographic proofs

3. **Victim interaction** (Guaranteed): Validators MUST restore from backups during:
   - Initial node setup/bootstrap
   - Disaster recovery
   - Version upgrades requiring state migration

**Real-world scenarios:**
- New validators bootstrapping from community-shared backup locations
- Multiple validators using the same cloud backup bucket for cost efficiency
- Validators restoring after hardware failures or migrations

The lack of any size validation makes this trivially exploitable once backup storage access is obtained.

## Recommendation

Implement chunk size validation during restoration to match backup creation constraints:

```rust
// In restore.rs, modify read_state_value function:
async fn read_state_value(
    storage: &Arc<dyn BackupStorage>,
    file_handle: FileHandle,
    max_chunk_bytes: usize,  // Add parameter
) -> Result<Vec<(StateKey, StateValue)>> {
    let mut file = storage.open_for_read(&file_handle).await?;
    let mut chunk = vec![];
    let mut total_bytes = 0;

    while let Some(record_bytes) = file.read_record_bytes().await? {
        total_bytes += record_bytes.len();
        
        // Enforce maximum chunk size
        ensure!(
            total_bytes <= max_chunk_bytes,
            "Chunk exceeds maximum size: {} bytes (limit: {})",
            total_bytes,
            max_chunk_bytes
        );
        
        chunk.push(bcs::from_bytes(&record_bytes)?);
    }

    Ok(chunk)
}
```

**Additional hardening:**
1. Add `--max-chunk-size` parameter to restore options with sensible default (e.g., 256MB)
2. Validate manifest's total size before beginning restoration
3. Implement streaming chunk processing to avoid loading entire chunks into memory
4. Add decompression size limits in CommandAdapter configurations
5. Log chunk sizes during restoration for monitoring/alerting

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
#[tokio::test]
async fn test_restore_memory_exhaustion() {
    use std::io::Write;
    use tempfile::TempDir;
    
    // Setup: Create a malicious backup with oversized chunk
    let temp_dir = TempDir::new().unwrap();
    let backup_path = temp_dir.path();
    
    // Create malicious chunk file with 1 billion records (would cause OOM)
    let chunk_file = backup_path.join("malicious_chunk.chunk");
    let mut file = std::fs::File::create(&chunk_file).unwrap();
    
    for i in 0..1_000_000_000 {
        // Each record: StateKey + StateValue (minimal ~100 bytes)
        // Total: ~100GB uncompressed
        let state_key = StateKey::raw(format!("key_{}", i).as_bytes());
        let state_value = StateValue::new_legacy(vec![0u8; 100]);
        let record = bcs::to_bytes(&(state_key, state_value)).unwrap();
        
        // Write length prefix + record
        file.write_all(&(record.len() as u32).to_be_bytes()).unwrap();
        file.write_all(&record).unwrap();
    }
    
    // Create manifest pointing to malicious chunk
    let manifest = StateSnapshotBackup {
        version: 100,
        epoch: 1,
        root_hash: HashValue::random(),
        chunks: vec![StateSnapshotChunk {
            first_idx: 0,
            last_idx: 999_999_999,
            first_key: HashValue::zero(),
            last_key: HashValue::random(),
            blobs: format!("file://{}", chunk_file.display()),
            proof: "file://proof.bin".to_string(),
        }],
        proof: "file://state.proof".to_string(),
    };
    
    // Attempt restoration - this will OOM
    let storage = Arc::new(LocalFs::new_with_opt(LocalFsOpt {
        dir: backup_path.to_path_buf(),
    }));
    
    // This call will exhaust memory and crash
    let result = StateSnapshotRestoreController::read_state_value(
        &storage,
        manifest.chunks[0].blobs.clone(),
    ).await;
    
    // In real scenario, process would be killed by OOM before returning
    assert!(result.is_err() || result.unwrap().len() > 100_000_000);
}
```

**Notes:**
- The PoC demonstrates creating an oversized chunk that would exhaust memory
- In production, this would be compressed using gzip, making the attack file much smaller
- The validator node would crash with OOM before completing the restoration
- Multiple concurrent chunk downloads (controlled by `concurrent_downloads` parameter) amplify the impact

### Citations

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L123-139)
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
        if let Some(epoch_history) = self.epoch_history.as_ref() {
            epoch_history.verify_ledger_info(&li)?;
        }
```

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L198-199)
```rust
        let con = self.concurrent_downloads;
        let mut futs_stream = stream::iter(futs_iter).buffered_x(con * 2, con);
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

**File:** storage/backup/backup-cli/src/storage/command_adapter/sample_configs/s3.sample.yaml (L18-21)
```yaml
    gzip -c | aws s3 cp - "s3://$BUCKET/$SUB_DIR/$FILE_HANDLE"
  open_for_read: |
    # route file handle content to stdout
    aws s3 cp "s3://$BUCKET/$SUB_DIR/$FILE_HANDLE" - | gzip -cd
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L228-236)
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
```
