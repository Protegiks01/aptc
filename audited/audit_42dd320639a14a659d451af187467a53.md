# Audit Report

## Title
Unbounded Memory Allocation in Epoch Ending Backup Restore Causes Out-of-Memory Denial of Service

## Summary
The `read_chunk()` function in the epoch ending restore process loads all deserialized `LedgerInfoWithSignatures` records from backup chunk files into memory without enforcing size limits. An attacker who can provide malicious backup files (through backup storage compromise, social engineering, or as a malicious backup provider) can trigger out-of-memory conditions and crash the restore process, preventing disaster recovery.

## Finding Description

The epoch ending restore process has an unbounded memory allocation vulnerability. During backup creation, chunk files are limited to 128MB through the `should_cut_chunk()` validation function. [1](#0-0) 

However, during restore operations, the `read_chunk()` function reads all records from chunk files without validating their size: [2](#0-1) 

The function reads records in a loop using `read_record_bytes()`, which can read individual records up to 4GB each (u32::MAX bytes), and pushes all deserialized `LedgerInfoWithSignatures` into a Vec without any limits on the number of records or total memory consumption.

The underlying record reading mechanism allocates memory based on the record size prefix without bounds checking: [3](#0-2) 

**Attack Path:**

1. Attacker gains access to backup storage through compromise, or acts as a malicious backup service provider
2. Attacker creates a malicious epoch ending chunk file containing either:
   - Millions of `LedgerInfoWithSignatures` records (e.g., 10 million records × ~2KB each = 20GB), OR
   - Large individual records (approaching the 4GB u32 limit)
3. Attacker modifies the manifest file to reference the malicious chunk with appropriate epoch ranges
4. When a node operator runs restore (via `aptos-db-tool restore bootstrap-db` or similar commands), the `EpochEndingRestoreController` loads the manifest
5. The manifest passes basic validation checks [4](#0-3)  since it only validates epoch ranges, not chunk sizes
6. `read_chunk()` is called and loads all records into memory, causing OOM
7. The restore process crashes before cryptographic validation of the ledger infos occurs

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The restore process should enforce the same 128MB chunk size limit that backup creation uses.

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:
- **"Validator node slowdowns"**: The OOM condition will cause the restore process to become unresponsive and eventually crash
- **"API crashes"**: The backup-cli tool will crash during restore operations

The impact extends beyond simple crashes:
- **Prevents disaster recovery**: Operators cannot restore nodes from compromised backups, which is critical after incidents
- **Supply chain risk**: Third-party backup service providers could inject malicious backups
- **Delayed network recovery**: If multiple operators use the same compromised backup source, network recovery after a major incident could be significantly delayed

While this doesn't directly attack the running network, it compromises the resilience and disaster recovery capabilities of the Aptos blockchain infrastructure.

## Likelihood Explanation

**Likelihood: Medium**

The attack requires the attacker to provide malicious backup files, which can occur through:

1. **Backup storage compromise**: Attackers who gain access to cloud storage (S3, GCS) or local filesystem where backups are stored can modify chunk files
2. **Supply chain attacks**: Malicious or compromised third-party backup service providers could inject malicious backups
3. **Social engineering**: Operators could be tricked into using malicious backup sources during emergency recovery scenarios
4. **Insider threats**: Malicious insiders with backup storage access

While this requires more than just network access, backup infrastructure typically has weaker security than production validator nodes, making compromise realistic. The Aptos backup system supports both local filesystem and cloud storage backends through command adapters, expanding the attack surface. [5](#0-4) 

## Recommendation

Implement chunk size validation during restore operations to match the limits enforced during backup creation. The fix should:

1. **Add size tracking in `read_chunk()`**: Track cumulative bytes read and fail if exceeding `max_chunk_size` (128MB default)
2. **Enforce record count limits**: Consider adding a maximum record count per chunk (e.g., based on typical epoch ending sizes)
3. **Validate before deserialization**: Check record byte sizes before deserializing to prevent wasting resources on malicious data

**Recommended Code Fix:**

```rust
async fn read_chunk(
    &self,
    file_handle: &FileHandleRef,
) -> Result<Vec<LedgerInfoWithSignatures>> {
    const MAX_CHUNK_SIZE: usize = 134217728; // 128MB - should match GlobalBackupOpt default
    const MAX_RECORDS_PER_CHUNK: usize = 100000; // Reasonable upper bound
    
    let mut file = self.storage.open_for_read(file_handle).await?;
    let mut chunk = vec![];
    let mut total_bytes = 0usize;

    while let Some(record_bytes) = file.read_record_bytes().await? {
        ensure!(
            chunk.len() < MAX_RECORDS_PER_CHUNK,
            "Chunk exceeds maximum record count: {} > {}",
            chunk.len(),
            MAX_RECORDS_PER_CHUNK
        );
        
        total_bytes = total_bytes.checked_add(record_bytes.len())
            .ok_or_else(|| anyhow!("Total chunk size overflow"))?;
            
        ensure!(
            total_bytes <= MAX_CHUNK_SIZE,
            "Chunk exceeds maximum size: {} > {} bytes",
            total_bytes,
            MAX_CHUNK_SIZE
        );
        
        chunk.push(bcs::from_bytes(&record_bytes)?);
    }

    Ok(chunk)
}
```

Similar fixes should be applied to transaction and state snapshot restore functions which have identical patterns. [6](#0-5) 

## Proof of Concept

```rust
#[tokio::test]
async fn test_malicious_chunk_oom_attack() {
    use aptos_temppath::TempPath;
    use std::fs::File;
    use std::io::Write;
    use aptos_types::ledger_info::LedgerInfoWithSignatures;
    
    // Create a temporary directory for malicious backup
    let tmpdir = TempPath::new();
    let storage = Arc::new(LocalFs::new(tmpdir.path().to_path_buf()));
    
    // Create a malicious chunk file with excessive records
    let backup_handle = storage.create_backup("test_backup").await.unwrap();
    let chunk_handle = storage.create_for_write(&backup_handle, "chunk.data").await.unwrap();
    
    // Write millions of records (each ~2KB) to exhaust memory
    // In a real attack, this would be 10+ million records
    for _ in 0..1_000_000 {
        let li = create_mock_ledger_info(); // Create realistic LedgerInfoWithSignatures
        let serialized = bcs::to_bytes(&li).unwrap();
        let size_prefix = (serialized.len() as u32).to_be_bytes();
        chunk_handle.write_all(&size_prefix).await.unwrap();
        chunk_handle.write_all(&serialized).await.unwrap();
    }
    
    // Create manifest pointing to malicious chunk
    let manifest = EpochEndingBackup {
        first_epoch: 0,
        last_epoch: 999999,
        waypoints: vec![/* matching waypoints */],
        chunks: vec![EpochEndingChunk {
            first_epoch: 0,
            last_epoch: 999999,
            ledger_infos: chunk_handle,
        }],
    };
    
    // Attempt restore - this will cause OOM and crash
    let controller = EpochEndingRestoreController::new(
        EpochEndingRestoreOpt { manifest_handle },
        global_opt,
        storage,
    );
    
    // This should panic with OOM before completing
    let result = controller.run(None).await;
    assert!(result.is_err()); // In fixed version, should fail gracefully with size limit error
}
```

**Notes:**

This vulnerability also affects transaction restore (`LoadedChunk::load`) and potentially state snapshot restore, which use the same unbounded reading pattern. A comprehensive fix should address all backup restore operations. The validation should occur during the `read_chunk()` phase before expensive deserialization and cryptographic verification operations.

### Citations

**File:** storage/backup/backup-cli/src/utils/mod.rs (L411-413)
```rust
pub(crate) fn should_cut_chunk(chunk: &[u8], record: &[u8], max_chunk_size: usize) -> bool {
    !chunk.is_empty() && chunk.len() + record.len() + size_of::<u32>() > max_chunk_size
}
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/restore.rs (L160-172)
```rust
    async fn read_chunk(
        &self,
        file_handle: &FileHandleRef,
    ) -> Result<Vec<LedgerInfoWithSignatures>> {
        let mut file = self.storage.open_for_read(file_handle).await?;
        let mut chunk = vec![];

        while let Some(record_bytes) = file.read_record_bytes().await? {
            chunk.push(bcs::from_bytes(&record_bytes)?);
        }

        Ok(chunk)
    }
```

**File:** storage/backup/backup-cli/src/utils/read_record_bytes.rs (L54-66)
```rust
        let record_size = u32::from_be_bytes(size_buf.as_ref().try_into()?) as usize;
        if record_size == 0 {
            return Ok(Some(Bytes::new()));
        }

        // read record
        let mut record_buf = BytesMut::with_capacity(record_size);
        self.read_full_buf_or_none(&mut record_buf).await?;
        if record_buf.is_empty() {
            bail!("Hit EOF when reading record.")
        }

        Ok(Some(record_buf.freeze()))
```

**File:** storage/backup/backup-cli/src/backup_types/epoch_ending/manifest.rs (L28-68)
```rust
impl EpochEndingBackup {
    pub fn verify(&self) -> Result<()> {
        // check number of waypoints
        ensure!(
            self.first_epoch <= self.last_epoch
                && self.last_epoch - self.first_epoch + 1 == self.waypoints.len() as u64,
            "Malformed manifest. first epoch: {}, last epoch {}, num waypoints {}",
            self.first_epoch,
            self.last_epoch,
            self.waypoints.len(),
        );

        // check chunk ranges
        ensure!(!self.chunks.is_empty(), "No chunks.");
        let mut next_epoch = self.first_epoch;
        for chunk in &self.chunks {
            ensure!(
                chunk.first_epoch == next_epoch,
                "Chunk ranges not continuous. Expected first epoch: {}, actual: {}.",
                next_epoch,
                chunk.first_epoch,
            );
            ensure!(
                chunk.last_epoch >= chunk.first_epoch,
                "Chunk range invalid. [{}, {}]",
                chunk.first_epoch,
                chunk.last_epoch,
            );
            next_epoch = chunk.last_epoch + 1;
        }

        // check last epoch in chunk matches manifest
        ensure!(
            next_epoch - 1 == self.last_epoch, // okay to -1 because chunks is not empty.
            "Last epoch in chunks: {}, in manifest: {}",
            next_epoch - 1,
            self.last_epoch,
        );

        Ok(())
    }
```

**File:** storage/backup/backup-cli/src/storage/mod.rs (L28-41)
```rust
/// String returned by a specific storage implementation to identify a backup, probably a folder name
/// which is exactly the same with the backup name we pass into `create_backup()`
/// This is created and returned by the storage when `create_backup()`, passed back to the storage
/// when `create_for_write()` and persisted nowhere (once a backup is created, files are referred to
/// by `FileHandle`s).
pub type BackupHandle = String;
pub type BackupHandleRef = str;

/// URI pointing to a file in a backup storage, like "s3:///bucket/path/file".
/// These are created by the storage when `create_for_write()`, stored in manifests by the backup
/// controller, and passed back to the storage when `open_for_read()` by the restore controller
/// to retrieve a file referred to in the manifest.
pub type FileHandle = String;
pub type FileHandleRef = str;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L100-137)
```rust
    async fn load(
        manifest: TransactionChunk,
        storage: &Arc<dyn BackupStorage>,
        epoch_history: Option<&Arc<EpochHistory>>,
    ) -> Result<Self> {
        let mut file = BufReader::new(storage.open_for_read(&manifest.transactions).await?);
        let mut txns = Vec::new();
        let mut persisted_aux_info = Vec::new();
        let mut txn_infos = Vec::new();
        let mut event_vecs = Vec::new();
        let mut write_sets = Vec::new();

        while let Some(record_bytes) = file.read_record_bytes().await? {
            let (txn, aux_info, txn_info, events, write_set): (
                _,
                PersistedAuxiliaryInfo,
                _,
                _,
                WriteSet,
            ) = match manifest.format {
                TransactionChunkFormat::V0 => {
                    let (txn, txn_info, events, write_set) = bcs::from_bytes(&record_bytes)?;
                    (
                        txn,
                        PersistedAuxiliaryInfo::None,
                        txn_info,
                        events,
                        write_set,
                    )
                },
                TransactionChunkFormat::V1 => bcs::from_bytes(&record_bytes)?,
            };
            txns.push(txn);
            persisted_aux_info.push(aux_info);
            txn_infos.push(txn_info);
            event_vecs.push(events);
            write_sets.push(write_set);
        }
```
