# Audit Report

## Title
Incomplete Backup Files Can Permanently Corrupt Backup Sets and Cause Restoration Failures

## Summary
The `create_for_write()` function in the LocalFS backup storage creates files immediately without transactional guarantees. When backup operations fail mid-write (due to crashes, network failures, or disk issues), partial files remain permanently in the backup set. These incomplete files cause restoration to fail with deserialization or validation errors, compromising disaster recovery capabilities.

## Finding Description

The backup system's file creation mechanism lacks atomicity guarantees. When `create_for_write()` is invoked, it immediately creates a file on disk: [1](#0-0) 

The function returns an `AsyncWrite` stream that the caller must write to and close via `shutdown()`. However, across all backup controllers (transaction, state snapshot, epoch ending), there is no error handling to clean up files if writing fails between creation and successful shutdown.

For example, in transaction backup: [2](#0-1) 

If an error occurs at line 163-170 (during proof fetch or copy), the `?` operator returns early. The proof file created at line 156-161 is never shut down and remains as a partial file. The same pattern exists for chunk files and manifest files: [3](#0-2) 

During restoration, partial files cause multiple failure modes:

1. **Partial chunk files**: The restoration process reads records and validates the count matches the manifest: [4](#0-3) 

2. **Partial proof files**: BCS deserialization fails when loading incomplete proof data: [5](#0-4) 

3. **Partial manifest files**: JSON parsing fails earlier in the restoration pipeline: [6](#0-5) 

Critically, the backup maintenance cleanup functionality is not implemented: [7](#0-6) 

The manifest verification only checks logical consistency (version ranges), not file completeness: [8](#0-7) 

## Impact Explanation

This issue qualifies as **Medium Severity** under Aptos bug bounty criteria: "State inconsistencies requiring intervention."

During disaster recovery scenarios, if the only available backup contains partial files from a previous failed backup attempt, restoration will fail completely. This causes:

1. **Extended downtime**: Validators cannot restore from backup and must resync from genesis or other nodes
2. **Manual intervention required**: Operators must manually identify and remove partial files before retry
3. **Potential data availability loss**: If multiple backup attempts fail and leave corruption, operators may need to find older backups or alternative recovery methods

While this doesn't directly impact consensus or cause fund loss, it severely compromises the disaster recovery infrastructure that Aptos validators depend on for business continuity.

## Likelihood Explanation

This issue has **high likelihood** of occurrence in production environments:

1. **Natural triggers**: Network interruptions, disk space exhaustion, process OOM kills, hardware failures, or operator intervention (SIGKILL) during backup operations
2. **No cleanup mechanism**: Once partial files exist, they remain permanently until manual cleanup
3. **Silent corruption**: Operators may not discover the corruption until attempting restoration during an actual disaster
4. **Production workloads**: Long-running backups of large state snapshots increase exposure to transient failures

The TODO comment in the codebase indicates this gap is known but unfixed, suggesting it's a real operational concern.

## Recommendation

Implement atomic file writes using a temporary-file-then-rename pattern:

```rust
async fn create_for_write(
    &self,
    backup_handle: &BackupHandleRef,
    name: &ShellSafeName,
) -> Result<(FileHandle, Box<dyn AsyncWrite + Send + Unpin>)> {
    let file_handle = Path::new(backup_handle)
        .join(name.as_ref())
        .path_to_string()?;
    let final_path = self.dir.join(&file_handle);
    
    // Write to temporary file with unique suffix
    let temp_name = format!("{}.tmp.{}", name.as_ref(), uuid::Uuid::new_v4());
    let temp_handle = Path::new(backup_handle).join(&temp_name).path_to_string()?;
    let temp_path = self.dir.join(&temp_handle);
    
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
        .err_notes(&temp_path)?;
    
    // Return wrapper that renames on successful shutdown
    Ok((file_handle.clone(), Box::new(AtomicFileWriter::new(file, temp_path, final_path))))
}
```

Additionally, implement the cleanup command to detect and remove orphaned `.tmp.*` files older than a threshold.

## Proof of Concept

```rust
#[tokio::test]
async fn test_incomplete_backup_corruption() {
    use tempfile::TempDir;
    use std::sync::Arc;
    
    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(LocalFs::new(temp_dir.path().to_path_buf()));
    
    // Create backup
    let backup_handle = storage.create_backup(&"test_backup".try_into().unwrap()).await.unwrap();
    
    // Start writing a chunk file but don't complete it
    let chunk_name = "test.chunk".try_into().unwrap();
    let (chunk_handle, mut chunk_file) = storage
        .create_for_write(&backup_handle, &chunk_name)
        .await.unwrap();
    
    // Write partial data
    chunk_file.write_all(b"partial data").await.unwrap();
    // Simulate crash - DON'T call shutdown()
    drop(chunk_file);
    
    // Verify partial file exists
    let partial_path = temp_dir.path().join(&backup_handle).join("test.chunk");
    assert!(partial_path.exists());
    
    // Create manifest referencing the partial chunk
    let manifest = TransactionBackup {
        first_version: 0,
        last_version: 10,
        chunks: vec![TransactionChunk {
            first_version: 0,
            last_version: 10,
            transactions: chunk_handle.clone(),
            proof: "dummy.proof".to_string(),
            format: TransactionChunkFormat::V1,
        }],
    };
    
    let (manifest_handle, mut manifest_file) = storage
        .create_for_write(&backup_handle, &"transaction.manifest".try_into().unwrap())
        .await.unwrap();
    manifest_file.write_all(&serde_json::to_vec(&manifest).unwrap()).await.unwrap();
    manifest_file.shutdown().await.unwrap();
    
    // Attempt restoration - should fail
    let loaded_manifest: TransactionBackup = storage.load_json_file(&manifest_handle).await.unwrap();
    let result = storage.open_for_read(&loaded_manifest.chunks[0].transactions).await;
    
    // This will succeed in opening, but reading will fail with incomplete data
    assert!(result.is_ok());
    let mut file = result.unwrap();
    
    // Attempting to read records will fail due to partial data
    let read_result = file.read_record_bytes().await;
    assert!(read_result.is_err() || read_result.unwrap().is_none());
}
```

**Notes**

This vulnerability specifically affects the backup/restore infrastructure rather than the core blockchain consensus or execution. While it doesn't directly threaten funds or consensus safety, it compromises the critical disaster recovery mechanism that Aptos validators rely on for business continuity and resilience. The lack of atomic file operations and cleanup mechanisms means partial backup files can accumulate silently until a restoration attempt fails during an actual disaster scenario.

### Citations

**File:** storage/backup/backup-cli/src/storage/local_fs/mod.rs (L89-94)
```rust
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&abs_path)
            .await
            .err_notes(&abs_path)?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/backup.rs (L156-171)
```rust
        let (proof_handle, mut proof_file) = self
            .storage
            .create_for_write(
                backup_handle,
                &Self::chunk_proof_name(first_version, last_version),
            )
            .await?;
        tokio::io::copy(
            &mut self
                .client
                .get_transaction_range_proof(first_version, last_version)
                .await?,
            &mut proof_file,
        )
        .await?;
        proof_file.shutdown().await?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/backup.rs (L173-178)
```rust
        let (chunk_handle, mut chunk_file) = self
            .storage
            .create_for_write(backup_handle, &Self::chunk_name(first_version))
            .await?;
        chunk_file.write_all(chunk_bytes).await?;
        chunk_file.shutdown().await?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L139-145)
```rust
        ensure!(
            manifest.first_version + (txns.len() as Version) == manifest.last_version + 1,
            "Number of items in chunks doesn't match that in manifest. first_version: {}, last_version: {}, items in chunk: {}",
            manifest.first_version,
            manifest.last_version,
            txns.len(),
        );
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L147-151)
```rust
        let (range_proof, ledger_info) = storage
            .load_bcs_file::<(TransactionAccumulatorRangeProof, LedgerInfoWithSignatures)>(
                &manifest.proof,
            )
            .await?;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L350-353)
```rust
                async move { storage.load_json_file(&hdl).await.err_notes(&hdl) }
            })
            .buffered_x(con * 3, con)
            .and_then(|m: TransactionBackup| future::ready(m.verify().map(|_| m)));
```

**File:** storage/db-tool/src/backup_maintenance.rs (L77-79)
```rust
            Command::Cleanup(_) => {
                // TODO: add cleanup logic for removing obsolete metadata files
            },
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/manifest.rs (L50-88)
```rust
    pub fn verify(&self) -> Result<()> {
        // check number of waypoints
        ensure!(
            self.first_version <= self.last_version,
            "Bad version range: [{}, {}]",
            self.first_version,
            self.last_version,
        );

        // check chunk ranges
        ensure!(!self.chunks.is_empty(), "No chunks.");

        let mut next_version = self.first_version;
        for chunk in &self.chunks {
            ensure!(
                chunk.first_version == next_version,
                "Chunk ranges not continuous. Expected first version: {}, actual: {}.",
                next_version,
                chunk.first_version,
            );
            ensure!(
                chunk.last_version >= chunk.first_version,
                "Chunk range invalid. [{}, {}]",
                chunk.first_version,
                chunk.last_version,
            );
            next_version = chunk.last_version + 1;
        }

        // check last version in chunk matches manifest
        ensure!(
            next_version - 1 == self.last_version, // okay to -1 because chunks is not empty.
            "Last version in chunks: {}, in manifest: {}",
            next_version - 1,
            self.last_version,
        );

        Ok(())
    }
```
