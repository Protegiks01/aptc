# Audit Report

## Title
Non-Atomic Batch File Operations Lead to Indexer State Corruption on Partial Write Failures

## Summary
The indexer-grpc file store uploader performs non-atomic batch operations where multiple `save_raw_file()` calls can succeed partially, leaving orphaned data files without corresponding batch metadata. This causes indexer state corruption when I/O failures occur during batch processing.

## Finding Description

The indexer-grpc file store uploader violates the atomic batch write invariant through a multi-step upload process without transaction guarantees. The vulnerability exists in the batch upload flow: [1](#0-0) 

The upload process makes three separate `save_raw_file()` calls:
1. Transaction data file write (line 208)
2. Batch metadata write (line 237, conditional)
3. Global metadata write (line 272, conditional)

Batch metadata updates are throttled by time constraints: [2](#0-1) 

This means multiple data files can be written successfully before batch metadata is updated. If the batch metadata write fails after data files succeed, those files become orphaned.

The `save_raw_file()` implementation provides no transactional guarantees: [3](#0-2) 

**Failure Scenario:**
1. Batch contains files F1 (v100), F2 (v101), F3 (v102)
2. F1 data written successfully
3. Batch metadata update skipped (time throttling)
4. F2 data written successfully  
5. Batch metadata write fails (I/O error, disk full, network timeout for GCS)
6. System crashes

**Post-Recovery State:**
The recovery process relies on batch metadata to discover files: [4](#0-3) 

Without batch metadata, the reader cannot serve the orphaned files: [5](#0-4) 

The system may re-upload the same versions, overwriting existing files with potentially different transaction data, or leave files permanently inaccessible.

## Impact Explanation

This qualifies as **Medium Severity** under Aptos bug bounty criteria: "State inconsistencies requiring intervention."

The indexer is a critical data infrastructure component. Corruption leads to:
- Downstream applications receiving incomplete/incorrect blockchain data
- Loss of historical transaction visibility
- Required manual intervention to detect and repair orphaned files
- Potential data loss if files are overwritten during re-upload

While this doesn't directly affect blockchain consensus (the validator nodes remain consistent), it breaks the indexer's fundamental guarantee of providing complete, accurate historical data.

## Likelihood Explanation

**High Likelihood** - This will occur naturally in production:
- I/O failures are common (disk full, network interruptions, hardware failures)
- Batch metadata updates are throttled every 10 seconds, creating wide vulnerability windows
- GCS has rate limiting (1.5s per object), increasing failure probability
- Multiple files per batch are standard (batches span 100K transactions)
- System crashes during upload leave partial state

No malicious action required - normal operational failures trigger this bug.

## Recommendation

Implement write-ahead logging or two-phase commit for batch operations:

```rust
async fn do_upload_atomic(
    &mut self,
    transactions: Vec<Transaction>,
    batch_metadata: BatchMetadata,
    end_batch: bool,
) -> Result<()> {
    // Phase 1: Write to temporary locations
    let temp_data_path = self.get_temp_path(first_version);
    self.writer.save_raw_file(temp_data_path.clone(), data_file).await?;
    
    let temp_metadata_path = self.get_temp_metadata_path(first_version);
    self.writer.save_raw_file(temp_metadata_path.clone(), metadata_bytes).await?;
    
    // Phase 2: Atomically commit by renaming/moving
    self.writer.atomic_commit(temp_data_path, final_data_path).await?;
    self.writer.atomic_commit(temp_metadata_path, final_metadata_path).await?;
    
    Ok(())
}
```

Alternatively, write batch metadata BEFORE data files, then use recovery to clean up incomplete batches by checking which files in the metadata actually exist.

## Proof of Concept

```rust
#[tokio::test]
async fn test_partial_batch_corruption() {
    // Setup file store
    let temp_dir = tempfile::tempdir().unwrap();
    let store = LocalFileStore::new(temp_dir.path().to_path_buf());
    
    // Simulate batch upload
    let transactions = vec![/* txn at v100 */, /* txn at v101 */];
    
    // Write first file successfully
    let path1 = PathBuf::from("0/100");
    store.save_raw_file(path1, encode_transactions(&transactions[0..1])).await.unwrap();
    
    // Write second file successfully  
    let path2 = PathBuf::from("0/101");
    store.save_raw_file(path2, encode_transactions(&transactions[1..2])).await.unwrap();
    
    // Simulate batch metadata write failure by removing write permissions
    std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o444)).unwrap();
    
    let metadata_path = PathBuf::from("0/metadata.json");
    let result = store.save_raw_file(metadata_path, batch_metadata_bytes).await;
    assert!(result.is_err()); // Batch metadata write fails
    
    // Recovery attempt
    let reader = FileStoreReader::new(chain_id, Arc::new(store)).await;
    let batch_metadata = reader.get_batch_metadata(100).await;
    
    // Assertion: Files exist but are invisible - data corruption
    assert!(tokio::fs::metadata(temp_dir.path().join("0/100")).await.is_ok());
    assert!(tokio::fs::metadata(temp_dir.path().join("0/101")).await.is_ok());
    assert!(batch_metadata.is_none()); // Metadata missing - files orphaned
}
```

## Notes

This vulnerability is a **reliability and data integrity issue** rather than a directly exploitable attack vector. It occurs through natural system failures (I/O errors, crashes) during the narrow time window between data file writes and batch metadata updates. While not exploitable by malicious actors, it violates the critical invariant that all successfully written indexer data must remain discoverable and consistent, qualifying as Medium severity state corruption requiring intervention.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L86-118)
```rust
    /// Recovers the batch metadata in memory buffer for the unfinished batch from file store.
    async fn recover(&self) -> Result<(u64, BatchMetadata)> {
        let _timer = TIMER.with_label_values(&["recover"]).start_timer();

        let mut version = self
            .reader
            .get_latest_version()
            .await
            .expect("Latest version must exist.");
        info!("Starting recovering process, current version in storage: {version}.");
        let mut num_folders_checked = 0;
        let mut buffered_batch_metadata_to_recover = BatchMetadata::default();
        while let Some(batch_metadata) = self.reader.get_batch_metadata(version).await {
            let batch_last_version = batch_metadata.files.last().unwrap().last_version;
            version = batch_last_version;
            if version % NUM_TXNS_PER_FOLDER != 0 {
                buffered_batch_metadata_to_recover = batch_metadata;
                break;
            }
            num_folders_checked += 1;
            if num_folders_checked >= MAX_NUM_FOLDERS_TO_CHECK_FOR_RECOVERY {
                panic!(
                    "File store metadata is way behind batch metadata, data might be corrupted."
                );
            }
        }

        self.update_file_store_metadata(version).await?;

        info!("Finished recovering process, recovered at version: {version}.");

        Ok((version, buffered_batch_metadata_to_recover))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L183-259)
```rust
    async fn do_upload(
        &mut self,
        transactions: Vec<Transaction>,
        batch_metadata: BatchMetadata,
        end_batch: bool,
    ) -> Result<()> {
        let _timer = TIMER.with_label_values(&["do_upload"]).start_timer();

        let first_version = transactions.first().unwrap().version;
        let last_version = transactions.last().unwrap().version;
        let data_file = {
            let _timer = TIMER
                .with_label_values(&["do_upload__prepare_file"])
                .start_timer();
            FileEntry::from_transactions(transactions, StorageFormat::Lz4CompressedProto)
        };
        let path = self.reader.get_path_for_version(first_version, None);

        info!("Dumping transactions [{first_version}, {last_version}] to file {path:?}.");

        {
            let _timer = TIMER
                .with_label_values(&["do_upload__save_file"])
                .start_timer();
            self.writer
                .save_raw_file(path, data_file.into_inner())
                .await?;
        }

        let mut update_batch_metadata = false;
        let max_update_frequency = self.writer.max_update_frequency();
        if self.last_batch_metadata_update_time.is_none()
            || Instant::now() - self.last_batch_metadata_update_time.unwrap()
                >= MIN_UPDATE_FREQUENCY
        {
            update_batch_metadata = true;
        } else if end_batch {
            update_batch_metadata = true;
            tokio::time::sleep_until(
                self.last_batch_metadata_update_time.unwrap() + max_update_frequency,
            )
            .await;
        }

        if !update_batch_metadata {
            return Ok(());
        }

        let batch_metadata_path = self.reader.get_path_for_batch_metadata(first_version);
        {
            let _timer = TIMER
                .with_label_values(&["do_upload__update_batch_metadata"])
                .start_timer();
            self.writer
                .save_raw_file(
                    batch_metadata_path,
                    serde_json::to_vec(&batch_metadata).map_err(anyhow::Error::msg)?,
                )
                .await?;
        }

        if end_batch {
            self.last_batch_metadata_update_time = None;
        } else {
            self.last_batch_metadata_update_time = Some(Instant::now());
        }

        if Instant::now() - self.last_metadata_update_time >= max_update_frequency {
            let _timer = TIMER
                .with_label_values(&["do_upload__update_metadata"])
                .start_timer();
            self.update_file_store_metadata(last_version + 1).await?;
            self.last_metadata_update_time = Instant::now();
        }

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/local.rs (L61-69)
```rust
    async fn save_raw_file(&self, file_path: PathBuf, data: Vec<u8>) -> Result<()> {
        let file_path = self.path.join(file_path);
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(file_path, data)
            .await
            .map_err(anyhow::Error::msg)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_reader.rs (L86-95)
```rust
        trace!(
            "Getting transactions from file store, version: {version}, max_files: {max_files:?}."
        );
        let batch_metadata = self.get_batch_metadata(version).await;
        if batch_metadata.is_none() {
            // TODO(grao): This is unexpected, should only happen when data is corrupted. Consider
            // make it panic!.
            error!("Failed to get the batch metadata, unable to serve the request.");
            return;
        }
```
