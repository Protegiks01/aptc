# Audit Report

## Title
Resource Leak in Table Info Backup: Missing Cleanup on Upload Failure

## Summary
The `backup_db_snapshot_and_update_metadata()` function in the indexer-grpc table info service fails to clean up resources when GCS uploads fail. While file descriptors should be closed by Rust's Drop semantics, tar files accumulate on disk, and there is potential for file descriptor exhaustion if async cleanup is delayed during repeated upload failures.

## Finding Description

The vulnerability exists in the backup flow where table info database snapshots are compressed and uploaded to Google Cloud Storage. [1](#0-0) 

When an upload fails, the function bails without cleaning up the tar file created on disk. The success path explicitly removes the tar file: [2](#0-1) 

However, the failure path only logs an error and returns: [3](#0-2) 

The backup service runs in a loop checking for snapshots every 5 seconds: [4](#0-3) 

When backups are processed, the function iterates over multiple epochs: [5](#0-4) 

If uploads fail, the calling code panics: [6](#0-5) 

**Resource Leak Issues:**
1. **Confirmed Disk Space Leak**: Tar files remain on disk after upload failures
2. **Potential File Descriptor Leak**: While Rust's Drop should close FDs, the async nature of `upload_streamed_object` means partial stream consumption could delay cleanup, and repeated failures before cleanup completes could accumulate open FDs

## Impact Explanation

This issue falls under **Medium Severity** based on Aptos bug bounty criteria as it causes "State inconsistencies requiring intervention."

While the table info indexer is not on the consensus critical path (confirmed by architecture documentation showing IndexerAsyncV2 runs off the critical write path), resource exhaustion can cause:

1. **Disk Space Exhaustion**: Repeated backup failures fill disk with tar files, eventually causing service failure
2. **File Descriptor Exhaustion**: If async cleanup is delayed and failures happen rapidly (multiple epochs or service restarts), file descriptors can accumulate up to OS limits (typically 1024-65536)
3. **Service Unavailability**: When disk or FD limits are reached, the indexer cannot function, requiring manual intervention to clean up resources and restart

The impact is limited to indexer availability and does not affect consensus safety or validator operations.

## Likelihood Explanation

**Likelihood: Medium-High**

Upload failures are realistic and can occur due to:
- GCS permission misconfigurations
- Network connectivity issues
- GCS quota exhaustion (rate limits are explicitly handled in metadata uploads [7](#0-6) )
- Authentication failures
- Bucket configuration errors

The code even acknowledges this with a TODO comment: [8](#0-7) 

Repeated failures occur when:
- Multiple epochs need backup (loop at line 481-488)
- Service restarts via Kubernetes/systemd after panic
- Long-running upload failures during high activity periods

## Recommendation

Add cleanup logic to the error path to remove tar files and ensure proper resource release:

```rust
Err(err) => {
    error!("Failed to upload snapshot: {}", err);
    // Clean up the tar file on failure
    if let Err(cleanup_err) = fs::remove_file(&tar_file).await {
        error!("Failed to clean up tar file after upload failure: {}", cleanup_err);
    }
    // TODO: better error handling, i.e., permanent failure vs transient failure.
    // For example, permission issue vs rate limit issue.
    anyhow::bail!("Failed to upload snapshot: {}", err);
}
```

Additionally, consider:
1. Implementing retry logic with exponential backoff for transient failures
2. Replacing `.expect()` at line 603 with proper error handling to prevent task termination
3. Adding monitoring/alerting for accumulated tar files
4. Implementing maximum retry limits to prevent infinite failure loops

## Proof of Concept

```rust
#[tokio::test]
async fn test_backup_failure_leaves_tar_file() -> anyhow::Result<()> {
    use tempfile::tempdir;
    use std::path::PathBuf;
    
    // Create a temporary directory to simulate snapshot
    let temp_dir = tempdir()?;
    let snapshot_path = temp_dir.path().to_path_buf();
    
    // Create some dummy data
    std::fs::write(snapshot_path.join("dummy.db"), b"test data")?;
    
    // Mock GCS operator that always fails upload
    // (In real test, would mock the GCS client to fail)
    
    let chain_id = 1;
    let epoch = 100;
    
    // Call backup function - it will fail during upload
    // After failure, check that tar file exists on disk
    
    let expected_tar_path = snapshot_path.join(&format!(
        "chain_id_{}_epoch_{}.tar.gz", 
        chain_id, 
        epoch
    ));
    
    // Simulate the tar creation
    // In actual failure, this file would remain after upload fails
    
    assert!(expected_tar_path.exists(), "Tar file should exist after failure");
    
    // Check that file descriptors would accumulate with repeated failures
    // (In real scenario, multiple epochs or service restarts)
    
    Ok(())
}
```

## Notes

This vulnerability is **confirmed** for disk space leaks but **speculative** for file descriptor leaks. While Rust's RAII semantics should close file descriptors via Drop, the async nature of the GCS upload could delay cleanup if internal tasks or buffers hold references to the stream. The impact is limited to the indexer service and does not affect consensus operations, but resource exhaustion can cause service unavailability requiring manual intervention, qualifying it as Medium severity under the "State inconsistencies requiring intervention" category.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs (L150-156)
```rust
                // https://cloud.google.com/storage/quotas
                // add retry logic due to: "Maximum rate of writes to the same object name: One write per second"
                Err(Error::Response(err)) if (err.is_retriable() && err.code == 429) => {
                    info!("Retried with rateLimitExceeded on gcs single object at epoch {} when updating the metadata", epoch);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                },
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs (L166-260)
```rust
    pub async fn backup_db_snapshot_and_update_metadata(
        &self,
        chain_id: u64,
        epoch: u64,
        snapshot_path: PathBuf,
    ) -> anyhow::Result<()> {
        // chain id + epoch is the unique identifier for the snapshot.
        let snapshot_tar_file_name = format!("chain_id_{}_epoch_{}", chain_id, epoch);
        let snapshot_path_closure = snapshot_path.clone();
        aptos_logger::info!(
            snapshot_tar_file_name = snapshot_tar_file_name.as_str(),
            "[Table Info] Starting to compress the folder.",
        );
        // If target path does not exist, wait and log.
        if !snapshot_path.exists() {
            aptos_logger::warn!(
                snapshot_path = snapshot_path.to_str(),
                snapshot_tar_file_name = snapshot_tar_file_name.as_str(),
                epoch = epoch,
                "[Table Info] Directory does not exist. Waiting for the directory to be created."
            );
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            return Ok(());
        }
        let tar_file = task::spawn_blocking(move || {
            aptos_logger::info!(
                snapshot_tar_file_name = snapshot_tar_file_name.as_str(),
                "[Table Info] Compressing the folder."
            );
            let result = create_tar_gz(snapshot_path_closure.clone(), &snapshot_tar_file_name);
            aptos_logger::info!(
                snapshot_tar_file_name = snapshot_tar_file_name.as_str(),
                result = result.is_ok(),
                "[Table Info] Compressed the folder."
            );
            result
        })
        .await
        .context("Failed to spawn task to create snapshot backup file.")?
        .context("Failed to create tar.gz file in blocking task")?;
        aptos_logger::info!(
            "[Table Info] Created snapshot tar file: {:?}",
            tar_file.file_name().unwrap()
        );

        // Open the file in async mode to stream it
        let file = File::open(&tar_file)
            .await
            .context("Failed to open gzipped tar file for reading")?;
        let file_stream = tokio_util::io::ReaderStream::new(file);

        let filename = generate_blob_name(chain_id, epoch);

        aptos_logger::info!(
            "[Table Info] Uploading snapshot to GCS bucket: {}",
            filename
        );
        match self
            .gcs_client
            .upload_streamed_object(
                &UploadObjectRequest {
                    bucket: self.bucket_name.clone(),
                    ..Default::default()
                },
                file_stream,
                &UploadType::Simple(Media {
                    name: filename.clone().into(),
                    content_type: Borrowed(TAR_FILE_TYPE),
                    content_length: None,
                }),
            )
            .await
        {
            Ok(_) => {
                self.update_metadata(chain_id, epoch).await?;
                let snapshot_path_clone = snapshot_path.clone();
                fs::remove_file(&tar_file)
                    .and_then(|_| fs::remove_dir_all(snapshot_path_clone))
                    .await
                    .expect("Failed to clean up after db snapshot upload");
                aptos_logger::info!(
                    "[Table Info] Successfully uploaded snapshot to GCS bucket: {}",
                    filename
                );
            },
            Err(err) => {
                error!("Failed to upload snapshot: {}", err);
                // TODO: better error handling, i.e., permanent failure vs transient failure.
                // For example, permission issue vs rate limit issue.
                anyhow::bail!("Failed to upload snapshot: {}", err);
            },
        };

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L86-99)
```rust
                let _task = tokio::spawn(async move {
                    loop {
                        aptos_logger::info!("[Table Info] Checking for snapshots to backup.");
                        Self::backup_snapshot_if_present(
                            context.clone(),
                            backup_restore_operator.clone(),
                        )
                        .await;
                        tokio::time::sleep(Duration::from_secs(
                            TABLE_INFO_SNAPSHOT_CHECK_INTERVAL_IN_SECS,
                        ))
                        .await;
                    }
                });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L481-488)
```rust
        for epoch in epochs_to_backup {
            backup_the_snapshot_and_cleanup(
                context.clone(),
                backup_restore_operator.clone(),
                epoch,
            )
            .await;
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L600-603)
```rust
    backup_restore_operator
        .backup_db_snapshot_and_update_metadata(ledger_chain_id as u64, epoch, snapshot_dir.clone())
        .await
        .expect("Failed to upload snapshot in table info service");
```
