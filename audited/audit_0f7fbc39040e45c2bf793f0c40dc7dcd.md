# Audit Report

## Title
GCS Bucket Hijacking Vulnerability - Missing Project Ownership Verification in Backup/Restore Operations

## Summary
The `verify_storage_bucket_existence()` function in the indexer table info backup/restore service fails to verify that a GCS bucket belongs to the expected Google Cloud project. This allows an attacker to hijack the bucket namespace if the original bucket is deleted, enabling data exfiltration of blockchain snapshots and state corruption through malicious snapshot injection.

## Finding Description

The `verify_storage_bucket_existence()` function only validates that a GCS bucket with the specified name exists, but does not verify bucket ownership or project association. [1](#0-0) 

The function calls `get_bucket()` with only the bucket name and discards the response without checking the bucket's project number or any ownership metadata. Since GCS bucket names are globally unique across all Google Cloud projects, if the legitimate bucket is deleted, an attacker can create a bucket with the same name in their own project.

The `GcsBackupRestoreOperator` is initialized with authentication but no project validation. [2](#0-1) 

This operator is used throughout the indexer service lifecycle. During runtime initialization, the backup restore operator is created and used without additional validation. [3](#0-2) 

**Attack Scenario:**

1. Legitimate bucket `aptos-indexer-backup-xyz` exists in Aptos project (project #123456789)
2. Bucket gets deleted (accidental deletion, account compromise, or billing issues)
3. Attacker creates bucket `aptos-indexer-backup-xyz` in their project (project #987654321)
4. Indexer service starts and calls `verify_storage_bucket_existence()`
5. Function verifies bucket exists ✓ (but doesn't detect it's the wrong project)
6. Service proceeds with operations using attacker's bucket

**Exploitation Paths:**

**Path 1 - Data Exfiltration:**
The service uploads database snapshots containing complete indexed blockchain state to the bucket. [4](#0-3) 

An attacker controlling the bucket receives sensitive blockchain data including table info mappings and complete database checkpoints.

**Path 2 - State Corruption via Metadata Poisoning:**
The service downloads and trusts metadata from the bucket without cryptographic verification. [5](#0-4) 

The metadata includes chain_id and epoch information that controls backup/restore logic. [6](#0-5) 

An attacker can manipulate this metadata to cause chain ID mismatches, force incorrect epoch handling, or bypass backup validation.

**Path 3 - Database Snapshot Injection:**
The service can restore database snapshots from the bucket during initialization or recovery. [7](#0-6) 

An attacker providing malicious snapshots can corrupt the indexer's RocksDB state, inject false table info mappings, or cause denial of service through corrupted database files.

This breaks the **State Consistency** invariant - the indexer's state can no longer be trusted to accurately reflect the blockchain's table info data.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program for multiple reasons:

1. **State Inconsistencies Requiring Intervention** (High/Critical): Malicious snapshot injection corrupts the indexer database state, requiring manual intervention and potentially a full re-indexing from genesis to recover. This affects service availability and data integrity.

2. **Data Exfiltration** (Critical): Complete database snapshots containing all indexed blockchain data are uploaded to attacker-controlled infrastructure. While this is indexer data rather than consensus-critical data, it represents a significant breach of operational security and could expose sensitive transaction patterns or user behavior.

3. **Denial of Service** (High): Corrupted snapshots can brick indexer nodes, preventing them from serving queries and disrupting ecosystem services that depend on indexed data.

The indexer-grpc table info service is a critical infrastructure component used by wallets, explorers, and other ecosystem applications. State corruption or prolonged unavailability would significantly impact the Aptos ecosystem.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Prerequisites for exploitation:**
1. Original GCS bucket must be deleted
2. Attacker must know the exact bucket name
3. Attacker must create replacement bucket before legitimate recovery

**Scenarios enabling bucket deletion:**
- **Accidental deletion by operators** during maintenance or cleanup (MEDIUM likelihood)
- **GCP account compromise** allowing bucket deletion (LOW-MEDIUM likelihood)
- **Automated cleanup scripts** with bugs (LOW likelihood)
- **Project billing issues** causing resource suspension/deletion (LOW likelihood)
- **Malicious insider** with GCP access (LOW likelihood per trust model)

**Attacker advantages:**
- Bucket names follow predictable patterns and may be discoverable
- No additional authentication required once bucket is created
- Attack is persistent - works for all future service startups
- Detection is difficult without explicit project validation

The combination of operational realities (accidental deletions do occur) and the severity of impact makes this a serious vulnerability despite requiring a precondition.

## Recommendation

**Immediate Fix:**

1. Store the expected GCP project number/ID in the service configuration
2. Validate bucket ownership after calling `get_bucket()`
3. Panic if project mismatch is detected

**Code Fix for `verify_storage_bucket_existence()`:**

```rust
pub async fn verify_storage_bucket_existence(&self, expected_project_number: u64) {
    info!(
        bucket_name = self.bucket_name,
        expected_project = expected_project_number,
        "Verifying bucket exists and belongs to expected project."
    );

    let bucket = self.gcs_client
        .get_bucket(&GetBucketRequest {
            bucket: self.bucket_name.to_string(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|_| panic!("Failed to get bucket: {}", self.bucket_name));
    
    // Verify bucket belongs to expected project
    let actual_project_number = bucket.project_number;
    if actual_project_number != expected_project_number {
        panic!(
            "Bucket project mismatch! Expected project {}, but bucket {} belongs to project {}. Possible bucket hijacking attack!",
            expected_project_number,
            self.bucket_name,
            actual_project_number
        );
    }
    
    info!(
        bucket_name = self.bucket_name,
        project_number = actual_project_number,
        "Bucket ownership verified successfully."
    );
}
```

**Configuration Update:**

Add `expected_project_number` to the `TableInfoServiceMode::Backup` variant and configuration parsing to pass the project number during initialization.

**Additional Recommendations:**

1. **Cryptographic Verification**: Sign metadata and snapshots with a private key controlled by Aptos, verify signatures before use
2. **Bucket Lifecycle Policies**: Enable GCS object versioning and deletion protection
3. **Monitoring**: Alert on bucket deletion events or project number changes
4. **Documentation**: Document the security requirement that buckets must belong to specific projects

## Proof of Concept

**Simulation Steps:**

```bash
# 1. Attacker Setup - Create GCS bucket in their project
gcloud config set project attacker-project-id
gsutil mb gs://aptos-indexer-backup-xyz

# 2. Victim Service Starts
# The indexer service configured to use bucket "aptos-indexer-backup-xyz"
# Current code in verify_storage_bucket_existence() will succeed

# 3. Attacker uploads malicious metadata
cat > /tmp/metadata.json << EOF
{
  "chain_id": 1,
  "epoch": 999999
}
EOF
gsutil cp /tmp/metadata.json gs://aptos-indexer-backup-xyz/metadata.json

# 4. Attacker creates malicious snapshot
# Create corrupted RocksDB snapshot that crashes indexer on restore
tar czf /tmp/malicious_snapshot.tar.gz <corrupted_db_files>
gsutil cp /tmp/malicious_snapshot.tar.gz gs://aptos-indexer-backup-xyz/chain_id_1_epoch_999999.tar.gz

# 5. Service downloads and uses malicious data
# get_metadata() returns attacker's metadata
# restore_db_snapshot() unpacks corrupted database
# Result: Indexer state corrupted or crashed
```

**Rust Test POC:**

```rust
#[tokio::test]
async fn test_bucket_hijacking_vulnerability() {
    // This test demonstrates the vulnerability by showing that
    // verify_storage_bucket_existence() accepts buckets from any project
    
    let legitimate_bucket = "aptos-test-bucket";
    let legitimate_project_num: u64 = 123456789;
    
    // Create operator pointing to bucket name
    let operator = GcsBackupRestoreOperator::new(legitimate_bucket.to_string()).await;
    
    // Current implementation: This passes even if bucket is in attacker's project
    operator.verify_storage_bucket_existence().await;
    
    // VULNERABILITY: No validation that bucket belongs to legitimate_project_num
    // An attacker's bucket with same name would pass verification
    
    // Expected behavior (not implemented):
    // operator.verify_storage_bucket_existence(legitimate_project_num).await;
    // Should panic if bucket.project_number != legitimate_project_num
}
```

**Notes:**
- This vulnerability affects the indexer infrastructure, not consensus validators
- While not directly a consensus-critical vulnerability, it represents a significant operational security risk
- The same vulnerability pattern exists in other GCS file store operators in the codebase [8](#0-7)

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs (L38-48)
```rust
    pub async fn new(bucket_name: String) -> Self {
        let gcs_config = ClientConfig::default()
            .with_auth()
            .await
            .expect("Failed to create GCS client.");
        let gcs_client = Client::new(gcs_config);
        Self {
            bucket_name,
            gcs_client,
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs (L52-65)
```rust
    pub async fn verify_storage_bucket_existence(&self) {
        info!(
            bucket_name = self.bucket_name,
            "Before gcs backup restore operator starts, verify the bucket exists."
        );

        self.gcs_client
            .get_bucket(&GetBucketRequest {
                bucket: self.bucket_name.to_string(),
                ..Default::default()
            })
            .await
            .unwrap_or_else(|_| panic!("Failed to get the bucket with name: {}", self.bucket_name));
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs (L67-81)
```rust
    pub async fn get_metadata(&self) -> Option<BackupRestoreMetadata> {
        match self.download_metadata_object().await {
            Ok(metadata) => Some(metadata),
            Err(Error::HttpClient(err)) => {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    None
                } else {
                    panic!("Error happens when accessing metadata file. {}", err);
                }
            },
            Err(e) => {
                panic!("Error happens when accessing metadata file. {}", e);
            },
        }
    }
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

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/backup_restore/gcs.rs (L264-314)
```rust
    pub async fn restore_db_snapshot(
        &self,
        chain_id: u64,
        metadata: BackupRestoreMetadata,
        db_path: PathBuf,
        base_path: PathBuf,
    ) -> anyhow::Result<()> {
        assert!(metadata.chain_id == chain_id, "Chain ID mismatch.");

        let epoch = metadata.epoch;
        let epoch_based_filename = generate_blob_name(chain_id, epoch);

        match self
            .gcs_client
            .download_streamed_object(
                &GetObjectRequest {
                    bucket: self.bucket_name.clone(),
                    object: epoch_based_filename.clone(),
                    ..Default::default()
                },
                &Range::default(),
            )
            .await
        {
            Ok(mut stream) => {
                // Create a temporary file and write the stream to it directly
                let temp_file_name = "snapshot.tar.gz";
                let temp_file_path = base_path.join(temp_file_name);
                let temp_file_path_clone = temp_file_path.clone();
                let mut temp_file = File::create(&temp_file_path_clone).await?;
                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(data) => temp_file.write_all(&data).await?,
                        Err(e) => return Err(anyhow::Error::new(e)),
                    }
                }
                temp_file.sync_all().await?;

                // Spawn blocking a thread to synchronously unpack gzipped tar file without blocking the async thread
                task::spawn_blocking(move || unpack_tar_gz(&temp_file_path_clone, &db_path))
                    .await?
                    .expect("Failed to unpack gzipped tar file");

                fs::remove_file(&temp_file_path)
                    .await
                    .context("Failed to remove temporary file after unpacking")?;
                Ok(())
            },
            Err(e) => Err(anyhow::Error::new(e)),
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L93-98)
```rust
        let backup_restore_operator = match node_config.indexer_table_info.table_info_service_mode {
            TableInfoServiceMode::Backup(gcs_bucket_name) => Some(Arc::new(
                GcsBackupRestoreOperator::new(gcs_bucket_name).await,
            )),
            _ => None,
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L544-560)
```rust
    let backup_metadata = backup_restore_operator.get_metadata().await;
    if let Some(metadata) = backup_metadata {
        if metadata.chain_id != (ledger_chain_id as u64) {
            panic!(
                "Table Info backup chain id does not match with current network. Expected: {}, found in backup: {}",
                context.chain_id().id(),
                metadata.chain_id
            );
        }
    } else {
        aptos_logger::warn!(
            epoch = epoch,
            snapshot_folder_name = snapshot_folder_name,
            "[Table Info] No backup metadata found. Skipping the backup."
        );
    }

```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/gcs.rs (L84-93)
```rust
    async fn verify_storage_bucket_existence(&self) {
        tracing::info!(
            bucket_name = self.bucket_name,
            "Before file store operator starts, verify the bucket exists."
        );
        // Verifies the bucket exists.
        Bucket::read(&self.bucket_name)
            .await
            .expect("Failed to read bucket.");
    }
```
