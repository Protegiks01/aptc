# Audit Report

## Title
Memory Exhaustion in Indexer GCS File Download Due to Missing Size Validation

## Summary
The `get_raw_file()` function in the indexer-grpc GCS file store operator downloads entire files from Google Cloud Storage into memory without any size validation, creating a potential out-of-memory (OOM) crash vector if an attacker with GCS write access uploads extremely large files.

## Finding Description

The vulnerability exists in the GCS file store reader implementation where files are downloaded entirely into memory without size checks: [1](#0-0) 

The `Object::download()` call at line 102 downloads the entire file content into a `Vec<u8>` without validating the file size beforehand. This contrasts with other parts of the codebase that implement defensive size checks, such as the NFT metadata crawler: [2](#0-1) [3](#0-2) 

**Attack Path:**

1. Attacker gains write access to the GCS bucket (via service account compromise or IAM misconfiguration)
2. Attacker creates extremely large files (e.g., multi-GB) with valid naming conventions (e.g., `0/1234567` or batch metadata files)
3. When the indexer data service attempts to serve requests, it reads from the file store: [4](#0-3) 

4. The file reading path follows: `get_transactions_with_durations()` → `get_raw_file_with_retries()` → `get_raw_file()`: [5](#0-4) 

5. The entire malicious file is loaded into memory, causing OOM crash

**Broken Invariant:** 
Violates invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits"

## Impact Explanation

**Severity: HIGH** (per Aptos bug bounty criteria: "API crashes")

An OOM crash of the indexer data service causes:
- Complete denial of service for all clients depending on the indexer
- Inability to serve historical transaction data
- Disruption of downstream indexing pipelines and applications
- Service unavailability requiring manual intervention and restart

While normal operation caps uploaded files at 50MB: [6](#0-5) 

This limit is only enforced during the upload process and provides no protection if files are created through other means.

## Likelihood Explanation

**Likelihood: MEDIUM-LOW**

The exploit requires:
1. **GCS Bucket Write Access**: Requires compromise of service account credentials or IAM misconfiguration. The bucket uses service account authentication: [7](#0-6) 

2. **Knowledge of Naming Conventions**: Attacker must understand the file structure used by the indexer
3. **Triggering Download**: Files must be accessed by the data service

**NOTE:** This vulnerability requires infrastructure-level access (service account compromise or misconfiguration) and is **NOT directly exploitable by unprivileged external attackers**. However, it represents a critical defense-in-depth failure.

## Recommendation

Implement size validation before downloading files, following the pattern used in the NFT metadata crawler:

```rust
async fn get_raw_file(&self, file_path: PathBuf) -> Result<Option<Vec<u8>>> {
    let path = self.get_path(file_path);
    
    // Define maximum acceptable file size (e.g., 100MB with safety margin)
    const MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;
    
    trace!(
        "Checking file size at {}/{}.",
        self.bucket_name,
        path.as_str()
    );
    
    // Get object metadata first to check size
    match Object::read(&self.bucket_name, path.as_str()).await {
        Ok(object) => {
            if object.size > MAX_FILE_SIZE_BYTES {
                bail!(
                    "[Indexer File] File too large: {} bytes exceeds maximum of {} bytes at {path:?}",
                    object.size,
                    MAX_FILE_SIZE_BYTES
                );
            }
            
            trace!(
                "Downloading object at {}/{} ({} bytes).",
                self.bucket_name,
                path.as_str(),
                object.size
            );
            
            match Object::download(&self.bucket_name, path.as_str()).await {
                Ok(file) => Ok(Some(file)),
                Err(err) => bail!("[Indexer File] Download failed: {err}"),
            }
        },
        Err(cloud_storage::Error::Other(err)) if err.contains("No such object: ") => {
            Ok(None)
        },
        Err(err) => {
            bail!("[Indexer File] Failed to read object metadata at {path:?}: {err}");
        },
    }
}
```

## Proof of Concept

```rust
// Reproduction scenario (requires GCS access):
// 
// 1. Create a test GCS bucket with service account
// 2. Upload a large file (e.g., 5GB) named "0/0" to the bucket
// 3. Configure indexer-grpc-data-service to use this bucket
// 4. Request transactions starting from version 0
// 5. Observe OOM crash when get_raw_file() attempts to download the 5GB file

#[cfg(test)]
mod test_memory_exhaustion {
    use super::*;
    
    #[tokio::test]
    #[ignore] // Requires GCS setup
    async fn test_large_file_download_causes_oom() {
        // Setup: Create GCS file store with malicious large file
        let bucket_name = "test-bucket".to_string();
        let service_account = "path/to/service/account.json".to_string();
        
        let gcs_store = GcsFileStore::new(
            bucket_name.clone(),
            None,
            service_account,
        ).await;
        
        // Simulate large file upload (would need to be done separately)
        // cloud_storage::Object::create(
        //     &bucket_name,
        //     vec![0u8; 5_000_000_000], // 5GB of zeros
        //     "0/0",
        //     "application/octet-stream"
        // ).await.unwrap();
        
        // Trigger download - should cause OOM without size checks
        let result = gcs_store.get_raw_file(PathBuf::from("0/0")).await;
        
        // Without fix: process crashes with OOM
        // With fix: returns error for file too large
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }
}
```

---

**Notes:**
- This vulnerability represents a **defense-in-depth** failure rather than a direct external attack vector
- Exploitation requires pre-existing infrastructure compromise (service account access)
- The issue violates defensive programming principles by trusting storage backend implicitly
- Similar size validation exists in other codebase components, indicating awareness of this pattern
- While the 50MB upload limit provides partial mitigation, it can be bypassed through direct GCS manipulation

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs (L22-49)
```rust
    pub async fn new(
        bucket_name: String,
        bucket_sub_dir: Option<PathBuf>,
        service_account_path: String,
    ) -> Self {
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe {
            env::set_var(SERVICE_ACCOUNT_ENV_VAR, service_account_path);
        }

        info!(
            bucket_name = bucket_name,
            "Verifying the bucket exists for GcsFileStore."
        );

        Bucket::read(&bucket_name)
            .await
            .expect("Failed to read bucket.");

        info!(
            bucket_name = bucket_name,
            "Bucket exists, GcsFileStore is created."
        );
        Self {
            bucket_name,
            bucket_sub_dir,
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs (L95-115)
```rust
    async fn get_raw_file(&self, file_path: PathBuf) -> Result<Option<Vec<u8>>> {
        let path = self.get_path(file_path);
        trace!(
            "Downloading object at {}/{}.",
            self.bucket_name,
            path.as_str()
        );
        match Object::download(&self.bucket_name, path.as_str()).await {
            Ok(file) => Ok(Some(file)),
            Err(cloud_storage::Error::Other(err)) => {
                if err.contains("No such object: ") {
                    Ok(None)
                } else {
                    bail!("[Indexer File] Error happens when downloading file at {path:?}. {err}",);
                }
            },
            Err(err) => {
                bail!("[Indexer File] Error happens when downloading file at {path:?}. {err}");
            },
        }
    }
```

**File:** ecosystem/nft-metadata-crawler/src/lib.rs (L17-37)
```rust
pub async fn get_uri_metadata(url: &str) -> anyhow::Result<(String, u32)> {
    let client = Client::builder()
        .timeout(Duration::from_secs(MAX_HEAD_REQUEST_RETRY_SECONDS))
        .build()
        .context("Failed to build reqwest client")?;
    let request = client.head(url.trim());
    let response = request.send().await?;
    let headers = response.headers();

    let mime_type = headers
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().unwrap_or("text/plain"))
        .unwrap_or("text/plain")
        .to_string();
    let size = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    Ok((mime_type, size))
```

**File:** ecosystem/nft-metadata-crawler/src/utils/json_parser.rs (L32-48)
```rust
        let (mime, size) = get_uri_metadata(&uri).await?;
        if ImageFormat::from_mime_type(&mime).is_some() {
            FAILED_TO_PARSE_JSON_COUNT
                .with_label_values(&["found image instead"])
                .inc();
            return Err(anyhow::anyhow!(format!(
                "JSON parser received image file: {}, skipping",
                mime
            )));
        } else if size > max_file_size_bytes {
            FAILED_TO_PARSE_JSON_COUNT
                .with_label_values(&["json file too large"])
                .inc();
            return Err(anyhow::anyhow!(format!(
                "JSON parser received file too large: {} bytes, skipping",
                size
            )));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L779-787)
```rust
async fn data_fetch_from_filestore(
    starting_version: u64,
    file_store_operator: Arc<Box<dyn FileStoreOperator>>,
    request_metadata: Arc<IndexerGrpcRequestMetadata>,
) -> anyhow::Result<Vec<Transaction>> {
    // Data is evicted from the cache. Fetch from file store.
    let (transactions, io_duration, decoding_duration) = file_store_operator
        .get_transactions_with_durations(starting_version, NUM_DATA_FETCH_RETRIES)
        .await?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/mod.rs (L59-86)
```rust
    async fn get_transactions_with_durations(
        &self,
        version: u64,
        retries: u8,
    ) -> Result<(Vec<Transaction>, f64, f64)> {
        let io_start_time = std::time::Instant::now();
        let bytes = self.get_raw_file_with_retries(version, retries).await?;
        let io_duration = io_start_time.elapsed().as_secs_f64();
        let decoding_start_time = std::time::Instant::now();
        let storage_format = self.storage_format();

        let transactions_in_storage = tokio::task::spawn_blocking(move || {
            FileEntry::new(bytes, storage_format).into_transactions_in_storage()
        })
        .await
        .context("Converting storage bytes to FileEntry transactions thread panicked")?;

        let decoding_duration = decoding_start_time.elapsed().as_secs_f64();
        Ok((
            transactions_in_storage
                .transactions
                .into_iter()
                .skip((version % FILE_ENTRY_TRANSACTION_COUNT) as usize)
                .collect(),
            io_duration,
            decoding_duration,
        ))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L27-27)
```rust
const MAX_SIZE_PER_FILE: usize = 50 * (1 << 20);
```
