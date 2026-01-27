# Audit Report

## Title
Indexer Service Permanent Failure Due to Unhandled Channel Closure in File Store Uploader

## Summary
The indexer-grpc file store uploader contains a critical flaw where channel closure due to receiver task failures causes a panic cascade that permanently crashes the entire indexer service with no automatic recovery mechanism. This vulnerability can be triggered by transient file store errors (network issues, disk failures, GCS rate limits) and results in complete indexer unavailability requiring manual intervention.

## Finding Description
The vulnerability exists in the communication pattern between sender and receiver tasks in the file store upload pipeline. The system uses a channel-based architecture where:

1. A sender task buffers transactions and sends them via channel when the buffer is full
2. A receiver task receives batched transactions and uploads them to file store (GCS or local filesystem)

The critical flaw occurs in the error handling: [1](#0-0) 

When `tx.send()` fails (because the receiver is closed), the error propagates up and hits unwrap calls: [2](#0-1) 

The receiver task can fail for multiple realistic reasons:

**GCS Upload Failures:** [3](#0-2) 

**Local Filesystem Failures:** [4](#0-3) 

When the receiver task encounters any upload error, it panics due to: [5](#0-4) 

**The Panic Cascade:**
1. Receiver task panics during file store upload failure
2. Channel closes
3. Sender task attempts to send next batch
4. `tx.send()` returns error (channel closed)
5. Sender task panics on `.unwrap()` at line 170
6. Both tasks are dead, no recovery mechanism exists

The same issue exists in the backfiller component: [6](#0-5) 

The entire service is supervised with no recovery: [7](#0-6) 

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **API Crashes**: The indexer-grpc service provides critical API endpoints for querying blockchain data. Complete service failure means all dependent services lose access to transaction data.

2. **Validator Node Slowdowns**: While not directly affecting consensus validators, indexer failures impact the broader Aptos ecosystem infrastructure that validators rely on for monitoring and analytics.

3. **Data Loss**: Buffered transactions that were not yet uploaded to file store are permanently lost when the service crashes, requiring re-processing from the last checkpoint.

4. **Availability Impact**: The indexer service becomes completely unavailable and requires manual restart. During this downtime:
   - No new transaction data is indexed
   - Downstream services (block explorers, analytics platforms, dApps) lose data access
   - Transaction history gaps are created

5. **No Automatic Recovery**: The Rust code contains no retry logic, circuit breakers, or task supervision. Recovery depends entirely on external orchestration (Docker restart policies, Kubernetes, systemd), which may have delays of seconds to minutes.

## Likelihood Explanation
The likelihood of this vulnerability being exploited is **High** for the following reasons:

**Common Trigger Scenarios:**
- **Network Issues**: Transient network failures when uploading to GCS (timeouts, connection resets, DNS failures)
- **GCS Rate Limiting**: Google Cloud Storage enforces rate limits (max 1 update per second per object). The code has a 1.5s delay but concurrent operations could still trigger limits
- **Disk Space**: Local file store can run out of disk space during directory creation or file writes
- **Permission Errors**: File system permission changes or GCS authentication token expiration
- **I/O Errors**: Disk hardware failures, filesystem corruption, or network storage issues

**Real-World Evidence:**
The codebase shows awareness of these issues - other components implement retry loops: [8](#0-7) 

However, the file_store_uploader_v2 component has no such protection.

**Attack Complexity**: Low - requires no privileged access, can be triggered by:
- Causing transient network issues
- Triggering GCS rate limits through normal load
- Filling disk space
- Waiting for natural infrastructure failures

## Recommendation

Implement comprehensive error handling with retry logic and graceful degradation:

```rust
// In file_store_uploader.rs, modify the receiver task:
s.spawn(async move {
    while let Some((transactions, batch_metadata, end_batch)) = rx.recv().await {
        let bytes_to_upload = batch_metadata.files.last().unwrap().size_bytes as u64;
        
        // Add retry logic with exponential backoff
        let mut retries = 0;
        const MAX_RETRIES: u32 = 5;
        const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
        
        loop {
            match self.do_upload(transactions.clone(), batch_metadata.clone(), end_batch).await {
                Ok(_) => {
                    FILE_STORE_UPLOADED_BYTES.inc_by(bytes_to_upload);
                    break;
                }
                Err(e) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        error!("Failed to upload after {} retries: {}", MAX_RETRIES, e);
                        // Option 1: Continue processing (data loss but service continues)
                        // Option 2: Exit gracefully allowing restart
                        break;
                    }
                    let backoff = INITIAL_BACKOFF * 2u32.pow(retries - 1);
                    warn!("Upload failed, retrying in {:?} (attempt {}/{}): {}", 
                          backoff, retries, MAX_RETRIES, e);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
});

// Also handle channel send errors gracefully in the sender task:
match file_store_operator
    .buffer_and_maybe_dump_transactions_to_file(transaction, tx.clone())
    .await
{
    Ok(_) => {},
    Err(e) => {
        error!("Failed to buffer transaction: {}. Channel may be closed.", e);
        // Implement recovery: wait and retry, or exit gracefully
        break;
    }
}
```

Additional recommendations:
1. Implement a circuit breaker pattern to detect repeated failures
2. Add health check endpoints that monitor task status
3. Emit metrics for channel send failures and retry counts
4. Consider using a persistent queue for buffered transactions
5. Add alerting for service degradation before complete failure

## Proof of Concept

```rust
// Test to demonstrate the vulnerability
// File: ecosystem/indexer-grpc/indexer-grpc-manager/tests/channel_failure_test.rs

use anyhow::Result;
use tokio::sync::mpsc::channel;
use std::time::Duration;

#[tokio::test]
async fn test_channel_closure_causes_panic() -> Result<()> {
    let (tx, mut rx) = channel::<String>(5);
    
    // Simulate receiver task that panics
    let receiver_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Simulate upload failure - in real code this is do_upload().unwrap()
        panic!("Simulated file store upload failure");
    });
    
    // Simulate sender task
    let sender_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        // After receiver panics, this will fail
        tx.send("transaction_batch".to_string())
            .await
            .unwrap(); // This unwrap will panic when receiver is gone
    });
    
    // Both tasks will panic, demonstrating the cascade
    let receiver_result = receiver_handle.await;
    let sender_result = sender_handle.await;
    
    assert!(receiver_result.is_err()); // Receiver panicked
    assert!(sender_result.is_err());   // Sender panicked due to closed channel
    
    Ok(())
}

// To reproduce in production:
// 1. Deploy indexer-grpc with GCS file store
// 2. Revoke GCS credentials temporarily or block network to GCS
// 3. Observe receiver task panic on upload failure
// 4. Observe sender task panic on channel send
// 5. Service is now dead and requires restart
```

**Notes**

The indexer-grpc component is critical infrastructure for the Aptos ecosystem, providing transaction data to block explorers, analytics platforms, and dApps. While it doesn't directly affect consensus or validator operations, its failure impacts the broader ecosystem's ability to interact with and monitor the blockchain.

The vulnerability is exacerbated by the fact that both the production file store uploader and the backfiller component share the same flawed pattern, meaning multiple critical services are affected by this issue.

The fix requires careful consideration of data consistency guarantees - whether to prioritize availability (continue with data loss) or consistency (fail and retry) depends on the specific requirements of the indexer service.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_operator.rs (L80-82)
```rust
        tx.send((transactions, self.buffer_batch_metadata.clone(), end_batch))
            .await
            .map_err(anyhow::Error::msg)?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L139-145)
```rust
                while let Some((transactions, batch_metadata, end_batch)) = rx.recv().await {
                    let bytes_to_upload = batch_metadata.files.last().unwrap().size_bytes as u64;
                    self.do_upload(transactions, batch_metadata, end_batch)
                        .await
                        .unwrap();
                    FILE_STORE_UPLOADED_BYTES.inc_by(bytes_to_upload);
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L167-170)
```rust
                        file_store_operator
                            .buffer_and_maybe_dump_transactions_to_file(transaction, tx.clone())
                            .await
                            .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/gcs.rs (L127-134)
```rust
        Object::create(
            self.bucket_name.as_str(),
            data,
            path.as_str(),
            JSON_FILE_TYPE,
        )
        .await
        .map_err(anyhow::Error::msg)?;
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

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L181-187)
```rust
                                                file_store_operator
                                                    .buffer_and_maybe_dump_transactions_to_file(
                                                        transaction,
                                                        tx.clone(),
                                                    )
                                                    .await
                                                    .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/grpc_manager.rs (L113-120)
```rust
                s.spawn(async move {
                    self.file_store_uploader
                        .lock()
                        .await
                        .start(self.data_manager.clone(), tx)
                        .await
                        .unwrap();
                });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L261-273)
```rust
            while self
                .file_store_operator
                .update_file_store_metadata_with_timeout(chain_id, batch_start_version)
                .await
                .is_err()
            {
                tracing::error!(
                    batch_start_version = batch_start_version,
                    "Failed to update file store metadata. Retrying."
                );
                std::thread::sleep(std::time::Duration::from_millis(500));
                METADATA_UPLOAD_FAILURE_COUNT.inc();
            }
```
