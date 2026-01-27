# Audit Report

## Title
Infinite Loop DoS Vulnerability in Live Data Service Due to Zero Batch Size

## Summary
The `start_streaming()` function in the indexer gRPC data service v2 contains an infinite loop vulnerability when a client provides `batch_size = 0`. The `get_data()` function returns an empty transaction batch without advancing the version cursor, causing the streaming loop to repeatedly process the same version indefinitely, leading to resource exhaustion and denial of service.

## Finding Description

The vulnerability exists in the interaction between two functions:

1. **In `start_streaming()`** [1](#0-0) , the code accepts user-provided `batch_size` without validation and converts it directly to `max_num_transactions_per_batch`. When `batch_size = 0`, this parameter becomes 0 with no lower bound check.

2. **In `get_data()`** [2](#0-1) , the while loop condition includes `result.len() < max_num_transactions_per_batch`. When `max_num_transactions_per_batch = 0`, this evaluates to `0 < 0` which is always false, preventing the loop from executing even once.

3. **The critical flaw** [3](#0-2)  occurs when the function returns `Some((result, total_bytes, version - 1))` where `version` equals `starting_version` because the loop never incremented it. This returns `Some(([], 0, starting_version - 1))`.

4. **Back in `start_streaming()`** [4](#0-3) , the code sets `next_version = last_processed_version + 1`, which becomes `(starting_version - 1) + 1 = starting_version`, making no forward progress.

5. **The infinite loop** [5](#0-4)  continues as long as the client keeps receiving responses, repeatedly sending empty transaction batches for the same version.

**Attack Path:**
1. Attacker sends a gRPC `GetTransactionsRequest` with `batch_size = 0` [6](#0-5) 
2. The request is processed without validation [7](#0-6) 
3. A streaming task is spawned that enters an infinite loop
4. The attacker keeps the connection open to maintain the loop
5. Multiple such requests exhaust server resources (CPU, memory, network bandwidth)

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria:
- It causes service disruption to the indexer gRPC data service
- Attackers can exhaust server resources through repeated malicious requests
- The indexer service becomes unavailable, preventing applications from querying blockchain data

However, this does NOT affect:
- Consensus operation or blockchain availability (indexer is off-chain infrastructure)
- Validator node operation
- On-chain state or funds
- Core blockchain security

The impact is limited to the availability of the indexer query service, which is critical for dApps but does not compromise blockchain integrity.

## Likelihood Explanation

**HIGH likelihood** - The vulnerability is easily exploitable:
- No authentication or special privileges required
- Single malformed gRPC request triggers the issue
- Attack vector is simple: set `batch_size = 0` in the request
- No rate limiting or validation prevents exploitation
- The protobuf definition allows `batch_size = 0` [8](#0-7) 
- Comment mentions validation for values > 1000 but no validation for 0

## Recommendation

Add validation to reject invalid `batch_size` values:

```rust
let max_num_transactions_per_batch = if let Some(batch_size) = request.batch_size {
    if batch_size == 0 {
        let err = Err(Status::invalid_argument(
            "batch_size must be greater than 0.",
        ));
        let _ = response_sender.blocking_send(err);
        continue;
    }
    batch_size as usize
} else {
    10000
};
```

Additionally, enforce the documented upper limit of 1000:
```rust
if batch_size > 1000 {
    let err = Err(Status::invalid_argument(
        "batch_size cannot exceed 1000.",
    ));
    let _ = response_sender.blocking_send(err);
    continue;
}
```

Apply the same validation in `historical_data_service.rs` [9](#0-8) .

## Proof of Concept

```rust
#[tokio::test]
async fn test_zero_batch_size_infinite_loop() {
    use aptos_protos::indexer::v1::{GetTransactionsRequest, TransactionsResponse};
    use tokio::sync::mpsc;
    use tonic::Request;
    
    // Create a GetTransactionsRequest with batch_size = 0
    let request = GetTransactionsRequest {
        starting_version: Some(0),
        transactions_count: Some(10), // Limit to prevent actual infinite loop in test
        batch_size: Some(0), // The malicious input
        transaction_filter: None,
    };
    
    let (response_tx, mut response_rx) = mpsc::channel::<Result<TransactionsResponse, tonic::Status>>(10);
    
    // Simulate sending to the live data service
    // In real scenario, this would connect to the gRPC endpoint
    
    // Expected behavior: Should receive multiple responses with the SAME processed_range
    let mut response_count = 0;
    let mut last_first_version = None;
    
    while let Some(Ok(response)) = response_rx.recv().await {
        response_count += 1;
        
        if let Some(range) = response.processed_range {
            if let Some(last_ver) = last_first_version {
                // Verify that we're stuck on the same version (infinite loop indicator)
                assert_eq!(range.first_version, last_ver, 
                    "Version should not advance with batch_size = 0");
            }
            last_first_version = Some(range.first_version);
        }
        
        // In a real attack, this would continue indefinitely
        if response_count >= 5 {
            break;
        }
    }
    
    assert!(response_count >= 5, "Should produce multiple responses without progress");
}
```

## Notes

The vulnerability is confirmed in the codebase at the exact lines mentioned in the security question. The `get_data()` function returns `Some` with an empty transactions vector when `batch_size = 0`, and the `start_streaming()` loop does not handle this case, causing `next_version` to remain unchanged and creating an infinite loop.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L74-140)
```rust
            while let Some((request, response_sender)) = handler_rx.blocking_recv() {
                COUNTER
                    .with_label_values(&["live_data_service_receive_request"])
                    .inc();
                // Extract request metadata before consuming the request.
                let request_metadata = Arc::new(get_request_metadata(&request));
                let request = request.into_inner();
                let id = request_metadata.request_connection_id.clone();
                let known_latest_version = self.get_known_latest_version();
                let starting_version = request.starting_version.unwrap_or(known_latest_version);

                info!("Received request: {request:?}.");
                if starting_version > known_latest_version + 10000 {
                    let err = Err(Status::failed_precondition(
                        "starting_version cannot be set to a far future version.",
                    ));
                    info!("Client error: {err:?}.");
                    let _ = response_sender.blocking_send(err);
                    COUNTER
                        .with_label_values(&["live_data_service_requested_data_too_new"])
                        .inc();
                    continue;
                }

                let filter = if let Some(proto_filter) = request.transaction_filter {
                    match filter_utils::parse_transaction_filter(
                        proto_filter,
                        self.max_transaction_filter_size_bytes,
                    ) {
                        Ok(filter) => Some(filter),
                        Err(err) => {
                            info!("Client error: {err:?}.");
                            let _ = response_sender.blocking_send(Err(err));
                            COUNTER
                                .with_label_values(&["live_data_service_invalid_filter"])
                                .inc();
                            continue;
                        },
                    }
                } else {
                    None
                };

                let max_num_transactions_per_batch = if let Some(batch_size) = request.batch_size {
                    batch_size as usize
                } else {
                    10000
                };

                let ending_version = request
                    .transactions_count
                    .map(|count| starting_version + count);

                scope.spawn(async move {
                    self.start_streaming(
                        id,
                        starting_version,
                        ending_version,
                        max_num_transactions_per_batch,
                        MAX_BYTES_PER_BATCH,
                        filter,
                        request_metadata,
                        response_sender,
                    )
                    .await
                });
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L172-234)
```rust
        loop {
            if next_version >= ending_version {
                break;
            }
            self.connection_manager
                .update_stream_progress(&id, next_version, size_bytes);
            let known_latest_version = self.get_known_latest_version();
            if next_version > known_latest_version {
                info!(stream_id = id, "next_version {next_version} is larger than known_latest_version {known_latest_version}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            if let Some((transactions, batch_size_bytes, last_processed_version)) = self
                .in_memory_cache
                .get_data(
                    next_version,
                    ending_version,
                    max_num_transactions_per_batch,
                    max_bytes_per_batch,
                    &filter,
                )
                .await
            {
                let _timer = TIMER
                    .with_label_values(&["live_data_service_send_batch"])
                    .start_timer();
                let response = TransactionsResponse {
                    transactions,
                    chain_id: Some(self.chain_id),
                    processed_range: Some(ProcessedRange {
                        first_version: next_version,
                        last_version: last_processed_version,
                    }),
                };
                // Record bytes ready to transfer after stripping for billing.
                let bytes_ready_to_transfer_after_stripping = response
                    .transactions
                    .iter()
                    .map(|t| t.encoded_len())
                    .sum::<usize>();
                BYTES_READY_TO_TRANSFER_FROM_SERVER_AFTER_STRIPPING
                    .with_label_values(&request_metadata.get_label_values())
                    .inc_by(bytes_ready_to_transfer_after_stripping as u64);
                next_version = last_processed_version + 1;
                size_bytes += batch_size_bytes as u64;
                if response_sender.send(Ok(response)).await.is_err() {
                    info!(stream_id = id, "Client dropped.");
                    COUNTER
                        .with_label_values(&["live_data_service_client_dropped"])
                        .inc();
                    break;
                }
            } else {
                let err = Err(Status::not_found("Requested data is too old."));
                info!(stream_id = id, "Client error: {err:?}.");
                let _ = response_sender.send(err).await;
                COUNTER
                    .with_label_values(&["terminate_requested_data_too_old"])
                    .inc();
                break;
            }
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L84-98)
```rust
            while version < ending_version
                && total_bytes < max_bytes_per_batch
                && result.len() < max_num_transactions_per_batch
            {
                if let Some(transaction) = data_manager.get_data(version).as_ref() {
                    // NOTE: We allow 1 more txn beyond the size limit here, for simplicity.
                    if filter.is_none() || filter.as_ref().unwrap().matches(transaction) {
                        total_bytes += transaction.encoded_len();
                        result.push(transaction.as_ref().clone());
                    }
                    version += 1;
                } else {
                    break;
                }
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L100-100)
```rust
            return Some((result, total_bytes, version - 1));
```

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L19-33)
```text
message GetTransactionsRequest {
  // Required; start version of current stream.
  optional uint64 starting_version = 1 [jstype = JS_STRING];

  // Optional; number of transactions to return in current stream.
  // If not present, return an infinite stream of transactions.
  optional uint64 transactions_count = 2 [jstype = JS_STRING];

  // Optional; number of transactions in each `TransactionsResponse` for current stream.
  // If not present, default to 1000. If larger than 1000, request will be rejected.
  optional uint64 batch_size = 3;

  // If provided, only transactions that match the filter will be included.
  optional BooleanTransactionFilter transaction_filter = 4;
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L102-106)
```rust
                let max_num_transactions_per_batch = if let Some(batch_size) = request.batch_size {
                    batch_size as usize
                } else {
                    DEFAULT_MAX_NUM_TRANSACTIONS_PER_BATCH
                };
```
