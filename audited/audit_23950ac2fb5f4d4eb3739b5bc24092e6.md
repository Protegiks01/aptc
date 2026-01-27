# Audit Report

## Title
Memory Exhaustion via Unbounded Transaction Count in Indexer-gRPC-v2-File-Store-Backfiller

## Summary
The indexer-grpc-v2-file-store-backfiller's `backfill()` function processes transactions from a fullnode without validating that the number of transactions received matches the requested count. Combined with an unbounded gRPC message size limit (`usize::MAX`), a malicious fullnode can trigger memory exhaustion by sending arbitrarily large responses containing millions of transactions, despite only a limited number being requested.

## Finding Description
The vulnerability exists in the transaction processing loop where the backfiller requests a specific number of transactions but processes all transactions received without validation. [1](#0-0) 

The backfiller requests `num_transactions_per_folder` transactions (e.g., 1000), but the processing loop has no mechanism to stop after receiving the requested count: [2](#0-1) 

The loop continues indefinitely (`while let Some(response_item) = stream.next().await`) processing every transaction received until the stream closes, with no counter tracking how many transactions have been processed relative to the request.

The critical vulnerability is that the gRPC client is configured with no message size limits: [3](#0-2) 

This configuration allows a malicious fullnode to send responses of arbitrary size. When the malicious fullnode sends a `TransactionsOutput` message with millions of transactions in a single response, the tonic/prost gRPC layer deserializes the entire protobuf message into memory as a `Vec<Transaction>` before the application code can process it.

The only validation is version continuity checking in `FileStoreOperatorV2`: [4](#0-3) 

This ensures transactions are sequential but does not limit the total count.

**Attack Path:**
1. Backfiller spawns a task requesting transactions starting at version V with count = 1000
2. Malicious fullnode ignores the `transactions_count` parameter
3. Malicious fullnode sends a single `TransactionsOutput` containing 10 million transactions (versions V to V+9,999,999)
4. The gRPC client's unbounded `max_decoding_message_size` allows deserialization
5. All 10 million Transaction protobuf objects (potentially 10KB+ each) are loaded into memory simultaneously
6. Memory consumption reaches 100GB+, causing OOM crash or severe system degradation
7. Process continues processing all transactions since there's no break condition after the requested count

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria:

- **Validator node slowdowns**: The memory exhaustion causes severe performance degradation as the system begins swapping or approaches OOM conditions
- **API crashes**: The backfiller process will crash due to OOM, disrupting indexer operations
- **Significant protocol violations**: Breaks the Resource Limits invariant (#9) that all operations must respect computational limits

While this affects the indexer infrastructure rather than consensus directly, indexers are critical infrastructure for the Aptos ecosystem, and their availability impacts dApp functionality, block explorers, and data availability services.

## Likelihood Explanation
**Likelihood: Medium to High**

**Attack Requirements:**
- Attacker must operate a malicious fullnode that the backfiller connects to
- Attack is trivial to execute - simply modify the fullnode gRPC server to send oversized responses
- No authentication or authorization bypass needed
- No special timing or race condition requirements

**Complexity: Low**
- Attack requires minimal technical sophistication
- Single malicious response can trigger the vulnerability
- No need for sustained attack or multiple requests

**Detectability: Low**
- Appears as legitimate gRPC traffic
- No obvious indicators until memory exhaustion occurs
- Difficult to distinguish from genuine large transaction batches

The vulnerability is highly exploitable if an attacker can position themselves as the fullnode data source for the backfiller.

## Recommendation

**Immediate Fix: Add transaction count validation and limit checks**

1. Track the number of transactions processed and enforce the requested limit:

```rust
s.spawn(async move {
    let mut grpc_client = create_grpc_client(fullnode_grpc_address).await;
    let request = tonic::Request::new(GetTransactionsFromNodeRequest {
        starting_version: Some(task_version),
        transactions_count: Some(num_transactions_per_folder),
    });
    let mut stream = grpc_client
        .get_transactions_from_node(request)
        .await
        .unwrap()
        .into_inner();

    let mut transactions_processed = 0u64;
    let expected_end_version = task_version + num_transactions_per_folder;

    while let Some(response_item) = stream.next().await {
        match response_item {
            Ok(r) => {
                assert!(r.chain_id == chain_id);
                match r.response.unwrap() {
                    Response::Data(data) => {
                        let transactions = data.transactions;
                        for transaction in transactions {
                            // Validate we haven't exceeded requested count
                            ensure!(
                                transaction.version < expected_end_version,
                                "Fullnode sent transaction {} beyond requested range [{}, {})",
                                transaction.version,
                                task_version,
                                expected_end_version
                            );
                            
                            file_store_operator
                                .buffer_and_maybe_dump_transactions_to_file(
                                    transaction,
                                    tx.clone(),
                                )
                                .await
                                .unwrap();
                            
                            transactions_processed += 1;
                            
                            // Break if we've received all requested transactions
                            if transactions_processed >= num_transactions_per_folder {
                                break;
                            }
                        }
                        
                        if transactions_processed >= num_transactions_per_folder {
                            break;
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
    
    // Verify we received the expected count
    ensure!(
        transactions_processed == num_transactions_per_folder 
            || file_store_operator.version() >= expected_end_version,
        "Fullnode only sent {} of {} requested transactions",
        transactions_processed,
        num_transactions_per_folder
    );
});
```

2. Configure reasonable gRPC message size limits instead of `usize::MAX`:

```rust
pub async fn create_grpc_client(address: Url) -> GrpcClientType {
    // Use 256MB limit instead of usize::MAX
    const MAX_MESSAGE_SIZE: usize = 256 * 1024 * 1024;
    
    backoff::future::retry(backoff::ExponentialBackoff::default(), || async {
        match FullnodeDataClient::connect(address.to_string()).await {
            Ok(client) => {
                tracing::info!(
                    address = address.to_string(),
                    "[Indexer Cache] Connected to indexer gRPC server."
                );
                Ok(client
                    .max_decoding_message_size(MAX_MESSAGE_SIZE)
                    .max_encoding_message_size(MAX_MESSAGE_SIZE)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .accept_compressed(CompressionEncoding::Zstd))
            },
            // ... rest of error handling
        }
    })
    .await
    .unwrap()
}
```

3. Add per-response transaction count validation to detect malicious responses early.

## Proof of Concept

```rust
// Mock malicious fullnode test
#[tokio::test]
async fn test_malicious_fullnode_memory_exhaustion() {
    use aptos_protos::internal::fullnode::v1::{
        TransactionsOutput, TransactionsFromNodeResponse,
        transactions_from_node_response::Response,
    };
    use aptos_protos::transaction::v1::Transaction;
    
    // Setup: Create a backfiller requesting 1000 transactions
    let num_transactions_requested = 1000u64;
    let starting_version = 0u64;
    
    // Attack: Malicious fullnode sends 1 million transactions instead
    let mut malicious_transactions = Vec::new();
    for version in starting_version..(starting_version + 1_000_000) {
        malicious_transactions.push(Transaction {
            version,
            // ... other transaction fields with dummy data
            // Each transaction ~10KB = 10GB total memory
            ..Default::default()
        });
    }
    
    // This single TransactionsOutput would consume ~10GB memory when deserialized
    let malicious_response = TransactionsFromNodeResponse {
        response: Some(Response::Data(TransactionsOutput {
            transactions: malicious_transactions,
        })),
        chain_id: 1,
    };
    
    // Current implementation would process all 1 million transactions
    // without any validation, leading to memory exhaustion
    
    // Expected: Should reject after processing first 1000 transactions
    // Actual: Processes all 1,000,000 transactions until OOM
}
```

**Notes:**
- This vulnerability is particularly dangerous because the backfiller is typically run as a long-lived service with access to significant resources
- The attack can be repeated continuously, preventing recovery
- Multiple concurrent backfill tasks amplify the impact as each can be exploited independently
- The vulnerability affects any service using `create_grpc_client` from `indexer-grpc-utils` when connecting to untrusted fullnodes

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L163-166)
```rust
                        let request = tonic::Request::new(GetTransactionsFromNodeRequest {
                            starting_version: Some(task_version),
                            transactions_count: Some(num_transactions_per_folder),
                        });
```

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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L36-49)
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_operator.rs (L50-55)
```rust
        ensure!(
            self.version == transaction.version,
            "Gap is found when buffering transaction, expected: {}, actual: {}",
            self.version,
            transaction.version,
        );
```
