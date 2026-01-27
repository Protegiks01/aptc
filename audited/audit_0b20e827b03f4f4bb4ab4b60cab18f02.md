# Audit Report

## Title
Missing Chain ID Validation in Indexer File Store Backfiller Allows Cross-Chain Data Corruption

## Summary
The indexer file store backfiller fails to validate the chain ID from the fullnode gRPC stream, allowing wrong-chain transaction data to be written to the file store when misconfigured. This breaks state consistency invariants and can lead to severe data corruption affecting all downstream consumers.

## Finding Description

The indexer-grpc-file-store-backfiller is responsible for backfilling historical transaction data from a fullnode into the file store. While it validates that the local file store metadata's chain ID matches the expected configuration parameter, it completely fails to validate the chain ID of data received from the fullnode gRPC stream. [1](#0-0) 

The backfiller receives an init frame from the fullnode stream but does not extract or validate the chain_id field: [2](#0-1) 

Throughout the streaming loop, the backfiller processes TransactionsFromNodeResponse without ever checking the chain_id field that exists in each response: [3](#0-2) 

In contrast, the cache worker implements comprehensive chain ID validation through the `verify_fullnode_init_signal` function: [4](#0-3) 

Additionally, the cache worker validates chain_id in every streaming response: [5](#0-4) 

The fullnode data service includes chain_id in every response: [6](#0-5) 

**Attack Path:**
1. Operator misconfigures backfiller with wrong-chain fullnode URL (e.g., testnet node instead of mainnet)
2. Backfiller connects successfully and receives init signal with wrong chain_id (not validated)
3. Backfiller receives and processes transactions with wrong chain_id in each response (not validated)
4. Wrong-chain transactions are written to file store
5. Downstream consumers (data services, indexers) read corrupted cross-chain data
6. State reconstruction produces incorrect results, leading to application-level failures

## Impact Explanation

This vulnerability represents a **HIGH severity** issue under the Aptos bug bounty program's "State inconsistencies requiring intervention" category.

**Impact:**
- **Data Corruption**: File store contains mixed data from different chains (testnet/mainnet/devnet)
- **State Inconsistency**: Violates the critical invariant that "State transitions must be atomic and verifiable via Merkle proofs" because cross-chain data has incompatible state roots
- **Downstream Failures**: All systems consuming from the file store (indexers, analytics, explorers) receive corrupted data
- **Loss of Data Integrity**: Once written, wrong-chain data requires manual intervention and potential file store rebuild
- **Application-Level Impact**: DApps and services relying on indexer data make incorrect decisions based on wrong-chain events

The severity is HIGH rather than CRITICAL because:
- Does not directly affect consensus or validator operations
- Does not cause fund loss (only data corruption)
- Requires operator misconfiguration (not a direct exploit)
- Can be recovered through file store rebuild (intervention required)

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

This vulnerability is likely to occur because:

1. **Common Misconfiguration**: Operators frequently work with multiple networks (mainnet, testnet, devnet) and may accidentally use wrong URLs in configuration
2. **No Safeguards**: The system provides no warning or validation when connecting to a wrong-chain node
3. **Silent Failure**: Wrong-chain data is accepted and written without any error indicators
4. **Operational Complexity**: Managing multiple environments increases misconfiguration risk
5. **Social Engineering**: An attacker could socially engineer an operator to use a malicious fullnode URL claiming it's the correct network

The vulnerability does not require:
- Privileged access to validator nodes
- Consensus participation
- Deep technical knowledge to exploit
- Multiple coordinated actors

## Recommendation

Implement comprehensive chain ID validation in the file store backfiller, following the same pattern used in the cache worker:

1. **Validate Init Signal**: Extract and validate chain_id from the init frame against the expected configuration
2. **Validate Streaming Responses**: Check chain_id in every TransactionsFromNodeResponse
3. **Fail Fast**: Panic or return error immediately on chain ID mismatch

**Code Fix for `processor.rs`:**

```rust
// After receiving init frame (around line 169), add:
let fullnode_chain_id = match init_frame {
    Response::Status(signal) => {
        if signal.r#type() != StatusType::Init {
            anyhow::bail!("Unexpected status signal type");
        }
        // Extract chain_id from the first response
        // (need to get it from the actual response wrapper)
        init_signal.chain_id // from TransactionsFromNodeResponse
    },
    _ => {
        anyhow::bail!("Unexpected response type");
    },
};

// Validate against expected chain_id
if fullnode_chain_id as u64 != chain_id {
    anyhow::bail!(
        "Chain ID mismatch: fullnode returned {}, but expected {}",
        fullnode_chain_id,
        chain_id
    );
}

// In the streaming loop (around line 274), add after getting response:
if response.chain_id as u64 != chain_id {
    panic!(
        "[Backfiller] Chain ID mismatch during streaming: got {}, expected {}",
        response.chain_id, chain_id
    );
}
```

The fix should mirror the validation pattern in: [4](#0-3) 

## Proof of Concept

**Rust Integration Test Scenario:**

```rust
// PoC demonstrating the vulnerability
#[tokio::test]
async fn test_backfiller_accepts_wrong_chain_data() {
    // Setup:
    // 1. Start a testnet fullnode (chain_id = 2)
    // 2. Configure backfiller expecting mainnet (chain_id = 1)
    // 3. Point backfiller at testnet fullnode
    
    let testnet_fullnode_url = "http://testnet-fullnode:50051";
    let expected_chain_id = 1; // mainnet
    
    // Create backfiller expecting mainnet but connecting to testnet
    let processor = Processor::new(
        Url::parse(testnet_fullnode_url).unwrap(),
        file_store_config,
        expected_chain_id, // mainnet
        enable_cache_compression,
        progress_file_path,
        Some(0),
        Some(1000),
        false,
        1,
        1,
    ).await.unwrap();
    
    // Start backfill - should fail but currently succeeds
    let result = processor.backfill().await;
    
    // VULNERABILITY: Backfiller accepts testnet data for mainnet file store
    // Expected: Error with chain ID mismatch
    // Actual: Success, testnet data written to mainnet file store
    
    // Verify wrong-chain data was written
    let transactions = file_store_operator.get_transactions(0, 1).await.unwrap();
    // These transactions have testnet chain_id but are in mainnet file store
    assert_eq!(transactions[0].chain_id, 2); // testnet
    // File store metadata still says chain_id = 1 (mainnet)
    let metadata = file_store_operator.get_file_store_metadata().await.unwrap();
    assert_eq!(metadata.chain_id, 1); // mainnet
    
    // Result: Cross-chain data corruption
}
```

**Steps to Reproduce:**
1. Deploy indexer-grpc-file-store-backfiller with mainnet file store configuration (chain_id=1)
2. Configure backfiller to connect to testnet fullnode URL
3. Start backfill operation
4. Observe that testnet transactions are successfully written to mainnet file store
5. Verify file store metadata shows chain_id=1 but contains chain_id=2 transactions
6. Downstream consumers reading from file store receive mixed-chain data

## Notes

The v2-file-store-backfiller has a partial mitigation with an assert statement: [7](#0-6) 

However, this is insufficient because:
1. It only validates during data processing, not at connection initialization
2. It doesn't follow the comprehensive validation pattern of the cache worker
3. Asserts can be compiled out in some build configurations

The proper validation pattern is demonstrated in the cache worker and should be replicated in all backfiller implementations.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L115-119)
```rust
        let file_store_operator: Box<dyn FileStoreOperator> = file_store_config.create();
        file_store_operator.verify_storage_bucket_existence().await;
        // Metadata is guaranteed to exist now
        let metadata = file_store_operator.get_file_store_metadata().await.unwrap();
        ensure!(metadata.chain_id == chain_id, "Chain ID mismatch.");
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L154-169)
```rust
        let init_frame = grpc_stream
            .next()
            .await
            .expect("Failed to get the first frame")?
            .response
            .unwrap();
        match init_frame {
            Response::Status(signal) => {
                if signal.r#type() != StatusType::Init {
                    anyhow::bail!("Unexpected status signal type");
                }
            },
            _ => {
                anyhow::bail!("Unexpected response type");
            },
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L265-302)
```rust
        loop {
            let item = grpc_stream.next().await;
            let item = item.unwrap();
            let response = match item {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!("Failed to get response: {:?}", e);
                    panic!("Failed to get response: {:?}", e);
                },
            };

            let resp = response.response.unwrap();
            match resp {
                Response::Data(txns) => {
                    let transactions = txns.transactions;
                    for txn in transactions {
                        let version = txn.version;
                        // Partial batch may be received; split and insert into buffer.
                        transactions_buffer.insert(version, txn);
                    }
                },
                Response::Status(signal) => {
                    if signal.r#type() != StatusType::BatchEnd {
                        anyhow::bail!("Unexpected status signal type");
                    }
                    while transactions_buffer.len() >= 1000 {
                        // Take the first 1000 transactions.
                        let mut transactions = Vec::new();
                        // Pop the first 1000 transactions from buffer.
                        for _ in 0..1000 {
                            let (_, txn) = transactions_buffer.pop_first().unwrap();
                            transactions.push(txn);
                        }
                        sender.send(transactions).await?;
                    }
                },
            }
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L286-325)
```rust
async fn verify_fullnode_init_signal(
    cache_operator: &mut CacheOperator<redis::aio::ConnectionManager>,
    init_signal: TransactionsFromNodeResponse,
    file_store_metadata: FileStoreMetadata,
) -> Result<(ChainID, StartingVersion)> {
    let (fullnode_chain_id, starting_version) = match init_signal
        .response
        .expect("[Indexer Cache] Response type does not exist.")
    {
        Response::Status(status_frame) => {
            match StatusType::try_from(status_frame.r#type)
                .expect("[Indexer Cache] Invalid status type.")
            {
                StatusType::Init => (init_signal.chain_id, status_frame.start_version),
                _ => {
                    bail!("[Indexer Cache] Streaming error: first frame is not INIT signal.");
                },
            }
        },
        _ => {
            bail!("[Indexer Cache] Streaming error: first frame is not siganl frame.");
        },
    };

    // Guaranteed that chain id is here at this point because we already ensure that fileworker did the set up
    let chain_id = cache_operator.get_chain_id().await?.unwrap();
    if chain_id != fullnode_chain_id as u64 {
        bail!("[Indexer Cache] Chain ID mismatch between fullnode init signal and cache.");
    }

    // It's required to start the worker with the same version as file store.
    if file_store_metadata.version != starting_version {
        bail!("[Indexer Cache] Starting version mismatch between filestore metadata and fullnode init signal.");
    }
    if file_store_metadata.chain_id != fullnode_chain_id as u64 {
        bail!("[Indexer Cache] Chain id mismatch between filestore metadata and fullnode.");
    }

    Ok((fullnode_chain_id, starting_version))
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L382-384)
```rust
        if received.chain_id as u64 != fullnode_chain_id as u64 {
            panic!("[Indexer Cache] Chain id mismatch happens during data streaming.");
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L245-261)
```rust
pub fn get_status(
    status_type: StatusType,
    start_version: u64,
    end_version: Option<u64>,
    ledger_chain_id: u8,
) -> TransactionsFromNodeResponse {
    TransactionsFromNodeResponse {
        response: Some(transactions_from_node_response::Response::Status(
            StreamStatus {
                r#type: status_type as i32,
                start_version,
                end_version,
            },
        )),
        chain_id: ledger_chain_id as u32,
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L176-176)
```rust
                                    assert!(r.chain_id == chain_id);
```
