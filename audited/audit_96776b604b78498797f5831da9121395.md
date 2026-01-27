# Audit Report

## Title
Transaction History Data Gap Vulnerability in Indexer gRPC Service Router

## Summary
The `DataServiceWrapperWrapper` in the indexer-grpc data service contains a critical routing flaw that creates gaps in transaction history when both historical and live services are running. The service makes a one-time routing decision at stream initialization but never switches between services mid-stream, causing clients to miss transactions when the historical service terminates prematurely.

## Finding Description

The vulnerability exists in the service routing logic that decides between historical and live data services. When a client requests transaction history and both services are available, the code performs a single peek operation to determine which service to use for the entire stream duration. [1](#0-0) 

The critical flaw is that once the historical service is selected, there is no mechanism to switch to the live service when the historical stream terminates. The historical service has an early termination condition where it stops streaming when transaction timestamps are within 60 seconds of current time: [2](#0-1) [3](#0-2) 

Meanwhile, the live service only maintains recent transactions in its in-memory cache and returns an error for versions below its minimum servable version: [4](#0-3) 

**Exploitation Scenario:**

1. Live service cache contains versions 10000-10500 (min_servable_version = 10000)
2. Historical file store contains versions 0-10500
3. Client requests: `starting_version = 1000`, no `transactions_count` (infinite stream)
4. Router peeks live service → sees error (1000 < 10000, "data too old")
5. Router falls back to historical service
6. Historical service streams versions 1000...9900
7. At version 9900, timestamp check triggers: delta < 60 seconds → `close_to_latest = true`
8. Historical service terminates stream (line 272)
9. Client receives versions 1000-9900, stream ends normally
10. **Gap created:** Client never receives versions 9901-10500 which ARE available in both services

The client has no indication that data is missing. The stream terminates normally with no error, and the `ProcessedRange` in the last response only indicates what was processed, not what was skipped. [5](#0-4) 

## Impact Explanation

This vulnerability represents a **High severity** data integrity violation per the Aptos bug bounty criteria for "Significant protocol violations." While the indexer-grpc service is infrastructure rather than core consensus, it is a critical component of the Aptos ecosystem that applications, wallets, and analytics platforms depend on for complete transaction history.

**Specific impacts:**

1. **Silent Data Loss**: Applications consuming the indexer stream receive incomplete transaction history without any error indication, leading to:
   - Incorrect account balance calculations
   - Missing transaction events for smart contract monitoring
   - Incomplete audit trails for compliance systems
   - Broken transaction ordering assumptions

2. **Protocol Violation**: The gRPC streaming protocol contract promises complete transaction delivery for the requested range. This bug violates that guarantee by silently omitting available transactions.

3. **Downstream System Corruption**: Indexer clients (block explorers, wallets, analytics platforms) that rely on complete history will have corrupted local state that's difficult to detect and repair.

4. **Operational Impact**: This affects all production deployments where both services run together (the recommended configuration), making it a widespread operational issue rather than an edge case.

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers in normal production conditions:

- **Trigger Frequency**: Occurs whenever clients request historical transactions that span the boundary between file store and live cache during the 60-second "close to latest" window
- **No Privilege Required**: Any indexer client can trigger this simply by requesting old transaction history
- **Production Configuration**: Both services running together is the recommended production setup for high availability
- **No Detection**: Clients have no built-in mechanism to detect gaps, making the issue persist unnoticed
- **Timing Window**: The 60-second threshold creates a constant window where this can occur as new transactions arrive

## Recommendation

**Fix: Implement seamless service handoff with gap detection**

The router should chain both services together when a request spans their boundaries:

```rust
async fn get_transactions(
    &self,
    req: Request<GetTransactionsRequest>,
) -> Result<Response<Self::GetTransactionsStream>, Status> {
    if let Some(live_data_service) = self.live_data_service.as_ref() {
        if let Some(historical_data_service) = self.historical_data_service.as_ref() {
            let request = req.into_inner();
            let starting_version = request.starting_version.unwrap_or(0);
            
            // Get live service's min servable version
            let min_live_version = live_data_service.get_min_servable_version().await;
            
            if starting_version >= min_live_version {
                // Request is within live range, use live service only
                return live_data_service
                    .get_transactions(Request::new(request))
                    .await;
            }
            
            // Request starts in historical range
            // Create chained stream: historical → live
            let (tx, rx) = channel(10);
            let hist_svc = historical_data_service.clone();
            let live_svc = live_data_service.clone();
            
            tokio::spawn(async move {
                let mut last_version = starting_version;
                
                // Stream from historical service
                let mut hist_stream = hist_svc
                    .get_transactions(Request::new(request.clone()))
                    .await?
                    .into_inner();
                    
                while let Some(result) = hist_stream.next().await {
                    match result {
                        Ok(response) => {
                            if let Some(range) = &response.processed_range {
                                last_version = range.last_version;
                            }
                            if tx.send(Ok(response)).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    }
                }
                
                // Continue from live service if there's a gap
                if last_version + 1 < min_live_version {
                    // Gap detected! Continue with live service
                    let mut live_request = request.clone();
                    live_request.starting_version = Some(last_version + 1);
                    
                    let mut live_stream = live_svc
                        .get_transactions(Request::new(live_request))
                        .await?
                        .into_inner();
                        
                    while let Some(result) = live_stream.next().await {
                        if tx.send(result).await.is_err() {
                            return;
                        }
                    }
                }
            });
            
            let output_stream = ReceiverStream::new(rx);
            return Ok(Response::new(Box::pin(output_stream) as Self::GetTransactionsStream));
        }
        // ... rest of logic
    }
    // ... rest of logic
}
```

**Additional recommendations:**
1. Add explicit gap detection and warning metrics
2. Extend historical service's "close_to_latest" threshold or make it configurable
3. Implement overlap region between services to prevent gaps
4. Add client-facing API to query service boundaries and detect potential gaps

## Proof of Concept

```rust
#[tokio::test]
async fn test_transaction_history_gap() {
    // Setup: Create both services with known boundaries
    // - Historical service: has transactions 0-9999 in file store
    // - Live service: has transactions 10000-10500 in cache (min_servable = 10000)
    
    let (hist_tx, hist_rx) = channel(10);
    let (live_tx, live_rx) = channel(10);
    
    let historical_service = DataServiceWrapper::new(
        Arc::new(ConnectionManager::new(1, 0)),
        hist_tx,
        100,
        false, // is_live = false
    );
    
    let live_service = DataServiceWrapper::new(
        Arc::new(ConnectionManager::new(1, 10000)),
        live_tx,
        100,
        true, // is_live = true
    );
    
    let wrapper = DataServiceWrapperWrapper::new(
        Some(live_service),
        Some(historical_service),
    );
    
    // Request starting from version 1000, no count limit (infinite stream)
    let request = GetTransactionsRequest {
        starting_version: Some(1000),
        transactions_count: None,
        batch_size: Some(100),
        transaction_filter: None,
    };
    
    // Execute request
    let mut stream = wrapper
        .get_transactions(Request::new(request))
        .await
        .unwrap()
        .into_inner();
    
    let mut last_version = 0;
    let mut total_transactions = 0;
    
    while let Some(result) = stream.next().await {
        let response = result.unwrap();
        if let Some(range) = response.processed_range {
            last_version = range.last_version;
        }
        total_transactions += response.transactions.len();
    }
    
    // Bug manifestation: stream ends at ~9900 instead of 10500
    // Expected: last_version >= 10500
    // Actual: last_version < 10000 (gap of 500+ transactions)
    assert!(
        last_version >= 10500,
        "Gap detected! Stream ended at version {} but should reach at least 10500. \
         Missing versions {}-10500",
        last_version,
        last_version + 1
    );
}
```

## Notes

This vulnerability is specific to the indexer-grpc infrastructure component rather than core blockchain consensus. However, it represents a significant reliability and data integrity issue for the Aptos ecosystem, as many critical applications depend on the indexer for complete transaction history. The silent nature of the data loss makes it particularly dangerous, as downstream systems may operate with incomplete information without detecting the gap.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/service.rs (L47-63)
```rust
        if let Some(live_data_service) = self.live_data_service.as_ref() {
            if let Some(historical_data_service) = self.historical_data_service.as_ref() {
                let request = req.into_inner();
                let mut stream = live_data_service
                    .get_transactions(Request::new(request.clone()))
                    .await?
                    .into_inner();
                let peekable = std::pin::pin!(stream.as_mut().peekable());
                if let Some(Ok(_)) = peekable.peek().await {
                    return live_data_service
                        .get_transactions(Request::new(request.clone()))
                        .await;
                }

                historical_data_service
                    .get_transactions(Request::new(request))
                    .await
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L198-200)
```rust
                if delta < Duration::from_secs(60) {
                    close_to_latest = true;
                }
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L225-233)
```rust
            } else {
                let err = Err(Status::not_found("Requested data is too old."));
                info!(stream_id = id, "Client error: {err:?}.");
                let _ = response_sender.send(err).await;
                COUNTER
                    .with_label_values(&["terminate_requested_data_too_old"])
                    .inc();
                break;
            }
```

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L35-49)
```text
message ProcessedRange {
    uint64 first_version = 1;
    uint64 last_version = 2;
}

// TransactionsResponse is a batch of transactions.
message TransactionsResponse {
  // Required; transactions data.
  repeated aptos.transaction.v1.Transaction transactions = 1;

  // Required; chain id.
  optional uint64 chain_id = 2 [jstype = JS_STRING];

  optional ProcessedRange processed_range = 3;
}
```
