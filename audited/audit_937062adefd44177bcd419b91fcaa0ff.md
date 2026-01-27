# Audit Report

## Title
Indexer gRPC Data Service Resource Exhaustion via Infinite Retry Loop in fetch_transactions()

## Summary
The `fetch_transactions()` function in the indexer-grpc-data-service-v2 contains an infinite retry loop with no timeout or error handling when gRPC backend calls fail. An attacker can trigger backend errors by requesting invalid transaction versions, causing service threads to hang indefinitely and leading to resource exhaustion and denial of service on the indexer API.

## Finding Description

The vulnerability exists in the `DataClient::fetch_transactions()` method which fetches transaction data from the gRPC manager backend: [1](#0-0) 

The function contains an infinite loop (line 27) with incomplete error handling. When the gRPC call fails or returns mismatched transaction versions, the loop continues indefinitely without any timeout, retry limit, or error propagation (line 41 explicitly notes "TODO(grao): Error handling").

**Attack Path:**

1. Attacker sends a `GetTransactionsRequest` with `starting_version` set to a value that will cause backend errors (e.g., version 0 or very old versions not in file storage)

2. The `LiveDataService` validates the version is not too far in the future but has **no lower bound validation**: [2](#0-1) 

3. When the requested version is not in cache, `InMemoryCache.get_data()` calls `fetch_past_data()`: [3](#0-2) 

4. This eventually calls `fetch_transactions()` which makes a gRPC call to the backend manager

5. The backend `DataManager.get_transactions()` attempts to fetch from file store for old versions. If the data is unavailable or corrupted, it returns an error: [4](#0-3) 

6. When `fetch_transactions()` receives this error response, it continues the loop indefinitely with no timeout

7. Multiple concurrent requests cause multiple threads to become stuck, exhausting thread pool resources and rendering the indexer API unresponsive

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program criteria:
- **"API crashes"** - The indexer gRPC API becomes unresponsive due to thread pool exhaustion
- **"Validator node slowdowns"** - While this doesn't directly affect consensus validators, the indexer is critical infrastructure that applications depend on

The impact is limited to the indexer service availability and does not affect:
- Core consensus protocol
- On-chain state or execution  
- Validator operations
- Fund security

However, the indexer API is essential for dApps, explorers, and other ecosystem services that query blockchain data. Sustained unavailability impacts the broader Aptos ecosystem functionality.

## Likelihood Explanation

**High Likelihood:**
- Attack requires only sending standard gRPC requests with specific version parameters
- No authentication or special privileges needed
- The vulnerable code path is easily triggered by requesting old or invalid versions
- Attacker can open multiple concurrent streams to accelerate resource exhaustion
- The infinite loop has no built-in mitigation (timeout, retry limit, circuit breaker)

## Recommendation

Implement proper error handling with retry limits and timeouts:

```rust
pub(super) async fn fetch_transactions(&self, starting_version: u64) -> Result<Vec<Transaction>, anyhow::Error> {
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY: Duration = Duration::from_millis(500);
    
    trace!("Fetching transactions from GrpcManager, start_version: {starting_version}.");

    let request = GetTransactionsRequest {
        starting_version: Some(starting_version),
        transactions_count: None,
        batch_size: None,
        transaction_filter: None,
    };
    
    for attempt in 0..MAX_RETRIES {
        let mut client = self
            .connection_manager
            .get_grpc_manager_client_for_request();
        
        match client.get_transactions(request.clone()).await {
            Ok(response) => {
                let transactions = response.into_inner().transactions;
                if transactions.is_empty() {
                    return Ok(vec![]);
                }
                if transactions.first().unwrap().version == starting_version {
                    return Ok(transactions);
                }
                warn!("Version mismatch: expected {}, got {}", starting_version, transactions.first().unwrap().version);
            }
            Err(e) => {
                error!("Failed to fetch transactions (attempt {}): {:?}", attempt + 1, e);
                if attempt < MAX_RETRIES - 1 {
                    tokio::time::sleep(RETRY_DELAY).await;
                    continue;
                }
            }
        }
    }
    
    bail!("Failed to fetch transactions after {} retries for version {}", MAX_RETRIES, starting_version)
}
```

Additionally, add lower bound validation in `LiveDataService`: [5](#0-4) 

Add validation after line 83:

```rust
let starting_version = request.starting_version.unwrap_or(known_latest_version);

// Add lower bound check
let min_servable_version = self.get_min_servable_version().await;
if starting_version < min_servable_version {
    let err = Err(Status::failed_precondition(
        format!("starting_version {} is too old, minimum servable version is {}", 
                starting_version, min_servable_version)
    ));
    info!("Client error: {err:?}.");
    let _ = response_sender.blocking_send(err);
    continue;
}
```

## Proof of Concept

```rust
// PoC: Trigger infinite loop via old version request
use aptos_protos::indexer::v1::GetTransactionsRequest;
use tonic::Request;

#[tokio::test]
async fn test_infinite_loop_dos() {
    // Setup indexer-grpc data service (assume standard test setup)
    let data_service = setup_test_data_service().await;
    
    // Request version 0 which is likely not in file store
    let request = Request::new(GetTransactionsRequest {
        starting_version: Some(0),
        transactions_count: None,
        batch_size: None,
        transaction_filter: None,
    });
    
    // This call will hang indefinitely if the backend returns errors
    // In production, multiple such requests would exhaust thread pool
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        data_service.get_transactions(request)
    ).await;
    
    // Should timeout, demonstrating the hang
    assert!(response.is_err(), "Request should timeout due to infinite retry loop");
}
```

## Notes

This vulnerability affects only the indexer-grpc data service, not the core consensus protocol. While the impact is limited to API availability rather than consensus safety or fund security, the indexer service is critical infrastructure for the Aptos ecosystem. The missing error handling represents a clear deviation from robust production service standards and enables easy denial-of-service attacks.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_client.rs (L18-43)
```rust
    pub(super) async fn fetch_transactions(&self, starting_version: u64) -> Vec<Transaction> {
        trace!("Fetching transactions from GrpcManager, start_version: {starting_version}.");

        let request = GetTransactionsRequest {
            starting_version: Some(starting_version),
            transactions_count: None,
            batch_size: None,
            transaction_filter: None,
        };
        loop {
            let mut client = self
                .connection_manager
                .get_grpc_manager_client_for_request();
            let response = client.get_transactions(request.clone()).await;
            if let Ok(response) = response {
                let transactions = response.into_inner().transactions;
                if transactions.is_empty() {
                    return vec![];
                }
                if transactions.first().unwrap().version == starting_version {
                    return transactions;
                }
            }
            // TODO(grao): Error handling.
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L82-96)
```rust
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L73-76)
```rust
            if data_manager.get_data(starting_version).is_none() {
                drop(data_manager);
                self.fetch_manager.fetch_past_data(starting_version).await;
                continue;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L366-371)
```rust
            let error_msg = "Failed to fetch transactions from filestore, either filestore is not available, or data is corrupted.";
            // TODO(grao): Consider downgrade this to warn! if this happens too frequently when
            // filestore is unavailable.
            error!(error_msg);
            bail!(error_msg);
        }
```
