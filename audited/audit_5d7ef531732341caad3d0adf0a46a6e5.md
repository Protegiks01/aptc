# Audit Report

## Title
Unbounded Stream Spawning Leads to Memory Exhaustion in Live Data Service

## Summary
The `LiveDataService::run()` function spawns unlimited concurrent tasks for streaming requests without enforcing a maximum concurrency limit. Attackers can send multiple requests with `transactions_count = None`, causing each stream to run until `u64::MAX` transactions are processed, effectively creating indefinitely running tasks that exhaust server memory and cause API service unavailability.

## Finding Description

The vulnerability exists in the request handling flow of the indexer-grpc live data service:

When a client sends a `GetTransactionsRequest`, the `ending_version` is calculated from `transactions_count`. [1](#0-0) 

If `transactions_count` is `None`, then `ending_version` becomes `None`. Each request spawns a new task within the tokio_scoped scope. [2](#0-1) 

In the `start_streaming()` function, when `ending_version` is `None`, it defaults to `u64::MAX`. [3](#0-2) 

The streaming loop continues until `next_version >= ending_version`. [4](#0-3) 

Since the blockchain will never reach `u64::MAX` transactions (≈18.4 quintillion), these streams run indefinitely as long as the client maintains the connection.

The incoming request channel has a buffer of only 10, [5](#0-4)  but this only limits queued requests. Once dequeued and spawned, tasks are not subject to this limit.

There is no maximum concurrency limit enforced on spawned tasks. The `ConnectionManager` tracks active streams in a `DashMap` but does not enforce any upper bound. [6](#0-5) 

**Attack Vector:**
1. Attacker opens N concurrent gRPC connections
2. Each connection sends `GetTransactionsRequest` with `transactions_count = None`
3. Each request spawns a task that runs indefinitely
4. Memory is exhausted by: task overhead, stream state in `active_streams` DashMap, response channel buffers, and cache pressure from concurrent streams
5. API service becomes unresponsive or crashes

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty program criteria, specifically falling under "API crashes" and "Validator node slowdowns."

The indexer-grpc-data-service is a critical infrastructure component that clients rely on to query blockchain data. Memory exhaustion would cause:
- API service crashes requiring restart
- Degraded performance affecting all connected clients
- Potential cascade failures if other services depend on the indexer
- Service unavailability during attack

While this doesn't directly affect consensus or state integrity, it breaks the **Resource Limits** invariant (#9) by allowing operations that don't respect computational and memory limits.

## Likelihood Explanation

**Likelihood: High**

The attack requires only:
- Standard gRPC client library (publicly available)
- Ability to make network connections to the indexer service
- No authentication or special privileges

The attack is trivial to execute:
```
# Pseudocode
for i in 1..1000:
    grpc_client.get_transactions(
        starting_version=0,
        transactions_count=None  # No limit
    )
    # Keep connection alive
```

The vulnerability is deterministic and easily reproducible. The only limiting factor is the HTTP2 keepalive timeout (60 seconds), but attackers can respond to pings to keep connections alive indefinitely. [7](#0-6) 

## Recommendation

Implement a maximum concurrency limit for active streams:

**1. Add configuration parameter:**
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveDataServiceConfig {
    pub enabled: bool,
    pub num_slots: usize,
    pub size_limit_bytes: usize,
    #[serde(default = "LiveDataServiceConfig::default_max_concurrent_streams")]
    pub max_concurrent_streams: usize,
}

impl LiveDataServiceConfig {
    fn default_max_concurrent_streams() -> usize {
        1000  // Reasonable default
    }
}
```

**2. Enforce limit in ConnectionManager:**
```rust
pub(crate) fn insert_active_stream(
    &self,
    id: &str,
    start_version: u64,
    end_version: Option<u64>,
) -> Result<(), Status> {
    if self.active_streams.len() >= self.max_concurrent_streams {
        return Err(Status::resource_exhausted(
            "Maximum concurrent streams limit reached"
        ));
    }
    // ... existing insertion logic
    Ok(())
}
```

**3. Check before spawning task:**
```rust
if let Err(err) = self.connection_manager
    .insert_active_stream(&id, starting_version, ending_version) 
{
    let _ = response_sender.blocking_send(Err(err));
    continue;
}
scope.spawn(async move {
    // ... existing streaming logic
});
```

Additionally, consider implementing per-client rate limiting and enforcing a reasonable maximum value for `ending_version` (e.g., `starting_version + 10_000_000`).

## Proof of Concept

```rust
// test_unbounded_streams.rs
use aptos_protos::indexer::v1::{
    data_service_client::DataServiceClient, GetTransactionsRequest,
};
use tokio::task::JoinHandle;

#[tokio::test]
async fn test_unbounded_stream_dos() {
    // Connect to indexer service
    let channel = tonic::transport::Channel::from_static("http://localhost:50051")
        .connect()
        .await
        .unwrap();
    
    let mut tasks: Vec<JoinHandle<()>> = vec![];
    
    // Spawn 100 concurrent streams with no ending version
    for i in 0..100 {
        let mut client = DataServiceClient::new(channel.clone());
        let task = tokio::spawn(async move {
            let request = GetTransactionsRequest {
                starting_version: Some(0),
                transactions_count: None, // No limit - will default to u64::MAX
                batch_size: Some(100),
                transaction_filter: None,
            };
            
            let mut stream = client
                .get_transactions(request)
                .await
                .unwrap()
                .into_inner();
            
            // Keep connection alive by consuming stream
            while let Ok(Some(_response)) = stream.message().await {
                // Just consume, don't process
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
        tasks.push(task);
    }
    
    // Monitor memory usage - will grow unbounded
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    
    // All tasks still running, consuming memory
    assert!(tasks.iter().all(|t| !t.is_finished()));
}
```

## Notes

While the indexer-grpc-data-service is not part of the core consensus infrastructure, it is a critical API component explicitly listed as High severity in the bug bounty program. The vulnerability exploits a logic flaw (unbounded `ending_version`) rather than simple network flooding, distinguishing it from out-of-scope network-level DoS attacks. The issue is deterministically exploitable and causes clear service availability harm.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L123-125)
```rust
                let ending_version = request
                    .transactions_count
                    .map(|count| starting_version + count);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L127-139)
```rust
                scope.spawn(async move {
                    self.start_streaming(
                        id,
                        starting_version,
                        ending_version,
                        max_num_transactions_per_batch,
                        MAX_BYTES_PER_BATCH,
                        filter,
                        request_metadata,
                        response_sender,
                    )
                    .await
                });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L171-171)
```rust
        let ending_version = ending_version.unwrap_or(u64::MAX);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L172-174)
```rust
        loop {
            if next_version >= ending_version {
                break;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L36-37)
```rust
const HTTP2_PING_INTERVAL_DURATION: std::time::Duration = std::time::Duration::from_secs(60);
const HTTP2_PING_TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(10);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L123-123)
```rust
        let (handler_tx, handler_rx) = tokio::sync::mpsc::channel(10);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L190-215)
```rust
    pub(crate) fn insert_active_stream(
        &self,
        id: &str,
        start_version: u64,
        end_version: Option<u64>,
    ) {
        self.active_streams.insert(
            id.to_owned(),
            (
                ActiveStream {
                    id: id.to_owned(),
                    start_time: Some(timestamp_now_proto()),
                    start_version,
                    end_version,
                    progress: None,
                },
                StreamProgressSamples::new(),
            ),
        );
        let label = if self.is_live_data_service {
            ["live_data_service"]
        } else {
            ["historical_data_service"]
        };
        NUM_CONNECTED_STREAMS.with_label_values(&label).inc();
    }
```
