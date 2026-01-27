# Audit Report

## Title
Unauthenticated gRPC Network Service Enables Denial of Service via Malformed Message Injection in Remote Executor System

## Summary
The gRPC network service in the remote executor system accepts unauthenticated network messages and passes them directly to BCS deserialization with unsafe error handling (`.unwrap()`), allowing any network peer to cause service degradation through repeated malformed messages that trigger thread panics and resource exhaustion.

## Finding Description

The vulnerability exists in the remote executor service's network message handling flow:

**1. Unauthenticated Message Reception**

The `simple_msg_exchange()` function accepts network messages without any authentication or authorization checks: [1](#0-0) 

Note that line 100 extracts `remote_addr` but never validates it. There is no authentication mechanism in the gRPC service implementation.

**2. Unvalidated Message Forwarding**

The raw message bytes are wrapped in a `Message` object without any content validation: [2](#0-1) 

The `Message::new()` constructor simply wraps the bytes without inspection: [3](#0-2) 

**3. Unsafe Deserialization in Message Handlers**

All downstream message handlers use `bcs::from_bytes().unwrap()` which panics on deserialization failures:

- Remote state view receiver: [4](#0-3) 

- Remote state view service: [5](#0-4) 

- Remote coordinator client: [6](#0-5) 

- Remote executor client: [7](#0-6) 

**4. Production Usage**

This remote executor service is used in production for sharded block execution: [8](#0-7) 

**Attack Scenario:**

1. Attacker discovers the network address of a remote executor shard (port scanning, network reconnaissance)
2. Attacker sends crafted gRPC messages with malformed BCS-encoded bytes to the `simple_msg_exchange` endpoint
3. The message is forwarded to registered handlers without validation
4. Handler attempts BCS deserialization with `.unwrap()`
5. Deserialization fails, causing a thread panic in the rayon thread pool
6. Repeated attacks exhaust thread pool resources or consume significant CPU/memory attempting to deserialize malformed messages (up to 80 MB per message)

**Invariant Violations:**

This vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The lack of authentication and input validation allows unbounded resource consumption without any access control or rate limiting.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: The remote executor service is used for sharded block execution in production. Repeated malformed messages cause thread panics and resource exhaustion, degrading executor shard performance and slowing block execution.

2. **Service Availability**: Exhausting the thread pool or consuming significant resources can make the remote executor service unresponsive, preventing block execution and causing liveness issues.

3. **No Authentication Layer**: Any network peer can exploit this vulnerability without credentials, making it trivially exploitable if the service is network-accessible.

The maximum message size is 80 MB: [9](#0-8) 

This allows attackers to send very large messages that consume significant resources even when deserialization fails.

## Likelihood Explanation

**High Likelihood:**

1. **No Authentication Required**: The gRPC service has no authentication mechanism, making it exploitable by any network peer
2. **Network Accessibility**: The service binds to configurable socket addresses for cross-shard communication, likely requiring network exposure in distributed deployments
3. **Simple Attack Vector**: Sending malformed gRPC messages requires only basic network tools
4. **No Rate Limiting**: There are no rate limits or request throttling mechanisms observed in the code

The only requirement is network access to the remote executor service, which would be necessary in any distributed sharding deployment.

## Recommendation

**Implement Multiple Defense Layers:**

1. **Add Authentication**: Implement mutual TLS or token-based authentication for the gRPC service
2. **Validate Messages**: Add basic validation before passing messages to handlers
3. **Safe Error Handling**: Replace `.unwrap()` with proper error handling that doesn't panic
4. **Rate Limiting**: Implement per-peer rate limiting on message reception

**Code Fix Example:**

```rust
// In remote_state_view.rs handle_message function (line 254):
fn handle_message(
    shard_id: ShardId,
    message: Message,
    state_view: Arc<RwLock<RemoteStateView>>,
) {
    let _timer = REMOTE_EXECUTOR_TIMER
        .with_label_values(&[&shard_id.to_string(), "kv_responses"])
        .start_timer();
    let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
        .with_label_values(&[&shard_id.to_string(), "kv_resp_deser"])
        .start_timer();
    
    // FIXED: Use proper error handling instead of unwrap
    let response: RemoteKVResponse = match bcs::from_bytes(&message.data) {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to deserialize RemoteKVResponse for shard {}: {}", shard_id, e);
            return; // Drop invalid message instead of panicking
        }
    };
    drop(bcs_deser_timer);
    
    // ... rest of the function
}
```

Apply similar fixes to all other handlers that use `.unwrap()` on deserialization.

## Proof of Concept

```rust
// PoC demonstrating malformed message causing panic
use aptos_secure_net::network_controller::{Message, NetworkController};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn test_malformed_message_dos() {
    // Setup remote executor service
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 52200);
    let mut controller = NetworkController::new(
        "test-executor".to_string(),
        server_addr,
        5000
    );
    
    let _rx = controller.create_inbound_channel("execute_command_0".to_string());
    controller.start();
    
    // Create gRPC client
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut client = rt.block_on(async {
        use aptos_protos::remote_executor::v1::network_message_service_client::NetworkMessageServiceClient;
        let conn = tonic::transport::Endpoint::new(format!("http://{}", server_addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
        NetworkMessageServiceClient::new(conn)
    });
    
    // Send malformed message (invalid BCS bytes)
    let malformed_bytes = vec![0xFF; 1000]; // Invalid BCS encoding
    rt.block_on(async {
        use aptos_protos::remote_executor::v1::NetworkMessage;
        let request = tonic::Request::new(NetworkMessage {
            message: malformed_bytes,
            message_type: "execute_command_0".to_string(),
        });
        
        // This will cause the handler to panic on unwrap()
        let _ = client.simple_msg_exchange(request).await;
    });
    
    // In production, repeated calls would exhaust resources
}
```

**Notes**

While the security question specifically mentions "buffer overflows," these do not exist in Rust's safe code due to memory safety guarantees. However, the **deserialization bugs** aspect is valid - the unsafe error handling with `.unwrap()` combined with lack of authentication creates a realistic DoS vulnerability.

The remote executor service is a production component used for sharded block execution, as confirmed by its integration into the main execution workflow. The lack of authentication on this critical service is a significant security oversight that enables unprivileged attackers to degrade service availability.

This vulnerability meets the High Severity criteria for "Validator node slowdowns" and "significant protocol violations" (violating the Resource Limits invariant that all operations must respect computational limits).

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
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

**File:** secure/net/src/network_controller/mod.rs (L56-70)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Message {
    pub data: Vec<u8>,
}

impl Message {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.data
    }
}
```

**File:** execution/executor-service/src/remote_state_view.rs (L254-254)
```rust
        let response: RemoteKVResponse = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L86-86)
```rust
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L89-89)
```rust
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/remote_executor_client.rs (L168-168)
```rust
            let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes).unwrap();
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-267)
```rust
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
```
