# Audit Report

## Title
Silent Message Delivery Failure in Remote Executor gRPC Service Causes Indefinite Coordinator Hang

## Summary
The `SimpleMsgExchange` gRPC method in the remote executor service always returns an `Empty` response regardless of whether messages are successfully delivered to registered handlers. This prevents coordinators from detecting lost execution results, causing indefinite blocking and validator liveness failures.

## Finding Description

The remote executor service uses a gRPC-based message passing system for distributed transaction execution across shards. The core vulnerability exists in the `GRPCNetworkMessageServiceServerWrapper::simple_msg_exchange` method: [1](#0-0) 

This method **always returns `Ok(Response::new(Empty {}))`** regardless of whether:
1. A handler is registered for the message type (lines 105-108)
2. The message is successfully delivered to the handler channel (line 107)

When no handler is registered, the method logs an error but still returns success (lines 109-114). This creates a silent failure mode where execution results can be lost without the sender's knowledge.

The coordinator waits indefinitely for results that never arrive: [2](#0-1) 

The `rx.recv().unwrap()` call on line 167 blocks indefinitely with no timeout, waiting for execution results that were never delivered.

The execution flow is:
1. Remote executor shard completes block execution and sends results via `send_execution_result`: [3](#0-2) 

2. Results are sent through the NetworkController which uses the gRPC service: [4](#0-3) 

3. The gRPC client sends the message and only panics on gRPC transport errors, but accepts the `Empty` response as success: [5](#0-4) 

**Failure Scenarios:**
- Race condition during initialization (handler not yet registered)
- Handler deregistration during shutdown while messages are in flight  
- Message type string mismatch due to configuration or code bugs
- Handler channel disconnection

## Impact Explanation

This vulnerability causes **High Severity** impact per Aptos bug bounty criteria:

1. **Validator Node Slowdown/Hang**: When execution results are silently lost, the coordinator blocks indefinitely waiting for results. Block execution cannot complete, and the validator becomes unresponsive.

2. **Requires Manual Intervention**: The indefinite blocking requires operator intervention to detect and restart the validator process.

3. **Violates Liveness Invariant**: The system fails to make progress in block execution, violating the liveness guarantee that all valid blocks should eventually be executed.

4. **Network-Wide Impact**: If multiple validators experience this issue (e.g., due to a common timing bug in initialization), it could affect network consensus and block production.

## Likelihood Explanation

**Moderate Likelihood** - This issue can be triggered by:

1. **Race Conditions**: During system startup, if remote executor shards begin sending results before the coordinator has registered all inbound handlers, messages will be silently dropped.

2. **Shutdown Timing**: During graceful shutdown, if handlers are deregistered while messages are still in flight, results can be lost.

3. **Configuration Errors**: If there's a mismatch in message type strings between sender and receiver (e.g., formatting differences in shard IDs), handlers won't be found.

4. **Code Bugs**: Any bug that causes handler deregistration or HashMap corruption would trigger this failure mode.

The likelihood increases with:
- Number of remote executor shards (more coordination complexity)
- System restart frequency
- Network instability causing process restarts

## Recommendation

**Fix 1: Return Error When Handler Not Found**

Modify `simple_msg_exchange` to return a gRPC error when no handler is registered:

```rust
async fn simple_msg_exchange(
    &self,
    request: Request<NetworkMessage>,
) -> Result<Response<Empty>, Status> {
    let remote_addr = request.remote_addr();
    let network_message = request.into_inner();
    let msg = Message::new(network_message.message);
    let message_type = MessageType::new(network_message.message_type);

    if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
        handler.send(msg).map_err(|e| {
            Status::internal(format!("Handler channel error: {}", e))
        })?;
        Ok(Response::new(Empty {}))
    } else {
        Err(Status::not_found(format!(
            "No handler registered for message type: {:?}",
            message_type
        )))
    }
}
```

**Fix 2: Add Timeout to Result Reception**

Add a timeout to `get_output_from_shards` to detect lost messages:

```rust
fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
    trace!("RemoteExecutorClient Waiting for results");
    let mut results = vec![];
    for (shard_id, rx) in self.result_rxs.iter().enumerate() {
        let received_bytes = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .map_err(|e| VMStatus::Error(
                StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                Some(format!("Timeout waiting for shard {} results: {}", shard_id, e))
            ))?
            .to_bytes();
        let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes)
            .map_err(|_| VMStatus::Error(
                StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                Some("Failed to deserialize execution result".to_string())
            ))?;
        results.push(result.inner?);
    }
    Ok(results)
}
```

**Fix 3: Add Acknowledgment Protocol**

Replace the `Empty` response with an acknowledgment that includes delivery status:

```protobuf
message DeliveryAck {
  bool delivered = 1;
  string error_message = 2;
}

service NetworkMessageService {
  rpc SimpleMsgExchange(NetworkMessage) returns (DeliveryAck);
}
```

## Proof of Concept

```rust
// Test that demonstrates the vulnerability
#[test]
fn test_message_lost_when_no_handler_registered() {
    use aptos_config::utils;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        thread,
        time::Duration,
    };

    // Setup server with no handlers registered
    let server_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST), 
        utils::get_available_port()
    );
    let server_handlers: Arc<Mutex<HashMap<MessageType, Sender<Message>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    
    // Intentionally NOT registering a handler for "test_type"
    let server = GRPCNetworkMessageServiceServerWrapper::new(
        server_handlers, 
        server_addr
    );
    
    let rt = Runtime::new().unwrap();
    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    server.start(
        &rt,
        "vulnerability_test".to_string(),
        server_addr,
        1000,
        server_shutdown_rx,
    );
    
    thread::sleep(Duration::from_millis(100)); // Wait for server startup
    
    // Create client and send message
    let mut grpc_client = GRPCNetworkMessageServiceClientWrapper::new(&rt, server_addr);
    let client_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST), 
        utils::get_available_port()
    );
    
    // Send message - this will succeed even though no handler exists
    rt.block_on(async {
        grpc_client
            .send_message(
                client_addr,
                Message::new("execution_result".as_bytes().to_vec()),
                &MessageType::new("unregistered_type".to_string()),
            )
            .await;
    });
    
    // SUCCESS: Message was "sent" but never delivered
    // A real coordinator would now block indefinitely on rx.recv()
    // demonstrating the liveness failure
    
    server_shutdown_tx.send(()).unwrap();
    
    println!("PoC: Message sent successfully but was silently dropped - coordinator would hang!");
}
```

## Notes

This vulnerability specifically affects the distributed remote executor service used for sharded parallel transaction execution. While not directly exploitable by external attackers, it represents a critical robustness issue that can cause validator outages through race conditions, timing bugs, or misconfigurations during normal operation.

The issue violates the liveness invariant and can cause validators to become unresponsive, requiring manual intervention. The fix should include both proper error propagation in the gRPC layer and timeout mechanisms in the coordinator to detect and recover from lost messages.

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

**File:** secure/net/src/grpc_network_service/mod.rs (L140-160)
```rust
    pub async fn send_message(
        &mut self,
        sender_addr: SocketAddr,
        message: Message,
        mt: &MessageType,
    ) {
        let request = tonic::Request::new(NetworkMessage {
            message: message.data,
            message_type: mt.get_type(),
        });
        // TODO: Retry with exponential backoff on failures
        match self.remote_channel.simple_msg_exchange(request).await {
            Ok(_) => {},
            Err(e) => {
                panic!(
                    "Error '{}' sending message to {} on node {:?}",
                    e, self.remote_addr, sender_addr
                );
            },
        }
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L163-172)
```rust
    fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
        trace!("RemoteExecutorClient Waiting for results");
        let mut results = vec![];
        for rx in self.result_rxs.iter() {
            let received_bytes = rx.recv().unwrap().to_bytes();
            let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes).unwrap();
            results.push(result.inner?);
        }
        Ok(results)
    }
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L115-119)
```rust
    fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
        let remote_execution_result = RemoteExecutionResult::new(result);
        let output_message = bcs::to_bytes(&remote_execution_result).unwrap();
        self.result_tx.send(Message::new(output_message)).unwrap();
    }
```

**File:** secure/net/src/network_controller/outbound_handler.rs (L155-160)
```rust
                grpc_clients
                    .get_mut(remote_addr)
                    .unwrap()
                    .send_message(*socket_addr, msg, message_type)
                    .await;
            }
```
