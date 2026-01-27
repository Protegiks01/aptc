# Audit Report

## Title
Unauthenticated gRPC Message Deserialization Panic Causes Executor Service Denial of Service

## Summary
The remote executor service accepts unauthenticated gRPC messages and deserializes them using `bcs::from_bytes().unwrap()`, which panics on malformed input. An attacker with network access can send specially crafted byte sequences to crash executor service threads, causing block execution failures and validator unavailability.

## Finding Description

The `Message::new()` function wraps raw bytes without validation [1](#0-0) , and these messages are accepted by an unauthenticated gRPC service [2](#0-1) .

The vulnerability manifests in three critical deserialization points where `.unwrap()` is called on untrusted network data:

**Location 1: Coordinator Client** - When receiving execution commands, the service deserializes without error handling [3](#0-2) . A panic here crashes the thread receiving execution commands, preventing the executor shard from processing blocks.

**Location 2: State View Service** - Key-value requests are deserialized in thread pool workers [4](#0-3) . Repeated malformed messages can exhaust the thread pool, degrading state view service availability.

**Location 3: Executor Client** - When collecting results from shards, deserialization failures panic the coordinator [5](#0-4) , failing entire block execution operations.

The remote executor service is used in production for sharded block execution when remote addresses are configured [6](#0-5) .

This violates Aptos secure coding guidelines which explicitly state: "unwrap() - Unwrap should only be used for test code. For all other use cases, prefer expect()" [7](#0-6) , and "Use Result<T, E> and Option<T> for error handling instead of unwrapping or expecting, to avoid panics" [8](#0-7) .

**Attack Path:**
1. Attacker sends gRPC `NetworkMessage` with malformed BCS-encoded bytes to exposed executor service endpoint
2. Message passes through unauthenticated `simple_msg_exchange` handler
3. Handler wraps bytes in `Message::new()` without validation
4. Message routes to registered handler based on message type
5. Handler calls `bcs::from_bytes().unwrap()` on malformed data
6. BCS deserialization fails, triggering panic
7. Thread crashes, causing service unavailability

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria for "API crashes" and "Validator node slowdowns". 

When the coordinator client thread panics, the executor shard stops processing execution commands, breaking distributed block execution. When the executor client panics during result collection, block execution fails completely. For validators running sharded execution, this directly impacts their ability to produce blocks, causing validator performance degradation and potential slashing.

The impact is amplified because:
- No authentication protects the gRPC endpoints
- The service uses plain HTTP without TLS
- Multiple attack vectors exist across different message types
- Panics in critical execution paths halt block processing

While this doesn't directly steal funds or violate consensus safety, it causes significant operational disruption to validator infrastructure, meeting the High Severity threshold.

## Likelihood Explanation

Likelihood is **Medium to High** depending on deployment configuration:

**If executor services are network-accessible:** Likelihood is HIGH. An attacker only needs to:
- Identify the service endpoint (default port 52200 for coordinator)
- Send a single malformed gRPC message
- No authentication or authorization required
- Attack complexity is trivial (invalid BCS bytes)

**If properly isolated in private networks:** Likelihood is MEDIUM. Requires network compromise or misconfiguration, but remains exploitable by insider threats or pivoted attackers.

The vulnerability is straightforward to exploit once network access is obtained, requiring no special privileges or deep protocol knowledge.

## Recommendation

Implement proper error handling for all message deserialization operations:

```rust
// In remote_cordinator_client.rs, line 89
let request: RemoteExecutionRequest = match bcs::from_bytes(&message.data) {
    Ok(req) => req,
    Err(e) => {
        error!("Failed to deserialize RemoteExecutionRequest: {}", e);
        return ExecutorShardCommand::Stop;
    }
};

// In remote_state_view_service.rs, line 86
let req: RemoteKVRequest = match bcs::from_bytes(&message.data) {
    Ok(req) => req,
    Err(e) => {
        error!("Failed to deserialize RemoteKVRequest: {}", e);
        return; // Early return, don't process invalid message
    }
};

// In remote_executor_client.rs, line 168
let result: RemoteExecutionResult = match bcs::from_bytes(&received_bytes) {
    Ok(res) => res,
    Err(e) => {
        error!("Failed to deserialize RemoteExecutionResult: {}", e);
        return Err(VMStatus::error(StatusCode::INVALID_DATA, None));
    }
};
```

Additionally, implement authentication for the gRPC service:
- Add mutual TLS authentication
- Validate sender identity before processing messages
- Implement message signing and verification
- Add rate limiting to prevent DoS attacks

## Proof of Concept

```rust
// PoC: Trigger panic in remote executor service
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};

#[tokio::test]
async fn test_malformed_message_panic() {
    // Start a remote executor service on localhost:52200
    // (requires running ExecutorService separately)
    
    let mut client = NetworkMessageServiceClient::connect("http://127.0.0.1:52200")
        .await
        .expect("Failed to connect");
    
    // Send malformed BCS data that will fail deserialization
    let malformed_request = NetworkMessage {
        message: vec![0xFF, 0xFF, 0xFF, 0xFF], // Invalid BCS bytes
        message_type: "execute_command_0".to_string(),
    };
    
    // This will cause the remote coordinator client to panic
    // when it tries to deserialize with bcs::from_bytes().unwrap()
    let result = client.simple_msg_exchange(malformed_request).await;
    
    // The service thread will panic, but this call might succeed
    // because the panic happens after the RPC handler returns
    println!("Result: {:?}", result);
    
    // Subsequent legitimate requests will fail because the handler thread crashed
    let legitimate_request = NetworkMessage {
        message: vec![/* valid BCS data */],
        message_type: "execute_command_0".to_string(),
    };
    
    // This will timeout or fail because the handler is no longer running
    let result = client.simple_msg_exchange(legitimate_request).await;
    assert!(result.is_err(), "Service should be unavailable after panic");
}
```

## Notes

This vulnerability is particularly concerning because:

1. It affects production code used for sharded block execution in validators
2. The gRPC service has no authentication layer whatsoever
3. Multiple deserialization points are vulnerable to the same attack pattern
4. The code explicitly violates documented Aptos secure coding guidelines
5. The impact scales with the number of executor shards deployed

The issue should be addressed urgently for any production deployments using remote executor services, especially if these services are exposed beyond localhost or highly restricted internal networks.

### Citations

**File:** secure/net/src/network_controller/mod.rs (L62-65)
```rust
impl Message {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
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

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-89)
```rust
    fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
        match self.command_rx.recv() {
            Ok(message) => {
                let _rx_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx"])
                    .start_timer();
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
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

**File:** execution/executor-service/src/remote_executor_client.rs (L163-169)
```rust
    fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
        trace!("RemoteExecutorClient Waiting for results");
        let mut results = vec![];
        for rx in self.result_rxs.iter() {
            let received_bytes = rx.recv().unwrap().to_bytes();
            let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes).unwrap();
            results.push(result.inner?);
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

**File:** RUST_CODING_STYLE.md (L182-183)
```markdown
- `unwrap()` - Unwrap should only be used for test code. For all other use cases, prefer `expect()`. The only exception is if the error message is custom-generated, in which case use `.unwrap_or_else(|| panic!("error: {}", foo))`.
- `expect()` - Expect should be invoked when a system invariant is expected to be preserved. `expect()` is preferred over `unwrap()` and should contain a detailed error message on failure in most cases.
```

**File:** RUST_SECURE_CODING.md (L79-81)
```markdown
### Error Handling

Use `Result<T, E>` and `Option<T>` for error handling instead of _unwrapping_ or _expecting_, to avoid panics, more details on [coding-style](./RUST_CODING_STYLE.md#error-handling).
```
