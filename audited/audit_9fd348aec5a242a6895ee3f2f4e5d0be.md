# Audit Report

## Title
Missing Message Type Validation in NetworkController Enables Type Confusion and Out-of-Bounds Access

## Summary
The NetworkController in the remote executor service does not validate that incoming message payloads match their declared message types. This allows unauthenticated attackers to cause denial-of-service via type confusion panics and trigger out-of-bounds array access by manipulating shard IDs in state query requests.

## Finding Description

The NetworkController routes messages based solely on a string-based `message_type` identifier without validating that the message payload actually matches the expected type for that route. This breaks two critical security guarantees:

1. **No Type Validation**: When the gRPC service receives a message, it only checks if a handler is registered for the `message_type` string, then blindly forwards the raw bytes to that handler without any validation. [1](#0-0) 

2. **Unchecked Shard ID Usage**: The remote state view service deserializes incoming `RemoteKVRequest` messages and uses the `shard_id` field to index into the response channel array without bounds checking. [2](#0-1) 

**Attack Path 1: Type Confusion Denial-of-Service**
1. Attacker sends gRPC message with `message_type="execute_command_0"` but payload contains serialized `RemoteKVRequest`
2. NetworkController routes to coordinator client's command channel
3. Coordinator client attempts BCS deserialization as `RemoteExecutionRequest` [3](#0-2) 

4. Deserialization fails due to type mismatch, `.unwrap()` causes panic, crashing the executor service

**Attack Path 2: Out-of-Bounds Array Access**
1. Attacker crafts `RemoteKVRequest` with malicious `shard_id >= num_shards` (e.g., shard_id=999)
2. Sends with correct `message_type="remote_kv_request"`
3. Message is deserialized successfully
4. At line 121, `kv_tx[shard_id]` triggers out-of-bounds panic

**Attack Path 3: Cross-Shard Response Misdirection**
1. Attacker sends `RemoteKVRequest` with incorrect but in-bounds `shard_id` (e.g., shard_id=1 when actual shard is 0)
2. State query executes normally
3. Response is sent to wrong shard at line 121
4. Correct shard never receives response, hangs waiting
5. Wrong shard receives unexpected data, causing state inconsistencies

The gRPC service has no authentication mechanism, allowing any network peer to exploit these vulnerabilities. [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

1. **Validator Node Crashes**: Type confusion attacks cause panics that crash the remote executor service, impacting block execution availability
2. **State Inconsistencies**: Misdirected responses between shards can cause different shards to have inconsistent views of state, potentially violating the "Deterministic Execution" invariant where all validators must produce identical state roots
3. **Liveness Degradation**: Repeated crashes force validator operators to restart services, degrading network liveness

While this doesn't directly cause consensus safety violations or fund loss, it meets the "Validator node slowdowns" and "Significant protocol violations" criteria for High severity.

## Likelihood Explanation

**Likelihood: High**

1. **No Authentication Barrier**: The NetworkController uses plain gRPC without authentication, so any network peer can send malicious messages
2. **Simple Exploitation**: Attack only requires crafting gRPC messages with mismatched types or invalid shard IDs
3. **No Rate Limiting**: No evidence of rate limiting on message processing
4. **Clear Attack Surface**: The executor service listens on a network socket, making it discoverable and accessible

The attack is trivially exploitable by anyone who can reach the executor service's network endpoint.

## Recommendation

Implement multi-layered validation:

**1. Add Message Type Validation in NetworkController:**
```rust
// In grpc_network_service/mod.rs, simple_msg_exchange()
async fn simple_msg_exchange(
    &self,
    request: Request<NetworkMessage>,
) -> Result<Response<Empty>, Status> {
    let remote_addr = request.remote_addr();
    let network_message = request.into_inner();
    let msg = Message::new(network_message.message);
    let message_type = MessageType::new(network_message.message_type.clone());
    
    // Validate message type format and bounds
    if !is_valid_message_type(&network_message.message_type) {
        return Err(Status::invalid_argument("Invalid message type"));
    }
    
    if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
        handler.send(msg).map_err(|_| Status::internal("Handler error"))?;
    } else {
        return Err(Status::not_found("No handler registered"));
    }
    Ok(Response::new(Empty {}))
}
```

**2. Add Bounds Checking in RemoteStateViewService:**
```rust
// In remote_state_view_service.rs, handle_message()
pub fn handle_message(
    message: Message,
    state_view: Arc<RwLock<Option<Arc<S>>>>,
    kv_tx: Arc<Vec<Sender<Message>>>,
) {
    let req: RemoteKVRequest = match bcs::from_bytes(&message.data) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to deserialize RemoteKVRequest: {}", e);
            return;
        }
    };
    
    let (shard_id, state_keys) = req.into();
    
    // Bounds check shard_id
    if shard_id >= kv_tx.len() {
        error!("Invalid shard_id {} >= {}", shard_id, kv_tx.len());
        return;
    }
    
    // ... rest of function
}
```

**3. Add Authentication:**
Implement mutual TLS or token-based authentication for the gRPC service to prevent unauthorized access.

## Proof of Concept

```rust
// PoC demonstrating type confusion attack
#[test]
fn test_type_confusion_attack() {
    use aptos_config::utils;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    // Setup executor service
    let executor_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST), 
        utils::get_available_port()
    );
    
    // Create malicious payload: RemoteKVRequest instead of RemoteExecutionRequest
    let malicious_request = RemoteKVRequest {
        shard_id: 0,
        keys: vec![],
    };
    let payload = bcs::to_bytes(&malicious_request).unwrap();
    
    // Send with wrong message type
    let rt = Runtime::new().unwrap();
    let mut client = GRPCNetworkMessageServiceClientWrapper::new(&rt, executor_addr);
    
    rt.block_on(async {
        client.send_message(
            executor_addr,
            Message::new(payload),
            &MessageType::new("execute_command_0".to_string()), // Wrong type!
        ).await;
    });
    
    // Expected: Coordinator client panics on deserialization
}

#[test]
fn test_out_of_bounds_shard_id() {
    // Setup with 2 shards
    let num_shards = 2;
    
    // Create request with invalid shard_id
    let malicious_request = RemoteKVRequest {
        shard_id: 999, // Out of bounds!
        keys: vec![],
    };
    let payload = bcs::to_bytes(&malicious_request).unwrap();
    
    // Send to state view service
    // Expected: Panic at kv_tx[999] array access
}
```

## Notes

This vulnerability affects the remote sharded execution feature, which appears to be used for distributed transaction execution across multiple shards. The lack of input validation at the network boundary creates multiple attack vectors that can impact both availability and correctness of the execution system. The combination of no authentication, no type validation, and no bounds checking creates a critical attack surface that requires immediate remediation.

### Citations

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

**File:** execution/executor-service/src/remote_state_view_service.rs (L74-122)
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

        let (shard_id, state_keys) = req.into();
        trace!(
            "remote state view service - received request for shard {} with {} keys",
            shard_id,
            state_keys.len()
        );
        let resp = state_keys
            .into_iter()
            .map(|state_key| {
                let state_value = state_view
                    .read()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .get_state_value(&state_key)
                    .unwrap();
                (state_key, state_value)
            })
            .collect_vec();
        let len = resp.len();
        let resp = RemoteKVResponse::new(resp);
        let bcs_ser_timer = REMOTE_EXECUTOR_TIMER
            .with_label_values(&["0", "kv_resp_ser"])
            .start_timer();
        let resp = bcs::to_bytes(&resp).unwrap();
        drop(bcs_ser_timer);
        trace!(
            "remote state view service - sending response for shard {} with {} keys",
            shard_id,
            len
        );
        let message = Message::new(resp);
        kv_tx[shard_id].send(message).unwrap();
    }
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-110)
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
                drop(bcs_deser_timer);

                match request {
                    RemoteExecutionRequest::ExecuteBlock(command) => {
                        let init_prefetch_timer = REMOTE_EXECUTOR_TIMER
                            .with_label_values(&[&self.shard_id.to_string(), "init_prefetch"])
                            .start_timer();
                        let state_keys = Self::extract_state_keys(&command);
                        self.state_view_client.init_for_block(state_keys);
                        drop(init_prefetch_timer);

                        let (sub_blocks, concurrency, onchain_config) = command.into();
                        ExecutorShardCommand::ExecuteSubBlocks(
                            self.state_view_client.clone(),
                            sub_blocks,
                            concurrency,
                            onchain_config,
                        )
                    },
                }
            },
```

**File:** execution/executor-service/src/remote_executor_service.rs (L21-55)
```rust
impl ExecutorService {
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        self_address: SocketAddr,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let service_name = format!("executor_service-{}", shard_id);
        let mut controller = NetworkController::new(service_name, self_address, 5000);
        let coordinator_client = Arc::new(RemoteCoordinatorClient::new(
            shard_id,
            &mut controller,
            coordinator_address,
        ));
        let cross_shard_client = Arc::new(RemoteCrossShardClient::new(
            &mut controller,
            remote_shard_addresses,
        ));

        let executor_service = Arc::new(ShardedExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            coordinator_client,
            cross_shard_client,
        ));

        Self {
            shard_id,
            controller,
            executor_service,
        }
    }
```
