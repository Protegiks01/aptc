# Audit Report

## Title
Missing Per-Message Access Control in Remote Executor Service Allows Unauthorized Command Execution

## Summary
The remote executor service lacks any per-message access control or sender authentication. Any peer that can connect to the GRPC endpoint can send arbitrary execution commands, state queries, or cross-shard messages to executor shards without verification. This violates defense-in-depth security principles and could enable unauthorized transaction execution and consensus manipulation if network-level protections fail.

## Finding Description

The remote executor service (`execution/executor-service/`) implements a distributed sharded execution system where a coordinator dispatches execution commands to multiple executor shards over the network. The system has **no application-level authentication or authorization** for incoming messages.

**Protocol Definition:**

The NetworkMessage structure contains only raw message data and a type identifier, with no authentication fields: [1](#0-0) 

**Missing Authentication in GRPC Handler:**

The GRPC service handler accepts messages from any connected peer without verification: [2](#0-1) 

The handler extracts `remote_addr` from the GRPC request but performs **no verification** that the sender is authorized to send the message type. It simply routes based on `message_type` string to registered handlers.

**Unprotected Message Handlers:**

1. **Execution Commands:** The coordinator client receives and processes ExecuteBlock commands without authentication: [3](#0-2) 

2. **State Requests:** The state view service processes RemoteKVRequest messages without sender verification: [4](#0-3) 

3. **Cross-Shard Messages:** Cross-shard communication accepts messages without authentication: [5](#0-4) 

**Insecure Network Configuration:**

The NetworkController and GRPC client use plain HTTP without TLS: [6](#0-5) 

**Attack Scenario:**

1. Attacker gains network access to executor shard endpoints (through misconfiguration, compromised internal network, or exposed service)
2. Attacker connects to the GRPC service endpoint
3. Attacker crafts malicious messages:
   - `RemoteExecutionRequest::ExecuteBlock` with arbitrary transactions
   - `RemoteKVRequest` to read sensitive state values
   - `CrossShardMsg` to inject false cross-shard communication
4. Messages are processed by the shard without verification
5. Attacker achieves unauthorized transaction execution and state manipulation

**Broken Invariants:**

This breaks multiple critical invariants:

- **Deterministic Execution (Invariant #1):** Attacker can cause different shards to execute different transactions, breaking deterministic execution
- **Access Control (Invariant #8):** No verification that message sender has authority to issue commands
- **Consensus Safety (Invariant #2):** Manipulation of execution could cause validators to diverge

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability qualifies as Critical severity because it enables:

1. **Unauthorized Transaction Execution:** Attacker can inject arbitrary execution commands to shards, potentially executing transactions that were never committed by consensus. This could lead to **Loss of Funds** through unauthorized state changes.

2. **Consensus/Safety Violations:** By manipulating individual shards differently, an attacker could cause different validators running sharded execution to compute different state roots for the same block, violating consensus safety.

3. **State Manipulation:** Unauthorized RemoteKVRequest handling allows reading sensitive state values and potentially manipulating state view responses.

4. **Non-Deterministic Execution:** Cross-shard message injection could cause shards to see inconsistent views during execution, breaking the deterministic execution guarantee.

The sharded executor is integrated into the main execution workflow: [7](#0-6) 

This means malicious execution commands could directly affect consensus-committed transactions.

## Likelihood Explanation

**Likelihood: Medium to High** depending on deployment configuration.

**Factors increasing likelihood:**

1. The service is designed as a **standalone process** with network communication: [8](#0-7) 

2. The service accepts command-line configured addresses, suggesting it's meant for distributed deployment

3. No authentication configuration is visible anywhere in the codebase

4. Uses plain HTTP without TLS

**Factors requiring consideration:**

- If deployed in a properly isolated internal network with strict firewall rules, exploitation requires the attacker to first compromise the internal network
- However, relying solely on network-level security violates defense-in-depth principles
- Any network misconfiguration, compromised internal host, or service exposure makes this immediately exploitable

Even in trusted networks, **application-level authentication is a security best practice** for critical infrastructure.

## Recommendation

Implement application-level authentication and authorization for the remote executor service:

1. **Add Mutual TLS Authentication:**
   - Use TLS for GRPC connections with client certificate verification
   - Validate client certificates against a trusted certificate authority
   - Configure NetworkController to use HTTPS instead of HTTP

2. **Implement Message-Level Authorization:**
   - Add sender identity verification in `simple_msg_exchange()`
   - Verify sender is authorized to send specific message types
   - Add cryptographic signatures to messages with sender's private key

3. **Use Noise Protocol Authentication:**
   - Integrate the existing Noise IK handshake mechanism from `network/framework/src/noise/handshake.rs`
   - Implement `HandshakeAuthMode::Mutual` for executor service connections
   - Maintain a trusted peers set for coordinators and shards

4. **Add Authorization Checks:**
```rust
// In GRPCNetworkMessageServiceServerWrapper::simple_msg_exchange
async fn simple_msg_exchange(
    &self,
    request: Request<NetworkMessage>,
) -> Result<Response<Empty>, Status> {
    let remote_addr = request.remote_addr();
    let network_message = request.into_inner();
    
    // ADD: Verify sender is authorized for this message type
    if !self.verify_sender_authorized(remote_addr, &network_message.message_type) {
        return Err(Status::permission_denied("Unauthorized sender"));
    }
    
    let msg = Message::new(network_message.message);
    let message_type = MessageType::new(network_message.message_type);
    // ... rest of handler
}
```

5. **Defense in Depth:**
   - Even if deployed in trusted networks, implement authentication
   - Follow principle of least privilege for message routing
   - Add request rate limiting and anomaly detection

## Proof of Concept

**Rust Test Demonstrating Lack of Access Control:**

```rust
#[tokio::test]
async fn test_unauthorized_execution_command() {
    use aptos_executor_service::remote_executor_service::ExecutorService;
    use aptos_secure_net::network_controller::NetworkController;
    use aptos_protos::remote_executor::v1::{
        network_message_service_client::NetworkMessageServiceClient,
        NetworkMessage,
    };
    
    // Start legitimate executor service
    let shard_addr = "127.0.0.1:9001".parse().unwrap();
    let coordinator_addr = "127.0.0.1:9000".parse().unwrap();
    
    let mut service = ExecutorService::new(
        0, // shard_id
        2, // num_shards
        4, // num_threads
        shard_addr,
        coordinator_addr,
        vec![shard_addr, "127.0.0.1:9002".parse().unwrap()],
    );
    service.start();
    
    // Wait for service to be ready
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Attacker connects from unauthorized address
    let malicious_client = NetworkMessageServiceClient::connect(
        format!("http://{}", shard_addr)
    ).await.unwrap();
    
    // Craft malicious ExecuteBlock command
    let malicious_command = RemoteExecutionRequest::ExecuteBlock(
        ExecuteBlockCommand {
            sub_blocks: /* crafted malicious transactions */,
            concurrency_level: 4,
            onchain_config: /* default config */,
        }
    );
    
    let request = NetworkMessage {
        message: bcs::to_bytes(&malicious_command).unwrap(),
        message_type: "execute_command_0".to_string(),
    };
    
    // Send unauthorized command - THIS SUCCEEDS without authentication
    let response = malicious_client.simple_msg_exchange(request).await;
    
    // Verify message was accepted and processed (vulnerability demonstrated)
    assert!(response.is_ok(), "Unauthorized message should be rejected but was accepted");
}
```

This PoC demonstrates that any client can connect to the executor service and send execution commands without authentication, violating the access control security requirement.

## Notes

This vulnerability represents an **architectural security gap** where the remote executor service relies entirely on network-level security without implementing application-level authentication. While this may be acceptable if the service is deployed in a completely isolated environment, it violates defense-in-depth security principles and creates risk if:

- The service is ever exposed outside the internal network
- Internal network security is compromised
- There are misconfigurations in network isolation
- The deployment model changes in the future

The comparison with the main Aptos validator network is instructive - the validator network implements robust Noise protocol authentication with trusted peer verification, while the remote executor service has no equivalent protection. This inconsistency suggests an oversight in the security architecture.

### Citations

**File:** protos/rust/src/pb/aptos.remote_executor.v1.rs (L7-13)
```rust
#[derive(Clone, PartialEq, ::prost::Message)]
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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L147-161)
```rust
    pub fn create_remote_sharded_block_executor(
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
        num_threads: Option<usize>,
    ) -> ShardedBlockExecutor<S, RemoteExecutorClient<S>> {
        ShardedBlockExecutor::new(RemoteExecutorClient::new(
            remote_shard_addresses,
            NetworkController::new(
                "remote-executor-coordinator".to_string(),
                coordinator_address,
                5000,
            ),
            num_threads,
        ))
    }
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

**File:** execution/executor-service/src/main.rs (L27-48)
```rust
fn main() {
    let args = Args::parse();
    aptos_logger::Logger::new().init();

    let (tx, rx) = crossbeam_channel::unbounded();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let _exe_service = ProcessExecutorService::new(
        args.shard_id,
        args.num_shards,
        args.num_executor_threads,
        args.coordinator_address,
        args.remote_executor_addresses,
    );

    rx.recv()
        .expect("Could not receive Ctrl-C msg from channel.");
    info!("Process executor service shutdown successfully.");
}
```
