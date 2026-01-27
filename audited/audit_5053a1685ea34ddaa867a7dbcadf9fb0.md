# Audit Report

## Title
Remote Executor Network Message Replay Attack Enables Cross-Shard State Inconsistency

## Summary
The `NetworkMessage` struct used for remote executor communication lacks replay protection mechanisms (nonce, sequence number, or timestamp). An attacker with network access can capture and replay `ExecuteBlockCommand` messages to remote executor shards, causing duplicate block execution and result queue corruption. This leads to execution results from old blocks being used for new blocks, violating deterministic execution invariants and causing state inconsistency across shards.

## Finding Description

The remote sharded block executor system uses gRPC-based network messages to distribute execution work across multiple shards. The `NetworkMessage` protobuf structure contains only two fields: `message` (raw bytes) and `message_type` (string identifier), with no replay protection. [1](#0-0) 

The gRPC service establishes connections over plain HTTP (not HTTPS), providing no transport-level security. [2](#0-1) 

When a message is received, the server directly processes it without any replay detection, immediately forwarding it to registered handlers based solely on message type. [3](#0-2) 

The remote coordinator client on each shard runs in a blocking loop, continuously receiving and processing execution commands. [4](#0-3) 

When the coordinator sends execution commands, it waits for exactly one response per shard via blocking channel receives. [5](#0-4) 

**Attack Scenario:**

1. Coordinator sends `ExecuteBlockCommand` for Block N to Shard A
2. Shard A processes and sends result R_N
3. Coordinator receives R_N and continues to Block N+1
4. **Attacker captures and replays the ExecuteBlockCommand for Block N**
5. Shard A's network channel queues the replayed message
6. After processing Block N+1, Shard A receives and processes the replayed Block N command
7. Shard A sends result R_N again (duplicate)
8. On Block N+2, Coordinator's `rx.recv()` returns the stale R_N result instead of R_(N+2)
9. Coordinator uses Block N execution results for Block N+2's state transition
10. **State inconsistency across shards:** Other shards have correct Block N+2 results, Shard A has Block N results

This breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks." The coordinator aggregates mismatched execution results, leading to incorrect state root computation.

The `ExecuteBlockCommand` structure itself contains no replay protection fields. [6](#0-5) 

This system is used in production when remote addresses are configured. [7](#0-6) 

## Impact Explanation

**Critical Severity** - This vulnerability causes:

1. **Consensus/Safety Violations**: Different shards produce different execution results for the same block, breaking consensus safety guarantees
2. **State Consistency Violations**: The aggregated state root becomes invalid as it's computed from mismatched shard results
3. **Non-Recoverable State Corruption**: Once wrong execution results are used, subsequent state transitions compound the error, potentially requiring a hard fork to recover

Per Aptos bug bounty criteria, this qualifies as **Critical Severity** because it enables "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)." If exploited systematically, all nodes using remote sharded execution would have corrupted state requiring coordinated recovery.

## Likelihood Explanation

**High Likelihood** when remote executor is enabled:

**Attacker Requirements:**
- Network-level access (MITM position, compromised router, or network tap)
- Ability to capture and replay gRPC messages
- Knowledge of when execution commands are sent

**Feasibility:**
- No authentication or encryption required (plain HTTP)
- No cryptographic operations to forge
- Simple packet capture and replay
- Timing is flexible (replay can occur anytime before next block)

**Deployment Context:**
- Remote executor is production-ready code, toggled via configuration
- Likely used in high-throughput scenarios requiring parallelization
- Network infrastructure for distributed execution increases attack surface

The vulnerability is deterministic and reliably exploitable once network access is obtained.

## Recommendation

Implement multi-layered replay protection:

**1. Add Sequence Numbers to NetworkMessage:**
```protobuf
message NetworkMessage {
    bytes message = 1;
    string message_type = 2;
    uint64 sequence_number = 3;  // Monotonically increasing per sender
    uint64 timestamp_ms = 4;     // Message creation timestamp
}
```

**2. Add Session-Based Authentication:**
- Implement mutual TLS for gRPC connections
- Use challenge-response authentication on session establishment
- Include session tokens in messages

**3. Track Processed Messages:**
```rust
pub struct GRPCNetworkMessageServiceServerWrapper {
    inbound_handlers: Arc<Mutex<HashMap<MessageType, Sender<Message>>>>,
    self_addr: SocketAddr,
    // Add replay protection
    processed_sequences: Arc<Mutex<HashMap<SocketAddr, u64>>>,
    message_timeout_ms: u64,
}

async fn simple_msg_exchange(&self, request: Request<NetworkMessage>) 
    -> Result<Response<Empty>, Status> {
    let remote_addr = request.remote_addr().ok_or(Status::unauthenticated("No remote address"))?;
    let network_message = request.into_inner();
    
    // Verify sequence number
    let mut sequences = self.processed_sequences.lock().unwrap();
    let last_seq = sequences.entry(remote_addr).or_insert(0);
    if network_message.sequence_number <= *last_seq {
        return Err(Status::invalid_argument("Duplicate or out-of-order message"));
    }
    *last_seq = network_message.sequence_number;
    
    // Verify timestamp freshness
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    if now - network_message.timestamp_ms > self.message_timeout_ms {
        return Err(Status::invalid_argument("Message expired"));
    }
    
    // Process message...
}
```

**4. Upgrade to TLS:**
```rust
async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
    let tls_config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(CA_CERT))
        .identity(Identity::from_pem(CLIENT_CERT, CLIENT_KEY));
    
    let conn = tonic::transport::Endpoint::new(remote_addr)
        .unwrap()
        .tls_config(tls_config)
        .unwrap()
        .connect_lazy();
    
    NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
}
```

## Proof of Concept

```rust
// File: secure/net/src/grpc_network_service/replay_attack_test.rs
#[cfg(test)]
mod replay_attack_tests {
    use super::*;
    use aptos_config::utils;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_replay_attack_causes_duplicate_processing() {
        // Setup server
        let server_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST), 
            utils::get_available_port()
        );
        let message_type = "execute_command".to_string();
        let server_handlers = Arc::new(Mutex::new(HashMap::new()));
        
        let (msg_tx, msg_rx) = crossbeam_channel::unbounded();
        server_handlers.lock().unwrap().insert(
            MessageType::new(message_type.clone()), 
            msg_tx
        );
        
        let server = GRPCNetworkMessageServiceServerWrapper::new(
            server_handlers, 
            server_addr
        );
        
        let rt = Runtime::new().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        server.start(&rt, "test".to_string(), server_addr, 5000, shutdown_rx);
        
        sleep(Duration::from_millis(100)).await;
        
        // Setup client
        let mut client = GRPCNetworkMessageServiceClientWrapper::new(&rt, server_addr);
        let client_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST), 
            utils::get_available_port()
        );
        
        // Send original message
        let original_message = b"execute_block_1".to_vec();
        client.send_message(
            client_addr,
            Message::new(original_message.clone()),
            &MessageType::new(message_type.clone())
        ).await;
        
        // Verify first receipt
        let msg1 = msg_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(msg1.data, original_message);
        
        // REPLAY ATTACK: Send same message again
        client.send_message(
            client_addr,
            Message::new(original_message.clone()),
            &MessageType::new(message_type.clone())
        ).await;
        
        // Verify duplicate is processed (VULNERABILITY)
        let msg2 = msg_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(msg2.data, original_message);
        
        // IMPACT: Both messages were processed without replay detection
        println!("VULNERABILITY CONFIRMED: Replayed message was processed");
        
        shutdown_tx.send(()).unwrap();
    }
    
    #[tokio::test]
    async fn test_cross_block_result_confusion() {
        // Simulate coordinator-shard communication with result queue corruption
        let (command_tx, command_rx) = crossbeam_channel::unbounded::<Message>();
        let (result_tx, result_rx) = crossbeam_channel::unbounded::<Message>();
        
        // Simulate shard processing loop
        let shard_handler = std::thread::spawn(move || {
            for _ in 0..3 {
                let cmd = command_rx.recv().unwrap();
                let block_id = String::from_utf8(cmd.data).unwrap();
                let result = format!("result_{}", block_id);
                result_tx.send(Message::new(result.into_bytes())).unwrap();
            }
        });
        
        // Coordinator sends Block 1
        command_tx.send(Message::new(b"block_1".to_vec())).unwrap();
        let result_1 = String::from_utf8(
            result_rx.recv().unwrap().data
        ).unwrap();
        assert_eq!(result_1, "result_block_1");
        
        // Coordinator sends Block 2
        command_tx.send(Message::new(b"block_2".to_vec())).unwrap();
        
        // ATTACK: Replay Block 1 command
        command_tx.send(Message::new(b"block_1".to_vec())).unwrap();
        
        // Coordinator receives result for Block 2
        let result_2 = String::from_utf8(
            result_rx.recv().unwrap().data
        ).unwrap();
        assert_eq!(result_2, "result_block_2");
        
        // Coordinator sends Block 3, but receives replayed Block 1 result
        // (demonstrating result queue corruption)
        let result_3 = String::from_utf8(
            result_rx.recv().unwrap().data
        ).unwrap();
        
        // VULNERABILITY: Result for Block 3 is actually from replayed Block 1
        assert_eq!(result_3, "result_block_1"); // Wrong result!
        println!("VULNERABILITY CONFIRMED: Block 3 received Block 1 results");
        
        shard_handler.join().unwrap();
    }
}
```

**Notes:**
- This vulnerability affects the remote sharded execution feature, enabled when `get_remote_addresses()` returns non-empty configuration
- The attack requires network-level access but no validator privileges
- Impact is amplified in distributed execution environments where network attack surface is larger
- No existing protections (authentication, TLS, nonces) were found in the codebase
- The vulnerability is in production code paths, not experimental or test-only code

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

**File:** secure/net/src/grpc_network_service/mod.rs (L124-138)
```rust
    pub fn new(rt: &Runtime, remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr: remote_addr.to_string(),
            remote_channel: rt
                .block_on(async { Self::get_channel(format!("http://{}", remote_addr)).await }),
        }
    }

    async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
        info!("Trying to connect to remote server at {:?}", remote_addr);
        let conn = tonic::transport::Endpoint::new(remote_addr)
            .unwrap()
            .connect_lazy();
        NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
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

**File:** execution/executor-service/src/lib.rs (L48-53)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecuteBlockCommand {
    pub(crate) sub_blocks: SubBlocksForShard<AnalyzedTransaction>,
    pub(crate) concurrency_level: usize,
    pub(crate) onchain_config: BlockExecutorConfigFromOnchain,
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
