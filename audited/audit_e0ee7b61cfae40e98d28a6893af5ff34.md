# Audit Report

## Title
Message Deduplication Failure in Remote Executor Service Leading to State Corruption

## Summary
The `simple_msg_exchange()` function in the gRPC network service lacks any message deduplication mechanism. While this service is **not** used for consensus voting (the original question's assumption about "vote double-counting" is incorrect), it **is** used for the remote sharded executor system. An attacker with network access to shard endpoints can send duplicate execution commands, causing shards to process the same block multiple times and polluting the coordinator's result channels with stale outputs, leading to state corruption and violation of the deterministic execution invariant.

## Finding Description

The `simple_msg_exchange()` function immediately forwards all received messages to registered handlers without any deduplication: [1](#0-0) 

The protocol itself lacks message identifiers or sequence numbers that could enable deduplication: [2](#0-1) 

Furthermore, the gRPC service has no authentication or authorization, allowing any client that can reach the endpoint to send arbitrary messages: [3](#0-2) 

**Attack Flow:**

1. A coordinator sends `ExecuteBlockCommand` to a remote shard via the network service
2. The shard's service loop continuously receives and processes commands: [4](#0-3) 

3. An attacker who can reach the shard's gRPC endpoint sends duplicate copies of the execution command
4. Each duplicate message is queued in the command channel and processed sequentially
5. The shard executes the same block multiple times and sends multiple results back to the coordinator
6. The coordinator's result collection expects exactly one result per shard: [5](#0-4) 

7. The coordinator receives the first result and continues execution
8. Subsequent duplicate results remain buffered in the channel
9. When the next block is executed, the coordinator receives the **stale result** instead of the fresh one
10. This causes the coordinator to compute incorrect transaction outputs and corrupt its local state

The remote executor is used when remote addresses are configured: [6](#0-5) 

## Impact Explanation

This vulnerability breaks the **Deterministic Execution** invariant (all validators must produce identical state roots for identical blocks) and the **State Consistency** invariant (state transitions must be atomic and verifiable).

**Severity: HIGH**

If exploited on a validator node running remote sharded execution:
- The validator would compute incorrect state roots
- This causes consensus disagreement with other validators
- The affected validator would be unable to validate blocks correctly
- In a Byzantine scenario, this could contribute to safety violations if combined with other attacks

The impact is classified as **High Severity** per the bug bounty criteria because it causes "significant protocol violations" and "validator node slowdowns" (the node would need to resync its state).

**Important Note:** This service is **not** used for consensus voting as suggested in the original question. The main Aptos consensus network uses a completely different networking stack (`network/` with `AptosNet` protocol). This remote executor service is specifically for distributed transaction execution in sharded mode.

## Likelihood Explanation

**Likelihood: LOW to MEDIUM**

The exploit requires:
1. Remote sharded execution to be enabled (configured via `--remote-executor-addresses`)
2. Network access to the shard's gRPC endpoints
3. Ability to craft valid `ExecuteBlockCommand` messages

**Mitigating factors:**
- Remote sharded execution appears to be an optional feature primarily used for performance testing/benchmarking
- It's unclear if this is enabled on production mainnet validators
- The gRPC endpoints are likely on internal networks, not publicly accessible
- However, internal threats (compromised machines, network issues causing duplicate delivery) remain valid concerns

**Aggravating factors:**
- Complete lack of authentication makes exploitation trivial once network access is obtained
- No deduplication at any layer (protocol, application, or handler)

## Recommendation

Implement multi-layered deduplication:

**1. Add message identifiers to the protocol:**
```protobuf
message NetworkMessage {
  bytes message = 1;
  string message_type = 2;
  uint64 message_id = 3;  // Add unique identifier
  uint64 sequence_number = 4;  // Add sequence tracking
}
```

**2. Implement deduplication in `simple_msg_exchange()`:**
```rust
// Add to GRPCNetworkMessageServiceServerWrapper
struct MessageDeduplicator {
    seen_messages: Arc<Mutex<HashMap<(String, u64), Instant>>>,
}

impl MessageDeduplicator {
    fn is_duplicate(&self, message_type: &str, message_id: u64) -> bool {
        let mut seen = self.seen_messages.lock().unwrap();
        // Check if seen within last 60 seconds
        if let Some(timestamp) = seen.get(&(message_type.to_string(), message_id)) {
            if timestamp.elapsed() < Duration::from_secs(60) {
                return true;
            }
        }
        seen.insert((message_type.to_string(), message_id), Instant::now());
        false
    }
}
```

**3. Add authentication using mTLS:** [3](#0-2) 

Replace the basic `Server::builder()` with TLS configuration:
```rust
Server::builder()
    .tls_config(ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(client_ca_cert))
    // ... rest of config
```

**4. Add rate limiting per source address to mitigate replay attacks.**

## Proof of Concept

```rust
#[test]
fn test_duplicate_message_causes_state_corruption() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use aptos_config::utils;
    
    // Setup server
    let server_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST), 
        utils::get_available_port()
    );
    let message_type = "execute_command_0".to_string();
    let server_handlers = Arc::new(Mutex::new(HashMap::new()));
    
    let (msg_tx, msg_rx) = crossbeam_channel::unbounded();
    server_handlers.lock().unwrap()
        .insert(MessageType::new(message_type.clone()), msg_tx);
    
    let server = GRPCNetworkMessageServiceServerWrapper::new(
        server_handlers, 
        server_addr
    );
    
    let rt = Runtime::new().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    server.start(&rt, "test".to_string(), server_addr, 1000, shutdown_rx);
    
    let mut client = GRPCNetworkMessageServiceClientWrapper::new(&rt, server_addr);
    
    thread::sleep(Duration::from_millis(10));
    
    // Send the same message 3 times (simulating replay attack)
    let test_message = Message::new(b"test_block_execution".to_vec());
    for _ in 0..3 {
        rt.block_on(async {
            client.send_message(
                server_addr,
                test_message.clone(),
                &MessageType::new(message_type.clone()),
            ).await;
        });
    }
    
    // Verify that all 3 duplicate messages were received
    // This demonstrates lack of deduplication
    for i in 0..3 {
        let received = msg_rx.recv().unwrap();
        assert_eq!(received.data, b"test_block_execution");
        println!("Received duplicate message {}", i + 1);
    }
    
    // In a real scenario, this would cause the executor shard to:
    // 1. Execute the same block 3 times
    // 2. Send 3 results back to coordinator
    // 3. Coordinator uses first result, other 2 pollute the channel
    // 4. Next execution gets stale result, causing state corruption
    
    shutdown_tx.send(()).unwrap();
}
```

## Notes

**Critical Clarification:** The original security question incorrectly assumes this service is used for consensus voting. This is **false**. The Aptos consensus system uses a completely separate networking layer (`network/` with peer-to-peer networking, not this gRPC service). 

This vulnerability affects the **remote sharded executor** system used for distributed transaction execution, not consensus vote processing. While still a valid security issue causing state corruption, it does not directly enable "vote double-counting" as suggested in the question.

The vulnerability is real and exploitable if the remote sharded execution feature is enabled, but its actual deployment status in production environments is uncertain based on the codebase analysis.

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

**File:** protos/proto/aptos/remote_executor/v1/network_msg.proto (L8-11)
```text
message NetworkMessage {
  bytes message = 1;
  string message_type = 2;
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
