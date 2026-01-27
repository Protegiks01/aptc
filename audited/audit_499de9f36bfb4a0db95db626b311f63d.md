# Audit Report

## Title
Executor Service Panic on Coordinator Network Failure Causes Unsafe Shutdown and State Divergence

## Summary
The executor service panics when unable to send execution results to the coordinator after a network partition, causing the executor process to crash after it has already executed blocks. This creates state divergence between the coordinator and executor shards and violates the fail-safe invariant.

## Finding Description

The security question asks whether the executor fails safely when `coordinator_address` becomes unreachable after initialization. The answer is **no** - the executor fails unsafely by panicking after already executing blocks.

**Execution Flow:**

1. The executor service receives execute commands from the coordinator via `RemoteCoordinatorClient` [1](#0-0) 

2. The `ShardedExecutorService` executes the block completely [2](#0-1) 

3. After execution completes, it sends results back to the coordinator [3](#0-2) 

4. The result transmission uses `.unwrap()` which will panic on channel send failures [4](#0-3) 

5. Messages flow through the `NetworkController` to the `OutboundHandler` which calls `send_message` on the gRPC client [5](#0-4) 

6. **Critical vulnerability**: When the gRPC message send fails (e.g., coordinator unreachable), the code explicitly panics instead of handling the error gracefully [6](#0-5) 

**State Divergence Problem:**

The executor has already completed block execution and modified its local state before attempting to send results. If the network fails at this point:
- The executor's state reflects the executed block
- The coordinator never receives the results
- The executor process crashes via panic
- The coordinator may retry the block or proceed differently
- This creates state divergence between coordinator and executor shards

This breaks the **State Consistency** invariant that "state transitions must be atomic and verifiable" and the **Deterministic Execution** invariant.

**Additional Vulnerability:**

The same panic behavior affects state value requests during execution [7](#0-6) 

## Impact Explanation

This is **HIGH severity** per the Aptos bug bounty criteria:

1. **Validator node crashes** - The panic crashes the entire executor service process, requiring manual restart. This meets the "Validator node slowdowns" and "API crashes" criteria for HIGH severity.

2. **State inconsistencies requiring intervention** - The divergence between coordinator and executor state after a crash requires manual intervention to resync. This meets MEDIUM severity "State inconsistencies requiring intervention."

3. **Availability impact** - An attacker who can cause transient network partitions can repeatedly crash executor shards, degrading the sharded execution system's availability.

4. **Protocol violation** - The failure mode violates the expected atomicity of block execution. Either the block executes and results are reported, or execution fails and no state changes occur. The current implementation executes blocks but may crash before reporting results.

The vulnerability is rated **HIGH** because it causes process crashes and state inconsistencies that require intervention.

## Likelihood Explanation

**HIGH likelihood** - This vulnerability triggers in common operational scenarios:

1. **Network failures**: Any transient network partition between executor and coordinator triggers the panic
2. **Coordinator crashes**: If the coordinator process crashes while executors are sending results
3. **Configuration errors**: Incorrect firewall rules or network topology
4. **Resource exhaustion**: Coordinator overwhelmed and unable to accept connections
5. **Malicious attacks**: Attacker with network-level access can deliberately cause partitions

The code even includes a TODO comment acknowledging retry logic is needed but instead uses panic [8](#0-7) 

In production sharded execution environments, network issues between coordinator and executor shards are expected operational conditions, not exceptional circumstances warranting process termination.

## Recommendation

Replace panic behavior with proper error handling and retry logic:

**Fix 1: Implement retry with exponential backoff in `send_message`:**

```rust
pub async fn send_message(
    &mut self,
    sender_addr: SocketAddr,
    message: Message,
    mt: &MessageType,
) -> Result<(), Status> {
    let request = tonic::Request::new(NetworkMessage {
        message: message.data,
        message_type: mt.get_type(),
    });
    
    // Implement exponential backoff retry
    let mut retry_count = 0;
    const MAX_RETRIES: u32 = 5;
    const INITIAL_BACKOFF_MS: u64 = 100;
    
    loop {
        match self.remote_channel.simple_msg_exchange(request.clone()).await {
            Ok(_) => return Ok(()),
            Err(e) if retry_count < MAX_RETRIES => {
                let backoff = INITIAL_BACKOFF_MS * 2u64.pow(retry_count);
                warn!(
                    "Failed to send message to {} (attempt {}/{}): {}. Retrying in {}ms",
                    self.remote_addr, retry_count + 1, MAX_RETRIES, e, backoff
                );
                tokio::time::sleep(tokio::time::Duration::from_millis(backoff)).await;
                retry_count += 1;
            },
            Err(e) => {
                error!(
                    "Failed to send message to {} after {} retries: {}",
                    self.remote_addr, MAX_RETRIES, e
                );
                return Err(e);
            },
        }
    }
}
```

**Fix 2: Handle errors gracefully in `send_execution_result`:**

```rust
fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
    let remote_execution_result = RemoteExecutionResult::new(result);
    let output_message = bcs::to_bytes(&remote_execution_result).unwrap();
    
    // Handle send failures gracefully instead of panicking
    if let Err(e) = self.result_tx.send(Message::new(output_message)) {
        error!(
            "Failed to send execution result for shard {}: {}. Coordinator may be unreachable.",
            self.shard_id, e
        );
        // Consider: transition to degraded state, attempt reconnection, or graceful shutdown
    }
}
```

**Fix 3: Implement graceful degradation in `ShardedExecutorService`:**

The executor should transition to a "waiting for coordinator" state rather than crashing, attempting to reconnect and resync with the coordinator.

## Proof of Concept

```rust
// Test demonstrating the panic
#[cfg(test)]
mod test {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    #[test]
    #[should_panic(expected = "Error")]
    fn test_executor_panics_on_coordinator_unreachable() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        // Create executor with coordinator address that doesn't exist
        let coordinator_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), // TEST-NET-1, unreachable
            9999
        );
        
        let mut grpc_client = GRPCNetworkMessageServiceClientWrapper::new(
            &rt, 
            coordinator_addr
        );
        
        let sender_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let message = Message::new(vec![1, 2, 3]);
        let message_type = MessageType::new("test".to_string());
        
        // This will panic when trying to send to unreachable coordinator
        rt.block_on(async {
            grpc_client.send_message(sender_addr, message, &message_type).await;
        });
        
        // Never reaches here - process has panicked
    }
}
```

**Reproduction Steps:**

1. Start executor service with valid coordinator address
2. Execute a block successfully
3. Network partition occurs (firewall rule, coordinator crash, etc.)
4. Executor attempts to send execution results
5. gRPC send fails, code panics at the error handling
6. Executor process terminates unsafely
7. State divergence exists - executor executed block but coordinator never received results

## Notes

The vulnerability exists despite a TODO comment acknowledging the need for retry logic. The code explicitly chooses to panic on network failures rather than handling them gracefully, violating basic resilience principles for distributed systems. This is particularly critical for the executor service which manages state transitions that must remain consistent with the coordinator.

### Citations

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

**File:** execution/executor-service/src/remote_cordinator_client.rs (L115-119)
```rust
    fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
        let remote_execution_result = RemoteExecutionResult::new(result);
        let output_message = bcs::to_bytes(&remote_execution_result).unwrap();
        self.result_tx.send(Message::new(output_message)).unwrap();
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L239-248)
```rust
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
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L254-254)
```rust
                    self.coordinator_client.send_execution_result(ret);
```

**File:** secure/net/src/network_controller/outbound_handler.rs (L155-159)
```rust
                grpc_clients
                    .get_mut(remote_addr)
                    .unwrap()
                    .send_message(*socket_addr, msg, message_type)
                    .await;
```

**File:** secure/net/src/grpc_network_service/mod.rs (L150-150)
```rust
        // TODO: Retry with exponential backoff on failures
```

**File:** secure/net/src/grpc_network_service/mod.rs (L151-159)
```rust
        match self.remote_channel.simple_msg_exchange(request).await {
            Ok(_) => {},
            Err(e) => {
                panic!(
                    "Error '{}' sending message to {} on node {:?}",
                    e, self.remote_addr, sender_addr
                );
            },
        }
```

**File:** execution/executor-service/src/remote_state_view.rs (L172-180)
```rust
    fn send_state_value_request(
        shard_id: ShardId,
        sender: Arc<Sender<Message>>,
        state_keys: Vec<StateKey>,
    ) {
        let request = RemoteKVRequest::new(shard_id, state_keys);
        let request_message = bcs::to_bytes(&request).unwrap();
        sender.send(Message::new(request_message)).unwrap();
    }
```
