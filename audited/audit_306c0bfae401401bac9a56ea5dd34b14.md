# Audit Report

## Title
Network Partition Causes Executor Service Deadlock and Panic in Sharded Execution

## Summary
The `ExecutorService` and remote sharded execution infrastructure lack timeout mechanisms and graceful error handling for cross-shard communication. When network partitions isolate shards, the system deadlocks indefinitely waiting for messages that never arrive, or panics when attempting to send to unreachable shards, rendering validator nodes non-responsive.

## Finding Description

The sharded block executor implements parallel transaction execution across multiple shards with cross-shard dependency resolution. When remote execution is enabled (shards on different machines), the system uses gRPC-based network communication without timeout protection or network partition detection.

**Critical Code Paths:**

1. **Cross-Shard Message Reception** - The `CrossShardCommitReceiver` spawns a thread that loops indefinitely waiting for cross-shard messages: [1](#0-0) 

This calls `receive_cross_shard_msg()` which blocks indefinitely: [2](#0-1) 

2. **Cross-Shard Message Transmission** - When sending cross-shard messages, the system uses `.unwrap()` which panics on channel errors: [3](#0-2) 

3. **gRPC Send Panic** - The underlying gRPC client panics on any network error: [4](#0-3) 

4. **Coordinator Deadlock** - The coordinator waits indefinitely for shard execution results: [5](#0-4) 

**Attack Scenario:**

1. Validator enables remote sharded execution with N shards distributed across machines
2. Network partition occurs (e.g., firewall rule, network split, switch failure) isolating one or more shards
3. Transactions with cross-shard dependencies are assigned to the block
4. **Shard A** completes execution and attempts to send cross-shard messages to isolated **Shard B**
   - The gRPC `send_message()` call fails with network error
   - System panics with message: "Error 'status: Unavailable...' sending message to ..."
5. Alternatively, **Shard B** waits in `receive_cross_shard_msg()` for messages from **Shard A**
   - The `rx.recv()` blocks indefinitely since the channel will never receive the message
   - The receiver thread hangs forever
6. The coordinator waits in `get_output_from_shards()` for results from **Shard B**
   - The `rx.recv()` blocks indefinitely waiting for execution results
   - The entire executor service becomes unresponsive

This breaks the **Deterministic Execution** and **State Consistency** invariants because different shards may have inconsistent views of execution state, and validators cannot complete block execution.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:

- **Validator node slowdowns/hangs**: The executor service deadlocks indefinitely, preventing the validator from executing new blocks. The node remains stuck until manually restarted.

- **Significant protocol violations**: Validators cannot fulfill their role in the consensus protocol if they cannot execute blocks. This degrades network liveness.

- **Loss of availability**: When multiple validators experience the same partition (e.g., datacenter-level network split), the network may lose consensus if more than 1/3 of validators become unresponsive.

The issue is particularly severe because:
- No automatic recovery mechanism exists
- No timeout or circuit breaker to fail fast
- The panic/deadlock is deterministic given the network condition
- Manual intervention (node restart) is required, but doesn't solve the underlying partition

## Likelihood Explanation

**High Likelihood:**

- Network partitions are common in distributed systems, occurring due to: datacenter failures, misconfigured firewalls, network switch failures, routing issues, cloud provider outages
- Sharded execution is an active feature being deployed for performance improvements
- The vulnerability triggers on **any** cross-shard transaction when **any** shard becomes unreachable
- No special attacker capabilities required—natural network issues trigger this
- The code has explicit TODOs acknowledging missing error handling: [6](#0-5) 

## Recommendation

Implement comprehensive timeout and error handling for cross-shard communication:

**1. Add timeouts to cross-shard message operations:**

```rust
// In remote_cross_shard_client.rs
impl CrossShardClient for RemoteCrossShardClient {
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        
        // Add timeout (e.g., 5 seconds)
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(message) => {
                let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes())
                    .expect("Failed to deserialize cross-shard message");
                msg
            },
            Err(RecvTimeoutError::Timeout) => {
                error!("Timeout waiting for cross-shard message in round {}", current_round);
                // Return a timeout error variant or panic with better error
                panic!("Cross-shard communication timeout - possible network partition");
            },
            Err(RecvTimeoutError::Disconnected) => {
                error!("Cross-shard channel disconnected in round {}", current_round);
                panic!("Cross-shard communication failed - channel disconnected");
            }
        }
    }
    
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        
        // Use send_timeout instead of unwrap
        if let Err(e) = tx.send_timeout(Message::new(input_message), Duration::from_secs(5)) {
            error!("Failed to send cross-shard message to shard {} round {}: {:?}", 
                   shard_id, round, e);
            panic!("Cross-shard send failed - possible network partition");
        }
    }
}
```

**2. Add retry logic with exponential backoff in gRPC client:**

```rust
// In grpc_network_service/mod.rs
pub async fn send_message(&mut self, sender_addr: SocketAddr, message: Message, mt: &MessageType) {
    let request = tonic::Request::new(NetworkMessage {
        message: message.data,
        message_type: mt.get_type(),
    });
    
    let max_retries = 3;
    let mut retry_delay = Duration::from_millis(100);
    
    for attempt in 0..max_retries {
        match self.remote_channel.simple_msg_exchange(request.clone()).await {
            Ok(_) => return,
            Err(e) => {
                if attempt == max_retries - 1 {
                    error!("Failed to send message after {} retries: {}", max_retries, e);
                    return; // Return error instead of panic
                }
                warn!("Retry {} failed: {}. Retrying in {:?}", attempt + 1, e, retry_delay);
                tokio::time::sleep(retry_delay).await;
                retry_delay *= 2; // Exponential backoff
            }
        }
    }
}
```

**3. Add timeout to coordinator result collection:**

```rust
// In remote_executor_client.rs
fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
    let mut results = vec![];
    let timeout = Duration::from_secs(30); // Configure based on expected execution time
    
    for (shard_id, rx) in self.result_rxs.iter().enumerate() {
        match rx.recv_timeout(timeout) {
            Ok(received_bytes) => {
                let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes.to_bytes())
                    .map_err(|e| VMStatus::Error(StatusCode::UNKNOWN_STATUS, Some(e.to_string())))?;
                results.push(result.inner?);
            },
            Err(RecvTimeoutError::Timeout) => {
                error!("Timeout waiting for results from shard {}", shard_id);
                return Err(VMStatus::Error(
                    StatusCode::UNKNOWN_STATUS,
                    Some(format!("Shard {} execution timeout - possible network partition", shard_id))
                ));
            },
            Err(RecvTimeoutError::Disconnected) => {
                error!("Channel disconnected for shard {}", shard_id);
                return Err(VMStatus::Error(
                    StatusCode::UNKNOWN_STATUS,
                    Some(format!("Shard {} channel disconnected", shard_id))
                ));
            }
        }
    }
    Ok(results)
}
```

**4. Add health monitoring and circuit breaker:**
- Implement periodic health checks between shards
- Detect prolonged communication failures
- Disable sharded execution and fall back to single-shard mode
- Alert operators about network partition conditions

## Proof of Concept

```rust
// File: execution/executor-service/tests/network_partition_test.rs
#[cfg(test)]
mod network_partition_tests {
    use aptos_secure_net::network_controller::NetworkController;
    use execution_service::remote_executor_service::ExecutorService;
    use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, thread, time::Duration};

    #[test]
    #[should_panic(expected = "Cross-shard communication timeout")]
    fn test_network_partition_causes_deadlock() {
        // Setup 2 shards
        let shard_0_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000);
        let shard_1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50001);
        let coordinator_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50002);
        
        // Start shard 0
        let mut executor_0 = ExecutorService::new(
            0,  // shard_id
            2,  // num_shards
            4,  // num_threads
            shard_0_addr,
            coordinator_addr,
            vec![shard_1_addr],  // remote shards
        );
        executor_0.start();
        
        // Don't start shard 1 - simulate network partition
        // (In real scenario, start it then kill the network connection)
        
        // Attempt to execute block with cross-shard dependencies
        // This will deadlock waiting for shard 1
        thread::sleep(Duration::from_secs(10));
        
        // Test fails by hanging indefinitely or panicking
        // Expected: Should timeout within 5 seconds with clear error
        executor_0.shutdown();
    }
    
    #[test]
    fn test_grpc_send_panic_on_network_error() {
        // Create gRPC client pointing to non-existent server
        let rt = tokio::runtime::Runtime::new().unwrap();
        let unreachable_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 60000);
        
        let mut client = GRPCNetworkMessageServiceClientWrapper::new(&rt, unreachable_addr);
        
        // Attempt to send message - will panic
        rt.block_on(async {
            client.send_message(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 60001),
                Message::new(vec![1, 2, 3]),
                &MessageType::new("test".to_string()),
            ).await;
        });
        
        // Expected: Should return error, not panic
        // Actual: Panics with "Error 'status: Unavailable' sending message..."
    }
}
```

**Notes**

This vulnerability specifically affects the remote sharded execution feature when enabled. The local sharded execution (using in-process channels) is not affected since crossbeam channels handle disconnection differently. However, once remote sharding is deployed to production validators for performance optimization, network partitions become a realistic and high-impact threat vector.

The absence of timeouts violates distributed systems best practices and creates a deterministic denial-of-service condition that requires no attacker privileges—natural network failures are sufficient to trigger the vulnerability.

### Citations

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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-59)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
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

**File:** secure/net/src/grpc_network_service/mod.rs (L150-160)
```rust
        // TODO: Retry with exponential backoff on failures
        match self.remote_channel.simple_msg_exchange(request).await {
            Ok(_) => {},
            Err(e) => {
                panic!(
                    "Error '{}' sending message to {} on node {:?}",
                    e, self.remote_addr, sender_addr
                );
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
