# Audit Report

## Title
Executor Service Shard Crash Due to Unhandled Channel Send Failure in Cross-Shard Communication

## Summary
The `RemoteCrossShardClient::send_cross_shard_msg()` function uses `.unwrap()` on channel send operations, which causes a panic and crashes the executor service thread when the receiver end is closed. This occurs during distributed block execution when cross-shard messages are transmitted over network channels.

## Finding Description

The vulnerability exists in the cross-shard communication system used for distributed block execution. [1](#0-0) 

The `send_cross_shard_msg()` function acquires a channel sender and calls `.unwrap()` on the send operation. When the receiver end of the channel is closed, the send operation returns an error, and the `.unwrap()` causes a panic.

The channel receivers are managed by the `OutboundHandler`, which runs in an async task: [2](#0-1) 

The OutboundHandler exits its loop (dropping all receivers) when it receives a disconnect error or stop signal. This can occur during:
1. NetworkController shutdown
2. Network failures causing GRPC disconnections
3. OutboundHandler task crashes

The cross-shard message sending occurs in two critical paths:

**Path 1: During Transaction Execution** [3](#0-2) 

The `CrossShardCommitSender` implements `TransactionCommitHook` and sends cross-shard messages when transactions commit, which is invoked during parallel block execution: [4](#0-3) 

**Path 2: After Block Execution Completes** [5](#0-4) 

The panic propagates through the rayon thread pool scope and crashes the executor service thread: [6](#0-5) 

There is no panic handler or recovery mechanism - when the thread crashes, that shard executor becomes permanently unavailable.

## Impact Explanation

This vulnerability results in **High Severity** impact per the Aptos bug bounty criteria, specifically "Validator node slowdowns" and "Significant protocol violations."

When a shard executor crashes:
- The affected shard cannot process any further block execution requests
- Distributed block execution fails for blocks that include transactions on that shard
- The coordinator cannot complete block execution and must retry or fail
- The node requires manual restart to recover

While this doesn't directly cause consensus violations (as distributed execution is a performance optimization), it severely degrades network performance and availability. If multiple shards fail, the distributed execution system becomes unavailable, forcing fallback to single-node execution or complete execution failure.

## Likelihood Explanation

The likelihood is **Medium** because it requires specific timing conditions:

**Triggering Scenarios:**
1. **Graceful Shutdown Race Condition**: If `NetworkController.shutdown()` is called while block execution is in progress, the OutboundHandler exits and drops receivers before the executor finishes sending messages
2. **Network Failures**: Transient GRPC connection failures causing the OutboundHandler to exit
3. **Task Crashes**: Any panic or fatal error in the OutboundHandler task itself

The vulnerability is not directly exploitable by an external attacker without network-level access (which is out of scope). However, it represents a critical reliability issue that can occur during normal operations, particularly during node restart or network partition scenarios.

## Recommendation

Replace `.unwrap()` with proper error handling that gracefully handles closed channels:

```rust
fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
    let input_message = bcs::to_bytes(&msg).unwrap();
    let tx = self.message_txs[shard_id][round].lock().unwrap();
    if let Err(e) = tx.send(Message::new(input_message)) {
        warn!(
            "Failed to send cross-shard message to shard {} round {}: {:?}. \
             Network connection may be closed.",
            shard_id, round, e
        );
        // Return error instead of panicking
        // Caller should handle this gracefully
    }
}
```

The `CrossShardClient` trait should be updated to return `Result` types:

```rust
pub trait CrossShardClient: Send + Sync {
    fn send_global_msg(&self, msg: CrossShardMsg) -> Result<(), SendError>;
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) -> Result<(), SendError>;
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> Result<CrossShardMsg, RecvError>;
}
```

All call sites should handle errors appropriately, potentially by:
- Logging errors and continuing execution for non-critical messages
- Returning errors to callers for critical messages
- Implementing retry logic with timeouts

## Proof of Concept

The following Rust test demonstrates the panic scenario:

```rust
#[test]
#[should_panic(expected = "sending on a closed channel")]
fn test_cross_shard_send_panic_on_closed_channel() {
    use crossbeam_channel::unbounded;
    
    // Simulate the channel setup
    let (tx, rx) = unbounded();
    
    // Drop the receiver to simulate OutboundHandler exit
    drop(rx);
    
    // Attempt to send - this will panic with .unwrap()
    tx.send("test_message").unwrap();
}

#[test]
fn test_executor_service_crash_on_network_shutdown() {
    use std::sync::Arc;
    use std::net::SocketAddr;
    
    // Create executor service with network controller
    let mut controller = NetworkController::new(
        "test".to_string(),
        "127.0.0.1:8080".parse().unwrap(),
        5000
    );
    
    let remote_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
    let tx = controller.create_outbound_channel(remote_addr, "cross_shard_0".to_string());
    
    controller.start();
    
    // Simulate network failure by shutting down controller
    controller.shutdown();
    
    // Give OutboundHandler time to exit
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    // Attempt to send - this will panic
    let result = std::panic::catch_unwind(|| {
        tx.send(Message::new(vec![1, 2, 3])).unwrap();
    });
    
    assert!(result.is_err(), "Expected panic when sending on closed channel");
}
```

**Notes**

This vulnerability is specific to the distributed execution feature (`RemoteCrossShardClient`) but the identical pattern exists in the local execution variant (`LocalCrossShardClient`): [7](#0-6) 

Both implementations should be fixed. The issue fundamentally stems from using `.unwrap()` on channel operations in production code paths where failures are possible and should be handled gracefully rather than causing process crashes.

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-59)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
    }
```

**File:** secure/net/src/network_controller/outbound_handler.rs (L103-145)
```rust
    async fn process_one_outgoing_message(
        outbound_handlers: Vec<(Receiver<Message>, SocketAddr, MessageType)>,
        socket_addr: &SocketAddr,
        inbound_handler: Arc<Mutex<InboundHandler>>,
        grpc_clients: &mut HashMap<SocketAddr, GRPCNetworkMessageServiceClientWrapper>,
    ) {
        loop {
            let mut select = Select::new();
            for (receiver, _, _) in outbound_handlers.iter() {
                select.recv(receiver);
            }

            let index;
            let msg;
            let _timer;
            {
                let oper = select.select();
                _timer = NETWORK_HANDLER_TIMER
                    .with_label_values(&[&socket_addr.to_string(), "outbound_msgs"])
                    .start_timer();
                index = oper.index();
                match oper.recv(&outbound_handlers[index].0) {
                    Ok(m) => {
                        msg = m;
                    },
                    Err(e) => {
                        warn!(
                            "{:?} for outbound handler on {:?}. This can happen in shutdown,\
                             but should not happen otherwise",
                            e.to_string(),
                            socket_addr
                        );
                        return;
                    },
                }
            }

            let remote_addr = &outbound_handlers[index].1;
            let message_type = &outbound_handlers[index].2;

            if message_type.get_type() == "stop_task" {
                return;
            }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L125-129)
```rust
                        self.cross_shard_client.send_cross_shard_msg(
                            *dependent_shard_id,
                            *round_id,
                            message,
                        );
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L417-424)
```rust
                txn_listener.on_transaction_committed(
                    txn_idx,
                    output_wrapper
                        .output
                        .as_ref()
                        .expect("Output must be set when status is success or skip rest")
                        .committed_output(),
                );
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L164-168)
```rust
                    cross_shard_client_clone.send_cross_shard_msg(
                        shard_id,
                        round,
                        CrossShardMsg::StopMsg,
                    );
```

**File:** execution/executor-service/src/remote_executor_service.rs (L62-66)
```rust
        builder
            .spawn(move || {
                executor_service_clone.start();
            })
            .expect("Failed to spawn thread");
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L331-333)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        self.message_txs[shard_id][round].send(msg).unwrap()
    }
```
