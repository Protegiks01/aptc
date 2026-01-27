# Audit Report

## Title
GRPC Message Reordering in Remote Cross-Shard Execution Causes Consensus Failures

## Summary
In remote cross-shard execution mode, the `RemoteCrossShardClient` uses GRPC unary RPCs to transmit cross-shard messages. GRPC/HTTP2 does not guarantee ordering across separate unary RPC calls, allowing the `StopMsg` to overtake data messages (`RemoteTxnWriteMsg`). This causes the `CrossShardCommitReceiver` to exit prematurely, leaving transactions indefinitely blocked while waiting for cross-shard state values that never arrive, resulting in consensus failures and network liveness loss.

## Finding Description

The vulnerability exists in the message ordering assumptions of the remote cross-shard execution system. The execution flow works as follows:

1. During sharded block execution, `CrossShardCommitSender` sends `RemoteTxnWriteMsg` messages to dependent shards as transactions commit. [1](#0-0) 

2. These messages are sent via `send_cross_shard_msg()` which serializes and transmits them over network channels. [2](#0-1) 

3. After execution completes, a `StopMsg` is sent to signal the receiver thread to terminate. [3](#0-2) 

4. The `CrossShardCommitReceiver` processes messages in a loop until it receives `StopMsg`. [4](#0-3) 

**The Critical Flaw:**

Each `send_cross_shard_msg()` call becomes a separate GRPC unary RPC via `send_message()`. [5](#0-4) 

GRPC over HTTP/2 multiplexes requests as separate streams and **does not guarantee ordering across different streams**. The GRPC server processes incoming RPCs concurrently through separate async tasks, which can further reorder messages based on task scheduling. [6](#0-5) 

**Attack Scenario:**

Shard A sends to Shard B:
1. `RemoteTxnWriteMsg(key1, value1)` 
2. `RemoteTxnWriteMsg(key2, value2)`
3. `RemoteTxnWriteMsg(key3, value3)` (data for dependent transaction)
4. Later, Shard B sends `StopMsg` to itself

Due to network conditions or GRPC concurrent processing, Shard B receives:
1. `RemoteTxnWriteMsg(key1, value1)`
2. `StopMsg` ← **arrives early**
3. Messages for key2, key3 never processed

Shard B's receiver exits, and transactions depending on key3 call `RemoteStateValue::get_value()` which blocks indefinitely on a condition variable with no timeout. [7](#0-6) 

**Invariant Violations:**

- **Deterministic Execution (Invariant #1):** Different validators may hang or fail at different points due to non-deterministic message arrival
- **Consensus Safety (Invariant #2):** Validators cannot reach agreement when some hang indefinitely

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000)

This meets the "Total loss of liveness/network availability" category from the Aptos bug bounty program. When message reordering occurs:

1. **Consensus Failure:** Validators receiving messages in different orders will exhibit different behaviors—some hanging, some completing—preventing consensus agreement
2. **Network Partition:** Affected validators become permanently stuck waiting for messages, effectively removing them from the validator set
3. **No Automatic Recovery:** The infinite block in `get_value()` has no timeout mechanism, requiring manual intervention or node restart
4. **Deterministic Execution Violation:** The non-deterministic message ordering violates the fundamental requirement that all validators execute identically

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability can manifest under normal network conditions:

1. **Network Latency Variance:** Real-world networks have variable latency that naturally causes message reordering
2. **GRPC Concurrency:** The GRPC server's concurrent request processing introduces non-determinism independent of network conditions
3. **No Mitigation:** The code has no sequence numbers, acknowledgments, or ordering guarantees to prevent this issue
4. **Probability Increases with Scale:** More shards and cross-shard dependencies increase the probability of reordering

The vulnerability requires:
- Remote cross-shard execution mode (multi-node deployment)
- Cross-shard transaction dependencies
- Network conditions or timing that causes reordering

An adversary with network-level access could deliberately reorder packets to trigger this consistently.

## Recommendation

**Solution: Use GRPC Streaming RPCs with Ordered Delivery**

Replace unary RPCs with a bidirectional streaming RPC that maintains message ordering:

```rust
// In RemoteCrossShardClient, establish a persistent ordered stream per (shard_id, round)
// Messages sent over the same stream maintain ordering guarantees

pub struct RemoteCrossShardClient {
    // Replace individual message channels with ordered streams
    message_streams: Arc<Vec<Vec<Mutex<OrderedMessageStream>>>>,
}

impl CrossShardClient for RemoteCrossShardClient {
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let stream = self.message_streams[shard_id][round].lock().unwrap();
        // Send over streaming RPC which maintains FIFO ordering
        stream.send_ordered(msg).unwrap();
    }
}
```

**Alternative Solutions:**

1. **Sequence Numbers:** Add sequence numbers to messages and buffer/reorder on receive
2. **Explicit Barrier:** Send explicit completion barrier after all data messages, with retry logic
3. **Message Count:** Include expected message count in StopMsg for validation
4. **Local Execution Only:** Document that remote execution mode is experimental and disable in production

## Proof of Concept

```rust
// Reproduction test for message reordering vulnerability
// File: execution/executor-service/tests/cross_shard_message_reorder_test.rs

#[test]
fn test_cross_shard_message_reordering() {
    // Setup: Create two remote executor shards with network delay injection
    let shard_a = create_remote_executor_shard(0);
    let shard_b = create_remote_executor_shard(1);
    
    // Create block with cross-shard dependency:
    // - Transaction T1 in shard A writes key X
    // - Transaction T2 in shard B reads key X (depends on T1)
    let block = create_block_with_cross_shard_deps();
    
    // Inject network delay to reorder messages:
    // - Delay data messages from shard A to shard B by 100ms  
    // - Allow StopMsg to arrive immediately
    inject_network_delay(from: shard_a, to: shard_b, delay_ms: 100);
    
    // Execute block
    let result_a = shard_a.execute_block(block.clone());
    let result_b = shard_b.execute_block(block.clone());
    
    // Expected: Shard B hangs waiting for cross-shard value
    // Actual behavior depends on whether StopMsg overtakes data message
    match (result_a, result_b) {
        (Ok(_), Err(timeout)) => {
            // Shard B timed out waiting for cross-shard message
            assert_eq!(timeout.kind(), ErrorKind::TimedOut);
        },
        (Ok(result_a), Ok(result_b)) => {
            // If both succeed, verify identical Merkle roots
            assert_eq!(result_a.root_hash, result_b.root_hash);
        },
        _ => panic!("Unexpected execution result pattern"),
    }
}
```

## Notes

This vulnerability is specific to the **remote cross-shard execution mode** using `RemoteCrossShardClient`. The local execution mode (`LocalCrossShardClient`) uses crossbeam channels which provide FIFO ordering guarantees and is not affected. [8](#0-7) 

The root cause is the architectural mismatch between:
1. The execution logic's assumption of FIFO message delivery
2. GRPC unary RPCs which do not provide ordering guarantees across separate calls

The vulnerability affects the deterministic execution requirement that is fundamental to blockchain consensus, making this a critical consensus-layer vulnerability despite not directly manipulating state or funds.

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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L103-134)
```rust
    fn send_remote_update_for_success(
        &self,
        txn_idx: TxnIndex,
        txn_output: &OnceCell<TransactionOutput>,
    ) {
        let edges = self.dependent_edges.get(&txn_idx).unwrap();
        let write_set = txn_output
            .get()
            .expect("Committed output must be set")
            .write_set();

        for (state_key, write_op) in write_set.expect_write_op_iter() {
            if let Some(dependent_shard_ids) = edges.get(state_key) {
                for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                    trace!("Sending remote update for success for shard id {:?} and txn_idx: {:?}, state_key: {:?}, dependent shard id: {:?}", self.shard_id, txn_idx, state_key, dependent_shard_id);
                    let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                        state_key.clone(),
                        Some(write_op.clone()),
                    ));
                    if *round_id == GLOBAL_ROUND_ID {
                        self.cross_shard_client.send_global_msg(message);
                    } else {
                        self.cross_shard_client.send_cross_shard_msg(
                            *dependent_shard_id,
                            *round_id,
                            message,
                        );
                    }
                }
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L163-168)
```rust
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_cross_shard_msg(
                        shard_id,
                        round,
                        CrossShardMsg::StopMsg,
                    );
```

**File:** secure/net/src/grpc_network_service/mod.rs (L91-115)
```rust
#[tonic::async_trait]
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
```

**File:** secure/net/src/grpc_network_service/mod.rs (L140-160)
```rust
    pub async fn send_message(
        &mut self,
        sender_addr: SocketAddr,
        message: Message,
        mt: &MessageType,
    ) {
        let request = tonic::Request::new(NetworkMessage {
            message: message.data,
            message_type: mt.get_type(),
        });
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L29-39)
```rust
    pub fn get_value(&self) -> Option<StateValue> {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        while let RemoteValueStatus::Waiting = *status {
            status = cvar.wait(status).unwrap();
        }
        match &*status {
            RemoteValueStatus::Ready(value) => value.clone(),
            RemoteValueStatus::Waiting => unreachable!(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L326-337)
```rust
impl CrossShardClient for LocalCrossShardClient {
    fn send_global_msg(&self, msg: CrossShardMsg) {
        self.global_message_tx.send(msg).unwrap()
    }

    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        self.message_txs[shard_id][round].send(msg).unwrap()
    }

    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        self.message_rxs[current_round].recv().unwrap()
    }
```
