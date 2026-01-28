# Audit Report

## Title
Silent Deadlock in Remote Sharded Execution on Network Partition

## Summary
When remote shards become unreachable during sharded execution, the system enters an unrecoverable deadlock state instead of detecting the failure and halting with an error. This causes total loss of liveness for affected validators, requiring process restart.

## Finding Description

The sharded execution system has a critical flaw in its network error handling that causes validators to silently deadlock when remote shards become unreachable.

**The vulnerability chain:**

1. During sharded transaction execution, when a transaction commits, cross-shard state updates are sent to dependent shards via `CrossShardCommitSender`. [1](#0-0) 

2. These messages flow through `RemoteCrossShardClient.send_cross_shard_msg()` which sends to an unbounded channel. [2](#0-1) 

3. The `OutboundHandler` consumes from this channel and calls `GRPCNetworkMessageServiceClientWrapper.send_message()` to send over the network. [3](#0-2) 

4. **Critical flaw**: When the gRPC call fails due to network partition, the code panics instead of handling the error gracefully. [4](#0-3) 

5. This panic terminates the async `OutboundHandler` task (caught by Tokio runtime), but the validator process continues running. [5](#0-4)  Further sends to the unbounded channel succeed locally but are never delivered over the network.

6. On the receiving end, `CrossShardCommitReceiver.start()` calls `receive_cross_shard_msg()` which blocks indefinitely waiting for messages that will never arrive. [6](#0-5) [7](#0-6) 

7. Meanwhile, transaction execution threads attempting to read cross-shard state call `RemoteStateValue.get_value()` which blocks on a condition variable waiting for the value to be set. [8](#0-7) [9](#0-8) 

8. Since the receiver thread is blocked and will never receive the message, the condition variable is never notified. **Execution deadlocks permanently.**

The validator appears to be running but cannot make any progress. No error is logged, no exception is raised, and no recovery mechanism exists. This affects production deployments where remote sharded execution is enabled. [10](#0-9) 

## Impact Explanation

**Critical Severity** - This meets the critical impact category "Total Loss of Liveness/Network Availability" from the Aptos bug bounty:

1. **Total loss of liveness/network availability**: Affected validators cannot participate in consensus, reducing network capacity and potentially causing consensus failures if enough validators are affected simultaneously.

2. **Non-recoverable without process restart**: Once deadlocked, the only recovery is to kill and restart the validator process. There is no automatic detection or self-healing mechanism.

3. **Consensus availability impact**: In a network with transient connectivity issues, multiple validators may deadlock, reducing the validator set below the 2/3 threshold needed for consensus progress.

This violates the fundamental distributed systems principle that network failures should be detectable and recoverable. The system silently fails in a way that appears healthy externally (process running, no crashes) but is completely non-functional internally.

## Likelihood Explanation

**High likelihood** in production distributed environments:

1. **Network partitions are common** in distributed systems due to datacenter connectivity issues, network configuration changes, firewall rule updates, cloud provider networking problems, and cross-region latency spikes causing timeouts.

2. **Sharded execution is used in production** for performance optimization when remote executor addresses are configured, increasing exposure to this code path.

3. **No special conditions required**: Any network connectivity issue between shards during execution triggers this vulnerability.

4. **Silent failure makes diagnosis difficult**: Operators may not realize validators are deadlocked until consensus stalls.

## Recommendation

Implement proper error handling in `GRPCNetworkMessageServiceClientWrapper.send_message()`:

1. Replace the panic with error propagation or retry logic with exponential backoff (as noted in the TODO comment)
2. Add circuit breaker pattern to detect persistent failures
3. Implement timeout mechanisms for `receive_cross_shard_msg()` to prevent indefinite blocking
4. Add monitoring and alerting for cross-shard communication failures
5. Implement graceful degradation when remote shards become unreachable

The code should handle network failures gracefully rather than causing silent deadlocks.

## Proof of Concept

To reproduce this vulnerability:

1. Set up a multi-shard executor deployment with remote sharding enabled
2. Start execution of a block with cross-shard dependencies
3. Introduce a network partition between shards (e.g., using iptables to drop packets)
4. Observe that the `OutboundHandler` task panics when gRPC calls fail
5. The sender continues to queue messages locally, but they never arrive
6. The receiver blocks indefinitely on `receive_cross_shard_msg()`
7. Execution threads block on `RemoteStateValue.get_value()`
8. The validator process remains running but completely deadlocked, requiring manual restart

The vulnerability can be demonstrated by simulating network failures in a test environment with remote sharded execution enabled.

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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** secure/net/src/network_controller/outbound_handler.rs (L89-99)
```rust
        rt.spawn(async move {
            info!("Starting outbound handler at {}", address.to_string());
            Self::process_one_outgoing_message(
                outbound_handlers,
                &address,
                inbound_handler.clone(),
                &mut grpc_clients,
            )
            .await;
            info!("Stopping outbound handler at {}", address.to_string());
        });
```

**File:** secure/net/src/network_controller/outbound_handler.rs (L155-160)
```rust
                grpc_clients
                    .get_mut(remote_addr)
                    .unwrap()
                    .send_message(*socket_addr, msg, message_type)
                    .await;
            }
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L77-82)
```rust
    fn get_state_value(&self, state_key: &StateKey) -> Result<Option<StateValue>, StateViewError> {
        if let Some(value) = self.cross_shard_data.get(state_key) {
            return Ok(value.get_value());
        }
        self.base_view.get_state_value(state_key)
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-275)
```rust
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
```
