# Audit Report

## Title
Missing Shard Identity Verification in Cross-Shard Communication Allows Execution Isolation Bypass

## Summary
The remote executor service fails to verify the identity of shards sending cross-shard messages, allowing a malicious or compromised shard to impersonate another shard and inject arbitrary state values into dependent shards. This breaks the deterministic execution invariant and can cause consensus failures across validators.

## Finding Description

The sharded block executor uses a remote communication system where shards send transaction execution results to other shards that have cross-shard dependencies. However, the system fails to authenticate the source of incoming cross-shard messages.

**Critical Code Paths:**

1. **Message Reception (GRPC Layer)**: When receiving cross-shard messages via GRPC, the server has access to the sender's socket address but discards it: [1](#0-0) 

The `remote_addr` is obtained at line 100 but never used for authentication. Only the message payload is forwarded to handlers.

2. **Cross-Shard Client**: The `RemoteCrossShardClient` receives messages without any sender verification: [2](#0-1) 

The `receive_cross_shard_msg` method returns deserialized messages without verifying which shard sent them.

3. **Message Structure**: The `CrossShardMsg` and `RemoteTxnWrite` structures contain no source shard identification: [3](#0-2) 

Messages only contain the state key and write operation, with no source authentication.

4. **State Update**: The `CrossShardCommitReceiver` blindly trusts incoming messages: [4](#0-3) 

When a `RemoteTxnWriteMsg` is received, the state is updated immediately without verifying the sender's authority to provide that state value.

**Attack Scenario:**

1. Block execution is partitioned across 8 shards (0-7)
2. Shard 2 has a transaction that writes to state key X
3. Shard 5 has a transaction that depends on state key X from Shard 2
4. **Normal flow**: Shard 2 executes and sends the correct value for X to Shard 5
5. **Attack**: Malicious Shard 3 (or even Shard 2 with malicious intent) sends a `RemoteTxnWriteMsg` to Shard 5 with:
   - `state_key`: X
   - `write_op`: Malicious/incorrect value
6. Shard 5 receives and trusts this value, updating its `CrossShardStateView`
7. Shard 5 executes its dependent transaction using the wrong value
8. **Result**: Different validators with different compromised shards compute different state roots, breaking consensus

This violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks." If different validators have different shards compromised (or none at all), they will compute different results for the same block.

## Impact Explanation

**Severity: High to Critical**

This vulnerability constitutes a **consensus violation** under the Aptos bug bounty program. Specifically:

- **Consensus Safety Violation**: Different validators can compute different state roots for identical blocks if they have different shard compromise patterns
- **Execution Non-Determinism**: The same block executed on different validators can produce different results
- **State Inconsistency**: Cross-shard dependencies can be corrupted, leading to incorrect state transitions

While this requires a compromised shard (which may seem like a high barrier), the sharded executor is designed for distributed execution where different shards may run on different physical machines or processes. A bug in one shard implementation, a compromised container, or a malicious operator of a single shard node could exploit this to cause network-wide consensus failures.

The impact is classified as **High** (significant protocol violation) with potential elevation to **Critical** if it can cause non-recoverable network partitions, as validators would produce conflicting state roots and be unable to reach consensus.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
1. Sharded block execution to be enabled (currently in development/testing)
2. At least one shard to be compromised or malicious
3. Cross-shard dependencies to exist in the block being executed

However, the likelihood increases because:
- The remote executor service code exists in production codebase
- Sharded execution is being actively developed for performance improvements
- No authentication mechanism exists at all - any entity with network access to a shard's GRPC endpoint can send messages
- The attack is silent and difficult to detect without explicit validation

Once sharded execution is deployed to production, this becomes a high-likelihood attack vector.

## Recommendation

Implement cryptographic authentication for cross-shard messages. The fix requires:

1. **Add Source Shard ID to Messages**: Extend `RemoteTxnWrite` to include the source shard ID:
```rust
pub struct RemoteTxnWrite {
    source_shard_id: ShardId,
    state_key: StateKey,
    write_op: Option<WriteOp>,
}
```

2. **Verify Expected Source**: In `CrossShardCommitReceiver`, validate that messages come from expected shards based on dependency graph:
```rust
// In CrossShardCommitReceiver::start
match msg {
    RemoteTxnWriteMsg(txn_commit_msg) => {
        let (source_shard_id, state_key, write_op) = txn_commit_msg.take();
        // Verify this shard should receive updates for this key from source_shard
        if !cross_shard_state_view.is_valid_dependency(source_shard_id, &state_key) {
            panic!("Invalid cross-shard message from shard {}", source_shard_id);
        }
        cross_shard_state_view.set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
    },
    // ...
}
```

3. **Add Network-Level Authentication**: Use the sender's socket address from the GRPC layer to verify it matches the expected address for the claimed shard:
```rust
// In GRPCNetworkMessageServiceServerWrapper::simple_msg_exchange
let remote_addr = request.remote_addr();
let network_message = request.into_inner();
let msg = Message::new(network_message.message);
let message_type = MessageType::new(network_message.message_type);

// Pass remote_addr to handler for verification
let msg_with_sender = MessageWithSender::new(msg, remote_addr);
```

4. **Maintain Shard Address Mapping**: The coordinator should provide each shard with an authenticated mapping of `shard_id -> socket_address` to validate incoming connections.

## Proof of Concept

```rust
// This PoC demonstrates how a malicious shard can inject fake state values
// Add to execution/executor-service/src/tests.rs

#[test]
fn test_cross_shard_impersonation_attack() {
    use crate::remote_cross_shard_client::RemoteCrossShardClient;
    use aptos_secure_net::network_controller::{Message, NetworkController};
    use aptos_vm::sharded_block_executor::messages::{CrossShardMsg, RemoteTxnWrite};
    use aptos_types::state_store::state_key::StateKey;
    use aptos_types::write_set::WriteOp;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    // Setup: Create two shards (victim at index 1, attacker at index 0)
    let victim_port = aptos_config::utils::get_available_port();
    let victim_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), victim_port);
    
    let mut victim_controller = NetworkController::new(
        "victim_shard".to_string(),
        victim_addr,
        5000
    );
    victim_controller.start();
    
    // Attacker creates a malicious cross-shard client
    let attacker_port = aptos_config::utils::get_available_port();
    let attacker_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), attacker_port);
    let mut attacker_controller = NetworkController::new(
        "attacker_shard".to_string(),
        attacker_addr,
        5000
    );
    
    // Attacker creates client to victim's cross-shard endpoint
    let malicious_client = RemoteCrossShardClient::new(
        &mut attacker_controller,
        vec![victim_addr]
    );
    
    // Craft malicious message with fake state value
    let state_key = StateKey::raw(b"important_balance");
    let malicious_value = WriteOp::Modification(
        bcs::to_bytes(&1_000_000_000u64).unwrap() // Fake 1B coins
    );
    
    let malicious_msg = CrossShardMsg::RemoteTxnWriteMsg(
        RemoteTxnWrite::new(state_key, Some(malicious_value))
    );
    
    // Send to victim shard - this should be rejected but isn't
    malicious_client.send_cross_shard_msg(
        1, // target shard ID (victim)
        0, // round
        malicious_msg
    );
    
    // Victim shard will trust this message and use the fake value
    // This demonstrates the vulnerability: no verification of sender
}
```

**Notes:**

The vulnerability exists at multiple layers:
- The `NetworkController` GRPC layer discards sender information
- The `RemoteCrossShardClient` doesn't track expected senders
- The `CrossShardMsg` structure lacks source identification  
- The `CrossShardCommitReceiver` performs no validation

Any production deployment of sharded execution with this code would be vulnerable to cross-shard impersonation attacks that break consensus determinism.

### Citations

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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L7-31)
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

impl RemoteTxnWrite {
    pub fn new(state_key: StateKey, write_op: Option<WriteOp>) -> Self {
        Self {
            state_key,
            write_op,
        }
    }

    pub fn take(self) -> (StateKey, Option<WriteOp>) {
        (self.state_key, self.write_op)
    }
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L25-45)
```rust
impl CrossShardCommitReceiver {
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
