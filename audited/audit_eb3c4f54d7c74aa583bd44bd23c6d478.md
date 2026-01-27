# Audit Report

## Title
Cross-Shard Message Forgery Enables Consensus Divergence via Unauthenticated Network Communication

## Summary
The remote cross-shard messaging system transmits state updates over plain HTTP without cryptographic signatures, allowing a man-in-the-middle attacker to forge or modify cross-shard messages. This causes different shards to compute inconsistent state roots, breaking consensus safety and enabling permanent chain splits.

## Finding Description

The sharded block executor system uses cross-shard messages to communicate state updates between executor shards during parallel block execution. These messages contain critical `StateKey` and `WriteOp` data that directly influence the final state root computation.

**Vulnerability Chain:**

1. **Unauthenticated Transport Layer**: Cross-shard messages are transmitted via plain HTTP GRPC without TLS encryption or authentication. [1](#0-0) 

2. **Missing Signature Verification**: The `receive_cross_shard_msg()` function directly deserializes incoming messages without any cryptographic verification. [2](#0-1) 

3. **Direct State Impact**: Received messages are immediately applied to the cross-shard state view without validation. [3](#0-2) 

4. **Consensus Divergence**: Modified state values propagate through block execution, causing different validators to produce different state roots for the same block.

**Attack Scenario:**

An attacker with network-level access between executor shards can:
- Intercept `RemoteTxnWriteMsg` messages containing state updates
- Modify the `StateKey` target or `WriteOp` value 
- Forward the corrupted message to the receiving shard

The receiving shard will accept the forged message and apply the incorrect state update. Since different shards receive different values for cross-shard dependencies, they will compute different final state roots when merging execution results.

**Invariant Violations:**

- **Invariant #1 (Deterministic Execution)**: Different validators no longer produce identical state roots for identical blocks
- **Invariant #2 (Consensus Safety)**: Validators can commit conflicting states, causing permanent chain splits
- **Invariant #4 (State Consistency)**: State transitions are no longer verifiable or atomic across shards

## Impact Explanation

**Severity: CRITICAL (up to $1,000,000)**

This vulnerability meets the highest severity criteria:

1. **Consensus/Safety Violation**: An attacker can cause honest validators to permanently diverge on the canonical chain state. This is a fundamental consensus safety break.

2. **Non-Recoverable Network Partition**: Once validators commit different state roots, the network cannot recover without manual intervention (hardfork). Different validators will reject each other's blocks as invalid.

3. **Scope**: Affects all deployments using remote sharded execution, which is designed for high-throughput distributed block processing.

Unlike traditional Byzantine fault scenarios requiring validator key compromise, this attack only requires passive network access between executor nodes—a significantly lower barrier for attackers in cloud or datacenter environments.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attack Requirements:**
- Network position between executor shards (MITM capability)
- Knowledge of BCS serialization format for `CrossShardMsg`
- Ability to intercept and modify GRPC traffic

**Factors Increasing Likelihood:**
- Plain HTTP is trivially interceptable on shared networks
- No authentication makes message forgery straightforward
- Distributed executor shards often communicate across network boundaries
- Cloud environments provide multiple MITM opportunities (ARP spoofing, BGP hijacking, compromised switches)

**Factors Decreasing Likelihood:**
- Requires sharded execution mode to be actively used
- Some deployments may use isolated networks with physical security
- Attacker needs to identify cross-shard message patterns

The vulnerability is **highly exploitable** given network access. The lack of any cryptographic protection makes exploitation deterministic once the attacker achieves a MITM position.

## Recommendation

Implement end-to-end cryptographic authentication for all cross-shard messages:

**1. Add Message Signatures:**
```rust
// In messages.rs
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignedCrossShardMsg {
    msg: CrossShardMsg,
    signer_shard_id: ShardId,
    signature: Ed25519Signature,
}
```

**2. Sign Messages on Send:** [4](#0-3) 

Modify to sign before serialization:
```rust
fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
    let signed_msg = self.sign_message(msg, round);
    let input_message = bcs::to_bytes(&signed_msg).unwrap();
    // ... send
}
```

**3. Verify Signatures on Receive:** [2](#0-1) 

Modify to verify before deserializing:
```rust
fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
    let rx = self.message_rxs[current_round].lock().unwrap();
    let message = rx.recv().unwrap();
    let signed_msg: SignedCrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
    
    // Verify signature against sender's public key
    self.verify_signature(&signed_msg, current_round)
        .expect("Invalid cross-shard message signature");
    
    signed_msg.msg
}
```

**4. Key Management:**
- Each shard should have an Ed25519 keypair generated at initialization
- Public keys should be distributed to all shards during setup
- Use deterministic key derivation from executor service identity

**5. Additional Hardening:**
- Enable mTLS for GRPC channels to provide transport-layer security
- Implement replay protection using message sequence numbers
- Add message freshness checks using timestamps

## Proof of Concept

**Network Interception PoC:**

```python
#!/usr/bin/env python3
# MITM proxy to demonstrate cross-shard message forgery
# Requires: mitmproxy, bcs python library

from mitmproxy import http
import bcs

class CrossShardMessageForger:
    def request(self, flow: http.HTTPFlow):
        # Intercept GRPC messages to cross_shard_* endpoints
        if "cross_shard_" in flow.request.path:
            # Parse BCS-encoded CrossShardMsg
            original_data = flow.request.content
            
            try:
                # Deserialize the message
                msg = bcs.deserialize(original_data, CrossShardMsg)
                
                # Modify the write operation value
                if hasattr(msg, 'RemoteTxnWriteMsg'):
                    print(f"[!] Intercepted cross-shard write")
                    print(f"[!] Original StateKey: {msg.state_key}")
                    
                    # Forge a different value
                    msg.write_op = forge_different_value()
                    
                    # Re-serialize and forward
                    flow.request.content = bcs.serialize(msg)
                    print(f"[!] Forwarded forged message")
            except:
                pass

def forge_different_value():
    # Return a malicious WriteOp that corrupts state
    # This would cause the receiving shard to compute wrong state root
    return create_malicious_write_op()

addons = [CrossShardMessageForger()]
```

**Expected Outcome:**
1. Run mitmproxy between two executor shards
2. Execute a block with cross-shard dependencies
3. The forged messages cause shard A to apply value X while shard B applies value Y
4. Final state roots diverge: `state_root_A ≠ state_root_B`
5. Validators reject each other's blocks, causing consensus failure

**Verification:**
Check executor logs for state root mismatches across validators processing the same block height.

## Notes

This vulnerability is **specific to the remote sharded execution mode**, which is designed for distributed block processing across multiple machines. The local execution mode using in-process channels is not affected. [5](#0-4) 

The plain HTTP transport configuration confirms lack of encryption: [6](#0-5) 

The `NetworkMessage` protobuf definition contains only raw bytes without any authentication fields: [7](#0-6) 

This represents a fundamental architectural oversight in the distributed execution design, where critical consensus-affecting data is transmitted without cryptographic protection.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L132-138)
```rust
    async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
        info!("Trying to connect to remote server at {:?}", remote_addr);
        let conn = tonic::transport::Endpoint::new(remote_addr)
            .unwrap()
            .connect_lazy();
        NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L32-38)
```rust
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::sharded_block_executor::{
    coordinator_client::CoordinatorClient,
    counters::WAIT_FOR_SHARDED_OUTPUT_SECONDS,
    cross_shard_client::CrossShardClient,
    executor_client::{ExecutorClient, ShardedExecutionOutput},
    global_executor::GlobalExecutor,
    messages::CrossShardMsg,
    sharded_aggregator_service,
    sharded_executor_service::ShardedExecutorService,
    ExecutorShardCommand, ShardedBlockExecutor,
};
use aptos_logger::trace;
use aptos_types::{
    block_executor::{
        config::BlockExecutorConfigFromOnchain,
        partitioner::{
            PartitionedTransactions, RoundId, ShardId, GLOBAL_ROUND_ID,
            MAX_ALLOWED_PARTITIONING_ROUNDS,
        },
    },
    state_store::StateView,
    transaction::TransactionOutput,
};
use crossbeam_channel::{unbounded, Receiver, Sender};
use move_core_types::vm_status::VMStatus;
use std::{sync::Arc, thread};

/// Executor service that runs on local machine and waits for commands from the coordinator and executes
/// them in parallel.
pub struct LocalExecutorService<S: StateView + Sync + Send + 'static> {
    join_handle: Option<thread::JoinHandle<()>>,
    phantom: std::marker::PhantomData<S>,
}

impl<S: StateView + Sync + Send + 'static> LocalExecutorService<S> {
    fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        command_rx: Receiver<ExecutorShardCommand<S>>,
        result_tx: Sender<Result<Vec<Vec<TransactionOutput>>, VMStatus>>,
        cross_shard_client: LocalCrossShardClient,
    ) -> Self {
        let coordinator_client = Arc::new(LocalCoordinatorClient::new(command_rx, result_tx));
        let executor_service = Arc::new(ShardedExecutorService::new(
            shard_id,
            num_shards,
```

**File:** protos/rust/src/pb/aptos.remote_executor.v1.rs (L8-13)
```rust
pub struct NetworkMessage {
    #[prost(bytes="vec", tag="1")]
    pub message: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="2")]
    pub message_type: ::prost::alloc::string::String,
}
```
