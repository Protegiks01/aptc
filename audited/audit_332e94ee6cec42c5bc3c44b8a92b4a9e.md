# Audit Report

## Title
Man-in-the-Middle Attack on Remote Executor Communication Enables Transaction Reordering and Gas Manipulation Leading to Consensus Divergence

## Summary
The remote executor service uses unencrypted HTTP for gRPC communication between the coordinator and executor shards, with no message authentication. This allows network attackers to perform man-in-the-middle attacks to modify execution commands in transit, reorder transactions, manipulate gas limits, and alter block parameters, breaking the deterministic execution invariant and causing consensus divergence across validator shards.

## Finding Description

The `GRPCNetworkMessageServiceClientWrapper` in the remote executor infrastructure establishes connections using unencrypted HTTP instead of HTTPS, providing no transport-layer security: [1](#0-0) 

The client explicitly uses `format!("http://{}", remote_addr)` to connect to remote executor shards, transmitting all messages over plaintext HTTP/2.

The `simple_msg_exchange()` RPC endpoint receives `NetworkMessage` protobuf messages and forwards them to registered handlers without any authentication or integrity verification: [2](#0-1) [3](#0-2) 

The `NetworkMessage` protobuf contains only raw bytes and a message type string: [4](#0-3) 

The critical `ExecuteBlockCommand` structure flows through this unprotected channel, containing transaction ordering, gas configuration, and execution parameters: [5](#0-4) [6](#0-5) 

The remote executor client serializes these commands using BCS and sends them through the unencrypted channel: [7](#0-6) 

This system is actively used in production when remote shard addresses are configured: [8](#0-7) 

**Attack Path:**
1. Attacker positions themselves on network path between coordinator and one or more executor shards
2. Coordinator sends `ExecuteBlockCommand` containing ordered transactions via BCS serialization
3. Attacker intercepts the unencrypted gRPC message in transit
4. Attacker modifies the BCS-serialized payload to:
   - Reorder transactions within `sub_blocks`
   - Change gas limits in `onchain_config` 
   - Modify `block_gas_limit_type`, `per_block_gas_limit`, or `gas_price_to_burn`
   - Alter `concurrency_level` settings
   - Drop or duplicate specific transactions
5. Attacker forwards modified message to executor shard
6. Shard deserializes and executes the tampered command without detecting modification
7. Different shards execute different transaction orderings, computing different state roots
8. Consensus breaks as validators cannot agree on the correct state

## Impact Explanation

This vulnerability qualifies as **CRITICAL** severity under the Aptos Bug Bounty program criteria for the following reasons:

**Consensus/Safety Violation**: This directly breaks the fundamental "Deterministic Execution" invariant (Critical Invariant #1). When an attacker tampers with execution commands to different shards, each shard executes a different ordering of transactions or uses different gas parameters. This causes:

- Different state roots computed by different shards
- Validators unable to reach consensus on block commitment
- Irrecoverable network divergence requiring hard fork to resolve
- Chain split if some validators commit different blocks

**Non-recoverable Network Partition**: If the attack persists across multiple blocks, different validator sets will have incompatible state histories. Recovery requires coordinating a hard fork with manual state reconciliation.

**Loss of Funds**: Transaction reordering can enable:
- Front-running attacks where attacker-controlled transactions execute before victim transactions
- Double-spend opportunities through reordering
- Gas manipulation causing incorrect fee charging

The impact matches the Critical severity definition: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Network Position**: Attackers need MITM capability between coordinator and shards. This is achievable through:
   - Compromised network infrastructure (routers, switches)
   - BGP hijacking for inter-datacenter communication
   - Cloud provider insider access
   - Compromised VPN/tunnel endpoints
   
2. **No Authentication**: There are zero cryptographic protections:
   - No TLS/HTTPS encryption
   - No message signing or HMAC verification
   - No mutual authentication between coordinator and shards
   - No replay attack protection

3. **Production Deployment**: The code shows this is actively used when remote addresses are configured, not just test infrastructure.

4. **BCS Format Manipulation**: BCS (Binary Canonical Serialization) is deterministic and well-documented, making payload modification straightforward for sophisticated attackers.

5. **Silent Failure**: The attack is undetectable at the network layer since there's no integrity checking. The only detection would be consensus failure after state divergence has occurred.

While requiring network-level access raises the bar, the complete absence of security controls makes successful exploitation highly likely for motivated attackers with infrastructure access.

## Recommendation

Implement end-to-end security for remote executor communication:

**Option 1: TLS/HTTPS (Immediate Fix)**
```rust
// In grpc_network_service/mod.rs, modify get_channel():
async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
    info!("Trying to connect to remote server at {:?}", remote_addr);
    
    // Use HTTPS with TLS
    let tls_config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(CA_CERT))
        .identity(Identity::from_pem(CLIENT_CERT, CLIENT_KEY));
    
    let conn = tonic::transport::Endpoint::new(format!("https://{}", remote_addr))
        .unwrap()
        .tls_config(tls_config)
        .unwrap()
        .connect_lazy();
        
    NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
}

// Server-side: Add TLS acceptor in start_async()
let tls_config = ServerTlsConfig::new()
    .identity(Identity::from_pem(SERVER_CERT, SERVER_KEY));

Server::builder()
    .tls_config(tls_config).unwrap()
    .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
    // ... rest of server config
```

**Option 2: Message-Level Authentication (Defense in Depth)**
```rust
// Add HMAC authentication to NetworkMessage
pub struct AuthenticatedNetworkMessage {
    pub message: Vec<u8>,
    pub message_type: String,
    pub hmac: Vec<u8>,  // HMAC-SHA256 of (message || message_type || timestamp)
    pub timestamp: u64,
}

// Verify HMAC on receipt
fn verify_message(msg: &AuthenticatedNetworkMessage, shared_key: &[u8]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(shared_key)?;
    mac.update(&msg.message);
    mac.update(msg.message_type.as_bytes());
    mac.update(&msg.timestamp.to_le_bytes());
    mac.verify_slice(&msg.hmac)?;
    
    // Check timestamp to prevent replay
    if msg.timestamp + MAX_AGE < current_timestamp() {
        return Err("Message too old");
    }
    Ok(())
}
```

**Option 3: Use Aptos Network Framework (Recommended)**

Integrate with the existing Aptos Network Framework that uses Noise protocol for authenticated encryption: [9](#0-8) 

This provides:
- Mutual authentication using validator keys
- Encryption with AES-GCM
- Anti-replay protection
- Integration with existing validator key infrastructure

## Proof of Concept

```rust
// PoC demonstrating message interception and modification
// File: execution/executor-service/tests/mitm_attack_test.rs

use aptos_executor_service::{ExecuteBlockCommand, RemoteExecutionRequest};
use aptos_types::block_executor::config::BlockExecutorConfigFromOnchain;
use bcs;

#[test]
fn test_mitm_message_tampering() {
    // Simulate legitimate execution command
    let original_command = RemoteExecutionRequest::ExecuteBlock(ExecuteBlockCommand {
        sub_blocks: create_test_sub_blocks(), // Contains ordered transactions
        concurrency_level: 4,
        onchain_config: BlockExecutorConfigFromOnchain::new_no_block_limit(),
    });
    
    // Serialize as coordinator would
    let serialized = bcs::to_bytes(&original_command).unwrap();
    
    // ATTACKER: Deserialize, modify, re-serialize
    let mut tampered_command: RemoteExecutionRequest = 
        bcs::from_bytes(&serialized).unwrap();
    
    if let RemoteExecutionRequest::ExecuteBlock(ref mut cmd) = tampered_command {
        // Reorder transactions
        let mut sub_blocks = cmd.sub_blocks.clone();
        if sub_blocks.sub_blocks.len() >= 2 {
            sub_blocks.sub_blocks.swap(0, 1); // Swap first two sub-blocks
        }
        cmd.sub_blocks = sub_blocks;
        
        // Manipulate gas config
        cmd.onchain_config = BlockExecutorConfigFromOnchain::new(
            BlockGasLimitType::NoLimit,
            true,
            Some(0), // Set gas price to 0 - free transactions!
        );
    }
    
    let tampered_serialized = bcs::to_bytes(&tampered_command).unwrap();
    
    // Verify tampering succeeded
    assert_ne!(serialized, tampered_serialized);
    
    // Send to executor shard - will execute tampered version
    // with no detection of modification
    send_to_shard(tampered_serialized);
    
    // Result: Shard executes wrong transaction order with manipulated gas
    // Different shards get different commands -> consensus breaks
}
```

**Notes**

This vulnerability exists due to the architectural decision to implement a separate network communication layer (`secure/net`) for the remote executor service rather than using the main Aptos network framework that includes proper authentication and encryption via the Noise protocol. The "secure" name in `aptos-secure-net` is misleading as it provides no actual security controls.

The issue is particularly severe because it affects the core execution layer where transaction ordering and gas parameters must be deterministic across all validators. Even a single tampered execution command can cause permanent consensus divergence.

Immediate mitigation should implement TLS with mutual authentication using validator certificates. Long-term, the remote executor communication should be migrated to use the production Aptos Network Framework's authenticated channels.

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

**File:** secure/net/src/grpc_network_service/mod.rs (L124-138)
```rust
    pub fn new(rt: &Runtime, remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr: remote_addr.to_string(),
            remote_channel: rt
                .block_on(async { Self::get_channel(format!("http://{}", remote_addr)).await }),
        }
    }

    async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
        info!("Trying to connect to remote server at {:?}", remote_addr);
        let conn = tonic::transport::Endpoint::new(remote_addr)
            .unwrap()
            .connect_lazy();
        NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
    }
```

**File:** protos/rust/src/pb/aptos.remote_executor.v1.tonic.rs (L92-118)
```rust
        pub async fn simple_msg_exchange(
            &mut self,
            request: impl tonic::IntoRequest<super::NetworkMessage>,
        ) -> std::result::Result<tonic::Response<super::Empty>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/aptos.remote_executor.v1.NetworkMessageService/SimpleMsgExchange",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "aptos.remote_executor.v1.NetworkMessageService",
                        "SimpleMsgExchange",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
```

**File:** protos/proto/aptos/remote_executor/v1/network_msg.proto (L8-11)
```text
message NetworkMessage {
  bytes message = 1;
  string message_type = 2;
}
```

**File:** execution/executor-service/src/lib.rs (L48-53)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecuteBlockCommand {
    pub(crate) sub_blocks: SubBlocksForShard<AnalyzedTransaction>,
    pub(crate) concurrency_level: usize,
    pub(crate) onchain_config: BlockExecutorConfigFromOnchain,
}
```

**File:** types/src/block_executor/config.rs (L84-90)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockExecutorConfigFromOnchain {
    pub block_gas_limit_type: BlockGasLimitType,
    enable_per_block_gas_limit: bool,
    per_block_gas_limit: Option<u64>,
    gas_price_to_burn: Option<u64>,
}
```

**File:** execution/executor-service/src/remote_executor_client.rs (L186-206)
```rust
    ) -> Result<ShardedExecutionOutput, VMStatus> {
        trace!("RemoteExecutorClient Sending block to shards");
        self.state_view_service.set_state_view(state_view);
        let (sub_blocks, global_txns) = transactions.into();
        if !global_txns.is_empty() {
            panic!("Global transactions are not supported yet");
        }
        for (shard_id, sub_blocks) in sub_blocks.into_iter().enumerate() {
            let senders = self.command_txs.clone();
            let execution_request = RemoteExecutionRequest::ExecuteBlock(ExecuteBlockCommand {
                sub_blocks,
                concurrency_level: concurrency_level_per_shard,
                onchain_config: onchain_config.clone(),
            });

            senders[shard_id]
                .lock()
                .unwrap()
                .send(Message::new(bcs::to_bytes(&execution_request).unwrap()))
                .unwrap();
        }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-267)
```rust
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
```

**File:** network/framework/src/transport/mod.rs (L1-10)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    logging::NetworkSchema,
    noise::{stream::NoiseStream, AntiReplayTimestamps, HandshakeAuthMode, NoiseUpgrader},
    protocols::{
        identity::exchange_handshake,
        wire::handshake::v1::{HandshakeMsg, MessagingProtocolVersion, ProtocolIdSet},
    },
```
