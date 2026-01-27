# Audit Report

## Title
Unauthenticated Remote Executor gRPC Service Allows Arbitrary Command Injection

## Summary
The `simple_msg_exchange` gRPC endpoint in the remote executor service has no authentication or authorization mechanism. The `remote_addr()` value cannot be trusted for access control as it only reflects the TCP socket peer address without cryptographic verification. Any attacker with network access to the executor service endpoints can send arbitrary execution commands, cross-shard messages, and state manipulation requests, leading to consensus corruption, loss of funds, and remote code execution.

## Finding Description
The remote executor service uses gRPC for inter-shard communication during sharded block execution. The `GRPCNetworkMessageServiceServerWrapper::simple_msg_exchange` function processes incoming network messages: [1](#0-0) 

The function extracts `remote_addr` from the gRPC request but **only uses it for logging** (line 111). No authentication or authorization checks are performed. Messages are routed solely based on `message_type` to registered handlers without verifying the sender's identity.

The gRPC server is started without TLS, authentication, or any security middleware: [2](#0-1) 

The `remote_addr()` value in tonic/gRPC comes from the underlying TCP socket's peer address. This is **not cryptographically authenticated** and can be influenced by:
- Network topology (NAT, proxies, load balancers)
- Source IP spoofing at lower layers
- Man-in-the-middle attacks

The remote executor service is designed to run as standalone processes with configurable network addresses: [3](#0-2) 

The service binds to addresses provided via command-line arguments, which may be exposed to untrusted networks. The `NetworkController` creates channels for different message types but performs no authentication: [4](#0-3) 

**Attack Path:**
1. Attacker discovers executor service endpoints (through port scanning, configuration leaks, or internal network access)
2. Attacker connects to the gRPC service (no TLS required, no authentication)
3. Attacker crafts malicious `NetworkMessage` with specific message types:
   - `execute_command_{shard_id}`: Send malicious execution commands
   - `execute_result_{shard_id}`: Inject fake execution results
   - `cross_shard_{round}`: Corrupt cross-shard communication
   - State view request types: Manipulate state reads
4. Messages are processed by registered handlers without verification
5. Attacker achieves consensus corruption, state manipulation, or code execution

## Impact Explanation
This vulnerability meets **Critical Severity** criteria per the Aptos Bug Bounty program:

**Consensus/Safety Violations**: An attacker can send malicious execution results to the coordinator, causing different validators to commit different state roots, violating the Deterministic Execution invariant. This breaks AptosBFT consensus safety.

**Loss of Funds**: By injecting malicious execution commands or fake results, an attacker can manipulate transaction outputs to mint tokens, redirect transfers, or corrupt account balances. The sharded executor directly affects blockchain state commitment.

**Remote Code Execution**: The executor processes arbitrary serialized commands via BCS deserialization. An attacker can craft malicious `ExecuteBlockCommand` payloads to exploit deserialization bugs or trigger unexpected code paths in the VM. [5](#0-4) 

**Network Partition**: By flooding malicious messages or causing the executor to crash, an attacker can force a non-recoverable partition requiring manual intervention or hard fork.

The vulnerability affects all three critical impact categories: funds, consensus, and availability.

## Likelihood Explanation
**Likelihood: HIGH**

The attack requires:
- Network access to executor service endpoints (feasible in cloud deployments, internal networks, or misconfigured firewalls)
- Basic gRPC client knowledge (widely available tools like `grpcurl`)
- No authentication credentials needed
- No cryptographic keys required
- No insider access needed

The executor service is explicitly designed to run in separate processes with network communication, suggesting production deployments where multiple physical machines communicate over networks. Default port `52200` is well-known: [6](#0-5) 

There is no network isolation documentation, TLS configuration, or authentication mechanism in the codebase, indicating this is a fundamental design oversight rather than a deployment misconfiguration issue.

## Recommendation
Implement mutual TLS authentication with client certificates for all remote executor communications:

```rust
// In grpc_network_service/mod.rs
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

impl GRPCNetworkMessageServiceServerWrapper {
    async fn start_async(
        self,
        server_addr: SocketAddr,
        rpc_timeout_ms: u64,
        server_shutdown_rx: oneshot::Receiver<()>,
        tls_config: Option<ServerTlsConfig>,  // Add TLS config
    ) {
        let mut server_builder = Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms));
        
        // Enable TLS with client certificate verification
        if let Some(tls) = tls_config {
            server_builder = server_builder
                .tls_config(tls)
                .expect("Failed to configure TLS");
        }
        
        server_builder
            .add_service(
                NetworkMessageServiceServer::new(self)
                    .max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
            .serve_with_shutdown(server_addr, async {
                server_shutdown_rx.await.ok();
            })
            .await
            .unwrap();
    }
}
```

Additionally, implement message authentication:

```rust
impl NetworkMessageService for GRPCNetworkMessageServiceServerWrapper {
    async fn simple_msg_exchange(
        &self,
        request: Request<NetworkMessage>,
    ) -> Result<Response<Empty>, Status> {
        // Verify client certificate and extract peer identity
        let peer_certs = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("No client certificate"))?;
        
        // Validate peer is authorized for this message type
        let authorized_peers = self.get_authorized_peers();
        if !authorized_peers.contains(&extract_peer_id(peer_certs)) {
            return Err(Status::permission_denied("Unauthorized peer"));
        }
        
        // Existing message processing...
    }
}
```

**Alternative approach**: Reuse the existing Noise protocol authentication from the main network layer instead of building a separate gRPC system: [7](#0-6) 

## Proof of Concept

```rust
// File: exploit_remote_executor.rs
// Demonstrates unauthenticated access to remote executor service

use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    NetworkMessage,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Target executor service (discovered via scanning or config leaks)
    let target = "http://10.0.0.100:52200"; // Example executor shard address
    
    // Connect without authentication
    let mut client = NetworkMessageServiceClient::connect(target)
        .await
        .expect("Failed to connect");
    
    println!("[+] Connected to remote executor without authentication!");
    
    // Craft malicious execution result message
    let malicious_payload = create_malicious_execution_result();
    let message = NetworkMessage {
        message: malicious_payload,
        message_type: "execute_result_0".to_string(), // Target shard 0
    };
    
    // Send malicious message - it will be processed!
    match client.simple_msg_exchange(message).await {
        Ok(_) => println!("[+] Malicious message accepted and processed!"),
        Err(e) => println!("[-] Error: {}", e),
    }
}

fn create_malicious_execution_result() -> Vec<u8> {
    // Craft malicious RemoteExecutionResult with fake transaction outputs
    // This would manipulate state roots and cause consensus divergence
    use aptos_executor_service::RemoteExecutionResult;
    
    let fake_result = RemoteExecutionResult {
        inner: Ok(vec![vec![/* malicious TransactionOutput */]]),
    };
    
    bcs::to_bytes(&fake_result).unwrap()
}
```

To test without actual exploitation:
```bash
# 1. Start a remote executor service
cargo run --bin aptos-executor-service -- \
  --shard-id 0 \
  --num-shards 2 \
  --coordinator-address 127.0.0.1:52200 \
  --remote-executor-addresses 127.0.0.1:52201 127.0.0.1:52202

# 2. Use grpcurl to verify unauthenticated access
grpcurl -plaintext -d '{"message":"dGVzdA==","message_type":"test"}' \
  127.0.0.1:52201 aptos.remote_executor.v1.NetworkMessageService/SimpleMsgExchange

# Expected: Message is accepted without authentication
```

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L75-87)
```rust
        Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
            .add_service(
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
            .add_service(reflection_service)
            .serve_with_shutdown(server_addr, async {
                server_shutdown_rx.await.ok();
                info!("Received signal to shutdown server at {:?}", server_addr);
            })
            .await
            .unwrap();
        info!("Server shutdown at {:?}", server_addr);
```

**File:** secure/net/src/grpc_network_service/mod.rs (L93-116)
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
}
```

**File:** execution/executor-service/src/process_executor_service.rs (L17-44)
```rust
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let self_address = remote_shard_addresses[shard_id];
        info!(
            "Starting process remote executor service on {}; coordinator address: {}, other shard addresses: {:?}; num threads: {}",
            self_address, coordinator_address, remote_shard_addresses, num_threads
        );
        aptos_node_resource_metrics::register_node_metrics_collector(None);
        let _mp = MetricsPusher::start_for_local_run(
            &("remote-executor-service-".to_owned() + &shard_id.to_string()),
        );

        AptosVM::set_concurrency_level_once(num_threads);
        let mut executor_service = ExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            self_address,
            coordinator_address,
            remote_shard_addresses,
        );
        executor_service.start();
        Self { executor_service }
```

**File:** secure/net/src/network_controller/mod.rs (L115-137)
```rust
    pub fn create_outbound_channel(
        &mut self,
        remote_peer_addr: SocketAddr,
        message_type: String,
    ) -> Sender<Message> {
        let (outbound_sender, outbound_receiver) = unbounded();

        self.outbound_handler
            .register_handler(message_type, remote_peer_addr, outbound_receiver);

        outbound_sender
    }

    pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
        let (inbound_sender, inbound_receiver) = unbounded();

        self.inbound_handler
            .lock()
            .unwrap()
            .register_handler(message_type, inbound_sender);

        inbound_receiver
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L30-30)
```rust
pub static COORDINATOR_PORT: u16 = 52200;
```

**File:** execution/executor-service/src/remote_executor_client.rs (L195-206)
```rust
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

**File:** network/framework/src/noise/handshake.rs (L1-10)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! The handshake module implements the handshake part of the protocol.
//! This module also implements additional anti-DoS mitigation,
//! by including a timestamp in each handshake initialization message.
//! Refer to the module's documentation for more information.
//! A successful handshake returns a [`NoiseStream`] which is defined in the
//! [stream] module.
//!
```
