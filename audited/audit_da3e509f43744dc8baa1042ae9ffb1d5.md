# Audit Report

## Title
Missing TLS Certificate Validation in Remote Executor Service Enables Man-in-the-Middle Attacks on Cross-Shard Communication

## Summary
The Remote Executor Service's `NetworkController` uses unencrypted HTTP connections without TLS for cross-shard communication, enabling attackers to intercept and manipulate transaction execution results between shards. This violates state consistency guarantees and could lead to consensus failures in sharded execution deployments.

## Finding Description

The `RemoteCrossShardClient` relies on `NetworkController` to send cross-shard messages containing transaction execution results (`StateKey` and `WriteOp` data). However, the underlying gRPC communication uses plain HTTP without any TLS encryption or certificate validation. [1](#0-0) 

The vulnerability originates in `GRPCNetworkMessageServiceClientWrapper::new()`, which creates connections using the HTTP scheme instead of HTTPS: [2](#0-1) 

The server-side implementation similarly lacks TLS configuration: [3](#0-2) 

**Attack Scenario:**

1. Executor services are deployed across multiple machines/networks for sharded block execution
2. An attacker positions themselves on the network path between two executor shards (e.g., through ARP spoofing, DNS hijacking, or compromised network infrastructure)
3. The attacker intercepts cross-shard messages containing `RemoteTxnWrite` data: [4](#0-3) 

4. The attacker modifies `WriteOp` values or `StateKey` mappings before forwarding them
5. Different shards execute transactions with manipulated dependency data, producing inconsistent state roots
6. This breaks the **Deterministic Execution** invariant - validators processing the same block would produce different state roots, causing consensus failure

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Significant Protocol Violations**: Enables manipulation of cross-shard transaction execution results, violating state consistency guarantees
2. **State Inconsistencies**: Different shards could commit different state values for the same transaction, breaking the deterministic execution invariant
3. **Consensus Impact**: If validators use different executor service deployments with manipulated cross-shard messages, they would compute different state roots, potentially causing consensus failures requiring manual intervention

While this doesn't directly result in fund theft or total network failure (which would be Critical), it represents a significant protocol violation that could require intervention to resolve state inconsistencies.

## Likelihood Explanation

**Likelihood: Medium to High** (depending on deployment model)

The likelihood depends on whether Aptos actually deploys the remote executor service in production:

- **If deployed across network boundaries**: High likelihood - standard MITM attacks become trivial
- **If only used locally**: Low likelihood - attacker would need host compromise

Required attacker capabilities:
- Network access between executor service nodes (not validator nodes)
- Standard MITM tools (mitmproxy, Burp Suite, etc.)
- No need for cryptographic breaks or insider access

The attack is highly feasible once network access is obtained, as there is zero authentication or integrity protection.

## Recommendation

Implement TLS with mutual certificate authentication for all `NetworkController` connections:

**1. Add TLS configuration to NetworkController:**
```rust
pub struct NetworkController {
    // ... existing fields ...
    tls_config: Option<TlsConfig>,
}

pub struct TlsConfig {
    cert_path: PathBuf,
    key_path: PathBuf,
    ca_cert_path: PathBuf,
}
```

**2. Modify GRPCNetworkMessageServiceClientWrapper to use HTTPS with certificate validation:**
```rust
async fn get_channel(
    remote_addr: String,
    tls_config: &TlsConfig,
) -> NetworkMessageServiceClient<Channel> {
    let ca_cert = tokio::fs::read(&tls_config.ca_cert_path).await.unwrap();
    let ca_cert = Certificate::from_pem(ca_cert);
    
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .domain_name("executor-service"); // Use proper domain validation
    
    let conn = tonic::transport::Endpoint::new(format!("https://{}", remote_addr))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect_lazy();
    
    NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
}
```

**3. Modify GRPCNetworkMessageServiceServerWrapper to require TLS:**
```rust
async fn start_async(
    self,
    server_addr: SocketAddr,
    rpc_timeout_ms: u64,
    server_shutdown_rx: oneshot::Receiver<()>,
    tls_config: &TlsConfig,
) {
    let cert = tokio::fs::read(&tls_config.cert_path).await.unwrap();
    let key = tokio::fs::read(&tls_config.key_path).await.unwrap();
    let identity = Identity::from_pem(cert, key);
    
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))
        .unwrap()
        .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
        .add_service(NetworkMessageServiceServer::new(self))
        .serve_with_shutdown(server_addr, async {
            server_shutdown_rx.await.ok();
        })
        .await
        .unwrap();
}
```

## Proof of Concept

**Setup:**
1. Deploy two executor services on separate machines (Shard A and Shard B)
2. Position attacker machine between them with network routing capabilities

**MITM Attack Script (using mitmproxy):**
```python
# mitm_executor.py
from mitmproxy import http
import json

def request(flow: http.HTTPFlow) -> None:
    # Intercept cross_shard messages
    if "cross_shard" in flow.request.path:
        # Decode BCS-serialized CrossShardMsg
        payload = flow.request.content
        
        # Manipulate the WriteOp data
        # In practice, decode BCS, modify WriteOp values, re-encode
        malicious_payload = manipulate_write_op(payload)
        flow.request.content = malicious_payload
        
        print(f"[!] Manipulated cross-shard message from {flow.client_conn.address}")

def manipulate_write_op(data: bytes) -> bytes:
    # This would decode BCS, flip bits in WriteOp, re-encode
    # Omitted for brevity, but straightforward with aptos-types crate
    return data
```

**Run the attack:**
```bash
# 1. Set up routing to intercept traffic between executor services
sudo iptables -t nat -A PREROUTING -p tcp --dport 50051 -j REDIRECT --to-port 8080

# 2. Run mitmproxy in transparent mode
mitmproxy --mode transparent --listen-port 8080 -s mitm_executor.py

# 3. Execute a sharded block - observe different state roots on different shards
# due to manipulated cross-shard messages
```

**Expected Result:**
- Shard A receives manipulated `WriteOp` values from Shard B
- Transactions on Shard A execute with incorrect dependency data
- State root computed by Shard A differs from correct execution
- If this affects validator execution, consensus fails due to state root mismatch

## Notes

This vulnerability only affects deployments using the **Remote Executor Service** for distributed sharded execution. The main Aptos validator network uses the Noise protocol with proper authentication and encryption: [5](#0-4) 

However, if the Remote Executor Service is intended for production use in sharded execution scenarios, the lack of TLS represents a critical security gap that must be addressed before deployment.

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L22-47)
```rust
    pub fn new(controller: &mut NetworkController, shard_addresses: Vec<SocketAddr>) -> Self {
        let mut message_txs = vec![];
        let mut message_rxs = vec![];
        // Create outbound channels for each shard per round.
        for remote_address in shard_addresses.iter() {
            let mut txs = vec![];
            for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
                let message_type = format!("cross_shard_{}", round);
                let tx = controller.create_outbound_channel(*remote_address, message_type);
                txs.push(Mutex::new(tx));
            }
            message_txs.push(txs);
        }

        // Create inbound channels for each round
        for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
            let message_type = format!("cross_shard_{}", round);
            let rx = controller.create_inbound_channel(message_type);
            message_rxs.push(Mutex::new(rx));
        }

        Self {
            message_txs: Arc::new(message_txs),
            message_rxs: Arc::new(message_rxs),
        }
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L1-21)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::network_controller::{metrics::NETWORK_HANDLER_TIMER, Message, MessageType};
use aptos_logger::{error, info};
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient,
    network_message_service_server::{NetworkMessageService, NetworkMessageServiceServer},
    Empty, NetworkMessage, FILE_DESCRIPTOR_SET,
};
use crossbeam_channel::Sender;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{runtime::Runtime, sync::oneshot};
use tonic::{
    transport::{Channel, Server},
    Request, Response, Status,
};
```

**File:** secure/net/src/grpc_network_service/mod.rs (L57-88)
```rust
    async fn start_async(
        self,
        server_addr: SocketAddr,
        rpc_timeout_ms: u64,
        server_shutdown_rx: oneshot::Receiver<()>,
    ) {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()
            .unwrap();

        info!("Starting Server async at {:?}", server_addr);
        // NOTE: (1) serve_with_shutdown() starts the server, if successful the task does not return
        //           till the server is shutdown. Hence this should be called as a separate
        //           non-blocking task. Signal handler 'server_shutdown_rx' is needed to shutdown
        //           the server
        //       (2) There is no easy way to know if/when the server has started successfully. Hence
        //           we may need to implement a healthcheck service to check if the server is up
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
