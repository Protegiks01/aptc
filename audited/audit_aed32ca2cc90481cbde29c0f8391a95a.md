# Audit Report

## Title
Indefinite Blocking in gRPC Client Due to Missing Timeout Configuration Leading to Resource Exhaustion

## Summary
The `simple_msg_exchange` function in the gRPC client implementation calls `ready().await` without any timeout configuration, allowing malicious remote peers to cause indefinite blocking and resource exhaustion by accepting connections but never responding. This violates the **Resource Limits** invariant that all operations must respect timeouts.

## Finding Description

The vulnerability exists in the gRPC client used by the remote executor network controller. When a node attempts to send messages to remote peers via the `NetworkMessageServiceClient`, the client calls `self.inner.ready().await` to check service readiness before sending requests. [1](#0-0) 

The critical issue is that the gRPC client is created without any timeout configuration: [2](#0-1) 

The connection is established using `connect_lazy()` with no timeout on the endpoint, no HTTP2 keepalive settings, and no request timeout. When `send_message` is called: [3](#0-2) 

If the remote server accepts the TCP connection but never responds to the gRPC request, the `ready()` call in `simple_msg_exchange` will block indefinitely. This causes the outbound handler task to hang: [4](#0-3) 

**Attack Propagation:**
1. Attacker controls a malicious node that accepts gRPC connections
2. When victim node calls `simple_msg_exchange`, it enters `ready().await`
3. Attacker's server accepts TCP connection but never sends response
4. The `ready()` future never completes, blocking indefinitely
5. The outbound handler task hangs, unable to process other messages
6. Resources accumulate as more messages queue up
7. Node communication degrades, potentially affecting consensus participation

**Contrast with Secure Implementation:**
Other parts of the codebase properly configure timeouts. For example, the indexer gRPC server configures HTTP2 keepalive: [5](#0-4) [6](#0-5) 

However, the `GRPCNetworkMessageServiceClientWrapper` lacks any such timeout configuration, making it vulnerable.

## Impact Explanation

This is a **HIGH severity** vulnerability per the Aptos bug bounty program criteria:

- **Validator node slowdowns**: The outbound handler is a critical component for node communication. When it hangs, the node cannot send messages to that peer, degrading network performance.
- **Resource exhaustion**: Blocked tasks continue to hold resources (memory, file descriptors) while waiting indefinitely.
- **Potential consensus impact**: If enough outbound handlers hang targeting different peers, a node may lose the ability to communicate with sufficient validators, affecting consensus participation.
- **Easy exploitation**: Any network peer can trigger this by simply accepting connections without responding.

The NetworkController is used by the remote executor service for distributed block execution: [7](#0-6) 

While the remote executor may not be on the critical consensus path in all deployments, the underlying `secure/net` infrastructure could be used in other contexts where communication failures would directly impact validator operations.

## Likelihood Explanation

**Likelihood: HIGH**

- **Low attacker requirements**: Any network peer can trigger this vulnerability by accepting connections but not responding
- **No special privileges needed**: Does not require validator access or insider knowledge
- **Simple exploitation**: Attacker only needs to accept TCP connections and remain silent
- **Deterministic trigger**: The vulnerability is reliably triggered when connecting to an unresponsive server
- **No rate limiting**: An attacker can potentially establish multiple connections to maximize impact

## Recommendation

Configure appropriate timeouts on the gRPC client to prevent indefinite blocking. The fix should include:

1. **Connection timeout** on the endpoint
2. **HTTP2 keepalive** to detect dead connections
3. **Request-level timeout** (can be implemented at application layer)

**Proposed Fix:**

```rust
async fn get_channel(remote_addr: String) -> NetworkMessageServiceClient<Channel> {
    info!("Trying to connect to remote server at {:?}", remote_addr);
    
    // Configure endpoint with timeouts
    let endpoint = tonic::transport::Endpoint::new(remote_addr)
        .unwrap()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .http2_keep_alive_interval(std::time::Duration::from_secs(60))
        .keep_alive_timeout(std::time::Duration::from_secs(10))
        .keep_alive_while_idle(true);
    
    let conn = endpoint.connect_lazy();
    NetworkMessageServiceClient::new(conn).max_decoding_message_size(MAX_MESSAGE_SIZE)
}
```

Additionally, consider wrapping the `send_message` call with a timeout:

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
    
    // Add timeout wrapper
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        self.remote_channel.simple_msg_exchange(request)
    ).await {
        Ok(Ok(_)) => {},
        Ok(Err(e)) => {
            error!(
                "Error '{}' sending message to {} on node {:?}",
                e, self.remote_addr, sender_addr
            );
        },
        Err(_) => {
            error!(
                "Timeout sending message to {} on node {:?}",
                self.remote_addr, sender_addr
            );
        }
    }
}
```

Also change the panic to an error log to prevent node crashes from communication failures.

## Proof of Concept

```rust
#[cfg(test)]
mod timeout_attack_poc {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::thread;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_indefinite_blocking_attack() {
        // Start a malicious server that accepts connections but never responds
        let malicious_port = aptos_config::utils::get_available_port();
        let malicious_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), malicious_port);
        
        thread::spawn(move || {
            let listener = TcpListener::bind(malicious_addr).unwrap();
            // Accept connection but never respond
            for stream in listener.incoming() {
                let _stream = stream.unwrap();
                // Keep connection open but never send data
                thread::sleep(Duration::from_secs(3600));
            }
        });
        
        // Wait for server to start
        thread::sleep(Duration::from_millis(100));
        
        // Create victim client
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut client = GRPCNetworkMessageServiceClientWrapper::new(&rt, malicious_addr);
        
        let victim_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let test_message = Message::new(vec![1, 2, 3]);
        let message_type = MessageType::new("test".to_string());
        
        // This will hang indefinitely without timeout
        let start = std::time::Instant::now();
        
        // Wrap in timeout to prove it hangs
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.send_message(victim_addr, test_message, &message_type)
        ).await;
        
        let elapsed = start.elapsed();
        
        // Should timeout after 5 seconds, proving the call blocks indefinitely
        assert!(result.is_err(), "Call should timeout");
        assert!(elapsed >= Duration::from_secs(5), "Should block for at least 5 seconds");
        assert!(elapsed < Duration::from_secs(6), "Should timeout after 5 seconds");
    }
}
```

## Notes

This vulnerability demonstrates a critical gap in defensive programming practices. While the server-side properly configures timeouts, the client-side lacks these protections. The issue is particularly concerning because:

1. The outbound handler processes messages in a single task loop, so one blocked call affects all subsequent messages
2. The panic on error (rather than graceful error handling) can crash the entire network controller
3. No circuit breaker or connection health monitoring exists to detect and isolate unresponsive peers

The fix should be implemented alongside proper error handling and connection health monitoring to ensure robust network communication resilience.

### Citations

**File:** protos/rust/src/pb/aptos.remote_executor.v1.tonic.rs (L92-104)
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
```

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

**File:** secure/net/src/network_controller/outbound_handler.rs (L155-160)
```rust
                grpc_clients
                    .get_mut(remote_addr)
                    .unwrap()
                    .send_message(*socket_addr, msg, message_type)
                    .await;
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L26-30)
```rust
// HTTP2 ping interval and timeout.
// This can help server to garbage collect dead connections.
// tonic server: https://docs.rs/tonic/latest/tonic/transport/server/struct.Server.html#method.http2_keepalive_interval
const HTTP2_PING_INTERVAL_DURATION: std::time::Duration = std::time::Duration::from_secs(60);
const HTTP2_PING_TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(10);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L205-207)
```rust
                Server::builder()
                    .http2_keepalive_interval(Some(HTTP2_PING_INTERVAL_DURATION))
                    .http2_keepalive_timeout(Some(HTTP2_PING_TIMEOUT_DURATION))
```

**File:** execution/executor-service/src/remote_executor_client.rs (L154-160)
```rust
            NetworkController::new(
                "remote-executor-coordinator".to_string(),
                coordinator_address,
                5000,
            ),
            num_threads,
        ))
```
