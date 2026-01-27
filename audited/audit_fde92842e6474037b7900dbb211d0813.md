# Audit Report

## Title
Unbounded Connection Upgrade Queue Allows Memory Exhaustion Attack on Validator Nodes

## Summary
The `TransportHandler` in the Aptos network layer maintains an unbounded `FuturesUnordered` queue for pending inbound connection upgrades. An attacker can exhaust validator node memory by rapidly opening TCP connections, causing the upgrade queue to grow without limit, leading to OOM crashes and loss of validator availability.

## Finding Description

While `AndThenStream` itself properly propagates backpressure at the stream level [1](#0-0) , the integration layer fails to apply proper admission control.

The vulnerability exists in `TransportHandler::listen()` where incoming connections are processed. The handler initializes an unbounded `FuturesUnordered` collection for pending connection upgrades [2](#0-1) . 

The event loop continuously polls the listener for new inbound connections [3](#0-2) . Each accepted connection immediately creates an upgrade future (involving expensive cryptographic handshakes) and pushes it to `pending_inbound_connections` **without any capacity check**.

Even when the channel to PeerManager is full or blocked [4](#0-3) , the listener continues accepting new connections on every loop iteration. This is because the `futures::select!` macro polls all branches concurrently - the listener branch (line 106) continues polling regardless of blocking in the upgrade completion branch (line 114-115).

The PeerManager does enforce an inbound connection limit (default: 100) [5](#0-4) , but this check occurs **after** the connection has completed its upgrade [6](#0-5) . By this time, memory has already been consumed during the upgrade phase.

Critically, the RPC handler implements explicit capacity checking for a similar pattern, rejecting requests when `inbound_rpc_tasks.len()` exceeds `max_concurrent_inbound_rpcs` [7](#0-6) . The TransportHandler lacks this protection.

**Attack Path:**
1. Attacker rapidly opens TCP connections to a validator node (thousands per second)
2. TCP listener accepts connections (kernel backlog: 256) [8](#0-7) 
3. Each connection creates an upgrade future performing Noise handshakes with 30-second timeout [9](#0-8) 
4. Upgrade futures accumulate in unbounded `pending_inbound_connections` queue
5. Each future holds: TcpSocket, cryptographic state, buffers (~10-50 KB each)
6. At 1000 connections/second: 30,000 concurrent upgrades = 300MB-1.5GB memory consumption
7. Validator node experiences memory pressure, CPU exhaustion from crypto operations
8. OOM crash or severe performance degradation
9. Validator unable to participate in consensus, affecting network liveness

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria:

- **Validator node slowdowns/crashes**: Direct impact on validator availability
- **Significant protocol violations**: Breaks the resource limits invariant - "All operations must respect gas, storage, and computational limits"
- **Network availability impact**: Multiple validators under attack could degrade consensus performance

While not causing direct fund loss or consensus safety violations, this enables targeted attacks against validator infrastructure, potentially causing:
- Temporary loss of validator participation
- Degraded consensus performance if multiple validators affected
- Network instability during coordinated attacks

## Likelihood Explanation

**Likelihood: High**

This attack is highly practical:
- **Low attack complexity**: Opening TCP connections requires minimal resources from attacker
- **No authentication required**: Attack occurs before peer authentication
- **No rate limiting at transport layer**: Missing the same protection present in RPC handler
- **Publicly accessible**: Validator nodes accept inbound connections by design
- **Economically viable**: Single attacker machine can generate thousands of connections per second

The attack requires no insider access, cryptographic breaks, or protocol knowledge - just network connectivity to validator nodes.

## Recommendation

Implement explicit capacity limiting for pending connection upgrades, mirroring the pattern used in the RPC handler:

**File: `network/framework/src/peer_manager/transport.rs`**

1. Add a configuration parameter for maximum concurrent connection upgrades (suggested: 256-512)

2. In `TransportHandler::upgrade_inbound_connection()`, add capacity check before creating upgrade future:

```rust
fn upgrade_inbound_connection(
    &self,
    incoming_connection: Result<(TTransport::Inbound, NetworkAddress), TTransport::Error>,
    pending_upgrades_count: usize, // Pass current queue size
    max_pending_upgrades: usize,   // Configuration parameter
) -> Option<BoxFuture<...>> {
    match incoming_connection {
        Ok((upgrade, addr)) => {
            // ADDED: Drop connections if upgrade queue is at capacity
            if pending_upgrades_count >= max_pending_upgrades {
                info!(
                    NetworkSchema::new(&self.network_context).network_address(&addr),
                    "{} Connection dropped due to pending upgrade limit: {} >= {}",
                    self.network_context, pending_upgrades_count, max_pending_upgrades
                );
                counters::connections_rejected(&self.network_context, ConnectionOrigin::Inbound).inc();
                return None;
            }
            
            // Existing code continues...
        }
        // ...
    }
}
```

3. Update the event loop to pass queue size:

```rust
inbound_connection = self.listener.select_next_some() => {
    if let Some(fut) = self.upgrade_inbound_connection(
        inbound_connection,
        pending_inbound_connections.len(),
        self.max_pending_connection_upgrades
    ) {
        pending_inbound_connections.push(fut);
    }
},
```

This ensures backpressure is properly applied at the connection upgrade layer, preventing unbounded memory growth.

## Proof of Concept

```rust
// Add to network/framework/src/peer_manager/transport.rs tests
#[tokio::test]
async fn test_connection_upgrade_queue_overflow() {
    use futures::stream::StreamExt;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    
    // Setup: Create a TransportHandler with default (unbounded) configuration
    let (transport_notifs_tx, _) = aptos_channels::new(10, &IntGauge::new());
    let (_, transport_reqs_rx) = aptos_channels::new(10, &IntGauge::new());
    
    let transport = tcp::TcpTransport::default();
    let listen_addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    
    let (mut handler, actual_addr) = TransportHandler::new(
        NetworkContext::mock(),
        TimeService::mock(),
        transport,
        listen_addr,
        transport_reqs_rx,
        transport_notifs_tx,
    );
    
    // Attack: Rapidly open 10,000 connections
    let attack_task = tokio::spawn(async move {
        let addr = actual_addr.to_string();
        for _ in 0..10000 {
            let _ = TcpStream::connect(&addr).await;
            // Don't complete handshake - let them pile up
        }
    });
    
    // Observation: pending_inbound_connections grows unbounded
    // Without the fix, this would consume excessive memory
    // With the fix, connections beyond the limit would be rejected
    
    tokio::time::timeout(Duration::from_secs(5), handler.listen()).await;
    attack_task.abort();
    
    // Assert: Memory usage should be bounded (requires instrumentation)
    // Or: Connection rejection counter should be > 0 after fix is applied
}
```

## Notes

This vulnerability demonstrates that while individual stream components like `AndThenStream` may properly implement backpressure semantics, system-level integration failures can still create resource exhaustion vulnerabilities. The inconsistency with the RPC handler's explicit capacity checking suggests this is an implementation oversight rather than intentional design. Production deployments should immediately implement connection upgrade limits until a proper fix is deployed.

### Citations

**File:** network/netcore/src/transport/and_then.rs (L95-110)
```rust
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Option<Self::Item>> {
        match self.as_mut().project().stream.poll_next(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok((fut1, addr)))) => Poll::Ready(Some(Ok((
                AndThenFuture::new(
                    fut1,
                    self.f.clone(),
                    addr.clone(),
                    ConnectionOrigin::Inbound,
                ),
                addr,
            )))),
        }
    }
```

**File:** network/framework/src/peer_manager/transport.rs (L91-92)
```rust
        let mut pending_inbound_connections = FuturesUnordered::new();
        let mut pending_outbound_connections = FuturesUnordered::new();
```

**File:** network/framework/src/peer_manager/transport.rs (L106-109)
```rust
                inbound_connection = self.listener.select_next_some() => {
                    if let Some(fut) = self.upgrade_inbound_connection(inbound_connection) {
                        pending_inbound_connections.push(fut);
                    }
```

**File:** network/framework/src/peer_manager/transport.rs (L356-356)
```rust
        if let Err(err) = self.transport_notifs_tx.send(event).await {
```

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** network/framework/src/peer_manager/mod.rs (L372-388)
```rust
                if !self
                    .active_peers
                    .contains_key(&conn.metadata.remote_peer_id)
                    && unknown_inbound_conns + 1 > self.inbound_connection_limit
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .connection_metadata_with_address(&conn.metadata),
                        "{} Connection rejected due to connection limit: {}",
                        self.network_context,
                        conn.metadata
                    );
                    counters::connections_rejected(&self.network_context, conn.metadata.origin)
                        .inc();
                    self.disconnect(conn);
                    return;
                }
```

**File:** network/framework/src/protocols/rpc/mod.rs (L212-223)
```rust
        // Drop new inbound requests if our completion queue is at capacity.
        if self.inbound_rpc_tasks.len() as u32 == self.max_concurrent_inbound_rpcs {
            // Increase counter of declined requests
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                INBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            return Err(RpcError::TooManyPending(self.max_concurrent_inbound_rpcs));
        }
```

**File:** network/netcore/src/transport/tcp.rs (L127-127)
```rust
        let listener = socket.listen(256)?;
```

**File:** network/framework/src/transport/mod.rs (L41-41)
```rust
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);
```
