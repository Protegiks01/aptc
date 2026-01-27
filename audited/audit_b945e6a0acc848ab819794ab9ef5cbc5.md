# Audit Report

## Title
Unbounded Inbound Connection Queue Allows Resource Exhaustion Attack on Validator Nodes

## Summary
The network transport layer's `TransportHandler::listen()` function uses an unbounded `FuturesUnordered` collection to queue pending inbound connection upgrades. An attacker can flood a validator with TCP connections, causing each to be queued for Noise handshake processing without any limit, leading to file descriptor, memory, and CPU exhaustion before the `inbound_connection_limit` in `PeerManager` can take effect.

## Finding Description

The vulnerability exists in the connection acceptance flow where inbound connections are processed in two stages:

1. **Stage 1 (Vulnerable)**: Connection accepted and queued for upgrade in `TransportHandler::listen()` [1](#0-0) 

2. **Stage 2 (Protection Too Late)**: Connection limit checked in `PeerManager::handle_new_connection_event()` [2](#0-1) 

The critical issue is that `pending_inbound_connections` is created as an unbounded `FuturesUnordered` collection [3](#0-2) . When a new inbound connection arrives, it's immediately pushed into this collection without checking any limits [4](#0-3) .

Each queued connection undergoes a Noise handshake upgrade process with a 30-second timeout [5](#0-4) . The `inbound_connection_limit` (default: 100) [6](#0-5)  only applies AFTER the connection upgrade completes successfully and reaches PeerManager.

**Attack Scenario:**
1. Attacker opens thousands of TCP connections to a validator
2. Each connection completes TCP 3-way handshake (accepted from TCP backlog of 256) [7](#0-6) 
3. Each accepted connection is pushed to unbounded `pending_inbound_connections` for Noise upgrade
4. Attacker either slows down the Noise handshake or lets connections timeout after 30 seconds
5. Thousands of connections accumulate in `pending_inbound_connections`, each consuming:
   - One file descriptor for the TCP socket
   - Memory for the future, cryptographic state, and buffers
   - CPU cycles for Noise handshake processing
6. PeerManager's `inbound_connection_limit` never activates because connections haven't completed upgrade

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Resource exhaustion degrades validator performance
- **Availability impact**: Exhausted file descriptors prevent accepting new legitimate connections, potentially disrupting validator-to-validator communication
- **Consensus impact**: If multiple validators are attacked simultaneously, network liveness could be affected

The attack breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - here, connection acceptance has no computational resource limit at the transport layer.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible:
- No authentication required before reaching the vulnerable code path
- Attacker only needs ability to open TCP connections to validator ports
- No rate limiting or connection limits before the vulnerable queue
- Attack complexity is low - standard TCP socket programming
- Validators have publicly known IP addresses and ports
- Attack can be automated and scaled easily

The only mitigations are OS-level file descriptor limits, which would cause the validator to fail rather than gracefully reject connections.

## Recommendation

Implement a hard limit on pending inbound connection upgrades at the `TransportHandler` level:

```rust
pub async fn listen(mut self) {
    let mut pending_inbound_connections = FuturesUnordered::new();
    let mut pending_outbound_connections = FuturesUnordered::new();
    
    // Add configuration parameter for max pending upgrades
    const MAX_PENDING_INBOUND_UPGRADES: usize = 100;
    
    loop {
        futures::select! {
            // ... dial_request handling ...
            
            inbound_connection = self.listener.select_next_some() => {
                // Check limit BEFORE accepting connection
                if pending_inbound_connections.len() >= MAX_PENDING_INBOUND_UPGRADES {
                    warn!(
                        NetworkSchema::new(&self.network_context),
                        "Rejecting inbound connection - max pending upgrades reached"
                    );
                    // Drop the connection immediately
                    continue;
                }
                
                if let Some(fut) = self.upgrade_inbound_connection(inbound_connection) {
                    pending_inbound_connections.push(fut);
                }
            },
            // ... rest of select branches ...
        }
    }
}
```

Additionally, make `MAX_PENDING_INBOUND_UPGRADES` configurable via `NetworkConfig` and add proper metrics tracking.

## Proof of Concept

```rust
// PoC: Connection flooding script (conceptual)
use tokio::net::TcpStream;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let target_addr = "validator_ip:6180"; // Validator listen address
    let mut connections = Vec::new();
    
    // Flood with connection attempts
    for i in 0..5000 {
        match TcpStream::connect(target_addr).await {
            Ok(mut stream) => {
                // Start Noise handshake but don't complete it
                // Just hold the connection open
                connections.push(stream);
                
                if i % 100 == 0 {
                    println!("Opened {} connections", i);
                }
            }
            Err(e) => {
                println!("Connection {} failed: {}", i, e);
                break;
            }
        }
        
        // Small delay to avoid overwhelming local system
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    println!("Total connections held: {}", connections.len());
    println!("Monitoring validator metrics for resource exhaustion...");
    
    // Hold connections open until timeout
    tokio::time::sleep(Duration::from_secs(60)).await;
}
```

Monitor validator metrics during attack:
- `aptos_network_pending_connection_upgrades{direction="inbound"}` should grow unbounded
- System file descriptor usage increases dramatically
- Memory consumption grows with pending connections
- Validator may become unresponsive to legitimate connection attempts

## Notes

The vulnerability exists because connection limiting happens at the wrong layer. While `PeerManager` has an `inbound_connection_limit` configuration, it only applies to fully established connections after the expensive Noise handshake completes. The unbounded queue at the transport layer allows attackers to exhaust resources before this limit takes effect. The TCP listen backlog of 256 provides minimal protection since accepted connections are immediately moved to the application-layer queue.

### Citations

**File:** network/framework/src/peer_manager/transport.rs (L90-125)
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
                },
                (upgrade, addr, peer_id, start_time, response_tx) = pending_outbound_connections.select_next_some() => {
                    self.handle_completed_outbound_upgrade(upgrade, addr, peer_id, start_time, response_tx).await;
                },
                (upgrade, addr, start_time) = pending_inbound_connections.select_next_some() => {
                    self.handle_completed_inbound_upgrade(upgrade, addr, start_time).await;
                },
                complete => break,
            }
        }

        warn!(
            NetworkSchema::new(&self.network_context),
            "{} Incoming connections listener Task ended", self.network_context
        );
    }
```

**File:** network/framework/src/peer_manager/mod.rs (L351-390)
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
            }
        }
```

**File:** network/framework/src/transport/mod.rs (L41-41)
```rust
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);
```

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** network/netcore/src/transport/tcp.rs (L127-127)
```rust
        let listener = socket.listen(256)?;
```
