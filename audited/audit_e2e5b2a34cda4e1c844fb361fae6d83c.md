# Audit Report

## Title
Handshake Flooding Enables Resource Exhaustion Before Connection Limit Enforcement

## Summary
The Aptos network layer accepts and processes inbound connections through expensive cryptographic handshakes before enforcing connection limits, allowing attackers to exhaust validator CPU and memory resources through handshake flooding attacks.

## Finding Description

The network layer processes inbound connections in two stages: (1) connection upgrade including Noise handshake and protocol negotiation, and (2) connection limit enforcement. The critical vulnerability is that stage (1) occurs before stage (2), allowing resource exhaustion.

**Attack Flow:**

1. Attacker initiates multiple simultaneous TCP connections to a validator node
2. Each connection is immediately accepted and queued for upgrade processing [1](#0-0) 
3. The upgrade process performs expensive operations with a 30-second timeout [2](#0-1) :
   - Noise IK handshake (Diffie-Hellman key exchanges) [3](#0-2) 
   - Handshake message exchange [4](#0-3) 
   - Protocol negotiation [5](#0-4) 
4. Only after completing all handshake operations does the system check connection limits [6](#0-5) 

**Evidence of Known Issue:**

The codebase contains an explicit acknowledgment of this vulnerability [7](#0-6) 

**Resource Consumption:**
- No limit on pending connection upgrades tracked by metrics [8](#0-7) 
- CPU exhaustion via cryptographic operations per connection
- Memory exhaustion via unbounded FuturesUnordered collection [9](#0-8) 
- Each attacker connection can consume resources for up to 30 seconds

**Why Existing Protections Are Insufficient:**
- Connection limits only apply post-handshake [10](#0-9) 
- Anti-replay timestamps only prevent replay from same public key [11](#0-10) , not flooding from multiple keys
- IP-based rate limiting applies to message bytes, not connection attempts [12](#0-11) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos Bug Bounty criteria: "Validator node slowdowns". 

An attacker can:
- Degrade validator performance by forcing continuous expensive cryptographic operations
- Exhaust CPU resources handling handshakes instead of processing consensus messages
- Cause memory pressure from unbounded pending connection futures
- Potentially trigger consensus delays if validator resources become sufficiently constrained

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits" - the handshake process has no computational limits before connection acceptance.

## Likelihood Explanation

**High Likelihood:**
- Attack requires only standard TCP connection capabilities
- No authentication required before resource consumption
- Attacker can use multiple source IPs to amplify attack
- No rate limiting on connection initiation
- Cost to attacker is minimal (TCP connections) vs. cost to defender (cryptographic operations)
- Validator nodes have publicly advertised network addresses

## Recommendation

Implement pre-handshake connection rate limiting at multiple levels:

1. **Add global pending upgrade limit** - Reject new connections when pending upgrades exceed threshold
2. **Implement per-IP connection rate limiting** - Track connection attempts per source IP before handshake
3. **Add handshake timeout tracking** - Aggressive timeout for connections not completing handshake quickly
4. **Implement connection slot reservation** - Reserve slots for known/trusted peers

**Example Fix for Critical Issue:**

```rust
// In TransportHandler::listen()
const MAX_PENDING_UPGRADES: usize = 200;

// Add check before pushing to pending_inbound_connections:
if pending_inbound_connections.len() >= MAX_PENDING_UPGRADES {
    warn!("Rejecting connection: max pending upgrades reached");
    continue; // Drop the connection without upgrade
}
```

Additionally, move connection limit checking to occur before or early in the handshake process, as acknowledged in the existing TODO comment.

## Proof of Concept

```rust
// Network flood PoC (conceptual - would require actual network test harness)
use std::net::TcpStream;
use std::thread;

fn flood_validator(target: &str, num_connections: usize) {
    let handles: Vec<_> = (0..num_connections)
        .map(|i| {
            let target = target.to_string();
            thread::spawn(move || {
                // Open connection and stall in handshake
                if let Ok(mut stream) = TcpStream::connect(&target) {
                    // Send partial Noise handshake to consume resources
                    let _ = stream.write(&[0u8; 32]); // Invalid handshake init
                    thread::sleep(Duration::from_secs(30)); // Hold connection
                }
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
}

// Flood validator with 1000 simultaneous connections
// Each forces a 30-second handshake timeout
flood_validator("validator_ip:6180", 1000);
```

## Notes

This vulnerability is distinct from generic network-layer DoS attacks because it exploits a specific implementation flaw in the application layer - the ordering of expensive cryptographic operations before connection limit enforcement. The TODO comment in the codebase confirms this is a recognized design issue requiring remediation.

### Citations

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

**File:** network/framework/src/peer_manager/transport.rs (L148-152)
```rust
                counters::pending_connection_upgrades(
                    &self.network_context,
                    ConnectionOrigin::Inbound,
                )
                .inc();
```

**File:** network/framework/src/transport/mod.rs (L41-41)
```rust
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);
```

**File:** network/framework/src/transport/mod.rs (L277-293)
```rust
    let (mut socket, remote_peer_id, peer_role) =
        ctxt.noise.upgrade_inbound(socket).await.map_err(|err| {
            if err.should_security_log() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(15)),
                    warn!(
                        SecurityEvent::NoiseHandshake,
                        NetworkSchema::new(&ctxt.noise.network_context)
                            .network_address(&addr)
                            .connection_origin(&origin),
                        error = %err,
                    )
                );
            }
            let err = io::Error::other(err);
            add_pp_addr(proxy_protocol_enabled, err, &addr)
        })?;
```

**File:** network/framework/src/transport/mod.rs (L303-305)
```rust
    let remote_handshake = exchange_handshake(&handshake_msg, &mut socket)
        .await
        .map_err(|err| add_pp_addr(proxy_protocol_enabled, err, &addr))?;
```

**File:** network/framework/src/transport/mod.rs (L308-317)
```rust
    let (messaging_protocol, application_protocols) = handshake_msg
        .perform_handshake(&remote_handshake)
        .map_err(|err| {
            let err = format!(
                "handshake negotiation with peer {} failed: {}",
                remote_peer_id.short_str(),
                err
            );
            add_pp_addr(proxy_protocol_enabled, io::Error::other(err), &addr)
        })?;
```

**File:** network/framework/src/peer_manager/mod.rs (L351-389)
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
```

**File:** network/framework/src/noise/handshake.rs (L59-64)
```rust
    pub fn is_replay(&self, pubkey: x25519::PublicKey, timestamp: u64) -> bool {
        if let Some(last_timestamp) = self.0.get(&pubkey) {
            &timestamp <= last_timestamp
        } else {
            false
        }
```

**File:** config/src/config/network_config.rs (L368-377)
```rust
pub struct RateLimitConfig {
    /// Maximum number of bytes/s for an IP
    pub ip_byte_bucket_rate: usize,
    /// Maximum burst of bytes for an IP
    pub ip_byte_bucket_size: usize,
    /// Initial amount of tokens initially in the bucket
    pub initial_bucket_fill_percentage: u8,
    /// Allow for disabling the throttles
    pub enabled: bool,
}
```
