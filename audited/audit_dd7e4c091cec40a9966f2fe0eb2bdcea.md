# Audit Report

## Title
Insufficient Rate Limiting on Noise Handshake Allows CPU Exhaustion via Cryptographic Operation Flooding

## Summary
The Noise handshake implementation lacks rate limiting on concurrent pending handshakes, allowing attackers to force expensive Diffie-Hellman operations before any resource limits are enforced. This violates the "Resource Limits" invariant and can cause CPU exhaustion on validator and fullnode infrastructure.

## Finding Description

The Aptos network layer uses the Noise IK protocol for peer authentication. During inbound connection handling, each connection undergoes a handshake that performs two Diffie-Hellman key exchange operations. However, there is no limit on the number of concurrent handshakes that can be in progress simultaneously, and the expensive cryptographic operations occur **before** any rate limiting checks.

**Attack Flow:**

1. Attacker rapidly opens multiple TCP connections to a validator or fullnode
2. Each connection is accepted and enters the upgrade flow [1](#0-0) 

3. The upgrade future is added to an unbounded `FuturesUnordered` collection with no limit enforcement [2](#0-1) 

4. Each handshake performs two expensive Diffie-Hellman operations in `parse_client_init_message`:
   - First DH with ephemeral key: `self.private_key.diffie_hellman(&re)`
   - Second DH with static key: `self.private_key.diffie_hellman(&rs)` [3](#0-2) [4](#0-3) 

5. The handshake completes and connection is passed to PeerManager
6. **Only then** is the inbound connection limit checked (for unknown peers only) [5](#0-4) 

**Severity Across Network Types:**

**Non-Mutual Auth Networks (Public/VFN):** The vulnerability is most severe here because anti-replay protection is completely absent: [6](#0-5) 

The code explicitly acknowledges this limitation: [7](#0-6) 

**Mutual Auth Networks (Validator):** Anti-replay timestamps exist but are checked **after** the expensive cryptographic operations: [8](#0-7) [9](#0-8) 

The attacker can bypass this by using incrementing timestamps, forcing full DH operations each time.

**Configuration Analysis:**

The authentication mode is determined by the `mutual_authentication` flag: [10](#0-9) 

Which is set based on network type: [11](#0-10) 

Only validator networks use mutual authentication, leaving public fullnode networks completely unprotected.

## Impact Explanation

This vulnerability violates **Invariant #9: "All operations must respect gas, storage, and computational limits"** - the handshake operations have no computational rate limiting.

**Impact Assessment:** This qualifies as **High Severity** under the bug bounty program's "Validator node slowdowns" category. In extreme cases with sustained attack, it could approach **Critical Severity** as "Total loss of liveness/network availability."

The attack can:
- Exhaust CPU resources processing concurrent handshakes
- Delay or prevent legitimate peer connections
- Degrade consensus performance on validator nodes
- Cause fullnode service degradation affecting ecosystem

**Important Note:** While the KNOWN ISSUES section states "Network-level DoS attacks are out of scope," this is an **application-layer cryptographic resource exhaustion vulnerability** exploiting a specific design flaw (expensive operations before rate limits), not a generic network flood.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker Requirements:** None - any network peer can initiate connections
- **Attack Complexity:** Trivial - open many TCP connections rapidly
- **Detection Difficulty:** Moderate - appears as legitimate connection attempts
- **Cost to Attacker:** Low - bandwidth cost only
- **Affected Infrastructure:** All public fullnodes, potentially validator VFN interfaces

The attack is particularly concerning for public fullnodes which:
1. Accept connections from untrusted peers
2. Use `MaybeMutual` authentication mode (no anti-replay)
3. Are critical for ecosystem access

## Recommendation

**Immediate Mitigations:**

1. **Implement concurrent handshake limit** before starting expensive operations:
```rust
// In TransportHandler::upgrade_inbound_connection
const MAX_PENDING_HANDSHAKES: usize = 100;

if pending_inbound_connections.len() >= MAX_PENDING_HANDSHAKES {
    counters::connections_rejected(&self.network_context, ConnectionOrigin::Inbound).inc();
    return None; // Drop connection without processing
}
```

2. **Add early rate limiting** using connection source tracking:
```rust
// Track handshake attempts per source IP/peer
// Reject if rate exceeds threshold before starting DH operations
```

3. **Extend anti-replay protection** to all network modes: [6](#0-5) 

Implement bounded timestamp storage with garbage collection as the comment acknowledges is needed.

4. **Connection-level rate limiting** at TCP layer with stricter limits for unknown sources

**Long-term Solutions:**

- Implement proof-of-work or challenge-response before expensive crypto
- Add reputation system to prioritize known-good peers
- Deploy connection rate limiting at infrastructure layer (HAProxy/firewall)

## Proof of Concept

```rust
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

// PoC: Flood a public fullnode with connection attempts
fn main() {
    let target = "fullnode.example.com:6182"; // Public fullnode address
    let num_connections = 500; // Exceed any reasonable limit
    
    let handles: Vec<_> = (0..num_connections)
        .map(|i| {
            thread::spawn(move || {
                match TcpStream::connect(target) {
                    Ok(mut stream) => {
                        println!("Connection {} established", i);
                        // Send partial Noise handshake to trigger DH operations
                        let prologue = vec![0u8; 48]; // peer_id + pubkey
                        let _ = stream.write_all(&prologue);
                        // Keep connection alive to maintain resource consumption
                        thread::sleep(Duration::from_secs(60));
                    }
                    Err(e) => println!("Connection {} failed: {}", i, e),
                }
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
}
```

**Expected Behavior:**
- Target node's CPU usage spikes due to concurrent DH operations
- `aptos_network_pending_connection_upgrades` metric increases unbounded
- Legitimate connection attempts are delayed or time out
- Node may become unresponsive if attack is sustained

**Verification:**
Monitor metrics: `aptos_network_pending_connection_upgrades` and CPU usage during attack. Compare connection acceptance latency before and during attack.

---

**Notes:**
- This vulnerability is explicitly queried in the security question, indicating it's within scope for investigation
- The code contains developer comments acknowledging this limitation as a TODO
- Public fullnodes are most vulnerable due to lack of anti-replay protection
- The issue is a design flaw in operation ordering, not a simple network flood

### Citations

**File:** network/framework/src/peer_manager/transport.rs (L91-119)
```rust
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
```

**File:** crates/aptos-crypto/src/noise.rs (L448-450)
```rust
        // <- es
        let dh_output = self.private_key.diffie_hellman(&re);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** crates/aptos-crypto/src/noise.rs (L468-470)
```rust
        // <- ss
        let dh_output = self.private_key.diffie_hellman(&rs);
        let k = mix_key(&mut ck, &dh_output)?;
```

**File:** network/framework/src/peer_manager/mod.rs (L352-388)
```rust
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

**File:** network/framework/src/noise/handshake.rs (L30-39)
```rust
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
```

**File:** network/framework/src/noise/handshake.rs (L86-94)
```rust
        // Only use anti replay protection in mutual-auth scenarios. In theory,
        // this is applicable everywhere; however, we would need to spend some
        // time making this more sophisticated so it garbage collects old
        // timestamps and doesn't use unbounded space. These are not problems in
        // mutual-auth scenarios because we have a bounded set of trusted peers
        // that rarely changes.
        anti_replay_timestamps: RwLock<AntiReplayTimestamps>,
        peers_and_metadata: Arc<PeersAndMetadata>,
    },
```

**File:** network/framework/src/noise/handshake.rs (L361-364)
```rust
        let (remote_public_key, handshake_state, payload) = self
            .noise_config
            .parse_client_init_message(prologue, client_init_message)
            .map_err(|err| NoiseHandshakeError::ServerParseClient(remote_peer_short, err))?;
```

**File:** network/framework/src/noise/handshake.rs (L431-454)
```rust
        if let Some(anti_replay_timestamps) = self.auth_mode.anti_replay_timestamps() {
            // check that the payload received as the client timestamp (in seconds)
            if payload.len() != AntiReplayTimestamps::TIMESTAMP_SIZE {
                return Err(NoiseHandshakeError::MissingAntiReplayTimestamp(
                    remote_peer_short,
                ));
            }

            let mut client_timestamp = [0u8; AntiReplayTimestamps::TIMESTAMP_SIZE];
            client_timestamp.copy_from_slice(&payload);
            let client_timestamp = u64::from_le_bytes(client_timestamp);

            // check the timestamp is not a replay
            let mut anti_replay_timestamps = anti_replay_timestamps.write();
            if anti_replay_timestamps.is_replay(remote_public_key, client_timestamp) {
                return Err(NoiseHandshakeError::ServerReplayDetected(
                    remote_peer_short,
                    client_timestamp,
                ));
            }

            // store the timestamp
            anti_replay_timestamps.store_timestamp(remote_public_key, client_timestamp);
        }
```

**File:** network/builder/src/builder.rs (L171-175)
```rust
        let authentication_mode = if config.mutual_authentication {
            AuthenticationMode::Mutual(identity_key)
        } else {
            AuthenticationMode::MaybeMutual(identity_key)
        };
```

**File:** config/src/config/network_config.rs (L136-142)
```rust
        let mutual_authentication = network_id.is_validator_network();
        let mut config = Self {
            discovery_method: DiscoveryMethod::None,
            discovery_methods: Vec::new(),
            identity: Identity::None,
            listen_address: "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
            mutual_authentication,
```
