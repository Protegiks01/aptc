# Audit Report

## Title
VFN Network Bypass: Malicious Peers Gain High-Priority Access via Network Interface Confusion

## Summary
The `get_peer_priority()` function in the Aptos data client incorrectly grants `HighPriority` status to any peer connected on the VFN network interface, regardless of whether the peer is actually a trusted validator. This allows malicious nodes to bypass peer prioritization controls by simply connecting to the publicly accessible VFN network port (6181), enabling them to monopolize state synchronization requests and degrade VFN performance.

## Finding Description

The vulnerability exists in the peer priority determination logic for Validator Full Nodes (VFNs). The code flow is:

**1. VFN Network Configuration:**
VFNs are configured to listen on the VFN network interface (typically port 6181) and use `MaybeMutual` authentication mode, which accepts connections from any peer with valid cryptographic credentials (PeerId matching public key), without requiring them to be in the trusted peers set. [1](#0-0) 

**2. Inbound Connection Acceptance:**
When a malicious peer connects to a VFN on the VFN network port, the Noise handshake accepts the connection in `MaybeMutual` mode. Since the peer is not in the trusted set and the local node is not a validator, the peer is assigned `PeerRole::Unknown`: [2](#0-1) 

Notably, the code comment states: "VFNs get no inbound connections on the vfn network" - indicating this scenario should not occur, yet nothing in the configuration enforces this assumption.

**3. Priority Assignment Bug:**
Despite receiving `PeerRole::Unknown`, when the VFN determines peer priority for state sync requests, it only checks the network interface, not the peer's role or trust status: [3](#0-2) 

The check `peer_network_id.is_vfn_network()` returns true for ANY peer connected on the VFN network, regardless of whether they are legitimate validators. This violates the stated intent in the comment: "VFNs should highly prioritize validators."

**4. Network ID Check Implementation:**
The network ID check is purely based on the enum value, with no authentication verification: [4](#0-3) 

**5. Preferential Peer Selection:**
High-priority peers are selected first for all state sync data requests, as the data client iterates through priority levels in order: [5](#0-4) 

**Attack Path:**
1. Attacker discovers VFN IP address (VFNs are publicly accessible nodes)
2. Attacker connects to port 6181 (VFN network) with valid cryptographic credentials (any PeerId/public key pair)
3. VFN accepts connection via `MaybeMutual` handshake, assigns `PeerRole::Unknown`
4. Priority check incorrectly grants `HighPriority` based solely on network interface
5. VFN preferentially sends state sync requests to attacker's node
6. Attacker delays responses or provides invalid data, degrading VFN synchronization performance

**Invariant Violation:**
This breaks the peer authentication and trust model invariant: only authenticated, trusted peers should receive privileged treatment for critical operations like state synchronization.

## Impact Explanation

**Severity: High** (aligns with "Validator node slowdowns" category - up to $50,000)

While this vulnerability directly affects VFNs rather than validators, the impact qualifies as High severity because:

1. **Network-Wide Performance Degradation**: VFNs serve as critical data sources for Public Full Nodes (PFNs). Compromising multiple VFNs creates a cascading effect that degrades state sync performance across the network.

2. **State Sync Disruption**: The malicious peer monopolizes the VFN's state sync requests, forcing the VFN to wait for timeouts before trying other peers, significantly slowing blockchain synchronization.

3. **Resource Exhaustion**: Multiple malicious connections (up to `inbound_connection_limit`, default 100) can consume VFN resources, compounding the performance impact.

4. **Operational Impact**: VFN operators would need to manually identify and block malicious IPs via HAProxy configuration, requiring intervention.

This is NOT a simple network-level DoS (which would be out of scope) but rather an application-layer logic bug in the peer prioritization system that enables targeted performance attacks.

## Likelihood Explanation

**Likelihood: High**

The attack has low barriers:
- **Discovery**: VFN IP addresses and ports are discoverable via network scanning or public node lists
- **Authentication**: Any attacker can generate valid cryptographic credentials (x25519 key pair + derived PeerId)
- **Execution**: Standard network socket connection to port 6181
- **Success Rate**: Guaranteed if VFN has available inbound connection slots (up to 100 by default)

The only limiting factor is the `inbound_connection_limit`, but this allows substantial attacker presence before connections are rejected: [6](#0-5) 

## Recommendation

**Fix: Verify peer role/trust status in addition to network interface**

The priority determination should check whether the peer is actually a trusted validator, not just whether they're connected on the VFN network:

```rust
// Handle the case that this node is a VFN
if peers_and_metadata
    .get_registered_networks()
    .contains(&NetworkId::Vfn)
{
    // VFNs should highly prioritize validators
    if peer_network_id.is_vfn_network() {
        // FIXED: Also verify peer is trusted/validator
        if is_trusted_peer(peers_and_metadata.clone(), peer) {
            return PeerPriority::HighPriority;
        }
        // Untrusted peers on VFN network should be medium/low priority
        return PeerPriority::MediumPriority;
    }
    // ... rest of logic
}
```

**Additional Hardening:**
1. Set `max_inbound_connections: 0` for VFN network in VFN configurations to prevent unexpected inbound connections
2. Add explicit validation that VFNs should only make outbound VFN network connections, not accept inbound ones
3. Consider adding peer role checks in the priority logic for all network types

## Proof of Concept

```rust
// Exploitation simulation (pseudocode for integration test)

#[test]
fn test_vfn_network_bypass_attack() {
    // 1. Setup: Create VFN node with VFN network registered
    let vfn_config = create_vfn_config();
    let vfn = spawn_vfn_node(vfn_config);
    
    // 2. Attacker: Generate malicious peer credentials
    let attacker_key = x25519::PrivateKey::generate_for_testing();
    let attacker_peer_id = PeerId::from_identity_public_key(
        attacker_key.public_key()
    );
    
    // 3. Attack: Connect to VFN network port as malicious peer
    let malicious_peer = PeerNetworkId::new(
        NetworkId::Vfn,
        attacker_peer_id
    );
    connect_to_vfn(&vfn, &malicious_peer, attacker_key);
    
    // 4. Verify: Check that malicious peer receives HighPriority
    let priority = get_peer_priority(
        vfn.base_config.clone(),
        vfn.peers_and_metadata.clone(),
        &malicious_peer
    );
    
    // BUG: Malicious peer incorrectly receives HighPriority
    assert_eq!(priority, PeerPriority::HighPriority);
    
    // 5. Exploit: VFN preferentially sends requests to malicious peer
    let request = create_state_sync_request();
    let selected_peers = vfn.choose_peers_for_request(&request);
    
    // Malicious peer is selected first due to HighPriority
    assert!(selected_peers.contains(&malicious_peer));
    
    // 6. Impact: Attacker delays response, degrading VFN performance
    delay_response(malicious_peer, Duration::from_secs(60));
    // VFN state sync is now blocked waiting for attacker's timeout
}
```

The PoC demonstrates that any peer connecting to the VFN network port receives `HighPriority` regardless of trust status, allowing malicious actors to monopolize state synchronization requests and degrade VFN performance.

### Citations

**File:** config/src/config/network_config.rs (L136-136)
```rust
        let mutual_authentication = network_id.is_validator_network();
```

**File:** network/framework/src/noise/handshake.rs (L417-422)
```rust
                            } else {
                                // We're a VFN or PFN. VFNs get no inbound connections on the vfn network
                                // (so the peer won't be a validator). Thus, we're on the public network
                                // so mark the peer as unknown.
                                Ok(PeerRole::Unknown)
                            }
```

**File:** state-sync/aptos-data-client/src/priority.rs (L75-82)
```rust
    // Handle the case that this node is a VFN
    if peers_and_metadata
        .get_registered_networks()
        .contains(&NetworkId::Vfn)
    {
        // VFNs should highly prioritize validators
        if peer_network_id.is_vfn_network() {
            return PeerPriority::HighPriority;
```

**File:** config/src/network_id.rs (L164-166)
```rust
    pub fn is_vfn_network(&self) -> bool {
        self == &NetworkId::Vfn
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L355-372)
```rust
        // Select peers by priority (starting with the highest priority first)
        let mut selected_peers = HashSet::new();
        for serviceable_peers in serviceable_peers_by_priorities {
            // Select peers by distance and latency
            let num_peers_remaining = num_peers_for_request.saturating_sub(selected_peers.len());
            let peers = self.choose_random_peers_by_distance_and_latency(
                serviceable_peers,
                num_peers_remaining,
            );

            // Add the peers to the entire set
            selected_peers.extend(peers);

            // If we have selected enough peers, return early
            if selected_peers.len() >= num_peers_for_request {
                return Ok(selected_peers);
            }
        }
```

**File:** network/framework/src/peer_manager/mod.rs (L352-389)
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
            }
```
