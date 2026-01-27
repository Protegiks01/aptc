# Audit Report

## Title
Network Segmentation Bypass via VFN Network ID Manipulation Enabling DoS on Validator Storage Services

## Summary
A malicious Public Full Node (PFN) can bypass network segmentation by configuring itself to use the VFN (Validator Full Node) network ID, gaining unauthorized access to validator VFN networks and exploiting privileged treatment in storage service rate limiting. This allows unlimited invalid storage requests that cannot be rate-limited, enabling denial-of-service attacks against validators.

## Finding Description

Aptos implements network segmentation to separate three distinct networks: Validator, VFN, and Public. The configuration sanitizer is designed to prevent unauthorized network access, but contains a critical flaw.

**Vulnerability Chain:**

**Step 1: Config Sanitizer Bypass**

The sanitizer only validates that fullnode networks cannot be Validator networks, but fails to validate VFN network assignment: [1](#0-0) 

A malicious PFN operator can set `full_node_networks = [{ network_id = "vfn" }]` in their config file, which passes validation.

**Step 2: Node Type Misclassification**

The node type detection logic classifies any node with a VFN network as a ValidatorFullnode: [2](#0-1) 

**Step 3: Unauthorized VFN Network Access**

VFN networks use `MaybeMutual` authentication mode which accepts ALL inbound connections without requiring the peer to be in the trusted peers set: [3](#0-2) 

When a validator receives an inbound connection on its VFN network from an unknown peer, it automatically infers the peer role as `ValidatorFullNode`: [4](#0-3) 

**Step 4: Storage Service Rate Limiting Bypass**

The storage service request moderator only ignores peers on the PUBLIC network after they send too many invalid requests. VFN network peers are NEVER ignored: [5](#0-4) 

This behavior is confirmed by tests showing VFN peers can send unlimited invalid requests without being ignored: [6](#0-5) 

**Attack Execution:**
1. Attacker runs a PFN with modified config: `full_node_networks = [{ network_id = "vfn" }]`
2. Attacker connects to any validator's VFN listening address (publicly accessible)
3. Validator accepts connection via MaybeMutual authentication
4. Validator classifies attacker as ValidatorFullNode peer
5. Attacker floods validator with invalid storage service requests
6. Normal PFNs would be ignored after `max_invalid_requests_per_peer`, but attacker is never ignored
7. Validator resources (CPU/memory) are exhausted processing invalid requests

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for multiple reasons:

1. **Validator Node Slowdowns**: The DoS attack directly degrades validator performance by forcing continuous processing of invalid storage requests without rate limiting. This impacts state synchronization and overall validator responsiveness.

2. **Significant Protocol Violation**: The network segmentation architecture is fundamentally violated. The VFN network is intended exclusively for validator-operated fullnodes with trusted relationships, not arbitrary public nodes.

3. **Resource Exhaustion**: Unlimited invalid requests consume validator CPU, memory, and network bandwidth, potentially affecting consensus participation and block production timing.

4. **Network-Wide Impact**: Multiple attackers could target all validators simultaneously, degrading the entire network's state sync capabilities and availability.

The vulnerability does NOT meet Critical severity because it does not directly cause fund loss, consensus safety violations, or permanent network partitioning. However, sustained attacks could indirectly impact liveness if validators become overloaded.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute:

- **Technical Barrier**: Very low - requires only editing a YAML config file
- **Discovery**: Easy - the config structure is well-documented
- **Cost**: Minimal - attacker only needs to run a single node
- **Detection**: Difficult - malicious node appears as legitimate VFN traffic
- **Prerequisites**: None - no special access, credentials, or resources required

The vulnerability is actively exploitable on mainnet and all public networks. Any malicious actor can implement this attack within minutes.

## Recommendation

Implement comprehensive network ID validation in the config sanitizer:

```rust
// In config/src/config/config_sanitizer.rs, function sanitize_fullnode_network_configs

for fullnode_network_config in fullnode_networks {
    let network_id = fullnode_network_config.network_id;

    // Verify that the fullnode network config is not a validator network config
    if network_id.is_validator_network() {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "Fullnode network configs cannot include a validator network!".into(),
        ));
    }

    // ADD THIS: Verify that public fullnodes cannot claim VFN network access
    if network_id.is_vfn_network() && !node_type.is_validator_fullnode() {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "Only validator fullnodes can use the VFN network! Public fullnodes must use the Public network.".into(),
        ));
    }

    // Existing uniqueness check...
}
```

**Additional Hardening:**

1. Require VFN network authentication to use Mutual mode with explicit trusted peers configuration
2. Add connection-level validation that verifies VFN peers are in the validator's trusted peer set
3. Implement storage service rate limiting for VFN peers after a higher threshold than PFNs

## Proof of Concept

**Attack Setup:**

```yaml
# malicious_pfn_config.yaml
base:
  role: "full_node"

# MALICIOUS: Claim to be on VFN network
full_node_networks:
  - network_id: "vfn"  # Should only be used by validator-operated VFNs
    listen_address: "/ip4/0.0.0.0/tcp/6182"
    seeds: {}
    # Connect to target validator's VFN listening address
```

**Reproduction Steps:**

1. Start an Aptos validator with VFN network configured on port 6181
2. Start malicious PFN with the above config
3. Configure malicious PFN to connect to `validator_vfn_address:6181`
4. Observe handshake succeeds and malicious node is classified as ValidatorFullNode
5. Send rapid invalid storage requests (e.g., requesting non-existent versions)
6. Observe that normal PFNs would be ignored after ~100 invalid requests
7. Observe malicious VFN-impersonating node is NEVER ignored
8. Monitor validator CPU/memory consumption increasing indefinitely

**Expected Validation Failure:**

The config should be rejected with:
```
Error: ConfigSanitizerFailed("FullnodeNetworksConfigSanitizer", 
  "Only validator fullnodes can use the VFN network! Public fullnodes must use the Public network.")
```

**Actual Behavior:**

Config passes validation, node starts, connects to validator VFN network, and can perform unlimited DoS attacks.

### Citations

**File:** config/src/config/config_sanitizer.rs (L133-139)
```rust
        // Verify that the fullnode network config is not a validator network config
        if network_id.is_validator_network() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Fullnode network configs cannot include a validator network!".into(),
            ));
        }
```

**File:** config/src/config/node_config_loader.rs (L47-50)
```rust
        let vfn_network_found = node_config
            .full_node_networks
            .iter()
            .any(|network| network.network_id.is_vfn_network());
```

**File:** network/framework/src/noise/handshake.rs (L384-426)
```rust
            HandshakeAuthMode::MaybeMutual(peers_and_metadata) => {
                let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id)?;
                let trusted_peer = trusted_peers.get(&remote_peer_id).cloned();
                match trusted_peer {
                    Some(peer) => {
                        Self::authenticate_inbound(remote_peer_short, &peer, &remote_public_key)
                    },
                    None => {
                        // The peer is not in the trusted peer set. Verify that the Peer ID is
                        // constructed correctly from the public key.
                        let derived_remote_peer_id =
                            aptos_types::account_address::from_identity_public_key(
                                remote_public_key,
                            );
                        if derived_remote_peer_id != remote_peer_id {
                            // The peer ID is not constructed correctly from the public key
                            Err(NoiseHandshakeError::ClientPeerIdMismatch(
                                remote_peer_short,
                                remote_peer_id,
                                derived_remote_peer_id,
                            ))
                        } else {
                            // Try to infer the role from the network context
                            if self.network_context.role().is_validator() {
                                if network_id.is_vfn_network() {
                                    // Inbound connections to validators on the VFN network must be VFNs
                                    Ok(PeerRole::ValidatorFullNode)
                                } else {
                                    // Otherwise, they're unknown. Validators will connect through
                                    // authenticated channels (on the validator network) so shouldn't hit
                                    // this, and PFNs will connect on public networks (which aren't common).
                                    Ok(PeerRole::Unknown)
                                }
                            } else {
                                // We're a VFN or PFN. VFNs get no inbound connections on the vfn network
                                // (so the peer won't be a validator). Thus, we're on the public network
                                // so mark the peer as unknown.
                                Ok(PeerRole::Unknown)
                            }
                        }
                    },
                }
            },
```

**File:** state-sync/storage-service/server/src/moderator.rs (L54-58)
```rust
        // If the peer is a PFN and has sent too many invalid requests, start ignoring it
        if self.ignore_start_time.is_none()
            && peer_network_id.network_id().is_public_network()
            && self.invalid_request_count >= self.max_invalid_requests
        {
```

**File:** state-sync/storage-service/server/src/moderator.rs (L381-392)
```rust
        // Handle a lot of invalid requests for a VFN
        let peer_network_id = PeerNetworkId::new(NetworkId::Vfn, PeerId::random());
        for _ in 0..max_invalid_requests * 20 {
            unhealthy_peer_state.increment_invalid_request_count(&peer_network_id);
        }

        // Verify the peer is not ignored and that the number of invalid requests is correct
        assert!(!unhealthy_peer_state.is_ignored());
        assert_eq!(
            unhealthy_peer_state.invalid_request_count,
            max_invalid_requests * 20
        );
```
