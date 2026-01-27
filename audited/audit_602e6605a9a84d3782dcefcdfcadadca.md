# Audit Report

## Title
Weak Distance-from-Validators Validation Allows Non-VFN Peers to Manipulate Network Priority Through Role Inference Bypass

## Summary
The peer monitoring service's distance validation logic contains two critical flaws: (1) the VFN network's MaybeMutual authentication mode incorrectly assigns `PeerRole::ValidatorFullNode` to any untrusted peer connecting on that network, allowing them to claim distance 1; and (2) for distances greater than 1, no role validation occurs at all, allowing any peer to claim artificially low distances. These issues enable malicious peers to gain preferential treatment in mempool, consensus observer, and state sync components.

## Finding Description

The vulnerability stems from a mismatch between role assignment and validation logic:

**Role Inference Issue:**

When validators accept connections on the VFN network, they use `HandshakeAuthMode::MaybeMutual` (because `mutual_authentication` is false for VFN networks). [1](#0-0) 

For untrusted peers in MaybeMutual mode, the handshake logic infers the role based on network context. When a validator receives a connection on the VFN network, it automatically assigns `PeerRole::ValidatorFullNode`: [2](#0-1) 

This inference assumes ANY peer connecting on the VFN network is a legitimate VFN, without verifying the peer is in the trusted_peers set.

**Validation Bypass:**

When validating distance responses, the client checks distance 1 requires VFN role and correct network: [3](#0-2) 

Since the attacker was incorrectly assigned VFN role during handshake, this validation passes. For distances greater than 1, only the maximum distance is checked with no role validation: [4](#0-3) 

**Exploitation in Priority Systems:**

The false distance values are then used by critical systems:

- **Mempool**: Prioritizes peers by validator distance for transaction forwarding [5](#0-4) 

- **Consensus Observer**: Sorts peers by distance for subscription selection, explicitly prioritizing distance over latency [6](#0-5) 

**Attack Scenario:**
1. Attacker discovers validator's VFN network endpoint
2. Attacker connects to validator on VFN network  
3. Validator incorrectly assigns `PeerRole::ValidatorFullNode` via role inference
4. Attacker responds to network info query with `distance_from_validators = 1`
5. Validation passes (role is VFN, network is correct)
6. Attacker gains priority in mempool forwarding and consensus observer subscription
7. Alternatively, any peer can claim distance > 1 without any role checks

## Impact Explanation

This vulnerability enables **Medium severity** attacks per Aptos bug bounty criteria:

1. **Consensus Observer Manipulation**: Malicious peers can become preferred subscription sources, potentially delivering stale or selectively filtered consensus data. While this doesn't break BFT consensus safety (validators still verify signatures), it can degrade liveness or enable eclipse attacks on observer nodes.

2. **Mempool Priority Hijacking**: Attackers gain preferential treatment in transaction forwarding, allowing them to:
   - Delay legitimate transaction propagation
   - Selectively censor transactions
   - Amplify their own malicious transactions

3. **State Sync Disruption**: Priority manipulation in state sync peer selection can slow down node synchronization.

The impact is classified as **state inconsistencies requiring intervention** rather than Critical because:
- Core consensus safety (BFT invariants) remains intact
- No direct fund theft or minting
- No permanent network partition
- Requires network-level intervention to identify and ban malicious peers

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Discover validator VFN network endpoints (may be publicly accessible or leaked through configuration)
- Standard networking capabilities to establish connections
- No cryptographic key compromise needed
- No validator insider access required

**Feasibility:**
- VFN network endpoints may be discoverable through DNS records, configuration leaks, or network scanning
- The attack requires only connecting to the network and responding to standard queries
- No sophisticated cryptographic attacks needed

**Detection Difficulty:**
- Hard to distinguish malicious peers from legitimate misconfigured VFNs
- Distance claims appear valid to all validation checks
- Requires manual investigation of peer behavior patterns

## Recommendation

**Immediate Fix:**

1. **Strict VFN Network Authentication**: Change VFN networks to use `HandshakeAuthMode::Mutual` requiring explicit trusted_peers configuration, or maintain a whitelist of authorized VFN public keys.

2. **Enhanced Distance Validation**: For ALL distance values, verify the peer's role is consistent with their claimed distance:

```rust
// In network_info.rs handle_monitoring_service_response
let is_valid_depth = match network_info_response.distance_from_validators {
    0 => {
        let peer_is_validator = peer_metadata.get_connection_metadata().role.is_validator();
        let peer_has_correct_network = /* existing check */;
        peer_is_validator && peer_has_correct_network
    },
    1 => {
        let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
        let peer_has_correct_network = /* existing check */;
        peer_is_vfn && peer_has_correct_network
    },
    distance_from_validators => {
        // NEW: Reject if peer has privileged role but claims distance > 1
        let peer_role = peer_metadata.get_connection_metadata().role;
        let role_consistent = !peer_role.is_validator() && !peer_role.is_vfn();
        role_consistent && (distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS)
    },
};
```

3. **Remove Automatic Role Inference**: In `handshake.rs`, remove the automatic VFN role assignment for untrusted peers on VFN network. Unknown peers should remain `PeerRole::Unknown`.

## Proof of Concept

```rust
// Simulated attack scenario demonstrating role inference bypass
#[tokio::test]
async fn test_vfn_role_inference_bypass() {
    // Setup: Create validator with VFN network using MaybeMutual auth
    let validator_keypair = generate_keypair();
    let validator_network_context = NetworkContext::new(
        RoleType::Validator,
        NetworkId::Vfn,  // VFN network
        validator_peer_id
    );
    
    // Create attacker (not in trusted_peers)
    let attacker_keypair = generate_keypair();
    let attacker_peer_id = derive_peer_id(&attacker_keypair);
    
    // Attacker connects to validator on VFN network
    // Validator uses MaybeMutual mode (mutual_authentication = false for VFN)
    let peers_and_metadata = PeersAndMetadata::new(&[NetworkId::Vfn]);
    let auth_mode = HandshakeAuthMode::MaybeMutual(peers_and_metadata.clone());
    
    // Perform handshake - validator will assign VFN role to attacker
    let (stream, peer_id, assigned_role) = validator_upgrader
        .upgrade_inbound(attacker_socket)
        .await
        .unwrap();
    
    // VULNERABILITY: Attacker incorrectly assigned PeerRole::ValidatorFullNode
    assert_eq!(assigned_role, PeerRole::ValidatorFullNode);
    
    // Attacker responds to network info query with distance = 1
    let malicious_response = NetworkInformationResponse {
        connected_peers: HashMap::new(),
        distance_from_validators: 1,  // Claiming VFN status
    };
    
    // Validation passes because role was incorrectly assigned
    let mut network_info_state = NetworkInfoState::new(validator_config, TimeService::mock());
    network_info_state.handle_monitoring_service_response(
        &peer_network_id,
        peer_metadata,  // Contains role = ValidatorFullNode
        request,
        PeerMonitoringServiceResponse::NetworkInformation(malicious_response),
        0.0
    );
    
    // EXPLOIT: Attacker's false distance is now stored and used for priority
    let stored_distance = network_info_state
        .get_latest_network_info_response()
        .unwrap()
        .distance_from_validators;
    assert_eq!(stored_distance, 1);
    
    // Attacker now has high priority in mempool and consensus observer
}
```

**Notes:**

While the specific question asks about "non-validators claiming validator status" (distance 0), the actual exploitable vulnerability allows:
1. Non-VFNs to claim VFN status (distance 1) via incorrect role inference
2. Any peer to claim arbitrary distances > 1 without role validation

The lack of role validation for distance > 1 is arguably the more widespread issue, as it affects all peer types on all networks. The VFN role inference issue is more targeted but potentially more impactful given VFNs' privileged status in the network topology.

### Citations

**File:** config/src/config/network_config.rs (L136-136)
```rust
        let mutual_authentication = network_id.is_validator_network();
```

**File:** network/framework/src/noise/handshake.rs (L407-410)
```rust
                            if self.network_context.role().is_validator() {
                                if network_id.is_vfn_network() {
                                    // Inbound connections to validators on the VFN network must be VFNs
                                    Ok(PeerRole::ValidatorFullNode)
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L128-135)
```rust
            1 => {
                // Verify the peer is a VFN and has the correct network id
                let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
                let peer_has_correct_network = match self.base_config.role {
                    RoleType::Validator => network_id.is_vfn_network(), // We're a validator
                    RoleType::FullNode => network_id.is_public_network(), // We're a VFN or PFN
                };
                peer_is_vfn && peer_has_correct_network
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L137-140)
```rust
            distance_from_validators => {
                // The distance must be less than or equal to the max
                distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS
            },
```

**File:** mempool/src/shared_mempool/priority.rs (L103-109)
```rust
        // Otherwise, compare by peer distance from the validators.
        // This avoids badly configured/connected peers (e.g., broken VN-VFN connections).
        let distance_ordering =
            compare_validator_distance(monitoring_metadata_a, monitoring_metadata_b);
        if !distance_ordering.is_eq() {
            return distance_ordering; // Only return if it's not equal
        }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L275-282)
```rust
/// Sorts the peers by subscription optimality (in descending order of
/// optimality). This requires: (i) sorting the peers by distance from the
/// validator set and ping latency (lower values are more optimal); and (ii)
/// filtering out peers that don't support consensus observer.
///
/// Note: we prioritize distance over latency as we want to avoid close
/// but not up-to-date peers. If peers don't have sufficient metadata
/// for sorting, they are given a lower priority.
```
