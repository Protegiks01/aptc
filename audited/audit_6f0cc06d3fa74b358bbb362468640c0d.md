# Audit Report

## Title
Consensus Observer Accepts Peers Without Network Topology Data, Enabling Potential Eclipse Attacks During Network Disruption

## Summary
The consensus observer peer selection logic defaults peers with missing distance data to `MAX_DISTANCE_FROM_VALIDATORS` (100) rather than excluding them, allowing selection of peers with unknown network positions. When all available peers lack distance information, the system will still subscribe to them, creating a window for eclipse attacks during peer monitoring service disruptions or network startup conditions.

## Finding Description

The `sort_peers_by_subscription_optimality` function in the consensus observer subscription utilities uses fallback values when peer metadata is unavailable: [1](#0-0) 

When distance is `None`, the code defaults to `MAX_DISTANCE_FROM_VALIDATORS` (100), representing disconnected or unknown peers: [2](#0-1) 

This contrasts with the state-sync data client, which **excludes** peers lacking complete metadata: [3](#0-2) 

**Attack Scenario:**

1. **Attacker disrupts peer monitoring service** or exploits network startup conditions where distance data is unavailable
2. **All available peers receive `distance = 100`** due to the fallback logic
3. **Consensus observer still selects peers** based solely on latency, unable to distinguish validators (distance 0) from malicious nodes (distance unknown)
4. **Attacker-controlled low-latency nodes** get selected as subscription targets
5. **Malicious peers can:**
   - Delay forwarding consensus blocks (DoS)
   - Selectively withhold transactions (censorship)
   - Force observer into fallback mode repeatedly
   - Waste node resources on suboptimal connections

The test suite confirms this is intentional behavior, not an oversight: [4](#0-3) 

## Impact Explanation

While cryptographic signature verification prevents accepting invalid consensus data, this vulnerability enables **availability and liveness attacks** against consensus observers:

- **Targeted Service Degradation**: Observers connecting to malicious peers experience delayed synchronization
- **Resource Exhaustion**: Node wastes bandwidth and compute on far-away or unresponsive peers  
- **Fallback Mode Abuse**: Repeated triggering of state-sync fallback disrupts normal operation
- **Network Partition Risk**: During actual network issues, observers cannot distinguish helpful peers from attackers

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention" - observers may fall significantly behind honest nodes, requiring manual intervention or extended fallback periods.

## Likelihood Explanation

**Moderate to High Likelihood:**

- **Network Startup**: All peers naturally lack distance data when joining a new network
- **Peer Monitoring Failures**: Service disruptions or bugs can cause widespread loss of distance metadata
- **Eclipse Attack Setup**: Attacker needs low-latency infrastructure and ability to influence peer discovery
- **No Authentication Required**: Any peer can be added to the network and selected if distance data is unavailable

The vulnerability is **easier to exploit** than typical consensus attacks because it doesn't require:
- Validator stake or insider access
- Cryptographic capabilities
- Protocol-level vulnerabilities

## Recommendation

Implement stricter peer selection criteria aligned with state-sync's approach:

**Option 1: Exclude peers without distance data**
```rust
// In sort_peers_by_subscription_optimality
let distance = get_distance_for_peer(peer_network_id, peer_metadata);
let latency = get_latency_for_peer(peer_network_id, peer_metadata);

// Only include peers with complete metadata
if let (Some(distance), Some(latency)) = (distance, latency) {
    peers_and_latencies_by_distance
        .entry(distance)
        .or_insert_with(Vec::new)
        .push((*peer_network_id, OrderedFloat(latency)));
} else {
    warn!(/* Log peer exclusion */);
}
```

**Option 2: Require minimum threshold of valid peers**
```rust
// Before subscription, verify enough peers have valid distance data
let peers_with_valid_distance = connected_peers
    .iter()
    .filter(|(_, metadata)| get_distance_for_peer(peer, metadata).is_some())
    .count();
    
if peers_with_valid_distance < config.min_peers_with_distance {
    // Enter fallback mode instead of subscribing to unknown peers
    return Err(Error::InsufficientPeerMetadata);
}
```

**Option 3: Add configuration flag**
```rust
pub struct ConsensusObserverConfig {
    // ...
    pub require_peer_distance_data: bool, // Default: true for production
}
```

## Proof of Concept

```rust
#[test]
fn test_peers_without_distance_enable_eclipse_attack() {
    use aptos_config::network_id::NetworkId;
    use std::collections::HashMap;
    
    // Scenario: All peers lack distance data (network startup or monitoring failure)
    let mut peers_and_metadata = HashMap::new();
    
    // Add legitimate validator with missing distance data
    let (validator_peer, validator_metadata) = create_peer_and_metadata(
        Some(0.1), // Low latency
        None,      // No distance data!
        true,      // Supports consensus observer
    );
    peers_and_metadata.insert(validator_peer, validator_metadata);
    
    // Add attacker-controlled peer with missing distance data but even lower latency
    let (attacker_peer, attacker_metadata) = create_peer_and_metadata(
        Some(0.05), // Even lower latency
        None,       // No distance data!
        true,       // Supports consensus observer
    );
    peers_and_metadata.insert(attacker_peer, attacker_metadata);
    
    // Sort peers - both have distance=100, so attacker wins due to lower latency
    let sorted_peers = sort_peers_by_subscription_optimality(&peers_and_metadata);
    
    // VULNERABILITY: Attacker peer is selected first despite unknown network position
    assert_eq!(sorted_peers[0], attacker_peer);
    assert_eq!(sorted_peers.len(), 2);
    
    // In production, this means:
    // 1. Consensus observer subscribes to attacker first
    // 2. Attacker can delay/drop blocks
    // 3. Observer falls behind or enters fallback mode
    // 4. No way to distinguish attacker from legitimate validator
}
```

**Expected Behavior**: Peers without distance data should either be excluded or require explicit operator override, preventing automatic selection during metadata unavailability windows.

**Actual Behavior**: All peers without distance data are included with `distance=100` and selected based on latency alone, creating eclipse attack opportunities.

## Notes

This vulnerability demonstrates a defense-in-depth failure. While signature verification prevents accepting invalid data, the lack of topology-aware peer selection allows attackers to position themselves as the primary data source, enabling DoS and censorship attacks that degrade consensus observer availability without violating cryptographic invariants.

The inconsistency between state-sync (which requires distance data) and consensus observer (which uses fallback values) suggests the latter's design may not have fully considered eclipse attack scenarios during peer monitoring service failures.

### Citations

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L296-312)
```rust
        // Get the distance and latency for the peer
        let distance = get_distance_for_peer(peer_network_id, peer_metadata);
        let latency = get_latency_for_peer(peer_network_id, peer_metadata);

        // If the distance is not found, use the maximum distance
        let distance =
            distance.unwrap_or(aptos_peer_monitoring_service_types::MAX_DISTANCE_FROM_VALIDATORS);

        // If the latency is not found, use a large latency
        let latency = latency.unwrap_or(MAX_PING_LATENCY_SECS);

        // Add the peer and latency to the distance group
        peers_and_latencies_by_distance
            .entry(distance)
            .or_insert_with(Vec::new)
            .push((*peer_network_id, OrderedFloat(latency)));
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L748-753)
```rust
        // Create a list of peers with empty metadata
        let peers_and_metadata = create_peers_and_metadata(true, true, true, 10);

        // Sort the peers and verify the results
        let sorted_peers = sort_peers_by_subscription_optimality(&peers_and_metadata);
        assert_eq!(sorted_peers.len(), 10);
```

**File:** peer-monitoring-service/types/src/lib.rs (L22-22)
```rust
pub const MAX_DISTANCE_FROM_VALIDATORS: u64 = 100; // Nodes that aren't connected to the network
```

**File:** state-sync/aptos-data-client/src/utils.rs (L231-260)
```rust
fn get_distance_and_latency_for_peer(
    peers_and_metadata: &Arc<PeersAndMetadata>,
    peer: PeerNetworkId,
) -> Option<(u64, f64)> {
    if let Some(peer_metadata) = get_metadata_for_peer(peers_and_metadata, peer) {
        // Get the distance and latency for the peer
        let peer_monitoring_metadata = peer_metadata.get_peer_monitoring_metadata();
        let distance = peer_monitoring_metadata
            .latest_network_info_response
            .as_ref()
            .map(|response| response.distance_from_validators);
        let latency = peer_monitoring_metadata.average_ping_latency_secs;

        // Return the distance and latency if both were found
        if let (Some(distance), Some(latency)) = (distance, latency) {
            return Some((distance, latency));
        }
    }

    // Otherwise, no distance and latency was found
    log_warning_with_sample(
        LogSchema::new(LogEntry::PeerStates)
            .event(LogEvent::PeerSelectionError)
            .message(&format!(
                "Unable to get distance and latency for peer! Peer: {:?}",
                peer
            )),
    );
    None
}
```
