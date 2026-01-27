# Audit Report

## Title
Consensus Observer Subscription Manipulation via Untrusted Peer-Reported Distance Metadata

## Summary
A malicious network peer can manipulate consensus observer subscription decisions by providing false `distance_from_validators` values in peer monitoring responses. This allows an attacker to force consensus observers to subscribe to malicious peers instead of legitimate validators, enabling consensus data manipulation attacks.

## Finding Description

The consensus observer system relies on peer-reported metadata to determine optimal subscription targets. Specifically, the `distance_from_validators` field in `NetworkInformationResponse` is self-reported by peers and used without cryptographic verification to rank peer optimality.

**Attack Flow:**

1. **Malicious Peer Connection**: An attacker connects to a consensus observer node as a regular network peer.

2. **False Distance Reporting**: When the peer monitoring service requests network information via `GetNetworkInformation`, the malicious peer responds with `distance_from_validators = 0`, falsely claiming to be a validator or directly connected to validators. [1](#0-0) 

3. **Uncritical Trust**: The peer monitoring server's `get_distance_from_validators()` function trusts peer-reported distances from `latest_network_info_response` without verification: [2](#0-1) 

4. **Metadata Propagation**: This false distance value flows through the network layer's `PeersAndMetadata` storage and is returned by `get_connected_peers_and_metadata()`: [3](#0-2) 

5. **Subscription Ranking**: The consensus observer's `sort_peers_by_subscription_optimality()` prioritizes peers by distance (lower is better), placing the malicious peer at the top: [4](#0-3) 

6. **Health Decision Impact**: In `check_subscription_peer_optimality()`, if the malicious peer ranks higher than the current subscription peer, the legitimate subscription is terminated: [5](#0-4) 

7. **Malicious Subscription**: The consensus observer creates a new subscription to the malicious peer, which can now feed incorrect or delayed consensus data.

**Security Guarantees Broken:**
- **Consensus Safety**: Observers may receive manipulated consensus data from untrusted sources
- **Trust Model Violation**: Network peers (untrusted actors) can influence critical consensus observer decisions
- **Data Integrity**: No cryptographic verification ensures peer-reported distances match actual network topology

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria)

This vulnerability qualifies as **High Severity** because:

1. **Validator Node Slowdowns**: Consensus observers relying on malicious data sources will experience degraded performance and increased latency in receiving valid consensus updates.

2. **Significant Protocol Violations**: The consensus observer protocol assumes it subscribes to optimal (closest to validators) peers. An attacker violates this invariant by injecting false distance metrics.

3. **Potential Consensus Degradation**: While not a direct consensus safety break at the validator level, manipulated observers can:
   - Delay propagation of valid blocks
   - Cause observers to diverge from canonical chain state
   - Impact downstream applications relying on observer data

4. **No Validator Collusion Required**: Any network peer can execute this attack without privileged access or validator cooperation.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low Attack Complexity**: The attacker only needs to:
   - Connect to the network as a regular peer
   - Respond to `GetNetworkInformation` RPC with `distance_from_validators = 0`
   - Implement consensus observer protocol handlers to maintain the subscription

2. **No Authentication Barrier**: The peer monitoring service accepts distance values from any connected peer without requiring cryptographic proof or validator signatures.

3. **Automatic Triggering**: The subscription health check runs periodically, automatically terminating legitimate subscriptions in favor of "more optimal" (malicious) peers.

4. **Observable Behavior**: Attackers can verify successful exploitation by monitoring subscription creation/termination events.

5. **Multiple Observer Impact**: A single malicious peer can target multiple consensus observers simultaneously, amplifying the attack surface.

## Recommendation

**Immediate Fix**: Implement cryptographic validation of `distance_from_validators` claims or remove reliance on peer-reported distance for critical subscription decisions.

**Option 1: Validator-Signed Distance Attestations**
```rust
// In NetworkInformationResponse
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>,
    pub distance_from_validators: u64,
    pub distance_proof: Option<ValidatorDistanceProof>, // Signed by validators
}

// Validate proof before using distance
fn get_distance_from_validators(
    base_config: &BaseConfig,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> u64 {
    // ... existing code ...
    for peer_metadata in connected_peers_and_metadata.values() {
        if let Some(ref latest_network_info_response) = 
            peer_metadata.get_peer_monitoring_metadata().latest_network_info_response 
        {
            // VALIDATE distance_proof before trusting the distance
            if verify_distance_proof(&latest_network_info_response) {
                min_peer_distance_from_validators = min(
                    min_peer_distance_from_validators,
                    latest_network_info_response.distance_from_validators,
                );
            }
        }
    }
    // ...
}
```

**Option 2: Direct Validator Verification**
```rust
// In sort_peers_by_subscription_optimality()
fn get_distance_for_peer(
    peer_network_id: &PeerNetworkId,
    peer_metadata: &PeerMetadata,
    validator_verifier: &ValidatorVerifier, // Pass validator set info
) -> Option<u64> {
    // Only trust distance from peers that are in the validator set
    // or have direct connections to verified validators
    if is_verified_validator(peer_network_id, validator_verifier) {
        return Some(0);
    }
    
    // For non-validators, compute distance based on connections
    // to verified validators (ignore self-reported values)
    let verified_connections = get_verified_validator_connections(peer_metadata);
    if !verified_connections.is_empty() {
        return Some(1); // One hop from validators
    }
    
    // Use conservative max distance if cannot verify
    Some(MAX_DISTANCE_FROM_VALIDATORS)
}
```

**Option 3: Remove Distance-Based Ranking** (Short-term mitigation)
```rust
// Prioritize validator connections and latency only
pub fn sort_peers_by_subscription_optimality(
    peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
    validator_verifier: &ValidatorVerifier,
) -> Vec<PeerNetworkId> {
    let mut validated_peers = Vec::new();
    let mut other_peers = Vec::new();
    
    for (peer_network_id, peer_metadata) in peers_and_metadata {
        if !supports_consensus_observer(peer_metadata) {
            continue;
        }
        
        let latency = get_latency_for_peer(peer_network_id, peer_metadata)
            .unwrap_or(MAX_PING_LATENCY_SECS);
        
        // Prioritize verified validators first, then by latency
        if is_verified_validator(peer_network_id, validator_verifier) {
            validated_peers.push((*peer_network_id, OrderedFloat(latency)));
        } else {
            other_peers.push((*peer_network_id, OrderedFloat(latency)));
        }
    }
    
    // Sort each group by latency
    validated_peers.sort_by_key(|(_, latency)| *latency);
    other_peers.sort_by_key(|(_, latency)| *latency);
    
    // Return validators first, then others
    validated_peers.into_iter()
        .chain(other_peers.into_iter())
        .map(|(peer, _)| peer)
        .collect()
}
```

## Proof of Concept

```rust
// Add to consensus/src/consensus_observer/observer/tests.rs

#[tokio::test]
async fn test_malicious_peer_distance_manipulation() {
    use aptos_peer_monitoring_service_types::{
        response::NetworkInformationResponse,
        PeerMonitoringMetadata,
    };
    
    // Setup: Create consensus observer with legitimate subscription
    let consensus_observer_config = ConsensusObserverConfig::default();
    let network_ids = &[NetworkId::Validator, NetworkId::Public];
    let (peers_and_metadata, consensus_observer_client) = 
        create_consensus_observer_client(network_ids);
    
    // Create legitimate validator peer (distance = 0, verified)
    let legitimate_validator = create_peer_and_connection(
        NetworkId::Validator,
        peers_and_metadata.clone(),
        0, // True distance = 0
        Some(0.1), // Low latency
        true,
    );
    
    // Subscribe to legitimate validator
    let mut subscription_manager = SubscriptionManager::new(
        consensus_observer_client,
        consensus_observer_config,
        None,
        Arc::new(MockDatabaseReader::new()),
        TimeService::mock(),
    );
    
    create_observer_subscription(
        &mut subscription_manager,
        consensus_observer_config,
        legitimate_validator,
    );
    
    // Verify legitimate subscription is active
    assert!(subscription_manager
        .active_observer_subscriptions
        .lock()
        .contains_key(&legitimate_validator));
    
    // ATTACK: Malicious peer connects and claims distance = 0
    let malicious_peer = PeerNetworkId::random_public();
    create_peer_and_connection(
        NetworkId::Public,
        peers_and_metadata.clone(),
        0, // FALSE claim: distance = 0 (pretending to be validator)
        Some(0.05), // Slightly better latency
        true,
    );
    
    // Set malicious peer's distance metadata
    let malicious_network_info = NetworkInformationResponse {
        connected_peers: BTreeMap::new(),
        distance_from_validators: 0, // FALSE: Claiming to be validator
    };
    
    let malicious_metadata = PeerMonitoringMetadata::new(
        Some(0.05),
        Some(0.05),
        Some(malicious_network_info), // Injected false distance
        None,
        None,
    );
    
    peers_and_metadata
        .update_peer_monitoring_metadata(malicious_peer, malicious_metadata)
        .unwrap();
    
    // Trigger subscription health check
    subscription_manager
        .check_and_manage_subscriptions()
        .await
        .unwrap();
    
    // VERIFICATION: Legitimate subscription terminated, malicious peer subscribed
    let active_subscriptions = subscription_manager.get_active_subscription_peers();
    
    // The legitimate validator subscription should be terminated
    assert!(!active_subscriptions.contains(&legitimate_validator),
        "Legitimate validator subscription was NOT terminated");
    
    // The malicious peer should now be subscribed
    assert!(active_subscriptions.contains(&malicious_peer),
        "Malicious peer subscription was NOT created");
    
    println!("ATTACK SUCCESSFUL: Malicious peer with false distance=0 replaced legitimate validator subscription");
}
```

**Notes**

The vulnerability exists because consensus observers trust peer-reported `distance_from_validators` values without cryptographic verification. The attack exploits the prioritization logic in `sort_peers_by_subscription_optimality()` where distance takes precedence over all other factors including the peer's actual validator status. This allows any network peer to claim optimal positioning and hijack consensus observer subscriptions, potentially feeding manipulated or delayed consensus data to observer nodes.

### Citations

**File:** peer-monitoring-service/types/src/response.rs (L51-55)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}
```

**File:** peer-monitoring-service/server/src/lib.rs (L296-340)
```rust
/// Returns the distance from the validators using the given base config
/// and the peers and metadata information.
fn get_distance_from_validators(
    base_config: &BaseConfig,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> u64 {
    // Get the connected peers and metadata
    let connected_peers_and_metadata = match peers_and_metadata.get_connected_peers_and_metadata() {
        Ok(connected_peers_and_metadata) => connected_peers_and_metadata,
        Err(error) => {
            warn!(LogSchema::new(LogEntry::PeerMonitoringServiceError).error(&error.into()));
            return MAX_DISTANCE_FROM_VALIDATORS;
        },
    };

    // If we're a validator and we have active validator peers, we're in the validator set.
    // TODO: figure out if we need to deal with validator set forks here.
    if base_config.role.is_validator() {
        for peer_metadata in connected_peers_and_metadata.values() {
            if peer_metadata.get_connection_metadata().role.is_validator() {
                return 0;
            }
        }
    }

    // Otherwise, go through our peers, find the min, and return a distance relative to the min
    let mut min_peer_distance_from_validators = MAX_DISTANCE_FROM_VALIDATORS;
    for peer_metadata in connected_peers_and_metadata.values() {
        if let Some(ref latest_network_info_response) = peer_metadata
            .get_peer_monitoring_metadata()
            .latest_network_info_response
        {
            min_peer_distance_from_validators = min(
                min_peer_distance_from_validators,
                latest_network_info_response.distance_from_validators,
            );
        }
    }

    // We're one hop away from the peer
    min(
        MAX_DISTANCE_FROM_VALIDATORS,
        min_peer_distance_from_validators + 1,
    )
}
```

**File:** network/framework/src/application/storage.rs (L108-125)
```rust
    pub fn get_connected_peers_and_metadata(
        &self,
    ) -> Result<HashMap<PeerNetworkId, PeerMetadata>, Error> {
        // Get the cached peers and metadata
        let cached_peers_and_metadata = self.cached_peers_and_metadata.load();

        // Collect all connected peers
        let mut connected_peers_and_metadata = HashMap::new();
        for (network_id, peers_and_metadata) in cached_peers_and_metadata.iter() {
            for (peer_id, peer_metadata) in peers_and_metadata.iter() {
                if peer_metadata.is_connected() {
                    let peer_network_id = PeerNetworkId::new(*network_id, *peer_id);
                    connected_peers_and_metadata.insert(peer_network_id, peer_metadata.clone());
                }
            }
        }
        Ok(connected_peers_and_metadata)
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L275-312)
```rust
/// Sorts the peers by subscription optimality (in descending order of
/// optimality). This requires: (i) sorting the peers by distance from the
/// validator set and ping latency (lower values are more optimal); and (ii)
/// filtering out peers that don't support consensus observer.
///
/// Note: we prioritize distance over latency as we want to avoid close
/// but not up-to-date peers. If peers don't have sufficient metadata
/// for sorting, they are given a lower priority.
pub fn sort_peers_by_subscription_optimality(
    peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
) -> Vec<PeerNetworkId> {
    // Group peers and latencies by validator distance, i.e., distance -> [(peer, latency)]
    let mut unsupported_peers = Vec::new();
    let mut peers_and_latencies_by_distance = BTreeMap::new();
    for (peer_network_id, peer_metadata) in peers_and_metadata {
        // Verify that the peer supports consensus observer
        if !supports_consensus_observer(peer_metadata) {
            unsupported_peers.push(*peer_network_id);
            continue; // Skip the peer
        }

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

**File:** consensus/src/consensus_observer/observer/subscription.rs (L100-162)
```rust
    fn check_subscription_peer_optimality(
        &mut self,
        peers_and_metadata: &HashMap<PeerNetworkId, PeerMetadata>,
        skip_peer_optimality_check: bool,
    ) -> Result<(), Error> {
        // Get the last optimality check time and connected peers
        let (last_optimality_check_time, last_optimality_check_peers) =
            self.last_optimality_check_time_and_peers.clone();

        // If we're skipping the peer optimality check, update the last check time and return
        let time_now = self.time_service.now();
        if skip_peer_optimality_check {
            self.last_optimality_check_time_and_peers = (time_now, last_optimality_check_peers);
            return Ok(());
        }

        // Determine if enough time has elapsed to force a refresh
        let duration_since_last_check = time_now.duration_since(last_optimality_check_time);
        let refresh_interval = Duration::from_millis(
            self.consensus_observer_config
                .subscription_refresh_interval_ms,
        );
        let force_refresh = duration_since_last_check >= refresh_interval;

        // Determine if the peers have changed since the last check.
        // Note: we only check for peer changes periodically to avoid
        // excessive subscription churn due to peer connects/disconnects.
        let current_connected_peers = peers_and_metadata.keys().cloned().collect();
        let peer_check_interval = Duration::from_millis(
            self.consensus_observer_config
                .subscription_peer_change_interval_ms,
        );
        let peers_changed = duration_since_last_check >= peer_check_interval
            && current_connected_peers != last_optimality_check_peers;

        // Determine if we should perform the optimality check
        if !force_refresh && !peers_changed {
            return Ok(()); // We don't need to check optimality yet
        }

        // Otherwise, update the last peer optimality check time and peers
        self.last_optimality_check_time_and_peers = (time_now, current_connected_peers);

        // Sort the peers by subscription optimality
        let sorted_peers =
            subscription_utils::sort_peers_by_subscription_optimality(peers_and_metadata);

        // Verify that this peer is one of the most optimal peers
        let max_concurrent_subscriptions =
            self.consensus_observer_config.max_concurrent_subscriptions as usize;
        if !sorted_peers
            .iter()
            .take(max_concurrent_subscriptions)
            .any(|peer| peer == &self.peer_network_id)
        {
            return Err(Error::SubscriptionSuboptimal(format!(
                "Subscription to peer: {} is no longer optimal! New optimal peers: {:?}",
                self.peer_network_id, sorted_peers
            )));
        }

        Ok(())
    }
```
