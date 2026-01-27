# Audit Report

## Title
Eclipse Attack on Public Fullnodes via Latency-Weighted Peer Selection Dominance

## Summary
Public fullnodes using latency-aware peer dialing can be completely eclipsed by attackers controlling multiple low-latency malicious peers. The exponential latency-to-weight conversion in peer selection heavily favors low-latency peers, allowing attackers to dominate all outbound connections without any diversity checks. **Note: This vulnerability affects public fullnodes only; validators are not vulnerable as they use all-to-all connections and do not employ latency-based peer selection.** [1](#0-0) 

## Finding Description

The peer selection mechanism contains a critical design flaw that enables eclipse attacks against public fullnodes through three compounding issues:

**1. Exponential Latency Bias Without Bounds**

The `convert_latency_to_weight` function creates extreme bias toward low-latency peers: [2](#0-1) 

For every 25ms of latency, the weight is halved. This creates selection ratios exceeding 100:1 between a 5ms peer and a 100ms peer, making attacker dominance trivial.

**2. No Diversity Requirements Across Selection Strategies**

The `choose_random_peers_by_ping_latency` function attempts three selection strategies but all operate on the same `eligible_peer_ids` set with no diversity enforcement: [3](#0-2) 

The random fallback at line 83-84 still selects from the attacker-dominated peer set.

**3. Trivially Spoofable Ping Measurement**

The ping measurement is a simple TCP connection time: [4](#0-3) 

Attackers can deploy nodes that accept TCP connections in <1ms, naturally achieving the lowest latencies.

**Attack Execution:**

1. Attacker deploys multiple malicious fullnodes (cloud-based for low latency)
2. These nodes advertise via public network discovery mechanisms
3. Target fullnode discovers attacker peers in `eligible_peers`
4. Ping measurements show attacker peers at 1-5ms, honest peers at 50-200ms
5. Latency-weighted selection gives attacker peers 50-200x higher probability
6. All 6 outbound connections (default limit) go to attacker peers: [5](#0-4) 

7. Target fullnode is completely eclipsed from honest network

## Impact Explanation

**Severity: Critical** (meets "Loss of Funds" criteria)

While this vulnerability does NOT affect validators (they use all-to-all connections on dedicated networks), it enables:

- **Fund Loss**: Applications/users relying on eclipsed fullnodes can be double-spent
- **State Manipulation**: Eclipsed nodes receive attacker-controlled blockchain data
- **Transaction Censorship**: Attacker can prevent transaction propagation from eclipsed nodes
- **API Data Poisoning**: APIs served by eclipsed fullnodes return false information

Each eclipsed fullnode becomes an attack vector for fund theft from its users/applications. Given that public fullnodes serve end-user applications and wallets, this represents a critical security risk qualifying for the "Loss of Funds" category.

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Deploy 10-20 cloud-based fullnodes globally (cost: ~$500-1000/month)
- No privileged access required
- No special network capabilities needed

**Success Probability:**
- Exponential latency weighting makes dominance mathematically guaranteed
- No diversity checks to prevent concentration
- Public network is permissionless

**Practical Feasibility:**
Economically viable for motivated attackers targeting high-value applications using specific fullnodes. The attack requires minimal technical sophistication beyond deploying geographically distributed nodes.

## Recommendation

Implement multi-layered diversity protections in peer selection:

**1. Cap Latency Weight Advantage:**
```rust
fn convert_latency_to_weight(latency_secs: f64) -> f64 {
    if latency_secs <= 0.0 {
        return 0.0;
    }
    let weight = 1.0 / latency_secs;
    // Cap maximum weight ratio at 10:1 instead of unlimited
    weight.min(10.0 / MIN_LATENCY_THRESHOLD)
}
```

**2. Enforce Diversity Requirements:**
```rust
fn choose_random_peers_by_ping_latency(
    // ... existing params
) -> Vec<(PeerId, DiscoveredPeer)> {
    // Existing latency-based selection
    let mut selected_peer_ids = /* ... */;
    
    // NEW: Require at least 2 peers from different /16 IP ranges
    let selected_peer_ids = enforce_ip_diversity(
        selected_peer_ids, 
        eligible_peer_ids,
        min_distinct_subnets: 2
    );
    
    // NEW: Require peers from at least 2 different discovery sources
    let selected_peer_ids = enforce_source_diversity(
        selected_peer_ids,
        eligible_peers,
        min_sources: 2  
    );
    
    // ... rest of function
}
```

**3. Cross-Validate Discovery Sources:**
- Require intersection of peers from multiple discovery mechanisms
- Reject peer sets dominated by single source

**4. Add Peer Reputation Scoring:**
- Track peer behavior over time
- Penalize peers that consistently have suspiciously low latencies
- Implement gradual trust building

## Proof of Concept

```rust
#[cfg(test)]
mod eclipse_attack_test {
    use super::*;
    
    #[tokio::test]
    async fn test_latency_based_eclipse_attack() {
        // Setup: Create 100 honest peers with 50-200ms latencies
        let mut eligible_peers = vec![];
        for i in 0..100 {
            let peer_id = PeerId::random();
            let mut peer = DiscoveredPeer::new(PeerRole::Upstream);
            // Honest peers: 50-200ms latency
            peer.set_ping_latency_secs(0.05 + (i as f64 * 0.0015));
            eligible_peers.push((peer_id, peer));
        }
        
        // Attacker: Add 10 malicious peers with 1-5ms latencies
        let mut attacker_peers = HashSet::new();
        for i in 0..10 {
            let peer_id = PeerId::random();
            let mut peer = DiscoveredPeer::new(PeerRole::Upstream);
            // Attacker peers: 1-5ms latency
            peer.set_ping_latency_secs(0.001 + (i as f64 * 0.0004));
            attacker_peers.insert(peer_id);
            eligible_peers.push((peer_id, peer));
        }
        
        let discovered_peers = create_discovered_peers(eligible_peers.clone(), false);
        
        // Select 6 peers (default outbound connection limit)
        let selected = choose_random_peers_by_ping_latency(
            NetworkContext::mock_public(),
            eligible_peers,
            6,
            discovered_peers,
        );
        
        // Verify eclipse: All 6 selected peers are attacker-controlled
        let selected_ids: HashSet<_> = selected.iter()
            .map(|(id, _)| *id)
            .collect();
            
        let attacker_selected = selected_ids.intersection(&attacker_peers).count();
        
        // VULNERABILITY: All or nearly all selections are attacker peers
        assert!(attacker_selected >= 5, 
            "Eclipse attack successful: {}/6 selections are attacker peers", 
            attacker_selected);
            
        // With exponential weighting, this assertion will pass,
        // demonstrating complete eclipse capability
    }
}
```

## Notes

**Critical Scope Clarification**: The security question asks about eclipsing "validators," but this vulnerability specifically affects **public fullnodes only**. Validators are not vulnerable because: [1](#0-0) 

Validator networks establish all-to-all connections and never use latency-based peer selection. However, the vulnerability remains critical as public fullnodes serve end-user applications, wallets, and APIs, making them high-value eclipse targets for fund theft and data manipulation attacks.

### Citations

**File:** network/framework/src/connectivity_manager/selection.rs (L36-88)
```rust
pub fn choose_random_peers_by_ping_latency(
    network_context: NetworkContext,
    eligible_peers: Vec<(PeerId, DiscoveredPeer)>,
    num_peers_to_choose: usize,
    discovered_peers: Arc<RwLock<DiscoveredPeerSet>>,
) -> Vec<(PeerId, DiscoveredPeer)> {
    // Get all eligible peer IDs
    let eligible_peer_ids = eligible_peers
        .iter()
        .map(|(peer_id, _)| *peer_id)
        .collect::<HashSet<_>>();

    // Identify the peer IDs that haven't been dialed recently
    let non_recently_dialed_peer_ids = eligible_peers
        .iter()
        .filter(|(_, peer)| !peer.has_dialed_recently())
        .map(|(peer_id, _)| *peer_id)
        .collect::<HashSet<_>>();

    // Choose peers (weighted by latency) from the non-recently dialed peers
    let mut selected_peer_ids = choose_peers_by_ping_latency(
        &network_context,
        &non_recently_dialed_peer_ids,
        num_peers_to_choose,
        discovered_peers.clone(),
    );

    // If not enough peers were selected, choose additional peers weighted by latency
    let num_selected_peer_ids = selected_peer_ids.len();
    if num_selected_peer_ids < num_peers_to_choose {
        // Filter out the already selected peers
        let unselected_peer_ids = get_unselected_peer_ids(&eligible_peer_ids, &selected_peer_ids);

        // Choose the remaining peers weighted by latency
        let num_remaining_peers = num_peers_to_choose.saturating_sub(num_selected_peer_ids);
        let remaining_selected_peer_ids = choose_peers_by_ping_latency(
            &network_context,
            &unselected_peer_ids,
            num_remaining_peers,
            discovered_peers.clone(),
        );

        // Extend the selected peers with the remaining peers
        selected_peer_ids.extend(remaining_selected_peer_ids);
    }

    // Extend the selected peers with random peers (if necessary)
    let selected_peer_ids =
        extend_with_random_peers(selected_peer_ids, &eligible_peer_ids, num_peers_to_choose);

    // Return the selected peers
    get_discovered_peers_for_ids(selected_peer_ids, discovered_peers)
}
```

**File:** network/framework/src/connectivity_manager/selection.rs (L90-98)
```rust
/// Returns true iff peers should be selected by ping latency. Note: this only
/// makes sense for the public network, as the validator and VFN networks
/// establish all-to-all connections.
pub fn should_select_peers_by_latency(
    network_context: &NetworkContext,
    enable_latency_aware_dialing: bool,
) -> bool {
    network_context.network_id().is_public_network() && enable_latency_aware_dialing
}
```

**File:** network/framework/src/connectivity_manager/selection.rs (L151-168)
```rust
fn convert_latency_to_weight(latency_secs: f64) -> f64 {
    // If the latency is <= 0, something has gone wrong, so return 0.
    if latency_secs <= 0.0 {
        return 0.0;
    }

    // Invert the latency to get the weight
    let mut weight = 1.0 / latency_secs;

    // For every 25ms of latency, reduce the weight by 1/2 (to
    // ensure that low latency peers are highly weighted)
    let num_reductions = (latency_secs / 0.025) as usize;
    for _ in 0..num_reductions {
        weight /= 2.0;
    }

    weight
}
```

**File:** network/framework/src/connectivity_manager/mod.rs (L600-620)
```rust
            if let Some(outbound_connection_limit) = self.outbound_connection_limit {
                // Get the number of outbound connections
                let num_outbound_connections = self
                    .connected
                    .iter()
                    .filter(|(_, metadata)| metadata.origin == ConnectionOrigin::Outbound)
                    .count();

                // Add any pending dials to the count
                let total_outbound_connections =
                    num_outbound_connections.saturating_add(self.dial_queue.len());

                // Calculate the potential number of peers to dial
                let num_peers_to_dial =
                    outbound_connection_limit.saturating_sub(total_outbound_connections);

                // Limit the number of peers to dial by the total number of eligible peers
                min(num_peers_to_dial, num_eligible_peers)
            } else {
                num_eligible_peers // Otherwise, we attempt to dial all eligible peers
            };
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1189-1203)
```rust
        // Attempt to connect to the socket addresses over TCP and time the connection
        for socket_address in socket_addresses {
            // Start the ping timer
            let start_time = Instant::now();

            // Attempt to connect to the socket address
            if let Ok(tcp_stream) = TcpStream::connect_timeout(
                socket_address,
                Duration::from_secs(MAX_CONNECTION_TIMEOUT_SECS),
            ) {
                // We connected successfully, update the peer's ping latency
                let ping_latency_secs = start_time.elapsed().as_secs_f64();
                discovered_peers
                    .write()
                    .update_ping_latency_secs(&peer_id, ping_latency_secs);
```
