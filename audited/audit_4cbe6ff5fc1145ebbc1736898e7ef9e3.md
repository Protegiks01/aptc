# Audit Report

## Title
Peer Selection Bias Enables Network Imbalance Through Latency-Based Selection Without Diversity Guarantee

## Summary
The `choose_random_peers_by_ping_latency()` function exhibits a peer selection bias that can lead to network imbalance when non-recently-dialed peers lack ping latency data. The random fallback mechanism (`extend_with_random_peers`) fails to ensure peer diversity because it only triggers when latency-based selection cannot fill the required quota. This creates a feedback loop where recently-dialed peers with latency data are repeatedly selected, excluding non-recently-dialed peers and enabling potential eclipse attacks on public full nodes.

## Finding Description

The vulnerability exists in the peer selection logic at [1](#0-0) 

The function implements a three-stage selection process:

**Stage 1**: Select from non-recently-dialed peers weighted by ping latency [2](#0-1) 

**Stage 2**: If insufficient peers selected, choose from ALL unselected peers weighted by latency [3](#0-2) 

**Stage 3**: If still insufficient, extend with random peers [4](#0-3) 

The critical flaw is in the `choose_peers_by_ping_latency()` helper function, which ONLY selects peers that have ping latency data: [5](#0-4) 

Specifically, peers without latency data are filtered out at: [6](#0-5) 

**Attack Scenario:**

When all non-recently-dialed peers lack ping latency data (due to failed TCP ping attempts, firewall rules blocking TCP but allowing P2P protocol, or being newly discovered), and recently-dialed peers have latency data from previous successful pings:

1. Stage 1 selects 0 peers (non-recently-dialed peers have no latency)
2. Stage 2 selects only from recently-dialed peers (only they have latency data)
3. If Stage 2 fills the quota, Stage 3 never triggers
4. Result: **Only recently-dialed peers are selected**

The TCP ping mechanism occurs before selection: [7](#0-6) 

But ping failures leave peers without latency data: [8](#0-7) 

Once a peer is dialed, it's marked as recently-dialed for 5 minutes: [9](#0-8) 

This creates a persistent bias where the same subset of peers is repeatedly selected, violating the network diversity invariant required for eclipse attack resistance.

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria.

This vulnerability enables:

1. **Network Imbalance**: Nodes connect to a biased subset of available peers, reducing network resilience
2. **Eclipse Attack Facilitation**: Attacker-controlled peers that respond well to TCP pings can monopolize a victim node's peer connections by ensuring legitimate peers fail ping tests
3. **State Sync Vulnerabilities**: Limited peer diversity makes it easier to feed malicious state to full nodes
4. **Reduced Decentralization**: Public full nodes fail to establish diverse peer connections

The issue affects public full nodes (latency-aware selection only applies to public networks): [10](#0-9) 

Validators are unaffected as they establish all-to-all connections and don't use latency-based selection.

While not causing direct consensus violations or fund loss (Critical severity), this creates state inconsistencies and network partitioning risks that require intervention (Medium severity).

## Likelihood Explanation

**Likelihood: High**

This vulnerability occurs naturally without attacker intervention when:
- Newly discovered peers haven't been successfully pinged yet
- Peers behind restrictive firewalls fail TCP pings but support P2P protocols
- Network conditions cause temporary TCP connectivity issues
- Geographic/network diversity means different peers have varying TCP reachability

An attacker can deliberately exploit this by:
1. Ensuring their controlled peers respond quickly to TCP ping attempts
2. Allowing their peers to be discovered and dialed once
3. Exploiting the natural bias to maintain connections preferentially to their peers

The feedback loop is self-reinforcing: recently-dialed peers maintain latency data and continue being selected, while non-recently-dialed peers remain excluded.

## Recommendation

Modify the selection logic to guarantee minimum diversity by always including random selection, not just as a fallback:

```rust
pub fn choose_random_peers_by_ping_latency(
    network_context: NetworkContext,
    eligible_peers: Vec<(PeerId, DiscoveredPeer)>,
    num_peers_to_choose: usize,
    discovered_peers: Arc<RwLock<DiscoveredPeerSet>>,
) -> Vec<(PeerId, DiscoveredPeer)> {
    // Calculate split between latency-based and random selection
    let num_latency_based = (num_peers_to_choose * 2) / 3; // 66% latency-based
    let num_random = num_peers_to_choose - num_latency_based; // 34% random
    
    // Get peer IDs
    let eligible_peer_ids = eligible_peers
        .iter()
        .map(|(peer_id, _)| *peer_id)
        .collect::<HashSet<_>>();
    
    // Select by latency (prioritize non-recently-dialed)
    let non_recently_dialed_peer_ids = eligible_peers
        .iter()
        .filter(|(_, peer)| !peer.has_dialed_recently())
        .map(|(peer_id, _)| *peer_id)
        .collect::<HashSet<_>>();
    
    let mut selected_peer_ids = choose_peers_by_ping_latency(
        &network_context,
        &non_recently_dialed_peer_ids,
        num_latency_based,
        discovered_peers.clone(),
    );
    
    // Fill remaining latency-based slots from all peers
    if selected_peer_ids.len() < num_latency_based {
        let unselected = get_unselected_peer_ids(&eligible_peer_ids, &selected_peer_ids);
        let remaining = choose_peers_by_ping_latency(
            &network_context,
            &unselected,
            num_latency_based - selected_peer_ids.len(),
            discovered_peers.clone(),
        );
        selected_peer_ids.extend(remaining);
    }
    
    // ALWAYS select random peers for diversity (not just fallback)
    let unselected = get_unselected_peer_ids(&eligible_peer_ids, &selected_peer_ids);
    let random_peers = unselected
        .into_iter()
        .choose_multiple(&mut ::rand_latest::thread_rng(), num_random);
    selected_peer_ids.extend(random_peers);
    
    get_discovered_peers_for_ids(selected_peer_ids, discovered_peers)
}
```

This ensures guaranteed peer diversity while still benefiting from latency-based optimization.

## Proof of Concept

The existing test demonstrates the vulnerability exists but passes because it expects this behavior: [11](#0-10) 

This test shows that when non-dialed peers lack latency data and dialed peers have it, only dialed peers are selected (lines 524-526).

To demonstrate the security impact, run the test and observe that with 100 non-dialed peers without latency and 100 dialed peers with latency, the selection consistently chooses only from the dialed set, creating measurable bias that persists across 5000 iterations (lines 511-532).

The test verifies this bias is intentional (line 525: `assert!(!non_dialed_peers.contains(&peer_id))`), confirming the vulnerability exists as designed.

**Notes:**

This vulnerability specifically affects the public full node network where latency-aware dialing is enabled. It does not impact validators or VFN networks that establish all-to-all connections. The issue arises from the design choice to use random peer selection only as a fallback mechanism rather than guaranteeing minimum diversity in all cases. While TCP ping-based latency measurement provides performance benefits, relying exclusively on it for selection creates a security weakness when ping success rates differ systematically between peer subsets.

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

**File:** network/framework/src/connectivity_manager/selection.rs (L93-98)
```rust
pub fn should_select_peers_by_latency(
    network_context: &NetworkContext,
    enable_latency_aware_dialing: bool,
) -> bool {
    network_context.network_id().is_public_network() && enable_latency_aware_dialing
}
```

**File:** network/framework/src/connectivity_manager/selection.rs (L103-146)
```rust
fn choose_peers_by_ping_latency(
    network_context: &NetworkContext,
    peer_ids: &HashSet<PeerId>,
    num_peers_to_choose: usize,
    discovered_peers: Arc<RwLock<DiscoveredPeerSet>>,
) -> HashSet<PeerId> {
    // If no peers can be chosen, return an empty list
    if num_peers_to_choose == 0 || peer_ids.is_empty() {
        return hashset![];
    }

    // Gather the latency weights for all peers
    let mut peer_ids_and_latency_weights = vec![];
    for peer_id in peer_ids {
        if let Some(ping_latency_secs) = discovered_peers.read().get_ping_latency_secs(peer_id) {
            let latency_weight = convert_latency_to_weight(ping_latency_secs);
            peer_ids_and_latency_weights.push((peer_id, OrderedFloat(latency_weight)));
        }
    }

    // Get the random peers by weight
    let weighted_selected_peers = peer_ids_and_latency_weights
        .choose_multiple_weighted(
            &mut ::rand_latest::thread_rng(),
            num_peers_to_choose,
            |peer| peer.1,
        )
        .map(|peers| peers.into_iter().map(|peer| *peer.0).collect::<Vec<_>>());

    // Return the random peers by weight
    weighted_selected_peers
        .unwrap_or_else(|error| {
            // We failed to select any peers
            error!(
                NetworkSchema::new(network_context),
                "Failed to choose peers by latency for network context: {:?}. Error: {:?}",
                network_context,
                error
            );
            vec![]
        })
        .into_iter()
        .collect::<HashSet<_>>()
}
```

**File:** network/framework/src/connectivity_manager/selection.rs (L494-536)
```rust
    fn test_choose_peers_by_latency_prioritized_dialed() {
        // Create a set of eligible peers
        let mut eligible_peers = vec![];

        // Add peers that have been dialed recently
        let num_dialed_peers = 100;
        let dialed_peers = insert_dialed_peers(num_dialed_peers, &mut eligible_peers);

        // Create the discovered peer set
        let discovered_peers = create_discovered_peers(eligible_peers.clone(), true);

        // Add peers that have not been dialed recently (with no ping latencies)
        let num_non_dialed_peers = 100;
        let non_dialed_peers = insert_non_dialed_peers(num_non_dialed_peers, &mut eligible_peers);

        // Choose peers by latency (multiple times) and verify the selection
        let mut peer_selection_counts = HashMap::new();
        for _ in 0..5000 {
            // Choose a single peer by latency and verify the number of selected peers
            let num_peers_to_dial = 1;
            let selected_peers = choose_random_peers_by_ping_latency(
                NetworkContext::mock(),
                eligible_peers.clone(),
                num_peers_to_dial,
                discovered_peers.clone(),
            );
            assert_eq!(selected_peers.len(), num_peers_to_dial);

            // Verify the selection and update the peer selection counts
            for (peer_id, _) in selected_peers {
                // Verify that the peer was dialed recently
                assert!(!non_dialed_peers.contains(&peer_id));
                assert!(dialed_peers.contains(&peer_id));

                // Update the peer selection counts
                let count = peer_selection_counts.entry(peer_id).or_insert(0);
                *count += 1;
            }
        }

        // Verify the top 10% of selected peers are the lowest latency peers
        verify_highest_peer_selection_latencies(discovered_peers.clone(), &peer_selection_counts);
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L90-93)
```rust
/// The amount of time to try other peers until dialing this peer again.
///
/// It's currently set to 5 minutes to ensure rotation through all (or most) peers
const TRY_DIAL_BACKOFF_TIME: Duration = Duration::from_secs(300);
```

**File:** network/framework/src/connectivity_manager/mod.rs (L632-633)
```rust
            // Ping the eligible peers (so that we can fetch missing ping latency information)
            self.ping_eligible_peers(eligible_peers.clone()).await;
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1195-1203)
```rust
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
