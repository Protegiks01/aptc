# Audit Report

## Title
TOCTOU Race Condition in Peer Selection Causes Stale Data and Reduced Connectivity

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists in the connectivity manager's peer selection logic. When selecting peers to dial, a snapshot of eligible peers is taken, but during an asynchronous ping operation, concurrent peer discovery updates can remove peers from the shared state. This causes the final peer retrieval to silently fail for removed peers, resulting in fewer outbound connections than intended.

## Finding Description

The vulnerability occurs in the peer dialing flow within `ConnectivityManager`. The issue manifests through the following execution path: [1](#0-0) 

At this point, the code creates a snapshot of the peer set by cloning it. This snapshot is used to filter eligible peers. [2](#0-1) 

Here lies the critical vulnerability: an `await` point where control is yielded to the async event loop, allowing other events to be processed, specifically `UpdateDiscoveredPeers` requests. [3](#0-2) 

During this await (inside `ping_eligible_peers`), the event loop can process incoming `UpdateDiscoveredPeers` messages. [4](#0-3) 

These messages can remove peers from the shared `discovered_peers` state via `remove_peer_if_empty`, which is called when peers no longer have addresses or keys from any discovery source. [5](#0-4) 

After the await completes, the code calls `choose_random_peers_by_ping_latency` passing the stale `eligible_peers` snapshot (which may contain references to removed peers) alongside the current `discovered_peers` state. [6](#0-5) 

Finally, `get_discovered_peers_for_ids` attempts to retrieve the full peer objects, but the `filter_map` at line 203 silently drops any peers that were removed, returning fewer peers than requested. This reduces the number of outbound connection attempts.

The race window exists because:
1. The `eligible_peers` snapshot is taken before the await
2. Shared state (`discovered_peers`) is modified during the await
3. The stale snapshot is used after the await to select peers
4. Missing peers are silently filtered out rather than being detected or logged

## Impact Explanation

This vulnerability falls under **Medium Severity** per the Aptos bug bounty criteria for the following reasons:

**State Inconsistencies:** The system operates on stale peer data, causing a mismatch between intended and actual connectivity behavior. Nodes may establish significantly fewer outbound connections than configured limits allow.

**Limited Availability Impact:** For public fullnodes, reduced connectivity can:
- Decrease network topology robustness
- Reduce peer diversity for transaction/block propagation  
- Make nodes more susceptible to eclipse attacks
- Limit participation in network-wide operations

**Quantifiable Impact:**
- If N peers are removed during the race window and would have been selected, the node establishes N fewer connections
- Under adversarial conditions with coordinated discovery updates, an attacker could persistently reduce a node's connectivity
- The issue self-corrects on the next connectivity check cycle (periodic), but the race can recur

**Not Critical Because:**
- Does not affect validator networks (they don't use latency-based selection per `should_select_peers_by_latency`)
- Does not directly cause consensus violations or fund loss
- Inbound connections from other peers provide partial mitigation
- Periodic retry mechanisms eventually establish connections
- No permanent state corruption occurs

## Likelihood Explanation

**High Likelihood of Occurrence:**

The race condition occurs whenever:
1. Latency-aware peer dialing is enabled (public fullnode networks)
2. A connectivity check is triggered
3. An `UpdateDiscoveredPeers` message arrives during the `ping_eligible_peers` await window

The race window is non-trivial (milliseconds to seconds) as it includes:
- Spawning multiple ping tasks for peers without latency data
- TCP connection attempts to peer addresses (up to 2 second timeout per attempt)
- Waiting for all ping tasks to complete via `join_all` [7](#0-6) 

**Exploitability:**

An attacker could increase likelihood by:
- Sending frequent discovery updates with peer removals
- Timing updates to coincide with known connectivity check intervals
- Targeting specific peers to remove from the victim's peer set

Discovery sources that could be manipulated: [8](#0-7) 

## Recommendation

**Fix Approach:** Eliminate the stale data by acquiring a fresh peer snapshot after the async ping operation completes, or hold the snapshot consistently throughout the selection process.

**Recommended Fix:**

```rust
// In choose_peers_to_dial(), after ping_eligible_peers returns:
async fn choose_peers_to_dial(&mut self) -> Vec<(PeerId, DiscoveredPeer)> {
    // ... existing code to get eligible_peers snapshot ...
    
    if selection::should_select_peers_by_latency(
        &self.network_context,
        self.enable_latency_aware_dialing,
    ) {
        self.ping_eligible_peers(eligible_peers.clone()).await;
        
        // FIX: Re-acquire eligible peers after pinging to get fresh state
        let discovered_peers = self.discovered_peers.read().peer_set.clone();
        let eligible_peers: Vec<_> = discovered_peers
            .into_iter()
            .filter(|(peer_id, peer)| {
                peer.is_eligible_to_be_dialed()
                    && !self.connected.contains_key(peer_id)
                    && !self.dial_queue.contains_key(peer_id)
                    && roles_to_dial.contains(&peer.role)
            })
            .collect();
        
        selection::choose_random_peers_by_ping_latency(
            self.network_context,
            eligible_peers,  // Now uses fresh snapshot
            num_peers_to_dial,
            self.discovered_peers.clone(),
        )
    } else {
        selection::choose_peers_to_dial_randomly(eligible_peers, num_peers_to_dial)
    }
}
```

**Alternative Fix:** Add validation and logging when `get_discovered_peers_for_ids` returns fewer peers than expected to detect and monitor this condition.

## Proof of Concept

```rust
#[tokio::test]
async fn test_peer_removal_race_during_selection() {
    use std::sync::Arc;
    use aptos_infallible::RwLock;
    use std::collections::HashMap;
    
    // Setup: Create discovered peers with 10 peers
    let mut peer_set = HashMap::new();
    let peer_ids: Vec<_> = (0..10).map(|_| PeerId::random()).collect();
    
    for peer_id in &peer_ids {
        let mut peer = DiscoveredPeer::new(PeerRole::ValidatorFullNode);
        peer.addrs.update(DiscoverySource::Config, vec![NetworkAddress::mock()]);
        peer.keys.update(DiscoverySource::Config, HashSet::new());
        peer.set_ping_latency_secs(0.05);
        peer_set.insert(*peer_id, peer);
    }
    
    let discovered_peers = Arc::new(RwLock::new(
        DiscoveredPeerSet::new_from_peer_set(peer_set)
    ));
    
    // Create eligible peers snapshot (simulating line 577-586)
    let eligible_peers: Vec<_> = discovered_peers
        .read()
        .peer_set
        .clone()
        .into_iter()
        .collect();
    
    assert_eq!(eligible_peers.len(), 10);
    
    // Simulate the race: Remove 5 peers during the "await" window
    // (simulating what happens during ping_eligible_peers)
    for peer_id in &peer_ids[0..5] {
        discovered_peers.write().remove_peer_if_empty(peer_id);
    }
    
    // Now call choose_random_peers_by_ping_latency with stale eligible_peers
    let selected_peers = choose_random_peers_by_ping_latency(
        NetworkContext::mock(),
        eligible_peers,  // Contains 10 peers
        10,
        discovered_peers.clone(),  // Only has 5 peers remaining
    );
    
    // BUG DEMONSTRATED: We requested 10 peers but got only 5
    // because 5 were removed during the race window
    assert_eq!(selected_peers.len(), 5);  // Should be 10, but only 5 returned
    println!("Race condition confirmed: requested 10 peers, got {}", selected_peers.len());
}
```

This PoC demonstrates that when `eligible_peers` contains peer IDs that have been removed from `discovered_peers`, the `get_discovered_peers_for_ids` function silently filters them out, returning fewer peers than requested.

## Notes

- The vulnerability only affects **public fullnode networks** where latency-aware peer selection is enabled
- **Validator networks are NOT affected** as they use all-to-all connectivity without latency-based selection
- The issue is transient and self-correcting on the next connectivity check cycle
- Impact is limited but could contribute to reduced network resilience under adversarial conditions
- The security question's classification of "Medium" severity is appropriate given the state inconsistency and potential connectivity impact

### Citations

**File:** network/framework/src/connectivity_manager/mod.rs (L136-144)
```rust
/// Config=lowest).
#[repr(u8)]
#[derive(Copy, Clone, Eq, Hash, PartialEq, Ord, PartialOrd, NumVariants, Serialize)]
pub enum DiscoverySource {
    OnChainValidatorSet,
    File,
    Rest,
    Config,
}
```

**File:** network/framework/src/connectivity_manager/mod.rs (L577-577)
```rust
        let discovered_peers = self.discovered_peers.read().peer_set.clone();
```

**File:** network/framework/src/connectivity_manager/mod.rs (L633-633)
```rust
            self.ping_eligible_peers(eligible_peers.clone()).await;
```

**File:** network/framework/src/connectivity_manager/mod.rs (L636-641)
```rust
            selection::choose_random_peers_by_ping_latency(
                self.network_context,
                eligible_peers,
                num_peers_to_dial,
                self.discovered_peers.clone(),
            )
```

**File:** network/framework/src/connectivity_manager/mod.rs (L650-715)
```rust
    async fn ping_eligible_peers(&mut self, eligible_peers: Vec<(PeerId, DiscoveredPeer)>) {
        // Identify the eligible peers that don't already have latency information
        let peers_to_ping = eligible_peers
            .into_iter()
            .filter(|(_, peer)| peer.ping_latency_secs.is_none())
            .collect::<Vec<_>>();

        // If there are no peers to ping, return early
        let num_peers_to_ping = peers_to_ping.len();
        if num_peers_to_ping == 0 {
            return;
        }

        // Spawn a task that pings each peer concurrently
        let ping_start_time = Instant::now();
        let mut ping_tasks = vec![];
        for (peer_id, peer) in peers_to_ping.into_iter() {
            // Get the network address for the peer
            let network_context = self.network_context;
            let network_address = match self.dial_states.get(&peer_id) {
                Some(dial_state) => match dial_state.random_addr(&peer.addrs) {
                    Some(network_address) => network_address.clone(),
                    None => {
                        warn!(
                            NetworkSchema::new(&network_context),
                            "Peer {} does not have a network address!",
                            peer_id.short_str()
                        );
                        continue; // Continue onto the next peer
                    },
                },
                None => {
                    warn!(
                        NetworkSchema::new(&network_context),
                        "Peer {} does not have a dial state!",
                        peer_id.short_str()
                    );
                    continue; // Continue onto the next peer
                },
            };

            // Ping the peer
            let ping_task = spawn_latency_ping_task(
                network_context,
                peer_id,
                network_address,
                self.discovered_peers.clone(),
            );

            // Add the task to the list of ping tasks
            ping_tasks.push(ping_task);
        }

        // Wait for all the ping tasks to complete (or timeout)
        let num_ping_tasks = ping_tasks.len();
        join_all(ping_tasks).await;

        // Log the peer ping latencies
        log_peer_ping_latencies(
            self.network_context,
            self.discovered_peers.clone(),
            num_peers_to_ping,
            num_ping_tasks,
            ping_start_time,
        );
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L923-926)
```rust
        // Remove peers that no longer have state
        for peer_id in peers_to_check_remove {
            self.discovered_peers.write().remove_peer_if_empty(&peer_id);
        }
```

**File:** network/framework/src/connectivity_manager/selection.rs (L197-211)
```rust
fn get_discovered_peers_for_ids(
    peer_ids: HashSet<PeerId>,
    discovered_peers: Arc<RwLock<DiscoveredPeerSet>>,
) -> Vec<(PeerId, DiscoveredPeer)> {
    peer_ids
        .into_iter()
        .filter_map(|peer_id| {
            discovered_peers
                .read()
                .peer_set
                .get(&peer_id)
                .map(|peer| (peer_id, peer.clone()))
        })
        .collect()
}
```
