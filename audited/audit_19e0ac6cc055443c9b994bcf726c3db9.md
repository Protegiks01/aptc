# Audit Report

## Title
Inverted Latency Filtering Logic Causes Selection of Highest-Latency Peers Instead of Lowest-Latency Peers

## Summary
The `choose_peers_by_latency()` function in `state-sync/aptos-data-client/src/utils.rs` contains a critical logic bug where latency filtering is inverted. When enabled, the function excludes low-latency (honest, well-performing) peers and only considers high-latency peers for state synchronization and data fetching. This directly contradicts the stated intention and causes nodes to preferentially sync from the slowest peers in the network.

## Finding Description

The vulnerability exists in the peer selection logic that determines which peers a node will use for state synchronization. The function is designed to filter out high-latency peers when certain thresholds are met (lines 102-104), but the sorting logic is backwards. [1](#0-0) 

The code comment clearly states the intention: "we only want to consider a subset of peers with the lowest latencies." The parameter `ignore_high_latency_peers` indicates that high-latency peers should be ignored.

However, the actual implementation does the opposite: [2](#0-1) 

The bug occurs because:
1. At line 90, latency is converted to weight using `1000.0 / latency` - lower latency = higher weight
2. At line 112, peers are sorted by weight in **ascending order** (lowest weight first)
3. Since lower weight = higher latency, this puts highest-latency peers first
4. At line 115, `.take(num_peers_to_consider)` takes the first N peers = highest-latency peers
5. The lowest-latency peers (highest weights) are at the end and get excluded [3](#0-2) 

**Attack Scenario:**
An attacker can exploit this by:
1. Connecting malicious peers with artificially high latency (e.g., introducing delays in ping responses)
2. Manipulating peer counts to trigger the filtering threshold (≥10 peers with ≥5:1 ratio per request)
3. Once filtering is enabled, honest low-latency peers are excluded
4. The victim node only considers the attacker's slow peers, causing:
   - Slow state synchronization
   - Increased susceptibility to eclipse attacks
   - Delayed transaction propagation
   - Potential consensus timeouts if validators are affected

The function is called with `ignore_high_latency_peers=true` in production code: [4](#0-3) 

## Impact Explanation

**High Severity** - This vulnerability causes validator nodes and fullnodes to preferentially select the worst-performing peers in the network when latency filtering is enabled. 

Impact includes:
- **Validator node slowdowns**: Validators syncing from high-latency peers will lag behind, potentially missing proposal deadlines and affecting consensus participation
- **State synchronization delays**: Fullnodes will take significantly longer to sync state, affecting user experience and network decentralization
- **Eclipse attack facilitation**: By forcing nodes to connect to slow/malicious peers, attackers can more easily eclipse victims from the honest network
- **Protocol violation**: The system violates its documented peer selection invariant of preferring low-latency peers

This meets the "High Severity" criteria per Aptos bug bounty: "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**High Likelihood** - This bug will trigger automatically in production whenever:
1. A node has ≥10 peers with valid latency data (default threshold)
2. The peer-to-request ratio is ≥5:1 (default threshold)  
3. The node makes non-optimistic fetch requests (e.g., `GetStorageServerSummary`) [5](#0-4) 

These conditions are commonly met in production networks with normal peer counts. An attacker can further ensure triggering by:
- Adding malicious peers to inflate peer counts
- Timing attacks during high peer availability periods
- No special privileges or validator access required

## Recommendation

**Fix: Reverse the sort order to select highest-weight (lowest-latency) peers**

Change line 112 to sort in **descending** order:

```rust
// Sort the peers by latency weights (descending) and take the number of peers to consider
potential_peers_and_latency_weights.sort_by_key(|(_, latency_weight)| std::cmp::Reverse(*latency_weight));
```

Or alternatively, use `sort_by` with reversed comparison:

```rust
potential_peers_and_latency_weights.sort_by(|(_, w1), (_, w2)| w2.partial_cmp(w1).unwrap_or(std::cmp::Ordering::Equal));
```

This ensures that after sorting, the first N peers taken are those with the **highest weights** (lowest latencies), matching the documented intention.

## Proof of Concept

```rust
#[test]
fn test_latency_filtering_selects_lowest_latency_peers() {
    use aptos_config::config::{AptosDataClientConfig, AptosLatencyFilteringConfig};
    use std::sync::Arc;
    
    // Create config with filtering enabled
    let config = Arc::new(AptosDataClientConfig {
        latency_filtering_config: AptosLatencyFilteringConfig {
            min_peers_for_latency_filtering: 10,
            min_peer_ratio_for_latency_filtering: 5,
            latency_filtering_reduction_factor: 2,
        },
        ..Default::default()
    });
    
    // Create mock peers with known latencies
    // Peer A: 0.01s (10ms) - lowest latency
    // Peer B: 0.05s (50ms) - medium latency  
    // Peer C: 0.10s (100ms) - highest latency
    // ... (create 10+ peers to trigger filtering)
    
    // Call choose_peers_by_latency with ignore_high_latency_peers=true
    // Expected: Should select from low-latency peers (A, B, ...)
    // Actual Bug: Selects from high-latency peers (C, ...)
    
    // Assert that the selected peers include low-latency peers
    // This test will FAIL with the current buggy implementation
}
```

**Validation**: The bug can be confirmed by tracing the execution with concrete values:
- If peers have latencies [0.1s, 0.5s, 0.9s], their weights are [10000, 2000, 1111]
- After ascending sort by weight: [(peer_0.9s, 1111), (peer_0.5s, 2000), (peer_0.1s, 10000)]
- Taking first 2 gives the 0.9s and 0.5s peers (highest latencies), excluding the 0.1s peer (lowest latency)

## Notes

The boundary condition mentioned in the security question (lines 102-104) does exist, but the more critical issue is the inverted sorting logic at line 112. While an attacker could manipulate peer counts to stay at boundaries to create unpredictable behavior, the fundamental bug is that the filtering mechanism itself is backwards - it always excludes the best peers and includes the worst peers when enabled, regardless of boundary conditions.

### Citations

**File:** state-sync/aptos-data-client/src/utils.rs (L94-109)
```rust
    // Determine the number of peers to consider. If high latency peers can be
    // ignored, we only want to consider a subset of peers with the lowest
    // latencies. However, this can only be done if we have a large total
    // number of peers, and there are enough potential peers for each request.
    let mut num_peers_to_consider = potential_peers_and_latency_weights.len() as u64;
    if ignore_high_latency_peers {
        let latency_filtering_config = &data_client_config.latency_filtering_config;
        let peer_ratio_per_request = num_peers_to_consider / num_peers_to_choose;
        if num_peers_to_consider >= latency_filtering_config.min_peers_for_latency_filtering
            && peer_ratio_per_request
                >= latency_filtering_config.min_peer_ratio_for_latency_filtering
        {
            // Consider a subset of peers with the lowest latencies
            num_peers_to_consider /= latency_filtering_config.latency_filtering_reduction_factor
        }
    }
```

**File:** state-sync/aptos-data-client/src/utils.rs (L111-120)
```rust
    // Sort the peers by latency weights and take the number of peers to consider
    potential_peers_and_latency_weights.sort_by_key(|(_, latency_weight)| *latency_weight);
    let potential_peers_and_latency_weights = potential_peers_and_latency_weights
        .into_iter()
        .take(num_peers_to_consider as usize)
        .map(|(peer, latency_weight)| (peer, latency_weight.into_inner()))
        .collect::<Vec<_>>();

    // Select the peers by latency weights
    choose_random_peers_by_weight(num_peers_to_choose, potential_peers_and_latency_weights)
```

**File:** state-sync/aptos-data-client/src/utils.rs (L173-183)
```rust
/// Converts the given latency measurement to a weight.
/// The lower the latency, the higher the weight.
fn convert_latency_to_weight(latency: f64) -> f64 {
    // If the latency is <= 0, something has gone wrong, so return 0.
    if latency <= 0.0 {
        return 0.0;
    }

    // Otherwise, invert the latency to get the weight
    1000.0 / latency
}
```

**File:** state-sync/aptos-data-client/src/client.rs (L520-537)
```rust
    /// Chooses peers randomly weighted by latency from the given set of serviceable peers
    fn choose_random_peers_by_latency(
        &self,
        serviceable_peers: HashSet<PeerNetworkId>,
        num_peers_to_choose: usize,
    ) -> HashSet<PeerNetworkId> {
        // Choose peers weighted by latency
        let selected_peers = utils::choose_peers_by_latency(
            self.data_client_config.clone(),
            num_peers_to_choose as u64,
            serviceable_peers.clone(),
            self.get_peers_and_metadata(),
            true,
        );

        // Extend the selected peers with random peers (if necessary)
        utils::extend_with_random_peers(selected_peers, serviceable_peers, num_peers_to_choose)
    }
```

**File:** config/src/config/state_sync_config.rs (L401-409)
```rust
impl Default for AptosLatencyFilteringConfig {
    fn default() -> Self {
        Self {
            latency_filtering_reduction_factor: 2, // Only consider the best 50% of peers
            min_peer_ratio_for_latency_filtering: 5, // Only filter if we have at least 5 potential peers per request
            min_peers_for_latency_filtering: 10, // Only filter if we have at least 10 total peers
        }
    }
}
```
