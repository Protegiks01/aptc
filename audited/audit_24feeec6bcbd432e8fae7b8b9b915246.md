# Audit Report

## Title
Mempool Load Balancing Bypass via Latency-Agnostic Peer Selection Allowing Transaction Censorship

## Summary
The `update_sender_bucket_for_peers()` function in `mempool/src/shared_mempool/priority.rs` contains a logic flaw that allows attackers to force all their malicious peers into the `top_peers` set when `enable_max_load_balancing_at_any_load = true` is configured with a high `num_sender_buckets` value. The vulnerability stems from the latency filtering logic unconditionally accepting peers without ping latency data, enabling an attacker to bypass load balancing controls and monopolize transaction broadcasts.

## Finding Description

The vulnerability exists in the peer selection logic that determines which peers should receive transaction broadcasts. When `enable_max_load_balancing_at_any_load = true`, the code calculates `num_top_peers` as follows: [1](#0-0) 

When this flag is enabled, `num_top_peers` is set to `min(num_sender_buckets, u8::MAX)`. If an operator configures `num_sender_buckets` to a high value (e.g., 255), this allows up to 255 peers to be designated as "top peers."

The critical flaw occurs in the latency-based filtering logic: [2](#0-1) 

This condition adds a peer to `top_peers` if **any** of these are true:
1. `base_ping_latency.is_none()` - the reference peer has no latency data
2. `ping_latency.is_none()` - this peer has no latency data  
3. The peer's latency is within the acceptable threshold

**The vulnerability**: Conditions 1 and 2 completely bypass the latency check. An attacker can exploit this by:

1. Connecting many malicious peers to a victim node configured with `enable_max_load_balancing_at_any_load = true` and high `num_sender_buckets` (e.g., 255)
2. Ensuring these peers don't have ping latency data (by connecting immediately before peer update, or not responding to latency pings)
3. During the `top_peers` selection loop, all attacker peers without latency data satisfy the condition `ping_latency.is_none()` and are added to `top_peers`
4. Sender buckets are distributed round-robin across all peers in `top_peers` [3](#0-2) 

5. When broadcasting transactions, each peer receives transactions from their assigned sender buckets: [4](#0-3) 

**Attack Scenario**:
- Victim node has `enable_max_load_balancing_at_any_load = true` and `num_sender_buckets = 255`
- Attacker connects 255 malicious peers
- These peers are newly connected or don't respond to ping requests (no latency data)
- All 255 attacker peers are added to `top_peers` because `ping_latency.is_none()`
- Transactions are distributed across all 255 attacker-controlled peers
- Attacker can now: censor transactions (not forward them), front-run by observing before wide propagation, or cause DoS by delaying broadcasts

## Impact Explanation

This vulnerability enables **transaction censorship** and **network disruption** attacks, qualifying as **High Severity** under the Aptos bug bounty program criteria for "Validator node slowdowns" and "Network protocol attacks (malicious peer handling)."

**Specific Impacts**:

1. **Transaction Censorship**: If an attacker controls the majority of peers in `top_peers`, they receive most transaction broadcasts. By selectively not forwarding certain transactions, the attacker can censor specific users or transaction types from reaching the broader network.

2. **Front-Running**: The attacker sees transactions before they're widely propagated, enabling front-running attacks in DeFi applications.

3. **Network Partitioning**: By controlling many peers and delaying/dropping broadcasts, the attacker can effectively partition the victim node from the network, causing it to fall behind in transaction propagation.

4. **Validator Performance Degradation**: For validator nodes, delayed transaction propagation impacts consensus participation and block proposal quality.

While this doesn't directly compromise consensus safety or cause fund loss, it severely degrades network performance and enables transaction-level attacks. The impact is amplified because mempool transaction propagation is critical for network liveness.

## Likelihood Explanation

**Likelihood: Medium-to-Low** (but HIGH impact when exploited)

**Prerequisites for exploitation**:
1. Victim node must have `enable_max_load_balancing_at_any_load = true` (default is `false`)
2. Victim node must configure high `num_sender_buckets` (default is 4, needs to be increased to ~255 for maximum impact)
3. Attacker must be able to connect many peers to the victim node

**Mitigating factors**:
- Default configuration is safe (`enable_max_load_balancing_at_any_load = false`, `num_sender_buckets = 4`)
- Requires explicit misconfiguration by node operator
- VFN nodes are less affected (they prioritize VFN network peers) [5](#0-4) 

**Aggravating factors**:
- The configuration option exists and may be enabled by operators seeking better load distribution
- Newly connected peers naturally lack latency data, making exploitation trivial
- No rate limiting on how many peers can be added to `top_peers`
- The vulnerability comment indicates developers recognized the load balancing concern but didn't address the security implications [6](#0-5) 

## Recommendation

**Fix the latency bypass vulnerability** by requiring latency data before adding peers to `top_peers`, or implementing a two-phase approach where peers without latency data are ranked lower.

**Recommended Fix**:

```rust
// In update_sender_bucket_for_peers(), replace lines 379-387 with:
if base_ping_latency.is_none() && ping_latency.is_none() {
    // Both lack latency data - only add if we haven't reached a minimum threshold
    // of peers with actual latency data
    if top_peers.len() < (num_top_peers as usize) / 2 {
        top_peers.push(*peer);
    }
} else if base_ping_latency.is_some() && ping_latency.is_none() {
    // This peer lacks latency but base exists - deprioritize but still consider
    // if we have capacity
    if top_peers.len() < num_top_peers as usize {
        top_peers.push(*peer);
    }
} else if let (Some(base), Some(current)) = (base_ping_latency, ping_latency) {
    // Both have latency - apply threshold check
    if current < base + (threshold_config.latency_slack_between_top_upstream_peers as f64) / 1000.0 {
        top_peers.push(*peer);
    }
}
```

**Alternative approach**: Cap `num_sender_buckets` to a safe maximum (e.g., 16) to limit the attack surface:

```rust
// In MempoolConfig::sanitize()
pub fn sanitize(
    node_config: &NodeConfig,
    _node_type: NodeType,
    _chain_id: Option<ChainId>,
) -> Result<(), Error> {
    let mempool = &node_config.mempool;
    
    // Cap num_sender_buckets to prevent peer flooding attacks
    if mempool.num_sender_buckets > 16 {
        return Err(Error::ConfigSanitizerFailed(
            "num_sender_buckets".to_string(),
            "Must be <= 16 to prevent peer flooding attacks".to_string(),
        ));
    }
    
    Ok(())
}
```

**Additional hardening**:
1. Add peer connection rate limiting
2. Implement minimum latency observation period before peer prioritization
3. Add metrics to detect when many peers lack latency data
4. Document the security implications of `enable_max_load_balancing_at_any_load`

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use aptos_config::config::{MempoolConfig, NodeType};
    use aptos_peer_monitoring_service_types::PeerMonitoringMetadata;
    use aptos_time_service::TimeService;
    use aptos_types::PeerId;
    use aptos_config::network_id::{NetworkId, PeerNetworkId};

    #[test]
    fn test_latency_bypass_attack() {
        // Configure mempool with vulnerable settings
        let mut mempool_config = MempoolConfig::default();
        mempool_config.enable_max_load_balancing_at_any_load = true;
        mempool_config.num_sender_buckets = 255; // Attacker's target configuration

        let time_service = TimeService::mock();
        let mut prioritized_peers_state = PrioritizedPeersState::new(
            mempool_config.clone(),
            NodeType::PublicFullnode,
            time_service.clone(),
        );

        // Attacker connects 255 malicious peers without latency data
        let mut malicious_peers = Vec::new();
        for _ in 0..255 {
            let peer = PeerNetworkId::new(NetworkId::Public, PeerId::random());
            // No latency data provided (attacker controls timing or doesn't respond to pings)
            malicious_peers.push((peer, None));
        }

        // Trigger peer prioritization update
        prioritized_peers_state.update_prioritized_peers(malicious_peers.clone(), 0, 0);

        // Verify all malicious peers are in top_peers (assigned sender buckets)
        let assigned_peers: Vec<_> = prioritized_peers_state
            .peer_to_sender_buckets
            .keys()
            .cloned()
            .collect();

        // Attack succeeds: all 255 malicious peers are assigned sender buckets
        assert_eq!(assigned_peers.len(), 255);
        
        // Verify transactions will be distributed across all attacker peers
        for bucket in 0..mempool_config.num_sender_buckets {
            let peer_with_bucket = prioritized_peers_state
                .peer_to_sender_buckets
                .iter()
                .find(|(_, buckets)| buckets.contains_key(&bucket));
            
            assert!(peer_with_bucket.is_some(), 
                "Bucket {} should be assigned to an attacker peer", bucket);
        }

        println!("Attack successful: {} malicious peers control transaction distribution",
                 assigned_peers.len());
    }
}
```

**Notes**:
- This vulnerability requires specific misconfiguration to exploit, but the default safety is not documented
- The `enable_max_load_balancing_at_any_load` flag was designed for performance (faster load balancing response), but introduces a security trade-off not mentioned in the configuration documentation
- VFN nodes have partial mitigation through preferential VFN peer selection, but PFNs are fully vulnerable
- The peer monitoring service populates latency data asynchronously, creating a time window where newly connected peers lack latency data and can be exploited

### Citations

**File:** mempool/src/shared_mempool/priority.rs (L319-329)
```rust
        let num_top_peers = max(
            1,
            min(
                self.mempool_config.num_sender_buckets,
                if self.mempool_config.enable_max_load_balancing_at_any_load {
                    u8::MAX
                } else {
                    threshold_config.max_number_of_upstream_peers
                },
            ),
        );
```

**File:** mempool/src/shared_mempool/priority.rs (L347-360)
```rust
        if self.node_type.is_validator_fullnode() {
            // Use the peer on the VFN network with lowest ping latency as the primary peer
            let peers_in_vfn_network = self
                .prioritized_peers
                .read()
                .iter()
                .cloned()
                .filter(|peer| peer.network_id() == NetworkId::Vfn)
                .collect::<Vec<_>>();

            if !peers_in_vfn_network.is_empty() {
                top_peers = vec![peers_in_vfn_network[0]];
            }
        }
```

**File:** mempool/src/shared_mempool/priority.rs (L379-387)
```rust
                if base_ping_latency.is_none()
                    || ping_latency.is_none()
                    || ping_latency.unwrap()
                        < base_ping_latency.unwrap()
                            + (threshold_config.latency_slack_between_top_upstream_peers as f64)
                                / 1000.0
                {
                    top_peers.push(*peer);
                }
```

**File:** mempool/src/shared_mempool/priority.rs (L401-409)
```rust
            // Assign sender buckets with Primary priority
            let mut peer_index = 0;
            for bucket_index in 0..self.mempool_config.num_sender_buckets {
                self.peer_to_sender_buckets
                    .entry(*top_peers.get(peer_index).unwrap())
                    .or_default()
                    .insert(bucket_index, BroadcastPeerPriority::Primary);
                peer_index = (peer_index + 1) % top_peers.len();
            }
```

**File:** mempool/src/shared_mempool/network.rs (L502-513)
```rust
                            self.prioritized_peers_state
                                .get_sender_buckets_for_peer(&peer)
                                .ok_or_else(|| {
                                    BroadcastError::PeerNotPrioritized(
                                        peer,
                                        self.prioritized_peers_state.get_peer_priority(&peer),
                                    )
                                })?
                                .clone()
                                .into_iter()
                                .collect()
                        };
```

**File:** config/src/config/mempool_config.rs (L100-103)
```rust
    /// When the load is low, PFNs send all the mempool traffic to only one upstream FN. When the load increases suddenly, PFNs will take
    /// up to 10 minutes (shared_mempool_priority_update_interval_secs) to enable the load balancing. If this flag is enabled,
    /// then the PFNs will always do load balancing irrespective of the load.
    pub enable_max_load_balancing_at_any_load: bool,
```
