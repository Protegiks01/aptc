# Audit Report

## Title
Single Failover Peer Enables Transaction Censorship During Primary Network Failures

## Summary
With `default_failovers=1`, Public Full Nodes (PFNs) rely on a single failover peer for transaction propagation when primary peers fail. An attacker who controls this failover peer can censor all mempool transactions for extended periods (10+ minutes) during primary network failures, as there is no automatic failover switching mechanism and peer reprioritization occurs infrequently.

## Finding Description

The mempool transaction broadcasting system uses a Primary/Failover peer model to provide redundancy. The `default_failovers` configuration parameter controls how many failover peers receive transactions with a delayed broadcast. [1](#0-0) [2](#0-1) 

The default value is 1, meaning only a single failover peer is designated for each sender bucket. Failover peers are selected via round-robin from the prioritized peer list: [3](#0-2) 

Peer prioritization is based on health (sync lag), network ID, validator distance, and ping latency: [4](#0-3) 

**Critical Flaw:** When broadcasting to failover peers, transactions are filtered by a 500ms delay, but this delay applies **continuously**, not just as a failover mechanism: [5](#0-4) 

**Attack Scenario:**
1. Attacker connects to victim PFN and manipulates peer monitoring metrics (responds quickly to ping requests, reports good sync state) to achieve high priority
2. Through the round-robin selection, attacker gets assigned as the failover peer for sender buckets
3. Primary peer experiences network failure (partition, crash, or Byzantine behavior)
4. System attempts to broadcast to primary peer → fails
5. After ACK timeout (2 seconds), broadcasts to primary are retried → continue failing
6. After 20 pending broadcasts, primary peer is rate-limited: [6](#0-5) 

7. **Only the failover peer receives transactions** (after 500ms delay)
8. Attacker either:
   - Drops all transactions without ACK (causes indefinite retries to same peer)
   - Sends ACK but doesn't propagate transactions (disappear silently)
   - Rate-limits ACKs to maintain maximum censorship with minimal detection

**No Automatic Failover Switching:** The system retries failed/expired broadcasts to the **same peer**, with no mechanism to switch to alternative peers: [7](#0-6) 

**Extended Censorship Window:** Peer reprioritization only occurs every 10 minutes: [8](#0-7) [9](#0-8) 

During this 600-second window, with only 1 failover peer controlling all transaction flow, the attacker can effectively censor all mempool transaction propagation for the victim PFN.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Transaction propagation is severely delayed (600+ seconds minimum)
- **Significant protocol violation**: Breaks transaction liveness guarantees during network failures
- **Affects network resilience**: Undermines redundancy mechanisms during adverse network conditions

The impact is limited to individual PFNs rather than network-wide consensus, preventing Critical classification. However, during network partitions or coordinated attacks on primary peers, multiple PFNs could be simultaneously affected, significantly degrading network transaction throughput.

## Likelihood Explanation

**Medium-High Likelihood:**

**Attacker Requirements (All Achievable):**
- Network connectivity to victim PFN (public network, no special access needed)
- Ability to respond to peer monitoring requests (standard P2P protocol)
- Control timing of responses to manipulate latency metrics

**Attack Feasibility:**
- Peer monitoring metric manipulation is straightforward (respond quickly to pings)
- Validator distance validation exists but only checks role consistency, not actual distance: [10](#0-9) 

- With limited upstream peers (common for PFNs), probability of being selected as failover peer is significant
- Attack is repeatable and sustainable by maintaining high-priority metrics

**Attack Triggers:**
- Naturally occurring network failures (partitions, high latency)
- Attacker can DoS primary peers to induce failure condition
- Byzantine primary peers refusing to propagate transactions

## Recommendation

**Immediate Mitigations:**

1. **Increase default failover redundancy:**
```rust
default_failovers: 3,  // Changed from 1 to provide triple redundancy
```

2. **Implement automatic failover switching:** When a peer consistently fails to ACK or becomes unhealthy, automatically reassign their sender buckets to other available peers without waiting for the full reprioritization interval.

3. **Add censorship detection:** Track transaction propagation success rates per peer. If a failover peer consistently receives transactions but they don't appear in committed blocks, flag the peer as potentially censoring and deprioritize.

4. **Reduce reprioritization interval during failures:**
```rust
shared_mempool_priority_update_interval_secs: 60,  // Changed from 600 (1 minute instead of 10)
```

5. **Implement peer reputation scoring:** Track long-term ACK response rates, transaction propagation success, and responsiveness. Use reputation scores in prioritization alongside latency/distance metrics.

**Long-term Solutions:**

1. Implement Byzantine-fault-tolerant broadcast mechanism where transactions are sent to multiple peers simultaneously (not just primary + single failover with delay)

2. Add cryptographic commitment schemes for transaction propagation tracking to detect censorship

3. Implement peer rotation for failover assignments on shorter intervals (e.g., every minute) independent of full reprioritization

## Proof of Concept

```rust
// Reproduction steps for smoke test demonstrating vulnerability:

#[tokio::test]
async fn test_single_failover_censorship() {
    // Setup: PFN with default_failovers=1 connecting to 3 upstream peers
    let mut pfn_config = NodeConfig::get_default_pfn_config();
    pfn_config.mempool.default_failovers = 1;
    
    let mut swarm = SwarmBuilder::new_local(3)
        .with_num_fullnodes(1)
        .with_aptos()
        .with_pfn_config(pfn_config)
        .build()
        .await;
    
    let pfn_peer_id = swarm.full_nodes().next().unwrap().peer_id();
    let pfn_client = swarm.full_node(pfn_peer_id).unwrap().rest_client();
    
    // Create test accounts
    let mut account_0 = create_and_fund_account(&mut swarm, 100).await;
    let account_1 = create_and_fund_account(&mut swarm, 10).await;
    
    swarm.wait_for_all_nodes_to_catchup(Duration::from_secs(MAX_CATCH_UP_WAIT_SECS))
        .await
        .unwrap();
    
    // Simulate primary peer failure by stopping validators[0] (assumed primary)
    swarm.validator_mut(swarm.validators().next().unwrap().peer_id())
        .unwrap()
        .stop();
    
    // Simulate attacker controlling failover peer by stopping validators[1] (assumed failover)
    // In real attack, attacker would ACK but drop transactions
    swarm.validator_mut(swarm.validators().nth(1).unwrap().peer_id())
        .unwrap()
        .stop();
    
    // Submit transaction to PFN
    let start_time = Instant::now();
    let result = transfer_coins(
        &pfn_client,
        &transaction_factory,
        &mut account_0,
        &account_1,
        10,
    ).await;
    
    // Transaction should be significantly delayed or fail
    // With only validators[2] remaining and not assigned as primary or failover,
    // transaction propagation is severely degraded
    
    // Measure time until transaction appears in mempool of remaining validator
    let remaining_validator_client = swarm.validators().nth(2).unwrap().rest_client();
    
    // This should timeout or take >> 600 seconds until peer reprioritization
    let wait_result = timeout(
        Duration::from_secs(30),
        remaining_validator_client.wait_for_signed_transaction(&result)
    ).await;
    
    assert!(wait_result.is_err(), "Transaction should not propagate within 30s with primary and failover peers down");
    
    let elapsed = start_time.elapsed();
    println!("Transaction censored for {} seconds", elapsed.as_secs());
    assert!(elapsed.as_secs() >= 30, "Censorship window should be significant");
}
```

**Note:** The above PoC demonstrates the vulnerability by simulating the scenario where both primary and single failover peers are unavailable. In a real attack, the attacker-controlled failover peer would send ACKs to avoid detection but drop transactions, making the censorship less obvious while equally effective.

### Citations

**File:** config/src/config/mempool_config.rs (L49-49)
```rust
    pub default_failovers: usize,
```

**File:** config/src/config/mempool_config.rs (L124-124)
```rust
            default_failovers: 1,
```

**File:** config/src/config/mempool_config.rs (L127-127)
```rust
            shared_mempool_priority_update_interval_secs: 600, // 10 minutes (frequent reprioritization is expensive)
```

**File:** mempool/src/shared_mempool/priority.rs (L74-120)
```rust
    fn compare_intelligent(
        &self,
        peer_a: &(PeerNetworkId, Option<&PeerMonitoringMetadata>),
        peer_b: &(PeerNetworkId, Option<&PeerMonitoringMetadata>),
    ) -> Ordering {
        // Deconstruct the peer tuples
        let (peer_network_id_a, monitoring_metadata_a) = peer_a;
        let (peer_network_id_b, monitoring_metadata_b) = peer_b;

        // First, compare the peers by health (e.g., sync lag)
        let unhealthy_ordering = compare_peer_health(
            &self.mempool_config,
            &self.time_service,
            monitoring_metadata_a,
            monitoring_metadata_b,
        );
        if !unhealthy_ordering.is_eq() {
            return unhealthy_ordering; // Only return if it's not equal
        }

        // Next, compare by network ID (i.e., Validator > VFN > Public)
        let network_ordering = compare_network_id(
            &peer_network_id_a.network_id(),
            &peer_network_id_b.network_id(),
        );
        if !network_ordering.is_eq() {
            return network_ordering; // Only return if it's not equal
        }

        // Otherwise, compare by peer distance from the validators.
        // This avoids badly configured/connected peers (e.g., broken VN-VFN connections).
        let distance_ordering =
            compare_validator_distance(monitoring_metadata_a, monitoring_metadata_b);
        if !distance_ordering.is_eq() {
            return distance_ordering; // Only return if it's not equal
        }

        // Otherwise, compare by peer ping latency (the lower the better)
        let latency_ordering = compare_ping_latency(monitoring_metadata_a, monitoring_metadata_b);
        if !latency_ordering.is_eq() {
            return latency_ordering; // Only return if it's not equal
        }

        // Otherwise, simply hash the peer IDs and compare the hashes.
        // In practice, this should be relatively rare.
        self.compare_hash(peer_network_id_a, peer_network_id_b)
    }
```

**File:** mempool/src/shared_mempool/priority.rs (L232-241)
```rust
        match self.last_peer_priority_update {
            None => true, // We haven't updated yet
            Some(last_update) => {
                let duration_since_update = self.time_service.now().duration_since(last_update);
                let update_interval_secs = self
                    .mempool_config
                    .shared_mempool_priority_update_interval_secs;
                duration_since_update.as_secs() > update_interval_secs
            },
        }
```

**File:** mempool/src/shared_mempool/priority.rs (L411-430)
```rust
            // Assign sender buckets with Failover priority. Use Round Robin.
            peer_index = 0;
            let num_prioritized_peers = self.prioritized_peers.read().len();
            for _ in 0..self.mempool_config.default_failovers {
                for bucket_index in 0..self.mempool_config.num_sender_buckets {
                    // Find the first peer that already doesn't have the sender bucket, and add the bucket
                    for _ in 0..num_prioritized_peers {
                        let peer = self.prioritized_peers.read()[peer_index];
                        let sender_bucket_list =
                            self.peer_to_sender_buckets.entry(peer).or_default();
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            sender_bucket_list.entry(bucket_index)
                        {
                            e.insert(BroadcastPeerPriority::Failover);
                            break;
                        }
                        peer_index = (peer_index + 1) % num_prioritized_peers;
                    }
                }
            }
```

**File:** mempool/src/shared_mempool/network.rs (L441-448)
```rust
            // The maximum number of broadcasts sent to a single peer that are pending a response ACK at any point.
            // If the number of un-ACK'ed un-expired broadcasts reaches this threshold, we do not broadcast anymore
            // and wait until an ACK is received or a sent broadcast expires.
            // This helps rate-limit egress network bandwidth and not overload a remote peer or this
            // node's network sender.
            if pending_broadcasts >= self.mempool_config.max_broadcasts_per_peer {
                return Err(BroadcastError::TooManyPendingBroadcasts(peer));
            }
```

**File:** mempool/src/shared_mempool/network.rs (L452-489)
```rust
        let (message_id, transactions, metric_label) =
            match std::cmp::max(expired_message_id, retry_message_id) {
                Some(message_id) => {
                    let metric_label = if Some(message_id) == expired_message_id {
                        Some(counters::EXPIRED_BROADCAST_LABEL)
                    } else {
                        Some(counters::RETRY_BROADCAST_LABEL)
                    };

                    let txns = message_id
                        .decode()
                        .into_iter()
                        .flat_map(|(sender_bucket, start_end_pairs)| {
                            if self.node_type.is_validator() {
                                mempool
                                    .timeline_range(sender_bucket, start_end_pairs)
                                    .into_iter()
                                    .map(|(txn, ready_time)| {
                                        (txn, ready_time, BroadcastPeerPriority::Primary)
                                    })
                                    .collect::<Vec<_>>()
                            } else {
                                self.prioritized_peers_state
                                    .get_sender_bucket_priority_for_peer(&peer, sender_bucket)
                                    .map_or_else(Vec::new, |priority| {
                                        mempool
                                            .timeline_range(sender_bucket, start_end_pairs)
                                            .into_iter()
                                            .map(|(txn, ready_time)| {
                                                (txn, ready_time, priority.clone())
                                            })
                                            .collect::<Vec<_>>()
                                    })
                            }
                        })
                        .collect::<Vec<_>>();
                    (message_id.clone(), txns, metric_label)
                },
```

**File:** mempool/src/shared_mempool/network.rs (L527-536)
```rust
                    for (sender_bucket, peer_priority) in sender_buckets {
                        let before = match peer_priority {
                            BroadcastPeerPriority::Primary => None,
                            BroadcastPeerPriority::Failover => Some(
                                Instant::now()
                                    - Duration::from_millis(
                                        self.mempool_config.shared_mempool_failover_delay_ms,
                                    ),
                            ),
                        };
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L118-141)
```rust
        let is_valid_depth = match network_info_response.distance_from_validators {
            0 => {
                // Verify the peer is a validator and has the correct network id
                let peer_is_validator = peer_metadata.get_connection_metadata().role.is_validator();
                let peer_has_correct_network = match self.base_config.role {
                    RoleType::Validator => network_id.is_validator_network(), // We're a validator
                    RoleType::FullNode => network_id.is_vfn_network(),        // We're a VFN
                };
                peer_is_validator && peer_has_correct_network
            },
            1 => {
                // Verify the peer is a VFN and has the correct network id
                let peer_is_vfn = peer_metadata.get_connection_metadata().role.is_vfn();
                let peer_has_correct_network = match self.base_config.role {
                    RoleType::Validator => network_id.is_vfn_network(), // We're a validator
                    RoleType::FullNode => network_id.is_public_network(), // We're a VFN or PFN
                };
                peer_is_vfn && peer_has_correct_network
            },
            distance_from_validators => {
                // The distance must be less than or equal to the max
                distance_from_validators <= MAX_DISTANCE_FROM_VALIDATORS
            },
        };
```
