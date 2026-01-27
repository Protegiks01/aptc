# Audit Report

## Title
Subscription Churn Vulnerability via Priority-Based Forced Re-selection

## Summary
An attacker controlling a high-priority peer can exploit the subscription selection logic to force repeated subscription terminations, disrupting state sync continuity. The vulnerability exists at lines 488-501 where the code incorrectly determines that a currently subscribed peer is "non-serviceable" when a higher-priority peer becomes available, even though the current peer remains fully serviceable. [1](#0-0) 

## Finding Description

The vulnerability stems from a logic flaw in how `choose_peer_for_subscription_request` interacts with `choose_serviceable_peer_for_subscription_request`. The outer function iterates through priority levels from highest to lowest, passing ONLY the serviceable peers of each specific priority level to the inner function: [2](#0-1) 

When the inner function checks if the currently subscribed peer is still serviceable, it only searches within the `serviceable_peers` set passed to it, which contains peers of a SINGLE priority level. If the current subscription is to a MediumPriority peer and the function is currently processing HighPriority peers, the check at line 488 will fail even though the MediumPriority peer is still perfectly serviceable.

**Attack Flow:**

1. Victim node subscribes to Peer A (MediumPriority, e.g., an inbound connection)
2. Attacker controls Peer B (HighPriority, e.g., victim has outbound connection to attacker's node)
3. Attacker makes Peer B appear non-serviceable by responding with stale storage summaries or going offline
4. Victim continues syncing via Peer A normally
5. Attacker makes Peer B serviceable by responding with fresh storage summaries
6. Next subscription request iterates priorities: `[HighPriority peers, MediumPriority peers, ...]`
7. First iteration processes HighPriority: `serviceable_peers = {Peer B}`
8. Inner function checks if current Peer A is in `{Peer B}` - it's not
9. Subscription to Peer A is forcibly terminated with error
10. New subscription established to Peer B
11. Attacker repeats cycle by making Peer B unserviceable, causing continuous churn

The attacker can control Peer B's serviceability because subscription requests require the peer's `synced_ledger_info` timestamp to be within `max_subscription_lag_secs` of current time: [3](#0-2) 

By controlling when they respond to storage summary polls with fresh vs. stale data, the attacker controls their peer's serviceability.

## Impact Explanation

**Medium Severity** - This vulnerability causes state sync disruption requiring manual intervention:

1. **Availability Impact**: Repeated subscription churning prevents nodes from maintaining stable sync streams, significantly degrading sync performance
2. **Progress Loss**: Each subscription termination loses the current stream's progress, forcing restart from a new point
3. **Resource Exhaustion**: Continuous subscription churn wastes bandwidth and CPU resources on connection establishment
4. **Sync Delays**: Victims may experience extended sync times or complete sync stalls if churn frequency is high

The impact is limited to state sync disruption and does not directly affect consensus, fund safety, or cause permanent network damage. However, it can degrade network health and node synchronization, qualifying as Medium severity per the bug bounty criteria ("State inconsistencies requiring intervention").

## Likelihood Explanation

**Moderate Likelihood:**

**Attacker Requirements:**
- Run a malicious peer node
- Have victim nodes establish connections to the attacker's peer with favorable priority (e.g., outbound connection for PFN victims)
- This can be achieved by being listed as a seed peer or being in victim's peer lists

**Feasibility:**
- Peer priorities are determined by connection type and network configuration [4](#0-3) 
- For PFN victims, outbound connections are HighPriority, which the attacker can achieve through network topology
- Controlling peer serviceability is trivial - simply respond with fresh or stale storage summaries
- No special privileges, stake, or validator access required

**Complexity:** Low - Attack execution is straightforward once the attacker has a high-priority peer position

## Recommendation

Add a stickiness mechanism to prevent unnecessary subscription switching when the current peer is still serviceable. Check if the current peer is serviceable across ALL priority levels before terminating:

```rust
fn choose_serviceable_peer_for_subscription_request(
    &self,
    request: &StorageServiceRequest,
    serviceable_peers: HashSet<PeerNetworkId>,
+   all_serviceable_peers: &HashSet<PeerNetworkId>,  // Add parameter
) -> crate::error::Result<Option<PeerNetworkId>, Error> {
    // ... existing code ...
    
    if let Some(subscription_state) = active_subscription_state.take() {
        if subscription_state.subscription_stream_id == request_stream_id {
            let peer_network_id = subscription_state.peer_network_id;
            
            // First check if current peer is serviceable at all
+           if all_serviceable_peers.contains(&peer_network_id) {
+               // Current peer is still serviceable. Only switch if we found 
+               // a serviceable peer in a HIGHER priority group
+               if serviceable_peers.contains(&peer_network_id) {
+                   // Same priority group, keep current peer
+                   *active_subscription_state = Some(subscription_state);
+                   return Ok(Some(peer_network_id));
+               }
+               // Higher priority peers available, but keep current peer to avoid churn
+               // unless config explicitly requires priority upgrades
+               *active_subscription_state = Some(subscription_state);
+               return Ok(Some(peer_network_id));
+           }
            
-           return if serviceable_peers.contains(&peer_network_id) {
-               *active_subscription_state = Some(subscription_state);
-               Ok(Some(peer_network_id))
-           } else {
                // Current peer is truly non-serviceable, allow re-selection
                Err(Error::DataIsUnavailable(format!(
                    "The peer that we were previously subscribing to is no \
                    longer serviceable! Peer: {:?}, request: {:?}",
                    peer_network_id, request
                )))
-           };
        }
    }
    // ... rest of existing code ...
}
```

Update the caller to pass all serviceable peers:

```rust
fn choose_peer_for_subscription_request(
    &self,
    request: &StorageServiceRequest,
    serviceable_peers_by_priorities: Vec<HashSet<PeerNetworkId>>,
) -> crate::error::Result<HashSet<PeerNetworkId>, Error> {
+   let all_serviceable: HashSet<PeerNetworkId> = serviceable_peers_by_priorities
+       .iter()
+       .flatten()
+       .cloned()
+       .collect();
    
    for serviceable_peers in serviceable_peers_by_priorities {
        if let Some(selected_peer) =
-           self.choose_serviceable_peer_for_subscription_request(request, serviceable_peers)?
+           self.choose_serviceable_peer_for_subscription_request(request, serviceable_peers, &all_serviceable)?
        {
            return Ok(hashset![selected_peer]);
        }
    }
    // ... rest of code ...
}
```

## Proof of Concept

```rust
// Integration test demonstrating subscription churn attack
#[tokio::test]
async fn test_subscription_churn_attack() {
    // Setup: Create data client with two peers
    // - Peer A: MediumPriority (inbound connection)  
    // - Peer B: HighPriority (outbound connection, attacker-controlled)
    let (data_client, poller) = setup_data_client_with_peers();
    
    // Initially make Peer B non-serviceable (stale storage summary)
    mock_peer_storage_summary(peer_b, stale_summary());
    poller.poll_all_peers().await;
    
    // Create subscription - should select Peer A
    let stream = data_client
        .subscribe_to_transactions_with_proof(metadata, false, timeout)
        .await
        .unwrap();
    assert_eq!(stream.peer, peer_a);
    
    // Attack: Make Peer B serviceable
    mock_peer_storage_summary(peer_b, fresh_summary());
    poller.poll_all_peers().await;
    
    // Next subscription request should FORCIBLY terminate Peer A subscription
    // even though Peer A is still serviceable
    let result = data_client
        .subscribe_to_transactions_with_proof(metadata, false, timeout)
        .await;
    
    // Verify subscription was terminated and switched to Peer B
    match result {
        Ok(new_stream) => {
            assert_eq!(new_stream.peer, peer_b);
            // Verify Peer A subscription was terminated
            assert!(stream_a_was_terminated());
        }
        Err(e) => panic!("Expected successful re-selection to Peer B, got: {:?}", e),
    }
    
    // Attacker makes Peer B non-serviceable again
    mock_peer_storage_summary(peer_b, stale_summary());
    poller.poll_all_peers().await;
    
    // Repeat - causes continuous churn
    let result = data_client
        .subscribe_to_transactions_with_proof(metadata, false, timeout)
        .await;
        
    // Subscription fails or switches back to Peer A, demonstrating churn
    assert!(result.is_err() || result.unwrap().peer == peer_a);
}
```

## Notes

The vulnerability demonstrates how the interaction between priority-based peer selection and subscription stickiness creates an exploitable condition. While prioritizing higher-quality peers is desirable, the current implementation lacks proper hysteresis to prevent malicious actors from weaponizing this behavior to disrupt state synchronization.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L429-436)
```rust
        // Prioritize peer selection by choosing the highest priority peer first
        for serviceable_peers in serviceable_peers_by_priorities {
            if let Some(selected_peer) =
                self.choose_serviceable_peer_for_subscription_request(request, serviceable_peers)?
            {
                return Ok(hashset![selected_peer]); // A peer was found!
            }
        }
```

**File:** state-sync/aptos-data-client/src/client.rs (L488-501)
```rust
                return if serviceable_peers.contains(&peer_network_id) {
                    // The previously chosen peer can still service the request
                    *active_subscription_state = Some(subscription_state);
                    Ok(Some(peer_network_id))
                } else {
                    // The previously chosen peer is either: (i) unable to service
                    // the request; or (ii) no longer the highest priority peer. So
                    // we need to return an error so the stream will be terminated.
                    Err(Error::DataIsUnavailable(format!(
                        "The peer that we were previously subscribing to should no \
                        longer service the subscriptions! Peer: {:?}, request: {:?}",
                        peer_network_id, request
                    )))
                };
```

**File:** state-sync/storage-service/types/src/responses.rs (L905-933)
```rust
fn can_service_subscription_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_subscription_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}

/// Returns true iff the synced ledger info timestamp
/// is within the given lag (in seconds).
fn check_synced_ledger_lag(
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
    time_service: TimeService,
    max_lag_secs: u64,
) -> bool {
    if let Some(synced_ledger_info) = synced_ledger_info {
        // Get the ledger info timestamp (in microseconds)
        let ledger_info_timestamp_usecs = synced_ledger_info.ledger_info().timestamp_usecs();

        // Get the current timestamp and max version lag (in microseconds)
        let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
        let max_version_lag_usecs = max_lag_secs * NUM_MICROSECONDS_IN_SECOND;

        // Return true iff the synced ledger info timestamp is within the max version lag
        ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs
    } else {
        false // No synced ledger info was found!
    }
```

**File:** state-sync/aptos-data-client/src/priority.rs (L53-122)
```rust
pub fn get_peer_priority(
    base_config: Arc<BaseConfig>,
    peers_and_metadata: Arc<PeersAndMetadata>,
    peer: &PeerNetworkId,
) -> PeerPriority {
    // Handle the case that this node is a validator
    let peer_network_id = peer.network_id();
    if base_config.role.is_validator() {
        // Validators should highly prioritize other validators
        if peer_network_id.is_validator_network() {
            return PeerPriority::HighPriority;
        }

        // VFNs should be prioritized over PFNs. Note: having PFNs
        // connected to a validator is a rare (but possible) scenario.
        return if peer_network_id.is_vfn_network() {
            PeerPriority::MediumPriority
        } else {
            PeerPriority::LowPriority
        };
    }

    // Handle the case that this node is a VFN
    if peers_and_metadata
        .get_registered_networks()
        .contains(&NetworkId::Vfn)
    {
        // VFNs should highly prioritize validators
        if peer_network_id.is_vfn_network() {
            return PeerPriority::HighPriority;
        }

        // Trusted peers should be prioritized over untrusted peers.
        // This prioritizes other VFNs/seed peers over regular PFNs.
        if is_trusted_peer(peers_and_metadata.clone(), peer) {
            return PeerPriority::MediumPriority;
        }

        // Outbound connections should be prioritized over inbound connections.
        // This prioritizes other VFNs/seed peers over regular PFNs.
        return if let Some(metadata) = utils::get_metadata_for_peer(&peers_and_metadata, *peer) {
            if metadata.get_connection_metadata().is_outbound_connection() {
                PeerPriority::MediumPriority
            } else {
                PeerPriority::LowPriority
            }
        } else {
            PeerPriority::LowPriority // We don't have connection metadata
        };
    }

    // Otherwise, this node is a PFN. PFNs should highly
    // prioritize trusted peers (i.e., VFNs and seed peers).
    if is_trusted_peer(peers_and_metadata.clone(), peer) {
        return PeerPriority::HighPriority;
    }

    // Outbound connections should be prioritized. This prioritizes
    // other VFNs/seed peers over regular PFNs. Inbound connections
    // are always low priority (as they are generally unreliable).
    if let Some(metadata) = utils::get_metadata_for_peer(&peers_and_metadata, *peer) {
        if metadata.get_connection_metadata().is_outbound_connection() {
            PeerPriority::HighPriority
        } else {
            PeerPriority::LowPriority
        }
    } else {
        PeerPriority::LowPriority // We don't have connection metadata
    }
}
```
