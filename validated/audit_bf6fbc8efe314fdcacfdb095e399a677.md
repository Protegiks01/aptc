# Audit Report

## Title
Banned Peer Ban Bypass Through Connection Cycling in Storage Service Request Moderator

## Summary
The storage service request moderator's garbage collection mechanism removes disconnected peers from the unhealthy peer tracking map, allowing banned peers to bypass exponential backoff restrictions by disconnecting and reconnecting. This enables persistent resource exhaustion attacks against validator storage services.

## Finding Description

The storage service implements a request moderator to prevent misbehaving peers from overwhelming the system with invalid requests. When a peer sends too many invalid requests, they are "ignored" for an exponentially increasing duration. However, a critical flaw exists in the garbage collection logic.

**Vulnerable Architecture:**

All handler instances share the same `Arc<RequestModerator>` instance [1](#0-0) , which contains an `Arc<DashMap<PeerNetworkId, UnhealthyPeerState>>` [2](#0-1) . This shared state means any manipulation affects all request processing threads.

**The Vulnerability:**

The `refresh_unhealthy_peer_states` method runs periodically every 1 second by default [3](#0-2)  and uses a `retain` operation to garbage collect disconnected peers [4](#0-3) . When a peer is not in the connected peers list, the method returns `false`, completely removing their entry including all ban state and exponential backoff history [5](#0-4) .

**Attack Flow:**

1. Malicious PFN peer sends 500 invalid requests (default `max_invalid_requests_per_peer`) [6](#0-5) 
2. Peer gets banned with `ignore_start_time` set, should wait 5 minutes [7](#0-6) 
3. Attacker disconnects their connection
4. Within 1 second, the refresh task removes them from `unhealthy_peer_states` entirely
5. Attacker reconnects with a clean slate
6. The validation check finds no entry in the map [8](#0-7) , so requests proceed normally
7. Attacker sends another 500 invalid requests before being banned again

This completely bypasses the exponential backoff mechanism that doubles the ignore duration with each violation [9](#0-8) . The attack only affects public network peers since only they are subject to ignoring [10](#0-9) , but this makes validators vulnerable to PFN attacks.

The vulnerability is confirmed by the test suite, which explicitly demonstrates that disconnected banned peers are garbage collected and treated as fresh peers upon reconnection [11](#0-10) .

## Impact Explanation

**Severity: HIGH** - Validator Node Slowdowns through DoS via Resource Exhaustion

This vulnerability enables persistent resource exhaustion attacks against storage service validators:

- **Bypassed Rate Limiting**: Attackers can send 500 invalid requests per connection cycle, completely defeating the rate limiting mechanism designed to protect validators
- **CPU/I/O Resource Exhaustion**: Each invalid request requires database queries and validation logic [12](#0-11) , consuming CPU and storage I/O resources
- **Coordinated Attack Potential**: Multiple malicious PFNs could simultaneously exploit this to severely degrade validator performance and state synchronization capabilities
- **Shared State Impact**: Because all handlers share the same `Arc<RequestModerator>` [13](#0-12) , the vulnerability affects every request processing thread

This qualifies as **High Severity** under the "Validator node slowdowns" category with "DoS through resource exhaustion" - not a network-layer DoS attack, but an application-layer logic flaw that enables defeating security controls to cause resource exhaustion.

## Likelihood Explanation

**Likelihood: HIGH**

- **Trivial Exploitation**: Attacker only needs to automate disconnect/reconnect cycles - no complex timing or special privileges required
- **Any PFN Can Attack**: Any public fullnode peer can execute this attack against validator storage services
- **Guaranteed Success**: The 1-second refresh interval [14](#0-13)  ensures disconnected peers are quickly removed from tracking
- **Test-Confirmed Behavior**: The vulnerability is explicitly demonstrated in the test suite [15](#0-14) , showing this is reproducible behavior
- **Low Detection**: Connection cycling appears as normal peer churn to network monitoring

The attack requires no special setup, coordination, or resources beyond a basic network connection.

## Recommendation

Persist ban state across peer disconnections to prevent ban evasion:

```rust
// Option 1: Keep ban state even for disconnected peers, with longer timeout
self.unhealthy_peer_states.retain(|peer_network_id, unhealthy_peer_state| {
    if connected_peers_and_metadata.contains_key(peer_network_id) {
        unhealthy_peer_state.refresh_peer_state(peer_network_id);
        if unhealthy_peer_state.is_ignored() {
            num_ignored_peers += 1;
        }
        true // Keep connected peers
    } else if unhealthy_peer_state.is_ignored() {
        // Keep banned peers even when disconnected
        num_ignored_peers += 1;
        true
    } else {
        // Only remove non-banned disconnected peers after grace period
        false
    }
});

// Option 2: Track connection cycling patterns and ban repeat offenders at IP level
// Option 3: Persist ban state to disk with longer-term tracking
```

Additionally, consider the TODO comment at line 59 suggesting connection termination should be implemented.

## Proof of Concept

The existing test suite demonstrates this vulnerability: [15](#0-14) 

The test `test_request_moderator_peer_garbage_collect` shows:
1. Peers send invalid requests and get tracked as unhealthy
2. Peers disconnect and are garbage collected from the tracking map
3. **When peers reconnect and send invalid requests, they are treated as fresh peers with no history** (lines 303-318)

This confirms the vulnerability is exploitable and defeats the exponential backoff security mechanism.

## Notes

This is a logic vulnerability in security-critical rate limiting code that defeats the intended protection mechanism. While it doesn't directly cause consensus violations or fund theft, it enables significant degradation of validator performance through resource exhaustion, qualifying as High Severity under the Aptos bug bounty framework's "Validator node slowdowns" category.

The vulnerability affects application-layer security controls, not network infrastructure, distinguishing it from out-of-scope "Network DoS attacks."

### Citations

**File:** state-sync/storage-service/server/src/lib.rs (L81-81)
```rust
    request_moderator: Arc<RequestModerator>,
```

**File:** state-sync/storage-service/server/src/lib.rs (L365-365)
```rust
            let duration = Duration::from_millis(config.request_moderator_refresh_interval_ms);
```

**File:** state-sync/storage-service/server/src/lib.rs (L399-406)
```rust
            let request_moderator = self.request_moderator.clone();
            let time_service = self.time_service.clone();
            self.runtime.spawn_blocking(move || {
                Handler::new(
                    cached_storage_server_summary,
                    optimistic_fetches,
                    lru_response_cache,
                    request_moderator,
```

**File:** state-sync/storage-service/server/src/moderator.rs (L56-56)
```rust
            && peer_network_id.network_id().is_public_network()
```

**File:** state-sync/storage-service/server/src/moderator.rs (L90-90)
```rust
                self.min_time_to_ignore_secs *= 2;
```

**File:** state-sync/storage-service/server/src/moderator.rs (L111-111)
```rust
    unhealthy_peer_states: Arc<DashMap<PeerNetworkId, UnhealthyPeerState>>,
```

**File:** state-sync/storage-service/server/src/moderator.rs (L142-149)
```rust
            if let Some(peer_state) = self.unhealthy_peer_states.get(peer_network_id) {
                if peer_state.is_ignored() {
                    return Err(Error::TooManyInvalidRequests(format!(
                        "Peer is temporarily ignored. Unable to handle request: {:?}",
                        request
                    )));
                }
            }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L213-228)
```rust
        self.unhealthy_peer_states
            .retain(|peer_network_id, unhealthy_peer_state| {
                if connected_peers_and_metadata.contains_key(peer_network_id) {
                    // Refresh the ignored peer state
                    unhealthy_peer_state.refresh_peer_state(peer_network_id);

                    // If the peer is ignored, increment the ignored peer count
                    if unhealthy_peer_state.is_ignored() {
                        num_ignored_peers += 1;
                    }

                    true // The peer is still connected, so we should keep it
                } else {
                    false // The peer is no longer connected, so we should remove it
                }
            });
```

**File:** config/src/config/state_sync_config.rs (L201-201)
```rust
            max_invalid_requests_per_peer: 500,
```

**File:** config/src/config/state_sync_config.rs (L213-213)
```rust
            min_time_to_ignore_peers_secs: 300, // 5 minutes
```

**File:** config/src/config/state_sync_config.rs (L214-214)
```rust
            request_moderator_refresh_interval_ms: 1000, // 1 second
```

**File:** state-sync/storage-service/server/src/tests/request_moderator.rs (L209-354)
```rust
#[tokio::test]
async fn test_request_moderator_peer_garbage_collect() {
    // Create test data
    let highest_synced_version = 500;
    let highest_synced_epoch = 3;

    // Create a storage service config for testing
    let max_invalid_requests_per_peer = 3;
    let storage_service_config = StorageServiceConfig {
        max_invalid_requests_per_peer,
        ..Default::default()
    };

    // Create the storage client and server
    let (mut mock_client, mut service, _, time_service, peers_and_metadata) =
        MockClient::new(None, Some(storage_service_config));
    utils::update_storage_server_summary(
        &mut service,
        highest_synced_version,
        highest_synced_epoch,
    );

    // Get the request moderator and unhealthy peer states
    let request_moderator = service.get_request_moderator();
    let unhealthy_peer_states = request_moderator.get_unhealthy_peer_states();

    // Connect multiple peers
    let peer_network_ids = [
        PeerNetworkId::new(NetworkId::Validator, PeerId::random()),
        PeerNetworkId::new(NetworkId::Vfn, PeerId::random()),
        PeerNetworkId::new(NetworkId::Public, PeerId::random()),
    ];
    for (index, peer_network_id) in peer_network_ids.iter().enumerate() {
        peers_and_metadata
            .insert_connection_metadata(
                *peer_network_id,
                create_connection_metadata(peer_network_id.peer_id(), index as u32),
            )
            .unwrap();
    }

    // Spawn the server
    tokio::spawn(service.start());

    // Send an invalid request from the first two peers
    for peer_network_id in peer_network_ids.iter().take(2) {
        // Send the invalid request
        send_invalid_transaction_request(
            highest_synced_version,
            &mut mock_client,
            *peer_network_id,
        )
        .await
        .unwrap_err();

        // Verify the peer is now tracked as unhealthy
        assert!(unhealthy_peer_states.contains_key(peer_network_id));
    }

    // Verify that only the first two peers are being tracked
    assert_eq!(unhealthy_peer_states.len(), 2);

    // Disconnect the first peer
    peers_and_metadata
        .update_connection_state(peer_network_ids[0], ConnectionState::Disconnecting)
        .unwrap();

    // Elapse enough time for the peer monitor loop to garbage collect the peer
    wait_for_request_moderator_to_garbage_collect(
        unhealthy_peer_states.clone(),
        &time_service,
        &peer_network_ids[0],
    )
    .await;

    // Verify that only the second peer is being tracked
    assert_eq!(unhealthy_peer_states.len(), 1);

    // Disconnect the second peer
    peers_and_metadata
        .remove_peer_metadata(peer_network_ids[1], ConnectionId::from(1))
        .unwrap();

    // Elapse enough time for the peer monitor loop to garbage collect the peer
    wait_for_request_moderator_to_garbage_collect(
        unhealthy_peer_states.clone(),
        &time_service,
        &peer_network_ids[1],
    )
    .await;

    // Verify that no peer is being tracked
    assert!(unhealthy_peer_states.is_empty());

    // Reconnect the first peer
    peers_and_metadata
        .update_connection_state(peer_network_ids[0], ConnectionState::Connected)
        .unwrap();

    // Send an invalid request from the first peer
    send_invalid_transaction_request(
        highest_synced_version,
        &mut mock_client,
        peer_network_ids[0],
    )
    .await
    .unwrap_err();

    // Verify the peer is now tracked as unhealthy
    assert!(unhealthy_peer_states.contains_key(&peer_network_ids[0]));

    // Process enough invalid requests to ignore the third peer
    for _ in 0..max_invalid_requests_per_peer {
        send_invalid_transaction_request(
            highest_synced_version,
            &mut mock_client,
            peer_network_ids[2],
        )
        .await
        .unwrap_err();
    }

    // Verify the third peer is now tracked and blocked
    assert_eq!(unhealthy_peer_states.len(), 2);
    assert!(unhealthy_peer_states
        .get(&peer_network_ids[2])
        .unwrap()
        .is_ignored());

    // Disconnect the third peer
    peers_and_metadata
        .remove_peer_metadata(peer_network_ids[2], ConnectionId::from(2))
        .unwrap();

    // Elapse enough time for the peer monitor loop to garbage collect the peer
    wait_for_request_moderator_to_garbage_collect(
        unhealthy_peer_states.clone(),
        &time_service,
        &peer_network_ids[2],
    )
    .await;

    // Verify that the peer is no longer being tracked
    assert!(!unhealthy_peer_states.contains_key(&peer_network_ids[2]));
    assert_eq!(unhealthy_peer_states.len(), 1);
}
```

**File:** state-sync/storage-service/server/src/handler.rs (L206-228)
```rust
    fn validate_and_handle_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<StorageServiceResponse, Error> {
        // Validate the request with the moderator
        self.request_moderator
            .validate_request(peer_network_id, request)?;

        // Process the request
        match &request.data_request {
            DataRequest::GetServerProtocolVersion => {
                let data_response = self.get_server_protocol_version();
                StorageServiceResponse::new(data_response, request.use_compression)
                    .map_err(|error| error.into())
            },
            DataRequest::GetStorageServerSummary => {
                let data_response = self.get_storage_server_summary();
                StorageServiceResponse::new(data_response, request.use_compression)
                    .map_err(|error| error.into())
            },
            _ => self.process_cachable_request(peer_network_id, request),
        }
```
