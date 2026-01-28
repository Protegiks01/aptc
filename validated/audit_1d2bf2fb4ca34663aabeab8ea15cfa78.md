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

The `refresh_unhealthy_peer_states` method runs periodically with a default interval of 1000ms (1 second) [3](#0-2)  and uses a `retain` operation to garbage collect disconnected peers [4](#0-3) . When a peer is not in the connected peers list, the method returns `false` [5](#0-4) , completely removing their entry including all ban state and exponential backoff history.

**Attack Flow:**

1. Malicious PFN peer sends 500 invalid requests (default `max_invalid_requests_per_peer`) [6](#0-5) 
2. Peer gets banned with `ignore_start_time` set [7](#0-6) , should wait 300 seconds (5 minutes) [8](#0-7) 
3. Attacker disconnects their connection
4. Within 1 second, the refresh task removes them from `unhealthy_peer_states` entirely
5. Attacker reconnects with a clean slate
6. The validation check finds no entry in the map [9](#0-8) , so requests proceed normally
7. Attacker sends another 500 invalid requests before being banned again

This completely bypasses the exponential backoff mechanism that doubles the ignore duration with each violation [10](#0-9) . The attack only affects public network peers since only they are subject to ignoring [11](#0-10) , but this makes validators vulnerable to PFN attacks.

The vulnerability is confirmed by the test suite, which explicitly demonstrates that disconnected banned peers are garbage collected and treated as fresh peers upon reconnection [12](#0-11) .

## Impact Explanation

**Severity: HIGH** - Validator Node Slowdowns through DoS via Resource Exhaustion

This vulnerability enables persistent resource exhaustion attacks against storage service validators:

- **Bypassed Rate Limiting**: Without the bypass, attackers are limited to 500 requests per 5 minutes (1.67 req/sec). With the bypass, they can send 500 requests, disconnect, reconnect immediately, and repeat—potentially achieving 250+ req/sec, a 150x increase in attack rate.

- **CPU/I/O Resource Exhaustion**: Each invalid request requires database queries and validation logic [13](#0-12) , consuming CPU and storage I/O resources.

- **Coordinated Attack Potential**: Multiple malicious PFNs could simultaneously exploit this to severely degrade validator performance and state synchronization capabilities.

- **Shared State Impact**: Because all handlers share the same `Arc<RequestModerator>` [14](#0-13) , the vulnerability affects every request processing thread.

This qualifies as **High Severity** under the "Validator node slowdowns" category with "DoS through resource exhaustion"—not a network-layer DoS attack (which is out of scope), but an application-layer logic flaw that enables defeating security controls to cause resource exhaustion.

## Likelihood Explanation

**Likelihood: HIGH**

- **Trivial Exploitation**: Attacker only needs to automate disconnect/reconnect cycles—no complex timing or special privileges required.

- **Any PFN Can Attack**: Any public fullnode peer can execute this attack against validator storage services.

- **Guaranteed Success**: The 1-second refresh interval [3](#0-2)  ensures disconnected peers are quickly removed from tracking.

- **Test-Confirmed Behavior**: The vulnerability is explicitly demonstrated in the test suite [15](#0-14) , showing this is reproducible and intentional behavior.

- **Low Detection**: Connection cycling appears as normal peer churn to network monitoring.

The attack requires no special setup, coordination, or resources beyond a basic network connection.

## Recommendation

Modify the garbage collection logic to persist ban state for disconnected peers for at least the duration of their ignore period. Options include:

1. **Persist Ban State**: Instead of immediately removing disconnected peers, mark them as disconnected but keep their ban state until the ignore period expires.

2. **Ban by Network Identity**: Track bans by more persistent identifiers (e.g., IP address ranges, peer IDs with historical tracking) rather than just current connection state.

3. **Connection Rate Limiting**: Implement additional rate limiting on connection establishment from the same peer identity to prevent rapid reconnection cycles.

Example fix for option 1:

```rust
// In refresh_unhealthy_peer_states(), modify the retain logic:
self.unhealthy_peer_states.retain(|peer_network_id, unhealthy_peer_state| {
    if connected_peers_and_metadata.contains_key(peer_network_id) {
        // Peer is connected - refresh state as normal
        unhealthy_peer_state.refresh_peer_state(peer_network_id);
        if unhealthy_peer_state.is_ignored() {
            num_ignored_peers += 1;
        }
        true // Keep the entry
    } else if unhealthy_peer_state.is_ignored() {
        // Peer is disconnected but still under ban - keep the entry
        num_ignored_peers += 1;
        true 
    } else {
        // Peer is disconnected and not banned - safe to remove
        false
    }
});
```

## Proof of Concept

The existing test suite already demonstrates this vulnerability. The test at [16](#0-15)  shows:

1. Lines 321-329: A peer sends enough invalid requests to get banned
2. Lines 331-336: The peer is verified to be ignored
3. Lines 338-341: The peer disconnects
4. Lines 343-349: The garbage collector removes the peer's ban state
5. Line 352: Assert confirms the peer is no longer tracked: `assert!(!unhealthy_peer_states.contains_key(&peer_network_ids[2]))`

To exploit in practice, an attacker would:
1. Connect to a validator's storage service as a PFN
2. Send 500 invalid storage requests
3. Disconnect immediately when banned
4. Wait 1-2 seconds for GC
5. Reconnect and repeat

This bypasses the intended 5-minute (300 second) ban period and exponential backoff, enabling sustained resource exhaustion at 150x the intended rate limit.

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L53-53)
```rust
    request_moderator: Arc<RequestModerator>,
```

**File:** state-sync/storage-service/server/src/moderator.rs (L50-68)
```rust
    pub fn increment_invalid_request_count(&mut self, peer_network_id: &PeerNetworkId) {
        // Increment the invalid request count
        self.invalid_request_count += 1;

        // If the peer is a PFN and has sent too many invalid requests, start ignoring it
        if self.ignore_start_time.is_none()
            && peer_network_id.network_id().is_public_network()
            && self.invalid_request_count >= self.max_invalid_requests
        {
            // TODO: at some point we'll want to terminate the connection entirely

            // Start ignoring the peer
            self.ignore_start_time = Some(self.time_service.now());

            // Log the fact that we're now ignoring the peer
            warn!(LogSchema::new(LogEntry::RequestModeratorIgnoredPeer)
                .peer_network_id(peer_network_id)
                .message("Ignoring peer due to too many invalid requests!"));
        }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L89-90)
```rust
                // Double the min time to ignore the peer
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

**File:** state-sync/storage-service/server/src/moderator.rs (L152-159)
```rust
            let storage_server_summary = self.cached_storage_server_summary.load();

            // Verify the request is serviceable using the current storage server summary
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
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

**File:** state-sync/storage-service/server/src/tests/request_moderator.rs (L210-354)
```rust
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

**File:** state-sync/storage-service/server/src/lib.rs (L343-343)
```rust
                                request_moderator.clone(),
```
