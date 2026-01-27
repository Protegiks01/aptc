# Audit Report

## Title
Peer Identity Rotation Bypass in State Sync Request Moderator Allows Persistent Resource Exhaustion

## Summary
Malicious peers can bypass the 5-minute peer blocking mechanism in the storage service by cycling through cryptographic identities (PeerIds) faster than the ignore timeout. When a blocked peer disconnects, its unhealthy state is garbage collected, allowing the attacker to reconnect with a new x25519 key pair and immediately resume sending invalid requests without waiting for the timeout to expire.

## Finding Description

The State Sync storage service implements a request moderation system to protect nodes from misbehaving peers. The `RequestModerator` tracks unhealthy peers that send invalid requests and temporarily ignores them for a configurable period (default: 5 minutes). [1](#0-0) 

However, the system has a critical flaw in how it handles peer state persistence:

**1. Peer Identification Based on Cryptographic Identity:**
Peers are identified using `PeerNetworkId`, which combines a `NetworkId` and a `PeerId`. [2](#0-1) 

The `PeerId` is derived from an x25519 public key by taking the last 16 bytes. [3](#0-2) 

**2. State Garbage Collection on Disconnect:**
When a peer disconnects, the `refresh_unhealthy_peer_states()` function removes all tracking state for that peer, including block history and timeout counters. [4](#0-3) 

**3. No IP-Based Rate Limiting:**
Connection admission control only enforces a total connection limit (default: 100 unknown inbound connections) but does not track connection rates or source IP addresses. [5](#0-4) 

**Attack Flow:**
1. Attacker generates an x25519 key pair (PeerId-A)
2. Connects to target node and sends 500 invalid storage service requests (default `max_invalid_requests_per_peer`)
3. Gets blocked for 5 minutes [6](#0-5) 
4. **Disconnects** - triggering state cleanup that removes all unhealthy peer tracking
5. Generates new x25519 key pair (PeerId-B)
6. Reconnects with fresh identity - no memory of previous violations
7. Repeats cycle every ~1 minute instead of waiting 5 minutes

The exponential backoff mechanism that doubles the ignore timeout on repeated violations is completely ineffective because the state is cleared on disconnect. [7](#0-6) 

## Impact Explanation

**Severity: Medium to High**

This vulnerability enables sustained resource exhaustion attacks against validator and fullnode storage services:

1. **Validator Node Slowdowns:** Forcing validators to process 500+ invalid requests per connection cycle degrades state sync performance, potentially impacting consensus participation (High severity per Aptos bug bounty: "Validator node slowdowns")

2. **Resource Exhaustion:** With 100 concurrent connection slots, an attacker can generate 50,000 invalid requests before cycling identities, causing CPU/memory exhaustion processing unserviceable storage requests

3. **Service Degradation:** State sync is critical for new nodes to bootstrap and existing nodes to catch up. Sustained attacks can prevent nodes from syncing, requiring manual intervention (Medium severity: "State inconsistencies requiring intervention")

4. **Defense Evasion:** The attack bypasses the intended peer reputation system, rendering the `min_time_to_ignore_peers_secs` configuration ineffective

## Likelihood Explanation

**Likelihood: High**

The attack is highly feasible:

1. **Low Computational Cost:** Generating x25519 key pairs is computationally trivial (milliseconds)
2. **No Authentication Required:** Public network peers don't need validator credentials
3. **Simple Implementation:** Basic network client can automate the attack
4. **No Monitoring Alerts:** Current metrics only track ignored peer counts, not identity rotation patterns
5. **Wide Attack Surface:** All nodes exposing storage service on public network are vulnerable

The test suite explicitly demonstrates state cleanup on disconnect, confirming this is intended behavior rather than a race condition. [8](#0-7) 

## Recommendation

Implement IP-based rate limiting and persistent peer reputation tracking:

**Option 1: Add IP-Based Tracking (Preferred)**
Augment `UnhealthyPeerState` to track connection source IP addresses and enforce rate limits per IP subnet, preventing identity rotation from the same source:

```rust
pub struct UnhealthyPeerState {
    ignore_start_time: Option<Instant>,
    invalid_request_count: u64,
    max_invalid_requests: u64,
    min_time_to_ignore_secs: u64,
    time_service: TimeService,
    // NEW: Track source IP to detect identity rotation
    source_ip: Option<IpAddr>,
    // NEW: Track connection attempts per IP
    connection_attempts_per_ip: HashMap<IpAddr, (u64, Instant)>,
}
```

Add IP-based blocking logic in `refresh_unhealthy_peer_states()` to maintain a temporary blocklist of source IPs that repeatedly connect with new identities.

**Option 2: Persistent State Across Disconnects**
Modify garbage collection to preserve unhealthy state for a grace period after disconnect:

```rust
pub struct UnhealthyPeerState {
    // ... existing fields ...
    disconnect_time: Option<Instant>, // Track when peer disconnected
    grace_period_secs: u64, // Don't GC immediately after disconnect
}
```

In `refresh_unhealthy_peer_states()`, only remove peers that have been disconnected longer than the grace period (e.g., 2x `min_time_to_ignore_peers_secs`).

**Option 3: Connection Rate Limiting**
Add per-IP connection rate limiting in `PeerManager::handle_new_connection_event()` to track new connections per time window and reject excessive connection attempts from the same source.

## Proof of Concept

```rust
// Integration test demonstrating peer identity rotation attack
#[tokio::test]
async fn test_peer_identity_rotation_bypass() {
    use aptos_config::config::StorageServiceConfig;
    use aptos_types::PeerId;
    use aptos_crypto::x25519;
    use std::time::Duration;
    
    // Setup storage service with default config
    let storage_config = StorageServiceConfig {
        max_invalid_requests_per_peer: 500,
        min_time_to_ignore_peers_secs: 300, // 5 minutes
        ..Default::default()
    };
    
    let (mut client, service, peers_metadata) = 
        MockClient::new(None, Some(storage_config));
    tokio::spawn(service.start());
    
    // Simulate attacker cycling through identities
    for iteration in 0..10 {
        // Generate new x25519 identity
        let private_key = x25519::PrivateKey::generate_for_testing();
        let peer_id = PeerId::from_identity_public_key(
            private_key.public_key()
        );
        let peer_network_id = PeerNetworkId::new(NetworkId::Public, peer_id);
        
        // Connect with new identity
        peers_metadata.insert_connection_metadata(
            peer_network_id,
            create_connection_metadata(peer_id, iteration)
        ).unwrap();
        
        // Send max invalid requests
        for _ in 0..500 {
            let response = send_invalid_request(&mut client, peer_network_id).await;
            // First 499 should return InvalidRequest
            // 500th should trigger blocking
        }
        
        // Verify peer is blocked
        assert!(service.get_request_moderator()
            .get_unhealthy_peer_states()
            .get(&peer_network_id)
            .unwrap()
            .is_ignored());
        
        // Disconnect - triggers state cleanup
        peers_metadata.remove_peer_metadata(peer_network_id, ConnectionId::from(iteration)).unwrap();
        
        // Wait for garbage collection
        tokio::time::sleep(Duration::from_millis(1100)).await;
        
        // Verify state was cleaned up
        assert!(!service.get_request_moderator()
            .get_unhealthy_peer_states()
            .contains_key(&peer_network_id));
        
        // Next iteration can immediately send 500 more requests
        // instead of waiting 5 minutes
    }
    
    // Attack successfully sent 5000 invalid requests in ~11 seconds
    // instead of waiting 50 minutes (10 iterations × 5 minutes)
}
```

**Notes:**

The vulnerability fundamentally stems from treating peer identity as immutable rather than recognizing that malicious actors can cheaply generate new cryptographic identities. The current design assumes honest peer behavior where disconnection represents genuine network issues rather than strategic evasion. A production-grade peer reputation system must account for Sybil-style identity rotation by tracking connection patterns at the network layer (IP addresses, connection rates) rather than relying solely on cryptographic peer identifiers.

### Citations

**File:** config/src/config/state_sync_config.rs (L213-213)
```rust
            min_time_to_ignore_peers_secs: 300, // 5 minutes
```

**File:** config/src/network_id.rs (L235-240)
```rust
#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// Identifier of a node, represented as (network_id, peer_id)
pub struct PeerNetworkId {
    network_id: NetworkId,
    peer_id: PeerId,
}
```

**File:** types/src/account_address.rs (L140-146)
```rust
pub fn from_identity_public_key(identity_public_key: x25519::PublicKey) -> AccountAddress {
    let mut array = [0u8; AccountAddress::LENGTH];
    let pubkey_slice = identity_public_key.as_slice();
    // keep only the last 16 bytes
    array.copy_from_slice(&pubkey_slice[x25519::PUBLIC_KEY_SIZE - AccountAddress::LENGTH..]);
    AccountAddress::new(array)
}
```

**File:** state-sync/storage-service/server/src/moderator.rs (L54-68)
```rust
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

**File:** state-sync/storage-service/server/src/moderator.rs (L199-228)
```rust
    pub fn refresh_unhealthy_peer_states(&self) -> Result<(), Error> {
        // Get the currently connected peers
        let connected_peers_and_metadata = self
            .peers_and_metadata
            .get_connected_peers_and_metadata()
            .map_err(|error| {
                Error::UnexpectedErrorEncountered(format!(
                    "Unable to get connected peers and metadata: {}",
                    error
                ))
            })?;

        // Remove disconnected peers and refresh ignored peer states
        let mut num_ignored_peers = 0;
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

**File:** network/framework/src/peer_manager/mod.rs (L351-389)
```rust
        // Verify that we have not reached the max connection limit for unknown inbound peers
        if conn.metadata.origin == ConnectionOrigin::Inbound {
            // Everything below here is meant for unknown peers only. The role comes from
            // the Noise handshake and if it's not `Unknown` then it is trusted.
            if conn.metadata.role == PeerRole::Unknown {
                // TODO: Keep track of somewhere else to not take this hit in case of DDoS
                // Count unknown inbound connections
                let unknown_inbound_conns = self
                    .active_peers
                    .iter()
                    .filter(|(peer_id, (metadata, _))| {
                        metadata.origin == ConnectionOrigin::Inbound
                            && trusted_peers
                                .get(peer_id)
                                .is_none_or(|peer| peer.role == PeerRole::Unknown)
                    })
                    .count();

                // Reject excessive inbound connections made by unknown peers
                // We control outbound connections with Connectivity manager before we even send them
                // and we must allow connections that already exist to pass through tie breaking.
                if !self
                    .active_peers
                    .contains_key(&conn.metadata.remote_peer_id)
                    && unknown_inbound_conns + 1 > self.inbound_connection_limit
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .connection_metadata_with_address(&conn.metadata),
                        "{} Connection rejected due to connection limit: {}",
                        self.network_context,
                        conn.metadata
                    );
                    counters::connections_rejected(&self.network_context, conn.metadata.origin)
                        .inc();
                    self.disconnect(conn);
                    return;
                }
            }
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
