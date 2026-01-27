# Audit Report

## Title
Peer Banning Bypass Through Identity Rotation in State Sync Storage Service

## Summary
The state sync storage service's peer banning mechanism can be completely bypassed by attackers who rotate through new cryptographic identities. An attacker can send 500 invalid requests per identity, get temporarily banned for 5 minutes, disconnect, generate a new keypair to obtain a fresh peer identity, and repeat indefinitely. This allows continuous resource exhaustion attacks against storage service nodes.

## Finding Description

The `RequestModerator` in the state sync storage service tracks invalid requests per `PeerNetworkId` to protect against malicious peers sending invalid data requests. When a peer exceeds `max_invalid_requests_per_peer` (default: 500), they are temporarily ignored for `min_time_to_ignore_peers_secs` (default: 300 seconds). [1](#0-0) [2](#0-1) 

However, the tracking is performed per `PeerNetworkId` (which includes the `PeerId`), stored in a `DashMap`: [3](#0-2) 

On the public network, Aptos uses `MaybeMutual` authentication mode, which allows any peer to connect as long as their `PeerId` is correctly derived from their x25519 public key: [4](#0-3) 

When an unknown peer connects, the handshake validates that the claimed `PeerId` matches the cryptographically derived value from the peer's public key. If valid, the connection is accepted with `PeerRole::Unknown`.

An attacker can trivially generate new x25519 keypairs, each producing a unique valid `PeerId`. When they connect with a new identity, they receive a fresh `UnhealthyPeerState` entry: [5](#0-4) 

Each new identity starts with `invalid_request_count: 0`, allowing the attacker to send another 500 invalid requests before being temporarily banned again.

Furthermore, when peers disconnect, their state is garbage collected from the tracking map: [6](#0-5) 

**Attack Flow:**
1. Attacker generates x25519 keypair → derives `PeerId_A`
2. Connects to public network with identity A
3. Sends 500 invalid storage service requests (e.g., requesting unavailable data ranges)
4. Gets temporarily ignored for 5 minutes
5. Disconnects (state is garbage collected)
6. Generates new keypair → derives `PeerId_B`
7. Connects with identity B (fresh counter, starts at 0)
8. Sends another 500 invalid requests
9. Repeat indefinitely

Each invalid request still requires validation against the storage server summary, consuming CPU resources: [7](#0-6) 

The inbound connection limit (default 100 for unknown peers) does not prevent this attack, as the attacker only needs one active connection at a time and can disconnect/reconnect with new identities.

## Impact Explanation

This vulnerability enables a **resource exhaustion attack** against Aptos validator and fullnode storage services:

1. **CPU Exhaustion**: Each invalid request must be deserialized, validated against the storage summary, and an error response constructed. With continuous rotation through identities, an attacker can maintain a high rate of invalid requests.

2. **Service Degradation**: Processing invalid requests consumes resources that should be serving legitimate peers, degrading state sync performance for the network.

3. **Coordinated Attack**: Multiple attackers can coordinate this attack, with each rotating through identities to amplify the impact.

According to the Aptos bug bounty severity categories, this qualifies as **Medium Severity**:
- "State inconsistencies requiring intervention" - The storage service may become degraded enough to require operator intervention
- Potentially **High Severity** if it causes "Validator node slowdowns" through sustained resource exhaustion

The attack does not directly cause:
- Loss of funds
- Consensus violations
- Permanent network damage

However, it breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The peer banning mechanism is specifically designed to enforce resource limits on malicious peers, but it can be trivially bypassed.

## Likelihood Explanation

**Likelihood: High**

The attack is:
- **Easy to execute**: Generating x25519 keypairs is a standard cryptographic operation available in any crypto library
- **Low cost**: No economic stake required, no fees to pay
- **Difficult to detect**: Each identity appears as a new, legitimate peer that happens to send some invalid requests
- **No special access needed**: Any public network peer can execute this attack
- **Already in attacker toolkit**: Similar identity rotation attacks are common in P2P networks

The only barriers are:
- Network connectivity to Aptos public network nodes (readily available)
- Basic understanding of the Noise handshake protocol (well-documented)

## Recommendation

Implement multi-layered defenses against peer banning bypass:

**1. IP-Based Rate Limiting in RequestModerator**

Track invalid request counts per source IP address in addition to per `PeerNetworkId`. Implement progressive penalties:

```rust
pub struct RequestModerator {
    // Existing fields...
    unhealthy_peer_states: Arc<DashMap<PeerNetworkId, UnhealthyPeerState>>,
    // New: Track by IP address
    unhealthy_ip_states: Arc<DashMap<IpAddr, UnhealthyIpState>>,
}

impl RequestModerator {
    pub fn validate_request(
        &self,
        peer_network_id: &PeerNetworkId,
        peer_ip: IpAddr,  // Extract from connection metadata
        request: &StorageServiceRequest,
    ) -> Result<(), Error> {
        // Check both peer identity AND IP address
        // Ban IP if too many identities from same IP send invalid requests
        // ...
    }
}
```

**2. Connection Fingerprinting**

Track connection patterns beyond just `PeerId`:
- Connection timing (rapid reconnects from same IP)
- Request patterns (identical invalid request sequences)
- Network characteristics (same latency/jitter profile)

**3. Progressive Penalties**

Implement exponential backoff that persists across identity changes for the same IP:
- First offense: 5 minute ban
- Second offense (same IP): 30 minute ban
- Third offense (same IP): 24 hour ban
- Repeat offenders: Permanent IP blacklist

**4. Connection Throttling**

Limit the rate at which new unknown identities can connect from the same IP address or subnet.

**5. Metrics and Monitoring**

Add metrics to detect identity rotation patterns:
- `aptos_storage_service_identity_rotation_detected`
- `aptos_storage_service_same_ip_multiple_banned_peers`

## Proof of Concept

```rust
#[tokio::test]
async fn test_peer_banning_bypass_via_identity_rotation() {
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_types::PeerId;
    
    // Setup storage service with low thresholds for testing
    let max_invalid_requests_per_peer = 5;
    let storage_service_config = StorageServiceConfig {
        max_invalid_requests_per_peer,
        min_time_to_ignore_peers_secs: 10,
        ..Default::default()
    };
    
    let (mut mock_client, mut service, _, _, _) =
        MockClient::new(None, Some(storage_service_config));
    
    let highest_synced_version = 100;
    utils::update_storage_server_summary(&mut service, highest_synced_version, 10);
    
    let request_moderator = service.get_request_moderator();
    let unhealthy_peer_states = request_moderator.get_unhealthy_peer_states();
    
    tokio::spawn(service.start());
    
    // Demonstrate identity rotation bypass
    for identity_round in 0..3 {
        // Generate new identity for each round
        let peer_network_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
        
        println!("Round {}: Using identity {:?}", identity_round, peer_network_id);
        
        // Send max_invalid_requests_per_peer invalid requests
        for request_num in 0..max_invalid_requests_per_peer {
            let response = send_invalid_transaction_request(
                highest_synced_version,
                &mut mock_client,
                peer_network_id,
            ).await;
            
            // First 5 requests should fail with InvalidRequest
            assert_matches!(
                response.unwrap_err(),
                StorageServiceError::InvalidRequest(_)
            );
        }
        
        // Verify this identity is now banned
        let peer_state = unhealthy_peer_states.get(&peer_network_id).unwrap();
        assert!(peer_state.is_ignored());
        println!("Identity {} is now banned", identity_round);
        
        // Next request from this identity should be rejected
        let response = send_invalid_transaction_request(
            highest_synced_version,
            &mut mock_client,
            peer_network_id,
        ).await;
        assert_matches!(
            response.unwrap_err(),
            StorageServiceError::TooManyInvalidRequests(_)
        );
        
        // BUT: Generate a new identity and the attack continues
        // No IP-based tracking prevents this
    }
    
    // All three identities are tracked separately
    assert_eq!(unhealthy_peer_states.len(), 3);
    
    // VULNERABILITY: Attacker can repeat this indefinitely with new identities
    // Each new PeerId gets a fresh counter starting at 0
    println!("Attack successful: Sent {} invalid requests across {} identities",
             max_invalid_requests_per_peer * 3, 3);
}

fn send_invalid_transaction_request(
    highest_synced_version: u64,
    mock_client: &mut MockClient,
    peer_network_id: PeerNetworkId,
) -> impl Future<Output = Result<StorageServiceResponse, StorageServiceError>> {
    // Request data beyond what's available - guaranteed to be invalid
    let request = StorageServiceRequest::new(
        DataRequest::GetTransactionsWithProof(TransactionsWithProofRequest {
            start_version: highest_synced_version + 1000,  // Invalid: too far ahead
            end_version: highest_synced_version + 2000,
            proof_version: highest_synced_version + 2000,
            include_events: false,
        }),
        false,  // use_compression
    );
    
    mock_client.send_request(request, peer_network_id)
}
```

**Expected Output:**
```
Round 0: Using identity PeerNetworkId(Public, 0x1234...)
Identity 0 is now banned
Round 1: Using identity PeerNetworkId(Public, 0x5678...)
Identity 1 is now banned
Round 2: Using identity PeerNetworkId(Public, 0xabcd...)
Identity 2 is now banned
Attack successful: Sent 15 invalid requests across 3 identities
```

This PoC demonstrates that an attacker can bypass peer banning by rotating through new cryptographic identities, with each identity receiving a fresh invalid request counter.

## Notes

This vulnerability is specifically in the **application-layer protocol design** of the peer reputation system, not a network-level DoS attack. The flaw is in the tracking mechanism that uses only `PeerNetworkId` without considering persistent identifiers like IP addresses. While the `MaybeMutual` authentication mode is necessary to allow public network participation, the peer banning system must account for the ease of identity rotation in permissionless networks.

The existing exponential backoff mechanism (doubling ignore time on each offense) only helps if the same `PeerId` reconnects, but it's trivial for attackers to generate new identities. The garbage collection of disconnected peer state, while necessary for memory management, exacerbates the problem by removing evidence of prior misbehavior.

### Citations

**File:** config/src/config/state_sync_config.rs (L201-201)
```rust
            max_invalid_requests_per_peer: 500,
```

**File:** config/src/config/state_sync_config.rs (L213-213)
```rust
            min_time_to_ignore_peers_secs: 300, // 5 minutes
```

**File:** state-sync/storage-service/server/src/moderator.rs (L111-112)
```rust
    unhealthy_peer_states: Arc<DashMap<PeerNetworkId, UnhealthyPeerState>>,
}
```

**File:** state-sync/storage-service/server/src/moderator.rs (L155-159)
```rust
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
```

**File:** state-sync/storage-service/server/src/moderator.rs (L161-178)
```rust
                let mut unhealthy_peer_state = self
                    .unhealthy_peer_states
                    .entry(*peer_network_id)
                    .or_insert_with(|| {
                        // Create a new unhealthy peer state (this is the first invalid request)
                        let max_invalid_requests =
                            self.storage_service_config.max_invalid_requests_per_peer;
                        let min_time_to_ignore_peers_secs =
                            self.storage_service_config.min_time_to_ignore_peers_secs;
                        let time_service = self.time_service.clone();

                        UnhealthyPeerState::new(
                            max_invalid_requests,
                            min_time_to_ignore_peers_secs,
                            time_service,
                        )
                    });
                unhealthy_peer_state.increment_invalid_request_count(peer_network_id);
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

**File:** network/framework/src/noise/handshake.rs (L384-426)
```rust
            HandshakeAuthMode::MaybeMutual(peers_and_metadata) => {
                let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id)?;
                let trusted_peer = trusted_peers.get(&remote_peer_id).cloned();
                match trusted_peer {
                    Some(peer) => {
                        Self::authenticate_inbound(remote_peer_short, &peer, &remote_public_key)
                    },
                    None => {
                        // The peer is not in the trusted peer set. Verify that the Peer ID is
                        // constructed correctly from the public key.
                        let derived_remote_peer_id =
                            aptos_types::account_address::from_identity_public_key(
                                remote_public_key,
                            );
                        if derived_remote_peer_id != remote_peer_id {
                            // The peer ID is not constructed correctly from the public key
                            Err(NoiseHandshakeError::ClientPeerIdMismatch(
                                remote_peer_short,
                                remote_peer_id,
                                derived_remote_peer_id,
                            ))
                        } else {
                            // Try to infer the role from the network context
                            if self.network_context.role().is_validator() {
                                if network_id.is_vfn_network() {
                                    // Inbound connections to validators on the VFN network must be VFNs
                                    Ok(PeerRole::ValidatorFullNode)
                                } else {
                                    // Otherwise, they're unknown. Validators will connect through
                                    // authenticated channels (on the validator network) so shouldn't hit
                                    // this, and PFNs will connect on public networks (which aren't common).
                                    Ok(PeerRole::Unknown)
                                }
                            } else {
                                // We're a VFN or PFN. VFNs get no inbound connections on the vfn network
                                // (so the peer won't be a validator). Thus, we're on the public network
                                // so mark the peer as unknown.
                                Ok(PeerRole::Unknown)
                            }
                        }
                    },
                }
            },
```
