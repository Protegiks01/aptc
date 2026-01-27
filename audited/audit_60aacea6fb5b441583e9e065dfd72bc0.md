# Audit Report

## Title
Resource Exhaustion via Unbanned Validator/VFN Invalid Storage Service Requests

## Summary
The storage service's `RequestModerator` only bans public network peers that send excessive invalid requests, but does not ban validator or VFN peers. This allows malicious or compromised validators/VFNs to send unlimited invalid requests, potentially causing resource exhaustion on target nodes through continuous spawning of blocking tasks for request validation.

## Finding Description

The storage service implements a peer banning mechanism in the `RequestModerator` to protect against malicious peers sending invalid requests. However, this protection only applies to public network peers (`NetworkId::Public`), explicitly excluding validators (`NetworkId::Validator`) and VFNs (`NetworkId::Vfn`). [1](#0-0) 

The banning logic checks `peer_network_id.network_id().is_public_network()` which only returns `true` for `NetworkId::Public`: [2](#0-1) 

Test cases confirm this intentional exclusion - validators and VFNs can send 10x-20x the maximum invalid request threshold without being banned: [3](#0-2) 

**Attack Flow:**
1. A compromised/malicious validator or VFN sends invalid storage service requests that cannot be serviced
2. Each request is received through the network layer and transformed into a `NetworkRequest`: [4](#0-3) 

3. The server spawns a blocking task for each request to avoid blocking the async runtime: [5](#0-4) 

4. Request validation occurs in the moderator, incrementing `invalid_request_count` but never triggering the ban for non-public peers: [6](#0-5) 

5. The malicious peer can repeat this indefinitely, as validators/VFNs are never ignored regardless of `invalid_request_count`

**Protective Mechanisms (Insufficient):**
While there are network-level rate limits (`MAX_CONCURRENT_INBOUND_RPCS = 100`), these only limit concurrent RPCs per connection: [7](#0-6) 

A malicious actor can continuously send invalid requests up to this limit, and as each completes, send another. With default configuration allowing 500 invalid requests before banning (which never happens for validators/VFNs): [8](#0-7) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty criteria due to potential for **validator node slowdowns**. 

While individual request validation may be fast, continuous invalid requests can:
- Saturate the blocking thread pool with validation tasks
- Consume CPU cycles for repeated validation failures
- Create backpressure on the async runtime when blocking tasks are slow to complete
- Degrade service quality for legitimate storage service requests from honest peers

The impact is amplified because:
1. No banning mechanism exists for the attack vector (validator/VFN peers)
2. A single compromised validator or VFN can execute the attack
3. The attack can persist indefinitely without automatic mitigation
4. Multiple validators could coordinate (though this would require collusion)

A TODO comment acknowledges the limitation: [9](#0-8) 

## Likelihood Explanation

**Likelihood: Medium**

This requires:
- A compromised or malicious validator/VFN (not a trivial requirement, but within scope for security analysis)
- Basic network connectivity to target nodes
- Ability to send malformed storage service requests

The attack is **easy to execute** once the prerequisite is met - simply send invalid `StorageServiceRequest` messages in a loop. The difficulty lies in compromising a validator or VFN, but this is a realistic threat model for blockchain security analysis.

**Note on Trust Model:** While the provided context states validators are "trusted roles," the security question explicitly asks about mechanisms to handle malicious peer requests. In production blockchain systems, defense-in-depth requires protection against compromised trusted actors.

## Recommendation

Implement peer banning for validator and VFN peers with appropriate tuning to avoid false positives that could impact consensus:

1. **Apply graduated response to all peer types:**
   - Track invalid request counts for all peers (already done)
   - For validators/VFNs, use a higher threshold (e.g., 5000 instead of 500)
   - Implement temporary connection termination instead of indefinite ignoring
   - Add exponential backoff for reconnection attempts

2. **Enhanced monitoring:**
   - Alert when validators/VFNs exceed invalid request thresholds
   - Log peer identity for investigation

3. **Code modification in `moderator.rs`:**
   ```rust
   // Replace the check at line 55-57 with:
   if self.ignore_start_time.is_none() 
       && self.invalid_request_count >= self.max_invalid_requests 
   {
       // Terminate connection for public peers immediately
       // For validators/VFNs, use higher threshold and log warning
       if peer_network_id.network_id().is_public_network() 
           || self.invalid_request_count >= (self.max_invalid_requests * 10) 
       {
           // Existing ignore logic
       }
   }
   ```

4. **Implement the TODO at line 59:** Actually terminate connections for peers exceeding extreme thresholds, not just ignore their requests.

## Proof of Concept

```rust
// Proof of concept demonstrating unbanned validator sending invalid requests
// This would be added as a test in state-sync/storage-service/server/src/tests/request_moderator.rs

#[tokio::test]
async fn test_validator_resource_exhaustion() {
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_types::PeerId;
    use std::time::Duration;
    
    // Setup storage service server with moderator
    let (mut server, moderator) = setup_storage_service_server();
    
    // Create a validator peer
    let malicious_validator = PeerNetworkId::new(NetworkId::Validator, PeerId::random());
    
    // Send 10,000 invalid requests (20x the normal ban threshold)
    for i in 0..10_000 {
        let invalid_request = create_invalid_storage_request();
        
        // Send request through network layer
        send_storage_request(&mut server, malicious_validator, invalid_request).await;
        
        // Verify peer is never banned
        let peer_states = moderator.get_unhealthy_peer_states();
        if let Some(peer_state) = peer_states.get(&malicious_validator) {
            assert!(!peer_state.is_ignored(), 
                "Validator should never be ignored at request {}", i);
        }
        
        // Small delay to avoid overwhelming test infrastructure
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    
    // Verify the validator sent way beyond normal ban threshold but was never banned
    let peer_states = moderator.get_unhealthy_peer_states();
    let peer_state = peer_states.get(&malicious_validator).unwrap();
    assert!(peer_state.invalid_request_count >= 10_000);
    assert!(!peer_state.is_ignored(), "Validator was never banned despite 10,000 invalid requests");
}
```

**Note:** This PoC demonstrates the mechanism but would need integration with actual test infrastructure. The key point is that validators can send unlimited invalid requests without being banned, which combined with blocking task spawning per request creates resource consumption risk.

### Citations

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

**File:** state-sync/storage-service/server/src/moderator.rs (L134-196)
```rust
    pub fn validate_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<(), Error> {
        // Validate the request and time the operation
        let validate_request = || {
            // If the peer is being ignored, return an error
            if let Some(peer_state) = self.unhealthy_peer_states.get(peer_network_id) {
                if peer_state.is_ignored() {
                    return Err(Error::TooManyInvalidRequests(format!(
                        "Peer is temporarily ignored. Unable to handle request: {:?}",
                        request
                    )));
                }
            }

            // Get the latest storage server summary
            let storage_server_summary = self.cached_storage_server_summary.load();

            // Verify the request is serviceable using the current storage server summary
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
                // Increment the invalid request count for the peer
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

                // Return the validation error
                return Err(Error::InvalidRequest(format!(
                    "The given request cannot be satisfied. Request: {:?}, storage summary: {:?}",
                    request, storage_server_summary
                )));
            }

            Ok(()) // The request is valid
        };
        utils::execute_and_time_duration(
            &metrics::STORAGE_REQUEST_VALIDATION_LATENCY,
            Some((peer_network_id, request)),
            None,
            validate_request,
            None,
        )
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L357-410)
```rust
    fn test_unhealthy_peer_networks() {
        // Create a new unhealthy peer state
        let max_invalid_requests = 10;
        let time_service = TimeService::mock();
        let mut unhealthy_peer_state =
            UnhealthyPeerState::new(max_invalid_requests, 1, time_service.clone());

        // Handle a lot of invalid requests for a validator
        let peer_network_id = PeerNetworkId::new(NetworkId::Validator, PeerId::random());
        for _ in 0..max_invalid_requests * 10 {
            unhealthy_peer_state.increment_invalid_request_count(&peer_network_id);
        }

        // Verify the peer is not ignored and that the number of invalid requests is correct
        assert!(!unhealthy_peer_state.is_ignored());
        assert_eq!(
            unhealthy_peer_state.invalid_request_count,
            max_invalid_requests * 10
        );

        // Create another unhealthy peer state
        let mut unhealthy_peer_state =
            UnhealthyPeerState::new(max_invalid_requests, 1, time_service.clone());

        // Handle a lot of invalid requests for a VFN
        let peer_network_id = PeerNetworkId::new(NetworkId::Vfn, PeerId::random());
        for _ in 0..max_invalid_requests * 20 {
            unhealthy_peer_state.increment_invalid_request_count(&peer_network_id);
        }

        // Verify the peer is not ignored and that the number of invalid requests is correct
        assert!(!unhealthy_peer_state.is_ignored());
        assert_eq!(
            unhealthy_peer_state.invalid_request_count,
            max_invalid_requests * 20
        );

        // Create another unhealthy peer state
        let mut unhealthy_peer_state =
            UnhealthyPeerState::new(max_invalid_requests, 1, time_service);

        // Handle a lot of invalid requests for a PFN
        let peer_network_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
        for _ in 0..max_invalid_requests * 5 {
            unhealthy_peer_state.increment_invalid_request_count(&peer_network_id);
        }

        // Verify the peer is ignored and that the number of invalid requests is correct
        assert!(unhealthy_peer_state.is_ignored());
        assert_eq!(
            unhealthy_peer_state.invalid_request_count,
            max_invalid_requests * 5
        );
    }
```

**File:** config/src/network_id.rs (L160-162)
```rust
    pub fn is_public_network(&self) -> bool {
        self == &NetworkId::Public
    }
```

**File:** state-sync/storage-service/server/src/network.rs (L62-84)
```rust
    fn event_to_request(
        network_id: NetworkId,
        event: Event<StorageServiceMessage>,
    ) -> Option<NetworkRequest> {
        match event {
            Event::RpcRequest(
                peer_id,
                StorageServiceMessage::Request(storage_service_request),
                protocol_id,
                response_tx,
            ) => {
                let response_sender = ResponseSender::new(response_tx);
                let peer_network_id = PeerNetworkId::new(network_id, peer_id);
                Some(NetworkRequest {
                    peer_network_id,
                    protocol_id,
                    storage_service_request,
                    response_sender,
                })
            },
            _ => None, // We don't use direct send and don't care about connection events
        }
    }
```

**File:** state-sync/storage-service/server/src/lib.rs (L389-419)
```rust
        while let Some(network_request) = self.network_requests.next().await {
            // All handler methods are currently CPU-bound and synchronous
            // I/O-bound, so we want to spawn on the blocking thread pool to
            // avoid starving other async tasks on the same runtime.
            let storage = self.storage.clone();
            let config = self.storage_service_config;
            let cached_storage_server_summary = self.cached_storage_server_summary.clone();
            let optimistic_fetches = self.optimistic_fetches.clone();
            let subscriptions = self.subscriptions.clone();
            let lru_response_cache = self.lru_response_cache.clone();
            let request_moderator = self.request_moderator.clone();
            let time_service = self.time_service.clone();
            self.runtime.spawn_blocking(move || {
                Handler::new(
                    cached_storage_server_summary,
                    optimistic_fetches,
                    lru_response_cache,
                    request_moderator,
                    storage,
                    subscriptions,
                    time_service,
                )
                .process_request_and_respond(
                    config,
                    network_request.peer_network_id,
                    network_request.protocol_id,
                    network_request.storage_service_request,
                    network_request.response_sender,
                );
            });
        }
```

**File:** network/framework/src/constants.rs (L14-15)
```rust
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** config/src/config/state_sync_config.rs (L201-201)
```rust
            max_invalid_requests_per_peer: 500,
```
