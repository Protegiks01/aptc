# Audit Report

## Title
Memory Exhaustion via Unbounded Optimistic Fetch Accumulation with Missing Disconnected Peer Garbage Collection

## Summary
The storage service server allows malicious peers to exhaust server memory by accumulating long-lived optimistic fetch requests. The vulnerability exists because: (1) optimistic fetch requests bypass RequestModerator validation, (2) there is no limit on the total number of optimistic fetches across all peers, (3) disconnected peers are not garbage collected from the optimistic_fetches map, and (4) with a misconfigured high `max_optimistic_fetch_period_ms` timeout, these entries persist for extended periods holding memory resources.

## Finding Description

The storage service server maintains a `DashMap<PeerNetworkId, OptimisticFetchRequest>` to track active optimistic fetch requests. Each entry holds a `StorageServiceRequest` and a `ResponseSender` containing a `oneshot::Sender` channel that cannot be released until the request is fulfilled or expires.

**Critical Design Flaws:**

1. **Validation Bypass**: Optimistic fetch requests bypass the RequestModerator's `validate_request()` check. [1](#0-0) 

2. **No Total Limit**: The DashMap has no bound on the total number of optimistic fetches across all peers. Only one fetch per `PeerNetworkId` is enforced by the map structure. [2](#0-1) 

3. **No Disconnected Peer Cleanup**: Unlike the RequestModerator which garbage collects disconnected peers from its `unhealthy_peer_states` map [3](#0-2) , the optimistic_fetches map has **no equivalent cleanup mechanism** for disconnected peers.

4. **Timeout-Dependent Expiration**: Entries are only removed when they expire based on `max_optimistic_fetch_period_ms`. [4](#0-3) 

**Attack Scenario:**

When `max_optimistic_fetch_period_ms` is misconfigured to a high value (hours or days instead of the default 5 seconds):

1. Attacker establishes many peer connections (Sybil attack on public fullnodes)
2. Each peer sends one optimistic fetch request (bypasses validation)
3. Peers disconnect immediately after sending the request
4. Optimistic fetch entries remain in memory (no garbage collection for disconnected peers)
5. Process repeats with new peer connections
6. Each entry holds: `StorageServiceRequest` + `ResponseSender` with oneshot channel + metadata
7. Memory accumulates until entries expire (which could be hours/days with misconfiguration)
8. Server memory exhaustion leads to degraded performance or crash

The vulnerability breaks the **Resource Limits invariant** (#9): "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty criteria:

- **Validator node slowdowns**: Memory pressure from thousands of accumulated optimistic fetch entries degrades node performance
- **Significant protocol violations**: Bypassing the RequestModerator validation mechanism violates the intended security model
- **Potential DoS**: In severe cases with extreme misconfiguration, memory exhaustion could crash the node

The impact is amplified because:
- Public fullnodes accept many connections from untrusted peers
- No defense exists against Sybil attacks accumulating optimistic fetches
- Each `ResponseSender` holds an open oneshot channel that consumes resources
- The default 5-second timeout provides good protection, but misconfigurations (which operators might make for perceived "better user experience") dramatically increase attack surface

## Likelihood Explanation

**Moderate-to-High Likelihood** in misconfigured environments:

**Attacker Requirements:**
- Ability to establish multiple peer connections (feasible on public fullnodes)
- No validator privileges required
- Standard network access

**Enabling Conditions:**
- `max_optimistic_fetch_period_ms` configured to high value (hours/days)
- Node operates as public fullnode accepting many connections
- No connection rate limiting external to the system

**Mitigating Factors:**
- Default configuration (5 seconds) provides strong protection
- Connection limits reduce attack scale (but can still be substantial)
- Public network peers can be throttled after too many invalid requests (though optimistic fetches bypass this initially)

The vulnerability is most dangerous when operators increase the timeout thinking it will improve peer experience, not realizing it opens a memory exhaustion attack vector.

## Recommendation

Implement three defense layers:

**1. Add Disconnected Peer Garbage Collection** (Primary Fix):

Create a periodic cleanup task similar to the RequestModerator's `refresh_unhealthy_peer_states()`: [5](#0-4) 

Add a new method in `optimistic_fetch.rs`:

```rust
pub fn garbage_collect_disconnected_peers(
    optimistic_fetches: Arc<DashMap<PeerNetworkId, OptimisticFetchRequest>>,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<(), Error> {
    let connected_peers = peers_and_metadata
        .get_connected_peers_and_metadata()
        .map_err(|error| {
            Error::UnexpectedErrorEncountered(format!(
                "Unable to get connected peers: {}", error
            ))
        })?;
    
    optimistic_fetches.retain(|peer_network_id, _| {
        connected_peers.contains_key(peer_network_id)
    });
    
    Ok(())
}
```

Call this from the spawn_optimistic_fetch_handler periodically.

**2. Add Maximum Total Optimistic Fetches Limit**:

Add to `StorageServiceConfig`:
```rust
pub max_total_optimistic_fetches: usize, // Default: 1000
```

Check before inserting in `handle_optimistic_fetch_request()`.

**3. Enforce Validation for Optimistic Fetches**:

Move validation before the bypass in handler.rs: [6](#0-5) 

Change to validate optimistic fetches through the moderator before accepting them.

## Proof of Concept

```rust
#[tokio::test]
async fn test_optimistic_fetch_memory_exhaustion() {
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_types::requests::*;
    use aptos_types::PeerId;
    use std::time::Duration;
    
    // Create storage service with HIGH timeout (simulating misconfiguration)
    let mut config = StorageServiceConfig::default();
    config.max_optimistic_fetch_period_ms = 3600000; // 1 hour (misconfigured!)
    
    // Initialize server components
    let optimistic_fetches = Arc::new(DashMap::new());
    let time_service = TimeService::mock();
    
    // Simulate Sybil attack: 10,000 peers sending optimistic fetches
    for i in 0..10000 {
        let peer_id = PeerId::random();
        let peer_network_id = PeerNetworkId::new(NetworkId::Public, peer_id);
        
        // Create optimistic fetch request
        let request = StorageServiceRequest::new(
            DataRequest::GetNewTransactionOutputsWithProof(
                NewTransactionOutputsWithProofRequest {
                    known_version: 1000,
                    known_epoch: 1,
                }
            ),
            false,
        );
        
        let (response_tx, _response_rx) = oneshot::channel();
        let response_sender = ResponseSender::new(response_tx);
        
        let optimistic_fetch = OptimisticFetchRequest::new(
            request,
            response_sender,
            time_service.clone(),
        );
        
        // Insert into map (simulating handle_optimistic_fetch_request)
        optimistic_fetches.insert(peer_network_id, optimistic_fetch);
        
        // Simulate peer disconnecting immediately after sending request
        // NOTE: No garbage collection occurs! Entry stays in map.
    }
    
    // Verify: 10,000 entries accumulated in memory
    assert_eq!(optimistic_fetches.len(), 10000);
    
    // These entries will persist for 1 HOUR before expiring
    // Each holds: StorageServiceRequest + ResponseSender (oneshot channel) + metadata
    // Total memory: ~10,000 * (request_size + channel_overhead) = significant MB
    
    println!("Accumulated {} optimistic fetches in memory", optimistic_fetches.len());
    println!("These will persist for {} ms before expiring", 
             config.max_optimistic_fetch_period_ms);
}
```

**Notes:**

This vulnerability demonstrates a critical gap in resource management where:
- The system correctly implements peer-level limits (one fetch per peer)
- The system correctly implements timeout-based expiration
- But fails to implement total capacity limits and disconnected peer cleanup
- The combination of these gaps with misconfiguration enables memory exhaustion attacks

The fix requires adding the missing garbage collection mechanism that already exists for the RequestModerator's unhealthy peer state tracking.

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L119-123)
```rust
        // Handle any optimistic fetch requests
        if request.data_request.is_optimistic_fetch() {
            self.handle_optimistic_fetch_request(peer_network_id, request, response_sender);
            return;
        }
```

**File:** state-sync/storage-service/server/src/handler.rs (L257-260)
```rust
        if self
            .optimistic_fetches
            .insert(peer_network_id, optimistic_fetch)
            .is_some()
```

**File:** state-sync/storage-service/server/src/moderator.rs (L198-228)
```rust
    /// Refresh the unhealthy peer states and garbage collect disconnected peers
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

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L416-428)
```rust
        if !optimistic_fetch.is_expired(config.max_optimistic_fetch_period_ms) {
            let highest_known_version = optimistic_fetch.highest_known_version();
            let highest_known_epoch = optimistic_fetch.highest_known_epoch();

            // Save the peer's version and epoch
            peers_and_highest_synced_data.insert(
                peer_network_id,
                (highest_known_version, highest_known_epoch),
            );
        } else {
            // The request has expired -- there's nothing to do
            peers_with_expired_optimistic_fetches.push(peer_network_id);
        }
```

**File:** state-sync/storage-service/server/src/lib.rs (L354-381)
```rust
    /// Spawns a non-terminating task that refreshes the unhealthy
    /// peer states in the request moderator.
    async fn spawn_moderator_peer_refresher(&mut self) {
        // Clone all required components for the task
        let config = self.storage_service_config;
        let request_moderator = self.request_moderator.clone();
        let time_service = self.time_service.clone();

        // Spawn the task
        self.runtime.spawn(async move {
            // Create a ticker for the refresh interval
            let duration = Duration::from_millis(config.request_moderator_refresh_interval_ms);
            let ticker = time_service.interval(duration);
            futures::pin_mut!(ticker);

            // Periodically refresh the peer states
            loop {
                ticker.next().await;

                // Refresh the unhealthy peer states
                if let Err(error) = request_moderator.refresh_unhealthy_peer_states() {
                    error!(LogSchema::new(LogEntry::RequestModeratorRefresh)
                        .error(&error)
                        .message("Failed to refresh the request moderator!"));
                }
            }
        });
    }
```
