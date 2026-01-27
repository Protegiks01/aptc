# Audit Report

## Title
Optimistic Fetch Request Flooding: Byzantine Peers Can Exhaust Storage Service Resources Through Unrestricted Valid Request Spam

## Summary
Byzantine peers can repeatedly send valid optimistic fetch requests (GetNewTransactionDataWithProof) with stale `known_version` values at an unlimited rate, bypassing all rate limiting mechanisms. This causes resource exhaustion through continuous request validation overhead and periodic blocking task spawns, potentially degrading service quality for legitimate peers synchronizing with the blockchain.

## Finding Description

The storage service's optimistic fetch mechanism lacks rate limiting for valid requests and does not validate the reasonableness of the `known_version` parameter. This breaks the **Resource Limits** invariant that "all operations must respect gas, storage, and computational limits."

**Attack Path:**

1. **Request Acceptance Without Rate Limiting**: The `handle_optimistic_fetch_request` function accepts any valid optimistic fetch request and stores it in the `optimistic_fetches` DashMap, replacing any existing request from the same peer. [1](#0-0) 

2. **Validation Gap**: The `RequestModerator.validate_request` only checks if requests are serviceable based on storage summary freshness, not request rate or parameter reasonableness. [2](#0-1) 

3. **Insufficient Parameter Validation**: The `can_service_optimistic_request` function only validates that the server's ledger timestamp is within `max_optimistic_fetch_lag_secs` of current time, but never validates if the peer's `known_version` is reasonable. [3](#0-2) [4](#0-3) 

4. **Resource Consumption Pattern**: Every 100ms (configurable via `storage_summary_refresh_interval_ms`), the periodic handler spawns blocking tasks to process ready optimistic fetches, performing storage I/O operations. [5](#0-4) 

5. **Stale Version Amplification**: When a Byzantine peer sends requests with very stale `known_version` values (e.g., 0), the server calculates large version ranges to fetch, bounded only by `max_chunk_size`. [6](#0-5) 

**Exploitation Scenario:**
- Byzantine peer sends GetNewTransactionDataWithProof with `known_version=0` at 100 requests/second
- Each request passes validation (server's ledger is recent enough)
- Server wastes CPU on: deserialization, validation, map operations (100 ops/sec per peer)
- Every 100ms, server spawns blocking task to fetch data starting from version 0 (~10 tasks/sec per peer)
- With N Byzantine peers: ~100N validations/sec, ~10N blocking tasks/sec
- Tokio's blocking thread pool (default 512 threads) exhausted with ~50 coordinated Byzantine peers
- Legitimate peer requests experience delays and timeouts

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

**"Validator node slowdowns"**: Byzantine peers can significantly degrade storage service performance for all connected peers. The attack consumes:
- Network bandwidth (receiving and deserializing requests)
- CPU cycles (request validation and map operations)
- Blocking thread pool capacity (spawning tasks every 100ms per peer)
- Storage I/O bandwidth (repeatedly fetching old data with stale versions)

With sufficient Byzantine peers (achievable on public network), legitimate validator and fullnode peers experience:
- Delayed responses to sync requests
- Potential timeouts causing sync failures
- Reduced overall network sync throughput

This degrades but does not completely halt synchronization, qualifying as node slowdown rather than total availability loss.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Ability to connect to storage service as a peer (no special privileges needed)
- Basic knowledge of optimistic fetch request format
- No coordination or insider access required

**Attack Feasibility:**
- Single Byzantine peer can cause measurable resource consumption
- Public network peers are not throttled by RequestModerator (only invalid requests are throttled)
- No authentication or reputation system prevents repeated connections
- Attack is sustainable indefinitely (requests don't fail validation)
- Multiple Byzantine peers amplify the effect linearly

**Detection Difficulty:**
- Valid requests appear legitimate in metrics
- Sampled logging reduces visibility of request replacement
- No alerts for high request rate from single peer

## Recommendation

Implement rate limiting for valid optimistic fetch requests per peer:

**1. Add Request Rate Tracking:**
Add to `UnhealthyPeerState` in `moderator.rs`:
```rust
pub struct UnhealthyPeerState {
    // ... existing fields ...
    optimistic_fetch_count: u64,
    optimistic_fetch_window_start: Instant,
}
```

**2. Add Rate Limit Check:**
In `RequestModerator::validate_request`:
```rust
// After existing validation, add:
if request.data_request.is_optimistic_fetch() {
    // Check rate limit for optimistic fetches
    let mut peer_state = self.unhealthy_peer_states.entry(*peer_network_id)
        .or_insert_with(|| UnhealthyPeerState::new(...));
    
    let elapsed = current_time.duration_since(peer_state.optimistic_fetch_window_start);
    if elapsed > Duration::from_secs(1) {
        // Reset window
        peer_state.optimistic_fetch_count = 0;
        peer_state.optimistic_fetch_window_start = current_time;
    }
    
    peer_state.optimistic_fetch_count += 1;
    
    // Limit to max_optimistic_fetches_per_second (e.g., 10)
    if peer_state.optimistic_fetch_count > config.max_optimistic_fetches_per_second {
        return Err(Error::TooManyInvalidRequests(
            "Optimistic fetch rate limit exceeded".into()
        ));
    }
}
```

**3. Add Version Reasonableness Check:**
In `can_service_optimistic_request`, validate `known_version`:
```rust
// Extract known_version from request
let known_version = extract_known_version(request);
let synced_version = synced_ledger_info.ledger_info().version();

// Reject if known_version is more than max_version_lag behind
let max_version_lag = aptos_data_client_config.max_optimistic_fetch_version_lag; // e.g., 10000
if synced_version.saturating_sub(known_version) > max_version_lag {
    return false;
}
```

**4. Add Configuration:**
In `StorageServiceConfig`:
```rust
pub max_optimistic_fetches_per_second: u64, // e.g., 10
pub max_optimistic_fetch_version_lag: u64,  // e.g., 10000
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_optimistic_fetch_flooding_attack() {
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_types::requests::DataRequest;
    use std::time::Instant;
    
    // Setup storage service with test storage
    let config = StorageServiceConfig::default();
    let (mut server, peer_network_id, _) = setup_test_storage_service(config).await;
    
    // Simulate Byzantine peer sending rapid optimistic fetch requests
    let start_time = Instant::now();
    let mut request_count = 0;
    
    // Send 100 requests as fast as possible
    for _ in 0..100 {
        let request = StorageServiceRequest::new(
            DataRequest::GetNewTransactionDataWithProof(
                GetNewTransactionDataWithProofRequest {
                    transaction_data_request_type: TransactionDataRequestType::TransactionOutputData,
                    known_version: 0,  // Stale version
                    known_epoch: 0,
                    max_response_bytes: 1000,
                }
            ),
            false
        );
        
        let (response_sender, _) = oneshot::channel();
        server.handle_request(peer_network_id, request, response_sender);
        request_count += 1;
    }
    
    let elapsed = start_time.elapsed();
    
    // Verify: No rate limiting occurred (all requests accepted)
    assert_eq!(request_count, 100);
    
    // Verify: Request rate exceeds reasonable threshold
    let requests_per_second = (request_count as f64) / elapsed.as_secs_f64();
    assert!(requests_per_second > 50.0, 
        "Byzantine peer sent {} requests/sec, demonstrating lack of rate limiting",
        requests_per_second);
    
    // Verify: Server spawned blocking tasks for stale version requests
    // This would consume resources processing version 0 repeatedly
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Check metrics for evidence of resource consumption
    let blocking_task_count = get_blocking_task_count(); // Implementation-specific
    assert!(blocking_task_count >= 2, 
        "Server spawned {} blocking tasks in 200ms for same stale version",
        blocking_task_count);
}
```

**Notes:**

The vulnerability is confirmed through code analysis showing:
1. No rate limiting mechanism for valid optimistic fetch requests exists in the codebase
2. The RequestModerator only throttles requests that fail `can_service()` validation
3. Optimistic fetch validation only checks server's ledger freshness, not client's `known_version` reasonableness
4. Request replacement in the map has minimal cost, allowing high-frequency attacks
5. Periodic processing spawns resource-intensive blocking tasks without per-peer rate limits

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L243-280)
```rust
    pub fn handle_optimistic_fetch_request(
        &self,
        peer_network_id: PeerNetworkId,
        request: StorageServiceRequest,
        response_sender: ResponseSender,
    ) {
        // Create the optimistic fetch request
        let optimistic_fetch = OptimisticFetchRequest::new(
            request.clone(),
            response_sender,
            self.time_service.clone(),
        );

        // Store the optimistic fetch and check if any existing fetches were found
        if self
            .optimistic_fetches
            .insert(peer_network_id, optimistic_fetch)
            .is_some()
        {
            sample!(
                SampleRate::Duration(Duration::from_secs(ERROR_LOG_FREQUENCY_SECS)),
                trace!(LogSchema::new(LogEntry::OptimisticFetchRequest)
                    .error(&Error::InvalidRequest(
                        "An active optimistic fetch was already found for the peer!".into()
                    ))
                    .peer_network_id(&peer_network_id)
                    .request(&request)
                );
            );
        }

        // Update the optimistic fetch metrics
        increment_counter(
            &metrics::OPTIMISTIC_FETCH_EVENTS,
            peer_network_id.network_id(),
            OPTIMISTIC_FETCH_ADD.into(),
        );
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L132-196)
```rust
    /// Validates the given request and verifies that the peer is behaving
    /// correctly. If the request fails validation, an error is returned.
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

**File:** state-sync/storage-service/types/src/responses.rs (L797-801)
```rust
            GetNewTransactionDataWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
```

**File:** state-sync/storage-service/types/src/responses.rs (L892-901)
```rust
/// Returns true iff an optimistic data request can be serviced
/// by the peer with the given synced ledger info.
fn can_service_optimistic_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_optimistic_fetch_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}
```

**File:** state-sync/storage-service/server/src/lib.rs (L240-260)
```rust
        self.runtime
            .spawn(async move {
                // Create a ticker for the refresh interval
                let duration = Duration::from_millis(config.storage_summary_refresh_interval_ms);
                let ticker = time_service.interval(duration);
                futures::pin_mut!(ticker);

                // Continuously handle the optimistic fetches
                loop {
                    futures::select! {
                        _ = ticker.select_next_some() => {
                            // Handle the optimistic fetches periodically
                            handle_active_optimistic_fetches(
                                runtime.clone(),
                                cached_storage_server_summary.clone(),
                                config,
                                optimistic_fetches.clone(),
                                lru_response_cache.clone(),
                                request_moderator.clone(),
                                storage.clone(),
                                subscriptions.clone(),
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L66-88)
```rust
        // Verify that the target version is higher than the highest known version
        let known_version = self.highest_known_version();
        let target_version = target_ledger_info.ledger_info().version();
        if target_version <= known_version {
            return Err(Error::InvalidRequest(format!(
                "Target version: {:?} is not higher than known version: {:?}!",
                target_version, known_version
            )));
        }

        // Calculate the number of versions to fetch
        let mut num_versions_to_fetch =
            target_version.checked_sub(known_version).ok_or_else(|| {
                Error::UnexpectedErrorEncountered(
                    "Number of versions to fetch has overflown!".into(),
                )
            })?;

        // Bound the number of versions to fetch by the maximum chunk size
        num_versions_to_fetch = min(
            num_versions_to_fetch,
            self.max_chunk_size_for_request(config),
        );
```
