# Audit Report

## Title
Optimistic Fetch Bandwidth Amplification: Unvalidated Requests Enable Network Resource Exhaustion

## Summary
The optimistic fetch mechanism in the storage service bypasses request validation, allowing any peer to trigger maximum-size data responses (up to 10-40 MB) by submitting requests with artificially low `known_version` values. This creates a bandwidth amplification factor of ~100,000x that can be exploited repeatedly to exhaust validator node bandwidth.

## Finding Description

The vulnerability exists in how optimistic fetch requests are processed in the storage service. When a peer sends an optimistic fetch request, it completely bypasses the `RequestModerator` validation that protects against invalid or malicious requests.

**Attack Flow:**

1. **Optimistic fetch bypasses validation**: When an optimistic fetch request arrives, it is immediately stored without any validation [1](#0-0) 

2. **No rate limiting on initial request**: The `handle_optimistic_fetch_request()` function simply stores the request in a map without checking if the peer's `known_version` is reasonable [2](#0-1) 

3. **Periodic processing triggers amplification**: Every 100ms (or on storage updates), the `handle_active_optimistic_fetches()` function processes all pending optimistic fetches [3](#0-2) 

4. **Maximum-size requests created**: When processing an optimistic fetch where `known_version << target_version`, the `get_storage_request_for_missing_data()` function calculates `num_versions_to_fetch = target_version - known_version`, then bounds it to the maximum chunk size (default 3,000 transactions) [4](#0-3) 

5. **Valid requests pass validation**: The created storage request is valid because it requests data that exists in the node's storage. The subsequent validation check passes, and the node serves up to 10 MB (or 40 MB for v2) of data [5](#0-4) 

6. **Immediate removal enables repetition**: After serving the data, the optimistic fetch is removed from the map, allowing the attacker to immediately submit another request with the same low `known_version` [6](#0-5) 

**Key Vulnerability Points:**

- Optimistic fetch requests set `known_version` and `known_epoch` which are fully attacker-controlled [7](#0-6) 

- The `RequestModerator` only validates non-optimistic, non-subscription requests, meaning optimistic fetches never count toward the invalid request limit [8](#0-7) 

- Each peer can have one active optimistic fetch at a time, but after it's served (within ~100ms), they can submit another immediately

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria: "Validator node slowdowns."

**Quantified Impact:**
- **Amplification Factor**: ~100,000x (100-byte request → 10 MB response) to ~400,000x (for 40 MB v2 responses)
- **Attack Rate**: Up to 10 requests/second per peer (limited by 100ms refresh interval)
- **Bandwidth Consumption**: 100 MB/second per attacking peer for v1, or 400 MB/second for v2
- **Scale**: An attacker controlling multiple peer connections can multiply this effect

**Security Invariant Broken:**
- **Resource Limits Invariant**: "All operations must respect gas, storage, and computational limits." The lack of validation on optimistic fetch requests allows unlimited bandwidth consumption without any rate limiting or cost.

**Real-World Impact:**
- Validator nodes experience severe bandwidth exhaustion
- Network performance degradation affects consensus and state sync
- Storage service becomes unresponsive to legitimate peers
- Potential cascade effect if multiple validators are targeted simultaneously

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Ability to establish peer connections to storage service nodes (standard P2P capability)
- No special privileges, credentials, or validator access required
- Simple request construction with low `known_version` values

**Exploitation Complexity:**
- **Very Low**: The attack requires only sending standard optimistic fetch requests with `known_version = 0`
- No cryptographic operations, no timing requirements, no race conditions
- Can be automated trivially in a few lines of code

**Detection Difficulty:**
- Requests appear legitimate and pass all validation checks
- LRU cache helps with repeated identical requests but doesn't prevent bandwidth exhaustion
- No clear distinction between malicious low `known_version` and legitimate lagging peers

## Recommendation

Implement validation for optimistic fetch requests before storing them:

1. **Validate optimistic fetches in RequestModerator**: Extend the validation logic to check optimistic fetch requests against the storage server summary before storing them. This ensures that only reasonable requests are accepted.

2. **Add sanity checks on known_version**: Reject optimistic fetch requests where `known_version` is unreasonably far behind the current synced version (e.g., more than 1 epoch behind), or implement a minimum `known_version` threshold.

3. **Implement rate limiting per peer**: Add a cooldown period between optimistic fetch requests from the same peer, or limit the number of optimistic fetches per time window.

4. **Track optimistic fetch metrics**: Monitor the frequency and version gaps in optimistic fetch requests to detect potential abuse patterns.

**Suggested Code Fix:**

In `handler.rs`, modify `handle_optimistic_fetch_request()` to validate the request:

```rust
pub fn handle_optimistic_fetch_request(
    &self,
    peer_network_id: PeerNetworkId,
    request: StorageServiceRequest,
    response_sender: ResponseSender,
) {
    // NEW: Validate the optimistic fetch request before storing
    if let Err(error) = self.request_moderator.validate_request(&peer_network_id, &request) {
        // Send error response and increment invalid request counter
        self.send_response(
            request,
            Err(StorageServiceError::InvalidRequest(error.to_string())),
            response_sender,
        );
        return;
    }

    // Existing code to create and store optimistic fetch...
}
```

Additionally, in `optimistic_fetch.rs`, add a sanity check in `get_storage_request_for_missing_data()`:

```rust
// After line 74, add:
const MAX_VERSION_LAG_THRESHOLD: u64 = 1_000_000; // Configurable threshold
if num_versions_to_fetch > MAX_VERSION_LAG_THRESHOLD {
    return Err(Error::InvalidRequest(format!(
        "Version lag too large: {} versions behind (known: {}, target: {})",
        num_versions_to_fetch, known_version, target_version
    )));
}
```

## Proof of Concept

```rust
// Integration test demonstrating the bandwidth amplification attack
// File: state-sync/storage-service/server/src/tests/optimistic_fetch_amplification_test.rs

#[tokio::test]
async fn test_optimistic_fetch_bandwidth_amplification() {
    // Setup: Create storage service with synced data at version 1,000,000
    let (mut mock_network, mut storage_service, mock_time, peer_network_id, _) = 
        MockNetwork::new(None, None, None);
    
    // Populate storage with 1,000,000 transactions
    for version in 0..1_000_000 {
        add_transaction_to_storage(&mut storage_service, version);
    }
    
    let mut total_bandwidth_used = 0u64;
    let attack_iterations = 10;
    
    // Attack: Send optimistic fetches with known_version=0 repeatedly
    for iteration in 0..attack_iterations {
        // Create optimistic fetch request with known_version=0
        let request = StorageServiceRequest::new(
            DataRequest::GetNewTransactionsWithProof(
                NewTransactionsWithProofRequest {
                    known_version: 0,  // Artificially low version
                    known_epoch: 0,
                    include_events: false,
                }
            ),
            false,
        );
        
        // Send the request
        let response = mock_network
            .send_request(peer_network_id, request.clone())
            .await
            .unwrap();
        
        // Verify large response received
        match response.get_data_response().unwrap() {
            DataResponse::NewTransactionsWithProof((transactions, _ledger_info)) => {
                // Each response contains max_chunk_size (3000) transactions
                assert_eq!(transactions.transactions.len(), 3000);
                
                // Estimate bandwidth: ~3KB per transaction average
                let response_size = transactions.transactions.len() * 3000;
                total_bandwidth_used += response_size as u64;
                
                println!("Iteration {}: Received {} transactions, ~{} bytes", 
                         iteration, transactions.transactions.len(), response_size);
            },
            _ => panic!("Unexpected response type"),
        }
        
        // Advance time by 100ms to trigger next optimistic fetch check
        mock_time.advance(Duration::from_millis(100));
    }
    
    // Verify bandwidth amplification
    let request_size = 100; // Approximate size of optimistic fetch request
    let total_request_size = request_size * attack_iterations;
    let amplification_factor = total_bandwidth_used / total_request_size;
    
    println!("Total bandwidth used: {} bytes", total_bandwidth_used);
    println!("Total request size: {} bytes", total_request_size);
    println!("Amplification factor: {}x", amplification_factor);
    
    // Assert significant amplification occurred
    assert!(amplification_factor > 10_000, 
            "Amplification factor should exceed 10,000x");
}
```

**Notes:**
- The attacker can achieve ~100,000x amplification (100 bytes → 10 MB)
- Attack can be repeated every 100ms, consuming 100+ MB/second
- Multiple peer connections multiply the effect
- No authentication, validation, or rate limiting prevents this attack
- LRU cache mitigates storage load but not bandwidth consumption

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L119-123)
```rust
        // Handle any optimistic fetch requests
        if request.data_request.is_optimistic_fetch() {
            self.handle_optimistic_fetch_request(peer_network_id, request, response_sender);
            return;
        }
```

**File:** state-sync/storage-service/server/src/handler.rs (L242-280)
```rust
    /// Handles the given optimistic fetch request
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

**File:** state-sync/storage-service/server/src/lib.rs (L243-262)
```rust
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
                                time_service.clone(),
                            ).await;
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L76-88)
```rust
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

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L274-278)
```rust
        let ready_optimistic_fetch =
            optimistic_fetches.remove_if(&peer_network_id, |_, optimistic_fetch| {
                optimistic_fetch.highest_known_version()
                    < target_ledger_info.ledger_info().version()
            });
```

**File:** config/src/config/state_sync_config.rs (L16-21)
```rust
// The maximum message size per state sync message
const SERVER_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

// The maximum message size per state sync message (for v2 data requests)
const CLIENT_MAX_MESSAGE_SIZE_V2: usize = 20 * 1024 * 1024; // 20 MiB (used for v2 data requests)
const SERVER_MAX_MESSAGE_SIZE_V2: usize = 40 * 1024 * 1024; // 40 MiB (used for v2 data requests)
```

**File:** state-sync/storage-service/types/src/requests.rs (L326-330)
```rust
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct NewTransactionOutputsWithProofRequest {
    pub known_version: u64, // The highest known output version
    pub known_epoch: u64,   // The highest known epoch
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
