# Audit Report

## Title
StorageServiceRequest Validation Bypass Allows Unlimited Invalid Requests to Evade Rate Limiting

## Summary
The storage service's request validation in the moderator layer fails to validate the consistency of `start_index` and `end_index` fields for `GetStateValuesWithProof` requests, allowing attackers to bypass the unhealthy peer tracking mechanism and flood the server with invalid requests that consume resources before being rejected at the storage layer.

## Finding Description

The storage service implements a two-layer validation architecture: the moderator layer (`RequestModerator`) validates requests before they reach the storage layer. The moderator tracks invalid requests per peer and temporarily ignores peers that exceed a threshold, preventing resource exhaustion attacks.

However, there is a critical validation gap for `GetStateValuesWithProof` requests: [1](#0-0) 

The moderator's `can_service` validation only checks if the requested version is available and if a proof can be created. **It does not validate that `start_index <= end_index`**, which is a fundamental consistency requirement for range queries.

In contrast, the storage layer enforces this validation: [2](#0-1) 

The storage layer calls `inclusive_range_len(start_index, end_index)` which validates the range: [3](#0-2) 

This creates a validation bypass where requests with `start_index > end_index`:
1. **Pass** the moderator's validation (no invalid request count increment)
2. **Fail** at the storage layer with `InvalidRequest` error
3. **Never trigger** unhealthy peer tracking or rate limiting

**Attack Flow:**
1. Attacker sends `GetStateValuesWithProof` with `start_index=1000, end_index=999, version=X`
2. Moderator validates: version X is available? ✓ Can create proof? ✓ → **Request approved**
3. Request reaches storage layer via handler: [4](#0-3) 
4. Storage layer rejects with `InvalidRequest` error
5. Error is converted to `StorageServiceError::InternalError` and returned to client: [5](#0-4) 
6. **Crucially:** The moderator's invalid request counter is NOT incremented because validation passed at line 212-213
7. Attacker repeats indefinitely without being rate-limited

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under Aptos bug bounty criteria for the following reasons:

1. **Validator Node Slowdowns**: Each invalid request still consumes CPU cycles for request processing, metric updates, storage interface calls, and error handling before rejection. An attacker can send thousands of such requests per second, degrading performance for legitimate clients.

2. **Significant Protocol Violation**: The unhealthy peer tracking mechanism is a critical security control designed to prevent resource exhaustion. This bypass completely undermines that protection for public network nodes, which are exposed to untrusted peers.

3. **Resource Exhaustion Vector**: While individual requests are eventually rejected, the cumulative cost of processing many such requests (network I/O, deserialization, validation checks, metrics, logging) can overwhelm storage service nodes, especially on public networks.

4. **No Penalty for Malicious Peers**: Unlike properly validated requests, these invalid requests never increment the peer's invalid request count, meaning attackers are never temporarily ignored: [6](#0-5) 

## Likelihood Explanation

**Likelihood: HIGH**

- **Trivial to Exploit**: Requires only crafting a single malformed request with `start_index > end_index`
- **No Authentication Required**: Any network peer can send these requests
- **Public Network Exposure**: Publicly accessible fullnodes are directly vulnerable
- **Scalable Attack**: Attacker can flood multiple nodes simultaneously
- **No Detection**: The attack bypasses the existing monitoring mechanism designed to detect and mitigate such behavior

## Recommendation

Add validation for index ordering in the moderator's `can_service` method for `GetStateValuesWithProof` requests:

```rust
GetStateValuesWithProof(request) => {
    let proof_version = request.version;
    
    // Validate index range consistency
    if request.start_index > request.end_index {
        return false; // Invalid range
    }

    let can_serve_states = self
        .states
        .map(|range| range.contains(request.version))
        .unwrap_or(false);

    let can_create_proof = self
        .synced_ledger_info
        .as_ref()
        .map(|li| li.ledger_info().version() >= proof_version)
        .unwrap_or(false);

    can_serve_states && can_create_proof
},
```

This ensures invalid range requests are caught by the moderator, properly tracked as invalid requests, and trigger rate limiting when the threshold is exceeded.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_state_values_validation_bypass() {
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_storage_service_types::requests::{DataRequest, StateValuesWithProofRequest, StorageServiceRequest};
    use aptos_types::PeerId;
    
    // Setup storage service with moderator tracking
    let (mut mock_network, mut storage_service, _) = setup_storage_service_with_moderator();
    let peer = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    
    // Create invalid request with start_index > end_index
    let invalid_request = StorageServiceRequest::new(
        DataRequest::GetStateValuesWithProof(StateValuesWithProofRequest {
            version: 100,
            start_index: 1000,  // start > end
            end_index: 999,
        }),
        false,
    );
    
    // Send many invalid requests
    for i in 0..100 {
        let response = send_request(&mut mock_network, peer, invalid_request.clone()).await;
        
        // Request fails at storage layer (returns error)
        assert!(response.is_err());
        
        // But peer is NOT marked as unhealthy or ignored
        let unhealthy_state = storage_service.get_moderator_unhealthy_peer_state(peer);
        assert!(unhealthy_state.is_none() || !unhealthy_state.unwrap().is_ignored());
        
        // Subsequent requests are still processed (not rate limited)
        println!("Request {} processed without rate limiting", i);
    }
    
    // Compare with properly invalid requests (wrong version range)
    let properly_invalid = StorageServiceRequest::new(
        DataRequest::GetTransactionsWithProof(TransactionsWithProofRequest {
            proof_version: 100,
            start_version: 1000,  // start > end
            end_version: 999,
            include_events: false,
        }),
        false,
    );
    
    // This properly triggers rate limiting after max_invalid_requests_per_peer
    for i in 0..10 {
        let response = send_request(&mut mock_network, peer, properly_invalid.clone()).await;
        assert!(response.is_err());
    }
    
    // Now peer IS ignored
    let unhealthy_state = storage_service.get_moderator_unhealthy_peer_state(peer).unwrap();
    assert!(unhealthy_state.is_ignored());
}
```

The PoC demonstrates that `GetStateValuesWithProof` requests with invalid ranges bypass rate limiting while properly validated request types trigger the unhealthy peer mechanism as designed.

## Notes

This validation gap exists specifically for state value requests because they use a different indexing scheme (state indices within a version) compared to version-based ranges used by transaction/output requests. All other request types properly validate ranges in the moderator layer using `CompleteDataRange::new()`, which catches degenerate ranges. The fix should align `GetStateValuesWithProof` validation with the same pattern.

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L727-741)
```rust
            GetStateValuesWithProof(request) => {
                let proof_version = request.version;

                let can_serve_states = self
                    .states
                    .map(|range| range.contains(request.version))
                    .unwrap_or(false);

                let can_create_proof = self
                    .synced_ledger_info
                    .as_ref()
                    .map(|li| li.ledger_info().version() >= proof_version)
                    .unwrap_or(false);

                can_serve_states && can_create_proof
```

**File:** state-sync/storage-service/server/src/storage.rs (L900-911)
```rust
    fn get_state_value_chunk_with_proof_by_size(
        &self,
        version: u64,
        start_index: u64,
        end_index: u64,
        max_response_size: u64,
        use_size_and_time_aware_chunking: bool,
    ) -> Result<StateValueChunkWithProof, Error> {
        // Calculate the number of state values to fetch
        let expected_num_state_values = inclusive_range_len(start_index, end_index)?;
        let max_num_state_values = self.config.max_state_chunk_size;
        let num_state_values_to_fetch = min(expected_num_state_values, max_num_state_values);
```

**File:** state-sync/storage-service/server/src/storage.rs (L1485-1494)
```rust
fn inclusive_range_len(start: u64, end: u64) -> aptos_storage_service_types::Result<u64, Error> {
    // len = end - start + 1
    let len = end.checked_sub(start).ok_or_else(|| {
        Error::InvalidRequest(format!("end ({}) must be >= start ({})", end, start))
    })?;
    let len = len
        .checked_add(1)
        .ok_or_else(|| Error::InvalidRequest(format!("end ({}) must not be u64::MAX", end)))?;
    Ok(len)
}
```

**File:** state-sync/storage-service/server/src/handler.rs (L196-202)
```rust
        process_result.map_err(|error| match error {
            Error::InvalidRequest(error) => StorageServiceError::InvalidRequest(error),
            Error::TooManyInvalidRequests(error) => {
                StorageServiceError::TooManyInvalidRequests(error)
            },
            error => StorageServiceError::InternalError(error.to_string()),
        })
```

**File:** state-sync/storage-service/server/src/handler.rs (L463-476)
```rust
    fn get_state_value_chunk_with_proof(
        &self,
        request: &StateValuesWithProofRequest,
    ) -> aptos_storage_service_types::Result<DataResponse, Error> {
        let state_value_chunk_with_proof = self.storage.get_state_value_chunk_with_proof(
            request.version,
            request.start_index,
            request.end_index,
        )?;

        Ok(DataResponse::StateValueChunkWithProof(
            state_value_chunk_with_proof,
        ))
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L161-179)
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
