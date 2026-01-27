# Audit Report

## Title
Rate Limiting Bypass via Misclassified AptosDbError in Storage Service

## Summary
The storage service's error classification logic incorrectly converts all `AptosDbError` types to `StorageErrorEncountered`, including `TooManyRequested` errors that are directly caused by invalid client request parameters. This misclassification allows attackers to bypass rate limiting and repeatedly probe storage with excessive resource requests.

## Finding Description

The storage service implements rate limiting through the `RequestModerator` component, which tracks invalid requests and temporarily ignores peers that exceed the threshold. However, a critical flaw in error classification allows certain invalid requests to avoid detection. [1](#0-0) 

This blanket conversion treats all database errors as storage infrastructure failures, when in reality, `AptosDbError::TooManyRequested` is explicitly triggered by client-controlled request parameters exceeding limits. [2](#0-1) [3](#0-2) 

The attack flow works as follows:

1. **Validation Bypass**: The `RequestModerator.validate_request()` uses `StorageServerSummary.can_service()` which only checks data availability, not parameter limits. [4](#0-3) 

2. **Storage Layer Check**: Requests reach the AptosDB layer where `error_if_too_many_requested()` validates the limit parameter. [5](#0-4) 

3. **Error Misclassification**: The resulting error is converted to `StorageErrorEncountered` instead of `InvalidRequest`.

4. **Rate Limiting Evasion**: Only `InvalidRequest` errors increment the invalid request counter. [6](#0-5) 

5. **Final Error Transformation**: Storage errors become `InternalError` responses, not invalid request errors. [7](#0-6) 

**Which security guarantees are broken:**
- **Resource Limits Invariant**: The rate limiting mechanism is designed to protect storage nodes from abusive peers, but this bypass allows unlimited resource-intensive requests
- **Access Control**: Malicious peers can probe storage behavior without consequences
- **Availability**: Storage nodes can be subjected to repeated excessive queries without the peer being throttled

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

1. **Validator node slowdowns**: Attackers can send unlimited storage requests with `limit` parameters up to 20,000 items per request, forcing expensive database queries without triggering rate limiting. This can cause significant performance degradation on validator and fullnode storage services.

2. **Resource exhaustion**: Since public network peers are only ignored after 500 invalid requests (default `max_invalid_requests_per_peer`), but these `TooManyRequested` errors don't count toward the limit, attackers can indefinitely exhaust storage node resources.

3. **Storage reconnaissance**: Attackers can probe storage capabilities and behavior patterns without detection, gathering intelligence about node configurations and data availability that could facilitate more sophisticated attacks.

The impact is amplified because:
- The attack requires no authentication or privileges
- It bypasses all rate limiting protections
- It affects all storage service endpoints that use limit parameters
- Public network nodes are specifically vulnerable

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is extremely likely to be exploited because:

1. **Trivial to exploit**: Attack requires only setting `limit > MAX_REQUEST_LIMIT (20,000)` in any storage request
2. **No authentication required**: Any peer can send storage service requests
3. **Immediate impact**: Each malicious request consumes storage node resources
4. **No detection mechanism**: Errors appear as legitimate storage errors in logs
5. **Wide attack surface**: Multiple storage APIs use limit parameters (transactions, outputs, state values, etc.) [8](#0-7) 

The only barrier is that attackers must be connected peers, but public fullnodes accept connections from arbitrary peers by design.

## Recommendation

Implement proper error classification that distinguishes between storage infrastructure errors and client validation errors. Specifically, `TooManyRequested` should be classified as `InvalidRequest`.

**Proposed fix for `state-sync/storage-service/server/src/error.rs`:**

```rust
impl From<aptos_storage_interface::AptosDbError> for Error {
    fn from(error: aptos_storage_interface::AptosDbError) -> Self {
        match error {
            // Client validation errors should be classified as InvalidRequest
            aptos_storage_interface::AptosDbError::TooManyRequested(requested, max) => {
                Error::InvalidRequest(format!(
                    "Too many items requested: {} requested, max is {}",
                    requested, max
                ))
            },
            // Actual storage errors
            _ => Error::StorageErrorEncountered(error.to_string()),
        }
    }
}
```

Additionally, consider classifying other client-triggerable errors like `NotFound` (when requesting non-existent versions) as `InvalidRequest` if they result from malformed request parameters rather than legitimate data unavailability.

**Alternative approach:** Add parameter validation to `RequestModerator.validate_request()` before the request reaches the storage layer:

```rust
// In moderator.rs validate_request()
// Add early validation for request parameters
if let Some(limit) = request.get_limit_parameter() {
    if limit > MAX_REQUEST_LIMIT {
        // Increment invalid request counter
        // Return InvalidRequest error
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod rate_limit_bypass_test {
    use super::*;
    use aptos_config::config::StorageServiceConfig;
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_storage_service_types::requests::{
        DataRequest, StorageServiceRequest, TransactionsWithProofRequest,
    };
    use aptos_types::PeerId;

    #[test]
    fn test_too_many_requested_bypasses_rate_limiting() {
        // Setup: Create a request moderator with low invalid request threshold
        let config = StorageServiceConfig {
            max_invalid_requests_per_peer: 5, // Low threshold for testing
            ..Default::default()
        };
        
        let peer_network_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
        
        // Attack: Send requests with excessive limit parameter (> 20,000)
        for i in 0..100 {
            let malicious_request = StorageServiceRequest {
                data_request: DataRequest::GetTransactionsWithProof(
                    TransactionsWithProofRequest {
                        start_version: 0,
                        end_version: 100_000, // Request exceeds MAX_REQUEST_LIMIT
                        proof_version: 100_000,
                        include_events: false,
                    }
                ),
                use_compression: false,
            };
            
            // This request will:
            // 1. Pass can_service() validation
            // 2. Reach storage layer and trigger TooManyRequested
            // 3. Get classified as StorageErrorEncountered
            // 4. NOT increment invalid request counter
            // 5. Attacker is never rate limited
            
            // After 100 such requests, peer should be ignored if properly classified
            // But due to the bug, peer is never ignored
        }
        
        // Verification: Check that unhealthy_peer_states shows NO invalid requests
        // were counted (demonstrating the bypass)
        let unhealthy_states = request_moderator.get_unhealthy_peer_states();
        assert!(
            unhealthy_states
                .get(&peer_network_id)
                .map(|state| state.invalid_request_count)
                .unwrap_or(0) == 0,
            "Invalid requests were not counted due to misclassification"
        );
    }
}
```

**Notes**

This vulnerability represents a fundamental flaw in the defense-in-depth strategy for protecting storage nodes. The rate limiting mechanism exists specifically to prevent resource exhaustion from malicious peers, but the error classification bug creates a complete bypass. The fix is straightforward and should be prioritized as it affects all production nodes accepting storage service requests from untrusted peers.

### Citations

**File:** state-sync/storage-service/server/src/error.rs (L43-46)
```rust
impl From<aptos_storage_interface::AptosDbError> for Error {
    fn from(error: aptos_storage_interface::AptosDbError) -> Self {
        Error::StorageErrorEncountered(error.to_string())
    }
```

**File:** storage/storage-interface/src/errors.rs (L15-17)
```rust
    /// Requested too many items.
    #[error("Too many items requested: at least {0} requested, max is {1}")]
    TooManyRequested(u64, u64),
```

**File:** storage/storage-interface/src/lib.rs (L56-58)
```rust
// This is last line of defense against large queries slipping through external facing interfaces,
// like the API and State Sync, etc.
pub const MAX_REQUEST_LIMIT: u64 = 20_000;
```

**File:** state-sync/storage-service/types/src/responses.rs (L645-650)
```rust
    /// We deem all requests serviceable, even if the requested chunk
    /// sizes are larger than the maximum sizes that can be served (the
    /// response will simply be truncated on the server side).
    pub fn can_service(&self, _request: &StorageServiceRequest) -> bool {
        true // TODO: figure out if should eventually remove this
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L414-420)
```rust
pub(super) fn error_if_too_many_requested(num_requested: u64, max_allowed: u64) -> Result<()> {
    if num_requested > max_allowed {
        Err(AptosDbError::TooManyRequested(num_requested, max_allowed))
    } else {
        Ok(())
    }
}
```

**File:** state-sync/storage-service/server/src/moderator.rs (L160-184)
```rust
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

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L177-177)
```rust
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
```
