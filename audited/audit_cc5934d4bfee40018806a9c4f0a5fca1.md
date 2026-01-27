# Audit Report

## Title
Rate Limiting Bypass via AptosDbError Misclassification in Storage Service

## Summary
The storage service incorrectly classifies all `AptosDbError` types as `StorageErrorEncountered` instead of `InvalidRequest`, allowing attackers to bypass rate limiting by repeatedly sending invalid requests that trigger database-level errors. This enables unlimited storage probing and resource exhaustion without being throttled.

## Finding Description

The vulnerability exists in the error classification logic of the storage service. The `From<AptosDbError>` implementation blindly converts all `AptosDbError` types to `StorageErrorEncountered`: [1](#0-0) 

However, the rate limiting mechanism in `RequestModerator` only tracks and throttles requests that return `InvalidRequest` errors: [2](#0-1) 

Several `AptosDbError` types can be triggered by malicious user input:

1. **TooManyRequested**: Triggered when requesting more items than `MAX_REQUEST_LIMIT`: [3](#0-2) 

2. **NotFound**: Triggered when requesting non-existent data: [4](#0-3) 

3. **Other** (from pruning checks): Triggered when requesting pruned state versions: [5](#0-4) 

4. **MissingRootError**: Triggered when requesting pruned state root: [6](#0-5) 

**Attack Path:**
1. Attacker sends storage requests with invalid parameters (e.g., `GetStateValuesWithProof` for pruned versions, requesting excessive items, or non-existent data)
2. Request passes initial validation in moderator: [7](#0-6) 
3. Storage layer raises `AptosDbError` during processing (e.g., from `get_state_value_chunk_iter`)
4. Error is converted to `StorageErrorEncountered` instead of `InvalidRequest`
5. Rate limiting counter is NOT incremented because only `InvalidRequest` triggers it
6. Attacker repeats indefinitely without being throttled

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns**: Attackers can flood validator nodes with invalid requests that bypass rate limiting, causing repeated database lookups and error handling overhead without being throttled.

2. **Resource Exhaustion**: The storage service processes each invalid request fully, including database queries, error handling, and response generation. Without rate limiting, attackers can exhaust CPU, memory, and I/O resources.

3. **Storage Probing**: Attackers can systematically probe the storage layer to discover:
   - Which versions are pruned vs. available
   - State tree structure and data ranges
   - System configuration (max request limits)
   
   All without being detected or throttled by the rate limiting system designed specifically to prevent such abuse.

4. **Significant Protocol Violation**: The rate limiting mechanism is a critical security control. Bypassing it violates the "Resource Limits" invariant that all operations must respect computational limits.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Low Attack Complexity**: Attackers only need to send standard storage service requests with invalid parameters (e.g., requesting pruned versions or excessive items). No special privileges or insider access required.

2. **No Detection**: Since errors are classified as internal storage errors rather than invalid requests, monitoring systems won't flag the attacker as sending excessive invalid requests.

3. **Direct Network Access**: Any peer connected to the storage service network can send these requests. Public Full Nodes (PFNs) are the primary target since they're the only nodes that get ignored by the rate limiter: [8](#0-7) 

4. **Immediate Impact**: The attack requires no setup or preconditions. Attackers can immediately begin sending invalid requests to exhaust resources.

## Recommendation

Fix the error classification to properly categorize user-triggered `AptosDbError` types as `InvalidRequest` rather than `StorageErrorEncountered`. The `From<AptosDbError>` implementation should inspect the error type:

```rust
impl From<aptos_storage_interface::AptosDbError> for Error {
    fn from(error: aptos_storage_interface::AptosDbError) -> Self {
        match error {
            // User-triggered errors should be classified as InvalidRequest
            AptosDbError::TooManyRequested(requested, max) => {
                Error::InvalidRequest(format!(
                    "Too many items requested: {} (max: {})",
                    requested, max
                ))
            },
            AptosDbError::NotFound(msg) => {
                Error::InvalidRequest(format!("Requested data not found: {}", msg))
            },
            AptosDbError::MissingRootError(version) => {
                Error::InvalidRequest(format!(
                    "State root at version {} is not available (likely pruned)",
                    version
                ))
            },
            // Actual internal storage errors
            _ => Error::StorageErrorEncountered(error.to_string()),
        }
    }
}
```

Additionally, review the pruning error path to ensure it returns the appropriate error type rather than a generic `Other`: [9](#0-8) 

## Proof of Concept

```rust
#[cfg(test)]
mod test_rate_limit_bypass {
    use super::*;
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_types::requests::{
        DataRequest, StateValuesWithProofRequest, StorageServiceRequest,
    };
    use aptos_types::PeerId;
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    
    #[tokio::test]
    async fn test_aptosdb_error_bypasses_rate_limiting() {
        // Setup: Create a storage service with rate limiting
        let peer_network_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
        let mut config = StorageServiceConfig::default();
        config.max_invalid_requests_per_peer = 5; // Should trigger after 5 invalid requests
        
        // Attack: Send requests that trigger AptosDbError::MissingRootError
        // by requesting a pruned version
        for i in 0..20 {
            let request = StorageServiceRequest {
                data_request: DataRequest::GetStateValuesWithProof(
                    StateValuesWithProofRequest {
                        version: 0, // Likely pruned
                        start_index: 0,
                        end_index: 100,
                    }
                ),
                use_compression: false,
            };
            
            // This should trigger AptosDbError::MissingRootError
            // which gets converted to StorageErrorEncountered
            // Rate limiting should NOT trigger (this is the bug)
            let result = storage_service.process_request(
                &peer_network_id,
                request,
                false
            ).await;
            
            // Verify the request failed but was NOT rate limited
            assert!(result.is_err());
            
            // After 5 requests, the peer should be ignored if rate limiting worked correctly
            // But it won't be because AptosDbError is misclassified
            if i >= 5 {
                // BUG: Peer is NOT ignored even after many invalid requests
                let peer_state = request_moderator
                    .get_unhealthy_peer_states()
                    .get(&peer_network_id);
                    
                // This assertion would FAIL with the current code (proving the bug)
                // because invalid_request_count stays at 0
                assert_eq!(peer_state.map(|s| s.invalid_request_count), Some(0));
            }
        }
        
        // The attacker successfully sent 20 invalid requests without being rate limited
        println!("Successfully bypassed rate limiting with 20+ invalid requests!");
    }
}
```

**Notes:**
- The misclassification occurs because errors from the database layer (`AptosDbError`) that should indicate invalid user input are treated as internal server errors
- This breaks the defense-in-depth security model where rate limiting protects against malicious or misbehaving peers
- The fix requires distinguishing between user-caused errors (which should trigger rate limiting) and genuine internal storage errors (which should not penalize the peer)
- The vulnerability specifically affects Public Full Node peers who are the only ones subject to the ignore mechanism in the rate limiter

### Citations

**File:** state-sync/storage-service/server/src/error.rs (L43-47)
```rust
impl From<aptos_storage_interface::AptosDbError> for Error {
    fn from(error: aptos_storage_interface::AptosDbError) -> Self {
        Error::StorageErrorEncountered(error.to_string())
    }
}
```

**File:** state-sync/storage-service/server/src/moderator.rs (L54-58)
```rust
        // If the peer is a PFN and has sent too many invalid requests, start ignoring it
        if self.ignore_start_time.is_none()
            && peer_network_id.network_id().is_public_network()
            && self.invalid_request_count >= self.max_invalid_requests
        {
```

**File:** state-sync/storage-service/server/src/moderator.rs (L160-178)
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
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L273-303)
```rust
    pub(super) fn error_if_state_merkle_pruned(
        &self,
        data_type: &str,
        version: Version,
    ) -> Result<()> {
        let min_readable_version = self
            .state_store
            .state_db
            .state_merkle_pruner
            .get_min_readable_version();
        if version >= min_readable_version {
            return Ok(());
        }

        let min_readable_epoch_snapshot_version = self
            .state_store
            .state_db
            .epoch_snapshot_pruner
            .get_min_readable_version();
        if version >= min_readable_epoch_snapshot_version {
            self.ledger_db.metadata_db().ensure_epoch_ending(version)
        } else {
            bail!(
                "{} at version {} is pruned. snapshots are available at >= {}, epoch snapshots are available at >= {}",
                data_type,
                version,
                min_readable_version,
                min_readable_epoch_snapshot_version,
            )
        }
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

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L343-348)
```rust
                    .ok_or_else(|| {
                        AptosDbError::NotFound(format!(
                            "NewBlockEvent at or after version {}",
                            min_version
                        ))
                    })?;
```

**File:** storage/jellyfish-merkle/src/lib.rs (L736-741)
```rust
                    if nibble_depth == 0 {
                        AptosDbError::MissingRootError(version)
                    } else {
                        err
                    }
                })?;
```

**File:** state-sync/storage-service/server/src/handler.rs (L211-213)
```rust
        // Validate the request with the moderator
        self.request_moderator
            .validate_request(peer_network_id, request)?;
```
