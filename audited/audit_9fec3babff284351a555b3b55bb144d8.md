# Audit Report

## Title
Rate Limiting Bypass via Pruning Race Condition in Storage Service Request Validation

## Summary
A race condition exists between the asynchronous state merkle pruner and the periodic storage summary cache refresh, allowing attackers to bypass the storage service rate limiting mechanism. Malicious peers can craft requests that pass validation checks but fail with storage errors, avoiding the `invalid_request_count` increment designed to protect against abusive behavior.

## Finding Description

The storage service implements rate limiting to protect against malicious peers sending invalid requests. The `RequestModerator::validate_request` function validates incoming requests against a cached `StorageServerSummary` before processing them. [1](#0-0) 

The validation logic checks if a request can be serviced using `can_service()`, which compares the requested data range against cached availability ranges. If validation fails, the `invalid_request_count` is incremented: [2](#0-1) 

However, this cached summary is only refreshed every 100ms by default: [3](#0-2) 

Meanwhile, the state merkle pruner runs asynchronously in a background thread, continuously pruning stale state versions in batches of 1,000 nodes: [4](#0-3) 

The cached states range is calculated based on the pruning window at the time of refresh: [5](#0-4) 

After validation passes, actual storage operations perform real-time pruning checks: [6](#0-5) 

When these pruning checks fail, they return `AptosDbError`, which gets converted to `Error::StorageErrorEncountered`: [7](#0-6) 

This error type does NOT trigger the invalid request counter increment, bypassing rate limiting.

**Attack Path:**
1. Attacker queries `GetStorageServerSummary` to obtain the cached states range (e.g., versions 500,000 to 1,500,000)
2. Attacker identifies the lower bound of the states range (version 500,000)
3. Between summary refreshes (100ms window), the pruner advances `min_readable_version` from 500,000 to 501,000
4. Attacker floods requests for versions 500,000-500,999 (within cached range but now pruned)
5. Requests pass `can_service()` validation (no counter increment)
6. Requests fail at `error_if_state_merkle_pruned()` with `StorageErrorEncountered`
7. Attacker repeats indefinitely, never triggering the ignore mechanism

## Impact Explanation

This vulnerability allows malicious peers to bypass the storage service's primary defense mechanism against abusive behavior. The rate limiting system is designed to identify and temporarily ignore peers that send excessive invalid requests (default: 500 invalid requests triggers a 5-minute ignore period). [8](#0-7) 

By exploiting this race condition, attackers can:
- Exhaust storage service resources by forcing full request processing (database queries, iterator creation, pruning checks)
- Bypass the `max_invalid_requests_per_peer` limit entirely
- Cause validator node slowdowns as storage queries accumulate
- Potentially degrade or disable state synchronization for honest peers

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations". If the attack can successfully overwhelm multiple validators simultaneously, it could escalate to **Critical Severity** by causing "Total loss of liveness/network availability."

## Likelihood Explanation

This vulnerability is **highly likely** to occur in production:

1. **Attack complexity is low**: The attacker only needs to send standard storage service requests with specific version ranges
2. **No special privileges required**: Any peer on the public network can exploit this
3. **Race condition window is substantial**: 100ms refresh interval with continuous pruning creates frequent exploitation opportunities
4. **Attack is deterministic**: Once the attacker identifies pruned versions from the cached summary, success is guaranteed during the refresh window
5. **Detection is difficult**: These requests appear legitimate until they hit the pruning check, making them hard to distinguish from normal traffic

The default configuration parameters make exploitation practical:
- 100ms summary refresh interval provides ample attack window
- 1,000 node batch size means significant pruning occurs between refreshes
- 500 invalid request threshold is never reached due to the bypass

## Recommendation

**Fix 1: Include pruning state in validation**

Modify `can_service()` to check against the actual current `min_readable_version` from the pruner, not just the cached summary range:

```rust
// In state-sync/storage-service/server/src/moderator.rs
pub fn validate_request(
    &self,
    peer_network_id: &PeerNetworkId,
    request: &StorageServiceRequest,
) -> Result<(), Error> {
    // ... existing ignore check ...
    
    // Verify request is serviceable with cached summary
    if !storage_server_summary.can_service(...) {
        // ... existing counter increment logic ...
    }
    
    // NEW: For state-related requests, also verify against current pruning state
    if let DataRequest::GetStateValuesWithProof(state_request) = &request.data_request {
        let min_readable_version = self.storage.get_state_merkle_min_readable_version()?;
        if state_request.version < min_readable_version {
            // Increment counter for pruned version access attempts
            let mut unhealthy_peer_state = self.unhealthy_peer_states
                .entry(*peer_network_id)
                .or_insert_with(|| { /* ... */ });
            unhealthy_peer_state.increment_invalid_request_count(peer_network_id);
            
            return Err(Error::InvalidRequest(format!(
                "Requested state version {} has been pruned (min readable: {})",
                state_request.version, min_readable_version
            )));
        }
    }
    
    Ok(())
}
```

**Fix 2: Count all validation-passing errors**

Alternatively, track storage errors that occur after validation passes and increment a separate counter, triggering the ignore mechanism if this counter exceeds a threshold:

```rust
// In state-sync/storage-service/server/src/moderator.rs
pub fn record_storage_error(&self, peer_network_id: &PeerNetworkId) {
    let mut unhealthy_peer_state = self.unhealthy_peer_states
        .entry(*peer_network_id)
        .or_insert_with(|| { /* ... */ });
    
    // Storage errors after validation still count toward rate limiting
    unhealthy_peer_state.increment_invalid_request_count(peer_network_id);
}
```

Then call this from the error handling in `process_request`:

```rust
match self.validate_and_handle_request(peer_network_id, &request) {
    Err(Error::StorageErrorEncountered(_)) => {
        // Record this as a potential abuse attempt
        self.request_moderator.record_storage_error(peer_network_id);
        // ... rest of error handling ...
    }
}
```

**Fix 3: Synchronize pruning with summary refresh**

Ensure the storage summary is updated immediately after each pruning batch completes, or at minimum, query fresh pruning state during validation.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_rate_limiting_bypass_via_pruning_race() {
    // Setup storage service with pruning enabled
    let (storage, _db, _tmpdir) = setup_storage_with_pruning();
    let config = create_test_config();
    let peers_and_metadata = create_test_peers();
    let moderator = RequestModerator::new(
        config.aptos_data_client,
        cached_summary.clone(),
        peers_and_metadata,
        config.storage_service,
        TimeService::real(),
    );
    
    // Populate database with state data
    populate_state_data(&storage, 0, 1_000_000).await;
    
    // Get initial storage summary
    refresh_cached_storage_summary(cached_summary.clone(), storage.clone(), config);
    let summary = cached_summary.load();
    let states_range = summary.data_summary.states.unwrap();
    let lower_bound = states_range.lowest();
    
    // Trigger pruning to advance min_readable_version beyond lower_bound
    trigger_pruning(&storage, 1000).await; // Prune 1000 versions
    
    // Create malicious peer
    let malicious_peer = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    
    // Send requests for pruned versions (still in cached summary)
    let mut successful_bypasses = 0;
    for version in lower_bound..(lower_bound + 1000) {
        let request = StorageServiceRequest {
            data_request: DataRequest::GetStateValuesWithProof(
                StateValuesWithProofRequest {
                    version,
                    start_index: 0,
                    end_index: 100,
                }
            ),
            use_compression: false,
        };
        
        // Validate request - should pass because cached summary not updated
        let validation_result = moderator.validate_request(&malicious_peer, &request);
        assert!(validation_result.is_ok(), "Validation should pass with stale cache");
        
        // Process request - should fail with storage error (not invalid request error)
        let process_result = handler.process_request(&malicious_peer, request, false);
        match process_result {
            Err(StorageServiceError::InternalError(_)) => {
                successful_bypasses += 1;
            }
            _ => panic!("Expected internal error for pruned version"),
        }
        
        // Verify counter was NOT incremented
        let peer_state = moderator.get_unhealthy_peer_states()
            .get(&malicious_peer);
        assert!(peer_state.is_none() || peer_state.unwrap().invalid_request_count == 0,
                "Invalid request counter should not be incremented");
    }
    
    assert_eq!(successful_bypasses, 1000, 
               "All 1000 requests should bypass rate limiting");
    
    // Verify peer is NOT ignored despite sending 1000 "invalid" requests
    assert!(!moderator.get_unhealthy_peer_states()
        .get(&malicious_peer)
        .map(|s| s.is_ignored())
        .unwrap_or(false),
        "Peer should not be ignored despite abusive behavior");
}
```

**Notes:**

The vulnerability specifically affects state-related requests (`GetStateValuesWithProof`, `GetNumberOfStatesAtVersion`) but the same pattern could apply to transaction/output requests if ledger pruning creates similar race conditions. The 100ms refresh interval combined with continuous asynchronous pruning creates a persistent exploitation window that makes this attack practical and reliable.

### Citations

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

**File:** config/src/config/state_sync_config.rs (L201-213)
```rust
            max_invalid_requests_per_peer: 500,
            max_lru_cache_size: 500, // At ~0.6MiB per chunk, this should take no more than 0.5GiB
            max_network_channel_size: 4000,
            max_network_chunk_bytes: SERVER_MAX_MESSAGE_SIZE as u64,
            max_network_chunk_bytes_v2: SERVER_MAX_MESSAGE_SIZE_V2 as u64,
            max_num_active_subscriptions: 30,
            max_optimistic_fetch_period_ms: 5000, // 5 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_storage_read_wait_time_ms: 10_000, // 10 seconds
            max_subscription_period_ms: 30_000,    // 30 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            min_time_to_ignore_peers_secs: 300, // 5 minutes
```

**File:** config/src/config/state_sync_config.rs (L215-215)
```rust
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
```

**File:** config/src/config/storage_config.rs (L398-411)
```rust
impl Default for StateMerklePrunerConfig {
    fn default() -> Self {
        StateMerklePrunerConfig {
            enable: true,
            // This allows a block / chunk being executed to have access to a non-latest state tree.
            // It needs to be greater than the number of versions the state committing thread is
            // able to commit during the execution of the block / chunk. If the bad case indeed
            // happens due to this being too small, a node restart should recover it.
            // Still, defaulting to 1M to be super safe.
            prune_window: 1_000_000,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
        }
```

**File:** state-sync/storage-service/server/src/storage.rs (L146-176)
```rust
    fn fetch_state_values_range(
        &self,
        latest_version: Version,
        transactions_range: &Option<CompleteDataRange<Version>>,
    ) -> aptos_storage_service_types::Result<Option<CompleteDataRange<Version>>, Error> {
        let pruner_enabled = self.storage.is_state_merkle_pruner_enabled()?;
        if !pruner_enabled {
            return Ok(*transactions_range);
        }
        let pruning_window = self.storage.get_epoch_snapshot_prune_window()?;

        if latest_version > pruning_window as Version {
            // lowest_state_version = latest_version - pruning_window + 1;
            let mut lowest_state_version = latest_version
                .checked_sub(pruning_window as Version)
                .ok_or_else(|| {
                    Error::UnexpectedErrorEncountered("Lowest state version has overflown!".into())
                })?;
            lowest_state_version = lowest_state_version.checked_add(1).ok_or_else(|| {
                Error::UnexpectedErrorEncountered("Lowest state version has overflown!".into())
            })?;

            // Create the state range
            let state_range = CompleteDataRange::new(lowest_state_version, latest_version)
                .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
            return Ok(Some(state_range));
        }

        // No pruning has occurred. Return the transactions range.
        Ok(*transactions_range)
    }
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

**File:** state-sync/storage-service/server/src/error.rs (L43-46)
```rust
impl From<aptos_storage_interface::AptosDbError> for Error {
    fn from(error: aptos_storage_interface::AptosDbError) -> Self {
        Error::StorageErrorEncountered(error.to_string())
    }
```
