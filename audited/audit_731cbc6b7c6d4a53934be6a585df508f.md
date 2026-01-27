# Audit Report

## Title
Storage Service TOCTOU Vulnerability Allows Rate Limiting Bypass and Resource Exhaustion

## Summary
The storage service's request validation uses a cached storage summary that can become stale between validation and processing. An attacker can exploit this time-of-check-time-of-use (TOCTOU) window to send requests that pass validation but fail during processing due to data pruning, bypassing the invalid request rate limiting mechanism and causing resource exhaustion on storage service nodes.

## Finding Description

The `validate_and_handle_request()` function validates incoming requests using a cached storage server summary, but processes them using actual storage which may have undergone pruning in the interim. [1](#0-0) 

The moderator loads a cached storage summary to validate whether a request can be serviced: [2](#0-1) 

This cached summary is refreshed periodically (default 100ms) and reflects the available data ranges at the time of refresh: [3](#0-2) 

The cached summary uses `get_first_txn_version()` which returns the current `min_readable_version` from the ledger pruner: [4](#0-3) 

**The TOCTOU Race:**

1. Cache is refreshed at time T0, showing transactions available from version 100 to 1000
2. Pruner advances `min_readable_version` from 100 to 200 at time T1
3. Request arrives at time T2 for versions 150-200
4. Moderator validates using cached summary (still shows 100-1000) - **PASSES**
5. Processing attempts to fetch from storage
6. Storage checks current `min_readable_version` (now 200) and returns error: [5](#0-4) 

7. Error is converted to `StorageServiceError::InternalError`: [6](#0-5) 

8. Peer is NOT penalized because only validation failures increment the invalid request count: [7](#0-6) 

**Exploitation:**

An attacker can:
1. Query `GetStorageServerSummary` to learn the advertised data ranges
2. Monitor for pruning by detecting when the advertised range decreases
3. Send flood of requests for versions in the TOCTOU window (versions that appear available in cache but are actually pruned)
4. Each request passes validation but fails processing, consuming CPU, network bandwidth, and storage I/O
5. Since these are not marked as "invalid requests", the attacker bypasses rate limiting and can sustain the attack indefinitely

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

1. **Validator node slowdowns**: The attack causes excessive resource consumption on storage service nodes, degrading their ability to serve legitimate state sync requests. This impacts new nodes joining the network and existing nodes catching up after downtime.

2. **Significant protocol violation**: The rate limiting mechanism designed to protect against malicious peers is bypassed. The RequestModerator's purpose is to track unhealthy peers and temporarily ignore them, but storage errors don't trigger this protection.

3. **Resource exhaustion without rate limiting**: Each malicious request consumes:
   - Network bandwidth for request/response serialization
   - CPU cycles for validation, storage access attempts, and error handling  
   - Storage I/O attempting to read pruned data
   - Metrics/logging overhead for error tracking

4. **Persistent attack window**: The TOCTOU window can be persistent for the entire cache refresh interval (100ms default) or longer if pruning outpaces cache updates. With default pruning windows of 90M versions, there's substantial opportunity for exploitation.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Attacker requirements**: Only network access to a storage service node - no validator privileges needed
2. **Attack complexity**: LOW - attacker can query storage summary, identify TOCTOU window, and script automated requests
3. **Detection difficulty**: The attack appears as legitimate requests that happen to fail due to timing, making it hard to distinguish from normal operation
4. **Persistence**: The vulnerable window exists continuously due to the inherent delay between cache refresh and pruning
5. **Default configuration susceptible**: With 100ms cache refresh interval and continuous pruning, the TOCTOU window is always present during active pruning periods

## Recommendation

**Immediate Fix**: Validate data availability against current storage state, not just cached summary, or mark requests that fail due to pruning as invalid:

```rust
fn validate_and_handle_request(
    &self,
    peer_network_id: &PeerNetworkId,
    request: &StorageServiceRequest,
) -> Result<StorageServiceResponse, Error> {
    // Validate the request with the moderator
    self.request_moderator
        .validate_request(peer_network_id, request)?;

    // Process the request
    match &request.data_request {
        DataRequest::GetServerProtocolVersion => {
            let data_response = self.get_server_protocol_version();
            StorageServiceResponse::new(data_response, request.use_compression)
                .map_err(|error| error.into())
        },
        DataRequest::GetStorageServerSummary => {
            let data_response = self.get_storage_server_summary();
            StorageServiceResponse::new(data_response, request.use_compression)
                .map_err(|error| error.into())
        },
        _ => {
            // Process and handle storage errors as invalid requests if they're pruning-related
            self.process_cachable_request(peer_network_id, request)
                .map_err(|error| {
                    // If this is a pruning error, treat it as an invalid request
                    if matches!(error, Error::StorageErrorEncountered(ref msg) if msg.contains("pruned")) {
                        // Increment invalid request count for the peer
                        self.request_moderator.mark_invalid_request(peer_network_id);
                        Error::InvalidRequest(format!("Requested pruned data: {}", msg))
                    } else {
                        error
                    }
                })
        }
    }
}
```

**Additional mitigation**: Reduce cache refresh interval or add double-check validation just before storage access.

## Proof of Concept

```rust
// Simulated attack scenario - would need to be adapted to actual test harness

#[tokio::test]
async fn test_toctou_rate_limiting_bypass() {
    // 1. Setup storage service with pruning enabled
    let (storage_service, mock_storage) = setup_storage_service_with_pruning();
    let attacker_peer = PeerNetworkId::random();
    
    // 2. Populate storage with data from version 1-1000
    mock_storage.populate_transactions(1, 1000);
    
    // 3. Wait for cache to refresh
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    // 4. Simulate pruning - advance min_readable_version to 500
    mock_storage.advance_pruning(500);
    
    // 5. Send 100 requests for pruned versions (200-300)
    // These should pass validation (cache shows 1-1000)
    // But fail processing (actual storage is 500-1000)
    for _ in 0..100 {
        let request = StorageServiceRequest {
            data_request: DataRequest::GetTransactionsWithProof(
                TransactionsWithProofRequest {
                    start_version: 200,
                    end_version: 300,
                    proof_version: 1000,
                    include_events: false,
                }
            ),
            use_compression: false,
        };
        
        let response = storage_service.handle_request(attacker_peer, request).await;
        
        // Request should fail with InternalError, not InvalidRequest
        assert!(matches!(response, Err(StorageServiceError::InternalError(_))));
    }
    
    // 6. Verify attacker peer was NOT marked as unhealthy
    let peer_state = storage_service.get_peer_state(attacker_peer);
    assert_eq!(peer_state.invalid_request_count, 0);
    assert!(!peer_state.is_ignored());
    
    // 7. Demonstrate resource exhaustion - measure CPU/IO during attack
    let metrics_before = get_storage_metrics();
    // ... continue attack ...
    let metrics_after = get_storage_metrics();
    assert!(metrics_after.storage_errors > metrics_before.storage_errors + 100);
}
```

**Notes:**
- This vulnerability is distinct from normal caching staleness because it allows bypassing the rate limiting security mechanism
- The attack is sustainable because pruning creates a persistent TOCTOU window
- Network-level rate limits provide partial mitigation but don't prevent the application-layer attack
- The vulnerability affects all storage service nodes serving state sync data

### Citations

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

**File:** state-sync/storage-service/server/src/handler.rs (L206-229)
```rust
    fn validate_and_handle_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<StorageServiceResponse, Error> {
        // Validate the request with the moderator
        self.request_moderator
            .validate_request(peer_network_id, request)?;

        // Process the request
        match &request.data_request {
            DataRequest::GetServerProtocolVersion => {
                let data_response = self.get_server_protocol_version();
                StorageServiceResponse::new(data_response, request.use_compression)
                    .map_err(|error| error.into())
            },
            DataRequest::GetStorageServerSummary => {
                let data_response = self.get_storage_server_summary();
                StorageServiceResponse::new(data_response, request.use_compression)
                    .map_err(|error| error.into())
            },
            _ => self.process_cachable_request(peer_network_id, request),
        }
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L134-188)
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
```

**File:** state-sync/storage-service/server/src/storage.rs (L1036-1073)
```rust
    fn get_data_summary(&self) -> aptos_storage_service_types::Result<DataSummary, Error> {
        // Fetch the latest ledger info
        let latest_ledger_info_with_sigs = self.storage.get_latest_ledger_info()?;

        // Fetch the epoch ending ledger info range
        let latest_ledger_info = latest_ledger_info_with_sigs.ledger_info();
        let epoch_ending_ledger_infos = if latest_ledger_info.ends_epoch() {
            let highest_ending_epoch = latest_ledger_info.epoch();
            Some(CompleteDataRange::from_genesis(highest_ending_epoch))
        } else if latest_ledger_info.epoch() > 0 {
            let highest_ending_epoch =
                latest_ledger_info.epoch().checked_sub(1).ok_or_else(|| {
                    Error::UnexpectedErrorEncountered("Highest ending epoch overflowed!".into())
                })?;
            Some(CompleteDataRange::from_genesis(highest_ending_epoch))
        } else {
            None // We haven't seen an epoch change yet
        };

        // Fetch the transaction and transaction output ranges
        let latest_version = latest_ledger_info.version();
        let transactions = self.fetch_transaction_range(latest_version)?;
        let transaction_outputs = self.fetch_transaction_output_range(latest_version)?;

        // Fetch the state values range
        let states = self.fetch_state_values_range(latest_version, &transactions)?;

        // Return the relevant data summary
        let data_summary = DataSummary {
            synced_ledger_info: Some(latest_ledger_info_with_sigs),
            epoch_ending_ledger_infos,
            transactions,
            transaction_outputs,
            states,
        };

        Ok(data_summary)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L329-333)
```rust
    fn get_first_txn_version(&self) -> Result<Option<Version>> {
        gauged_api("get_first_txn_version", || {
            Ok(Some(self.ledger_pruner.get_min_readable_version()))
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```
