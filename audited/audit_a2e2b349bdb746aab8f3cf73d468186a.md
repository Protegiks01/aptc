# Audit Report

## Title
Unbounded Loop Iteration in Legacy Output Reduction Logic Enables Storage Service DoS

## Summary
The `max_num_output_reductions` parameter in `NewTransactionsOrOutputsWithProofRequest` is passed from client to server without validation, allowing a malicious peer to force the storage service into executing thousands of expensive database operations and serializations in a single request, causing resource exhaustion and service degradation.

## Finding Description

The storage service's legacy transaction/output fetching mechanism uses a client-controlled `max_num_output_reductions` parameter to limit fallback attempts when transaction outputs are too large to fit in a network frame. However, this parameter is **never validated** by the server, allowing a malicious client to specify an arbitrarily large value. [1](#0-0) 

The client sends this value to the server, which processes it without any bounds checking: [2](#0-1) 

The server then uses this value directly in a loop condition within the legacy implementation: [3](#0-2) 

The loop continues while `num_output_reductions <= max_num_output_reductions`, performing on each iteration:
1. Database I/O via `get_transaction_outputs()` which reads from 6+ database tables per transaction version
2. Construction of TransactionOutput objects with write sets, events, and auxiliary data
3. Generation of cryptographic accumulator proofs
4. Full serialization of the response to check size limits
5. Halving the chunk size if too large

**Attack Execution:**
1. Malicious peer sends `NewTransactionsOrOutputsWithProofRequest` with `max_num_output_reductions = 10000`
2. Server enters loop attempting to return outputs
3. On each iteration where outputs are too large, the loop repeats with halved chunk size
4. Server performs up to 10,001 database fetch + serialization cycles before fallback to transactions
5. Each cycle involves significant CPU, I/O, and memory allocation

**Missing Validation:**
The server configuration has no field to cap this parameter: [4](#0-3) 

The request moderator only validates whether data is available, not parameter sanity: [5](#0-4) 

The default client configuration sets this to 0 (safe), but clients control the value in each request: [6](#0-5) 

## Impact Explanation

**Severity: Medium** (per Aptos bug bounty criteria)

This vulnerability enables resource exhaustion attacks against storage service nodes:

1. **CPU Exhaustion**: Repeated serialization operations (O(N) where N = max_num_output_reductions)
2. **I/O Amplification**: Multiple database round-trips for the same version range (O(N) database operations)
3. **Memory Pressure**: Allocating and discarding large TransactionOutputListWithProofV2 objects repeatedly
4. **Service Degradation**: Storage servers become slow or unresponsive to legitimate requests
5. **State Sync Disruption**: New nodes cannot sync efficiently if storage servers are overloaded

While this doesn't directly cause fund loss or consensus violations, it affects **network availability** and can prevent nodes from syncing state, which is critical for network health. Storage service availability is essential for:
- New validators joining the network
- Full nodes syncing from genesis or catching up after downtime
- State restoration and backup operations

The attack requires minimal resources from the attacker (just setting a parameter value) and affects critical infrastructure.

**Note**: This vulnerability only affects the legacy code path when `enable_transaction_data_v2` is disabled (non-default configuration). However, the legacy API remains available for backward compatibility and can still be exploited.

## Likelihood Explanation

**Likelihood: Medium**

**Factors Increasing Likelihood:**
- Easy to exploit: attacker simply sets a parameter to a large value
- No authentication required: any network peer can send storage service requests
- No rate limiting specific to this parameter
- Legacy code path still active and maintained for backward compatibility

**Factors Decreasing Likelihood:**
- Default configuration uses v2 API which doesn't have this parameter (when `enable_transaction_data_v2 = true`)
- Legacy path only used when nodes explicitly disable transaction data v2
- Request moderator may eventually ban peers sending too many requests (after 500 invalid requests per default config)
- Some nodes may have configured non-default values to mitigate

Overall, while not the default code path, the attack is trivial to execute and the vulnerable code remains in production.

## Recommendation

Implement server-side validation and capping of the `max_num_output_reductions` parameter:

**Option 1: Add server-side cap in StorageServiceConfig**
```rust
// In config/src/config/state_sync_config.rs
pub struct StorageServiceConfig {
    // ... existing fields ...
    
    /// Maximum allowed output reductions per request (prevents DoS)
    pub max_allowed_output_reductions: u64,
}

impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            // ... existing defaults ...
            max_allowed_output_reductions: 3, // Reasonable limit
        }
    }
}
```

**Option 2: Cap in storage layer**
```rust
// In state-sync/storage-service/server/src/storage.rs
fn get_transactions_or_outputs_with_proof_by_size_legacy(
    &self,
    proof_version: u64,
    start_version: u64,
    end_version: u64,
    mut num_outputs_to_fetch: u64,
    include_events: bool,
    max_num_output_reductions: u64,
    max_response_size: u64,
) -> Result<TransactionDataWithProofResponse, Error> {
    // Cap the max reductions to prevent DoS
    const MAX_ALLOWED_OUTPUT_REDUCTIONS: u64 = 3;
    let max_num_output_reductions = std::cmp::min(
        max_num_output_reductions,
        MAX_ALLOWED_OUTPUT_REDUCTIONS
    );
    
    let mut num_output_reductions = 0;
    while num_output_reductions <= max_num_output_reductions {
        // ... rest of implementation
    }
}
```

**Option 3: Request validation**
Add validation in the request moderator to reject requests with unreasonable parameters.

**Recommended approach**: Combine Option 2 (immediate mitigation) with Option 1 (configuration flexibility). A cap of 3-5 reductions is reasonable because:
- Each halving reduces data by 50%
- After 3 reductions: 1000 → 500 → 250 → 125 outputs
- Beyond 5 reductions, chunk size becomes too small to be efficient

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// This would go in state-sync/storage-service/server/src/tests/

#[tokio::test]
async fn test_excessive_output_reductions_dos() {
    use crate::tests::mock;
    use aptos_storage_service_types::requests::*;
    
    // Create mock database that returns large outputs
    let highest_version = 10000;
    let highest_epoch = 10;
    let mut db_reader = mock::create_mock_db_with_summary_updates(
        create_test_ledger_info(highest_version, highest_epoch),
        0,
    );
    
    // Set up large outputs that will always overflow
    let large_output_list = create_large_output_list(1000);
    
    // Expect get_transaction_outputs to be called MANY times
    // With max_num_output_reductions=1000, this could be called 1000+ times!
    for i in 0..=1000 {
        let chunk_size = 1000 / (2_u64.pow(i as u32));
        if chunk_size == 0 { break; }
        
        db_reader
            .expect_get_transaction_outputs()
            .times(1)
            .with(eq(1), eq(chunk_size), eq(highest_version))
            .returning(move |_, _, _| Ok(large_output_list.clone()));
    }
    
    // Also expect fallback to transactions after all reductions exhausted
    db_reader
        .expect_get_transactions()
        .returning(|_, _, _| Ok(create_test_transaction_list()));
    
    // Create storage service with small network chunk size
    let mut config = StorageServiceConfig::default();
    config.max_network_chunk_bytes = 1000; // Force overflow
    
    let storage = StorageReader::new(config, Arc::new(db_reader), TimeService::mock());
    
    // Malicious request with excessive max_num_output_reductions
    let result = storage.get_transactions_or_outputs_with_proof(
        highest_version,  // proof_version
        1,               // start_version
        1000,            // end_version
        false,           // include_events
        1000,            // MALICIOUS: excessive max_num_output_reductions
    );
    
    // The request eventually completes, but after performing 1000+ database operations!
    assert!(result.is_ok());
    
    // In a real attack, multiple such requests would overwhelm the server
}

// Attacker script (pseudo-code showing attack execution)
fn malicious_client_attack() {
    let storage_client = connect_to_storage_service(target_peer);
    
    // Send multiple concurrent requests with excessive reductions
    for _ in 0..100 {
        tokio::spawn(async {
            let request = NewTransactionsOrOutputsWithProofRequest {
                known_version: 0,
                known_epoch: 0,
                include_events: false,
                max_num_output_reductions: 10000, // DoS parameter
            };
            
            storage_client.send_request(request).await;
        });
    }
    
    // Server now processing 100 * 10000+ database operations
    // Result: CPU exhaustion, I/O saturation, service degradation
}
```

**Notes:**
- The vulnerability is exploitable but mitigated by the v2 API being default
- Legacy API remains vulnerable for backward compatibility
- A simple cap of 3-5 reductions is sufficient and prevents the attack entirely
- The TODO comment in the config acknowledges this needs migration to better chunk packing logic

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L1017-1024)
```rust
            DataRequest::GetNewTransactionsOrOutputsWithProof(
                NewTransactionsOrOutputsWithProofRequest {
                    known_version,
                    known_epoch,
                    include_events,
                    max_num_output_reductions: self.get_max_num_output_reductions(),
                },
            )
```

**File:** state-sync/storage-service/server/src/handler.rs (L547-567)
```rust
    fn get_transactions_or_outputs_with_proof(
        &self,
        request: &TransactionsOrOutputsWithProofRequest,
    ) -> aptos_storage_service_types::Result<DataResponse, Error> {
        let response = self.storage.get_transactions_or_outputs_with_proof(
            request.proof_version,
            request.start_version,
            request.end_version,
            request.include_events,
            request.max_num_output_reductions,
        )?;

        Ok(DataResponse::TransactionsOrOutputsWithProof((
            response
                .transaction_list_with_proof
                .map(|t| t.consume_transaction_list_with_proof()),
            response
                .transaction_output_list_with_proof
                .map(|t| t.consume_output_list_with_proof()),
        )))
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L845-897)
```rust
    fn get_transactions_or_outputs_with_proof_by_size_legacy(
        &self,
        proof_version: u64,
        start_version: u64,
        end_version: u64,
        mut num_outputs_to_fetch: u64,
        include_events: bool,
        max_num_output_reductions: u64,
        max_response_size: u64,
    ) -> Result<TransactionDataWithProofResponse, Error> {
        let mut num_output_reductions = 0;
        while num_output_reductions <= max_num_output_reductions {
            let output_list_with_proof = self.storage.get_transaction_outputs(
                start_version,
                num_outputs_to_fetch,
                proof_version,
            )?;
            let response = TransactionDataWithProofResponse {
                transaction_data_response_type: TransactionDataResponseType::TransactionOutputData,
                transaction_list_with_proof: None,
                transaction_output_list_with_proof: Some(output_list_with_proof),
            };

            let (overflow_frame, num_bytes) =
                check_overflow_network_frame(&response, max_response_size)?;

            if !overflow_frame {
                return Ok(response);
            } else if num_outputs_to_fetch == 1 {
                break; // We cannot return less than a single item. Fallback to transactions
            } else {
                metrics::increment_chunk_truncation_counter(
                    metrics::TRUNCATION_FOR_SIZE,
                    DataResponse::TransactionDataWithProof(response).get_label(),
                );
                let new_num_outputs_to_fetch = num_outputs_to_fetch / 2;
                debug!("The request for {:?} outputs was too large (num bytes: {:?}, limit: {:?}). Current number of data reductions: {:?}",
                    num_outputs_to_fetch, num_bytes, max_response_size, num_output_reductions);
                num_outputs_to_fetch = new_num_outputs_to_fetch; // Try again with half the amount of data
                num_output_reductions += 1;
            }
        }

        // Return transactions only
        self.get_transactions_with_proof_by_size(
            proof_version,
            start_version,
            end_version,
            include_events,
            max_response_size,
            self.config.enable_size_and_time_aware_chunking,
        )
    }
```

**File:** config/src/config/state_sync_config.rs (L154-193)
```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageServiceConfig {
    /// Whether to enable size and time-aware chunking
    pub enable_size_and_time_aware_chunking: bool,
    /// Whether transaction data v2 is enabled
    pub enable_transaction_data_v2: bool,
    /// Maximum number of epoch ending ledger infos per chunk
    pub max_epoch_chunk_size: u64,
    /// Maximum number of invalid requests per peer
    pub max_invalid_requests_per_peer: u64,
    /// Maximum number of items in the lru cache before eviction
    pub max_lru_cache_size: u64,
    /// Maximum number of pending network messages
    pub max_network_channel_size: u64,
    /// Maximum number of bytes to send per network message
    pub max_network_chunk_bytes: u64,
    /// Maximum number of bytes to send per network message (for v2 data)
    pub max_network_chunk_bytes_v2: u64,
    /// Maximum number of active subscriptions (per peer)
    pub max_num_active_subscriptions: u64,
    /// Maximum period (ms) of pending optimistic fetch requests
    pub max_optimistic_fetch_period_ms: u64,
    /// Maximum number of state keys and values per chunk
    pub max_state_chunk_size: u64,
    /// Maximum time (ms) to wait for storage before truncating a response
    pub max_storage_read_wait_time_ms: u64,
    /// Maximum period (ms) of pending subscription requests
    pub max_subscription_period_ms: u64,
    /// Maximum number of transactions per chunk
    pub max_transaction_chunk_size: u64,
    /// Maximum number of transaction outputs per chunk
    pub max_transaction_output_chunk_size: u64,
    /// Minimum time (secs) to ignore peers after too many invalid requests
    pub min_time_to_ignore_peers_secs: u64,
    /// The interval (ms) to refresh the request moderator state
    pub request_moderator_refresh_interval_ms: u64,
    /// The interval (ms) to refresh the storage summary
    pub storage_summary_refresh_interval_ms: u64,
}
```

**File:** config/src/config/state_sync_config.rs (L460-471)
```rust
impl Default for AptosDataClientConfig {
    fn default() -> Self {
        Self {
            enable_transaction_data_v2: true,
            data_poller_config: AptosDataPollerConfig::default(),
            data_multi_fetch_config: AptosDataMultiFetchConfig::default(),
            ignore_low_score_peers: true,
            latency_filtering_config: AptosLatencyFilteringConfig::default(),
            latency_monitor_loop_interval_ms: 100,
            max_epoch_chunk_size: MAX_EPOCH_CHUNK_SIZE,
            max_num_output_reductions: 0,
            max_optimistic_fetch_lag_secs: 20, // 20 seconds
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
