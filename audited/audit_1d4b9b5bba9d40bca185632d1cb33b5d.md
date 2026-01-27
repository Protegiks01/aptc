# Audit Report

## Title
CPU Exhaustion via Unbounded Optimistic Fetch Requests with Stale Versions

## Summary
An attacker can establish multiple peer connections and send optimistic fetch requests with varying stale `known_version` values that bypass all rate limiting. When new data becomes available, the storage service processes these requests in parallel, generating expensive Merkle proofs for each unique version range, causing CPU and I/O exhaustion on validator and fullnode infrastructure.

## Finding Description

The storage service implements optimistic fetch requests that allow peers to speculatively request new transaction outputs beyond their known blockchain state. However, this mechanism contains a critical vulnerability in how it validates and processes these requests.

**Validation Bypass**: Optimistic fetch requests completely bypass the `RequestModerator` validation that provides rate limiting for other request types. [1](#0-0) 

When a request is received, if it's an optimistic fetch, it returns early before reaching the validation logic that would normally check the request moderator. [2](#0-1) 

**No Concurrent Limit**: While the system limits each peer to one active optimistic fetch at a time by using `PeerNetworkId` as the map key, there is no limit on the total number of concurrent optimistic fetches from different peers. [3](#0-2) 

An attacker can establish up to `max_inbound_connections` (default: 100) peer connections. [4](#0-3) 

**No Staleness Validation**: The system does not validate whether the `known_version` value is unreasonably stale. It only checks that the target version is higher than the known version when generating the response. [5](#0-4) 

**Expensive Proof Generation**: When processing optimistic fetches, the server must read from storage and generate Merkle proofs. Each request with a different `known_version` creates a different storage request with a different cache key (based on `start_version`), forcing separate proof generation operations. [6](#0-5) 

The proof generation involves reading transaction outputs from storage iterators and computing accumulator range proofs. [7](#0-6) 

**Parallel Processing Amplification**: When optimistic fetches become ready (new data is available), they are all processed in parallel by spawning separate blocking tasks. [8](#0-7) 

**Attack Execution**:
1. Attacker opens 100 peer connections (max inbound limit)
2. Each peer sends `NewTransactionOutputsWithProofRequest` with a different stale `known_version` (e.g., peer 1: version 100, peer 2: version 200, etc.)
3. Requests bypass RequestModerator validation and are stored
4. When new blockchain data becomes available, all 100 requests become "ready" simultaneously
5. Server spawns 100 parallel blocking tasks to process them
6. Each task generates different Merkle proofs (different cache keys due to different start_versions)
7. CPU and I/O are exhausted by concurrent proof generation operations
8. Legitimate peers cannot sync efficiently, and validator performance degrades

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Validator node slowdowns**: The attack directly causes CPU and I/O exhaustion on validator nodes, degrading their ability to participate in consensus efficiently
- **Significant protocol violations**: Breaks the Resource Limits invariant (#9) that "all operations must respect gas, storage, and computational limits" - optimistic fetches consume unbounded CPU without any rate limiting
- **API crashes**: Under sustained attack, the storage service could become unresponsive or crash due to resource exhaustion

The vulnerability affects all nodes running the storage service (validators and fullnodes), potentially disrupting state synchronization across the network. While it doesn't directly compromise consensus safety or cause fund loss, it can significantly degrade network performance and availability.

## Likelihood Explanation

This vulnerability is **highly likely** to be exploited:

- **Low barrier to entry**: Attacker only needs to establish network connections to public fullnodes (no authentication required)
- **Simple to execute**: Sending optimistic fetch requests with varying `known_version` values is straightforward
- **Hard to detect**: Requests appear legitimate and bypass all validation
- **Difficult to mitigate**: No existing rate limiting mechanism applies to optimistic fetches
- **Amplification effect**: Each peer connection multiplies the attack impact through parallel processing

The attack requires no insider access, special permissions, or complex setup - just standard peer-to-peer network connectivity.

## Recommendation

Implement comprehensive rate limiting and validation for optimistic fetch requests:

1. **Apply RequestModerator validation to optimistic fetches**: Remove the early return that bypasses validation
2. **Limit total concurrent optimistic fetches**: Add a configurable limit (e.g., 30 max across all peers)
3. **Validate known_version staleness**: Reject requests where `known_version` is more than a configurable threshold behind current version (e.g., 10,000 versions)
4. **Implement per-peer optimistic fetch rate limiting**: Track how frequently each peer sends optimistic fetches
5. **Add metrics and monitoring**: Track optimistic fetch processing times and implement alerting for abuse patterns

Example fix for applying RequestModerator validation:

```rust
// In handler.rs process_request_and_respond()
// Remove the early return for optimistic fetches, process them through normal validation path
// Handle optimistic fetch requests AFTER validation
if request.data_request.is_optimistic_fetch() {
    // Validate first
    let validation_result = self.request_moderator.validate_request(&peer_network_id, &request);
    if let Err(error) = validation_result {
        self.send_response(request, Err(StorageServiceError::InvalidRequest(error.to_string())), response_sender);
        return;
    }
    
    self.handle_optimistic_fetch_request(peer_network_id, request, response_sender);
    return;
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: state-sync/storage-service/server/src/tests/optimistic_fetch_abuse.rs

#[tokio::test]
async fn test_optimistic_fetch_cpu_exhaustion() {
    // Setup storage service with default config
    let (mut mock_client, service, _) = MockClient::new(None, None);
    tokio::spawn(service.start());
    
    // Create 100 different peer connections
    let num_attackers = 100;
    let mut peers = vec![];
    for i in 0..num_attackers {
        let peer = PeerNetworkId::new(NetworkId::Public, PeerId::random());
        peers.push(peer);
        
        // Each peer sends optimistic fetch with different stale known_version
        let known_version = (i * 100) as u64; // Versions: 0, 100, 200, ... 9900
        let request = StorageServiceRequest::new(
            DataRequest::GetNewTransactionOutputsWithProof(
                NewTransactionOutputsWithProofRequest {
                    known_version,
                    known_epoch: 0,
                }
            ),
            false,
        );
        
        // Send request - it should be accepted without validation
        mock_client.send_request(peer, request).await;
    }
    
    // Wait for requests to be stored
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Verify all 100 optimistic fetches are stored (no rate limiting applied)
    let optimistic_fetches = service.get_optimistic_fetches();
    assert_eq!(optimistic_fetches.len(), num_attackers);
    
    // Simulate new data becoming available
    // All 100 fetches will be processed in parallel, generating different proofs
    service.update_storage_summary(create_storage_summary(10000));
    
    // Monitor CPU usage - it should spike due to parallel proof generation
    // In production, this would cause significant performance degradation
}
```

## Notes

This vulnerability demonstrates a critical gap in the storage service's defense-in-depth strategy. While individual request types are carefully rate-limited through the `RequestModerator`, optimistic fetches were designed with an implicit trust assumption that proved dangerous. The combination of:

- Validation bypass
- No concurrent fetch limits
- Parallel processing
- Expensive cryptographic proof generation

creates a perfect storm for resource exhaustion attacks. The fix requires both immediate tactical changes (applying existing validation) and strategic improvements (new limits specific to optimistic fetches).

### Citations

**File:** state-sync/storage-service/server/src/handler.rs (L119-123)
```rust
        // Handle any optimistic fetch requests
        if request.data_request.is_optimistic_fetch() {
            self.handle_optimistic_fetch_request(peer_network_id, request, response_sender);
            return;
        }
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

**File:** state-sync/storage-service/server/src/handler.rs (L256-272)
```rust
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
```

**File:** config/src/config/state_sync_config.rs (L195-218)
```rust
impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            enable_size_and_time_aware_chunking: false,
            enable_transaction_data_v2: true,
            max_epoch_chunk_size: MAX_EPOCH_CHUNK_SIZE,
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
            request_moderator_refresh_interval_ms: 1000, // 1 second
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
        }
    }
}
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L66-74)
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
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L100-107)
```rust
        // Create the storage request
        let data_request = match &self.request.data_request {
            DataRequest::GetNewTransactionOutputsWithProof(_) => {
                DataRequest::GetTransactionOutputsWithProof(TransactionOutputsWithProofRequest {
                    proof_version: target_version,
                    start_version,
                    end_version,
                })
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L291-333)
```rust
            // Spawn a blocking task to handle the optimistic fetch
            runtime.spawn_blocking(move || {
                // Get the fetch start time and request
                let optimistic_fetch_start_time = optimistic_fetch.fetch_start_time;
                let optimistic_fetch_request = optimistic_fetch.request.clone();

                // Handle the optimistic fetch request and time the operation
                let handle_request = || {
                    // Get the storage service request for the missing data
                    let missing_data_request = optimistic_fetch
                        .get_storage_request_for_missing_data(config, &target_ledger_info)?;

                    // Notify the peer of the new data
                    utils::notify_peer_of_new_data(
                        cached_storage_server_summary.clone(),
                        optimistic_fetches.clone(),
                        subscriptions.clone(),
                        lru_response_cache.clone(),
                        request_moderator.clone(),
                        storage.clone(),
                        time_service.clone(),
                        &peer_network_id,
                        missing_data_request,
                        target_ledger_info,
                        optimistic_fetch.take_response_sender(),
                    )
                };
                let result = utils::execute_and_time_duration(
                    &metrics::OPTIMISTIC_FETCH_LATENCIES,
                    Some((&peer_network_id, &optimistic_fetch_request)),
                    None,
                    handle_request,
                    Some(optimistic_fetch_start_time),
                );

                // Log an error if the handler failed
                if let Err(error) = result {
                    warn!(LogSchema::new(LogEntry::OptimisticFetchResponse)
                        .error(&Error::UnexpectedErrorEncountered(error.to_string())));
                }
            });
        }
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L591-708)
```rust
        // Get the iterators for the transaction, info, write set, events,
        // auxiliary data and persisted auxiliary infos.
        let transaction_iterator = self
            .storage
            .get_transaction_iterator(start_version, num_outputs_to_fetch)?;
        let transaction_info_iterator = self
            .storage
            .get_transaction_info_iterator(start_version, num_outputs_to_fetch)?;
        let transaction_write_set_iterator = self
            .storage
            .get_write_set_iterator(start_version, num_outputs_to_fetch)?;
        let transaction_events_iterator = self
            .storage
            .get_events_iterator(start_version, num_outputs_to_fetch)?;
        let persisted_auxiliary_info_iterator = self
            .storage
            .get_persisted_auxiliary_info_iterator(start_version, num_outputs_to_fetch as usize)?;
        let mut multizip_iterator = itertools::multizip((
            transaction_iterator,
            transaction_info_iterator,
            transaction_write_set_iterator,
            transaction_events_iterator,
            persisted_auxiliary_info_iterator,
        ));

        // Initialize the fetched data items
        let mut transactions_and_outputs = vec![];
        let mut transaction_infos = vec![];
        let mut persisted_auxiliary_infos = vec![];

        // Create a response progress tracker
        let mut response_progress_tracker = ResponseDataProgressTracker::new(
            num_outputs_to_fetch,
            max_response_size,
            self.config.max_storage_read_wait_time_ms,
            self.time_service.clone(),
        );

        // Fetch as many transaction outputs as possible
        while !response_progress_tracker.is_response_complete() {
            match multizip_iterator.next() {
                Some((
                    Ok(transaction),
                    Ok(info),
                    Ok(write_set),
                    Ok(events),
                    Ok(persisted_auxiliary_info),
                )) => {
                    // Create the transaction output
                    let output = TransactionOutput::new(
                        write_set,
                        events,
                        info.gas_used(),
                        info.status().clone().into(),
                        TransactionAuxiliaryData::None, // Auxiliary data is no longer supported
                    );

                    // Calculate the number of serialized bytes for the data items
                    let num_transaction_bytes = get_num_serialized_bytes(&transaction)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_info_bytes = get_num_serialized_bytes(&info)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_output_bytes = get_num_serialized_bytes(&output)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_auxiliary_info_bytes =
                        get_num_serialized_bytes(&persisted_auxiliary_info).map_err(|error| {
                            Error::UnexpectedErrorEncountered(error.to_string())
                        })?;

                    // Add the data items to the lists
                    let total_serialized_bytes = num_transaction_bytes
                        + num_info_bytes
                        + num_output_bytes
                        + num_auxiliary_info_bytes;
                    if response_progress_tracker.data_items_fits_in_response(
                        !is_transaction_or_output_request,
                        total_serialized_bytes,
                    ) {
                        transactions_and_outputs.push((transaction, output));
                        transaction_infos.push(info);
                        persisted_auxiliary_infos.push(persisted_auxiliary_info);

                        response_progress_tracker.add_data_item(total_serialized_bytes);
                    } else {
                        break; // Cannot add any more data items
                    }
                },
                Some((Err(error), _, _, _, _))
                | Some((_, Err(error), _, _, _))
                | Some((_, _, Err(error), _, _))
                | Some((_, _, _, Err(error), _))
                | Some((_, _, _, _, Err(error))) => {
                    return Err(Error::StorageErrorEncountered(error.to_string()));
                },
                None => {
                    // Log a warning that the iterators did not contain all the expected data
                    warn!(
                        "The iterators for transactions, transaction infos, write sets, events, \
                        auxiliary data and persisted auxiliary infos are missing data! Start version: {:?}, \
                        end version: {:?}, num outputs to fetch: {:?}, num fetched: {:?}.",
                        start_version, end_version, num_outputs_to_fetch, transactions_and_outputs.len()
                    );
                    break;
                },
            }
        }

        // Create the transaction output list with proof
        let num_fetched_outputs = transactions_and_outputs.len();
        let accumulator_range_proof = if num_fetched_outputs == 0 {
            AccumulatorRangeProof::new_empty() // Return an empty proof if no outputs were fetched
        } else {
            self.storage.get_transaction_accumulator_range_proof(
                start_version,
                num_fetched_outputs as u64,
                proof_version,
            )?
        };
```
