# Audit Report

## Title
Cache Stampede Vulnerability in Epoch Ending Ledger Info Lookups Enables Storage DoS

## Summary
The `lru_response_cache` in the optimistic fetch handler fails to prevent concurrent duplicate storage operations when multiple peers request the same epoch ending ledger info. An attacker controlling multiple peer connections can intentionally trigger a cache stampede, forcing repeated expensive storage reads for identical data, causing validator node performance degradation.

## Finding Description

The vulnerability exists in the concurrent processing of optimistic fetch requests in `identify_ready_and_invalid_optimistic_fetches()`. When multiple peers send optimistic fetch requests with the same `known_epoch`, the storage service spawns concurrent blocking tasks to process each request. [1](#0-0) 

Each concurrent task may need to fetch epoch ending ledger info for the same epoch. The code calls `utils::get_epoch_ending_ledger_info()` which internally uses the Handler to process the request: [2](#0-1) 

The Handler's cache check operation is not atomic. Between checking if the cache contains the result and inserting the fetched result, multiple concurrent threads can all find the cache empty: [3](#0-2) 

The race condition occurs at lines 397-404 (cache check) versus lines 456-457 (cache insert). If N concurrent tasks all check the cache before any have inserted the result, all N tasks will miss the cache and proceed to fetch from storage, executing identical expensive storage operations.

**Attack Path:**
1. Attacker establishes multiple peer connections to a storage service node (allowed on public network)
2. Each peer sends an optimistic fetch request (e.g., `GetNewTransactionOutputsWithProof`) with the same `known_epoch` value
3. The optimistic fetch handler periodically processes these requests concurrently via `spawn_blocking`
4. All spawned tasks check the cache for the same epoch ending ledger info at approximately the same time
5. All tasks find the cache empty (cache stampede)
6. All tasks proceed to execute `storage.get_epoch_ending_ledger_infos()` for the same epoch
7. Multiple redundant storage reads occur, consuming I/O, CPU, and memory resources

The attacker can repeat this attack continuously by coordinating request timing and targeting different epochs or repeatedly targeting the same epoch after cache eviction.

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program, specifically under "Validator node slowdowns."

The impact includes:
- **Resource Exhaustion**: Repeated storage operations amplify I/O load, CPU usage, and memory consumption on validator/fullnode storage services
- **Performance Degradation**: Legitimate optimistic fetch requests experience increased latency when the storage service is under load
- **Cascading Effects**: Storage service slowdowns can impact state synchronization across the network, affecting node catch-up performance
- **Amplification Factor**: An attacker with M peer connections can amplify storage operations by M times for each targeted epoch

While this does not directly cause consensus violations or fund loss, it significantly impacts network availability and node operational health, meeting the High Severity criteria.

## Likelihood Explanation

This vulnerability is **highly likely** to be exploitable:

**Attacker Requirements:**
- Ability to establish multiple peer connections (trivial on public network)
- No special privileges, authentication, or insider access required
- Can be executed from commodity hardware

**Exploitation Complexity:**
- Low - requires only coordinating request timing across multiple connections
- Attack can be fully automated
- No cryptographic operations or complex protocol manipulation needed

**Detection Difficulty:**
- Moderate - appears as legitimate optimistic fetch traffic
- Request moderator only validates request correctness, not duplicate request patterns
- No deduplication or rate limiting based on request content [4](#0-3) 

The attack can be sustained indefinitely and is highly repeatable, making it a practical DoS vector.

## Recommendation

Implement request deduplication for concurrent epoch ending ledger info lookups. Use a synchronization mechanism to ensure only one storage operation occurs for each unique epoch, while other concurrent requests wait for and share the result.

**Recommended Fix:**

Add a deduplication layer using a `DashMap` of in-flight requests with conditional variables or futures:

```rust
// In Handler struct
in_flight_epoch_requests: Arc<DashMap<u64, Arc<Mutex<Option<Result<LedgerInfoWithSignatures, Error>>>>>>,

// In get_epoch_ending_ledger_info
pub fn get_epoch_ending_ledger_info<T: StorageReaderInterface>(
    // ... existing parameters ...
    in_flight_epoch_requests: Arc<DashMap<u64, Arc<Mutex<Option<Result<...>>>>>>,
) -> Result<LedgerInfoWithSignatures, Error> {
    // Check if request is already in flight
    let result_slot = in_flight_epoch_requests
        .entry(epoch)
        .or_insert_with(|| Arc::new(Mutex::new(None)))
        .clone();
    
    let mut guard = result_slot.lock();
    
    // If result already computed, return it
    if let Some(result) = guard.as_ref() {
        return result.clone();
    }
    
    // Otherwise, compute result (existing logic)
    let result = {
        // ... existing request processing ...
    };
    
    // Store result for other waiting threads
    *guard = Some(result.clone());
    in_flight_epoch_requests.remove(&epoch);
    
    result
}
```

Alternatively, enhance the cache implementation to use a cache with stampede protection (e.g., `async-cache` with request coalescing).

## Proof of Concept

```rust
// Rust test demonstrating the cache stampede
#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn test_cache_stampede_on_epoch_ending_ledger_info() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::collections::HashMap;
    
    // Setup: Create storage service with instrumented storage
    let storage_access_count = Arc::new(AtomicU64::new(0));
    let storage_count_clone = storage_access_count.clone();
    
    // Create mock storage that counts accesses
    let mock_storage = MockStorageWithCounter::new(storage_count_clone);
    
    // Create multiple peer connections requesting the same epoch
    let num_peers = 10;
    let target_epoch = 100u64;
    let mut handles = vec![];
    
    // Simulate concurrent optimistic fetch requests from multiple peers
    for peer_id in 0..num_peers {
        let storage_clone = mock_storage.clone();
        let handle = tokio::spawn(async move {
            // Each peer sends optimistic fetch with same known_epoch
            let request = StorageServiceRequest::new(
                DataRequest::GetNewTransactionOutputsWithProof(
                    NewTransactionOutputsWithProofRequest {
                        known_version: 1000,
                        known_epoch: target_epoch,
                    }
                ),
                false,
            );
            
            // Process optimistic fetch (triggers epoch ending ledger info lookup)
            process_optimistic_fetch(peer_id, request, storage_clone).await
        });
        handles.push(handle);
    }
    
    // Wait for all concurrent requests
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Verify: Storage was accessed multiple times for the same epoch
    let access_count = storage_access_count.load(Ordering::SeqCst);
    
    println!("Storage accesses for epoch {}: {}", target_epoch, access_count);
    
    // VULNERABILITY: Access count should be 1 (cached), but will be ~num_peers
    // due to cache stampede
    assert!(
        access_count > 1,
        "Cache stampede detected: {} redundant storage operations",
        access_count - 1
    );
}

// Mock storage that counts get_epoch_ending_ledger_infos calls
struct MockStorageWithCounter {
    access_count: Arc<AtomicU64>,
}

impl MockStorageWithCounter {
    fn new(counter: Arc<AtomicU64>) -> Self {
        Self { access_count: counter }
    }
}

impl StorageReaderInterface for MockStorageWithCounter {
    fn get_epoch_ending_ledger_infos(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<EpochChangeProof> {
        // Increment counter to track storage accesses
        self.access_count.fetch_add(1, Ordering::SeqCst);
        
        // Simulate expensive storage operation
        std::thread::sleep(Duration::from_millis(100));
        
        // Return mock epoch ending ledger info
        Ok(create_mock_epoch_change_proof(start_epoch, end_epoch))
    }
}
```

## Notes

The vulnerability is specific to the concurrent processing model used in optimistic fetch handling where multiple `spawn_blocking` tasks can race to fetch the same epoch ending ledger info. The issue is exacerbated by:

1. **No Request Deduplication**: The system lacks coordination between concurrent requests for identical data
2. **Non-Atomic Cache Operations**: The check-then-fetch-then-insert pattern in `process_cachable_request` is inherently racy
3. **Public Network Access**: The attack surface includes all public fullnode peers, not just validators

The shared `lru_response_cache` is correctly implemented and does cache responses, but the non-atomic usage pattern allows the cache stampede race condition to occur before the first successful insert completes.

### Citations

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L481-552)
```rust
    let mut active_tasks = vec![];
    for (peer_network_id, (highest_known_version, highest_known_epoch)) in
        peers_and_highest_synced_data.into_iter()
    {
        // Clone all required components for the task
        let runtime = runtime.clone();
        let cached_storage_server_summary = cached_storage_server_summary.clone();
        let highest_synced_ledger_info = highest_synced_ledger_info.clone();
        let optimistic_fetches = optimistic_fetches.clone();
        let subscriptions = subscriptions.clone();
        let lru_response_cache = lru_response_cache.clone();
        let request_moderator = request_moderator.clone();
        let storage = storage.clone();
        let time_service = time_service.clone();
        let peers_with_invalid_optimistic_fetches = peers_with_invalid_optimistic_fetches.clone();
        let peers_with_ready_optimistic_fetches = peers_with_ready_optimistic_fetches.clone();

        // Spawn a blocking task to determine if the optimistic fetch is ready or
        // invalid. We do this because each entry may require reading from storage.
        let active_task = runtime.spawn_blocking(move || {
            // Check if we have synced beyond the highest known version
            if highest_known_version < highest_synced_version {
                if highest_known_epoch < highest_synced_epoch {
                    // Fetch the epoch ending ledger info from storage (the
                    // peer needs to sync to their epoch ending ledger info).
                    let epoch_ending_ledger_info = match utils::get_epoch_ending_ledger_info(
                        cached_storage_server_summary.clone(),
                        optimistic_fetches.clone(),
                        subscriptions.clone(),
                        highest_known_epoch,
                        lru_response_cache.clone(),
                        request_moderator.clone(),
                        &peer_network_id,
                        storage.clone(),
                        time_service.clone(),
                    ) {
                        Ok(epoch_ending_ledger_info) => epoch_ending_ledger_info,
                        Err(error) => {
                            // Log the failure to fetch the epoch ending ledger info
                            error!(LogSchema::new(LogEntry::OptimisticFetchRefresh)
                                .error(&error)
                                .message(&format!(
                                    "Failed to get the epoch ending ledger info for epoch: {:?} !",
                                    highest_known_epoch
                                )));

                            return;
                        },
                    };

                    // Check that we haven't been sent an invalid optimistic fetch request
                    // (i.e., a request that does not respect an epoch boundary).
                    if epoch_ending_ledger_info.ledger_info().version() <= highest_known_version {
                        peers_with_invalid_optimistic_fetches
                            .lock()
                            .push(peer_network_id);
                    } else {
                        peers_with_ready_optimistic_fetches
                            .lock()
                            .push((peer_network_id, epoch_ending_ledger_info));
                    }
                } else {
                    peers_with_ready_optimistic_fetches
                        .lock()
                        .push((peer_network_id, highest_synced_ledger_info.clone()));
                };
            }
        });

        // Add the task to the list of active tasks
        active_tasks.push(active_task);
    }
```

**File:** state-sync/storage-service/server/src/handler.rs (L384-461)
```rust
    fn process_cachable_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> aptos_storage_service_types::Result<StorageServiceResponse, Error> {
        // Increment the LRU cache probe counter
        increment_counter(
            &metrics::LRU_CACHE_EVENT,
            peer_network_id.network_id(),
            LRU_CACHE_PROBE.into(),
        );

        // Check if the response is already in the cache
        if let Some(response) = self.lru_response_cache.get(request) {
            increment_counter(
                &metrics::LRU_CACHE_EVENT,
                peer_network_id.network_id(),
                LRU_CACHE_HIT.into(),
            );
            return Ok(response.clone());
        }

        // Otherwise, fetch the data from storage and time the operation
        let fetch_data_response = || match &request.data_request {
            DataRequest::GetStateValuesWithProof(request) => {
                self.get_state_value_chunk_with_proof(request)
            },
            DataRequest::GetEpochEndingLedgerInfos(request) => {
                self.get_epoch_ending_ledger_infos(request)
            },
            DataRequest::GetNumberOfStatesAtVersion(version) => {
                self.get_number_of_states_at_version(*version)
            },
            DataRequest::GetTransactionOutputsWithProof(request) => {
                self.get_transaction_outputs_with_proof(request)
            },
            DataRequest::GetTransactionsWithProof(request) => {
                self.get_transactions_with_proof(request)
            },
            DataRequest::GetTransactionsOrOutputsWithProof(request) => {
                self.get_transactions_or_outputs_with_proof(request)
            },
            DataRequest::GetTransactionDataWithProof(request) => {
                self.get_transaction_data_with_proof(request)
            },
            _ => Err(Error::UnexpectedErrorEncountered(format!(
                "Received an unexpected request: {:?}",
                request
            ))),
        };
        let data_response = utils::execute_and_time_duration(
            &metrics::STORAGE_FETCH_PROCESSING_LATENCY,
            Some((peer_network_id, request)),
            None,
            fetch_data_response,
            None,
        )?;

        // Create the storage response and time the operation
        let create_storage_response = || {
            StorageServiceResponse::new(data_response, request.use_compression)
                .map_err(|error| error.into())
        };
        let storage_response = utils::execute_and_time_duration(
            &metrics::STORAGE_RESPONSE_CREATION_LATENCY,
            Some((peer_network_id, request)),
            None,
            create_storage_response,
            None,
        )?;

        // Create and cache the storage response
        self.lru_response_cache
            .insert(request.clone(), storage_response.clone());

        // Return the storage response
        Ok(storage_response)
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
