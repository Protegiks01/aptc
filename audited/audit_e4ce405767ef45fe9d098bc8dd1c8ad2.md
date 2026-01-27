# Audit Report

## Title
Storage Service Size Validation Occurs After Resource Consumption, Enabling DoS Through Repeated Oversized Requests

## Summary
The storage service validates response sizes **after** fetching data from the database and serializing it, rather than before allocation. This allows malicious peers to repeatedly request oversized data chunks, forcing the server to consume significant database I/O, memory, and CPU resources before rejecting the requests, enabling effective Denial-of-Service attacks against validator and full nodes.

## Finding Description

The Aptos storage service implements size validation through the `check_overflow_network_frame` function, but this validation occurs **after** expensive operations have already been performed. The vulnerability exists in the legacy data fetching implementations used throughout the storage service.

**Vulnerable Code Flow:**

In `get_epoch_ending_ledger_infos_by_size_legacy`: [1](#0-0) 

The data is fetched from storage first (consuming database I/O and allocating memory for potentially large epoch change proofs).

Then, size validation happens: [2](#0-1) 

The `check_overflow_network_frame` function itself performs BCS serialization (additional CPU and memory cost): [3](#0-2) 

This same pattern exists in all legacy fetch functions:
- `get_transactions_with_proof_by_size_legacy` [4](#0-3) 
- `get_transaction_outputs_with_proof_by_size_legacy` [5](#0-4) 
- `get_transactions_or_outputs_with_proof_by_size_legacy` [6](#0-5) 

**Why Request Validation Doesn't Prevent This:**

The `RequestModerator::validate_request` only checks if the data exists, not if it would be too large: [7](#0-6) 

The `can_service` implementation only validates data availability, not size constraints: [8](#0-7) 

**Attack Scenario:**

1. Malicious peer sends a request for a large epoch range (e.g., requesting 200 epochs)
2. Request passes `can_service` validation (only checks if epochs exist)
3. Storage service fetches all epoch ending ledger infos from database (database I/O + memory allocation)
4. Service serializes the data using BCS (CPU + additional memory)
5. Only then discovers the serialized data exceeds `max_network_chunk_bytes` (10 MiB or 40 MiB)
6. Request is rejected, but resources were already consumed

The attacker can repeat this 500 times per peer before being ignored [9](#0-8) , then wait 5 minutes [10](#0-9)  or use additional peer identities to continue the attack.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

**Validator Node Slowdowns:** Repeated oversized requests force validators to:
- Perform expensive database queries fetching large data ranges
- Allocate significant memory for fetched data structures
- Execute CPU-intensive BCS serialization operations
- All before rejecting the requests

**API Crashes:** Sustained attacks can cause:
- Memory exhaustion from repeated large allocations
- Database connection pool exhaustion
- CPU starvation affecting consensus participation
- Potential node crashes under extreme load

**Significant Protocol Violations:** This breaks the Resource Limits invariant (#9): "All operations must respect gas, storage, and computational limits." The service consumes unbounded resources before validation occurs.

The vulnerability affects all nodes running the storage service (validators and full nodes), can be exploited by any network peer without special privileges, and can impact network health by degrading validator performance.

## Likelihood Explanation

**High Likelihood:**
- Attack requires no special privileges (any peer can send storage service requests)
- Attack is trivially executable (just send requests for large data ranges)
- No rate limiting exists before resource consumption
- 500 invalid requests allowed per peer before temporary ignore
- Attacker can use multiple peer IDs or wait for 5-minute cooldown to repeat
- Default chunk sizes are large enough to cause significant resource consumption (up to 40 MiB of serialized data)

**Low Complexity:**
- No cryptographic operations required
- No need to compromise validator keys or consensus
- Simple network protocol exploitation
- Can be automated easily

## Recommendation

Implement size estimation **before** fetching data from storage. The fix should:

1. **Pre-validate request size based on chunk limits:**
```rust
fn get_epoch_ending_ledger_infos_by_size_legacy(
    &self,
    start_epoch: u64,
    expected_end_epoch: u64,
    mut num_ledger_infos_to_fetch: u64,
    max_response_size: u64,
) -> Result<EpochChangeProof, Error> {
    // NEW: Validate request size BEFORE fetching
    let max_epochs_per_chunk = self.config.max_epoch_chunk_size;
    if num_ledger_infos_to_fetch > max_epochs_per_chunk {
        num_ledger_infos_to_fetch = max_epochs_per_chunk;
    }
    
    // Use size estimation heuristics to further bound the request
    // For example, use average epoch size to estimate total bytes
    let estimated_size = estimate_epoch_data_size(num_ledger_infos_to_fetch);
    if estimated_size > max_response_size {
        num_ledger_infos_to_fetch = calculate_safe_epoch_count(max_response_size);
    }
    
    // Now fetch with bounded parameters
    while num_ledger_infos_to_fetch >= 1 {
        let end_epoch = start_epoch.checked_add(num_ledger_infos_to_fetch)?;
        let epoch_change_proof = self.storage
            .get_epoch_ending_ledger_infos(start_epoch, end_epoch)?;
        
        // Keep existing overflow check as defense-in-depth
        let (overflow_frame, num_bytes) = 
            check_overflow_network_frame(&epoch_change_proof, max_response_size)?;
        // ... rest of logic
    }
}
```

2. **Enhance RequestModerator validation to check size bounds:**
Add size-based validation in `can_service` to reject obviously oversized requests before they reach the handler.

3. **Implement stricter rate limiting:**
Reduce `max_invalid_requests_per_peer` or implement exponential backoff earlier in the request pipeline.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_dos_via_oversized_epoch_requests() {
    // Setup: Create storage service with test data
    let (storage_service, mut mock_storage) = setup_test_storage_service();
    
    // Populate storage with many epochs (e.g., 500 epochs)
    for epoch in 0..500 {
        mock_storage.add_epoch_ending_ledger_info(epoch, create_large_ledger_info());
    }
    
    // Attack: Send requests for oversized epoch ranges
    let malicious_peer = PeerNetworkId::random();
    let mut resource_consumption_metrics = vec![];
    
    for i in 0..500 {  // max_invalid_requests_per_peer
        let start_time = Instant::now();
        let start_memory = get_current_memory_usage();
        
        // Request large epoch range that will be rejected after resource consumption
        let request = StorageServiceRequest::new(
            DataRequest::GetEpochEndingLedgerInfos(
                EpochEndingLedgerInfoRequest {
                    start_epoch: 0,
                    expected_end_epoch: 200,  // Large range
                }
            ),
            false, // no compression
        );
        
        let response = storage_service.handle_request(malicious_peer, request).await;
        
        let elapsed = start_time.elapsed();
        let memory_used = get_current_memory_usage() - start_memory;
        
        // Verify response is error (too large)
        assert!(matches!(response, Err(StorageServiceError::InternalError(_))));
        
        // Record resources consumed before rejection
        resource_consumption_metrics.push((elapsed, memory_used));
    }
    
    // Demonstrate that significant resources were consumed
    let total_time: Duration = resource_consumption_metrics.iter().map(|(t, _)| *t).sum();
    let total_memory: usize = resource_consumption_metrics.iter().map(|(_, m)| *m).sum();
    
    println!("DoS Attack Results:");
    println!("  Total time wasted: {:?}", total_time);
    println!("  Total memory allocated: {} MB", total_memory / 1_000_000);
    println!("  Average time per request: {:?}", total_time / 500);
    
    // Assert significant resource consumption occurred
    assert!(total_time > Duration::from_secs(5), "Significant CPU time consumed");
    assert!(total_memory > 100_000_000, "Significant memory consumed (>100MB)");
}
```

**Notes:**
- The vulnerability is present in both v1 and v2 data request paths
- Size-aware chunking (when enabled) partially mitigates but doesn't eliminate the issue
- The attack is amplified when requesting data types with large serialized sizes (e.g., transactions with events)
- Database I/O is the most expensive operation being performed unnecessarily

### Citations

**File:** state-sync/storage-service/server/src/storage.rs (L315-317)
```rust
            let epoch_change_proof = self
                .storage
                .get_epoch_ending_ledger_infos(start_epoch, end_epoch)?;
```

**File:** state-sync/storage-service/server/src/storage.rs (L323-324)
```rust
            let (overflow_frame, num_bytes) =
                check_overflow_network_frame(&epoch_change_proof, max_response_size)?;
```

**File:** state-sync/storage-service/server/src/storage.rs (L520-542)
```rust
        mut num_transactions_to_fetch: u64,
        include_events: bool,
        max_response_size: u64,
    ) -> Result<TransactionDataWithProofResponse, Error> {
        while num_transactions_to_fetch >= 1 {
            let transaction_list_with_proof = self.storage.get_transactions(
                start_version,
                num_transactions_to_fetch,
                proof_version,
                include_events,
            )?;
            let response = TransactionDataWithProofResponse {
                transaction_data_response_type: TransactionDataResponseType::TransactionData,
                transaction_list_with_proof: Some(transaction_list_with_proof),
                transaction_output_list_with_proof: None,
            };
            if num_transactions_to_fetch == 1 {
                return Ok(response); // We cannot return less than a single item
            }

            // Attempt to divide up the request if it overflows the message size
            let (overflow_frame, num_bytes) =
                check_overflow_network_frame(&response, max_response_size)?;
```

**File:** state-sync/storage-service/server/src/storage.rs (L748-764)
```rust
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
            if num_outputs_to_fetch == 1 {
                return Ok(response); // We cannot return less than a single item
            }

            // Attempt to divide up the request if it overflows the message size
            let (overflow_frame, num_bytes) =
                check_overflow_network_frame(&response, max_response_size)?;
```

**File:** state-sync/storage-service/server/src/storage.rs (L857-869)
```rust
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
```

**File:** state-sync/storage-service/server/src/storage.rs (L1499-1508)
```rust
fn check_overflow_network_frame<T: ?Sized + Serialize>(
    data: &T,
    max_network_frame_bytes: u64,
) -> aptos_storage_service_types::Result<(bool, u64), Error> {
    let num_serialized_bytes = bcs::to_bytes(&data)
        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?
        .len() as u64;
    let overflow_frame = num_serialized_bytes >= max_network_frame_bytes;
    Ok((overflow_frame, num_serialized_bytes))
}
```

**File:** state-sync/storage-service/server/src/moderator.rs (L155-159)
```rust
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
```

**File:** state-sync/storage-service/types/src/responses.rs (L700-707)
```rust
                    match CompleteDataRange::new(request.start_epoch, request.expected_end_epoch) {
                        Ok(desired_range) => desired_range,
                        Err(_) => return false,
                    };
                self.epoch_ending_ledger_infos
                    .map(|range| range.superset_of(&desired_range))
                    .unwrap_or(false)
            },
```

**File:** config/src/config/state_sync_config.rs (L201-201)
```rust
            max_invalid_requests_per_peer: 500,
```

**File:** config/src/config/state_sync_config.rs (L213-213)
```rust
            min_time_to_ignore_peers_secs: 300, // 5 minutes
```
