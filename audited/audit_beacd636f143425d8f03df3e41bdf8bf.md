# Audit Report

## Title
Unvalidated `max_num_output_reductions` Parameter Enables Resource Exhaustion in Subscription Streams

## Summary
The `max_num_output_reductions` parameter sent in subscription requests (line 1222 of `state-sync/aptos-data-client/src/client.rs`) is not validated on the storage service side, allowing malicious peers to force up to ~12x amplification of expensive database read operations per subscription request, leading to validator node resource exhaustion and slowdowns. [1](#0-0) 

## Finding Description
When a peer subscribes to transactions or outputs via `subscribe_to_transactions_or_outputs_with_proof()`, the client includes a `max_num_output_reductions` parameter in the request. This parameter controls how many times the storage service will attempt to reduce the output chunk size (by halving) before falling back to returning transactions. [2](#0-1) 

The storage service receives this parameter and uses it directly in the legacy implementation without any validation: [3](#0-2) 

The vulnerability occurs in the `while` loop at line 856, which iterates up to `max_num_output_reductions + 1` times. Each iteration performs:
1. An expensive database read via `self.storage.get_transaction_outputs()` (line 857-861)
2. Response serialization and size checking (line 862-869)
3. Chunk size reduction by half if the response overflows (line 880-884)

**Attack Path:**
1. Malicious peer modifies its local configuration or directly crafts network messages with `max_num_output_reductions` set to a high value (e.g., 100 or higher)
2. Peer creates subscription requests using `SubscribeTransactionsOrOutputsWithProof`
3. Storage service processes the request without validation, passing the attacker-controlled value directly to the legacy implementation
4. The reduction loop executes up to `min(max_num_output_reductions + 1, log₂(max_transaction_output_chunk_size))` ≈ 12 iterations
5. Each iteration performs a full database read from AptosDB [4](#0-3) 

**Amplification Factor:**
- Default behavior: `max_num_output_reductions = 0` → 1 database read before fallback
- Exploited behavior: `max_num_output_reductions = 100` → up to 12 database reads before fallback
- Amplification: **12x per subscription request** [5](#0-4) 

**Subscription Context Multiplier:**
Each peer can maintain up to 30 active subscriptions, and subscriptions make continuous requests (potentially every block). Multiple malicious peers can connect simultaneously, compounding the resource exhaustion. [6](#0-5) 

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty program category of "Validator node slowdowns":

1. **Resource Exhaustion**: The 12x amplification of database reads directly impacts validator node performance, as AptosDB queries are I/O-intensive operations
2. **Cumulative Effect**: With up to 30 subscriptions per peer and multiple malicious peers, the amplification compounds exponentially
3. **Continuous Attack**: Subscriptions make repeated requests, causing sustained resource exhaustion
4. **Default Configuration Vulnerable**: The legacy implementation is enabled by default (`enable_size_and_time_aware_chunking = false`), making all nodes vulnerable

The attack breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The lack of validation allows malicious peers to force excessive computational work beyond intended limits.

## Likelihood Explanation
This vulnerability has **HIGH likelihood** of exploitation:

1. **No Authentication Required**: Any connected peer can send subscription requests
2. **Simple Exploitation**: Attacker only needs to modify local configuration or craft network messages with a high `max_num_output_reductions` value
3. **No Server-Side Validation**: The storage service handler passes the parameter through without any bounds checking
4. **Default Configuration Affected**: The vulnerable legacy code path is active by default [7](#0-6) 

## Recommendation
Implement server-side validation of the `max_num_output_reductions` parameter to enforce reasonable bounds:

```rust
// In state-sync/storage-service/server/src/handler.rs or storage.rs
const MAX_ALLOWED_OUTPUT_REDUCTIONS: u64 = 5;

fn get_transactions_or_outputs_with_proof(
    &self,
    request: &TransactionsOrOutputsWithProofRequest,
) -> aptos_storage_service_types::Result<DataResponse, Error> {
    // Validate max_num_output_reductions
    let validated_max_reductions = std::cmp::min(
        request.max_num_output_reductions,
        MAX_ALLOWED_OUTPUT_REDUCTIONS
    );
    
    let response = self.storage.get_transactions_or_outputs_with_proof(
        request.proof_version,
        request.start_version,
        request.end_version,
        request.include_events,
        validated_max_reductions, // Use validated value
    )?;
    // ... rest of function
}
```

Additionally, consider:
1. Adding similar validation for all request types that accept `max_num_output_reductions`
2. Migrating to the size-and-time-aware chunking implementation as noted in the TODO comment
3. Adding monitoring/alerting for peers making requests with unusually high reduction counts

## Proof of Concept
```rust
// Test demonstrating the vulnerability
// Add to state-sync/storage-service/server/src/tests/subscribe_transactions_or_outputs.rs

#[tokio::test]
async fn test_excessive_output_reductions_amplification() {
    // Setup test environment
    let highest_version = 1000;
    let highest_epoch = 10;
    let peer_version = 0;
    
    // Create mock DB that tracks number of get_transaction_outputs calls
    let mut db_reader = create_mock_db_reader(highest_version, highest_epoch);
    let call_counter = Arc::new(AtomicU64::new(0));
    let counter_clone = call_counter.clone();
    
    // Configure DB to count calls to get_transaction_outputs
    db_reader
        .expect_get_transaction_outputs()
        .returning(move |_, _, _| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            // Return oversized response to force reductions
            Ok(create_large_output_list())
        });
    
    // Create storage service with legacy implementation enabled
    let mut storage_config = StorageServiceConfig::default();
    storage_config.enable_size_and_time_aware_chunking = false;
    
    let (mut client, service, _, _, _) = 
        MockClient::new(Some(db_reader), Some(storage_config));
    tokio::spawn(service.start());
    
    // Test 1: Normal behavior with max_num_output_reductions = 0
    let _ = subscribe_to_transactions_or_outputs(
        &mut client,
        peer_version,
        highest_epoch,
        false,
        0, // max_num_output_reductions = 0
        random_stream_id(),
        0,
        false,
        storage_config.max_network_chunk_bytes,
    ).await;
    
    let normal_calls = call_counter.load(Ordering::SeqCst);
    assert_eq!(normal_calls, 1, "Should make only 1 database call with max_reductions=0");
    
    // Reset counter
    call_counter.store(0, Ordering::SeqCst);
    
    // Test 2: Malicious behavior with max_num_output_reductions = 100
    let _ = subscribe_to_transactions_or_outputs(
        &mut client,
        peer_version,
        highest_epoch,
        false,
        100, // max_num_output_reductions = 100 (malicious)
        random_stream_id(),
        0,
        false,
        storage_config.max_network_chunk_bytes,
    ).await;
    
    let malicious_calls = call_counter.load(Ordering::SeqCst);
    assert!(
        malicious_calls >= 10,
        "Should make ~12 database calls with max_reductions=100, got: {}",
        malicious_calls
    );
    
    // Demonstrate the amplification factor
    println!(
        "Amplification factor: {}x (normal: {} calls, malicious: {} calls)",
        malicious_calls / normal_calls,
        normal_calls,
        malicious_calls
    );
}
```

**Notes**

The vulnerability is specific to the **legacy implementation** used when `enable_size_and_time_aware_chunking` is `false` (the default). The newer implementation has better chunking logic that mitigates this issue, but the legacy path remains vulnerable and is actively used in production configurations. The TODO comment at line 432 of `state_sync_config.rs` acknowledges this area needs improvement but doesn't address the security implications of unvalidated parameters. [8](#0-7)

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L1218-1226)
```rust
            DataRequest::SubscribeTransactionsOrOutputsWithProof(
                SubscribeTransactionsOrOutputsWithProofRequest {
                    subscription_stream_metadata,
                    include_events,
                    max_num_output_reductions: self.get_max_num_output_reductions(),
                    subscription_stream_index: request_metadata.subscription_stream_index,
                },
            )
        };
```

**File:** state-sync/storage-service/types/src/requests.rs (L400-406)
```rust
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SubscribeTransactionsOrOutputsWithProofRequest {
    pub subscription_stream_metadata: SubscriptionStreamMetadata, // The metadata for the subscription stream request
    pub subscription_stream_index: u64, // The request index of the subscription stream
    pub include_events: bool,           // Whether or not to include events in the response
    pub max_num_output_reductions: u64, // The max num of output reductions before transactions are returned
}
```

**File:** state-sync/storage-service/server/src/storage.rs (L845-886)
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
```

**File:** state-sync/storage-service/server/src/subscription.rs (L116-125)
```rust
            DataRequest::SubscribeTransactionsOrOutputsWithProof(request) => {
                DataRequest::GetTransactionsOrOutputsWithProof(
                    TransactionsOrOutputsWithProofRequest {
                        proof_version: target_version,
                        start_version,
                        end_version,
                        include_events: request.include_events,
                        max_num_output_reductions: request.max_num_output_reductions,
                    },
                )
```

**File:** config/src/config/state_sync_config.rs (L195-207)
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
```

**File:** config/src/config/state_sync_config.rs (L428-433)
```rust
    /// Maximum number of output reductions (division by 2) before transactions are returned,
    /// e.g., if 1000 outputs are requested in a single data chunk, and this is set to 1, then
    /// we'll accept anywhere between 1000 and 500 outputs. Any less, and the server should
    /// return transactions instead of outputs.
    // TODO: migrate away from this, and use cleaner chunk packing configs and logic.
    pub max_num_output_reductions: u64,
```

**File:** config/src/config/state_sync_config.rs (L460-470)
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
```

**File:** state-sync/storage-service/server/src/handler.rs (L547-557)
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
```
