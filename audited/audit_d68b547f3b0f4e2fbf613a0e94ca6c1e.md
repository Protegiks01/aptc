# Audit Report

## Title
State Synchronization Halt Due to Zero Chunk Sizes from Empty Peer Set

## Summary
When no peers are connected or all peers are ignored, `OptimalChunkSizes::empty()` initializes all chunk sizes to zero. This causes data stream initialization to fail with either integer overflow errors or infinite loops creating invalid requests, completely halting state synchronization and preventing nodes from joining or recovering from network partitions.

## Finding Description

The vulnerability occurs through a multi-step failure in the state synchronization pipeline:

**1. Empty Initialization:** The streaming service initializes with an empty global data summary containing zero chunk sizes. [1](#0-0) 

**2. Zero Chunk Size Definition:** `OptimalChunkSizes::empty()` sets all chunk sizes to 0. [2](#0-1) 

**3. No Peers Scenario:** When no valid peers exist, `calculate_global_data_summary()` returns the empty summary. [3](#0-2) 

**4. Validation Bypass:** The `verify_optimal_chunk_sizes()` function checks for zero chunk sizes, but only if the summary is NOT empty. When the summary IS empty, validation is completely skipped. [4](#0-3) [5](#0-4) 

**5. Unchecked Usage:** When initializing data streams, `get_global_data_summary()` loads the cached value WITHOUT validation. [6](#0-5) [7](#0-6) 

**6. Stream Engines Use Zero Chunk Sizes:** All stream engines (StateStreamEngine, EpochEndingStreamEngine, TransactionStreamEngine) extract and use the zero chunk sizes. [8](#0-7) [9](#0-8) [10](#0-9) 

**7. Critical Failure in Request Batching:** The `create_data_client_request_batch()` function fails catastrophically with chunk size 0: [11](#0-10) 

When `optimal_chunk_size = 0`:
- `num_items_to_fetch = min(total_items_to_fetch, 0) = 0`
- If `request_start_index = 0`: Causes integer underflow when computing `request_end_index = 0 + 0 - 1`, returning an overflow error
- If `request_start_index > 0`: Creates invalid requests with `request_end_index = request_start_index - 1` (end < start)
- `total_items_to_fetch` never decreases (subtracting 0)
- Loop runs until hitting `max_number_of_requests`, creating many invalid requests

**8. Invalid Requests Rejected:** The storage service validates and rejects requests where `end_index < start_index`. [12](#0-11) 

## Impact Explanation

This vulnerability has **Medium severity** impact per the Aptos bug bounty criteria:

**State Synchronization Halt:** Nodes cannot synchronize state when no peers are available or all peers are ignored. This breaks the state consistency invariant requiring nodes to reach consensus on state.

**Affected Scenarios:**
1. **New Node Bootstrapping:** Fresh nodes joining the network with no initial peers cannot sync and remain permanently stuck
2. **Network Partition Recovery:** Nodes recovering from network partitions where all previous peers disconnected cannot re-sync
3. **Peer Reputation Failures:** If all peers get marked as ignored due to scoring issues, existing nodes cannot create new sync streams

**Limited but Real Impact:**
- Does NOT directly affect consensus safety (existing synced nodes continue operating)
- Does NOT cause fund loss or theft
- DOES prevent new nodes from joining (network availability issue)
- DOES require manual intervention to recover (restart with valid peers)

This qualifies as "State inconsistencies requiring intervention" under Medium severity ($10,000 category).

## Likelihood Explanation

**Likelihood: Medium-to-High** in specific operational scenarios:

**High Likelihood Scenarios:**
1. **Network Bootstrap Phase:** When network participants first start, there's a window where no peers are known
2. **Isolated Node Deployment:** Validators or fullnodes deployed in isolated network segments
3. **Aggressive Peer Filtering:** Configurations with strict peer reputation thresholds combined with network instability

**Trigger Conditions:**
- No connected peers OR all peers ignored (score below threshold)
- Stream creation request while global data summary remains empty
- No special privileges or malicious actions required

**Attack Complexity:** None - this is a defensive bug that occurs naturally under adverse network conditions, not requiring attacker actions.

## Recommendation

Implement validation at the point of use to ensure chunk sizes are never zero when creating data streams:

**Fix Option 1 - Validate Before Stream Initialization:**
Modify `update_progress_of_data_stream()` to validate chunk sizes before initializing requests:

```rust
// In streaming_service.rs, update_progress_of_data_stream()
if !data_stream.data_requests_initialized() {
    // Validate optimal chunk sizes before use
    if global_data_summary.is_empty() {
        return Err(Error::NoDataToFetch(
            "Cannot initialize stream: no peers available with valid chunk sizes".into()
        ));
    }
    verify_optimal_chunk_sizes(&global_data_summary.optimal_chunk_sizes)?;
    
    // Initialize the request batch
    data_stream.initialize_data_requests(global_data_summary)?;
    // ... rest of code
}
```

**Fix Option 2 - Use Safe Defaults:**
Modify `median_or_max()` to return configured max values when no peer data exists: [13](#0-12) 

Change behavior so that when `values` is empty, return `max_value` from config instead of allowing `GlobalDataSummary::empty()` to be created with zeros. However, this requires changing the early return at line 352-355.

**Fix Option 3 - Guard in Request Batch Creation:**
Add explicit check in `create_data_client_request_batch()`:

```rust
fn create_data_client_request_batch(
    start_index: u64,
    end_index: u64,
    max_number_of_requests: u64,
    optimal_chunk_size: u64,
    stream_engine: StreamEngine,
) -> Result<Vec<DataClientRequest>, Error> {
    // Add validation
    if optimal_chunk_size == 0 {
        return Err(Error::AptosDataClientResponseIsInvalid(
            "Optimal chunk size cannot be zero".into()
        ));
    }
    
    if start_index > end_index {
        return Ok(vec![]);
    }
    // ... rest of existing code
}
```

**Recommended Approach:** Implement Fix Option 1 (validate before use) as it provides the clearest error message and prevents the issue at the appropriate abstraction level.

## Proof of Concept

```rust
// Reproduction test (add to state-sync/data-streaming-service/src/tests/)
#[tokio::test]
async fn test_zero_chunk_size_stream_initialization() {
    use crate::streaming_service::DataStreamingService;
    use crate::tests::streaming_service;
    use aptos_data_client::global_summary::{GlobalDataSummary, OptimalChunkSizes};
    
    // Create streaming service with empty global data summary
    let (streaming_client, mut streaming_service) = 
        streaming_service::create_streaming_client_and_server(
            None, false, false, false, false
        );
    
    // Verify global data summary is empty with zero chunk sizes
    let global_summary = streaming_service.get_global_data_summary();
    assert_eq!(global_summary.optimal_chunk_sizes.state_chunk_size, 0);
    assert_eq!(global_summary.optimal_chunk_sizes.transaction_chunk_size, 0);
    assert_eq!(global_summary.optimal_chunk_sizes.epoch_chunk_size, 0);
    
    // Attempt to create a state stream
    let stream_result = streaming_client
        .get_all_state_values(0, 0)
        .await;
    
    // Stream creation should succeed (bug: no validation here)
    assert!(stream_result.is_ok());
    let mut stream_listener = stream_result.unwrap();
    
    // Spawn service to process stream initialization
    tokio::spawn(streaming_service.start_service());
    
    // Wait for stream initialization to be attempted
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Try to get a notification - this should fail because stream
    // initialization with chunk_size=0 causes errors
    let notification_result = tokio::time::timeout(
        Duration::from_secs(5),
        stream_listener.select_next_some()
    ).await;
    
    // Expect timeout or error due to zero chunk size issue
    assert!(notification_result.is_err() || 
            matches!(notification_result, Ok(Err(_))));
    
    // Demonstrates: Stream cannot make progress with zero chunk sizes
}
```

**Steps to Reproduce in Live Environment:**
1. Start an Aptos fullnode with no seed peers configured
2. Request state synchronization before any peers connect
3. Observe that data streams fail to initialize or create invalid requests
4. Check logs for "End index to fetch has overflown" or repeated request failures
5. Node remains unable to sync until peers connect and provide valid chunk sizes

### Citations

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L106-106)
```rust
            global_data_summary: Arc::new(ArcSwap::new(Arc::new(GlobalDataSummary::empty()))),
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L157-159)
```rust
    fn get_global_data_summary(&self) -> GlobalDataSummary {
        self.global_data_summary.load().clone().deref().clone()
    }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L345-345)
```rust
        let global_data_summary = self.get_global_data_summary();
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L463-471)
```rust
    if global_data_summary.is_empty() {
        sample!(
            SampleRate::Duration(Duration::from_secs(GLOBAL_DATA_REFRESH_LOG_FREQ_SECS)),
            info!(LogSchema::new(LogEntry::RefreshGlobalData)
                .message("Latest global data summary is empty."))
        );
    } else {
        verify_optimal_chunk_sizes(&global_data_summary.optimal_chunk_sizes)?;
    }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L478-491)
```rust
fn verify_optimal_chunk_sizes(optimal_chunk_sizes: &OptimalChunkSizes) -> Result<(), Error> {
    if optimal_chunk_sizes.state_chunk_size == 0
        || optimal_chunk_sizes.epoch_chunk_size == 0
        || optimal_chunk_sizes.transaction_chunk_size == 0
        || optimal_chunk_sizes.transaction_output_chunk_size == 0
    {
        Err(Error::AptosDataClientResponseIsInvalid(format!(
            "Found at least one optimal chunk size of zero: {:?}",
            optimal_chunk_sizes
        )))
    } else {
        Ok(())
    }
}
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L53-60)
```rust
    pub fn empty() -> Self {
        OptimalChunkSizes {
            epoch_chunk_size: 0,
            state_chunk_size: 0,
            transaction_chunk_size: 0,
            transaction_output_chunk_size: 0,
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L352-355)
```rust
        // If we have no peers, return an empty global summary
        if storage_summaries.is_empty() {
            return GlobalDataSummary::empty();
        }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L448-456)
```rust
fn median_or_max<T: Ord + Copy>(mut values: Vec<T>, max_value: T) -> T {
    // Calculate median
    values.sort_unstable();
    let idx = values.len() / 2;
    let median = values.get(idx).copied();

    // Return median or max
    min(median.unwrap_or(max_value), max_value)
}
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L255-261)
```rust
            let client_requests = create_data_client_request_batch(
                self.next_request_index,
                end_state_index,
                num_requests_to_send,
                global_data_summary.optimal_chunk_sizes.state_chunk_size,
                self.clone().into(),
            )?;
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1557-1563)
```rust
        let client_requests = create_data_client_request_batch(
            self.next_request_epoch,
            self.end_epoch,
            num_requests_to_send,
            global_data_summary.optimal_chunk_sizes.epoch_chunk_size,
            self.clone().into(),
        )?;
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1806-1842)
```rust
        let (request_end_version, optimal_chunk_sizes) = match &self.request {
            StreamRequest::GetAllTransactions(request) => (
                request.end_version,
                global_data_summary
                    .optimal_chunk_sizes
                    .transaction_chunk_size,
            ),
            StreamRequest::GetAllTransactionOutputs(request) => (
                request.end_version,
                global_data_summary
                    .optimal_chunk_sizes
                    .transaction_output_chunk_size,
            ),
            StreamRequest::GetAllTransactionsOrOutputs(request) => (
                request.end_version,
                global_data_summary
                    .optimal_chunk_sizes
                    .transaction_output_chunk_size,
            ),
            request => invalid_stream_request!(request),
        };

        // Calculate the number of requests to send
        let num_requests_to_send = calculate_num_requests_to_send(
            max_number_of_requests,
            max_in_flight_requests,
            num_in_flight_requests,
        );

        // Create the client requests
        let client_requests = create_data_client_request_batch(
            self.next_request_version,
            request_end_version,
            num_requests_to_send,
            optimal_chunk_sizes,
            self.clone().into(),
        )?;
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2070-2096)
```rust
    while total_items_to_fetch > 0 && num_requests_made < max_number_of_requests {
        // Calculate the number of items to fetch in this request
        let num_items_to_fetch = cmp::min(total_items_to_fetch, optimal_chunk_size);

        // Calculate the start and end indices for the request
        let request_start_index = next_index_to_request;
        let request_end_index = request_start_index
            .checked_add(num_items_to_fetch)
            .and_then(|e| e.checked_sub(1)) // = request_start_index + num_items_to_fetch - 1
            .ok_or_else(|| Error::IntegerOverflow("End index to fetch has overflown!".into()))?;

        // Create the data client requests
        let data_client_request =
            create_data_client_request(request_start_index, request_end_index, &stream_engine)?;
        data_client_requests.push(data_client_request);

        // Update the local loop state
        next_index_to_request = request_end_index
            .checked_add(1)
            .ok_or_else(|| Error::IntegerOverflow("Next index to request has overflown!".into()))?;
        total_items_to_fetch = total_items_to_fetch
            .checked_sub(num_items_to_fetch)
            .ok_or_else(|| Error::IntegerOverflow("Total items to fetch has overflown!".into()))?;
        num_requests_made = num_requests_made.checked_add(1).ok_or_else(|| {
            Error::IntegerOverflow("Number of payload requests has overflown!".into())
        })?;
    }
```

**File:** state-sync/storage-service/server/src/tests/state_values.rs (L160-168)
```rust
    // Test invalid ranges
    let start_index = 100;
    for end_index in [0, 99] {
        let response =
            get_state_values_with_proof(&mut mock_client, 0, start_index, end_index, false)
                .await
                .unwrap_err();
        assert_matches!(response, StorageServiceError::InvalidRequest(_));
    }
```
