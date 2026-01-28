# Audit Report

## Title
State Sync Liveness Failure Due to Invalid Request Generation from Empty GlobalDataSummary with Zero Chunk Sizes

## Summary
A validation bypass in the state sync system allows empty GlobalDataSummary objects with zero chunk sizes to be cached when all peers are ignored. This causes existing data streams to generate invalid requests with inverted index ranges (end < start), leading to a deadlock where state sync cannot progress until external intervention (new peer connections or node restart).

## Finding Description

The vulnerability exists in the state sync data streaming service through a multi-component failure chain:

**Step 1: Empty Summary Generation**
When all connected peers have scores below `IGNORE_PEER_THRESHOLD` (25.0), the `calculate_global_data_summary()` function filters them out using `get_storage_summary_if_not_ignored()`, resulting in an empty storage summaries list and returning `GlobalDataSummary::empty()`. [1](#0-0) 

**Step 2: Zero Chunk Sizes**
The empty GlobalDataSummary contains `OptimalChunkSizes` with all fields set to 0. [2](#0-1) 

**Step 3: Validation Bypass**
The critical flaw occurs in `fetch_global_data_summary()`, which only validates chunk sizes when the summary is NOT empty (line 469-471). Empty summaries bypass `verify_optimal_chunk_sizes()` validation entirely. [3](#0-2) 

**Step 4: Invalid Request Creation**
When existing data streams call `create_data_client_request_batch()` with `optimal_chunk_size = 0`, the function creates malformed requests. With `num_items_to_fetch = min(total_items_to_fetch, 0) = 0` (line 2072), the calculation at lines 2076-2079 produces `request_end_index = request_start_index + 0 - 1`, resulting in an end index less than the start index when `request_start_index > 0`. [4](#0-3) 

**Step 5: Request Rejection**
Storage service peers reject these invalid requests because `inclusive_range_len()` detects that `end < start` and returns `Error::InvalidRequest`. [5](#0-4) 

**The Deadlock Mechanism:**
1. All peers become ignored → empty summary cached
2. Existing streams generate invalid requests → rejected by peers
3. No successful data responses → peer scores cannot increase
4. Peer scores remain below threshold → peers stay ignored
5. Summary remains empty on refresh → cycle continues

The poller continues polling ignored peers for storage summaries, but these polls do NOT update peer scores. [6](#0-5)  Peer scores only increase through successful DATA request responses via `update_score_success()`. [7](#0-6)  However, data requests are only sent to non-ignored peers as verified by `get_storage_summary_if_not_ignored()`. [8](#0-7) 

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria (up to $10,000):

**Medium Severity - Temporary Liveness Issues:**
- Individual nodes lose state sync capability requiring manual intervention (restart or new peer connections)
- State inconsistencies until resolution
- Does not affect entire network, only isolated nodes
- Validators affected would experience degraded consensus participation

The vulnerability does NOT qualify as Critical or High because:
- It does not halt the entire network
- Recovery is possible through new peer connections or node restart  
- It does not cause permanent state corruption or fund loss
- Requires all connected peers to be simultaneously ignored (less likely for well-connected validators)

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can realistically occur in these scenarios:

1. **Network Partitions**: Temporary connectivity issues causing node isolation with only low-quality peers
2. **Software Bugs**: Legitimate peers with bugs sending invalid responses, triggering score decreases via the multipliers defined in peer_states.rs [9](#0-8) 
3. **Limited Peer Connectivity**: Nodes with few peer connections (2-4 peers) are more susceptible
4. **Peer Scoring Cascade**: Once peers start getting ignored, the empty summary causes more errors, preventing recovery

Triggering requires:
- All connected peers scoring below 25.0 (approximately 14 "not useful" errors at 0.95 multiplier or 4 "malicious" errors at 0.8 multiplier per peer)
- No new peer connections during the deadlock period
- Active data streams attempting to sync

The attack requires no special privileges - any network peer can cause score decreases through invalid responses.

## Recommendation

**Fix 1: Validate Empty Summaries**
In `streaming_service.rs`, the `fetch_global_data_summary()` function should reject empty summaries with an error rather than allowing them to be cached:

```rust
fn fetch_global_data_summary<T: AptosDataClientInterface + Send + Clone + 'static>(
    aptos_data_client: T,
) -> Result<GlobalDataSummary, Error> {
    let global_data_summary = aptos_data_client.get_global_data_summary();
    
    if global_data_summary.is_empty() {
        return Err(Error::DataIsUnavailable(
            "Global data summary is empty - no peers available".to_string()
        ));
    }
    
    verify_optimal_chunk_sizes(&global_data_summary.optimal_chunk_sizes)?;
    Ok(global_data_summary)
}
```

**Fix 2: Validate Chunk Sizes in Request Creation**
In `stream_engine.rs`, add validation in `create_data_client_request_batch()` to prevent zero chunk sizes:

```rust
fn create_data_client_request_batch(
    start_index: u64,
    end_index: u64,
    max_number_of_requests: u64,
    optimal_chunk_size: u64,
    stream_engine: StreamEngine,
) -> Result<Vec<DataClientRequest>, Error> {
    if optimal_chunk_size == 0 {
        return Err(Error::UnexpectedErrorEncountered(
            "Invalid optimal_chunk_size: cannot be zero".into()
        ));
    }
    // ... rest of function
}
```

**Fix 3: Allow Score Recovery for Ignored Peers**
Modify the scoring system to allow ignored peers to recover gradually through successful summary polls, or implement a timeout mechanism that periodically resets peer scores to allow recovery.

## Proof of Concept

The following demonstrates the vulnerability flow:

1. **Setup**: Node has 3 connected peers, all with normal scores (50.0)
2. **Trigger**: All 3 peers send invalid responses causing scores to drop below 25.0
3. **Empty Summary**: `calculate_global_data_summary()` returns empty summary with zero chunk sizes
4. **Invalid Request**: Existing stream calls `create_data_client_request_batch(100, 200, 10, 0, engine)` resulting in request with start=100, end=99
5. **Rejection**: Storage service rejects request via `inclusive_range_len()` returning InvalidRequest
6. **Deadlock**: Peer scores cannot recover because only data responses update scores, but data requests aren't sent to ignored peers

The deadlock persists until manual intervention (restart or new peer connection).

**Notes**

This vulnerability demonstrates a critical gap in the state sync system's resilience to temporary network issues. The combination of peer scoring mechanics, empty summary caching, and lack of validation creates a self-perpetuating failure state. While individual nodes can recover through restart or new peer connections, the vulnerability could affect network health if multiple nodes encounter similar conditions simultaneously, particularly during network partition events or widespread peer software bugs.

### Citations

**File:** state-sync/aptos-data-client/src/peer_states.rs (L36-43)
```rust
/// Add this score on a successful response.
const SUCCESSFUL_RESPONSE_DELTA: f64 = 1.0;
/// Not necessarily a malicious response, but not super useful.
const NOT_USEFUL_MULTIPLIER: f64 = 0.95;
/// Likely to be a malicious response.
const MALICIOUS_MULTIPLIER: f64 = 0.8;
/// Ignore a peer when their score dips below this threshold.
const IGNORE_PEER_THRESHOLD: f64 = 25.0;
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L143-149)
```rust
    pub fn get_storage_summary_if_not_ignored(&self) -> Option<&StorageServerSummary> {
        if self.is_ignored() {
            None
        } else {
            self.storage_summary.as_ref()
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L339-354)
```rust
    pub fn calculate_global_data_summary(&self) -> GlobalDataSummary {
        // Gather all storage summaries, but exclude peers that are ignored
        let storage_summaries: Vec<StorageServerSummary> = self
            .peer_to_state
            .iter()
            .filter_map(|peer_state| {
                peer_state
                    .value()
                    .get_storage_summary_if_not_ignored()
                    .cloned()
            })
            .collect();

        // If we have no peers, return an empty global summary
        if storage_summaries.is_empty() {
            return GlobalDataSummary::empty();
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2070-2079)
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
```

**File:** state-sync/storage-service/server/src/storage.rs (L1485-1494)
```rust
fn inclusive_range_len(start: u64, end: u64) -> aptos_storage_service_types::Result<u64, Error> {
    // len = end - start + 1
    let len = end.checked_sub(start).ok_or_else(|| {
        Error::InvalidRequest(format!("end ({}) must be >= start ({})", end, start))
    })?;
    let len = len
        .checked_add(1)
        .ok_or_else(|| Error::InvalidRequest(format!("end ({}) must not be u64::MAX", end)))?;
    Ok(len)
}
```

**File:** state-sync/aptos-data-client/src/poller.rs (L436-439)
```rust
        // Update the summary for the peer
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/aptos-data-client/src/client.rs (L817-817)
```rust
                self.peer_states.update_score_success(peer);
```
