# Audit Report

## Title
State Sync Liveness Failure Due to Invalid Request Generation from Empty GlobalDataSummary with Zero Chunk Sizes

## Summary
A validation bypass in the state sync system allows empty GlobalDataSummary objects with zero chunk sizes to be cached when all peers are ignored. This causes existing data streams to generate invalid requests with inverted index ranges (end < start), leading to a deadlock where state sync cannot progress until external intervention (new peer connections or node restart).

## Finding Description

The vulnerability exists in the state sync data streaming service through a multi-component failure chain:

**Step 1: Empty Summary Generation**
When all connected peers have scores below `IGNORE_PEER_THRESHOLD` (25.0), the `calculate_global_data_summary()` function filters them out, resulting in an empty storage summaries list and returning `GlobalDataSummary::empty()`. [1](#0-0) 

**Step 2: Zero Chunk Sizes**
The empty GlobalDataSummary contains `OptimalChunkSizes` with all fields set to 0. [2](#0-1) 

**Step 3: Validation Bypass**
The critical flaw occurs in `fetch_global_data_summary()`, which only validates chunk sizes when the summary is NOT empty. Empty summaries bypass `verify_optimal_chunk_sizes()` validation entirely. [3](#0-2) 

**Step 4: Invalid Request Creation**
When existing data streams call `create_data_client_request_batch()` with `optimal_chunk_size = 0`, the function creates malformed requests. With `num_items_to_fetch = min(total_items_to_fetch, 0) = 0`, the calculation `request_end_index = request_start_index + 0 - 1` produces an end index less than the start index when `request_start_index > 0`. [4](#0-3) 

**Step 5: Request Rejection**
Storage service peers reject these invalid requests because `inclusive_range_len()` detects that `end < start` and returns `Error::InvalidRequest`. [5](#0-4) 

**The Deadlock Mechanism:**
1. All peers become ignored → empty summary cached
2. Existing streams generate invalid requests → rejected by peers
3. No successful data responses → peer scores cannot increase
4. Peer scores remain below threshold → peers stay ignored
5. Summary remains empty on refresh → cycle continues

The poller continues polling ignored peers for storage summaries, but these polls do NOT update peer scores. Peer scores only increase through successful DATA request responses, which cannot occur because data requests are only sent to non-ignored peers. [6](#0-5) 

## Impact Explanation

This qualifies as **Medium to High Severity** per Aptos bug bounty criteria:

**Medium Severity** (Temporary Liveness Issues):
- Individual nodes lose state sync capability requiring manual intervention
- State inconsistencies until resolution through new peer connections or restart
- Does not affect entire network, only isolated nodes

**Potentially High Severity** (Validator Node Slowdowns):
- If validators are affected, they cannot catch up to current state
- Degraded consensus participation until recovery
- However, requires validators to simultaneously ignore all their peers (less likely given their typical peer connectivity)

The vulnerability does NOT qualify as Critical because:
- It does not halt the entire network
- Recovery is possible through new peer connections or node restart
- It does not cause permanent state corruption or fund loss

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can realistically occur in these scenarios:

1. **Network Partitions**: Temporary connectivity issues causing node isolation with only low-quality peers
2. **Software Bugs**: Legitimate peers with bugs sending invalid responses, triggering score decreases  
3. **Limited Peer Connectivity**: Nodes with few peer connections (2-4 peers) are more susceptible
4. **Peer Scoring Cascade**: Once peers start getting ignored, the empty summary causes more errors, preventing recovery

Triggering requires:
- All connected peers scoring below 25.0 (approximately 14 "not useful" errors or 4 "malicious" errors per peer)
- No new peer connections during the deadlock period
- Active data streams attempting to sync

The attack requires no special privileges - any network peer can cause score decreases through invalid responses.

## Recommendation

**Fix 1: Remove Empty Summary Validation Bypass**
Always validate optimal chunk sizes, even for empty summaries:

```rust
fn fetch_global_data_summary<T: AptosDataClientInterface + Send + Clone + 'static>(
    aptos_data_client: T,
) -> Result<GlobalDataSummary, Error> {
    let global_data_summary = aptos_data_client.get_global_data_summary();
    
    // Always validate chunk sizes
    verify_optimal_chunk_sizes(&global_data_summary.optimal_chunk_sizes)?;
    
    if global_data_summary.is_empty() {
        sample!(
            SampleRate::Duration(Duration::from_secs(GLOBAL_DATA_REFRESH_LOG_FREQ_SECS)),
            info!(LogSchema::new(LogEntry::RefreshGlobalData)
                .message("Latest global data summary is empty."))
        );
    }
    
    Ok(global_data_summary)
}
```

**Fix 2: Add Zero Check in Request Batch Creation**
Prevent creation of invalid requests when chunk size is zero:

```rust
fn create_data_client_request_batch(...) -> Result<Vec<DataClientRequest>, Error> {
    if start_index > end_index {
        return Ok(vec![]);
    }
    
    // Add check for zero chunk size
    if optimal_chunk_size == 0 {
        return Err(Error::UnexpectedErrorEncountered(
            "Cannot create requests with zero optimal chunk size".into()
        ));
    }
    
    // ... rest of implementation
}
```

**Fix 3: Score Recovery Mechanism**
Implement periodic score recovery or allow polling success to marginally increase scores to prevent permanent deadlock.

## Proof of Concept

The vulnerability can be demonstrated through the following sequence:

1. Configure node with `ignore_low_score_peers = true`
2. Connect to 2-3 test peers
3. Cause peers to send invalid responses (corrupt data, proof verification failures)
4. Observe peer scores dropping below IGNORE_PEER_THRESHOLD (25.0)
5. Verify `GlobalDataSummary::empty()` is cached with zero chunk sizes
6. Observe existing data streams attempting to create requests
7. Confirm `Error::IntegerOverflow` (when start_index=0) or `Error::InvalidRequest` from peers
8. Verify state sync halts and cannot recover without new peer connections

The core bug is in the validation logic where empty summaries bypass chunk size validation, allowing a known-invalid state (zero chunk sizes) to propagate through the system.

## Notes

**Recovery Paths:**
- New peer connections that aren't immediately ignored
- Node restart (resets all peer scores to default 50.0)
- Manual peer management/configuration changes

**Root Cause:**
The fundamental issue is treating empty summaries as a special case that bypasses validation, when they should either be rejected entirely or prevented from being used for request generation.

### Citations

**File:** state-sync/aptos-data-client/src/peer_states.rs (L280-300)
```rust
    /// Updates the score of the peer according to a successful operation
    pub fn update_score_success(&self, peer: PeerNetworkId) {
        if let Some(mut entry) = self.peer_to_state.get_mut(&peer) {
            // Get the peer's old score
            let old_score = entry.score;

            // Update the peer's score with a successful operation
            entry.update_score_success();

            // Log if the peer is no longer ignored
            let new_score = entry.score;
            if old_score <= IGNORE_PEER_THRESHOLD && new_score > IGNORE_PEER_THRESHOLD {
                info!(
                    (LogSchema::new(LogEntry::PeerStates)
                        .event(LogEvent::PeerNoLongerIgnored)
                        .message("Peer will no longer be ignored")
                        .peer(&peer))
                );
            }
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L341-355)
```rust
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

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L463-474)
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

    Ok(global_data_summary)
}
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

**File:** state-sync/storage-service/server/src/storage.rs (L1485-1493)
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
```
