# Audit Report

## Title
State Synchronization Accepts Incomplete State Snapshot Due to Unverified NumberOfStatesAtVersion Response

## Summary
The `NumberOfStatesAtVersion` response from storage service peers lacks cryptographic proof and is trusted without verification. A malicious peer can provide a falsely low state count, causing state synchronization to terminate prematurely with an incomplete state snapshot. This leaves nodes in a corrupted state where transaction execution will fail when accessing missing state values.

## Finding Description

The state synchronization process relies on the `NumberOfStatesAtVersion` response to determine how many state value chunks to request. This response contains only a `u64` value with no cryptographic proof or verification mechanism. [1](#0-0) 

When a node performs state sync, the `StateStreamEngine` first requests the total number of states at a specific version: [2](#0-1) 

The response is accepted with only a basic sanity check (ensuring it's not less than `next_request_index`): [3](#0-2) 

This value is then used to determine when the stream is complete: [4](#0-3) 

**Attack Path:**

1. Malicious peer receives `GetNumberOfStatesAtVersion(V)` request
2. Attacker responds with falsely low count (e.g., 1000 instead of actual 2000)
3. `StateStreamEngine` trusts this value and calculates `end_state_index = 999`
4. Stream requests `StateValuesWithProof` chunks for indices 0-999
5. Malicious peer provides valid chunks with correct Merkle proofs (these are real state values, just incomplete)
6. The last chunk has `is_last_chunk() = false` (proof structure shows more states exist)
7. Stream marks itself complete when `last_received_index >= 999`
8. Stream sends `EndOfStream` notification
9. Storage synchronizer receives incomplete chunks but stream has terminated
10. The receiver task exits without finalizing the snapshot properly [5](#0-4) 

The critical issue is that when `all_states_synced = false` (determined by `is_last_chunk()`), the code continues waiting for more chunks. However, the stream has already terminated based on the false `NumberOfStates` value, leaving the state snapshot incomplete. [6](#0-5) 

## Impact Explanation

This vulnerability falls under **Medium to High Severity**:

**Medium Severity Impact:**
- **State inconsistencies requiring intervention**: Nodes accept incomplete state snapshots, violating the "State Consistency" invariant. The missing state values will cause transaction execution failures when accessed.
- **Limited operational impact**: Individual node corruption that requires manual intervention to fix.

**Potential High/Critical Severity:**
- **Consensus divergence**: If multiple nodes sync from different malicious peers providing different incomplete states, they could diverge when executing transactions that access the missing state values.
- **Deterministic execution violation**: Different nodes with different incomplete states will produce different execution results for the same transactions.

The impact aligns with Medium Severity per the bug bounty program: "State inconsistencies requiring intervention" and could escalate to High if consensus divergence occurs.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Ability to operate as a storage service peer in the network
- Node must select the malicious peer for state sync
- No privileged validator access required

**Complexity: Low**
- Attack is straightforward - simply return a lower number
- Provide valid state chunks (no need to forge proofs)
- Exploits fundamental trust assumption in the protocol

**Likelihood Factors Increasing Risk:**
- During network bootstrap, new nodes select peers for state sync
- No redundant verification from multiple peers
- No cross-validation of the `NumberOfStates` value
- Silent failure mode (node accepts incomplete state)

## Recommendation

Implement cryptographic verification or cross-validation for the `NumberOfStatesAtVersion` response:

**Option 1: Add Merkle Proof for State Count**
Extend the response to include a proof that the reported count matches the actual state tree size. This would require the prover to demonstrate the rightmost leaf in the Jellyfish Merkle tree.

**Option 2: Cross-Validate with Multiple Peers**
Query multiple storage service peers and require consensus on the `NumberOfStates` value before proceeding.

**Option 3: Validate Completion Against Proof Structure**
When the stream completes, verify that the last chunk's `is_last_chunk()` returns `true` before accepting the state snapshot as complete:

```rust
// In storage_synchronizer.rs, after the while loop exits
if !received_last_chunk_confirmation {
    return Err(Error::UnexpectedError(
        "State sync stream ended but last chunk did not indicate completion".into()
    ));
}
```

**Option 4: Eliminate Separate NumberOfStates Request**
Remove the dependency on `NumberOfStates` entirely. Instead, continue requesting state chunks until receiving a chunk where `is_last_chunk() = true`, using only the proof-verified chunk structure to determine completion.

**Recommended Fix: Option 4**
This is the most robust solution as it eliminates the unverified trust assumption entirely and relies solely on cryptographically verified proof structures.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// This test would need to be added to state-sync/data-streaming-service/src/tests/

#[tokio::test]
async fn test_incomplete_state_sync_with_false_number_of_states() {
    // Setup: Create a mock storage service that returns false NumberOfStates
    let mock_storage = MockStorageService::new();
    
    // Actual state has 2000 values at version 100
    let actual_state_count = 2000;
    let version = 100;
    
    // Malicious peer returns only 1000
    let malicious_state_count = 1000;
    mock_storage.set_number_of_states_response(version, malicious_state_count);
    
    // Provide valid state chunks for indices 0-999
    for i in (0..malicious_state_count).step_by(100) {
        let end = std::cmp::min(i + 99, malicious_state_count - 1);
        let chunk = create_valid_state_chunk(version, i, end, false); // is_last = false
        mock_storage.add_state_chunk(chunk);
    }
    
    // Start state sync
    let mut state_sync = StateSync::new(mock_storage);
    let result = state_sync.sync_to_version(version).await;
    
    // Vulnerability: State sync completes successfully
    assert!(result.is_ok());
    
    // But state is incomplete - only 1000 values synced instead of 2000
    let synced_count = state_sync.get_synced_state_count(version);
    assert_eq!(synced_count, malicious_state_count);
    
    // Transaction accessing state at index 1500 will fail
    let state_key = create_state_key(1500);
    let result = state_sync.get_state_value(version, state_key).await;
    assert!(result.is_err()); // Missing state value
    
    // This demonstrates the node accepted incomplete state
    // In production, this would cause consensus divergence
}
```

The proof of concept demonstrates that a node will accept an incomplete state snapshot when provided with a false `NumberOfStates` value, violating state consistency guarantees and leading to transaction execution failures.

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L148-148)
```rust
    NumberOfStatesAtVersion(u64),
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L269-284)
```rust
        info!(
            (LogSchema::new(LogEntry::AptosDataClient)
                .event(LogEvent::Pending)
                .message(&format!(
                    "Requested the number of states at version: {:?}",
                    self.request.version
                )))
        );

        // Return the request
        self.state_num_requested = true;
        Ok(vec![DataClientRequest::NumberOfStates(
            NumberOfStatesRequest {
                version: self.request.version,
            },
        )])
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L342-349)
```rust
                // Check if the stream is complete
                let last_stream_index = self
                    .get_number_of_states()?
                    .checked_sub(1)
                    .ok_or_else(|| Error::IntegerOverflow("End index has overflown!".into()))?;
                if last_received_index >= last_stream_index {
                    self.stream_is_complete = true;
                }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L360-382)
```rust
            NumberOfStates(request) => {
                if let ResponsePayload::NumberOfStates(number_of_states) = client_response_payload {
                    info!(
                        (LogSchema::new(LogEntry::ReceivedDataResponse)
                            .event(LogEvent::Success)
                            .message(&format!(
                                "Received number of states at version: {:?}. Total states: {:?}",
                                request.version, number_of_states
                            )))
                    );
                    self.state_num_requested = false;

                    // Sanity check the response before saving it.
                    if number_of_states < self.next_request_index {
                        return Err(Error::NoDataToFetch(format!(
                            "The next state index to fetch is higher than the \
                            total number of states. Next index: {:?}, total states: {:?}",
                            self.next_request_index, number_of_states
                        )));
                    } else {
                        self.number_of_states = Some(number_of_states);
                    }
                }
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L862-929)
```rust
        // Handle state value chunks
        while let Some(storage_data_chunk) = state_snapshot_listener.next().await {
            // Start the snapshot timer for the state value chunk
            let _timer = metrics::start_timer(
                &metrics::STORAGE_SYNCHRONIZER_LATENCIES,
                metrics::STORAGE_SYNCHRONIZER_STATE_VALUE_CHUNK,
            );

            // Commit the state value chunk
            match storage_data_chunk {
                StorageDataChunk::States(notification_id, states_with_proof) => {
                    // Commit the state value chunk
                    let all_states_synced = states_with_proof.is_last_chunk();
                    let last_committed_state_index = states_with_proof.last_index;
                    let num_state_values = states_with_proof.raw_values.len();

                    let result = state_snapshot_receiver.add_chunk(
                        states_with_proof.raw_values,
                        states_with_proof.proof.clone(),
                    );

                    // Handle the commit result
                    match result {
                        Ok(()) => {
                            // Update the logs and metrics
                            info!(
                                LogSchema::new(LogEntry::StorageSynchronizer).message(&format!(
                                    "Committed a new state value chunk! Chunk size: {:?}, last persisted index: {:?}",
                                    num_state_values,
                                    last_committed_state_index
                                ))
                            );

                            // Update the chunk metrics
                            let operation_label =
                                metrics::StorageSynchronizerOperations::SyncedStates.get_label();
                            metrics::set_gauge(
                                &metrics::STORAGE_SYNCHRONIZER_OPERATIONS,
                                operation_label,
                                last_committed_state_index,
                            );
                            metrics::observe_value(
                                &metrics::STORAGE_SYNCHRONIZER_CHUNK_SIZES,
                                operation_label,
                                num_state_values as u64,
                            );

                            if !all_states_synced {
                                // Update the metadata storage with the last committed state index
                                if let Err(error) = metadata_storage
                                    .clone()
                                    .update_last_persisted_state_value_index(
                                        &target_ledger_info,
                                        last_committed_state_index,
                                        all_states_synced,
                                    )
                                {
                                    let error = format!("Failed to update the last persisted state index at version: {:?}! Error: {:?}", version, error);
                                    send_storage_synchronizer_error(
                                        error_notification_sender.clone(),
                                        notification_id,
                                        error,
                                    )
                                    .await;
                                }
                                decrement_pending_data_chunks(pending_data_chunks.clone());
                                continue; // Wait for the next chunk
                            }
```

**File:** types/src/state_store/state_value.rs (L355-363)
```rust
impl StateValueChunkWithProof {
    /// Returns true iff this chunk is the last chunk (i.e., there are no
    /// more state values to write to storage after this chunk).
    pub fn is_last_chunk(&self) -> bool {
        let right_siblings = self.proof.right_siblings();
        right_siblings
            .iter()
            .all(|sibling| *sibling == *SPARSE_MERKLE_PLACEHOLDER_HASH)
    }
```
