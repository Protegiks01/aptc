# Audit Report

## Title
State Sync Deadlock via Malicious Number of States Manipulation

## Summary
A malicious peer can return an incorrectly small `number_of_states` value in response to `GetNumberOfStatesAtVersion` requests, causing the state sync stream to prematurely complete while the storage layer correctly detects incomplete state via cryptographic proofs. This creates an unrecoverable deadlock that prevents nodes from bootstrapping.

## Finding Description

The vulnerability exists in how the state sync system handles the `number_of_states` value returned by peers. This value lacks cryptographic validation and is trusted directly by the StateStreamEngine to determine when to stop requesting state values.

**Attack Flow:**

1. **Malicious Response**: A malicious peer responds to `GetNumberOfStatesAtVersion` with an artificially small value (e.g., 100 when 1000 states actually exist). [1](#0-0) 

2. **Insufficient Validation**: The only validation is a basic sanity check comparing the value against the next request index, with no cryptographic proof validation. [2](#0-1) 

3. **Premature Stream Completion**: The StateStreamEngine uses this malicious value to calculate the end index and marks the stream complete after receiving states up to that incorrect limit. [3](#0-2) [4](#0-3) 

4. **Storage Detects Incompleteness**: When processing state chunks, the storage synchronizer uses the cryptographic `is_last_chunk()` method which correctly identifies that the received chunk is NOT the final chunk based on the SparseMerkleRangeProof structure. [5](#0-4) [6](#0-5) 

5. **Deadlock**: When `is_last_chunk()` returns false, storage waits for additional chunks but the stream has already completed and been reset. The node enters an infinite wait state with no timeout mechanism. [7](#0-6) [8](#0-7) 

6. **No Recovery**: The bootstrapper indefinitely waits for pending storage data with only periodic logging but no timeout. [9](#0-8) 

The EndOfStream handling simply resets the stream without checking storage completion status. [10](#0-9) 

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program:

- **Non-recoverable network partition requiring manual intervention**: Affected nodes cannot complete bootstrapping and become permanently stuck. There is no automatic timeout or recovery mechanism. The node must be manually restarted and connected to honest peers.

- **Total loss of liveness for affected nodes**: The node cannot sync state, cannot participate in consensus, and cannot serve user requests. It remains in a perpetual "waiting for pending data" state.

- **Affects State Consistency Invariant**: The node has incomplete state (missing critical state values) but cannot detect or recover from this condition automatically.

The attack can prevent new nodes from joining the network and can cause existing nodes to become stuck if they attempt to re-bootstrap or fast-sync to a new snapshot.

## Likelihood Explanation

**High Likelihood:**

- **Low Barrier to Entry**: Any entity can run a storage service peer and advertise state data availability. No validator privileges or stake required.

- **Easy to Execute**: The attacker simply needs to return a smaller number in response to `GetNumberOfStatesAtVersion` - trivial to implement.

- **Difficult to Detect**: The victim node appears to be syncing normally until it reaches the incorrect limit, then appears to be "waiting for pending data" which could be mistaken for normal network delays.

- **High Impact**: Every node attempting to bootstrap could potentially connect to the malicious peer, especially if it advertises high data availability.

- **No Rate Limiting**: The attack can be repeated against multiple nodes simultaneously.

## Recommendation

Implement cryptographic validation of the `number_of_states` value by cross-checking it against the actual state values received:

1. **Add a mismatch detector** between stream completion and storage finalization:

```rust
// In StateStreamEngine::transform_client_response_into_notification
// After line 348 where stream_is_complete is set
if last_received_index >= last_stream_index {
    // Before marking complete, check if this is truly the last chunk
    // by verifying the proof indicates no more states exist
    self.stream_is_complete = true;
}
```

2. **Validate against cryptographic proof** when receiving the final state chunk:

```rust
// In process_state_values_payload
if state_value_chunk_with_proof.is_last_chunk() {
    // Verify that the number_of_states we were told matches reality
    let expected_last_index = self.number_of_states
        .ok_or_else(|| Error::UnexpectedError("Missing number_of_states".into()))?
        .checked_sub(1)
        .ok_or_else(|| Error::IntegerOverflow("Invalid number_of_states".into()))?;
    
    if state_value_chunk_with_proof.last_index != expected_last_index {
        return Err(Error::VerificationError(format!(
            "Peer provided incorrect number_of_states! Expected last index: {}, actual last index: {}",
            expected_last_index, state_value_chunk_with_proof.last_index
        )));
    }
}
```

3. **Add timeout mechanism** for pending storage data:

```rust
// In bootstrapper.rs drive_progress
const MAX_PENDING_DATA_WAIT_SECS: u64 = 300; // 5 minutes timeout

if self.storage_synchronizer.pending_storage_data() {
    if self.pending_data_start_time.is_none() {
        self.pending_data_start_time = Some(Instant::now());
    }
    
    if let Some(start_time) = self.pending_data_start_time {
        if start_time.elapsed().as_secs() > MAX_PENDING_DATA_WAIT_SECS {
            warn!("Timeout waiting for pending storage data. Resetting stream.");
            self.reset_active_stream(None).await?;
            self.storage_synchronizer.reset_chunk_executor()?;
            self.pending_data_start_time = None;
        }
    }
}
```

## Proof of Concept

```rust
// Malicious Storage Service Implementation
// File: malicious_storage_service.rs

use aptos_storage_service_types::{
    requests::DataRequest,
    responses::{DataResponse, StorageServiceResponse},
};

pub struct MaliciousStorageService {
    actual_state_count: u64,
    malicious_state_count: u64,
}

impl MaliciousStorageService {
    pub fn new(actual_state_count: u64, malicious_state_count: u64) -> Self {
        Self {
            actual_state_count,
            malicious_state_count,
        }
    }
    
    pub fn handle_request(&self, request: DataRequest) -> StorageServiceResponse {
        match request {
            DataRequest::GetNumberOfStatesAtVersion(_version) => {
                // Return artificially small value instead of actual count
                let data_response = DataResponse::NumberOfStatesAtVersion(
                    self.malicious_state_count // e.g., 100 instead of 1000
                );
                StorageServiceResponse::new(data_response, false).unwrap()
            },
            DataRequest::GetStateValuesWithProof(req) => {
                // Serve legitimate state values up to malicious limit
                // After that, victim won't request more due to stream completion
                // but storage will detect incompleteness via is_last_chunk()
                self.serve_legitimate_state_values(req)
            },
            _ => self.handle_other_requests(request),
        }
    }
}

// Attack Scenario:
// 1. Run malicious storage service with:
//    actual_state_count = 1000
//    malicious_state_count = 100
// 2. Victim node connects and requests GetNumberOfStatesAtVersion
// 3. Malicious service returns 100
// 4. Victim requests states 0-99
// 5. Stream marks complete after receiving state 99
// 6. Storage processes chunk at index 99, calls is_last_chunk()
// 7. Proof shows this is NOT last chunk (states 100-999 still exist)
// 8. Storage waits for more chunks but stream is already complete
// 9. Node stuck indefinitely in "waiting for pending data" state
```

**Notes**

This vulnerability exploits a critical disconnect between the untrusted `number_of_states` value used for stream management and the cryptographically verified `is_last_chunk()` proof used for storage finalization. The StateStreamEngine trusts the peer-provided count to determine when to stop requesting data, while the storage layer correctly uses cryptographic proofs to determine completeness. This mismatch creates an unrecoverable deadlock with no timeout mechanism, allowing a malicious peer to permanently prevent nodes from completing state sync bootstrapping.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L1030-1038)
```rust
    async fn get_number_of_states(
        &self,
        version: Version,
        request_timeout_ms: u64,
    ) -> crate::error::Result<Response<u64>> {
        let data_request = DataRequest::GetNumberOfStatesAtVersion(version);
        self.create_and_send_storage_request(request_timeout_ms, data_request)
            .await
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L240-252)
```rust
        // If we have the number of states, send the requests
        if let Some(number_of_states) = self.number_of_states {
            // Calculate the number of requests to send
            let num_requests_to_send = calculate_num_requests_to_send(
                max_number_of_requests,
                max_in_flight_requests,
                num_in_flight_requests,
            );

            // Calculate the end index
            let end_state_index = number_of_states
                .checked_sub(1)
                .ok_or_else(|| Error::IntegerOverflow("End state index has overflown!".into()))?;
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L372-381)
```rust
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
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L872-876)
```rust
                StorageDataChunk::States(notification_id, states_with_proof) => {
                    // Commit the state value chunk
                    let all_states_synced = states_with_proof.is_last_chunk();
                    let last_committed_state_index = states_with_proof.last_index;
                    let num_state_values = states_with_proof.raw_values.len();
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L909-929)
```rust
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

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L427-432)
```rust
        } else if self.storage_synchronizer.pending_storage_data() {
            // Wait for any pending data to be processed
            sample!(
                SampleRate::Duration(Duration::from_secs(PENDING_DATA_LOG_FREQ_SECS)),
                info!("Waiting for the storage synchronizer to handle pending data!")
            );
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1466-1486)
```rust
    async fn handle_end_of_stream_or_invalid_payload(
        &mut self,
        data_notification: DataNotification,
    ) -> Result<(), Error> {
        // Calculate the feedback based on the notification
        let notification_feedback = match data_notification.data_payload {
            DataPayload::EndOfStream => NotificationFeedback::EndOfStream,
            _ => NotificationFeedback::PayloadTypeIsIncorrect,
        };
        let notification_and_feedback =
            NotificationAndFeedback::new(data_notification.notification_id, notification_feedback);

        // Reset the stream
        self.reset_active_stream(Some(notification_and_feedback))
            .await?;

        // Return an error if the payload was invalid
        match data_notification.data_payload {
            DataPayload::EndOfStream => Ok(()),
            _ => Err(Error::InvalidPayload("Unexpected payload type!".into())),
        }
```

**File:** state-sync/state-sync-driver/src/utils.rs (L40-40)
```rust
pub const PENDING_DATA_LOG_FREQ_SECS: u64 = 3;
```
