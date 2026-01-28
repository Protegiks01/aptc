# Audit Report

## Title
State Sync Livelock via Malicious Number of States Manipulation

## Summary
A malicious peer can return an incorrectly small `number_of_states` value in response to `GetNumberOfStatesAtVersion` requests, causing the state sync stream to prematurely complete while the storage layer correctly detects incomplete state via cryptographic proofs. This creates a livelock condition that prevents affected nodes from completing bootstrapping.

## Finding Description

The vulnerability exists in the state sync system's handling of the `number_of_states` value returned by peers. This value lacks cryptographic validation and is directly trusted by the StateStreamEngine to determine when to stop requesting state values.

**Attack Flow:**

1. **Malicious Response**: A malicious peer responds to `GetNumberOfStatesAtVersion` with an artificially small value. The peer selection mechanism allows any connected peer to serve this request, including low-priority untrusted peers. Low-priority peers are selected when higher-priority peers are insufficient, as the selection iterates through all priority groups. [1](#0-0) 

2. **Insufficient Validation**: The only validation performed is a basic sanity check comparing the value against the next request index (`number_of_states >= next_request_index`), with no cryptographic proof validation of the actual state count. [2](#0-1) 

3. **Premature Stream Completion**: The StateStreamEngine uses this malicious value to calculate the end index (`last_stream_index = number_of_states - 1`) and marks the stream complete (`stream_is_complete = true`) after receiving states up to that incorrect limit. [3](#0-2) 

4. **Storage Detects Incompleteness**: When processing state chunks, the storage synchronizer uses the cryptographic `is_last_chunk()` method which correctly identifies that the received chunk is NOT the final chunk based on the SparseMerkleRangeProof structure (checking if all right siblings are placeholder hashes). [4](#0-3) [5](#0-4) 

5. **Livelock Condition**: When `is_last_chunk()` returns false, storage processes the chunk, updates metadata, and continues waiting for additional chunks. Meanwhile, the stream sends EndOfStream because it considers itself complete, then resets. The bootstrapper then initializes a new stream from the last persisted index. [6](#0-5) [7](#0-6) [8](#0-7) 

6. **No Recovery**: The malicious response passes basic validation and does not trigger peer penalization via `notify_bad_response`. The bootstrapper reinitializes a new stream that can select the same malicious peer again, creating an infinite loop. [9](#0-8) 

## Impact Explanation

This vulnerability causes **node-level liveness failure** requiring manual intervention:

- **Individual Node Liveness Loss**: Affected nodes cannot complete bootstrapping and enter a livelock state where they repeatedly request the same incomplete state chunks without making progress. The node cannot sync state, cannot participate in consensus, and cannot serve user requests.

- **No Automatic Recovery**: The malicious responses pass basic validation, so no peer penalization occurs. The node continuously retries the same bootstrapping process without making progress.

- **Manual Intervention Required**: The node must be manually restarted and reconnected to different honest peers to escape the livelock condition.

This qualifies as a **Medium severity** vulnerability per the Aptos bug bounty program, falling under "Limited Protocol Violations" with temporary liveness issues requiring manual intervention. It does not affect network-wide consensus or cause fund loss, limiting it to individual node impact.

## Likelihood Explanation

**Moderate Likelihood:**

- **Low Barrier to Entry**: Any entity can run a peer node and advertise state data availability. While malicious peers may be lower priority, they are selected when higher-priority peers are unavailable or insufficient.

- **Trivial Execution**: The attacker simply needs to return a smaller number in response to `GetNumberOfStatesAtVersion` requests.

- **No Cryptographic Validation**: The `number_of_states` value is not bound to any cryptographic proof, making the attack straightforward.

- **No Peer Penalization**: Because the malicious response passes basic validation, the peer's score is not decreased, allowing repeated exploitation.

- **Mitigating Factors**: In a healthy network with many honest high-priority peers, malicious low-priority peers are less likely to be selected. However, during network partitions or when nodes have limited connections, the attack becomes more feasible.

## Recommendation

Implement cryptographic validation of the `number_of_states` value by:

1. **Include State Root in Response**: Have peers return the state root hash along with the number of states.

2. **Verify Against Ledger Info**: Validate that the state root matches the expected state root from the verified ledger info at that version.

3. **Add Peer Penalization**: Penalize peers that provide `number_of_states` values that lead to incomplete state chunks (when `is_last_chunk()` returns false but the stream completed).

4. **Implement Retry Limits**: Add a maximum retry count for bootstrapping from the same version to prevent infinite loops, with escalating peer priority requirements on retries.

## Proof of Concept

A full proof of concept would require setting up a malicious peer node and modifying the storage service handler to return an incorrect `number_of_states` value. The attack flow demonstrates the vulnerability exists based on the verified code paths, but a complete PoC would strengthen this finding.

## Notes

This is a logic vulnerability affecting individual node bootstrapping rather than network-wide consensus. While the impact is limited to individual nodes, it represents a denial-of-service vector against new nodes or nodes attempting to resync after downtime. The vulnerability is most concerning during network stress or partition scenarios where malicious peers have a higher chance of being selected.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L394-400)
```rust
        // Select peers by priority (starting with the highest priority first)
        let mut selected_peers = HashSet::new();
        for serviceable_peers in serviceable_peers_by_priorities {
            // Select peers by distance and latency
            let num_peers_remaining = num_peers_for_request.saturating_sub(selected_peers.len());
            let peers = self.choose_random_peers_by_latency(serviceable_peers, num_peers_remaining);

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

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L874-874)
```rust
                    let all_states_synced = states_with_proof.is_last_chunk();
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L909-928)
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
```

**File:** types/src/state_store/state_value.rs (L358-363)
```rust
    pub fn is_last_chunk(&self) -> bool {
        let right_siblings = self.proof.right_siblings();
        right_siblings
            .iter()
            .all(|sibling| *sibling == *SPARSE_MERKLE_PLACEHOLDER_HASH)
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-451)
```rust
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
        {
            if !self.send_failure && self.stream_end_notification_id.is_none() {
                self.send_end_of_stream_notification().await?;
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L435-436)
```rust
            self.initialize_active_data_stream(global_data_summary)
                .await?;
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
