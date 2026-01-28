# Audit Report

## Title
State Sync Livelock via Malicious Number of States Manipulation

## Summary
A malicious peer can return an incorrectly small `number_of_states` value in response to `GetNumberOfStatesAtVersion` requests, causing the state sync stream to prematurely complete while the storage layer correctly detects incomplete state via cryptographic proofs. This creates a livelock condition that prevents affected nodes from completing bootstrapping.

## Finding Description

The vulnerability exists in the state sync system's handling of the `number_of_states` value returned by peers. This value lacks cryptographic validation and is directly trusted by the StateStreamEngine to determine when to stop requesting state values.

**Attack Flow:**

1. **Malicious Response**: A malicious peer responds to `GetNumberOfStatesAtVersion` with an artificially small value. The peer selection mechanism allows any connected peer to serve this request, including low-priority untrusted peers. [1](#0-0) 

2. **Insufficient Validation**: The only validation performed is a basic sanity check comparing the value against the next request index, with no cryptographic proof validation of the actual state count. [2](#0-1) 

3. **Premature Stream Completion**: The StateStreamEngine uses this malicious value to calculate the end index and marks the stream complete after receiving states up to that incorrect limit. [3](#0-2) [4](#0-3) 

4. **Storage Detects Incompleteness**: When processing state chunks, the storage synchronizer uses the cryptographic `is_last_chunk()` method which correctly identifies that the received chunk is NOT the final chunk based on the SparseMerkleRangeProof structure. [5](#0-4) [6](#0-5) 

5. **Livelock Condition**: When `is_last_chunk()` returns false, storage continues waiting for additional chunks. The stream sends EndOfStream and resets. The bootstrapper then initializes a new stream from the last persisted index, which receives the same malicious `number_of_states` value, creating an infinite loop. [7](#0-6) [8](#0-7) 

6. **No Recovery**: The bootstrapper checks for pending storage data periodically with only logging, but no timeout mechanism exists for this livelock scenario. [9](#0-8) 

The EndOfStream handling resets the stream without validating storage completion status. [10](#0-9) 

## Impact Explanation

This vulnerability causes **node-level liveness failure** requiring manual intervention:

- **Individual Node Liveness Loss**: Affected nodes cannot complete bootstrapping and enter a livelock state where they repeatedly request the same incomplete state chunks without making progress. The node cannot sync state, cannot participate in consensus, and cannot serve user requests.

- **No Automatic Recovery**: The timeout mechanism only applies when waiting for notifications on active streams, not for the livelock scenario where streams continuously reset. No peer penalization occurs because the malicious responses pass basic validation. [11](#0-10) 

- **Manual Intervention Required**: The node must be manually restarted and reconnected to honest peers to escape the livelock condition.

- **State Inconsistency**: The node has incomplete state (missing critical state values) but the stream engine considers syncing complete based on the malicious `number_of_states` value.

This qualifies as a **Medium to High severity** logic vulnerability affecting individual node liveness and state consistency.

## Likelihood Explanation

**Moderate to High Likelihood:**

- **Low Barrier to Entry**: Any entity can run a peer node and advertise state data availability. While malicious peers may be lower priority, they can still be selected when servicing requests.

- **Trivial Execution**: The attacker simply needs to return a smaller number in response to `GetNumberOfStatesAtVersion` requests.

- **No Cryptographic Validation**: The `number_of_states` value is not bound to any cryptographic proof, making the attack straightforward.

- **Difficult to Detect**: The victim node appears to be syncing normally until reaching the incorrect limit, then continuously retries without clear indication of malicious behavior.

- **No Peer Penalization**: Because the malicious response passes basic validation, the peer's score is not decreased, allowing repeated exploitation.

## Recommendation

Add cryptographic validation for the `number_of_states` value by:

1. Requiring peers to provide a proof that binds the state count to the state root hash at the requested version
2. Validating this proof before trusting the `number_of_states` value
3. Alternatively, detect the livelock condition (e.g., requesting the same state indices repeatedly) and trigger peer rotation or report the peer as malicious
4. Add a timeout/retry limit for the scenario where storage is waiting for additional chunks after stream completion

## Proof of Concept

The vulnerability can be demonstrated by:
1. Setting up a malicious peer that responds to `GetNumberOfStatesAtVersion` with an artificially small value
2. Configuring a node to bootstrap using this peer
3. Observing the node enter a livelock state where it repeatedly requests the same state chunks
4. Verifying that `is_last_chunk()` returns false on the storage side while the stream marks itself complete

## Notes

- This is a **livelock** (continuous futile activity) rather than a strict deadlock (complete halt)
- The impact is **node-specific**, not network-wide
- The vulnerability exploits the lack of cryptographic binding between `number_of_states` and the actual state tree structure
- The SparseMerkleRangeProof correctly identifies incomplete state, but this information doesn't propagate back to the stream engine
- Recovery requires manual intervention (restart + peer rotation)

### Citations

**File:** state-sync/aptos-data-client/src/priority.rs (L53-122)
```rust
pub fn get_peer_priority(
    base_config: Arc<BaseConfig>,
    peers_and_metadata: Arc<PeersAndMetadata>,
    peer: &PeerNetworkId,
) -> PeerPriority {
    // Handle the case that this node is a validator
    let peer_network_id = peer.network_id();
    if base_config.role.is_validator() {
        // Validators should highly prioritize other validators
        if peer_network_id.is_validator_network() {
            return PeerPriority::HighPriority;
        }

        // VFNs should be prioritized over PFNs. Note: having PFNs
        // connected to a validator is a rare (but possible) scenario.
        return if peer_network_id.is_vfn_network() {
            PeerPriority::MediumPriority
        } else {
            PeerPriority::LowPriority
        };
    }

    // Handle the case that this node is a VFN
    if peers_and_metadata
        .get_registered_networks()
        .contains(&NetworkId::Vfn)
    {
        // VFNs should highly prioritize validators
        if peer_network_id.is_vfn_network() {
            return PeerPriority::HighPriority;
        }

        // Trusted peers should be prioritized over untrusted peers.
        // This prioritizes other VFNs/seed peers over regular PFNs.
        if is_trusted_peer(peers_and_metadata.clone(), peer) {
            return PeerPriority::MediumPriority;
        }

        // Outbound connections should be prioritized over inbound connections.
        // This prioritizes other VFNs/seed peers over regular PFNs.
        return if let Some(metadata) = utils::get_metadata_for_peer(&peers_and_metadata, *peer) {
            if metadata.get_connection_metadata().is_outbound_connection() {
                PeerPriority::MediumPriority
            } else {
                PeerPriority::LowPriority
            }
        } else {
            PeerPriority::LowPriority // We don't have connection metadata
        };
    }

    // Otherwise, this node is a PFN. PFNs should highly
    // prioritize trusted peers (i.e., VFNs and seed peers).
    if is_trusted_peer(peers_and_metadata.clone(), peer) {
        return PeerPriority::HighPriority;
    }

    // Outbound connections should be prioritized. This prioritizes
    // other VFNs/seed peers over regular PFNs. Inbound connections
    // are always low priority (as they are generally unreliable).
    if let Some(metadata) = utils::get_metadata_for_peer(&peers_and_metadata, *peer) {
        if metadata.get_connection_metadata().is_outbound_connection() {
            PeerPriority::HighPriority
        } else {
            PeerPriority::LowPriority
        }
    } else {
        PeerPriority::LowPriority // We don't have connection metadata
    }
}
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L240-266)
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

            // Create the client requests
            let client_requests = create_data_client_request_batch(
                self.next_request_index,
                end_state_index,
                num_requests_to_send,
                global_data_summary.optimal_chunk_sizes.state_chunk_size,
                self.clone().into(),
            )?;

            // Return the requests
            self.update_request_tracking(&client_requests)?;
            return Ok(client_requests);
        }
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L360-387)
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
            },
            request => invalid_client_request!(request, self),
        }
        Ok(None)
    }
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L870-929)
```rust
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

**File:** types/src/state_store/state_value.rs (L358-363)
```rust
    pub fn is_last_chunk(&self) -> bool {
        let right_siblings = self.proof.right_siblings();
        right_siblings
            .iter()
            .all(|sibling| *sibling == *SPARSE_MERKLE_PLACEHOLDER_HASH)
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L427-441)
```rust
        } else if self.storage_synchronizer.pending_storage_data() {
            // Wait for any pending data to be processed
            sample!(
                SampleRate::Duration(Duration::from_secs(PENDING_DATA_LOG_FREQ_SECS)),
                info!("Waiting for the storage synchronizer to handle pending data!")
            );
        } else {
            // Fetch a new data stream to start streaming data
            self.initialize_active_data_stream(global_data_summary)
                .await?;
        }

        // Check if we've now bootstrapped
        self.notify_listeners_if_bootstrapped().await
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L698-729)
```rust
            // Identify the next state index to fetch
            let next_state_index_to_process = if existing_snapshot_progress {
                // The state snapshot receiver requires that after each reboot we
                // rewrite the last persisted index (again!). This is a limitation
                // of how the snapshot is persisted (i.e., in-memory sibling freezing).
                // Thus, on each stream reset, we overlap every chunk by a single item.
                self
                    .metadata_storage
                    .get_last_persisted_state_value_index(&target_ledger_info)
                    .map_err(|error| {
                        Error::StorageError(format!(
                            "Failed to get the last persisted state value index at version {:?}! Error: {:?}",
                            target_ledger_info_version, error
                        ))
                    })?
            } else {
                0 // We need to start the snapshot sync from index 0
            };

            // Fetch the missing state values
            self.state_value_syncer
                .update_next_state_index_to_process(next_state_index_to_process);
            self.streaming_client
                .get_all_state_values(
                    target_ledger_info_version,
                    Some(next_state_index_to_process),
                )
                .await?
        };
        self.active_data_stream = Some(data_stream);

        Ok(())
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1466-1487)
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
    }
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1538-1556)
```rust
    /// Resets the currently active data stream and speculative state
    pub async fn reset_active_stream(
        &mut self,
        notification_and_feedback: Option<NotificationAndFeedback>,
    ) -> Result<(), Error> {
        if let Some(active_data_stream) = &self.active_data_stream {
            let data_stream_id = active_data_stream.data_stream_id;
            utils::terminate_stream_with_feedback(
                &mut self.streaming_client,
                data_stream_id,
                notification_and_feedback,
            )
            .await?;
        }

        self.active_data_stream = None;
        self.speculative_stream_state = None;
        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/utils.rs (L200-238)
```rust
pub async fn get_data_notification(
    max_stream_wait_time_ms: u64,
    max_num_stream_timeouts: u64,
    active_data_stream: Option<&mut DataStreamListener>,
) -> Result<DataNotification, Error> {
    let active_data_stream = active_data_stream
        .ok_or_else(|| Error::UnexpectedError("The active data stream does not exist!".into()))?;

    let timeout_ms = Duration::from_millis(max_stream_wait_time_ms);
    if let Ok(data_notification) = timeout(timeout_ms, active_data_stream.select_next_some()).await
    {
        // Update the metrics for the data notification receive latency
        metrics::observe_duration(
            &metrics::DATA_NOTIFICATION_LATENCIES,
            metrics::NOTIFICATION_CREATE_TO_RECEIVE,
            data_notification.creation_time,
        );

        // Reset the number of consecutive timeouts for the data stream
        active_data_stream.num_consecutive_timeouts = 0;
        Ok(data_notification)
    } else {
        // Increase the number of consecutive timeouts for the data stream
        active_data_stream.num_consecutive_timeouts += 1;

        // Check if we've timed out too many times
        if active_data_stream.num_consecutive_timeouts >= max_num_stream_timeouts {
            Err(Error::CriticalDataStreamTimeout(format!(
                "{:?}",
                max_num_stream_timeouts
            )))
        } else {
            Err(Error::DataStreamNotificationTimeout(format!(
                "{:?}",
                timeout_ms
            )))
        }
    }
}
```
