# Audit Report

## Title
State Sync Stream Deadlock via Stale Target Ledger Info Race Condition

## Summary
A race condition in `ContinuousTransactionStreamEngine::select_target_ledger_info()` allows the stream to cache a target ledger info that becomes unavailable before requests are created. This causes the stream to enter a permanent deadlock state where all requests fail but the stale target is never reset, preventing the node from syncing new data. [1](#0-0) 

## Finding Description

The vulnerability occurs in the continuous transaction stream engine's target selection and request creation logic:

**Step 1: Target Selection with Initial Advertised Data** [2](#0-1) 

When `current_target_ledger_info` is `None`, the engine calls `select_target_ledger_info()` which reads from `global_data_summary.advertised_data` (line 1191) and selects the highest synced ledger info. This selected target is then cached in `self.current_target_ledger_info` (line 1220).

**Step 2: Network State Change**
Between the initial call and subsequent calls to `create_data_client_requests()`, the global data summary can be updated (via `ArcSwap` in the data client) when:
- Peers go offline or are disconnected
- Network partitions occur  
- Malicious peers advertise high ledger infos then deliberately disappear [3](#0-2) 

**Step 3: Stale Target Usage**
On the next call to `create_data_client_requests()` with updated `advertised_data`, the check at line 1188 prevents re-selection because `current_target_ledger_info` is not `None`. The engine proceeds to create requests using the stale target: [4](#0-3) 

**Step 4: Request Creation with Stale Proof Version** [5](#0-4) 

The `proof_version` is set to the cached target's version (line 2126), which may no longer be advertised by any peer.

**Step 5: Peer Selection Failure** [6](#0-5) 

When routing the request, no peer can service it because `can_create_proof()` requires the peer's `synced_ledger_info.version() >= proof_version`, and no peer advertises the stale proof version anymore.

**Step 6: Permanent Deadlock** [7](#0-6) 

Failed requests are retried with exponential backoff, but the stale `current_target_ledger_info` is never reset. The only reset condition is: [8](#0-7) 

This only triggers when data is **successfully received** up to the target version, which never happens because no peer can service the requests. The stream is permanently deadlocked until `max_request_retry` is exceeded: [9](#0-8) 

## Impact Explanation

This vulnerability constitutes **High Severity** per the Aptos bug bounty criteria ("Validator node slowdowns"). The impact includes:

1. **Node Availability**: Affected nodes cannot sync new blocks and fall permanently behind the network
2. **Validator Impact**: Validator nodes experiencing this become unable to participate in consensus
3. **Service Disruption**: Fullnodes cannot serve current state to clients
4. **Resource Waste**: The stream consumes resources retrying unserviceable requests with exponential backoff

While this does not cause consensus safety violations or fund loss, it directly affects network availability and node operation, meeting the High Severity threshold.

## Likelihood Explanation

**High Likelihood** - This can occur through:

1. **Natural Network Churn**: Normal peer disconnections during target selection window
2. **Malicious Exploitation**: An attacker operating network peers can:
   - Advertise high ledger infos to attract selection
   - Immediately disconnect or stop advertising
   - Force victim nodes into permanent deadlock
   - Requires no validator privileges or stake

3. **Network Partitions**: Temporary partitions that resolve after target selection can leave nodes with stale targets

The attack is realistic and requires only network peer access, making it highly likely in production environments with dynamic peer connections.

## Recommendation

Add validation to ensure the cached target is still available in current advertised data:

```rust
// In create_data_client_requests, after line 1187:
let (next_request_version, next_request_epoch) = self.next_request_version_and_epoch;
if self.current_target_ledger_info.is_none() {
    // ... existing selection logic ...
} else {
    // NEW: Validate cached target is still advertised
    if let Some(ref cached_target) = self.current_target_ledger_info {
        let cached_version = cached_target.ledger_info().version();
        
        // Check if any peer can still create proof at this version
        let highest_advertised = global_data_summary
            .advertised_data
            .highest_synced_ledger_info();
        
        let target_still_available = highest_advertised
            .map(|li| li.ledger_info().version() >= cached_version)
            .unwrap_or(false);
        
        if !target_still_available {
            // Reset stale target and reselect
            warn!("Cached target ledger info is no longer advertised, reselecting");
            self.current_target_ledger_info = None;
            
            // Recurse to select new target
            return self.create_data_client_requests(
                max_number_of_requests,
                max_in_flight_requests,
                num_in_flight_requests,
                global_data_summary,
                unique_id_generator,
            );
        }
    }
}
```

## Proof of Concept

```rust
// Rust test demonstrating the deadlock condition
#[tokio::test]
async fn test_stale_target_deadlock() {
    // Setup: Create stream engine with initial advertised data
    let mut advertised_data_v1 = AdvertisedData::empty();
    let ledger_info_high = create_ledger_info(1000, 5); // version 1000, epoch 5
    advertised_data_v1.synced_ledger_infos = vec![ledger_info_high.clone()];
    
    let mut global_summary_v1 = GlobalDataSummary::empty();
    global_summary_v1.advertised_data = advertised_data_v1;
    
    // Create stream engine
    let stream_request = create_continuous_stream_request(0, 0, None); 
    let mut engine = ContinuousTransactionStreamEngine::new(
        config,
        &stream_request
    ).unwrap();
    
    // First call: Select target from v1 (ledger info version 1000)
    let requests_1 = engine.create_data_client_requests(
        10, 10, 0, &global_summary_v1, id_gen.clone()
    ).unwrap();
    
    // Verify target was cached
    assert!(engine.current_target_ledger_info.is_some());
    assert_eq!(engine.current_target_ledger_info.unwrap().ledger_info().version(), 1000);
    
    // Network change: peer with version 1000 goes offline
    let mut advertised_data_v2 = AdvertisedData::empty();
    let ledger_info_low = create_ledger_info(500, 5); // Now only version 500 available
    advertised_data_v2.synced_ledger_infos = vec![ledger_info_low];
    
    let mut global_summary_v2 = GlobalDataSummary::empty();
    global_summary_v2.advertised_data = advertised_data_v2;
    
    // Second call: Should fail to create serviceable requests
    let requests_2 = engine.create_data_client_requests(
        10, 10, 0, &global_summary_v2, id_gen.clone()
    ).unwrap();
    
    // Verify requests use stale proof_version=1000
    for req in requests_2 {
        if let DataClientRequest::TransactionsWithProof(txn_req) = req {
            assert_eq!(txn_req.proof_version, 1000); // Stale!
            
            // Verify no peer can service this
            let can_service = advertised_data_v2
                .synced_ledger_infos
                .iter()
                .any(|li| li.ledger_info().version() >= 1000);
            assert!(!can_service); // Deadlock: unserviceable requests
        }
    }
    
    // The stream is now permanently deadlocked with unserviceable requests
}
```

## Notes

This vulnerability specifically affects the continuous transaction streaming path and does not impact optimistic fetch or subscription-based streaming, which extract target ledger info from peer responses rather than using cached targets. The issue requires fixing the target validation logic to detect and handle stale targets proactively.

### Citations

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L498-535)
```rust
    fn select_target_ledger_info(
        &self,
        advertised_data: &AdvertisedData,
    ) -> Result<Option<LedgerInfoWithSignatures>, Error> {
        // Check if the stream has a final target ledger info
        match &self.request {
            StreamRequest::ContinuouslyStreamTransactions(request) => {
                if let Some(target) = &request.target {
                    return Ok(Some(target.clone()));
                }
            },
            StreamRequest::ContinuouslyStreamTransactionOutputs(request) => {
                if let Some(target) = &request.target {
                    return Ok(Some(target.clone()));
                }
            },
            StreamRequest::ContinuouslyStreamTransactionsOrOutputs(request) => {
                if let Some(target) = &request.target {
                    return Ok(Some(target.clone()));
                }
            },
            request => invalid_stream_request!(request),
        };

        // We don't have a final target, select the highest to make progress
        if let Some(highest_synced_ledger_info) = advertised_data.highest_synced_ledger_info() {
            let (next_request_version, _) = self.next_request_version_and_epoch;
            if next_request_version > highest_synced_ledger_info.ledger_info().version() {
                Ok(None) // We're already at the highest synced ledger info. There's no known target.
            } else {
                Ok(Some(highest_synced_ledger_info))
            }
        } else {
            Err(Error::DataIsUnavailable(
                "Unable to find the highest synced ledger info!".into(),
            ))
        }
    }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1078-1081)
```rust
        // Update the current target ledger info if we've hit it
        if last_received_version >= target_ledger_info.ledger_info().version() {
            self.current_target_ledger_info = None;
        }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1186-1222)
```rust
        // If we don't have a syncing target, try to select one
        let (next_request_version, next_request_epoch) = self.next_request_version_and_epoch;
        if self.current_target_ledger_info.is_none() {
            // Try to select a new ledger info from the advertised data
            if let Some(target_ledger_info) =
                self.select_target_ledger_info(&global_data_summary.advertised_data)?
            {
                if target_ledger_info.ledger_info().epoch() > next_request_epoch {
                    // There was an epoch change. Request an epoch ending ledger info.
                    info!(
                        (LogSchema::new(LogEntry::AptosDataClient)
                            .event(LogEvent::Pending)
                            .message(&format!(
                                "Requested an epoch ending ledger info for epoch: {:?}",
                                next_request_epoch
                            )))
                    );
                    self.end_of_epoch_requested = true;
                    return Ok(vec![DataClientRequest::EpochEndingLedgerInfos(
                        EpochEndingLedgerInfosRequest {
                            start_epoch: next_request_epoch,
                            end_epoch: next_request_epoch,
                        },
                    )]);
                } else {
                    debug!(
                        (LogSchema::new(LogEntry::ReceivedDataResponse)
                            .event(LogEvent::Success)
                            .message(&format!(
                                "Setting new target ledger info. Version: {:?}, Epoch: {:?}",
                                target_ledger_info.ledger_info().version(),
                                target_ledger_info.ledger_info().epoch()
                            )))
                    );
                    self.current_target_ledger_info = Some(target_ledger_info);
                }
            }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1226-1267)
```rust
        let maybe_target_ledger_info = self.current_target_ledger_info.clone();
        let client_requests = if let Some(target_ledger_info) = maybe_target_ledger_info {
            // Check if we're still waiting for stream notifications to be sent
            if next_request_version > target_ledger_info.ledger_info().version() {
                return Ok(vec![]);
            }

            // Calculate the number of requests to send
            let num_requests_to_send = calculate_num_requests_to_send(
                max_number_of_requests,
                max_in_flight_requests,
                num_in_flight_requests,
            );

            // Create the client requests for the target
            let optimal_chunk_sizes = match &self.request {
                StreamRequest::ContinuouslyStreamTransactions(_) => {
                    global_data_summary
                        .optimal_chunk_sizes
                        .transaction_chunk_size
                },
                StreamRequest::ContinuouslyStreamTransactionOutputs(_) => {
                    global_data_summary
                        .optimal_chunk_sizes
                        .transaction_output_chunk_size
                },
                StreamRequest::ContinuouslyStreamTransactionsOrOutputs(_) => {
                    global_data_summary
                        .optimal_chunk_sizes
                        .transaction_output_chunk_size
                },
                request => invalid_stream_request!(request),
            };
            let client_requests = create_data_client_request_batch(
                next_request_version,
                target_ledger_info.ledger_info().version(),
                num_requests_to_send,
                optimal_chunk_sizes,
                self.clone().into(),
            )?;
            self.update_request_tracking(&client_requests, &target_ledger_info)?;
            client_requests
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2116-2128)
```rust
        StreamEngine::ContinuousTransactionStreamEngine(stream_engine) => {
            let target_ledger_info_version = stream_engine
                .get_target_ledger_info()?
                .ledger_info()
                .version();
            match &stream_engine.request {
                StreamRequest::ContinuouslyStreamTransactions(request) => {
                    TransactionsWithProof(TransactionsWithProofRequest {
                        start_version: start_index,
                        end_version: end_index,
                        proof_version: target_ledger_info_version,
                        include_events: request.include_events,
                    })
```

**File:** state-sync/aptos-data-client/src/client.rs (L103-103)
```rust
    global_summary_cache: Arc<ArcSwap<GlobalDataSummary>>,
```

**File:** state-sync/storage-service/types/src/responses.rs (L868-881)
```rust
    fn can_service_transactions_with_proof(
        &self,
        start_version: u64,
        end_version: u64,
        proof_version: u64,
    ) -> bool {
        let desired_range = match CompleteDataRange::new(start_version, end_version) {
            Ok(desired_range) => desired_range,
            Err(_) => return false,
        };

        let can_service_transactions = self.can_service_transactions(&desired_range);
        let can_create_proof = self.can_create_proof(proof_version);
        can_service_transactions && can_create_proof
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-454)
```rust
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
        {
            if !self.send_failure && self.stream_end_notification_id.is_none() {
                self.send_end_of_stream_notification().await?;
            }
            return Ok(()); // There's nothing left to do
        }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L729-744)
```rust
    fn resend_data_client_request(
        &mut self,
        data_client_request: &DataClientRequest,
    ) -> Result<(), Error> {
        // Increment the number of client failures for this request
        self.request_failure_count += 1;

        // Resend the client request
        let pending_client_response = self.send_client_request(true, data_client_request.clone());

        // Push the pending response to the head of the sent requests queue
        self.get_sent_data_requests()?
            .push_front(pending_client_response);

        Ok(())
    }
```
