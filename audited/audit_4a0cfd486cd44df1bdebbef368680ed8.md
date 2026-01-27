# Audit Report

## Title
Race Condition Between Global Summary Snapshot and Peer Pruning Causes Permanent Synchronization Failure

## Summary
A timing vulnerability exists in the state synchronization system where `ensure_data_is_available()` validates data availability using a snapshot of the global summary at stream creation time, but network-wide pruning can make this data unavailable by the time actual requests are sent. This causes streams to be created successfully but then fail permanently when requesting from peers that have pruned the required historical transaction outputs.

## Finding Description

The vulnerability arises from a race condition between two different views of data availability:

1. **Stream Creation Phase**: `ensure_data_is_available()` uses the global aggregated summary to validate that required data exists somewhere in the network [1](#0-0) 

2. **Request Phase**: `choose_peers_for_request()` validates each peer individually using their current advertised ranges [2](#0-1) 

The global summary aggregates transaction output ranges from all peers into a single view [3](#0-2) . The `is_remaining_data_available()` method checks if data exists in ANY advertised range using this aggregated view [4](#0-3) .

**Attack Scenario:**
1. At T=0: Peer A advertises transaction_outputs [100, 2000], Peer B advertises [500, 2000]
2. At T=1: Global summary shows ranges [[100, 2000], [500, 2000]]
3. At T=2: Node needs to sync from version 200
4. At T=3: `ensure_data_is_available(200)` checks global summary and returns TRUE (version 200 exists in range [100, 2000])
5. At T=4: Stream is created successfully [5](#0-4) 
6. At T=5: Peer A prunes aggressively to [400, 2000]
7. At T=6: Polling updates Peer A's summary [6](#0-5) 
8. At T=7: Request for version 200 attempts peer selection:
   - Peer A: [400, 2000] doesn't contain 200 [7](#0-6) 
   - Peer B: [500, 2000] doesn't contain 200
9. No peers selected, returns `DataIsUnavailable` [8](#0-7) 
10. Retry with exponential backoff [9](#0-8) 
11. All subsequent retries fail because `ensure_data_is_available()` is never re-called to validate the stream should be terminated
12. Synchronization is permanently stuck

The `lowest_transaction_output_version()` function returns the minimum across all peer ranges [10](#0-9) , which is used for metrics but also influences the global summary used by `is_remaining_data_available()`.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program because:

1. **Validator Node Slowdowns**: Validator nodes attempting to catch up from behind cannot sync past the pruned versions, effectively preventing them from rejoining the network
2. **Significant Protocol Violation**: The state sync protocol's fundamental guarantee—that nodes can synchronize to the latest state—is violated
3. **Availability Impact**: Affected nodes cannot participate in consensus, reducing network resilience

The vulnerability breaks the **State Consistency** and **Liveness** invariants:
- Nodes cannot maintain consistent state if they cannot sync
- The network loses liveness for affected nodes

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH** in production deployments where:

1. Nodes configure different pruning rates (common for archival vs. regular validators)
2. A node falls significantly behind due to downtime or network issues
3. The default polling interval is 100ms [11](#0-10) , creating a window for the race condition
4. Aggressive network-wide pruning occurs during active sync attempts

The vulnerability requires:
- No special attacker privileges (happens during normal operation)
- No malicious actors (natural consequence of distributed pruning)
- Common scenario: node maintenance, network partitions, or new nodes joining

## Recommendation

**Immediate Fix**: Add periodic re-validation of data availability during request retries.

```rust
// In data_stream.rs, add re-validation before retries
fn should_retry_request(&mut self, advertised_data: &AdvertisedData) -> Result<bool, Error> {
    // Re-validate that data is still available before retrying
    if !self.stream_engine.is_remaining_data_available(advertised_data)? {
        return Err(Error::DataIsUnavailable(format!(
            "Data is no longer available in the network. Stream should be terminated."
        )));
    }
    
    // Check if retry limit reached
    if self.request_failure_count > MAX_RETRY_COUNT {
        return Ok(false);
    }
    
    Ok(true)
}
```

**Additional Mitigations**:
1. Implement minimum data retention policies across the network
2. Add alerts when global `lowest_transaction_output_version` increases rapidly
3. Provide snapshot endpoints for nodes that fall too far behind
4. Add stream termination after N consecutive `DataIsUnavailable` errors with recommendation to use snapshots

## Proof of Concept

```rust
// Reproduction steps (pseudo-code for integration test)

#[tokio::test]
async fn test_pruning_race_condition() {
    // Setup: Create 3 nodes with different pruning configs
    let mut node_a = create_node_with_pruning_window(1000);
    let mut node_b = create_node_with_pruning_window(500);
    let mut lagging_node = create_node();
    
    // Node A and B sync to version 2000
    node_a.sync_to_version(2000).await;
    node_b.sync_to_version(2000).await;
    
    // At this point:
    // Node A has: [1000, 2000]
    // Node B has: [1500, 2000]
    
    // Lagging node tries to sync from version 1200
    let global_summary = lagging_node.get_global_summary();
    
    // Verify global summary shows [1000, 2000] and [1500, 2000]
    assert!(global_summary.advertised_data.transaction_outputs
        .iter().any(|r| r.lowest() == 1000));
    
    // Create stream (should succeed)
    let stream_result = lagging_node.create_stream_from_version(1200).await;
    assert!(stream_result.is_ok());
    
    // NOW: Node A prunes further to [1400, 2000]
    node_a.prune_to_version(1400).await;
    
    // Wait for polling to update
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Try to make request for version 1200
    let request_result = lagging_node.request_transaction_outputs(1200, 1300).await;
    
    // BUG: Request fails because NO peer has version 1200 anymore
    assert!(matches!(request_result, Err(Error::DataIsUnavailable(_))));
    
    // BUG: Retries will keep failing indefinitely
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let retry_result = lagging_node.retry_request().await;
        assert!(retry_result.is_err());
    }
    
    // Synchronization is permanently stuck
    assert!(lagging_node.current_version() < 1400);
}
```

## Notes

This vulnerability is particularly insidious because:
1. It only manifests under specific timing conditions in production
2. The global summary provides a false sense of data availability
3. No error clearly indicates the root cause (appears as transient network issues)
4. Affects nodes during critical catch-up operations when network participation is needed most

The fix requires careful consideration of when to terminate vs. retry streams, balancing between resilience to transient failures and recognizing truly unavailable data.

### Citations

**File:** state-sync/data-streaming-service/src/data_stream.rs (L351-378)
```rust
            let response_timeout_ms = self.data_client_config.response_timeout_ms;
            let max_response_timeout_ms = self.data_client_config.max_response_timeout_ms;

            // Exponentially increase the timeout based on the number of
            // previous failures (but bounded by the max timeout).
            let request_timeout_ms = min(
                max_response_timeout_ms,
                response_timeout_ms * (u32::pow(2, self.request_failure_count as u32) as u64),
            );

            // Update the retry counter and log the request
            increment_counter_multiple_labels(
                &metrics::RETRIED_DATA_REQUESTS,
                data_client_request.get_label(),
                &request_timeout_ms.to_string(),
            );
            info!(
                (LogSchema::new(LogEntry::RetryDataRequest)
                    .stream_id(self.data_stream_id)
                    .message(&format!(
                        "Retrying data request type: {:?}, with new timeout: {:?} (ms)",
                        data_client_request.get_label(),
                        request_timeout_ms.to_string()
                    )))
            );

            request_timeout_ms
        };
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L866-877)
```rust
    pub fn ensure_data_is_available(&self, advertised_data: &AdvertisedData) -> Result<(), Error> {
        if !self
            .stream_engine
            .is_remaining_data_available(advertised_data)?
        {
            return Err(Error::DataIsUnavailable(format!(
                "Unable to satisfy stream engine: {:?}, with advertised data: {:?}",
                self.stream_engine, advertised_data
            )));
        }
        Ok(())
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L540-560)
```rust
    fn identify_serviceable(
        &self,
        peers_by_priorities: &BTreeMap<PeerPriority, HashSet<PeerNetworkId>>,
        priority: PeerPriority,
        request: &StorageServiceRequest,
    ) -> HashSet<PeerNetworkId> {
        // Get the peers for the specified priority
        let prospective_peers = peers_by_priorities
            .get(&priority)
            .unwrap_or(&hashset![])
            .clone();

        // Identify and return the serviceable peers
        prospective_peers
            .into_iter()
            .filter(|peer| {
                self.peer_states
                    .can_service_request(peer, self.time_service.clone(), request)
            })
            .collect()
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L698-701)
```rust
        Err(Error::DataIsUnavailable(format!(
            "All {} attempts failed for the given request: {:?}. Errors: {:?}",
            num_sent_requests, request, sent_request_errors
        )))
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L382-386)
```rust
            if let Some(transaction_outputs) = summary.data_summary.transaction_outputs {
                advertised_data
                    .transaction_outputs
                    .push(transaction_outputs);
            }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L1291-1310)
```rust
    fn is_remaining_data_available(&self, advertised_data: &AdvertisedData) -> Result<bool, Error> {
        let advertised_ranges = match &self.request {
            StreamRequest::ContinuouslyStreamTransactions(_) => &advertised_data.transactions,
            StreamRequest::ContinuouslyStreamTransactionOutputs(_) => {
                &advertised_data.transaction_outputs
            },
            StreamRequest::ContinuouslyStreamTransactionsOrOutputs(_) => {
                &advertised_data.transaction_outputs
            },
            request => invalid_stream_request!(request),
        };

        // Verify we can satisfy the next version
        let (next_request_version, _) = self.next_request_version_and_epoch;
        Ok(AdvertisedData::contains_range(
            next_request_version,
            next_request_version,
            advertised_ranges,
        ))
    }
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L287-287)
```rust
        data_stream.ensure_data_is_available(&advertised_data)?;
```

**File:** state-sync/aptos-data-client/src/poller.rs (L437-439)
```rust
        data_summary_poller
            .data_client
            .update_peer_storage_summary(peer, storage_summary);
```

**File:** state-sync/storage-service/types/src/responses.rs (L833-847)
```rust
    fn can_service_transaction_outputs_with_proof(
        &self,
        start_version: u64,
        end_version: u64,
        proof_version: u64,
    ) -> bool {
        let desired_range = match CompleteDataRange::new(start_version, end_version) {
            Ok(desired_range) => desired_range,
            Err(_) => return false,
        };

        let can_service_outputs = self.can_service_transaction_outputs(&desired_range);
        let can_create_proof = self.can_create_proof(proof_version);
        can_service_outputs && can_create_proof
    }
```

**File:** state-sync/aptos-data-client/src/global_summary.rs (L206-208)
```rust
    pub fn lowest_transaction_output_version(&self) -> Option<Version> {
        get_lowest_version_from_range_set(&self.transaction_outputs)
    }
```

**File:** config/src/config/state_sync_config.rs (L355-355)
```rust
            poll_loop_interval_ms: 100,
```
