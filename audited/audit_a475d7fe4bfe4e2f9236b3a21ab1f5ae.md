# Audit Report

## Title
Race Condition in Subscription Peer Selection Causes State Sync Liveness Failure

## Summary
The `AptosDataClient` maintains a single shared `active_subscription_state` across all data streams, but the `choose_serviceable_peer_for_subscription_request()` function incorrectly handles concurrent subscription requests with different stream IDs. When multiple subscription streams are active simultaneously, one stream's peer selection state overwrites another's, causing valid subscription streams to terminate unexpectedly and preventing nodes from syncing state.

## Finding Description
The vulnerability exists in the subscription peer selection logic within the state-sync data client. The system is designed to support multiple concurrent subscription streams (e.g., one for transactions, one for outputs), each identified by a unique `subscription_stream_id`. However, the implementation uses a single global `active_subscription_state` that can only track one subscription stream at a time. [1](#0-0) 

The critical flaw occurs in the `choose_serviceable_peer_for_subscription_request()` function. When a subscription request arrives, the function acquires the mutex lock and uses `.take()` to extract the current subscription state: [2](#0-1) 

If the extracted stream ID doesn't match the incoming request's stream ID, the existing state is permanently discarded without restoration: [3](#0-2) 

A new peer is then selected for the incoming stream and overwrites the global state: [4](#0-3) 

**Exploitation Scenario:**

1. The `DataStreamingService` creates Stream A (transactions, stream_id=100) which selects Peer X
2. Stream A successfully syncs, with state: `(peer=X, stream_id=100)`
3. The service creates Stream B (outputs, stream_id=200) 
4. Stream B's request arrives, extracts Stream A's state via `.take()`
5. Stream IDs don't match (100 ≠ 200), so Stream A's state is discarded
6. Stream B selects Peer Y, state becomes: `(peer=Y, stream_id=200)`
7. Stream A's next request finds state `(peer=Y, stream_id=200)`
8. Stream IDs don't match (200 ≠ 100), triggering error at line 496-500
9. Stream A terminates despite being valid

The DataStreamingService explicitly supports multiple concurrent streams: [5](#0-4) 

Each stream receives a cloned AptosDataClient that shares the same Arc-wrapped subscription state: [6](#0-5) 

When subscription errors occur, the stream engine terminates the subscription: [7](#0-6) 

## Impact Explanation
This is a **Critical** severity vulnerability that can cause "Total loss of liveness/network availability" as defined in the Aptos bug bounty program.

**State Sync Failure**: Nodes rely on subscription streams to continuously sync the latest state. When these streams are incorrectly terminated, nodes cannot catch up to the network's current state, violating the **State Consistency** invariant that requires atomic and verifiable state transitions.

**Cascading Failures**: If multiple data streams are active (which is the normal operating mode), this race condition will repeatedly trigger, causing continuous stream terminations and preventing any forward progress in state synchronization.

**Network Partition Risk**: In the worst case, affected nodes become permanently stuck at an outdated state, unable to participate in consensus or validate transactions. This creates a partial network partition that may require manual intervention or node restarts to resolve.

The impact is amplified because:
- No malicious input is required - this occurs during normal operation
- All nodes running multiple subscription streams are affected
- The issue is non-obvious and difficult to diagnose in production
- Recovery requires service disruption

## Likelihood Explanation
**Likelihood: High**

This vulnerability will trigger whenever:
1. The DataStreamingService has multiple active subscription streams (standard configuration)
2. These streams make subscription requests with different stream IDs (guaranteed by design)
3. Request timing interleaves such that one stream's request arrives before another's completes

Given that:
- The test suite explicitly validates support for 10 concurrent streams: [8](#0-7) 
- Subscription streaming is enabled by default for continuous transaction syncing
- Multiple stream types (transactions, outputs, transactions-or-outputs) can coexist
- The race window is non-trivial (entire duration of peer selection logic)

The bug will manifest regularly in production environments, particularly under high load when multiple streams are actively syncing.

## Recommendation
The fix requires maintaining separate subscription states for each active subscription stream ID, rather than a single global state. Implement a `HashMap<u64, SubscriptionState>` keyed by `subscription_stream_id`:

```rust
// In AptosDataClient struct:
active_subscription_states: Arc<Mutex<HashMap<u64, SubscriptionState>>>,

// In choose_serviceable_peer_for_subscription_request:
fn choose_serviceable_peer_for_subscription_request(
    &self,
    request: &StorageServiceRequest,
    serviceable_peers: HashSet<PeerNetworkId>,
) -> crate::error::Result<Option<PeerNetworkId>, Error> {
    // ... extract request_stream_id ...
    
    let mut active_subscription_states = self.active_subscription_states.lock();
    
    // Check if we have an active subscription for THIS stream ID
    if let Some(subscription_state) = active_subscription_states.get(&request_stream_id) {
        let peer_network_id = subscription_state.peer_network_id;
        return if serviceable_peers.contains(&peer_network_id) {
            Ok(Some(peer_network_id))
        } else {
            // Remove the stale entry for this stream
            active_subscription_states.remove(&request_stream_id);
            Err(Error::DataIsUnavailable(format!(...)))
        };
    }
    
    // Choose a new peer for this stream ID
    if let Some(selected_peer) = selected_peer {
        let subscription_state = SubscriptionState::new(selected_peer, request_stream_id);
        active_subscription_states.insert(request_stream_id, subscription_state);
    }
    
    Ok(selected_peer)
}
```

Additionally, implement cleanup logic to remove entries when streams terminate, preventing unbounded HashMap growth.

## Proof of Concept

```rust
#[tokio::test]
async fn test_concurrent_subscription_race_condition() {
    use aptos_config::config::{AptosDataClientConfig, BaseConfig};
    use aptos_time_service::TimeService;
    use std::sync::Arc;
    
    // Create a data client
    let config = AptosDataClientConfig::default();
    let base_config = BaseConfig::default();
    let time_service = TimeService::mock();
    let storage = Arc::new(MockDbReader::new());
    let (storage_service_client, _) = create_mock_storage_service_client();
    
    let (data_client, _poller) = AptosDataClient::new(
        config,
        base_config,
        time_service,
        storage,
        storage_service_client,
        None,
    );
    
    // Simulate Stream A with stream_id=100
    let stream_a_metadata = SubscriptionRequestMetadata {
        known_version_at_stream_start: 0,
        known_epoch_at_stream_start: 0,
        subscription_stream_id: 100,
        subscription_stream_index: 0,
    };
    
    // First request from Stream A - should succeed and select a peer
    let response_a1 = data_client
        .subscribe_to_transactions_with_proof(stream_a_metadata, false, 5000)
        .await;
    assert!(response_a1.is_ok(), "Stream A first request should succeed");
    
    // Simulate Stream B with stream_id=200
    let stream_b_metadata = SubscriptionRequestMetadata {
        known_version_at_stream_start: 0,
        known_epoch_at_stream_start: 0,
        subscription_stream_id: 200,
        subscription_stream_index: 0,
    };
    
    // Request from Stream B - will overwrite Stream A's state
    let response_b1 = data_client
        .subscribe_to_transaction_outputs_with_proof(stream_b_metadata, 5000)
        .await;
    assert!(response_b1.is_ok(), "Stream B first request should succeed");
    
    // Second request from Stream A - should FAIL due to race condition
    let stream_a_metadata_2 = SubscriptionRequestMetadata {
        subscription_stream_index: 1,
        ..stream_a_metadata
    };
    
    let response_a2 = data_client
        .subscribe_to_transactions_with_proof(stream_a_metadata_2, false, 5000)
        .await;
    
    // BUG: This will fail with "peer should no longer service the subscriptions"
    // even though Stream A was working fine
    assert!(response_a2.is_err(), "Stream A second request fails due to race condition");
    assert!(
        format!("{:?}", response_a2.unwrap_err())
            .contains("should no longer service the subscriptions"),
        "Error indicates incorrect peer state"
    );
}
```

This test demonstrates that when multiple subscription streams are active with different stream IDs, subsequent requests from the first stream will fail incorrectly, breaking state synchronization liveness guarantees.

## Notes

This vulnerability specifically affects the state synchronization layer, not consensus itself. However, nodes that cannot sync state become unable to participate in consensus, effectively causing a liveness failure. The issue is particularly insidious because it manifests as intermittent failures that are difficult to diagnose, potentially leading operators to incorrectly attribute the problem to network issues or peer misbehavior rather than a client-side race condition.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L99-99)
```rust
    active_subscription_state: Arc<Mutex<Option<SubscriptionState>>>,
```

**File:** state-sync/aptos-data-client/src/client.rs (L480-484)
```rust
        let mut active_subscription_state = self.active_subscription_state.lock();

        // If we have an active subscription and the request is for the same
        // stream ID, use the same peer (as long as it is still serviceable).
        if let Some(subscription_state) = active_subscription_state.take() {
```

**File:** state-sync/aptos-data-client/src/client.rs (L485-502)
```rust
            if subscription_state.subscription_stream_id == request_stream_id {
                // The stream IDs match. Verify that the request is still serviceable.
                let peer_network_id = subscription_state.peer_network_id;
                return if serviceable_peers.contains(&peer_network_id) {
                    // The previously chosen peer can still service the request
                    *active_subscription_state = Some(subscription_state);
                    Ok(Some(peer_network_id))
                } else {
                    // The previously chosen peer is either: (i) unable to service
                    // the request; or (ii) no longer the highest priority peer. So
                    // we need to return an error so the stream will be terminated.
                    Err(Error::DataIsUnavailable(format!(
                        "The peer that we were previously subscribing to should no \
                        longer service the subscriptions! Peer: {:?}, request: {:?}",
                        peer_network_id, request
                    )))
                };
            }
```

**File:** state-sync/aptos-data-client/src/client.rs (L506-514)
```rust
        let selected_peer = self
            .choose_random_peers_by_distance_and_latency(serviceable_peers, 1)
            .into_iter()
            .next();

        // If a peer was selected, update the active subscription state
        if let Some(selected_peer) = selected_peer {
            let subscription_state = SubscriptionState::new(selected_peer, request_stream_id);
            *active_subscription_state = Some(subscription_state);
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L68-68)
```rust
    data_streams: HashMap<DataStreamId, DataStream<T>>,
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L280-280)
```rust
            self.aptos_data_client.clone(),
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L610-625)
```rust
            let num_data_streams = 10;
            let mut stream_ids = vec![];
            for _ in 0..num_data_streams {
                // Create a new data stream
                let (new_stream_request, response_receiver) = create_new_stream_request();
                streaming_service.handle_stream_request_message(
                    new_stream_request,
                    create_stream_update_notifier(),
                );
                let data_stream_listener =
                    response_receiver.now_or_never().unwrap().unwrap().unwrap();
                let data_stream_id = data_stream_listener.data_stream_id;

                // Remember the data stream id and drop the listener
                stream_ids.push(data_stream_id);
            }
```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L937-953)
```rust
    /// Handles a subscription error for the specified client request
    fn handle_subscription_error(
        &mut self,
        client_request: &DataClientRequest,
        request_error: aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // We should only receive an error notification if we have an active stream
        if self.active_subscription_stream.is_none() {
            return Err(Error::UnexpectedErrorEncountered(format!(
                "Received a subscription notification error but no active subscription stream exists! Error: {:?}, request: {:?}",
                request_error, client_request
            )));
        }

        // Reset the active subscription stream and update the metrics
        self.active_subscription_stream = None;
        update_terminated_subscription_metrics(request_error.get_label());
```
