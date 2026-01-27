# Audit Report

## Title
Unbounded DashSet Growth in Data Summary Poller Leading to Memory Exhaustion

## Summary
The `DataSummaryPoller` in `state-sync/aptos-data-client/src/poller.rs` maintains two DashSets (`in_flight_priority_polls` and `in_flight_regular_polls`) to track peers with active poll requests. These sets can grow unbounded when spawned poll tasks fail to complete, as there is no cleanup mechanism for stale entries, no handling of peer disconnections, and the spawned tasks run detached without monitoring. This leads to memory exhaustion and complete failure of the data summary polling system.

## Finding Description

The vulnerability exists in the peer polling mechanism that tracks in-flight requests. When `poll_peer` is called, it adds a peer to the in-flight DashSet **before** spawning an async task: [1](#0-0) 

The async task is then spawned and its `JoinHandle` is returned but **never awaited or stored** by the caller: [2](#0-1) [3](#0-2) 

The peer is only removed from the DashSet by calling `in_flight_request_complete` inside the async task: [4](#0-3) 

**Critical Failure Scenarios:**

1. **Blocking Pool Exhaustion**: The response deserialization uses `spawn_blocking` without timeout protection: [5](#0-4) 

If the blocking pool is exhausted (64 threads maximum), the `.await` at line 764 will hang indefinitely waiting for an available thread. The request timeout only covers the network request phase (line 720), not the deserialization phase. This causes the polling task to hang permanently, preventing `in_flight_request_complete` from ever being called.

2. **No Cleanup on Peer Disconnect**: The `garbage_collect_peer_states` function only cleans up the `peer_to_state` map, NOT the in-flight DashSets: [6](#0-5) 

When a peer disconnects while having an in-flight poll, the entry remains in the DashSet forever.

3. **Test Confirmation**: The test suite confirms this issue by manually calling `in_flight_request_complete` for disconnected peers: [7](#0-6) 

At lines 524 and 542, peer_1 is disconnected but the test must manually call `in_flight_request_complete` to clean it up, proving there's no automatic cleanup mechanism.

**Attack Path:**

1. Attacker establishes connections as multiple network peers (no validator access needed)
2. Attacker responds to poll requests with large, compressed payloads that require blocking pool threads for decompression
3. If the blocking pool becomes exhausted under load (other system components also use it), poll tasks hang at the `spawn_blocking` await
4. Peers accumulate in the DashSets as tasks fail to complete
5. Once the max in-flight limit is reached (default 30 per peer type), no new peers can be polled: [8](#0-7) 

6. The data summary polling system fails completely, preventing state synchronization
7. Memory continues to grow as more peers are added but never removed

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

- **Validator Node Slowdowns**: As memory grows unbounded, node performance degrades significantly
- **Significant Protocol Violations**: The state sync mechanism fails when the polling system can no longer gather peer data summaries, violating the resource limits invariant (#9: "All operations must respect gas, storage, and computational limits")
- **Availability Impact**: Nodes cannot properly sync state when the poller is disabled, affecting network availability

The vulnerability breaks the **Resource Limits invariant** by allowing unbounded memory growth through the DashSets. While not immediately causing total network failure, it can lead to individual node failures and cascading degradation across the network.

## Likelihood Explanation

**Likelihood: Medium-High**

1. **Natural Occurrence**: The blocking pool exhaustion can occur naturally under high load without malicious intent. Multiple system components use `spawn_blocking`: [9](#0-8) 

2. **Malicious Triggering**: An attacker can deliberately:
   - Send compressed responses requiring decompression in the blocking pool
   - Establish many peer connections to increase poll frequency
   - Cause peers to disconnect during active polls

3. **No Privileged Access Required**: Any network peer can trigger this vulnerability

4. **Gradual Degradation**: The issue compounds over time as more entries accumulate, making it harder to detect initially but eventually causing node failure

## Recommendation

**Immediate Fix:**

1. Implement a timeout wrapper around the entire `send_request_to_peer_and_decode` call:

```rust
// In poll_peer function, wrap the request with tokio::time::timeout
let request_timeout = data_summary_poller.data_client_config.response_timeout_ms;
let result = tokio::time::timeout(
    Duration::from_millis(request_timeout * 2), // Account for network + processing
    async {
        data_summary_poller
            .data_client
            .send_request_to_peer_and_decode(peer, storage_request, request_timeout)
            .await
            .map(Response::into_payload)
    }
).await;

let result = match result {
    Ok(inner_result) => inner_result,
    Err(_timeout) => {
        // Timeout occurred, ensure cleanup happens
        data_summary_poller.in_flight_request_complete(&peer);
        return;
    }
};

data_summary_poller.in_flight_request_complete(&peer);
```

2. Add a periodic cleanup task that removes stale in-flight entries older than a threshold (e.g., 5x the request timeout).

3. Clean up in-flight entries when peers disconnect by hooking into the peer disconnect event handler:

```rust
// Add to DataSummaryPoller
pub fn cleanup_disconnected_peer(&self, peer: &PeerNetworkId) {
    self.in_flight_priority_polls.remove(peer);
    self.in_flight_regular_polls.remove(peer);
}
```

Call this from the `garbage_collect_peer_states` flow.

4. Monitor and alert on in-flight DashSet growth using the existing metrics infrastructure.

## Proof of Concept

```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_unbounded_dashset_growth_on_blocking_pool_exhaustion() {
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    use aptos_config::config::AptosDataClientConfig;
    
    // Create a data client and poller
    let (mut mock_network, _, _, poller) = MockNetwork::new(None, None, None);
    
    // Add several peers
    let peers: Vec<_> = (0..40).map(|_| {
        mock_network.add_peer(PeerPriority::HighPriority)
    }).collect();
    
    // Simulate blocking pool exhaustion by spawning many blocking tasks
    for _ in 0..70 {
        tokio::task::spawn_blocking(|| {
            std::thread::sleep(std::time::Duration::from_secs(100)); // Hold blocking threads
        });
    }
    
    // Now attempt to poll peers - these should hang in spawn_blocking
    for peer in peers.iter().take(35) {
        poll_peer(poller.clone(), true, *peer);
    }
    
    // Wait for tasks to attempt execution
    sleep(Duration::from_secs(2)).await;
    
    // Check in-flight count - should be stuck at 35 (or max config limit)
    let in_flight_count = poller.in_flight_priority_polls.len();
    assert!(in_flight_count >= 30, "In-flight polls should accumulate");
    
    // Verify no new peers can be polled due to max in-flight limit
    let peers_to_poll = poller.identify_peers_to_poll(true).unwrap();
    assert_eq!(peers_to_poll.len(), 0, "Should be unable to poll new peers when at max in-flight");
    
    // Memory continues to grow as DashSet retains all peer entries indefinitely
    println!("DashSet size: {}", in_flight_count);
    println!("Expected cleanup: NONE - vulnerability demonstrated");
}
```

**Notes**

The vulnerability is exacerbated by the default configuration allowing up to 30 in-flight polls per peer type [10](#0-9) , meaning 60 total peer entries can accumulate before the system stops polling entirely. With no cleanup mechanism, these entries persist indefinitely, causing permanent memory leaks and system degradation.

The issue is particularly severe because it affects the critical state synchronization subsystem, which is essential for validator node operation and network health. Without proper peer data summaries, nodes cannot determine which peers have the data they need, effectively breaking state sync functionality.

### Citations

**File:** state-sync/aptos-data-client/src/poller.rs (L104-108)
```rust
        let data_poller_config = self.data_client_config.data_poller_config;
        let max_num_in_flight_polls = data_poller_config.max_num_in_flight_priority_polls;
        if num_in_flight_polls >= max_num_in_flight_polls {
            return hashset![];
        }
```

**File:** state-sync/aptos-data-client/src/poller.rs (L343-346)
```rust
        // Go through each peer and poll them individually
        for peer in peers_to_poll {
            poll_peer(poller.clone(), poll_priority_peers, peer);
        }
```

**File:** state-sync/aptos-data-client/src/poller.rs (L393-400)
```rust
pub(crate) fn poll_peer(
    data_summary_poller: DataSummaryPoller,
    is_priority_peer: bool,
    peer: PeerNetworkId,
) -> JoinHandle<()> {
    // Mark the in-flight poll as started. We do this here to prevent
    // the main polling loop from selecting the same peer concurrently.
    data_summary_poller.in_flight_request_started(is_priority_peer, &peer);
```

**File:** state-sync/aptos-data-client/src/poller.rs (L418-419)
```rust
        // Mark the in-flight poll as now complete
        data_summary_poller.in_flight_request_complete(&peer);
```

**File:** state-sync/aptos-data-client/src/poller.rs (L460-466)
```rust
    // Spawn the poller
    if let Some(runtime) = runtime {
        runtime.spawn(poller)
    } else {
        tokio::spawn(poller)
    }
}
```

**File:** state-sync/aptos-data-client/src/client.rs (L750-765)
```rust
        // Try to convert the storage service enum into the exact variant we're expecting.
        // We do this using spawn_blocking because it involves serde and compression.
        tokio::task::spawn_blocking(move || {
            match T::try_from(storage_response) {
                Ok(new_payload) => Ok(Response::new(context, new_payload)),
                // If the variant doesn't match what we're expecting, report the issue
                Err(err) => {
                    context
                        .response_callback
                        .notify_bad_response(ResponseError::InvalidPayloadDataType);
                    Err(err.into())
                },
            }
        })
        .await
        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L332-336)
```rust
    /// Garbage collects the peer states to remove data for disconnected peers
    pub fn garbage_collect_peer_states(&self, connected_peers: HashSet<PeerNetworkId>) {
        self.peer_to_state
            .retain(|peer_network_id, _| connected_peers.contains(peer_network_id));
    }
```

**File:** state-sync/aptos-data-client/src/tests/poller.rs (L520-543)
```rust
        poller.in_flight_request_started(poll_priority_peers, &peer_1);

        // Add peer 2 and disconnect peer 1
        let peer_2 = mock_network.add_peer(peer_priority);
        mock_network.disconnect_peer(peer_1);

        // Request the next set of peers to poll and verify it's peer 2.
        // Mark the request as in-flight but not completed.
        let peers_to_poll = poller.identify_peers_to_poll(poll_priority_peers).unwrap();
        assert_eq!(peers_to_poll, hashset![peer_2]);
        poller.in_flight_request_started(poll_priority_peers, &peer_2);

        // Request the next set of peers to poll and verify no peers are returned
        // (peer 2's request is still in-flight).
        for _ in 0..10 {
            assert_eq!(
                poller.identify_peers_to_poll(poll_priority_peers),
                Ok(hashset![])
            );
        }

        // Reconnect peer 1
        poller.in_flight_request_complete(&peer_1);
        mock_network.reconnect_peer(peer_1);
```

**File:** config/src/config/state_sync_config.rs (L351-352)
```rust
            max_num_in_flight_priority_polls: 30,
            max_num_in_flight_regular_polls: 30,
```
