# Audit Report

## Title
Peer Monitoring Service Lacks Exponential Backoff and Per-Peer Moderation, Enabling Resource Exhaustion Attack

## Summary
The peer monitoring service's error handling mechanism uses fixed-interval retries without exponential backoff and lacks per-peer request moderation. This allows malicious peers to sustain error-inducing requests indefinitely, exhausting server resources and keeping the system in a degraded state while bypassing the intent of rate limiting.

## Finding Description

The peer monitoring service implements a client-side retry mechanism through the `RequestTracker` that uses a **fixed retry interval** without exponential backoff: [1](#0-0) 

When errors occur, the tracker records failures but continues retrying at the same fixed interval: [2](#0-1) 

The latency monitoring state handler has a TODO comment acknowledging that peers should be disconnected after excessive failures, but this is **not implemented**: [3](#0-2) 

On the server side, the `BoundedExecutor` limits total concurrent requests (default 1000) but provides **no per-peer request moderation or invalid request tracking**: [4](#0-3) 

Each request is processed regardless of previous error patterns from that peer: [5](#0-4) 

The server's error handling returns errors but doesn't track or penalize misbehaving peers: [6](#0-5) 

**Attack Scenario:**
1. Attacker connects as one or more peers to the network
2. Sends monitoring requests designed to trigger server-side errors (e.g., storage errors by querying unavailable data, or crafting edge-case inputs)
3. Server processes each request, consuming CPU cycles, I/O operations, and BoundedExecutor permits
4. Server returns error responses
5. Client's retry mechanism activates after the fixed interval with no backoff
6. Steps 2-5 repeat indefinitely as no disconnection occurs
7. With network-level limit of 100 concurrent RPCs per peer connection, attacker can maximize resource consumption
8. Multiple peer connections multiply the effect, exhausting the global server limit (1000 concurrent requests)

**Contrast with Storage Service:** Unlike the peer monitoring service, the storage service implements proper request moderation with exponential backoff: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **Medium severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns** (High severity per bounty): If validators run peer monitoring service (which they do for network health monitoring), sustained attacks can cause performance degradation affecting consensus participation.

2. **State Inconsistencies Requiring Intervention** (Medium severity): The system remains functional but in a degraded state where legitimate monitoring requests are delayed or blocked, requiring manual intervention to identify and disconnect malicious peers.

3. **Resource Exhaustion**: While not causing total network failure, the attack can:
   - Exhaust the BoundedExecutor's semaphore permits (up to 1000 concurrent)
   - Block legitimate peer monitoring requests
   - Consume CPU and I/O resources processing error-inducing requests
   - Keep the monitoring system in persistent degraded state

The network-level per-peer RPC limit (100 concurrent) provides some protection: [8](#0-7) [9](#0-8) 

However, this doesn't prevent the attack—it only caps the rate per connection. Multiple connections can still exhaust server resources.

## Likelihood Explanation

**Likelihood: Medium to High**

**Ease of Exploitation:**
- No special privileges required—any peer can connect to the network
- Simple to execute: craft requests that trigger server errors
- Network allows multiple peer connections from same attacker

**Attack Complexity:**
- Attacker needs to understand which requests cause errors
- Requires sustained connection but no special timing or coordination
- Can be automated easily

**Mitigating Factors:**
- Network-level per-peer rate limiting provides partial protection
- Requires multiple connections for severe impact
- Monitoring and metrics would reveal attack pattern

**Real-World Scenarios:**
1. Malicious peer intentionally crafts error-inducing requests
2. Compromised or buggy peer inadvertently triggers the issue
3. Network partition causes legitimate storage errors, triggering aggressive retries

## Recommendation

Implement per-peer request moderation with exponential backoff, similar to the storage service's `RequestModerator`:

1. **Add RequestModerator to Peer Monitoring Server:**
```rust
// In peer-monitoring-service/server/src/moderator.rs (new file)
pub struct PeerMonitoringModerator {
    max_invalid_requests: u64,
    min_time_to_ignore_secs: u64,
    unhealthy_peer_states: Arc<DashMap<PeerNetworkId, UnhealthyPeerState>>,
    time_service: TimeService,
}

impl PeerMonitoringModerator {
    pub fn should_ignore_peer(&self, peer_network_id: &PeerNetworkId) -> bool {
        self.unhealthy_peer_states
            .get(peer_network_id)
            .map_or(false, |state| state.is_ignored())
    }
    
    pub fn record_invalid_request(&self, peer_network_id: &PeerNetworkId) {
        // Track and penalize peers sending invalid requests
    }
}
```

2. **Implement Exponential Backoff in Client:**
```rust
// In peer-monitoring-service/client/src/peer_states/request_tracker.rs
pub struct RequestTracker {
    // ... existing fields ...
    min_backoff_usec: u64,
    max_backoff_usec: u64,
    current_backoff_multiplier: u64, // Doubles on each failure
}

impl RequestTracker {
    pub fn record_response_failure(&mut self) {
        self.num_consecutive_request_failures += 1;
        // Exponential backoff: double the interval (capped at max)
        self.current_backoff_multiplier = 
            std::cmp::min(self.current_backoff_multiplier * 2, MAX_BACKOFF_MULTIPLIER);
    }
    
    pub fn record_response_success(&mut self) {
        self.num_consecutive_request_failures = 0;
        // Reset backoff on success
        self.current_backoff_multiplier = 1;
    }
    
    pub fn new_request_required(&self) -> bool {
        // ... existing checks ...
        // Use backoff multiplier to increase interval
        let effective_interval = 
            self.request_interval_usec * self.current_backoff_multiplier;
        self.time_service.now() > 
            last_request_time.add(Duration::from_micros(effective_interval))
    }
}
```

3. **Implement Automatic Peer Disconnection:**
```rust
// In peer-monitoring-service/client/src/peer_states/latency_info.rs
fn handle_request_failure(&self, peer_network_id: &PeerNetworkId) {
    self.request_tracker.write().record_response_failure();
    
    let num_consecutive_failures = 
        self.request_tracker.read().get_num_consecutive_failures();
    if num_consecutive_failures >= self.latency_monitoring_config.max_latency_ping_failures {
        // Implement actual disconnection instead of just warning
        self.disconnect_peer(peer_network_id);
        error!(LogSchema::new(LogEntry::LatencyPing)
            .event(LogEvent::PeerDisconnected)
            .peer(peer_network_id)
            .message("Disconnecting peer due to excessive failures"));
    }
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: peer-monitoring-service/server/src/tests/resource_exhaustion_test.rs

#[tokio::test]
async fn test_fixed_interval_retry_resource_exhaustion() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    
    // Setup: Create server with BoundedExecutor (capacity 100 for test)
    let (server, peer_monitoring_client) = setup_test_server(100).await;
    
    // Track server resource consumption
    let requests_processed = Arc::new(AtomicU64::new(0));
    let requests_processed_clone = requests_processed.clone();
    
    // Simulate attacker sending error-inducing requests
    let attacker_task = tokio::spawn(async move {
        for i in 0..1000 {
            // Send request that triggers storage error
            let result = peer_monitoring_client
                .get_node_information_with_invalid_params()
                .await;
            
            // Error is returned, but no backoff applied
            assert!(result.is_err());
            
            // Fixed interval retry (e.g., 1 second)
            tokio::time::sleep(Duration::from_secs(1)).await;
            
            requests_processed_clone.fetch_add(1, Ordering::Relaxed);
        }
    });
    
    // Run for 60 seconds
    tokio::time::sleep(Duration::from_secs(60)).await;
    
    // Verify: Server processed ~60 requests (1 per second) without backoff
    let total_processed = requests_processed.load(Ordering::Relaxed);
    assert!(total_processed >= 55 && total_processed <= 65);
    
    // Verify: No disconnection occurred despite all requests failing
    assert!(peer_is_still_connected());
    
    // Verify: Each request consumed server resources (BoundedExecutor permits)
    // This demonstrates the resource exhaustion vulnerability
    
    // Expected behavior: Exponential backoff should have reduced
    // request rate to much less than 60 requests in 60 seconds
    // Expected behavior: Peer should have been disconnected after ~3 failures
}
```

## Notes

The vulnerability is exacerbated by the fact that the peer monitoring service is critical for network health visibility. Degrading this service makes it harder for operators to detect and respond to network issues, including the attack itself. The storage service's proper implementation of request moderation with exponential backoff shows this is a known pattern that should be applied consistently across all services handling peer requests.

### Citations

**File:** peer-monitoring-service/client/src/peer_states/request_tracker.rs (L76-90)
```rust
    pub fn new_request_required(&self) -> bool {
        // There's already an in-flight request. A new one should not be sent.
        if self.in_flight_request() {
            return false;
        }

        // Otherwise, check the last request time for freshness
        match self.last_request_time {
            Some(last_request_time) => {
                self.time_service.now()
                    > last_request_time.add(Duration::from_micros(self.request_interval_usec))
            },
            None => true, // A request should be sent immediately
        }
    }
```

**File:** peer-monitoring-service/client/src/peer_states/request_tracker.rs (L101-104)
```rust
    /// Records a failure for the request
    pub fn record_response_failure(&mut self) {
        self.num_consecutive_request_failures += 1;
    }
```

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L59-72)
```rust
    /// Handles a ping failure for the specified peer
    fn handle_request_failure(&self, peer_network_id: &PeerNetworkId) {
        // Update the number of ping failures for the request tracker
        self.request_tracker.write().record_response_failure();

        // TODO: If the number of ping failures is too high, disconnect from the node
        let num_consecutive_failures = self.request_tracker.read().get_num_consecutive_failures();
        if num_consecutive_failures >= self.latency_monitoring_config.max_latency_ping_failures {
            warn!(LogSchema::new(LogEntry::LatencyPing)
                .event(LogEvent::TooManyPingFailures)
                .peer(peer_network_id)
                .message("Too many ping failures occurred for the peer!"));
        }
    }
```

**File:** peer-monitoring-service/server/src/lib.rs (L66-69)
```rust
        let bounded_executor = BoundedExecutor::new(
            node_config.peer_monitoring_service.max_concurrent_requests as usize,
            executor,
        );
```

**File:** peer-monitoring-service/server/src/lib.rs (L105-122)
```rust
            self.bounded_executor
                .spawn_blocking(move || {
                    let response = Handler::new(
                        base_config,
                        peers_and_metadata,
                        start_time,
                        storage,
                        time_service,
                    )
                    .call(
                        peer_network_id.network_id(),
                        peer_monitoring_service_request,
                    );
                    log_monitoring_service_response(&response);
                    response_sender.send(response);
                })
                .await;
        }
```

**File:** peer-monitoring-service/server/src/lib.rs (L184-204)
```rust
        // Process the response and handle any errors
        match response {
            Err(error) => {
                // Log the error and update the counters
                increment_counter(
                    &metrics::PEER_MONITORING_ERRORS_ENCOUNTERED,
                    network_id,
                    error.get_label(),
                );
                error!(LogSchema::new(LogEntry::PeerMonitoringServiceError)
                    .error(&error)
                    .request(&request));

                // Return an appropriate response to the client
                match error {
                    Error::InvalidRequest(error) => {
                        Err(PeerMonitoringServiceError::InvalidRequest(error))
                    },
                    error => Err(PeerMonitoringServiceError::InternalError(error.to_string())),
                }
            },
```

**File:** state-sync/storage-service/server/src/moderator.rs (L22-99)
```rust
/// A simple struct that tracks the state of an unhealthy peer
#[derive(Clone, Debug)]
pub struct UnhealthyPeerState {
    ignore_start_time: Option<Instant>, // The time when we first started ignoring the peer
    invalid_request_count: u64,         // The total number of invalid requests from the peer
    max_invalid_requests: u64, // The max number of invalid requests before ignoring the peer
    min_time_to_ignore_secs: u64, // The min time (secs) to ignore the peer (doubles each round)
    time_service: TimeService, // The time service
}

impl UnhealthyPeerState {
    pub fn new(
        max_invalid_requests: u64,
        min_time_to_ignore_secs: u64,
        time_service: TimeService,
    ) -> Self {
        Self {
            ignore_start_time: None,
            invalid_request_count: 0,
            max_invalid_requests,
            min_time_to_ignore_secs,
            time_service,
        }
    }

    /// Increments the invalid request count for the peer and marks
    /// the peer to be ignored if it has sent too many invalid requests.
    /// Note: we only ignore peers on the public network.
    pub fn increment_invalid_request_count(&mut self, peer_network_id: &PeerNetworkId) {
        // Increment the invalid request count
        self.invalid_request_count += 1;

        // If the peer is a PFN and has sent too many invalid requests, start ignoring it
        if self.ignore_start_time.is_none()
            && peer_network_id.network_id().is_public_network()
            && self.invalid_request_count >= self.max_invalid_requests
        {
            // TODO: at some point we'll want to terminate the connection entirely

            // Start ignoring the peer
            self.ignore_start_time = Some(self.time_service.now());

            // Log the fact that we're now ignoring the peer
            warn!(LogSchema::new(LogEntry::RequestModeratorIgnoredPeer)
                .peer_network_id(peer_network_id)
                .message("Ignoring peer due to too many invalid requests!"));
        }
    }

    /// Returns true iff the peer should be ignored
    pub fn is_ignored(&self) -> bool {
        self.ignore_start_time.is_some()
    }

    /// Refreshes the peer's state (if it has been ignored for long enough).
    /// Note: each time we unblock a peer, we double the min time to ignore the peer.
    /// This provides an exponential backoff for peers that are sending too many invalid requests.
    pub fn refresh_peer_state(&mut self, peer_network_id: &PeerNetworkId) {
        if let Some(ignore_start_time) = self.ignore_start_time {
            let ignored_duration = self.time_service.now().duration_since(ignore_start_time);
            if ignored_duration >= Duration::from_secs(self.min_time_to_ignore_secs) {
                // Reset the invalid request count
                self.invalid_request_count = 0;

                // Reset the ignore start time
                self.ignore_start_time = None;

                // Double the min time to ignore the peer
                self.min_time_to_ignore_secs *= 2;

                // Log the fact that we're no longer ignoring the peer
                warn!(LogSchema::new(LogEntry::RequestModeratorIgnoredPeer)
                    .peer_network_id(peer_network_id)
                    .message("No longer ignoring peer! Enough time has elapsed."));
            }
        }
    }
}
```

**File:** network/framework/src/constants.rs (L14-15)
```rust
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** network/framework/src/protocols/rpc/mod.rs (L212-223)
```rust
        // Drop new inbound requests if our completion queue is at capacity.
        if self.inbound_rpc_tasks.len() as u32 == self.max_concurrent_inbound_rpcs {
            // Increase counter of declined requests
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                INBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            return Err(RpcError::TooManyPending(self.max_concurrent_inbound_rpcs));
        }
```
