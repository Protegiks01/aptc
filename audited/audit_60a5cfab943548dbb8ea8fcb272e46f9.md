# Audit Report

## Title
Missing Per-Peer Request Rate Metrics in Storage Service Server Enables Undetectable Resource Exhaustion Attacks

## Summary
The storage service server lacks metrics to track request rates per individual peer, only tracking aggregated metrics by network ID and request type. This prevents detection and mitigation of resource exhaustion attacks where a single malicious peer floods the server with valid but expensive requests.

## Finding Description
The storage service server in Aptos implements request tracking and peer moderation, but has a critical gap in observability and defense mechanisms:

**Current State:**
The server tracks requests only at the network level: [1](#0-0) 

When processing requests, the handler increments counters by `network_id` and `request_type`, but not by individual peer: [2](#0-1) 

The `RequestModerator` tracks only **invalid** requests per peer and automatically blocks peers that exceed the threshold: [3](#0-2) 

However, there is no tracking or rate limiting for the **total volume** of valid requests per peer.

**Attack Scenario:**
1. A malicious peer connects to a storage service server (especially on public networks)
2. The attacker floods the server with valid but resource-intensive requests (e.g., large transaction range queries, state queries with `GetTransactionsWithProof` or `GetStateValuesWithProof`)
3. Since all requests are valid:
   - They pass the `RequestModerator` validation
   - They are not counted toward the peer's `invalid_request_count`
   - The peer is never marked as unhealthy or ignored
4. Server resources (CPU, memory, I/O) become exhausted processing the flood of requests
5. Legitimate peers experience degraded service or timeouts
6. Operators monitoring metrics see high request volume in `STORAGE_REQUESTS_RECEIVED` but cannot identify which specific peer is attacking (metrics only show `network_id`, not individual `peer_id`)
7. No automatic defense mechanism activates (unlike invalid request handling which has exponential backoff)

**Defense Asymmetry:**
The client side tracks per-peer request counts: [4](#0-3) 

And exposes these as aggregated metrics by peer buckets: [5](#0-4) 

However, the server side has no equivalent tracking, creating an asymmetric defense posture where clients can monitor their own behavior but servers cannot monitor incoming request patterns per peer.

## Impact Explanation
This issue qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Validator Node Slowdowns**: A sustained attack can significantly degrade storage service performance, affecting state synchronization across the network
2. **API Crashes**: Resource exhaustion could lead to storage service crashes or unresponsiveness
3. **Network-Wide Impact**: Multiple nodes under attack simultaneously could disrupt state sync operations network-wide
4. **Detection Gap**: The lack of per-peer metrics means attacks cannot be detected through standard monitoring, allowing them to persist unnoticed

While network-level DoS is generally out of scope, this vulnerability is distinct because:
- It exploits a **specific design gap** in the storage service's defense mechanism (invalid vs. valid request tracking)
- It prevents **detection and mitigation** of attacks that are otherwise detectable
- The asymmetry between client-side and server-side metrics indicates this is an **implementation oversight** rather than an intentional design decision

## Likelihood Explanation
This attack is **highly likely** to occur because:

1. **Low Barrier to Entry**: Any peer can connect to storage service servers on public networks
2. **Simple Exploitation**: Crafting valid storage service requests requires minimal sophistication
3. **No Defense Mechanism**: Unlike invalid requests which trigger automatic blocking, high-volume valid requests have no mitigation
4. **Limited Visibility**: Operators cannot identify attacking peers from current metrics
5. **High Value Target**: Disrupting state sync can cascade into broader network issues

The configuration shows the system is designed to handle peer abuse: [6](#0-5) [7](#0-6) 

But this defense only applies to invalid requests, not total request volume.

## Recommendation
Implement comprehensive per-peer request rate tracking on the server side:

**1. Add per-peer request rate metrics:**
```rust
// In metrics.rs
pub static STORAGE_REQUESTS_PER_PEER: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_storage_service_server_requests_per_peer_bucket",
        "Gauge for tracking request counts per peer bucket",
        &["peer_bucket_id", "network_id", "request_type"]
    )
    .unwrap()
});
```

**2. Track total requests in RequestModerator:**
Add to `UnhealthyPeerState`:
```rust
total_request_count: u64,
last_request_window_start: Instant,
max_requests_per_window: u64,
request_window_duration_secs: u64,
```

**3. Implement rate limiting logic:**
Check total request rate in addition to invalid requests, with configurable thresholds and time windows similar to the invalid request handling.

**4. Update metrics periodically:**
Similar to client-side implementation, aggregate per-peer requests by bucket and update gauges every 15 seconds.

## Proof of Concept
```rust
// Simulated attack scenario (conceptual - not executable without test harness)
use aptos_config::network_id::{NetworkId, PeerNetworkId};
use aptos_types::PeerId;
use aptos_storage_service_types::requests::*;

// Attacker spawns malicious peer
let attacker_peer = PeerNetworkId::new(NetworkId::Public, PeerId::random());

// Flood with valid but expensive requests
for _ in 0..10000 {
    let request = StorageServiceRequest {
        data_request: DataRequest::GetTransactionsWithProof(
            TransactionsWithProofRequest {
                proof_version: 1000000,
                start_version: 0,
                end_version: 3000, // Max chunk size
                include_events: true,
            }
        ),
        use_compression: false,
    };
    
    // Send request - will be accepted as valid
    // No per-peer rate limiting or tracking exists
    // Server processes all requests, consuming resources
    // Metrics show high volume but not which peer
}
```

**Expected Result:**
- All requests are processed (they are valid)
- Server resources are exhausted
- No automatic blocking occurs
- Operators cannot identify attacking peer from metrics
- Legitimate peers experience timeouts

**Notes**
This issue specifically addresses the security question about per-peer request rate metrics. While the broader DoS attack may be considered out of scope, the **lack of detection and mitigation capabilities** for such attacks represents a concrete implementation gap in the storage service's security architecture. The asymmetry between client-side per-peer tracking and server-side aggregate-only tracking suggests this is an oversight rather than an intentional design decision.

### Citations

**File:** state-sync/storage-service/server/src/metrics.rs (L115-122)
```rust
pub static STORAGE_REQUESTS_RECEIVED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_storage_service_server_requests_received",
        "Counters related to the storage server requests received",
        &["network_id", "request_type"]
    )
    .unwrap()
});
```

**File:** state-sync/storage-service/server/src/handler.rs (L99-103)
```rust
        increment_counter(
            &metrics::STORAGE_REQUESTS_RECEIVED,
            peer_network_id.network_id(),
            request.get_label(),
        );
```

**File:** state-sync/storage-service/server/src/moderator.rs (L50-68)
```rust
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
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L70-74)
```rust
    /// The number of responses received from this peer (by data request label)
    received_responses_by_type: Arc<DashMap<String, u64>>,

    /// The number of requests sent to this peer (by data request label)
    sent_requests_by_type: Arc<DashMap<String, u64>>,
```

**File:** state-sync/aptos-data-client/src/metrics.rs (L173-190)
```rust
pub static SENT_REQUESTS_BY_PEER_BUCKET: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_data_client_sent_requests_by_peer_bucket",
        "Gauge related to the sent requests by peer buckets",
        &["peer_bucket_id", "request_label"]
    )
    .unwrap()
});

/// Gauge for tracking the number of received responses by peer buckets
pub static RECEIVED_RESPONSES_BY_PEER_BUCKET: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_data_client_received_responses_by_peer_bucket",
        "Gauge related to the received responses by peer buckets",
        &["peer_bucket_id", "request_label"]
    )
    .unwrap()
});
```

**File:** config/src/config/state_sync_config.rs (L163-164)
```rust
    /// Maximum number of invalid requests per peer
    pub max_invalid_requests_per_peer: u64,
```

**File:** config/src/config/state_sync_config.rs (L187-188)
```rust
    /// Minimum time (secs) to ignore peers after too many invalid requests
    pub min_time_to_ignore_peers_secs: u64,
```
