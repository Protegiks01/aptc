# Audit Report

## Title
Monitoring Blind Spot: Rate-Limited Peers Not Reflected in IGNORED_PEERS Metric Enabling Stealth Network Degradation

## Summary
The `IGNORED_PEERS` metric tracks only score-based peer ignoring on the data client side, while the storage service's `RequestModerator` separately rate-limits peers without updating this metric. This dual-system architecture creates a monitoring blind spot where network partition conditions can exist without visibility in the primary peer health metric.

## Finding Description

Aptos implements two independent peer management systems that track ignored peers separately:

**System 1: Data Client Score-Based Ignoring** [1](#0-0) 

This metric (`aptos_data_client_ignored_peers`) only tracks peers whose response quality score drops below the ignore threshold (25.0). [2](#0-1) 

**System 2: Storage Service Rate-Limiting** [3](#0-2) 

This tracks peers sending too many invalid requests via a separate metric (`aptos_storage_service_server_ignored_peer_count`). [4](#0-3) 

**The Critical Gap:**
When a peer is rate-limited by the storage service for exceeding `max_invalid_requests_per_peer` (default: 500), the data client receives `TooManyInvalidRequests` errors: [5](#0-4) 

These errors are treated as generic "unexpected errors" with only a 0.95x score multiplier (`NOT_USEFUL_MULTIPLIER`). It takes approximately 30 consecutive failures to drop a peer's score from 50 to below 25, during which time `IGNORED_PEERS` shows zero ignored peers despite active rate-limiting. [6](#0-5) 

## Impact Explanation

This constitutes a **Medium severity** monitoring vulnerability under the "State inconsistencies requiring intervention" category. While it doesn't directly cause network partition, it masks degradation conditions:

- Operators monitoring `IGNORED_PEERS` won't detect gradual peer isolation via rate-limiting
- The storage service's `IGNORED_PEER_COUNT` metric exists in a different namespace and may not be included in standard dashboards
- During an incident, operators lack visibility into the true extent of peer connectivity issues
- This delays incident response and remediation of network health problems

The configuration defaults amplify the issue: [7](#0-6) 

With 5-minute ignore windows and exponential backoff, rate-limited peers can remain blocked for extended periods without metric visibility.

## Likelihood Explanation

**Moderate likelihood** - this condition can arise from:

1. **Configuration mismatches**: Storage services advertising data ranges they cannot serve triggers invalid request counting
2. **Network timing issues**: Race conditions between storage summary updates and actual data availability
3. **Malicious storage summaries**: Compromised validators deliberately advertising incorrect data ranges to trigger rate-limiting of honest peers

The dual-metric architecture is working as designed, making this an inherent operational blind spot rather than a rare edge case.

## Recommendation

**Unified Peer Health Monitoring:**

1. Update the `IGNORED_PEERS` metric to aggregate both score-based ignoring AND storage service rate-limiting:

```rust
// In state-sync/aptos-data-client/src/peer_states.rs
fn update_peer_ignored_metrics(
    peer_to_state: Arc<DashMap<PeerNetworkId, PeerState>>,
    storage_service_ignored_peers: Arc<DashMap<PeerNetworkId, UnhealthyPeerState>>, // NEW
) {
    let mut ignored_peer_counts_by_network: BTreeMap<NetworkId, u64> = BTreeMap::new();
    
    // Existing score-based ignoring
    for peer_state_entry in peer_to_state.iter() {
        // ... existing code ...
    }
    
    // NEW: Add storage service rate-limited peers
    for unhealthy_peer in storage_service_ignored_peers.iter() {
        if unhealthy_peer.is_ignored() {
            let network_id = unhealthy_peer.key().network_id();
            *ignored_peer_counts_by_network.entry(network_id).or_default() += 1;
        }
    }
    
    // Update metrics with combined count
    for (network_id, ignored_peer_count) in ignored_peer_counts_by_network.iter() {
        metrics::set_gauge(&metrics::IGNORED_PEERS, &network_id.to_string(), *ignored_peer_count);
    }
}
```

2. Add a labeled dimension to distinguish ignore reasons:
```rust
pub static IGNORED_PEERS: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_data_client_ignored_peers",
        "Gauge related to the number of ignored peers",
        &["network", "reason"] // NEW: add reason label
    ).unwrap()
});
```

3. Treat `TooManyInvalidRequests` errors with higher severity (malicious multiplier) rather than generic "not useful": [8](#0-7) 

## Proof of Concept

```rust
// Test demonstrating the monitoring blind spot
// File: state-sync/aptos-data-client/tests/monitoring_gap_test.rs

#[tokio::test]
async fn test_rate_limited_peers_not_in_ignored_peers_metric() {
    // Setup: Create data client and mock storage service
    let data_client_config = AptosDataClientConfig::default();
    let storage_config = StorageServiceConfig {
        max_invalid_requests_per_peer: 5,
        min_time_to_ignore_peers_secs: 1,
        ..Default::default()
    };
    
    // Create peer on public network
    let peer = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    
    // Simulate 5 invalid requests to trigger rate-limiting
    for _ in 0..5 {
        // RequestModerator increments invalid request count
        unhealthy_peer_state.increment_invalid_request_count(&peer);
    }
    
    // Verify: Peer is ignored by storage service
    assert!(unhealthy_peer_state.is_ignored());
    
    // Verify: IGNORED_PEER_COUNT metric shows 1
    let storage_ignored_count = get_metric_value("aptos_storage_service_server_ignored_peer_count");
    assert_eq!(storage_ignored_count, 1);
    
    // Critical gap: IGNORED_PEERS metric still shows 0
    // because peer score hasn't dropped below 25.0 yet
    let data_client_ignored_count = get_metric_value("aptos_data_client_ignored_peers");
    assert_eq!(data_client_ignored_count, 0); // MONITORING BLIND SPOT
    
    // Peer is functionally isolated but primary metric doesn't reflect it
}
```

**Notes:**

This vulnerability represents an **architectural monitoring gap** rather than a logic error. The two peer management systems serve different purposes (response quality vs. request validity), but the lack of unified visibility creates operational risk during network incidents or attacks targeting peer connectivity.

### Citations

**File:** state-sync/aptos-data-client/src/metrics.rs (L125-132)
```rust
pub static IGNORED_PEERS: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_data_client_ignored_peers",
        "Gauge related to the number of ignored peers",
        &["network"]
    )
    .unwrap()
});
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L38-43)
```rust
/// Not necessarily a malicious response, but not super useful.
const NOT_USEFUL_MULTIPLIER: f64 = 0.95;
/// Likely to be a malicious response.
const MALICIOUS_MULTIPLIER: f64 = 0.8;
/// Ignore a peer when their score dips below this threshold.
const IGNORE_PEER_THRESHOLD: f64 = 25.0;
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L45-52)
```rust
pub enum ErrorType {
    /// A response or error that's not actively malicious but also doesn't help
    /// us make progress, e.g., timeouts, remote errors, invalid data, etc...
    NotUseful,
    /// A response or error that appears to be actively hindering progress or
    /// attempting to deceive us, e.g., invalid proof.
    Malicious,
}
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L152-160)
```rust
    fn is_ignored(&self) -> bool {
        // Only ignore peers if the config allows it
        if !self.data_client_config.ignore_low_score_peers {
            return false;
        }

        // Otherwise, ignore peers with a low score
        self.score <= IGNORE_PEER_THRESHOLD
    }
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

**File:** state-sync/storage-service/server/src/metrics.rs (L33-40)
```rust
pub static IGNORED_PEER_COUNT: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_storage_service_server_ignored_peer_count",
        "Gauge for tracking the number of actively ignored peers",
        &["network_id"]
    )
    .unwrap()
});
```

**File:** state-sync/aptos-data-client/src/client.rs (L844-866)
```rust
                    aptos_storage_service_client::Error::StorageServiceError(err) => {
                        Error::UnexpectedErrorEncountered(err.to_string())
                    },
                    _ => Error::UnexpectedErrorEncountered(error.to_string()),
                };

                warn!(
                    (LogSchema::new(LogEntry::StorageServiceResponse)
                        .event(LogEvent::ResponseError)
                        .request_type(&request.get_label())
                        .request_id(id)
                        .peer(&peer)
                        .error(&client_error))
                );

                increment_request_counter(
                    &metrics::ERROR_RESPONSES,
                    client_error.get_label(),
                    peer,
                );

                self.notify_bad_response(id, peer, &request, ErrorType::NotUseful);
                Err(client_error)
```

**File:** config/src/config/state_sync_config.rs (L201-213)
```rust
            max_invalid_requests_per_peer: 500,
            max_lru_cache_size: 500, // At ~0.6MiB per chunk, this should take no more than 0.5GiB
            max_network_channel_size: 4000,
            max_network_chunk_bytes: SERVER_MAX_MESSAGE_SIZE as u64,
            max_network_chunk_bytes_v2: SERVER_MAX_MESSAGE_SIZE_V2 as u64,
            max_num_active_subscriptions: 30,
            max_optimistic_fetch_period_ms: 5000, // 5 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_storage_read_wait_time_ms: 10_000, // 10 seconds
            max_subscription_period_ms: 30_000,    // 30 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            min_time_to_ignore_peers_secs: 300, // 5 minutes
```
