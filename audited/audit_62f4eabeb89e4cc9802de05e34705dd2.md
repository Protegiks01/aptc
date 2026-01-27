# Audit Report

## Title
Peer Monitoring Service Client Fails to Disconnect Misbehaving Peers After RPC Failures, Enabling Connection Slot Exhaustion

## Summary
The peer monitoring service client does not distinguish between transient and permanent RPC failures, and critically, never disconnects peers even after consecutive failures exceed configured thresholds. This allows malicious peers to maintain connectivity indefinitely while causing repeated RPC errors, leading to resource exhaustion and peer selection manipulation.

## Finding Description

The peer monitoring service client wraps all RPC errors in a generic `Error` enum without distinguishing error types: [1](#0-0) 

The underlying `RpcError` type has multiple distinct variants representing different failure scenarios: [2](#0-1) 

When RPC errors occur during peer monitoring requests, all error types are handled identically - the client merely increments a failure counter and logs a warning. In `LatencyInfoState`, there is an explicit TODO comment acknowledging that peers should be disconnected after excessive failures, but this is never implemented: [3](#0-2) 

The `handle_monitoring_service_response_error` method across all three state types (LatencyInfo, NetworkInfo, NodeInfo) only records failures and logs warnings, never triggering disconnection: [4](#0-3) [5](#0-4) [6](#0-5) 

The `RequestTracker` tracks consecutive failures but provides no enforcement mechanism: [7](#0-6) 

In stark contrast, the network's HealthChecker properly disconnects peers when failures exceed thresholds: [8](#0-7) 

**Attack Scenario:**

1. Attacker connects to an Aptos node as a peer
2. Attacker repeatedly causes RPC failures by:
   - Timing out latency ping requests (`RpcError::TimedOut`)
   - Sending invalid responses (`RpcError::InvalidRpcResponse`)
   - Causing application errors (`RpcError::ApplicationError`)
   - Sending malformed serialized data (`RpcError::BcsError`)
3. The peer monitoring client increments failure counters and logs warnings, but never disconnects
4. The attacker maintains a connection slot indefinitely
5. Peer monitoring metadata becomes stale/missing, causing the peer to be deprioritized in mempool and consensus observer, but still consuming resources

The peer monitoring metadata is used in critical paths for mempool transaction broadcasting prioritization: [9](#0-8) 

And for consensus observer peer selection: [10](#0-9) 

The default threshold is only 3 failures for latency monitoring: [11](#0-10) 

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under Aptos bug bounty criteria due to:

1. **Validator Node Slowdowns**: Misbehaving peers consume connection slots, CPU cycles for request processing, and network bandwidth while providing no useful service
2. **Significant Protocol Violations**: The peer monitoring service is designed to maintain healthy peer connections, but fails to enforce this fundamental invariant
3. **Resource Exhaustion**: Multiple attackers can saturate all available peer connection slots, preventing legitimate peers from connecting and potentially degrading consensus performance or state sync efficiency
4. **Peer Selection Manipulation**: While misbehaving peers are deprioritized, they still occupy connection slots that could be used by legitimate well-connected peers

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of exploitation:

1. **Low Attack Complexity**: Attackers only need to establish peer connections and send invalid responses or timeout requests - no special privileges required
2. **No Authentication Barrier**: Public fullnodes accept connections from arbitrary peers
3. **Trivial to Reproduce**: Simply timing out RPC requests or sending malformed responses triggers the vulnerability
4. **Acknowledged Technical Debt**: The TODO comment shows developers are aware of the missing disconnect logic but haven't implemented it
5. **No Rate Limiting**: There's no mechanism to throttle or ban peers exhibiting this behavior

## Recommendation

Implement proper error classification and peer disconnection logic:

1. **Classify RPC Errors by Severity**:
   - Transient (retry): `TimedOut`, `UnexpectedResponseChannelCancel`, `MpscSendError`
   - Permanent (disconnect immediately): `InvalidRpcResponse`, `BcsError` (for malformed data)
   - Cumulative (disconnect after threshold): `ApplicationError`, repeated transient failures

2. **Add Disconnect Method** to `StateValueInterface`:
```rust
fn should_disconnect_peer(&self) -> bool;
```

3. **Implement Disconnection in `handle_request_failure`**:
   - When consecutive failures exceed `max_latency_ping_failures`, call the network client's `disconnect_from_peer()` method with `DisconnectReason::PeerMisbehavior` (similar to HealthChecker)
   - Immediately disconnect on permanent error types like `InvalidRpcResponse`

4. **Apply Same Logic to NetworkInfo and NodeInfo States**: Currently they don't even check failure thresholds

5. **Add Metrics**: Track disconnect reasons to monitor peer health

The fix should mirror the HealthChecker's approach, replacing the TODO at line 64 of `latency_info.rs` with actual disconnection logic.

## Proof of Concept

```rust
// Malicious peer behavior - times out all monitoring requests
// 
// Setup:
// 1. Attacker runs a modified peer that accepts connections
// 2. When receiving LatencyPing, GetNetworkInformation, or GetNodeInformation requests,
//    the peer delays response beyond timeout threshold
// 3. Repeat indefinitely
//
// Expected behavior: Peer should be disconnected after 3 consecutive failures (per config)
// Actual behavior: Peer remains connected, warning logs accumulate, connection slot wasted
//
// To reproduce:
// 1. Deploy a test peer that implements PeerMonitoringServiceServer
// 2. In handle_latency_ping(), sleep for longer than latency_ping_timeout_ms (20 seconds)
// 3. Connect to a validator/fullnode running peer monitoring client
// 4. Observe warning logs: "Too many ping failures occurred for the peer!"
// 5. Observe peer never gets disconnected via: `tcpdump` or connection status logs
// 6. Verify connection persists beyond 3 * 30 seconds = 90 seconds (3 failures at 30s intervals)
//
// Alternate exploitation:
// - Send invalid serialized responses (BcsError)
// - Send mismatched ping counters (InvalidRpcResponse)  
// - Return ApplicationError in server handler
//
// Impact demonstration:
// - Monitor connection slots: Should see misbehaving peer occupying a slot
// - Check mempool peer prioritization: Peer will be deprioritized but not removed
// - Scale to multiple attacking peers to exhaust all connection slots
```

**Notes**

The vulnerability exists because the peer monitoring service client was designed with monitoring in mind, not enforcement. The TODO comment explicitly acknowledges that disconnection should happen but was never implemented. This creates an asymmetry with the HealthChecker protocol, which properly enforces peer health through disconnection. The missing enforcement mechanism violates the fundamental network security invariant that misbehaving peers should be disconnected to preserve resources and maintain network health.

### Citations

**File:** peer-monitoring-service/client/src/error.rs (L10-35)
```rust
#[derive(Debug, Error)]
pub enum Error {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Error from remote monitoring service: {0}")]
    PeerMonitoringServiceError(#[from] PeerMonitoringServiceError),

    #[error("Aptos network rpc error: {0}")]
    RpcError(#[from] RpcError),

    #[error("Unexpected error encountered: {0}")]
    UnexpectedError(String),
}

impl Error {
    /// Returns a summary label for the error
    pub fn get_label(&self) -> &'static str {
        match self {
            Self::NetworkError(_) => "network_error",
            Self::PeerMonitoringServiceError(_) => "peer_monitoring_service_error",
            Self::RpcError(_) => "rpc_error",
            Self::UnexpectedError(_) => "unexpected_error",
        }
    }
}
```

**File:** network/framework/src/protocols/rpc/error.rs (L13-44)
```rust
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Error: {0:?}")]
    Error(#[from] anyhow::Error),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Bcs error: {0:?}")]
    BcsError(#[from] bcs::Error),

    #[error("Not connected with peer: {0}")]
    NotConnected(PeerId),

    #[error("Received invalid rpc response message")]
    InvalidRpcResponse,

    #[error("Application layer unexpectedly dropped response channel")]
    UnexpectedResponseChannelCancel,

    #[error("Error in application layer handling rpc request: {0:?}")]
    ApplicationError(anyhow::Error),

    #[error("Error sending on mpsc channel, connection likely shutting down: {0:?}")]
    MpscSendError(#[from] mpsc::SendError),

    #[error("Too many pending RPCs: {0}")]
    TooManyPending(u32),

    #[error("Rpc timed out")]
    TimedOut,
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

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L197-211)
```rust
    fn handle_monitoring_service_response_error(
        &mut self,
        peer_network_id: &PeerNetworkId,
        error: Error,
    ) {
        // Handle the failure
        self.handle_request_failure(peer_network_id);

        // Log the error
        warn!(LogSchema::new(LogEntry::LatencyPing)
            .event(LogEvent::ResponseError)
            .message("Error encountered when pinging peer!")
            .peer(peer_network_id)
            .error(&error));
    }
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L160-174)
```rust
    fn handle_monitoring_service_response_error(
        &mut self,
        peer_network_id: &PeerNetworkId,
        error: Error,
    ) {
        // Handle the failure
        self.handle_request_failure();

        // Log the error
        warn!(LogSchema::new(LogEntry::NetworkInfoRequest)
            .event(LogEvent::ResponseError)
            .message("Error encountered when requesting network information from the peer!")
            .peer(peer_network_id)
            .error(&error));
    }
```

**File:** peer-monitoring-service/client/src/peer_states/node_info.rs (L108-122)
```rust
    fn handle_monitoring_service_response_error(
        &mut self,
        peer_network_id: &PeerNetworkId,
        error: Error,
    ) {
        // Handle the failure
        self.handle_request_failure();

        // Log the error
        warn!(LogSchema::new(LogEntry::NodeInfoRequest)
            .event(LogEvent::ResponseError)
            .message("Error encountered when requesting node information from the peer!")
            .peer(peer_network_id)
            .error(&error));
    }
```

**File:** peer-monitoring-service/client/src/peer_states/request_tracker.rs (L101-104)
```rust
    /// Records a failure for the request
    pub fn record_response_failure(&mut self) {
        self.num_consecutive_request_failures += 1;
    }
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L356-392)
```rust
                // If the ping failures are now more than
                // `self.ping_failures_tolerated`, we disconnect from the node.
                // The HealthChecker only performs the disconnect. It relies on
                // ConnectivityManager or the remote peer to re-establish the connection.
                let failures = self
                    .network_interface
                    .get_peer_failures(peer_id)
                    .unwrap_or(0);
                if failures > self.ping_failures_tolerated {
                    info!(
                        NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                        "{} Disconnecting from peer: {}",
                        self.network_context,
                        peer_id.short_str()
                    );
                    let peer_network_id =
                        PeerNetworkId::new(self.network_context.network_id(), peer_id);
                    if let Err(err) = timeout(
                        Duration::from_millis(50),
                        self.network_interface.disconnect_peer(
                            peer_network_id,
                            DisconnectReason::NetworkHealthCheckFailure,
                        ),
                    )
                    .await
                    {
                        warn!(
                            NetworkSchema::new(&self.network_context)
                                .remote_peer(&peer_id),
                            error = ?err,
                            "{} Failed to disconnect from peer: {} with error: {:?}",
                            self.network_context,
                            peer_id.short_str(),
                            err
                        );
                    }
                }
```

**File:** mempool/src/shared_mempool/priority.rs (L593-611)
```rust
fn compare_peer_health(
    mempool_config: &MempoolConfig,
    time_service: &TimeService,
    monitoring_metadata_a: &Option<&PeerMonitoringMetadata>,
    monitoring_metadata_b: &Option<&PeerMonitoringMetadata>,
) -> Ordering {
    // Check the health of the peer monitoring metadata
    let is_healthy_a =
        check_peer_metadata_health(mempool_config, time_service, monitoring_metadata_a);
    let is_healthy_b =
        check_peer_metadata_health(mempool_config, time_service, monitoring_metadata_b);

    // Compare the health statuses
    match (is_healthy_a, is_healthy_b) {
        (true, false) => Ordering::Greater, // A is healthy, B is unhealthy
        (false, true) => Ordering::Less,    // A is unhealthy, B is healthy
        _ => Ordering::Equal,               // Both are healthy or unhealthy
    }
}
```

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L195-218)
```rust
/// Gets the distance from the validators for the specified peer from the peer metadata
fn get_distance_for_peer(
    peer_network_id: &PeerNetworkId,
    peer_metadata: &PeerMetadata,
) -> Option<u64> {
    // Get the distance for the peer
    let peer_monitoring_metadata = peer_metadata.get_peer_monitoring_metadata();
    let distance = peer_monitoring_metadata
        .latest_network_info_response
        .as_ref()
        .map(|response| response.distance_from_validators);

    // If the distance is missing, log a warning
    if distance.is_none() {
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Unable to get distance for peer! Peer: {:?}",
                peer_network_id
            ))
        );
    }

    distance
}
```

**File:** config/src/config/peer_monitoring_config.rs (L47-56)
```rust
impl Default for LatencyMonitoringConfig {
    fn default() -> Self {
        Self {
            latency_ping_interval_ms: 30_000, // 30 seconds
            latency_ping_timeout_ms: 20_000,  // 20 seconds
            max_latency_ping_failures: 3,
            max_num_latency_pings_to_retain: 10,
        }
    }
}
```
