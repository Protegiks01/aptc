# Audit Report

## Title
Lack of Monotonicity Validation in Peer Monitoring Service Enables Byzantine Peers to Manipulate Mempool Prioritization

## Summary
The `record_node_info_response()` function accepts node information responses from peers without validating that blockchain progress indicators (epochs, versions, timestamps) are monotonically increasing. This allows Byzantine peers to send regressing or future values, manipulating their perceived health status in mempool peer prioritization, potentially causing transaction propagation delays across the network.

## Finding Description

The peer monitoring service client stores node information from peers to make prioritization decisions in mempool transaction forwarding. The `record_node_info_response()` function unconditionally accepts and overwrites previous node info without any validation: [1](#0-0) 

This stored information contains critical blockchain progress indicators: [2](#0-1) 

The mempool uses this data to determine peer health by comparing the peer's `ledger_timestamp_usecs` against the current time: [3](#0-2) 

**Vulnerability:** The health check uses `saturating_sub`, which returns 0 if the peer's timestamp is in the future. This means:
- Byzantine peers sending **future timestamps** always appear healthy (0 < max_sync_lag)
- Byzantine peers sending **regressing timestamps** appear unhealthy and get deprioritized
- No detection or logging occurs for non-monotonic values

Healthy peers are prioritized over unhealthy ones in transaction forwarding: [4](#0-3) 

**Attack Scenario:**
1. Multiple Byzantine peers send `NodeInformationResponse` with `ledger_timestamp_usecs` set to future values or repeatedly send regressing values
2. Due to lack of monotonicity enforcement, these values are accepted without validation
3. Byzantine peers with future timestamps always pass health checks and get prioritized for mempool transaction forwarding
4. If these peers drop or delay transaction propagation, network-wide transaction dissemination is degraded
5. Legitimate peers may be deprioritized relative to the Byzantine peers

## Impact Explanation

This vulnerability falls under **Medium Severity** ("State inconsistencies requiring intervention") with potential escalation to **High Severity** ("Validator node slowdowns"):

- **Medium Impact:** The peer monitoring state becomes inconsistent with actual peer sync status, requiring manual intervention to identify and disconnect misbehaving peers
- **Potential High Impact:** If multiple coordinated Byzantine peers exploit this to monopolize mempool transaction forwarding while not actually propagating transactions, this could cause measurable validator node slowdowns due to degraded transaction propagation across the network

The impact is limited by:
- Other mechanisms that detect non-responsive peers
- The attack requires coordination among multiple peers to be effective
- Does not directly affect consensus safety or fund security

## Likelihood Explanation

**High Likelihood:**
- Any network peer can send node info responses without special privileges
- No validation or rate limiting on node info updates
- The attack is trivial to execute (send crafted responses)
- Multiple peers could coordinate this attack easily

**Factors Reducing Impact:**
- Network may eventually disconnect peers exhibiting other bad behaviors
- Mempool has fallback mechanisms for peer selection
- Monitoring tools may detect anomalous peer behavior

## Recommendation

Implement monotonicity validation in `record_node_info_response()`:

```rust
pub fn record_node_info_response(&mut self, node_info_response: NodeInformationResponse) {
    // Validate monotonicity if we have a previous response
    if let Some(previous_response) = &self.recorded_node_info_response {
        // Check epoch progression
        if node_info_response.highest_synced_epoch < previous_response.highest_synced_epoch {
            warn!(LogSchema::new(LogEntry::NodeInfoRequest)
                .message("Rejecting node info response with regressing epoch"));
            self.handle_request_failure();
            return;
        }
        
        // Check version progression within the same epoch
        if node_info_response.highest_synced_epoch == previous_response.highest_synced_epoch 
            && node_info_response.highest_synced_version < previous_response.highest_synced_version {
            warn!(LogSchema::new(LogEntry::NodeInfoRequest)
                .message("Rejecting node info response with regressing version"));
            self.handle_request_failure();
            return;
        }
        
        // Check timestamp is not unreasonably in the future
        let current_time_usecs = self.time_service.now_unix_time().as_micros() as u64;
        let max_future_drift_usecs = 60_000_000; // 60 seconds
        if node_info_response.ledger_timestamp_usecs > current_time_usecs + max_future_drift_usecs {
            warn!(LogSchema::new(LogEntry::NodeInfoRequest)
                .message("Rejecting node info response with future timestamp"));
            self.handle_request_failure();
            return;
        }
    }

    // Update the request tracker with a successful response
    self.request_tracker.write().record_response_success();

    // Save the node info
    self.recorded_node_info_response = Some(node_info_response);
}
```

Additional improvements:
- Add metrics for rejected non-monotonic responses
- Consider disconnecting peers that repeatedly send invalid data
- Log peer ID when rejecting responses for investigation

## Proof of Concept

```rust
#[test]
fn test_reject_regressing_node_info() {
    // Create node info state
    let node_monitoring_config = NodeMonitoringConfig::default();
    let time_service = TimeService::mock();
    let mut node_info_state = NodeInfoState::new(node_monitoring_config, time_service.clone());
    
    // Send initial node info with epoch 100, version 1000000
    let initial_response = NodeInformationResponse {
        build_information: Default::default(),
        highest_synced_epoch: 100,
        highest_synced_version: 1000000,
        ledger_timestamp_usecs: time_service.now_unix_time().as_micros() as u64,
        lowest_available_version: 999990,
        uptime: Duration::from_secs(3600),
    };
    node_info_state.record_node_info_response(initial_response.clone());
    
    // Verify it was stored
    assert_eq!(
        node_info_state.get_latest_node_info_response().unwrap().highest_synced_epoch,
        100
    );
    
    // Send regressing node info with epoch 50, version 500000
    let regressing_response = NodeInformationResponse {
        build_information: Default::default(),
        highest_synced_epoch: 50,  // Regressing!
        highest_synced_version: 500000,  // Regressing!
        ledger_timestamp_usecs: time_service.now_unix_time().as_micros() as u64 - 1000000,
        lowest_available_version: 499990,
        uptime: Duration::from_secs(7200),
    };
    node_info_state.record_node_info_response(regressing_response);
    
    // BUG: The regressing response is accepted without validation
    // Expected: Should reject and keep previous response
    // Actual: Overwrites with regressing data
    assert_eq!(
        node_info_state.get_latest_node_info_response().unwrap().highest_synced_epoch,
        50  // This proves the vulnerability - regressing value was accepted
    );
    
    // Send future timestamp
    let future_timestamp = time_service.now_unix_time().as_micros() as u64 + 1000000000;
    let future_response = NodeInformationResponse {
        build_information: Default::default(),
        highest_synced_epoch: 200,
        highest_synced_version: 2000000,
        ledger_timestamp_usecs: future_timestamp,  // Far in the future
        lowest_available_version: 1999990,
        uptime: Duration::from_secs(10800),
    };
    node_info_state.record_node_info_response(future_response);
    
    // BUG: Future timestamp is accepted without validation
    assert_eq!(
        node_info_state.get_latest_node_info_response().unwrap().ledger_timestamp_usecs,
        future_timestamp  // Future timestamp accepted
    );
}
```

## Notes

This vulnerability is exacerbated by the use of `saturating_sub` in the health check logic, which causes future timestamps to always appear healthy. The lack of any validation (monotonicity, timestamp bounds, sanity checks) allows Byzantine peers to freely manipulate their perceived state without detection. While not a critical consensus safety issue, it represents a significant protocol violation that can be exploited to degrade network performance.

### Citations

**File:** peer-monitoring-service/client/src/peer_states/node_info.rs (L47-53)
```rust
    pub fn record_node_info_response(&mut self, node_info_response: NodeInformationResponse) {
        // Update the request tracker with a successful response
        self.request_tracker.write().record_response_success();

        // Save the node info
        self.recorded_node_info_response = Some(node_info_response);
    }
```

**File:** peer-monitoring-service/types/src/response.rs (L94-102)
```rust
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeInformationResponse {
    pub build_information: BTreeMap<String, String>, // The build information of the node
    pub highest_synced_epoch: u64,                   // The highest synced epoch of the node
    pub highest_synced_version: u64,                 // The highest synced version of the node
    pub ledger_timestamp_usecs: u64, // The latest timestamp of the blockchain (in microseconds)
    pub lowest_available_version: u64, // The lowest stored version of the node (in storage)
    pub uptime: Duration,            // The amount of time the peer has been running
}
```

**File:** mempool/src/shared_mempool/priority.rs (L562-589)
```rust
fn check_peer_metadata_health(
    mempool_config: &MempoolConfig,
    time_service: &TimeService,
    monitoring_metadata: &Option<&PeerMonitoringMetadata>,
) -> bool {
    monitoring_metadata
        .and_then(|metadata| {
            metadata
                .latest_node_info_response
                .as_ref()
                .map(|node_information_response| {
                    // Get the peer's ledger timestamp and the current timestamp
                    let peer_ledger_timestamp_usecs =
                        node_information_response.ledger_timestamp_usecs;
                    let current_timestamp_usecs = get_timestamp_now_usecs(time_service);

                    // Calculate the max sync lag before the peer is considered unhealthy (in microseconds)
                    let max_sync_lag_secs =
                        mempool_config.max_sync_lag_before_unhealthy_secs as u64;
                    let max_sync_lag_usecs = max_sync_lag_secs * MICROS_PER_SECOND;

                    // Determine if the peer is healthy
                    current_timestamp_usecs.saturating_sub(peer_ledger_timestamp_usecs)
                        < max_sync_lag_usecs
                })
        })
        .unwrap_or(false) // If metadata is missing, consider the peer unhealthy
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
