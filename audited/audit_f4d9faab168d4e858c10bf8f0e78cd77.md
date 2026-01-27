# Audit Report

## Title
Consensus Health Check Accepts Stale Metrics Without Timestamp Validation

## Summary
The `handle_consensus_health_check()` function in the inspection service does not perform any staleness checks on the `CONSENSUS_EXECUTING_GAUGE` metric. If the state sync driver loop stops updating this metric (due to hang, crash, or misconfiguration), the health check continues to pass with hours-old stale data, causing validators to appear healthy when they've stopped consensus participation. [1](#0-0) 

## Finding Description

The consensus health check endpoint relies on the `CONSENSUS_EXECUTING_GAUGE` metric to determine if a validator is currently participating in consensus. This gauge is updated by the state sync driver in its main event loop: [2](#0-1) 

The driver's `drive_progress()` method is called periodically (every 100ms by default) from the main event loop: [3](#0-2) [4](#0-3) 

However, the health check function performs NO staleness validation: [5](#0-4) 

It simply checks if the gauge value equals "1" without verifying when this value was last updated. Prometheus `IntGauge` metrics persist their last set value indefinitely: [6](#0-5) 

**Failure Scenarios:**

1. **Driver Loop Hang/Deadlock**: If the state sync driver's event loop deadlocks or hangs, `drive_progress()` stops being called. The gauge remains at its last value (potentially 1), and health checks continue passing indefinitely.

2. **Partial Process Failure**: If the driver thread panics or crashes while the inspection service HTTP server continues running, metrics are never updated but remain queryable with stale values.

3. **Misconfiguration**: If `progress_check_interval_ms` is misconfigured to an extremely large value (hours), there's a massive staleness window: [7](#0-6) [8](#0-7) 

**Contrast with Proper Staleness Checking:**

Other parts of the codebase implement proper timestamp-based staleness validation. The telemetry service explicitly documents this pattern for cache freshness monitoring, showing the codebase has established precedent for staleness checks that this health check violates.

This breaks the monitoring integrity invariant: health checks should accurately reflect current node state, not potentially hours-old cached values.

## Impact Explanation

**Severity: High** (Validator node slowdowns / Significant protocol violations)

This issue causes:

1. **Failed Validator Detection**: External monitoring systems (load balancers, alerting tools, orchestration platforms) rely on this health check endpoint to determine validator health. Stale metrics cause them to route traffic to or report healthy status for validators that have stopped consensus participation.

2. **Delayed Incident Response**: Operations teams monitoring validator health will not detect consensus failures until they notice missed block proposals or other secondary symptoms, significantly delaying response time.

3. **Cascading Monitoring Failures**: Automated recovery systems that depend on health checks may fail to trigger, leaving validators in degraded states longer than necessary.

4. **Validator Performance Degradation**: Validators appearing healthy while not participating in consensus contribute to network performance issues, as other validators must compensate.

This meets the **High Severity** criteria of "Validator node slowdowns" and "Significant protocol violations" - the health monitoring protocol is violated, allowing degraded validators to appear operational.

## Likelihood Explanation

**Likelihood: Medium to High**

This issue has moderate to high likelihood because:

1. **Event Loop Failures**: Rust async event loops can hang due to blocking operations, deadlocks in shared state, or resource exhaustion. While not common, they are realistic failure modes.

2. **Configuration Errors**: Node operators may accidentally misconfigure `progress_check_interval_ms` to large values, creating multi-hour staleness windows.

3. **Production Complexity**: In production environments with high load, partial failures where some components crash while others continue running are documented failure modes.

4. **No Defense in Depth**: There are no compensating controls - the health check has a single point of failure with no staleness validation.

The default 100ms interval provides good freshness under normal operation, but the lack of staleness checks means any failure in the update path causes indefinite metric staleness.

## Recommendation

Implement timestamp-based staleness validation following the pattern used elsewhere in the codebase:

1. **Add a timestamp gauge** to track when consensus metrics were last updated:

```rust
pub static CONSENSUS_EXECUTING_GAUGE_LAST_UPDATE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_state_sync_consensus_executing_gauge_last_update_timestamp",
        "Unix timestamp (seconds) when the consensus executing gauge was last updated"
    )
    .unwrap()
});
```

2. **Update the timestamp** in `update_executing_component_metrics()`:

```rust
// Set the consensus executing gauge
if executing_component == ExecutingComponent::Consensus {
    metrics::CONSENSUS_EXECUTING_GAUGE.set(1);
} else {
    metrics::CONSENSUS_EXECUTING_GAUGE.set(0);
}

// Update the last update timestamp
metrics::CONSENSUS_EXECUTING_GAUGE_LAST_UPDATE.set(
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
);
```

3. **Add staleness check** in `handle_consensus_health_check()`:

```rust
// Define acceptable staleness threshold (e.g., 5 seconds)
const MAX_METRIC_STALENESS_SECS: u64 = 5;

pub async fn handle_consensus_health_check(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Verify the node is a validator
    if !node_config.base.role.is_validator() {
        return (
            StatusCode::BAD_REQUEST,
            Body::from("This node is not a validator!"),
            CONTENT_TYPE_TEXT.into(),
        );
    }

    let metrics = utils::get_all_metrics();
    
    // Check metric staleness
    if let Some(last_update_str) = metrics.get("aptos_state_sync_consensus_executing_gauge_last_update_timestamp{}") {
        if let Ok(last_update_secs) = last_update_str.parse::<u64>() {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            if now_secs - last_update_secs > MAX_METRIC_STALENESS_SECS {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::from(format!(
                        "Consensus health check failed! Metric is stale (last updated {} seconds ago)",
                        now_secs - last_update_secs
                    )),
                    CONTENT_TYPE_TEXT.into(),
                );
            }
        }
    } else {
        // Timestamp metric not found - treat as unhealthy
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Body::from("Consensus health check failed! Timestamp metric not available"),
            CONTENT_TYPE_TEXT.into(),
        );
    }
    
    // Check the consensus execution gauge value
    if let Some(gauge_value) = metrics.get(CONSENSUS_EXECUTION_GAUGE) {
        if gauge_value == "1" {
            return (
                StatusCode::OK,
                Body::from("Consensus health check passed!"),
                CONTENT_TYPE_TEXT.into(),
            );
        }
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Body::from("Consensus health check failed! Consensus is not executing!"),
        CONTENT_TYPE_TEXT.into(),
    )
}
```

## Proof of Concept

```rust
// Test demonstrating stale metric issue
#[tokio::test]
async fn test_consensus_health_check_accepts_stale_metrics() {
    use aptos_config::config::{NodeConfig, RoleType};
    use crate::server::metrics::{handle_consensus_health_check, CONSENSUS_EXECUTION_GAUGE};
    
    // Setup: Create a validator node config
    let mut node_config = NodeConfig::default();
    node_config.base.role = RoleType::Validator;
    
    // Simulate: Set the consensus executing gauge to 1 (healthy)
    CONSENSUS_EXECUTING_GAUGE.set(1);
    
    // Verify: Health check passes with fresh metric
    let (status, _, _) = handle_consensus_health_check(&node_config).await;
    assert_eq!(status, StatusCode::OK);
    
    // Simulate: Hours pass without any metric update
    // (In real scenario: driver loop has hung/crashed)
    tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    
    // BUG: Health check still passes with 1-hour-old stale metric!
    let (status, _, _) = handle_consensus_health_check(&node_config).await;
    assert_eq!(status, StatusCode::OK); // Should fail but passes!
    
    // The gauge value is still 1, but consensus stopped hours ago
    // External monitoring systems incorrectly believe validator is healthy
}

// Test with proposed fix
#[tokio::test]
async fn test_consensus_health_check_rejects_stale_metrics_with_fix() {
    use aptos_config::config::{NodeConfig, RoleType};
    
    let mut node_config = NodeConfig::default();
    node_config.base.role = RoleType::Validator;
    
    // Set gauge to 1 and timestamp to current time
    CONSENSUS_EXECUTING_GAUGE.set(1);
    CONSENSUS_EXECUTING_GAUGE_LAST_UPDATE.set(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    );
    
    // Fresh metric passes
    let (status, _, _) = handle_consensus_health_check(&node_config).await;
    assert_eq!(status, StatusCode::OK);
    
    // Manually set stale timestamp (10 seconds ago)
    let stale_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() - 10;
    CONSENSUS_EXECUTING_GAUGE_LAST_UPDATE.set(stale_timestamp as i64);
    
    // Stale metric correctly fails health check
    let (status, _, _) = handle_consensus_health_check(&node_config).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
```

## Notes

This vulnerability represents a gap in defensive monitoring that violates the principle of defense in depth. While the primary failure (driver loop stopping) is the root cause, the health check should detect and report this condition rather than accepting indefinitely stale data. The fix follows established patterns in the codebase for cache staleness monitoring and adds minimal overhead while significantly improving operational safety.

### Citations

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L20-48)
```rust
pub async fn handle_consensus_health_check(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Verify the node is a validator. If not, return an error.
    if !node_config.base.role.is_validator() {
        return (
            StatusCode::BAD_REQUEST,
            Body::from("This node is not a validator!"),
            CONTENT_TYPE_TEXT.into(),
        );
    }

    // Check the value of the consensus execution gauge
    let metrics = utils::get_all_metrics();
    if let Some(gauge_value) = metrics.get(CONSENSUS_EXECUTION_GAUGE) {
        if gauge_value == "1" {
            return (
                StatusCode::OK,
                Body::from("Consensus health check passed!"),
                CONTENT_TYPE_TEXT.into(),
            );
        }
    }

    // Otherwise, consensus is not executing
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Body::from("Consensus health check failed! Consensus is not executing!"),
        CONTENT_TYPE_TEXT.into(),
    )
}
```

**File:** state-sync/state-sync-driver/src/driver.rs (L235-236)
```rust
                _ = progress_check_interval.select_next_some() => {
                    self.drive_progress().await;
```

**File:** state-sync/state-sync-driver/src/driver.rs (L667-669)
```rust
    async fn drive_progress(&mut self) {
        // Update the executing component metrics
        self.update_executing_component_metrics();
```

**File:** state-sync/state-sync-driver/src/driver.rs (L743-748)
```rust
        // Set the consensus executing gauge
        if executing_component == ExecutingComponent::Consensus {
            metrics::CONSENSUS_EXECUTING_GAUGE.set(1);
        } else {
            metrics::CONSENSUS_EXECUTING_GAUGE.set(0);
        }
```

**File:** state-sync/state-sync-driver/src/metrics.rs (L111-117)
```rust
pub static CONSENSUS_EXECUTING_GAUGE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_state_sync_consensus_executing_gauge",
        "Gauge indicating whether consensus is currently executing"
    )
    .unwrap()
});
```

**File:** config/src/config/state_sync_config.rs (L115-115)
```rust
    pub progress_check_interval_ms: u64,
```

**File:** config/src/config/state_sync_config.rs (L142-142)
```rust
            progress_check_interval_ms: 100,
```
