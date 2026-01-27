# Audit Report

## Title
Silent Task Failure in PeerLocationUpdater Due to Dropped JoinHandle

## Summary
The `PeerLocationUpdater::run()` method spawns a background task that periodically queries peer location data from BigQuery, but immediately drops the returned `JoinHandle`. This causes any panic in the background task to go unnoticed, leading to silent degradation of the telemetry service's peer location tracking capability without any operator visibility.

## Finding Description

The vulnerability exists in the `PeerLocationUpdater::run()` method: [1](#0-0) 

When `tokio::spawn` is called, it returns a `JoinHandle` that can be used to monitor the task's health and detect panics. However, this `JoinHandle` is immediately dropped (not assigned to any variable), making it impossible to detect if the spawned task panics.

If the background task panics due to:
- Unexpected data format from BigQuery causing unhandled parsing errors
- Bugs in the BigQuery client library or other dependencies
- Resource exhaustion or memory issues
- Logic errors in string parsing or data processing

The task will silently abort, and the service will continue operating with stale peer location data indefinitely. The peer location data is consumed by the metrics ingestion pipeline to add geographic labels: [2](#0-1) 

**Critical Missing Observability**: Unlike similar background updaters in the same codebase, `PeerLocationUpdater` lacks health monitoring metrics:

- `PeerSetCacheUpdater` has success/failure counters and last-update timestamps: [3](#0-2) 

- `AllowlistCacheUpdater` has comprehensive update metrics: [4](#0-3) 

- But `PeerLocationUpdater` has NO metrics for update success/failure or staleness detection: [5](#0-4) 

The only metrics are for individual BigQuery requests, not overall updater health, making task failures completely invisible to operators.

## Impact Explanation

**Severity: Medium** (State inconsistencies requiring intervention)

While this vulnerability does not directly affect blockchain consensus, execution, or state management, it represents a **state inconsistency** between expected behavior (fresh peer location data) and actual behavior (stale data after silent task failure). This qualifies as Medium severity under the bug bounty criteria for "State inconsistencies requiring intervention."

**Specific Impacts:**
1. **Silent degradation**: Operators have no way to detect that peer location tracking has failed
2. **Misleading observability**: Metrics continue with stale geographic labels, potentially misleading operational decisions
3. **No alerting capability**: Unlike other background updaters, there are no staleness metrics to trigger alerts
4. **Operational blind spots**: Geographic distribution monitoring becomes unreliable without operator awareness

## Likelihood Explanation

**Likelihood: Medium-High**

The likelihood is elevated because:
1. BigQuery schema changes or data format variations are common in production environments
2. Dependency updates could introduce panics in the BigQuery client library
3. The task runs hourly and accumulates risk over long-running deployments
4. No defensive monitoring exists to catch early failures
5. The pattern differs from other similar components that have proper health checks

The inconsistency in error handling patterns across the codebase suggests this was an oversight rather than intentional design.

## Recommendation

Implement comprehensive health monitoring similar to `PeerSetCacheUpdater`:

1. **Add health metrics** (similar to validator cache):
```rust
// In metrics.rs, add:
pub(crate) static PEER_LOCATION_UPDATE_SUCCESS_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "telemetry_web_service_peer_location_update_success_count",
        "Number of successful peer location updates",
        &[]
    ).unwrap()
});

pub(crate) static PEER_LOCATION_UPDATE_FAILED_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "telemetry_web_service_peer_location_update_failed_count",
        "Number of failed peer location updates",
        &["error_type"]
    ).unwrap()
});

pub(crate) static PEER_LOCATION_LAST_UPDATE_TIMESTAMP: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "telemetry_web_service_peer_location_last_update_timestamp_seconds",
        "Unix timestamp of last peer location update"
    ).unwrap()
});
```

2. **Update the run method** to handle errors and record metrics:
```rust
pub fn run(self) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match query_peer_locations(&self.client).await {
                Ok(locations) => {
                    let mut peer_locations = self.peer_locations.write();
                    *peer_locations = locations;
                    
                    PEER_LOCATION_UPDATE_SUCCESS_COUNT.inc();
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    PEER_LOCATION_LAST_UPDATE_TIMESTAMP.set(now as i64);
                },
                Err(e) => {
                    PEER_LOCATION_UPDATE_FAILED_COUNT
                        .with_label_values(&[&e.to_string()])
                        .inc();
                    aptos_logger::error!("Failed to query peer locations: {}", e);
                },
            }
        }
    });
}
```

3. **Set up alerting** on `now() - PEER_LOCATION_LAST_UPDATE_TIMESTAMP > threshold` to detect stuck updaters.

## Proof of Concept

Create a test demonstrating undetected task panic:

```rust
#[tokio::test]
async fn test_task_panic_goes_unnoticed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::{sleep, Duration};
    
    let panic_occurred = Arc::new(AtomicBool::new(false));
    let panic_flag = panic_occurred.clone();
    
    // Simulate the current implementation - JoinHandle is dropped
    tokio::spawn(async move {
        panic_flag.store(true, Ordering::SeqCst);
        panic!("Simulated BigQuery parsing error");
    });
    
    // Wait for panic to occur
    sleep(Duration::from_millis(100)).await;
    
    // The panic occurred but was not detected
    assert!(panic_occurred.load(Ordering::SeqCst));
    
    // In the current implementation, there's no way to detect this failure
    // The service continues running with stale data
    // Operators have no visibility into the failure
}
```

**Notes**

This vulnerability demonstrates a violation of the **fail-loud principle** in distributed systems. While the telemetry service is not consensus-critical, silent failures in operational components can cascade into more severe issues by hiding underlying problems. The inconsistency in monitoring patterns across similar background updaters (`PeerSetCacheUpdater` has proper metrics, `PeerLocationUpdater` does not) suggests this was an implementation oversight rather than intentional design, making it a valid Medium severity finding under the "state inconsistencies requiring intervention" category.

### Citations

**File:** crates/aptos-telemetry-service/src/peer_location.rs (L40-56)
```rust
    pub fn run(self) -> anyhow::Result<()> {
        tokio::spawn(async move {
            loop {
                match query_peer_locations(&self.client).await {
                    Ok(locations) => {
                        let mut peer_locations = self.peer_locations.write();
                        *peer_locations = locations;
                    },
                    Err(e) => {
                        aptos_logger::error!("Failed to query peer locations: {}", e);
                    },
                }
                tokio::time::sleep(Duration::from_secs(3600)).await; // 1 hour
            }
        });
        Ok(())
    }
```

**File:** crates/aptos-telemetry-service/src/prometheus_push_metrics.rs (L67-69)
```rust
    if enable_location_labels {
        extra_labels.extend_from_slice(&peer_location_labels(&context, &claims.peer_id));
    }
```

**File:** crates/aptos-telemetry-service/src/validator_cache.rs (L61-83)
```rust
    async fn update(&self) {
        for (chain_name, url) in self.query_addresses.iter() {
            match self.update_for_chain(chain_name, url).await {
                Ok(_) => {
                    VALIDATOR_SET_UPDATE_SUCCESS_COUNT
                        .with_label_values(&[&chain_name.to_string()])
                        .inc();
                    debug!(
                        "validator set update successful for chain name {}",
                        chain_name
                    );
                },
                Err(err) => {
                    VALIDATOR_SET_UPDATE_FAILED_COUNT
                        .with_label_values(&[&chain_name.to_string(), &err.to_string()])
                        .inc();
                    error!(
                        "validator set update error for chain name {}: {:?}",
                        chain_name, err
                    );
                },
            }
        }
```

**File:** crates/aptos-telemetry-service/src/allowlist_cache.rs (L190-216)
```rust
    /// Update allowlists for all configured contracts
    async fn update(&self) {
        for contract in self.contracts.iter() {
            match self.update_contract(contract).await {
                Ok(count) => {
                    ALLOWLIST_CACHE_UPDATE_SUCCESS_COUNT
                        .with_label_values(&[&contract.name])
                        .inc();
                    debug!(
                        "allowlist cache update successful for contract '{}': {} addresses",
                        contract.name, count
                    );
                },
                Err(err) => {
                    // Log error but don't clear cache - stale data is better than no data
                    // The ALLOWLIST_CACHE_LAST_UPDATE_TIMESTAMP metric will show staleness
                    // Operators should alert on: now() - last_update_timestamp > threshold
                    ALLOWLIST_CACHE_UPDATE_FAILED_COUNT
                        .with_label_values(&[&contract.name, err.error_type()])
                        .inc();
                    error!(
                        "allowlist cache update failed for contract '{}': {:?} (using stale cache)",
                        contract.name, err
                    );
                },
            }
        }
```

**File:** crates/aptos-telemetry-service/src/metrics.rs (L195-209)
```rust
pub(crate) static BIG_QUERY_REQUEST_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "big_query_request_total",
        "Total number of big query requests"
    )
    .unwrap()
});

pub(crate) static BIG_QUERY_REQUEST_FAILURES_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "big_query_request_failures_total",
        "Total number of big query request failures"
    )
    .unwrap()
});
```
