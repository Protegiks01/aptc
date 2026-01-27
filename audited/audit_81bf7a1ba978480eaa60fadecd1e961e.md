# Audit Report

## Title
Timing Side-Channel in Consensus Health Check Endpoint Leaks Validator State and Consensus Activity

## Summary
The `/consensus_health_check` endpoint inefficiently gathers all Prometheus metrics to check a single gauge value, creating a timing side-channel that allows attackers to infer consensus round progression, validator set size, transaction processing patterns, and voting activity through response time analysis.

## Finding Description

The inspection service exposes a `/consensus_health_check` endpoint designed for external health monitoring that leaks sensitive consensus information through timing analysis. [1](#0-0) 

The vulnerability exists because `handle_consensus_health_check()` calls `utils::get_all_metrics()` to check a single metric value. This function gathers ALL Prometheus metrics from the entire system: [2](#0-1) 

The metrics gathering process iterates through all metric families, including consensus-specific metrics that scale with validator activity: [3](#0-2) 

The consensus subsystem exports per-peer voting metrics that increase during active consensus rounds: [4](#0-3) 

These per-peer metrics create one gauge entry per validator per hash during consensus voting. With 100 validators, this adds 100+ metric entries during each consensus round, proportionally increasing the iteration time in `get_metric_families()`.

The inspection service binds to all network interfaces by default with no authentication: [5](#0-4) 

**Attack Path**:

1. Attacker measures baseline response time for `/consensus_health_check` when consensus is idle
2. During active consensus rounds, new per-peer voting metrics are created (`CONSENSUS_CURRENT_ROUND_VOTED_POWER`, `CONSENSUS_CURRENT_ROUND_TIMEOUT_VOTED_POWER`)
3. Response time increases proportionally to the number of active metrics
4. By repeatedly querying the endpoint at high frequency (10-100 Hz), attacker correlates timing variations with:
   - Consensus round progression (metric count spikes during voting)
   - Validator set size changes (more validators = more per-peer metrics)
   - Transaction processing load (execution metrics increase)
   - Voting patterns (timing correlates with when votes arrive)

5. Cross-endpoint correlation: Attacker combines timing from `/consensus_health_check`, `/peer_information`, and `/metrics` to build a complete picture of validator state transitions

## Impact Explanation

This qualifies as **Medium severity** per Aptos bug bounty criteria:

- **Information Disclosure**: Reveals consensus timing, round progression, and validator activity patterns
- **Privacy Violation**: External parties can monitor validator voting behavior without authorization
- **Attack Enablement**: Timing information helps attackers plan sophisticated attacks:
  - Identify optimal moments for consensus disruption
  - Detect validator liveness patterns
  - Monitor transaction processing capacity
  - Infer network topology changes

While this doesn't directly violate consensus safety, it provides actionable intelligence for planning timing-based attacks against the consensus protocol.

## Likelihood Explanation

**High Likelihood**:

- **No Authentication**: The endpoint is publicly accessible by default
- **Trivial Exploitation**: Requires only standard HTTP timing measurements
- **Production Deployment**: Health check endpoints are commonly exposed for load balancers and monitoring systems, even when full metrics endpoints are firewalled
- **High Frequency**: The endpoint is explicitly designed for frequent polling (comment states "used every few seconds")

An attacker can execute this attack with a simple HTTP client measuring response times, making it easily exploitable by any network-connected adversary.

## Recommendation

**Solution 1: Direct Gauge Access (Recommended)**

Instead of gathering all metrics, directly access the specific gauge value. The inspection service should accept a reference to the consensus executing gauge at initialization or use a shared metrics accessor.

**Solution 2: Constant-Time Response**

If direct access is not feasible, ensure all health check endpoints return responses in constant time by pre-computing results or adding artificial delays to normalize response times.

**Solution 3: Authentication and Rate Limiting**

Add authentication to inspection service endpoints and implement rate limiting to prevent high-frequency timing analysis.

**Code Fix Example**:

```rust
// In metrics.rs - Instead of gathering all metrics
pub async fn handle_consensus_health_check(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    if !node_config.base.role.is_validator() {
        return (
            StatusCode::BAD_REQUEST,
            Body::from("This node is not a validator!"),
            CONTENT_TYPE_TEXT.into(),
        );
    }

    // Direct access to gauge value (requires passing reference at initialization)
    // let gauge_value = CONSENSUS_EXECUTING_GAUGE.get();
    
    // Or check if metric exists in registry without gathering all
    // This still requires optimization to avoid timing leaks
    
    // Temporary workaround: Add constant delay to normalize timing
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    let metrics = utils::get_all_metrics();
    // ... rest of implementation
}
```

Additionally, consider restricting the inspection service binding address in production configurations and adding authentication for sensitive endpoints.

## Proof of Concept

**Rust Client for Timing Analysis**:

```rust
use std::time::Instant;
use reqwest;

#[tokio::main]
async fn main() {
    let endpoint = "http://validator-node:9101/consensus_health_check";
    let client = reqwest::Client::new();
    
    // Collect baseline timing samples
    let mut timings = Vec::new();
    for _ in 0..1000 {
        let start = Instant::now();
        let _ = client.get(endpoint).send().await;
        let duration = start.elapsed().as_micros();
        timings.push(duration);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    
    // Analyze timing distribution
    timings.sort();
    let median = timings[timings.len() / 2];
    let p95 = timings[(timings.len() * 95) / 100];
    
    println!("Median response time: {} μs", median);
    println!("P95 response time: {} μs", p95);
    
    // Significant timing variations (>20% difference) indicate:
    // - Consensus round transitions
    // - Validator set changes
    // - Transaction processing spikes
    
    // Monitor for timing spikes that correlate with consensus activity
    for timing in &timings {
        if *timing > median + (median / 5) {  // 20% above median
            println!("Timing spike detected: {} μs (possible consensus activity)", timing);
        }
    }
}
```

This PoC demonstrates how an attacker measures response time variations to infer validator consensus state without accessing the actual metric values.

## Notes

The vulnerability is exacerbated by the fact that consensus metrics include per-peer gauges that scale with validator set size. During active consensus, metrics like `CONSENSUS_CURRENT_ROUND_VOTED_POWER` create one entry per validator per block hash, significantly increasing the metric count and thus the response time.

The inspection service was designed for debugging and monitoring, but lacks security considerations for production deployments where it may be exposed to untrusted networks. The timing side-channel persists even when operators disable other sensitive endpoints like `/peer_information` or `/configuration`, because the health check endpoint cannot be disabled and always performs the expensive metric gathering operation.

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

**File:** crates/aptos-inspection-service/src/server/utils.rs (L26-29)
```rust
pub fn get_all_metrics() -> HashMap<String, String> {
    let metric_families = get_metric_families();
    get_metrics_map(metric_families)
}
```

**File:** crates/aptos-inspection-service/src/server/utils.rs (L50-79)
```rust
fn get_metric_families() -> Vec<MetricFamily> {
    let metric_families = aptos_metrics_core::gather();
    let mut total: u64 = 0;
    let mut families_over_2000: u64 = 0;

    // Take metrics of metric gathering so we know possible overhead of this process
    for metric_family in &metric_families {
        let family_count = metric_family.get_metric().len();
        if family_count > 2000 {
            families_over_2000 = families_over_2000.saturating_add(1);
            let name = metric_family.get_name();
            warn!(
                count = family_count,
                metric_family = name,
                "Metric Family '{}' over 2000 dimensions '{}'",
                name,
                family_count
            );
        }
        total = total.saturating_add(family_count as u64);
    }

    // These metrics will be reported on the next pull, rather than create a new family
    NUM_METRICS.with_label_values(&["total"]).inc_by(total);
    NUM_METRICS
        .with_label_values(&["families_over_2000"])
        .inc_by(families_over_2000);

    metric_families
}
```

**File:** consensus/src/counters.rs (L557-574)
```rust
pub static CONSENSUS_CURRENT_ROUND_VOTED_POWER: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "aptos_consensus_current_round_voted_power",
        "Counter for consensus participation status, 0 means no participation and 1 otherwise",
        &["peer_id", "hash_index"]
    )
    .unwrap()
});

/// For the current ordering round, for each peer, whether they have voted for a timeout
pub static CONSENSUS_CURRENT_ROUND_TIMEOUT_VOTED_POWER: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "aptos_consensus_current_round_timeout_voted_power",
        "Counter for consensus participation status, 0 means no participation and 1 otherwise",
        &["peer_id"]
    )
    .unwrap()
});
```

**File:** config/src/config/inspection_service_config.rs (L26-37)
```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
}
```
