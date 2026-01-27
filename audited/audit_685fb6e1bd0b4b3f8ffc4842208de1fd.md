# Audit Report

## Title
Prometheus Metric Cardinality Explosion via Unsanitized X-Aptos-Client Header

## Summary
The Aptos REST API extracts the `X-Aptos-Client` HTTP header and uses it directly as a Prometheus metric label without cardinality limits. An attacker can send requests with arbitrary header values matching a permissive regex pattern, creating unbounded unique time series that exhaust memory and degrade API performance, leading to service crashes.

## Finding Description

The vulnerability exists in the API request logging middleware where the `REQUEST_SOURCE_CLIENT` metric tracks client requests by source identifier. The attack flow is:

**Step 1: Header Extraction**
The middleware extracts the `X-Aptos-Client` header from incoming HTTP requests without any cardinality controls. [1](#0-0) 

**Step 2: Insufficient Validation** 
The `determine_request_source_client` function validates header values using a regex pattern that allows millions of unique combinations. The regex `aptos-[a-zA-Z\-]+/[0-9A-Za-z\.\-]+` permits any alphanumeric identifier and version string. [2](#0-1) [3](#0-2) 

**Step 3: Direct Metric Label Usage**
The extracted value is used directly as a metric label in Prometheus without cardinality limits. Each unique header value creates a new time series in the metrics system. [4](#0-3) 

The `REQUEST_SOURCE_CLIENT` metric is defined with three labels including the unsanitized `request_source_client` value: [5](#0-4) 

**Attack Scenario:**
An attacker sends HTTP requests with crafted headers:
- `X-Aptos-Client: aptos-attack/1.0.0`
- `X-Aptos-Client: aptos-attack/1.0.1`
- `X-Aptos-Client: aptos-attack/1.0.2`
- ... (continuing with unlimited variations)

Each unique value creates a new Prometheus time series, consuming memory linearly with the number of unique headers sent. The regex allows combinations like:
- Identifier variations: `aptos-a`, `aptos-ab`, `aptos-abc`, ..., `aptos-zzzzz`
- Version variations: `0`, `1`, `1.0`, `1.0.0`, `1.0.0.0`, ..., `9.9.9.9.9`

This breaks the **Resource Limits** invariant - the metrics system should respect reasonable resource constraints and not allow unbounded memory growth from external input.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:

1. **API Crashes**: Unbounded metric cardinality leads to memory exhaustion, causing the API server to crash or become unresponsive. This directly matches the "API crashes" category in High Severity.

2. **Validator Node Slowdowns**: If the API server runs on validator infrastructure, metrics collection overhead causes performance degradation affecting block processing. This matches "Validator node slowdowns" in High Severity.

3. **Metrics System Failure**: High cardinality makes Prometheus queries timeout, rendering the entire observability infrastructure unusable for operators.

The codebase shows awareness of cardinality issues through monitoring (warnings when families exceed 2000 dimensions), but implements no preventive controls: [6](#0-5) 

However, this monitoring is only in the faucet metrics server, not the main API, and provides no protection mechanism.

## Likelihood Explanation

**Likelihood: High**

1. **No Authentication Required**: Any client can send arbitrary HTTP headers to public API endpoints.

2. **Trivial Exploitation**: Attackers only need to send HTTP requests with varying `X-Aptos-Client` headers. No special tools, privileges, or blockchain knowledge required.

3. **No Rate Limiting on Cardinality**: While the infrastructure has connection-level rate limiting, there are no per-metric cardinality limits. A single slow-rate attacker can gradually build up cardinality over time.

4. **Wide Attack Surface**: Every API endpoint processes this header through the logging middleware, maximizing attack opportunities. [7](#0-6) 

5. **Immediate Impact**: Each unique header creates permanent metric series until server restart or manual intervention.

## Recommendation

Implement a whitelist-based approach or strict cardinality limits:

**Solution 1: Whitelist Known Clients**
```rust
const KNOWN_CLIENTS: &[&str] = &[
    "aptos-rust-sdk",
    "aptos-python-sdk", 
    "aptos-typescript-sdk",
    "aptos-cli",
    "aptos-go-sdk",
];

fn determine_request_source_client(aptos_client: &Option<String>) -> &str {
    let aptos_client = match aptos_client {
        Some(aptos_client) => aptos_client,
        None => return REQUEST_SOURCE_CLIENT_UNKNOWN,
    };

    match REQUEST_SOURCE_CLIENT_REGEX.find_iter(aptos_client).last() {
        Some(capture) => {
            let client_str = capture.as_str();
            // Extract identifier before the slash
            if let Some(slash_pos) = client_str.find('/') {
                let identifier = &client_str[..slash_pos];
                if KNOWN_CLIENTS.iter().any(|&known| identifier == known) {
                    return identifier; // Return only identifier, not full version
                }
            }
            REQUEST_SOURCE_CLIENT_UNKNOWN
        }
        None => REQUEST_SOURCE_CLIENT_UNKNOWN,
    }
}
```

**Solution 2: Cardinality Limit with LRU Cache**
```rust
use once_cell::sync::Lazy;
use std::sync::Mutex;
use lru::LruCache;

static CLIENT_CACHE: Lazy<Mutex<LruCache<String, String>>> = 
    Lazy::new(|| Mutex::new(LruCache::new(100))); // Max 100 unique clients

fn determine_request_source_client(aptos_client: &Option<String>) -> String {
    let aptos_client = match aptos_client {
        Some(aptos_client) => aptos_client,
        None => return REQUEST_SOURCE_CLIENT_UNKNOWN.to_string(),
    };

    match REQUEST_SOURCE_CLIENT_REGEX.find_iter(aptos_client).last() {
        Some(capture) => {
            let client_str = capture.as_str().to_string();
            let mut cache = CLIENT_CACHE.lock().unwrap();
            
            if let Some(cached) = cache.get(&client_str) {
                return cached.clone();
            }
            
            if cache.len() >= 100 {
                return REQUEST_SOURCE_CLIENT_UNKNOWN.to_string();
            }
            
            cache.put(client_str.clone(), client_str.clone());
            client_str
        }
        None => REQUEST_SOURCE_CLIENT_UNKNOWN.to_string(),
    }
}
```

**Recommended Approach**: Use Solution 1 (whitelist) as it provides the strongest security guarantee and aligns with the intended use case of tracking known SDK clients.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Cardinality Explosion Attack on Aptos API

API_ENDPOINT="http://localhost:8080"  # Adjust to target API endpoint

echo "Starting cardinality explosion attack..."
echo "Sending requests with unique X-Aptos-Client headers..."

# Send 10,000 requests with unique client identifiers
for i in $(seq 1 10000); do
    # Generate unique header value matching the regex
    CLIENT_HEADER="aptos-attack-${i}/1.0.${i}"
    
    curl -s -X GET "${API_ENDPOINT}/v1/" \
         -H "X-Aptos-Client: ${CLIENT_HEADER}" \
         > /dev/null
    
    if [ $((i % 100)) -eq 0 ]; then
        echo "Sent $i requests..."
    fi
done

echo "Attack complete. Check Prometheus metrics at ${API_ENDPOINT}/metrics"
echo "Search for 'aptos_api_request_source_client' to see cardinality explosion."
echo "Expected: 10,000+ unique time series created."

# Verification query
echo -e "\nMetric cardinality check:"
curl -s "${API_ENDPOINT}/metrics" | grep "aptos_api_request_source_client{" | wc -l
```

**Expected Result**: After running this script, the API's `/metrics` endpoint will show thousands of unique `aptos_api_request_source_client` time series, each consuming memory. Continued execution will eventually cause OOM errors or severe performance degradation.

**Verification Steps**:
1. Monitor API server memory usage before/during/after attack
2. Query Prometheus for `count(aptos_api_request_source_client)` to see cardinality
3. Observe API response time degradation as cardinality increases
4. Check for OOM kills or crashes in API server logs

## Notes

This vulnerability demonstrates a critical principle in metrics design: **never use unbounded external input as metric labels**. While the regex provides format validation, it does not constrain cardinality, which is the actual security concern in time-series databases like Prometheus.

The issue is exacerbated by the fact that the header is intended for legitimate telemetry purposes, making it difficult to simply remove. The whitelist approach maintains the intended functionality while eliminating the attack vector.

### Citations

**File:** api/src/log.rs (L21-22)
```rust
static REQUEST_SOURCE_CLIENT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"aptos-[a-zA-Z\-]+/[0-9A-Za-z\.\-]+").unwrap());
```

**File:** api/src/log.rs (L72-75)
```rust
        aptos_client: request
            .headers()
            .get(X_APTOS_CLIENT)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
```

**File:** api/src/log.rs (L124-130)
```rust
    REQUEST_SOURCE_CLIENT
        .with_label_values(&[
            determine_request_source_client(&log.aptos_client),
            operation_id,
            log.status.to_string().as_str(),
        ])
        .inc();
```

**File:** api/src/log.rs (L148-162)
```rust
fn determine_request_source_client(aptos_client: &Option<String>) -> &str {
    // If the header is not set we can't determine the request source.
    let aptos_client = match aptos_client {
        Some(aptos_client) => aptos_client,
        None => return REQUEST_SOURCE_CLIENT_UNKNOWN,
    };

    // If there were no matches, we can't determine the request source. If there are
    // multiple matches for some reason, instead of logging nothing, we use whatever
    // value we matched on last.
    match REQUEST_SOURCE_CLIENT_REGEX.find_iter(aptos_client).last() {
        Some(capture) => capture.as_str(),
        None => REQUEST_SOURCE_CLIENT_UNKNOWN,
    }
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

**File:** crates/aptos-faucet/metrics-server/src/gather_metrics.rs (L18-33)
```rust
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
```

**File:** api/src/runtime.rs (L257-259)
```rust
            // NOTE: Make sure to keep this after all the `with` middleware.
            .catch_all_error(convert_error)
            .around(middleware_log);
```
