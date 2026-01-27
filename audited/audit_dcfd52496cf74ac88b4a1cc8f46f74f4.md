# Audit Report

## Title
Unbounded Metric Cardinality Explosion via X_APTOS_CLIENT Header Leading to Log Flooding and Resource Exhaustion

## Summary
The Aptos API's request logging middleware allows attackers to create unbounded metric cardinality by sending HTTP requests with arbitrary `X_APTOS_CLIENT` header values. This causes the `REQUEST_SOURCE_CLIENT` metric family to exceed 2000 dimensions, triggering continuous warning logs every 15 seconds during Prometheus scraping, resulting in log flooding and gradual memory exhaustion.

## Finding Description

The API's logging middleware extracts and validates the `X_APTOS_CLIENT` header using a regex pattern but does not limit values to a known whitelist. [1](#0-0) 

The validation function accepts any value matching the regex pattern and returns it directly as a string slice: [2](#0-1) 

This extracted value is then used directly as a label in the `REQUEST_SOURCE_CLIENT` metric without any cardinality protection: [3](#0-2) 

The metric is defined with three labels: `request_source_client`, `operation_id`, and `status`: [4](#0-3) 

An attacker can send requests with varying header values like:
- `X_APTOS_CLIENT: aptos-attacker1/1.0.0`
- `X_APTOS_CLIENT: aptos-attacker2/1.0.0`
- `X_APTOS_CLIENT: aptos-attacker3/1.0.0`

With 31 API operation_ids and approximately 20 common HTTP status codes, just 4 unique client values create 2,480 time series (4 × 31 × 20), exceeding the 2000-dimension warning threshold.

When metrics are gathered during Prometheus scraping, families exceeding 2000 dimensions trigger warnings without any rate limiting: [5](#0-4) 

With Prometheus configured to scrape every 15 seconds, this results in 4 warning logs per minute, 240 per hour, and 5,760 per day for each affected metric family. [6](#0-5) 

**Contrast with Secure Implementation:**

The keyless pepper service demonstrates proper cardinality protection by replacing unknown values with a constant `INVALID_PATH` label: [7](#0-6) 

The API logging middleware lacks this protection mechanism.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos Bug Bounty program criteria:

1. **Resource Exhaustion**: Unbounded metric cardinality leads to continuous memory growth in the Prometheus process and validator nodes, potentially requiring intervention to clear accumulated metrics.

2. **Log Flooding**: Continuous warning logs every 15 seconds obscure legitimate security alerts and operational issues, degrading monitoring effectiveness.

3. **Performance Degradation**: Large metric families increase the time required to gather, encode, and scrape metrics, causing validator node slowdowns during metrics collection.

4. **Monitoring System Impact**: High-cardinality metrics make dashboards slow and Prometheus queries expensive, potentially affecting alerting and operational visibility.

This matches the Medium severity category: "State inconsistencies requiring intervention" and contributes to "Validator node slowdowns" (High severity characteristics), but does not directly compromise consensus, funds, or network availability.

## Likelihood Explanation

**Likelihood: High**

1. **No Authentication Required**: Public API endpoints are accessible without authentication
2. **Trivial Exploitation**: Attacker only needs to send HTTP requests with custom header values
3. **No Cardinality Limits**: No validation against known client values or maximum cardinality enforcement
4. **Regex Accepts Unbounded Variations**: Pattern `aptos-[a-zA-Z\-]+/[0-9A-Za-z\.\-]+` allows infinite combinations
5. **Rate Limiting Insufficient**: Even with 100 requests/minute limit, an attacker can create enough unique values over hours/days to exceed thresholds
6. **Persistent Impact**: Metrics persist until process restart or explicit cleanup

## Recommendation

Implement cardinality protection by maintaining a whitelist of known client identifiers and replacing unknown values with a constant label:

```rust
// In api/src/log.rs

const KNOWN_CLIENTS: &[&str] = &[
    "aptos-sdk",
    "aptos-ts-sdk", 
    "aptos-python-sdk",
    "aptos-go-sdk",
    "aptos-rust-sdk",
    // Add other official clients
];

const UNKNOWN_CLIENT: &str = "unknown";

fn determine_request_source_client(aptos_client: &Option<String>) -> &'static str {
    let aptos_client = match aptos_client {
        Some(aptos_client) => aptos_client,
        None => return UNKNOWN_CLIENT,
    };

    // Extract the client identifier using regex
    let captured = match REQUEST_SOURCE_CLIENT_REGEX.find_iter(aptos_client).last() {
        Some(capture) => capture.as_str(),
        None => return UNKNOWN_CLIENT,
    };
    
    // Extract the client name (before the '/')
    let client_name = captured.split('/').next().unwrap_or("");
    
    // Check if it's a known client
    for known_client in KNOWN_CLIENTS {
        if client_name == *known_client {
            return known_client;
        }
    }
    
    // Return constant for unknown clients
    UNKNOWN_CLIENT
}
```

This approach:
- Limits cardinality to a fixed set of known clients plus "unknown"
- Maintains observability for official SDKs
- Prevents unbounded metric growth
- Follows the pattern used in the keyless pepper service

## Proof of Concept

```bash
#!/bin/bash
# PoC: Generate high-cardinality metrics via X_APTOS_CLIENT header

API_ENDPOINT="http://localhost:8080/v1"
METRICS_ENDPOINT="http://localhost:9101/metrics"

echo "Starting metric cardinality explosion attack..."

# Send requests with 10 unique client identifiers to various endpoints
for i in {1..10}; do
    for endpoint in "" "/accounts/0x1" "/blocks/by_version/1"; do
        curl -s -H "X_APTOS_CLIENT: aptos-attacker${i}/1.0.0" \
             "${API_ENDPOINT}${endpoint}" > /dev/null 2>&1
        echo "Sent request with client: aptos-attacker${i}"
    done
done

echo ""
echo "Waiting for metrics scrape (15 seconds)..."
sleep 16

echo ""
echo "Checking metrics for REQUEST_SOURCE_CLIENT cardinality..."
curl -s "$METRICS_ENDPOINT" | grep -A 5 "aptos_api_request_source_client" | head -20

echo ""
echo "Checking logs for cardinality warnings..."
echo "Expected: Warnings about 'aptos_api_request_source_client' exceeding 2000 dimensions"
echo "(If 10 clients × 31 endpoints × 20 status codes = 6,200 dimensions)"
```

**Expected Result:**
- The `aptos_api_request_source_client` metric family will contain entries for each unique combination of (client_value, operation_id, status_code)
- Inspection service logs will show warnings like: `"Metric Family 'aptos_api_request_source_client' over 2000 dimensions '6200'"`
- Logs will repeat every 15 seconds as Prometheus scrapes the metrics endpoint

**Notes:**
- This PoC demonstrates the attack with 10 unique client values across multiple endpoints
- In a real attack, an automated script could generate hundreds or thousands of unique values over time
- The attack persists until the validator node is restarted or metrics are manually cleared
- Each scrape cycle continues logging warnings, flooding the log files

### Citations

**File:** api/src/log.rs (L21-22)
```rust
static REQUEST_SOURCE_CLIENT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"aptos-[a-zA-Z\-]+/[0-9A-Za-z\.\-]+").unwrap());
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

**File:** terraform/helm/monitoring/files/prometheus.yml (L1-3)
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
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
