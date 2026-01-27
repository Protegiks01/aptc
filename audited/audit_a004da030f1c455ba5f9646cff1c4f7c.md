# Audit Report

## Title
Unauthenticated Faucet Metrics Endpoint Exposes Operational Data to Network-Accessible Clients

## Summary
The Aptos faucet metrics server exposes operational metrics including rate limit rejection counts, request patterns, outstanding transaction counts, and funder account balances through an unauthenticated `/metrics` endpoint. Any network-accessible client can scrape this data, enabling attackers to optimize timing and patterns of faucet abuse attempts.

## Finding Description

The faucet metrics server implements a publicly accessible `/metrics` endpoint with no authentication or authorization controls. [1](#0-0) 

The server binds to `0.0.0.0` by default, exposing the endpoint to all network interfaces. [2](#0-1) 

The only middleware applied is CORS, which permits GET requests from any origin. [3](#0-2) 

The exposed metrics include sensitive operational data:

1. **Rate limit rejection counts** tracked by rejection reason code: [4](#0-3) 

2. **Request patterns and latency** by method, operation, and status: [5](#0-4) 

3. **Outstanding transaction counts** and **funder account balance**: [6](#0-5) 

The `UsageLimitExhausted` rejection reason specifically indicates when rate limits are being enforced: [7](#0-6) 

**Attack Scenario:**
1. Attacker continuously scrapes `/metrics` endpoint (e.g., `curl http://faucet:9101/metrics`)
2. Monitors `aptos_tap_rejection_reason_count{rejection_reason_code="101"}` to track rate limit hits
3. Analyzes `aptos_tap_requests` histogram to identify low-traffic periods
4. Observes `aptos_tap_transfer_funder_account_balance` to gauge remaining capacity
5. Times abuse attempts to maximize success by avoiding detected patterns and exhausted limits

## Impact Explanation

This finding falls under **High Severity** per the Aptos bug bounty program as it represents a significant operational security violation that enables more effective attacks against the faucet service.

While not directly causing loss of funds or consensus violations, the information disclosure:
- Aids attackers in bypassing rate limit protections through timing optimization
- Exposes capacity and operational status that should remain confidential
- Violates security best practices for production API services
- Increases the likelihood of successful faucet abuse attempts

The faucet service is critical infrastructure for testnet operations, and its abuse impacts developer experience and testnet token availability.

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is trivially exploitable:
- No authentication required
- Default configuration exposes endpoint to public internet (0.0.0.0)
- Standard Prometheus metrics format makes parsing straightforward
- Continuous monitoring requires minimal resources (single curl loop)
- Information directly aids in attack optimization with clear actionable signals

Any attacker can immediately begin collecting this intelligence to improve their faucet abuse campaigns.

## Recommendation

Implement authentication and authorization for the metrics endpoint. Add an optional bearer token authentication mechanism:

```rust
// In MetricsServerConfig
pub struct MetricsServerConfig {
    pub disable: bool,
    pub listen_address: String,
    pub listen_port: u16,
    // Add authentication configuration
    pub bearer_token: Option<String>,
}

// In server.rs, add authentication middleware
use poem::{Endpoint, Middleware, Request, Result, middleware::AddData};
use poem::http::StatusCode;

struct BearerAuth {
    token: Option<String>,
}

impl<E: Endpoint> Middleware<E> for BearerAuth {
    type Output = BearerAuthEndpoint<E>;
    
    fn transform(&self, ep: E) -> Self::Output {
        BearerAuthEndpoint {
            ep,
            token: self.token.clone(),
        }
    }
}

struct BearerAuthEndpoint<E> {
    ep: E,
    token: Option<String>,
}

#[poem::async_trait]
impl<E: Endpoint> Endpoint for BearerAuthEndpoint<E> {
    type Output = E::Output;
    
    async fn call(&self, req: Request) -> Result<Self::Output> {
        if let Some(expected_token) = &self.token {
            if let Some(auth_header) = req.headers().get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str == format!("Bearer {}", expected_token) {
                        return self.ep.call(req).await;
                    }
                }
            }
            return Err(poem::Error::from_status(StatusCode::UNAUTHORIZED));
        }
        // If no token configured, allow unauthenticated access
        self.ep.call(req).await
    }
}

// Update run_metrics_server to apply middleware
pub fn run_metrics_server(
    config: MetricsServerConfig,
) -> impl Future<Output = Result<(), std::io::Error>> {
    let cors = Cors::new().allow_methods(vec![Method::GET]);
    let route = Route::new().at("/metrics", metrics);
    
    let route = if config.bearer_token.is_some() {
        route.with(BearerAuth { token: config.bearer_token.clone() })
    } else {
        route
    };
    
    Server::new(TcpListener::bind((
        config.listen_address.clone(),
        config.listen_port,
    )))
    .run(route.with(cors))
}
```

**Alternative recommendations:**
1. Bind to `127.0.0.1` by default instead of `0.0.0.0` to limit access to localhost
2. Document that operators MUST implement network-level access controls (firewall rules, VPC restrictions)
3. Add IP allowlisting configuration option for authorized Prometheus scrapers

## Proof of Concept

```bash
#!/bin/bash
# POC: Scraping unauthenticated faucet metrics

# Start a faucet instance with default configuration
# The metrics server will be accessible on 0.0.0.0:9101

# Continuously monitor rate limit rejections
while true; do
    echo "=== $(date) ==="
    
    # Scrape all metrics
    curl -s http://localhost:9101/metrics > metrics.txt
    
    # Extract rate limit rejection count
    echo "Rate limit rejections:"
    grep "aptos_tap_rejection_reason_count" metrics.txt | grep "101"
    
    # Extract funder balance
    echo "Funder balance:"
    grep "aptos_tap_transfer_funder_account_balance" metrics.txt
    
    # Extract request patterns
    echo "Request patterns:"
    grep "aptos_tap_requests_sum" metrics.txt
    
    echo ""
    sleep 5
done
```

**To demonstrate the vulnerability:**

1. Deploy the faucet service with default configuration
2. Run the POC script in the background
3. Generate legitimate and rate-limited requests to the faucet
4. Observe that the POC script successfully captures:
   - When rate limits are triggered (rejection_reason_code="101" counter increases)
   - Faucet capacity (balance decreases with each funded request)
   - Traffic patterns (request histograms show busy/idle periods)
   - No authentication challenges occur

This intelligence allows an attacker to optimize their abuse attempts by timing requests during low-traffic periods and monitoring when rate limits reset.

## Notes

This vulnerability represents a deviation from security best practices where sensitive operational metrics should be protected. While the Aptos inspection service also exposes metrics without authentication [8](#0-7) , that service is intended for validator operators in controlled network environments.

The faucet, being a public-facing service, has a different threat model and should implement application-level access controls rather than relying solely on infrastructure-level protections which may be misconfigured or unavailable in all deployment scenarios.

### Citations

**File:** crates/aptos-faucet/metrics-server/src/server.rs (L26-29)
```rust
#[handler]
fn metrics() -> Vec<u8> {
    encode_metrics(TextEncoder)
}
```

**File:** crates/aptos-faucet/metrics-server/src/server.rs (L34-39)
```rust
    let cors = Cors::new().allow_methods(vec![Method::GET]);
    Server::new(TcpListener::bind((
        config.listen_address.clone(),
        config.listen_port,
    )))
    .run(Route::new().at("/metrics", metrics).with(cors))
```

**File:** crates/aptos-faucet/metrics-server/src/config.rs (L26-28)
```rust
    fn default_listen_address() -> String {
        "0.0.0.0".to_string()
    }
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

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L29-36)
```rust
static REJECTION_REASONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_tap_rejection_reason_count",
        "Number of times the tap has returned the given rejection reason.",
        &["rejection_reason_code"]
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/middleware/metrics.rs (L38-53)
```rust
pub static NUM_OUTSTANDING_TRANSACTIONS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_tap_num_outstanding_transactions",
        "Number of transactions we've submitted but have not been processed by the blockchain.",
    )
    .unwrap()
});

// TODO: Consider using IntGaugeVec to attach the account address as a label.
pub static TRANSFER_FUNDER_ACCOUNT_BALANCE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_tap_transfer_funder_account_balance",
        "Balance of the account used by the tap instance. Only populated for the TransferFunder.",
    )
    .unwrap()
});
```

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L244-245)
```rust
    /// Key (IP / Firebase UID) has exhausted its usage limit.
    UsageLimitExhausted = 101,
```

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L72-76)
```rust
/// Handles a new metrics request (with text encoding)
pub fn handle_metrics_request() -> (StatusCode, Body, String) {
    let buffer = utils::get_encoded_metrics(TextEncoder::new());
    (StatusCode::OK, Body::from(buffer), CONTENT_TYPE_TEXT.into())
}
```
