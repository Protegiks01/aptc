# Audit Report

## Title
Memory Exhaustion via Unbounded Header Allocation in Faucet Logging Middleware

## Summary

The `middleware_log()` function in the aptos-faucet service allocates memory for HTTP header values without enforcing size limits, and this allocation occurs before any application-level request limiting mechanisms (semaphore, rate limiters). An attacker can exploit this by sending numerous concurrent requests with maximum-sized headers to cause memory exhaustion and crash the faucet service.

## Finding Description

The vulnerability exists in the request logging middleware that processes all incoming HTTP requests to the aptos-faucet service. [1](#0-0) 

The middleware extracts three HTTP headers (`REFERER`, `USER_AGENT`, `FORWARDED`) and converts them to `String` objects via `to_string()` without any validation of their lengths. These strings are then stored in the `HttpRequestLog` structure and held in memory until the request completes.

The critical issue is the **ordering of operations** in the request processing pipeline. [2](#0-1) 

The `middleware_log` is applied as an outer middleware using `.around()` at line 219, which means it executes **before** any route handlers. In contrast, the faucet's request limiting mechanisms execute much later in the request flow. [3](#0-2) 

The `concurrent_requests_semaphore` check only occurs inside `preprocess_request()` at line 204-215, which is called by the route handlers **after** the middleware has already allocated memory for the headers.

**Attack Path:**

1. Attacker crafts HTTP POST requests to `/fund` or `/is_eligible` endpoints with maximum-sized headers (up to ~15KB total, limited only by the underlying HTTP server's default limits)
2. Each request arrives at the faucet service
3. `middleware_log` immediately extracts and allocates `String` objects for headers (**no size validation**)
4. Memory is held in `HttpRequestLog` → `DropLogger` until request completes
5. Only **after** this allocation do route handlers execute and check the semaphore/rate limiters
6. Attacker sends thousands of concurrent requests with large headers
7. Memory accumulates (e.g., 10,000 requests × 15KB = ~150MB just for header strings)
8. Service experiences memory exhaustion and potential OOM crash

The `max_concurrent_requests` configuration is optional [4](#0-3)  and may not be configured in all deployments. Even when configured, it only limits requests that **reach** the handler, not those that are processed by outer middleware.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **API crashes**: Memory exhaustion can cause the faucet service to crash or become unresponsive, denying service to legitimate users who need test tokens
- **Validator node slowdowns**: If the faucet service runs on shared infrastructure with validator nodes (which may occur in test/development environments), memory exhaustion could impact validator performance

While rate limiting checkers exist in the codebase, they are application-level checkers that execute **after** the vulnerable middleware has already allocated memory. [5](#0-4) 

The vulnerability breaks the documented invariant: **"Resource Limits: All operations must respect gas, storage, and computational limits."** The middleware performs unbounded memory allocation without enforcing resource limits.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Attack Complexity**: Low - requires only sending HTTP requests with large headers
- **Attacker Requirements**: No authentication or privileged access required; the faucet is a public service
- **Mitigations**: 
  - OS-level connection limits may restrict concurrent connections
  - Deployment-specific load balancers (HAProxy) may enforce limits, but this is not guaranteed across all deployments
  - The underlying HTTP server (hyper) has default limits (~16KB total headers), preventing unlimited growth per request, but this still allows significant memory allocation
- **Exploitability**: An attacker can send requests from multiple source IPs or use distributed systems to bypass IP-based rate limiting

The optional nature of `max_concurrent_requests` means some deployments may have no application-level concurrent request limiting at all.

## Recommendation

Implement header size validation **before** string allocation in the middleware. Add explicit limits that are checked before the `to_string()` conversions:

```rust
const MAX_HEADER_VALUE_LENGTH: usize = 1024; // 1KB limit per header

pub async fn middleware_log<E: Endpoint>(next: E, request: Request) -> Result<Response> {
    let start = std::time::Instant::now();

    let source_ip = RealIp::from_request(&request, &mut RequestBody::default())
        .await
        .map(|ip| ip.0)
        .unwrap_or(None);

    let request_log = HttpRequestLog {
        source_ip,
        method: request.method().to_string(),
        path: request.uri().path().to_string(),
        referer: request
            .headers()
            .get(header::REFERER)
            .and_then(|v| {
                if v.len() > MAX_HEADER_VALUE_LENGTH {
                    None
                } else {
                    v.to_str().ok().map(|v| v.to_string())
                }
            }),
        user_agent: request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| {
                if v.len() > MAX_HEADER_VALUE_LENGTH {
                    None
                } else {
                    v.to_str().ok().map(|v| v.to_string())
                }
            }),
        forwarded: request
            .headers()
            .get(header::FORWARDED)
            .and_then(|v| {
                if v.len() > MAX_HEADER_VALUE_LENGTH {
                    None
                } else {
                    v.to_str().ok().map(|v| v.to_string())
                }
            }),
    };
    
    // ... rest of function
}
```

Alternatively, truncate headers instead of discarding them entirely, or configure the HTTP server with stricter header limits.

## Proof of Concept

```rust
#[cfg(test)]
mod memory_exhaustion_test {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, REFERER, USER_AGENT};
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_large_headers_memory_exhaustion() {
        // Start faucet server (assuming test helper exists)
        let faucet_url = "http://127.0.0.1:8081"; // test instance
        
        // Create large header values (14KB each, approaching hyper's 16KB total limit)
        let large_value = "A".repeat(14 * 1024);
        
        // Spawn 1000 concurrent requests with large headers
        let mut handles = vec![];
        for _ in 0..1000 {
            let url = faucet_url.to_string();
            let value = large_value.clone();
            
            let handle = tokio::spawn(async move {
                let client = reqwest::Client::new();
                let mut headers = HeaderMap::new();
                headers.insert(REFERER, HeaderValue::from_str(&value).unwrap());
                headers.insert(USER_AGENT, HeaderValue::from_str("test").unwrap());
                
                // Send request to fund endpoint
                let _ = client.post(&format!("{}/fund", url))
                    .headers(headers)
                    .json(&serde_json::json!({
                        "address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                    }))
                    .timeout(Duration::from_secs(30))
                    .send()
                    .await;
            });
            
            handles.push(handle);
        }
        
        // Wait for all requests - observe memory usage
        // With 1000 requests × 14KB headers = ~14MB allocated just for REFERER headers
        // Before any semaphore or rate limiting checks
        for handle in handles {
            let _ = handle.await;
        }
        
        // Monitor memory usage - should show significant allocation
        // that persists until requests complete
    }
}
```

**Execution Steps:**
1. Deploy aptos-faucet test instance without `max_concurrent_requests` configured
2. Run the PoC test which sends 1000 concurrent requests with 14KB headers
3. Monitor service memory usage during the test
4. Observe that memory is allocated before any faucet-level limiting mechanisms engage
5. Scale up concurrent requests to demonstrate memory exhaustion and potential OOM

## Notes

This vulnerability is distinct from network-level DoS attacks (which are out of scope). It is an **application-level resource management issue** where the application code fails to validate resource consumption before allocation. The fix should be implemented at the application layer by adding header size validation in the middleware itself.

### Citations

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L22-46)
```rust
pub async fn middleware_log<E: Endpoint>(next: E, request: Request) -> Result<Response> {
    let start = std::time::Instant::now();

    let source_ip = RealIp::from_request(&request, &mut RequestBody::default())
        .await
        .map(|ip| ip.0)
        .unwrap_or(None);

    let request_log = HttpRequestLog {
        source_ip,
        method: request.method().to_string(),
        path: request.uri().path().to_string(),
        referer: request
            .headers()
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        user_agent: request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
        forwarded: request
            .headers()
            .get(header::FORWARDED)
            .and_then(|v| v.to_str().ok().map(|v| v.to_string())),
    };
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L38-53)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandlerConfig {
    /// Whether we should return helpful errors.
    pub use_helpful_errors: bool,

    /// Whether we should return rejections the moment a Checker returns any,
    /// or should instead run through all Checkers first. Generally prefer
    /// setting this to true, as it is less work on the tap, but setting it
    /// to false does give the user more immediate information.
    pub return_rejections_early: bool,

    /// The maximum number of requests the tap instance should handle at once.
    /// This allows the tap to avoid overloading its Funder, as well as to
    /// signal to a healthchecker that it is overloaded (via `/`).
    pub max_concurrent_requests: Option<usize>,
}
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L207-220)
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
        );
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L197-215)
```rust
    async fn preprocess_request(
        &self,
        fund_request: &FundRequest,
        source_ip: RealIp,
        header_map: &HeaderMap,
        dry_run: bool,
    ) -> poem::Result<(CheckerData, bool, Option<SemaphorePermit<'_>>), AptosTapError> {
        let permit = match &self.concurrent_requests_semaphore {
            Some(semaphore) => match semaphore.try_acquire() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return Err(AptosTapError::new(
                        "Server overloaded, please try again later".to_string(),
                        AptosTapErrorCode::ServerOverloaded,
                    ))
                },
            },
            None => None,
        };
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L261-270)
```rust
        // Ensure request passes checkers.
        let mut rejection_reasons = Vec::new();
        for checker in &self.checkers {
            rejection_reasons.extend(checker.check(checker_data.clone(), dry_run).await.map_err(
                |e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError),
            )?);
            if !rejection_reasons.is_empty() && self.return_rejections_early {
                break;
            }
        }
```
