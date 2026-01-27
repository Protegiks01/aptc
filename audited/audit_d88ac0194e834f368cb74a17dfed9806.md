# Audit Report

## Title
Unbounded Memory Allocation in Indexer gRPC Gateway Leads to Denial of Service

## Summary
The indexer-grpc-gateway service uses jemalloc as its global allocator without any memory limits configured, and performs unbounded request body collection in middleware. An attacker can send arbitrarily large requests to exhaust memory, causing OOM conditions and crashing the gateway service.

## Finding Description

The indexer-grpc-gateway has a critical resource exhaustion vulnerability caused by two compounding issues:

**Issue 1: No jemalloc memory limits**

The gateway configures jemalloc as the global allocator but provides no memory limit configuration: [1](#0-0) 

Unlike other critical services like aptos-node which configure jemalloc with profiling parameters, the gateway has no `malloc_conf` static variable to set memory limits or other protective parameters. [2](#0-1) 

**Issue 2: Unbounded body collection in middleware**

The `get_data_service_url` middleware function collects the entire request body into memory without any size validation for GetTransactions requests: [3](#0-2) 

The middleware checks if the request is to the GetTransactions endpoint and then calls `body.collect().await` which attempts to allocate memory for the entire request body, regardless of size. There is no Content-Length header validation or size limit check before this allocation.

**Issue 3: No Axum body size limits**

The Axum router is configured without any DefaultBodyLimit layer: [4](#0-3) 

While Axum 0.7.5 has a default 2MB body limit, the middleware manually collects the body before any framework-level limits can apply, bypassing this protection.

**Attack Path:**

1. Attacker identifies the indexer gateway endpoint (typically public-facing)
2. Attacker sends HTTP POST requests to `/aptos.indexer.v1.RawData/GetTransactions` with extremely large bodies (e.g., 1GB+)
3. The middleware attempts to collect the entire body into memory via `body.collect().await`
4. With no jemalloc memory limits, the allocator attempts to satisfy the allocation
5. Multiple concurrent requests rapidly exhaust available memory
6. The gateway process crashes due to OOM, causing denial of service

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for "API crashes" and "Significant protocol violations."

**Specific impacts:**

1. **Denial of Service**: The indexer gateway can be crashed by any external attacker, disrupting indexer data availability for all downstream consumers (dApps, explorers, processors)

2. **Infrastructure disruption**: The indexer infrastructure is critical for ecosystem applications. Gateway unavailability impacts the entire Aptos ecosystem's ability to query historical blockchain data

3. **Resource exhaustion cascade**: If multiple gateway instances share infrastructure, memory exhaustion on one instance can impact others

4. **Easy exploitation**: No authentication or rate limiting can fully prevent this attack since even legitimate-looking requests can carry malicious payloads

While this doesn't directly affect consensus or validator nodes, the indexer infrastructure is a critical component of the Aptos ecosystem's availability guarantees.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **No authentication required**: The gateway is designed to be publicly accessible
2. **Trivial exploitation**: Any HTTP client can send large POST requests
3. **Immediate impact**: Each malicious request immediately consumes memory
4. **No rate limiting at allocation layer**: While there may be network-level rate limits, memory allocation happens before any application-level controls
5. **Common attack pattern**: Memory exhaustion DoS is a well-known attack vector that automated scanners commonly probe for

The attacker needs:
- Network access to the gateway (publicly available by design)
- Basic HTTP client capability
- No special credentials or insider knowledge

## Recommendation

Implement multi-layer protection against unbounded memory allocation:

**1. Configure jemalloc memory limits**

Add a `malloc_conf` configuration similar to aptos-node:

```rust
#[allow(unsafe_code)]
#[cfg(unix)]
#[used]
#[unsafe(no_mangle)]
pub static mut malloc_conf: *const c_char = 
    c"prof:true,lg_prof_sample:23,lg_dirty_mult:8,lg_muzzy_decay_ms:14".as_ptr().cast();
```

**2. Add explicit body size validation in middleware**

Before calling `body.collect()`, validate the Content-Length header:

```rust
const MAX_BODY_SIZE: usize = 15 * 1024 * 1024; // 15MB, matching MESSAGE_SIZE_LIMIT

if head.uri.path() == "/aptos.indexer.v1.RawData/GetTransactions" {
    // Validate Content-Length header
    if let Some(content_length) = head.headers.get("content-length") {
        if let Ok(size_str) = content_length.to_str() {
            if let Ok(size) = size_str.parse::<usize>() {
                if size > MAX_BODY_SIZE {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!("Request body too large: {} bytes (max: {})", size, MAX_BODY_SIZE)
                    ));
                }
            }
        }
    }
    
    let body_bytes = body.collect().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .to_bytes();
    // ...
}
```

**3. Add Axum DefaultBodyLimit layer**

Apply framework-level protection:

```rust
use axum::extract::DefaultBodyLimit;

let app = Router::new()
    .route("/*path", any(proxy).with_state(self.config.clone()))
    .layer(from_fn_with_state(
        self.config.clone(),
        get_data_service_url,
    ))
    .layer(DefaultBodyLimit::max(MAX_BODY_SIZE));
```

**4. Align with existing MESSAGE_SIZE_LIMIT constant**

Reference the existing constant used by other indexer services: [5](#0-4) 

## Proof of Concept

```rust
// PoC: Send large request to trigger OOM
use reqwest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gateway_url = "http://localhost:8080/aptos.indexer.v1.RawData/GetTransactions";
    
    // Create a 1GB payload
    let large_payload = vec![0u8; 1024 * 1024 * 1024];
    
    // Send multiple concurrent requests to exhaust memory
    let mut handles = vec![];
    for _ in 0..10 {
        let payload = large_payload.clone();
        let url = gateway_url.to_string();
        let handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let _ = client.post(&url)
                .header("content-type", "application/grpc")
                .body(payload)
                .send()
                .await;
        });
        handles.push(handle);
    }
    
    // Wait for requests to complete (gateway will likely crash before this)
    for handle in handles {
        let _ = handle.await;
    }
    
    Ok(())
}
```

**Expected Result**: The gateway process will consume increasing amounts of memory and eventually crash with an OOM error, making the service unavailable.

**Notes**

While the downstream gRPC services (data-service, grpc-manager) have proper message size limits configured, the gateway acts as a proxy that performs body collection before forwarding requests. This architectural decision creates an attack surface that bypasses the protection mechanisms in place for the backend services. [6](#0-5) 

The vulnerability is specific to the gateway's middleware implementation and does not affect the core blockchain consensus or validator operations. However, it represents a significant availability risk for the indexer infrastructure that many ecosystem applications depend on.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-gateway/src/main.rs (L10-11)
```rust
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;
```

**File:** aptos-node/src/main.rs (L14-19)
```rust
/// Can be overridden by setting the `MALLOC_CONF` env var.
#[allow(unsafe_code)]
#[cfg(unix)]
#[used]
#[unsafe(no_mangle)]
pub static mut malloc_conf: *const c_char = c"prof:true,lg_prof_sample:23".as_ptr().cast();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-gateway/src/gateway.rs (L44-49)
```rust
        let app = Router::new()
            .route("/*path", any(proxy).with_state(self.config.clone()))
            .layer(from_fn_with_state(
                self.config.clone(),
                get_data_service_url,
            ));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-gateway/src/gateway.rs (L115-121)
```rust
    if head.uri.path() == "/aptos.indexer.v1.RawData/GetTransactions" {
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .to_bytes();
        body = body_bytes.clone().into();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L18-19)
```rust
// Limit the message size to 15MB. By default the downstream can receive up to 15MB.
pub const MESSAGE_SIZE_LIMIT: usize = 1024 * 1024 * 15;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/config.rs (L15-15)
```rust
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * (1 << 20);
```
