# Audit Report

## Title
Unbounded Request Body Size in Rosetta API Enables Memory Exhaustion DoS Attack

## Summary
The Aptos Rosetta API does not enforce request body size limits on any of its endpoints, allowing attackers to send arbitrarily large JSON payloads that cause memory exhaustion and service crashes. This vulnerability affects all POST endpoints in the Rosetta service and can lead to validator node slowdowns or complete API unavailability.

## Finding Description

The Aptos Rosetta API implementation uses the warp web framework without applying content length limits to request bodies. While the `ApiConfig` structure includes a `content_length_limit` field with a default of 8 MB, [1](#0-0)  the Rosetta API routes never utilize this configuration.

All Rosetta API endpoints use `warp::body::json()` without the protective `warp::body::content_length_limit()` filter:

- Construction API routes (combine, derive, hash, metadata, parse, payloads, preprocess, submit) [2](#0-1) 
- Account API routes (balance) [3](#0-2) 
- Network API routes (options, status) [4](#0-3) 
- Block API routes [5](#0-4) 

The `WebServer::serve()` function simply passes routes to `warp::serve()` without any middleware to enforce size limits: [6](#0-5) 

In contrast, other services in the codebase properly implement body size limits. The telemetry service demonstrates the correct pattern by using `warp::body::content_length_limit(MAX_CONTENT_LENGTH)` where `MAX_CONTENT_LENGTH` is set to 1 MB: [7](#0-6)  and [8](#0-7) 

**Attack Flow:**
1. Attacker identifies a Rosetta API endpoint (e.g., `/construction/combine`, `/account/balance`)
2. Attacker crafts an HTTP POST request with a multi-gigabyte JSON body
3. Warp's `body::json()` filter attempts to read the entire body into memory
4. Memory exhaustion occurs, causing the Rosetta service to slow down or crash
5. If the Rosetta API runs on the same machine as a validator node, this impacts node availability

This violates the critical invariant: **"Resource Limits: All operations must respect gas, storage, and computational limits"** - the system fails to enforce basic resource constraints on API requests.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** according to the Aptos bug bounty program because it enables:

1. **Validator node slowdowns**: When the Rosetta API is deployed alongside validator infrastructure, memory exhaustion can degrade validator performance
2. **API crashes**: The service can be forced to crash through out-of-memory errors, causing complete loss of Rosetta API availability
3. **Denial of Service**: Repeated attacks can maintain persistent service unavailability

The impact is particularly severe because:
- The Rosetta API is typically publicly exposed for blockchain indexers and wallets
- No authentication is required to exploit this vulnerability
- Memory exhaustion can cascade to affect co-located services
- The attack is trivial to execute and can be automated

## Likelihood Explanation

This vulnerability has **VERY HIGH likelihood** of exploitation:

**Ease of Exploitation:**
- Requires only basic HTTP client capabilities (curl, browser, script)
- No authentication, authorization, or specialized knowledge needed
- Attack can be executed in a single request
- Can be automated for sustained DoS campaigns

**Attack Visibility:**
- Attacker can discover the vulnerability through standard API testing
- Rosetta API endpoints are documented and publicly known
- No special reconnaissance required

**Deployment Context:**
- Rosetta API is commonly deployed in production environments
- Often runs on the same infrastructure as critical validator services
- Typically exposed to the public internet for wallet/indexer integration

## Recommendation

Apply request body size limits to all Rosetta API routes using warp's `content_length_limit` filter. 

**Recommended Fix:**

1. Define a reasonable maximum request size in the Rosetta configuration (suggested: 1-8 MB)

2. Modify each route to include the content length limit filter:

```rust
// Example fix for construction routes
pub fn combine_route(
    server_context: RosettaContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("construction" / "combine")
        .and(warp::post())
        .and(warp::body::content_length_limit(8 * 1024 * 1024)) // 8 MB limit
        .and(warp::body::json())
        .and(with_context(server_context))
        .and_then(handle_request(construction_combine))
}
```

3. Apply this pattern consistently to all POST endpoints that accept JSON bodies

4. Consider extracting the limit into a constant or reading from `ApiConfig.content_length_limit()`

5. Add proper error handling to return a clear HTTP 413 (Payload Too Large) response when limits are exceeded

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
#[tokio::test]
async fn test_rosetta_memory_exhaustion_attack() {
    use std::time::Duration;
    use tokio::time::timeout;
    
    // Start a Rosetta API server (in test environment)
    let rosetta_addr = "http://localhost:8082";
    
    // Create a very large JSON payload (1 GB)
    let large_payload = serde_json::json!({
        "network_identifier": {
            "blockchain": "aptos",
            "network": "testnet"
        },
        "unsigned_transaction": "A".repeat(1_000_000_000), // 1 GB string
        "signatures": []
    });
    
    // Send the malicious request to /construction/combine
    let client = reqwest::Client::new();
    let result = timeout(
        Duration::from_secs(30),
        client.post(format!("{}/construction/combine", rosetta_addr))
            .json(&large_payload)
            .send()
    ).await;
    
    // The service should either:
    // 1. Accept and process the huge payload (vulnerability confirmed)
    // 2. Time out due to memory exhaustion
    // 3. Crash with OOM error
    
    match result {
        Ok(Ok(response)) => {
            println!("Vulnerability confirmed: Server accepted {} byte payload", 
                     large_payload.to_string().len());
            assert!(false, "Server should reject large payloads");
        }
        Ok(Err(e)) => {
            println!("Connection error (possible crash): {:?}", e);
        }
        Err(_) => {
            println!("Request timeout - service likely overwhelmed");
        }
    }
}

// Alternatively, using curl for manual testing:
// curl -X POST http://localhost:8082/construction/combine \
//   -H "Content-Type: application/json" \
//   -d @large_file.json
// 
// Where large_file.json is a multi-gigabyte JSON file
```

**To verify the vulnerability exists:**
1. Deploy a Rosetta API instance
2. Monitor memory usage (e.g., with `top` or `htop`)
3. Send a POST request with a 1 GB+ JSON body to any endpoint
4. Observe memory consumption spike and potential service crash

**Expected behavior after fix:**
- Requests exceeding the configured limit should be rejected with HTTP 413
- Memory usage should remain bounded regardless of request size
- Service should remain responsive under attack

## Notes

This vulnerability is particularly concerning because:

1. **Configuration exists but is unused**: The codebase already has `ApiConfig.content_length_limit` infrastructure [9](#0-8)  but the Rosetta API doesn't leverage it when constructing routes

2. **Inconsistent security practices**: The main Aptos API (using Poem framework) properly applies the content length limit [10](#0-9)  while the Rosetta API (using Warp) does not

3. **Production deployment impact**: Rosetta APIs are commonly deployed in production to support wallet integrations and blockchain indexers, making this a real-world attack surface

The fix is straightforward and should be applied consistently across all POST endpoints that accept request bodies.

### Citations

**File:** config/src/config/api_config.rs (L31-31)
```rust
    pub content_length_limit: Option<u64>,
```

**File:** config/src/config/api_config.rs (L155-160)
```rust
    pub fn content_length_limit(&self) -> u64 {
        match self.content_length_limit {
            Some(v) => v,
            None => DEFAULT_REQUEST_CONTENT_LENGTH_LIMIT,
        }
    }
```

**File:** crates/aptos-rosetta/src/construction.rs (L62-62)
```rust
        .and(warp::body::json())
```

**File:** crates/aptos-rosetta/src/account.rs (L40-40)
```rust
            .and(warp::body::json())
```

**File:** crates/aptos-rosetta/src/network.rs (L31-31)
```rust
        .and(warp::body::json())
```

**File:** crates/aptos-rosetta/src/block.rs (L23-23)
```rust
        .and(warp::body::json())
```

**File:** crates/aptos-warp-webserver/src/webserver.rs (L34-50)
```rust
    pub async fn serve<F>(&self, routes: F)
    where
        F: Filter<Error = Infallible> + Clone + Sync + Send + 'static,
        F::Extract: Reply,
    {
        match &self.tls_cert_path {
            None => warp::serve(routes).bind(self.address).await,
            Some(cert_path) => {
                warp::serve(routes)
                    .tls()
                    .cert_path(cert_path)
                    .key_path(self.tls_key_path.as_ref().unwrap())
                    .bind(self.address)
                    .await
            },
        }
    }
```

**File:** crates/aptos-telemetry-service/src/log_ingest.rs (L35-36)
```rust
        .and(warp::body::content_length_limit(MAX_CONTENT_LENGTH))
        .and(warp::body::aggregate())
```

**File:** crates/aptos-telemetry-service/src/constants.rs (L5-5)
```rust
pub const MAX_CONTENT_LENGTH: u64 = 1024 * 1024;
```

**File:** api/src/runtime.rs (L175-175)
```rust
    let size_limit = context.content_length_limit();
```
