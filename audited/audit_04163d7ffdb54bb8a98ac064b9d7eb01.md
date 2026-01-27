# Audit Report

## Title
Multiple Panic Paths in Node-Checker Causing Service Crash Instead of Error Handling

## Summary
The node-checker component contains multiple `.unwrap()` calls that can cause panic and crash the checker service when processing user-supplied URLs, rather than returning proper error responses. This affects availability of the node-checker service.

## Finding Description

The `build_version.rs` checker depends on `SystemInformationProvider` and `NodeAddress` utilities that contain multiple panic paths when handling URLs. These panic paths violate Rust's error handling best practices by using `.unwrap()` on operations that can fail with user-controlled input.

**Primary panic path in SystemInformationProvider:** [1](#0-0) 

This `url.set_port(Some(metrics_port)).unwrap()` call will panic if the URL scheme doesn't support ports (e.g., `file://`, `mailto:`, `data:` URIs). The `Url::set_port()` method returns `Result<(), ()>` and fails when the URL is a "cannot-be-a-base" URL.

**Additional panic paths in NodeAddress:** [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Attack vector:**
A user can send a request to the node-checker's `/check` endpoint with a URL using a non-HTTP scheme: [6](#0-5) 

The URL parameter is parsed by the `url` crate which accepts many valid URL schemes beyond HTTP/HTTPS (e.g., `file:///path`, `mailto:user@example.com`). When the checker attempts to set a port on such URLs, the unwrap causes a panic and crashes the service.

## Impact Explanation

This is a **Low Severity** issue per the Aptos bug bounty criteria:
- Categorized as "Non-critical implementation bugs"
- Only affects the node-checker service, not blockchain consensus, validator nodes, or fund security
- Results in denial-of-service on the checker API, not the blockchain itself
- No impact on critical invariants (consensus safety, deterministic execution, state consistency)

The node-checker is an ancillary monitoring tool, not a critical blockchain component. A crash only affects health-check availability, not blockchain operation.

## Likelihood Explanation

**Likelihood: Moderate**
- Attack is trivial - requires only sending a single HTTP request with a malformed URL parameter
- Public node-checker endpoints would be vulnerable to any internet user
- No authentication or special permissions required
- The `url` crate is permissive and will parse many non-HTTP schemes
- No validation exists to enforce HTTP/HTTPS schemes before calling `set_port()`

## Recommendation

Replace all `.unwrap()` calls with proper error handling using `?` operator or explicit error mapping:

```rust
// In SystemInformationProvider::new
url.set_port(Some(metrics_port))
    .map_err(|_| anyhow!("Cannot set port on URL scheme: {}", url.scheme()))?;

// In NodeAddress methods
url.set_port(Some(port))
    .context("Failed to set port on URL - scheme may not support ports")?;

// For reqwest::ClientBuilder
reqwest::ClientBuilder::new()
    .timeout(timeout)
    .cookie_provider(self.cookie_store.clone())
    .build()
    .context("Failed to build HTTP client")?
```

Additionally, add URL scheme validation at the API entry point:

```rust
// In api.rs check() method after line 81
if node_url.0.scheme() != "http" && node_url.0.scheme() != "https" {
    return Err(poem::Error::from((
        StatusCode::BAD_REQUEST,
        anyhow!("URL must use http:// or https:// scheme, got: {}", node_url.0.scheme()),
    )));
}
```

## Proof of Concept

```bash
# Send request with file:// URL to node-checker endpoint
curl "http://node-checker-api/check?baseline_configuration_id=devnet_fullnode&node_url=file:///etc/passwd&metrics_port=9101"

# Expected: Service panics and crashes with thread panic message
# Actual behavior: Should return HTTP 400 error with proper error message
```

Rust test to demonstrate the panic:

```rust
#[test]
#[should_panic(expected = "cannot set port")]
fn test_set_port_panic_on_file_url() {
    let mut url = Url::parse("file:///etc/passwd").unwrap();
    url.set_port(Some(9101)).unwrap(); // This will panic
}
```

---

**Notes:**
While this vulnerability is real and exploitable, it only affects the node-checker service availability, not blockchain security. The impact is limited to DoS on the monitoring tool. Per the strict validation criteria requiring Critical/High/Medium severity for full vulnerability reports, this Low severity finding may not meet the reporting threshold depending on program scope.

### Citations

**File:** ecosystem/node-checker/src/provider/system_information.rs (L45-45)
```rust
        url.set_port(Some(metrics_port)).unwrap();
```

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L75-79)
```rust
        url.set_port(Some(
            self.api_port
                .context("Can't build API URL without an API port")?,
        ))
        .unwrap();
```

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L85-89)
```rust
        url.set_port(Some(
            self.api_port
                .context("Can't build metrics URL without a metrics port")?,
        ))
        .unwrap();
```

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L96-100)
```rust
            Some(_) => Ok(reqwest::ClientBuilder::new()
                .timeout(timeout)
                .cookie_provider(self.cookie_store.clone())
                .build()
                .unwrap()),
```

**File:** ecosystem/node-checker/src/configuration/node_address.rs (L108-112)
```rust
        let client = reqwest::ClientBuilder::new()
            .timeout(timeout)
            .cookie_provider(self.cookie_store.clone())
            .build()
            .unwrap();
```

**File:** ecosystem/node-checker/src/server/api.rs (L81-87)
```rust
        let target_node_address = NodeAddress::new(
            node_url.0,
            api_port.0,
            metrics_port.0,
            noise_port.0,
            public_key,
        );
```
