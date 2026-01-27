# Audit Report

## Title
Missing Content-Type Header in Faucet Metrics Server Enables Content Sniffing

## Summary
The metrics endpoint in the Aptos faucet metrics server does not explicitly set the `Content-Type: text/plain` header when serving Prometheus metrics, potentially allowing browser content sniffing attacks if user-controlled data appears in metric labels.

## Finding Description
The `metrics()` handler function returns raw `Vec<u8>` without explicitly setting HTTP response headers. [1](#0-0) 

When a web framework handler returns `Vec<u8>` directly without explicit Content-Type specification, the framework typically defaults to `application/octet-stream` or leaves the header unset. Without the proper `Content-Type: text/plain` header and without `X-Content-Type-Options: nosniff`, browsers may perform MIME type sniffing. If the metrics response contains HTML-like patterns (which can occur if user-controlled data is included in metric labels), browsers may interpret the content as HTML and execute embedded scripts, leading to Cross-Site Scripting (XSS).

This contrasts with other metrics endpoints in the codebase that explicitly set the correct Content-Type header. For example, the indexer-grpc metrics server explicitly sets the header: [2](#0-1) 

Similarly, the pepper service metrics handler sets the Content-Type: [3](#0-2) 

And the inspection service uses a constant for this purpose: [4](#0-3) 

The faucet metrics server only configures CORS but does not set security-relevant headers: [5](#0-4) 

## Impact Explanation
This is a **Low severity** issue per the Aptos bug bounty program. While it represents a security best practice violation, the practical exploitability is limited because:
- Requires a victim to directly navigate to the `/metrics` endpoint in a browser (uncommon)
- Requires user-controlled data in metrics to contain specific HTML/JavaScript patterns
- Metrics endpoints are typically accessed by Prometheus scrapers, not human users
- Modern browsers have built-in XSS protections
- The endpoint has no authentication to compromise

## Likelihood Explanation
The likelihood of exploitation is **low** because multiple conditions must be satisfied:
1. User-controlled data must be present in metric labels (e.g., from transaction data, error messages, or request paths)
2. This data must contain HTML/JavaScript patterns recognizable by browser content sniffers
3. A user must directly access the `/metrics` endpoint in a web browser
4. The browser must successfully sniff the content as HTML rather than treating it as plain text

## Recommendation
Explicitly set the `Content-Type` header to `text/plain` for Prometheus text format, consistent with all other metrics endpoints in the codebase. Additionally, set `X-Content-Type-Options: nosniff` to prevent content sniffing.

**Fixed implementation:**
```rust
#[handler]
fn metrics() -> poem::Response {
    let buffer = encode_metrics(TextEncoder);
    poem::Response::builder()
        .header(poem::http::header::CONTENT_TYPE, "text/plain")
        .header("X-Content-Type-Options", "nosniff")
        .body(buffer)
}
```

## Proof of Concept
```rust
// Test to verify the Content-Type header
#[tokio::test]
async fn test_metrics_content_type() {
    use poem::{test::TestClient, Route};
    
    let app = Route::new().at("/metrics", metrics);
    let cli = TestClient::new(app);
    
    let resp = cli.get("/metrics").send().await;
    resp.assert_status_is_ok();
    
    // Verify Content-Type is set correctly
    let content_type = resp.0.headers().get("content-type").unwrap();
    assert_eq!(content_type, "text/plain");
    
    // Verify X-Content-Type-Options is set
    let nosniff = resp.0.headers().get("x-content-type-options").unwrap();
    assert_eq!(nosniff, "nosniff");
}
```

## Notes
While this is classified as Low severity, it represents a deviation from security best practices that is consistently followed elsewhere in the Aptos codebase. The fix is trivial and aligns with the defensive security posture demonstrated by other metrics endpoints. The vulnerability does not impact consensus, state management, or any blockchain-critical functionality, but addressing it reduces the attack surface for potential XSS vectors.

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

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L214-216)
```rust
        Response::builder()
            .header("Content-Type", "text/plain")
            .body(encode_buffer)
```

**File:** keyless/pepper/service/src/metrics.rs (L90-93)
```rust
            hyper::Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(buffer))
```

**File:** crates/aptos-inspection-service/src/server/utils.rs (L14-15)
```rust
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_TEXT: &str = "text/plain";
```
