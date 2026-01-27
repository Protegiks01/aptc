# Audit Report

## Title
Global Panic Handler Crashes NFT Metadata Crawler Service on Request Handler Panics

## Summary
The NFT metadata crawler's asset uploader API lacks request-level panic catching middleware, combined with a global panic handler that terminates the entire process. Any panic in request handlers (including the potential unwrap panic at line 32 of `upload_batch.rs`) will crash the entire service, causing a denial-of-service for all users. [1](#0-0) 

## Finding Description
The vulnerability stems from three architectural issues working in combination:

**1. Unsafe Unwrap in Request Handler:**
The `upload_batch()` function contains an unwrap operation that assumes database query results are always non-null based on SQL filtering, without defensive error handling. [1](#0-0) 

**2. Process-Terminating Panic Handler:**
The NFT metadata crawler uses the indexer-grpc-server-framework which installs a global panic handler at startup that immediately exits the process with code 12 on any panic. [2](#0-1) 

**3. No Request-Level Panic Catching:**
The Axum router has no panic-catching middleware layer, only an `Extension` layer for dependency injection. This means panics propagate directly to the global handler. [3](#0-2) 

When the handler panics, the global panic hook executes before Tokio's task-level panic handling, triggering `process::exit(12)` and terminating the entire service. [4](#0-3) 

## Impact Explanation
**Severity: Medium** (per Aptos Bug Bounty criteria)

This qualifies as an API crash vulnerability affecting service availability:
- **Complete Service Outage**: A single panic in any request handler terminates the entire process
- **All Users Affected**: Not just the request that triggered the panic, but all concurrent and subsequent users
- **Manual Recovery Required**: Service remains down until manually restarted
- **No Data Loss**: Does not affect blockchain consensus or stored data

While this impacts availability, it does not affect core blockchain operations, consensus, or validator nodes. The NFT metadata crawler is an ecosystem indexer service separate from the core protocol.

## Likelihood Explanation
**Likelihood: Low to Medium**

The unwrap panic could be triggered by:
- Database corruption or inconsistencies
- Schema migration mismatches between code and database
- Diesel ORM edge cases where `is_not_null()` filter doesn't guarantee `Some` values
- Concurrent database modifications in rare race conditions

However, attackers cannot directly trigger this through malicious input alone. The vulnerability requires either:
1. Existing database integrity issues
2. Deployment/migration errors
3. Diesel implementation quirks

The more significant issue is that ANY panic anywhere in request handling will crash the service, creating multiple potential trigger points beyond just this unwrap.

## Recommendation
Implement defense-in-depth by adding request-level panic catching:

**Option 1: Add Tower CatchPanic Middleware (Recommended)**
```rust
use tower_http::catch_panic::CatchPanicLayer;

fn build_router(&self) -> axum::Router {
    let self_arc = Arc::new(self.clone());
    axum::Router::new()
        .route("/upload", post(Self::handle_upload_batch))
        .route("/status/:application_id/:idempotency_key", get(Self::handle_get_status))
        .layer(Extension(self_arc.clone()))
        .layer(CatchPanicLayer::new())  // Add panic catching
}
```

**Option 2: Remove Unsafe Unwrap**
```rust
for url in &request.urls {
    if let Some(cdn_image_uri) = existing_rows.get(url.as_str()) {
        let cdn_uri = match cdn_image_uri.as_deref() {
            Some(uri) => uri,
            None => {
                error!("Database returned null cdn_image_uri despite is_not_null filter");
                continue; // Skip or return error
            }
        };
        request_statuses.push(AssetUploaderRequestStatuses::new_completed(
            &request.idempotency_tuple,
            url.as_str(),
            cdn_uri,
        ));
    } else {
        // existing else branch
    }
}
```

**Option 3: Modify Global Panic Handler**
Only exit for panics in main task threads, not request handlers. However, this is more complex and Option 1 is preferred.

## Proof of Concept
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use diesel::r2d2::Pool;
    use diesel::r2d2::ConnectionManager;
    
    #[test]
    #[should_panic]
    fn test_unwrap_panic_on_none() {
        // Simulate the scenario where database returns None despite filter
        let cdn_image_uri: Option<String> = None;
        
        // This is what happens at line 32 - will panic
        let _result = cdn_image_uri.as_deref().unwrap();
        
        // Without panic catching middleware, this propagates to global handler
        // which calls process::exit(12), crashing the entire service
    }
}
```

To demonstrate the service crash:
1. Deploy the NFT metadata crawler with the current code
2. Cause a database integrity issue (e.g., manually set `cdn_image_uri` to NULL in a row)
3. Send an upload request containing that URL
4. Observe the entire service process terminates with exit code 12
5. All other users' requests fail until service restart

## Notes
- This vulnerability affects the NFT metadata crawler ecosystem service, not core blockchain consensus or validator operations
- The impact is limited to availability of the indexer API service
- The architectural pattern of using process-terminating panic handlers is appropriate for main application threads but problematic for request handlers
- Similar issues may exist in other ecosystem services using the `indexer-grpc-server-framework` without panic-catching middleware

### Citations

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/upload_batch.rs (L28-33)
```rust
        if let Some(cdn_image_uri) = existing_rows.get(url.as_str()) {
            request_statuses.push(AssetUploaderRequestStatuses::new_completed(
                &request.idempotency_tuple,
                url.as_str(),
                cdn_image_uri.as_deref().unwrap(), // Safe to unwrap because we checked for existence when querying
            ));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L149-168)
```rust
pub fn setup_panic_handler() {
    std::panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());
    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);
    // Kill the process
    process::exit(12);
}
```

**File:** ecosystem/nft-metadata-crawler/src/asset_uploader/api/mod.rs (L138-149)
```rust
impl Server for AssetUploaderApiContext {
    fn build_router(&self) -> axum::Router {
        let self_arc = Arc::new(self.clone());
        axum::Router::new()
            .route("/upload", post(Self::handle_upload_batch))
            .route(
                "/status/:application_id/:idempotency_key",
                get(Self::handle_get_status),
            )
            .layer(Extension(self_arc.clone()))
    }
}
```
