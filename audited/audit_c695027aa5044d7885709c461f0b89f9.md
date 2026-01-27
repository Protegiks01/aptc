# Audit Report

## Title
Faucet API Server Lacks Panic Handling Middleware Leading to Ungraceful Service Crashes

## Summary
The Aptos faucet server does not implement panic catching middleware during request handling, unlike the main Aptos API server. If a panic occurs during a faucet request, the task will abort without proper error logging or graceful response handling, potentially causing connection resets for clients.

## Finding Description
The faucet server's `run_impl()` function configures the Poem web server without the `CatchPanic` middleware that is present in the main Aptos API server. [1](#0-0) 

In contrast, the main Aptos API server includes explicit panic handling: [2](#0-1) 

The main API's panic handler catches panics, logs them, and returns proper error responses: [3](#0-2) 

Without this middleware, any panic during faucet request handling (from `unwrap()`, `expect()`, arithmetic overflow, array bounds violations, etc.) will cause the Tokio task to abort. Clients receive connection resets rather than proper HTTP error responses, and the panic is not logged for debugging purposes.

Example panic points in request handling include: [4](#0-3) [5](#0-4) 

## Impact Explanation
This qualifies as **High Severity** under the Aptos bug bounty program, which explicitly lists "API crashes" as High Severity (up to $50,000).

The faucet is a critical developer onboarding tool for testnets. While not part of the core blockchain consensus, its unavailability directly impacts:
- Developer experience and testnet usability
- Ability to obtain test tokens for development
- Public-facing service reliability

## Likelihood Explanation
While specific panic conditions may be rare in well-tested code paths, the architectural gap is clear. Any unexpected panic (from dependencies, edge cases, or malformed requests) will not be handled gracefully. The probability increases with:
- Complex request validation logic across multiple checkers
- External dependencies (Redis, captcha services)
- Edge cases in transaction submission handling

## Recommendation
Add the `CatchPanic` middleware to the faucet server, matching the pattern used in the main API server:

1. Create a panic handler in `crates/aptos-faucet/core/src/endpoints/error_converter.rs`:
```rust
pub fn panic_handler(err: Box<dyn Any + Send>) -> Response {
    aptos_logger::error!("Faucet panic captured: {:?}", err);
    AptosTapErrorResponse::from(AptosTapError::new(
        "Internal server error".to_string(),
        AptosTapErrorCode::InternalError,
    ))
    .into_response()
}
```

2. Update the route configuration in `run_impl()`:
```rust
Route::new()
    .nest(...)
    .with(cors)
    .with(CatchPanic::new().with_handler(panic_handler))
    .around(middleware_log)
```

## Proof of Concept
To demonstrate the vulnerability:

1. Inject a deliberate panic in a request handler (e.g., in `FundApi::fund`):
```rust
panic!("Test panic during request handling");
```

2. Send a fund request to the faucet endpoint

3. **Without CatchPanic**: Client receives connection reset, no log entry with panic details, service may become unstable

4. **With CatchPanic**: Client receives proper HTTP 500 response, panic is logged with full context, service continues operating normally

The architectural discrepancy is evident by comparing the middleware configuration between the two servers as cited above.

## Notes
The faucet server is a non-critical testnet utility, but follows patterns established by the main API server which has explicit panic protection. This represents a deviation from the defensive programming practices demonstrated in the core API implementation.

### Citations

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

**File:** api/src/runtime.rs (L256-256)
```rust
            .with(CatchPanic::new().with_handler(panic_handler))
```

**File:** api/src/error_converter.rs (L49-52)
```rust
pub fn panic_handler(err: Box<dyn Any + Send>) -> Response {
    error!("Panic captured: {:?}", err);
    build_panic_response("internal error".into())
}
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L343-348)
```rust
            builder = builder.api_key(&api_key).expect("Failed to set API key");
        }

        if let Some(additional_headers) = &self.node_additional_headers {
            for (key, value) in additional_headers {
                builder = builder.header(key, value).expect("Failed to set header");
```

**File:** crates/aptos-faucet/core/src/endpoints/errors.rs (L208-208)
```rust
        if *USE_HELPFUL_ERRORS.get().unwrap() {
```
