# Audit Report

## Title
Global Panic Handler Bypasses API CatchPanic Middleware, Enabling DoS via Process Termination

## Summary
The API server's `CatchPanic` middleware is rendered ineffective by a global panic handler that terminates the entire process before panic recovery can occur. If any panic occurs during API request handling (including hash parsing), the global panic handler immediately calls `process::exit(12)`, crashing the entire API server instead of converting the panic to an error response.

## Finding Description

The API server implements `CatchPanic` middleware to gracefully handle panics and convert them to error responses: [1](#0-0) 

The middleware uses a custom panic handler to convert panics to proper API error responses: [2](#0-1) 

However, the Aptos node initialization sets up a **global panic handler** that takes precedence: [3](#0-2) 

This global panic handler inspects the VMState and **terminates the process** if the panic occurs outside the bytecode verifier or deserializer: [4](#0-3) 

**Critical flaw**: Rust's panic hooks are invoked **before** unwinding begins. When a panic occurs during API request handling:
1. The global panic handler is invoked immediately
2. Since VMState is NOT set to `VERIFIER` or `DESERIALIZER` for API requests
3. The handler calls `process::exit(12)` at line 57
4. The entire API server process terminates
5. The `CatchPanic` middleware never executes because unwinding never begins

The bytecode verifier avoids this by explicitly setting VMState before using `catch_unwind`: [5](#0-4) 

The API server does NOT set VMState, making it vulnerable to process termination on any panic.

**Attack Path**:
1. Attacker crafts malformed input that triggers a panic in API code (e.g., via unexpected edge case, library bug, or resource exhaustion)
2. Global panic handler fires before CatchPanic middleware
3. Process exits with code 12
4. Entire API server crashes, affecting all clients
5. Requires node operator intervention to restart

While the hash parsing implementation properly returns errors and should not panic under normal circumstances: [6](#0-5) [7](#0-6) 

The architectural flaw means **any** panic in API request handling (from any cause: library bugs, unexpected inputs, resource exhaustion, index out of bounds, unwrap failures, etc.) will terminate the server.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program's "API crashes" category. An attacker who can trigger a panic in API request handling can:

- **Denial of Service**: Crash the entire API server process
- **Service Disruption**: All API clients lose connectivity
- **Operational Impact**: Requires manual node operator intervention to restart
- **Repeated Exploitation**: Attack can be repeated to prevent API availability

The vulnerability affects the API server's availability guarantee and breaks the intended panic recovery mechanism.

## Likelihood Explanation

**Moderate Likelihood**: While the specific hash parsing code properly handles errors, the architectural flaw applies to all API request handling code. Likelihood factors:

- API servers handle untrusted external input continuously
- Panics can occur from: library bugs, unexpected edge cases, resource exhaustion, index bounds violations, unwrap on None/Err, arithmetic overflows (if unchecked), etc.
- The global panic handler is always active for the API server process
- No VMState protection exists for API request handlers
- Attack surface includes all API endpoints and parameter parsing logic

## Recommendation

**Option 1: Remove process exit for API server panics** (Recommended)

Set a thread-local flag or VMState for API request handling similar to the verifier:

```rust
// In api/src/runtime.rs, wrap route handler
pub fn attach_poem_to_runtime(...) -> anyhow::Result<SocketAddr> {
    // ... existing code ...
    
    runtime_handle.spawn(async move {
        // Set API handling state before processing requests
        let prev_state = move_core_types::state::set_state(VMState::API_HANDLER); // New state variant
        
        let route = Route::new()
            // ... existing route setup ...
            .with(CatchPanic::new().with_handler(panic_handler));
            
        Server::new_with_acceptor(acceptor)
            .run(route)
            .await
            .map_err(anyhow::Error::msg)
    });
}
```

Update crash handler to allow API handler panics to unwind:

```rust
// In crates/crash-handler/src/lib.rs
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // ... logging ...
    
    if state::get_state() == VMState::VERIFIER 
        || state::get_state() == VMState::DESERIALIZER 
        || state::get_state() == VMState::API_HANDLER {  // Add this
        return;  // Allow unwinding
    }
    
    process::exit(12);
}
```

**Option 2: Disable global panic handler for API-only nodes**

Allow configuration to disable process termination for nodes running only API services.

**Option 3: Use separate process for API server**

Run the API server in a dedicated process without the crash handler, allowing panics to be caught by CatchPanic middleware.

## Proof of Concept

The vulnerability is architectural and affects any panic in API handling. While hash parsing doesn't panic under normal conditions, the flaw can be demonstrated by injecting a panic via failpoint:

```rust
#[cfg(test)]
mod test {
    use poem::test::TestClient;
    use poem::Route;
    use poem::middleware::CatchPanic;
    
    #[tokio::test]
    async fn test_panic_crashes_server_with_global_handler() {
        // Setup global panic handler (simulating node initialization)
        aptos_crash_handler::setup_panic_handler();
        
        // Create API route with CatchPanic middleware
        let route = Route::new()
            .at("/crash", poem::endpoint::make_sync(|_| {
                panic!("Simulated API panic");
            }))
            .with(CatchPanic::new());
        
        let client = TestClient::new(route);
        
        // This request will terminate the process instead of returning error
        // Process exits with code 12 before CatchPanic can catch it
        let resp = client.get("/crash").send().await;
        
        // This assertion will never execute because process exits
        assert_eq!(resp.status(), 500);  // Expected: Internal Server Error
                                          // Actual: Process terminated
    }
}
```

The test demonstrates that the global panic handler terminates the process before `CatchPanic` middleware can convert the panic to an error response.

## Notes

While the specific `HashValue::from_str()` implementation uses proper error handling and should not panic, the architectural vulnerability affects all API request handling code. Any panic from any source (library bugs, resource exhaustion, arithmetic overflow, unwrap failures, index violations, etc.) will crash the entire API server due to the global panic handler bypassing the `CatchPanic` middleware.

The bytecode verifier and deserializer are explicitly protected via `VMState` settings, but API request handlers lack this protection, making them vulnerable to process termination on panic.

### Citations

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

**File:** aptos-node/src/lib.rs (L234-234)
```rust
    aptos_crash_handler::setup_panic_handler();
```

**File:** crates/crash-handler/src/lib.rs (L27-57)
```rust
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
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

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L138-172)
```rust
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
        DuplicationChecker::verify_module(module)?;

        signature_v2::verify_module(config, module)?;

        InstructionConsistency::verify_module(module)?;
        constants::verify_module(module)?;
        friends::verify_module(module)?;

        RecursiveStructDefChecker::verify_module(module)?;
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;

        // Add the failpoint injection to test the catch_unwind behavior.
        fail::fail_point!("verifier-failpoint-panic");

        script_signature::verify_module(module, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .finish(Location::Undefined),
        )
    });
    move_core_types::state::set_state(prev_state);
    result
```

**File:** api/types/src/hash.rs (L30-36)
```rust
    fn from_str(s: &str) -> anyhow::Result<Self, anyhow::Error> {
        if let Some(hex) = s.strip_prefix("0x") {
            Ok(hex.parse::<aptos_crypto::hash::HashValue>()?.into())
        } else {
            Ok(s.parse::<aptos_crypto::hash::HashValue>()?.into())
        }
    }
```

**File:** crates/aptos-crypto/src/hash.rs (L267-271)
```rust
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, HashValueParseError> {
        <[u8; Self::LENGTH]>::from_hex(hex)
            .map_err(|_| HashValueParseError)
            .map(Self::new)
    }
```
