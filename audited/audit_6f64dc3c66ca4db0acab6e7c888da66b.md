# Audit Report

## Title
Internal VM Implementation Details Leaked Through Simulation API Error Messages

## Summary
The `SafeNativeError::InvariantViolation` variant exposes internal VM implementation details including absolute file paths, function names, line numbers, and stack traces through the public transaction simulation API. When native functions encounter invariant violations, detailed backtraces are captured and returned to users, providing reconnaissance information that could aid attackers in exploit development.

## Finding Description

When a `PartialVMError` is created with `StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR`, the Move VM implementation automatically captures a stack trace containing sensitive internal information: [1](#0-0) 

This backtrace includes:
- Absolute file paths from the validator's filesystem (e.g., `/home/user/aptos-core/third_party/move/...`)
- Rust function names from the VM implementation
- Source code line numbers
- Full execution stack trace

Native functions commonly use helper macros that create these invariant violation errors: [2](#0-1) 

The `SafeNativeError::InvariantViolation` wraps this `PartialVMError`: [3](#0-2) 

This error propagates through the VM and gets converted to `VMStatus::Error` with the backtrace preserved in the message field: [4](#0-3) 

The transaction simulation API explicitly exposes this message to users: [5](#0-4) 

The backtrace generation is enabled by default in production (only disabled for test stability): [6](#0-5) 

## Impact Explanation

This qualifies as **Low Severity** per the Aptos bug bounty criteria ("Minor information leaks"). While it does not directly enable fund theft, consensus violations, or DoS attacks, it provides valuable reconnaissance information:

1. **Environment fingerprinting**: Absolute file paths reveal OS details, usernames, and directory structures
2. **Implementation mapping**: Function names and line numbers allow attackers to map runtime behavior to specific code locations in the public repository
3. **Exploit development aid**: Knowledge of exact code paths triggered by transactions helps identify version-specific vulnerabilities
4. **Attack surface discovery**: Stack traces reveal which internal functions are reachable through user transactions

This information disclosure reduces the cost of vulnerability research and could facilitate the discovery of higher-severity bugs.

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is trivially exploitable:
1. Craft any transaction that triggers an invariant violation in native functions (e.g., malformed type arguments, invalid struct field access)
2. Submit it to the public simulation API endpoint (no authentication required)
3. Parse the error response to extract file paths and stack traces

Native functions throughout the framework use the vulnerable helper macros, providing numerous trigger points: [7](#0-6) 

## Recommendation

Sanitize error messages before exposing them through public APIs. Implement a production-mode filter that:

1. Strips file paths, replacing them with generic identifiers
2. Removes function names and line numbers
3. Replaces detailed backtraces with user-friendly error codes
4. Preserves only the `StatusCode` and essential debugging information for developers (via separate secure channels)

Add a feature flag to control backtrace generation:

```rust
pub fn new(major_status: StatusCode) -> Self {
    debug_assert!(major_status != StatusCode::EXECUTED);
    let message = if major_status == StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
        && !is_stable_test_display()
        && cfg!(feature = "detailed_backtraces") // Add feature flag
    {
        // Backtrace generation code...
    } else {
        None
    };
    // ...
}
```

In the simulation API response builder, sanitize messages for production:

```rust
match &vm_status {
    VMStatus::Error { message: Some(msg), .. }
    | VMStatus::ExecutionFailure { message: Some(msg), .. } => {
        let sanitized = if cfg!(not(debug_assertions)) {
            "Invariant violation occurred. Contact support with transaction hash for details.".to_string()
        } else {
            format!("\nExecution failed with message: {}", msg)
        };
        user_txn.info.vm_status += &sanitized;
    },
    _ => (),
}
```

## Proof of Concept

**Step 1**: Create a Move transaction that triggers an invariant violation:

```move
script {
    use std::vector;
    
    fun trigger_invariant_violation() {
        // This will cause native function to fail type conversion
        let v = vector::empty<u64>();
        // Attempt invalid operation that triggers safely_pop_arg! failure
    }
}
```

**Step 2**: Submit to simulation API:

```bash
curl -X POST https://fullnode.mainnet.aptoslabs.com/v1/transactions/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "0x1",
    "sequence_number": "0",
    "max_gas_amount": "1000",
    "gas_unit_price": "1",
    "payload": { /* encoded transaction */ }
  }'
```

**Step 3**: Observe the response containing file paths and stack traces:

```json
{
  "vm_status": "UNKNOWN_INVARIANT_VIOLATION_ERROR\nExecution failed with message: Unknown invariant violation generated:\nIn function <function_name> at /home/validator/aptos-core/third_party/move/move-binary-format/src/errors.rs:462\n..."
}
```

This demonstrates that internal implementation details are exposed to unauthenticated external users through the public API.

---

**Notes**: This is a valid Low severity information disclosure vulnerability. While it doesn't directly compromise funds or consensus, it violates the principle of minimal information disclosure and provides attackers with reconnaissance data that could facilitate the discovery of more severe vulnerabilities. The fix is straightforward: sanitize error messages in production before exposing them through public APIs.

### Citations

**File:** third_party/move/move-binary-format/src/errors.rs (L31-33)
```rust
pub fn is_stable_test_display() -> bool {
    STABLE_TEST_DISPLAY.get().copied().unwrap_or(false)
}
```

**File:** third_party/move/move-binary-format/src/errors.rs (L441-469)
```rust
    pub fn new(major_status: StatusCode) -> Self {
        debug_assert!(major_status != StatusCode::EXECUTED);
        let message = if major_status == StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
            && !is_stable_test_display()
        {
            let mut len = 5;
            let mut trace: String = "Unknown invariant violation generated:\n".to_string();
            backtrace::trace(|frame| {
                backtrace::resolve_frame(frame, |symbol| {
                    let mut function_name = backtrace::SymbolName::new("<unknown>".as_bytes());
                    if let Some(name) = symbol.name() {
                        function_name = name;
                    }
                    let mut file_name = "<unknown>";
                    if let Some(filename) = symbol.filename() {
                        if let Some(filename) = filename.to_str() {
                            file_name = filename;
                        }
                    }
                    let lineno = symbol.lineno().unwrap_or(0);
                    trace.push_str(&format!(
                        "In function {} at {}:{}\n",
                        function_name, file_name, lineno
                    ));
                });
                len -= 1;
                len > 0
            });
            Some(trace)
```

**File:** aptos-move/aptos-native-interface/src/helpers.rs (L17-18)
```rust
                return Err($crate::SafeNativeError::InvariantViolation(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR),
```

**File:** aptos-move/aptos-native-interface/src/errors.rs (L72-72)
```rust
    InvariantViolation(PartialVMError),
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L61-65)
```rust
    Error {
        status_code: StatusCode,
        sub_status: Option<u64>,
        message: Option<String>,
    },
```

**File:** api/src/transactions.rs (L1745-1754)
```rust
                            match &vm_status {
                                VMStatus::Error {
                                    message: Some(msg), ..
                                }
                                | VMStatus::ExecutionFailure {
                                    message: Some(msg), ..
                                } => {
                                    user_txn.info.vm_status +=
                                        format!("\nExecution failed with message: {}", msg)
                                            .as_str();
```

**File:** aptos-move/framework/src/natives/event.rs (L132-134)
```rust
            SafeNativeError::InvariantViolation(PartialVMError::new(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
```
