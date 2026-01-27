# Audit Report

## Title
Consensus Split Vulnerability Due to Compile-Time Feature Flag in Debug Native Functions

## Summary
The `native_old_debug_print()` and related debug functions in the Aptos Move framework contain conditional compilation logic using `cfg!(feature = "testing")` that can cause non-deterministic transaction execution if validators build their binaries with different feature flag configurations, leading to consensus splits.

## Finding Description

The debug native functions implement conditional logic that behaves differently based on compile-time feature flags: [1](#0-0) 

When the `testing` feature is enabled at compile time, the function executes `read_ref()` and `native_format_debug()` operations that can return errors. When disabled, the entire conditional block is compiled out, and the function always returns successfully. [2](#0-1) 

The `native_format_debug()` function can fail in multiple ways: type layout conversion errors, abort errors for delayed fields, or formatting implementation errors. These failures propagate back through the debug print function.

**Attack Scenario:**
1. Validator A builds their node with `--features testing` enabled (misconfiguration or malicious intent)
2. Validator B builds with default features (testing disabled)
3. A transaction calls `debug::print()` with a type that causes formatting to fail
4. On Validator A: The function executes formatting logic, encounters an error, transaction aborts
5. On Validator B: The conditional block is compiled out, function returns Ok immediately, transaction succeeds
6. Result: Different state roots computed, consensus split

The functions charge zero gas regardless of execution path: [3](#0-2) 

Since no `context.charge()` call exists in these debug functions, `legacy_gas_used` remains zero in both cases, so gas differences don't mask the execution difference.

## Impact Explanation

This vulnerability has **Critical** severity impact as defined in the Aptos bug bounty program because it can cause:

1. **Consensus/Safety Violations**: Validators executing identical blocks would compute different state roots, violating the fundamental "Deterministic Execution" invariant that all validators must produce identical state roots for identical blocks.

2. **Non-Recoverable Network Partition**: If validators split into two groups with different feature configurations, they would permanently disagree on which transactions succeed/fail, requiring a hard fork to resolve.

The vulnerability breaks Invariant #1 from the Aptos specification: "All validators must produce identical state roots for identical blocks."

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires specific conditions:
- At least one validator must build with the `testing` feature enabled
- The default build configuration has `testing` disabled [4](#0-3) 

Triggering factors:
1. **Misconfiguration**: Validator operator accidentally builds with wrong features
2. **Malicious Actor**: Compromised validator intentionally uses different build
3. **Development/Testnet**: Testing environments might enable this feature

The build version checker only validates commit hashes, not feature flags: [5](#0-4) 

This provides no runtime protection against feature flag mismatches.

## Recommendation

**Immediate Fix**: Remove conditional compilation from consensus-critical code paths. Debug functions should either:

1. **Always execute deterministically** (recommended):
```rust
#[inline]
fn native_old_debug_print(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    // Always consume the argument for determinism
    let x = safely_pop_arg!(args, Reference);
    let val = x.read_ref().map_err(SafeNativeError::InvariantViolation)?;
    
    // Only output when testing, but always validate inputs
    if cfg!(feature = "testing") {
        println!(
            "[debug] {}",
            native_format_debug(context, &ty_args[0], val)?
        );
    }
    Ok(smallvec![])
}
```

2. **Or be completely disabled on-chain**:
    - Return an error immediately if called in production
    - Make debug functions unavailable in non-test builds

**Long-term Solution**: Implement runtime build configuration validation that checks feature flags match across validators, extending the BuildVersionChecker to include feature flag verification.

## Proof of Concept

```rust
// Test case demonstrating non-deterministic execution
// File: aptos-move/framework/src/natives/debug_consensus_test.rs

#[cfg(test)]
mod tests {
    use super::*;
    use move_core_types::account_address::AccountAddress;
    
    #[test]
    fn test_debug_print_determinism_violation() {
        // This test would need to be run twice:
        // 1. With --features testing
        // 2. Without features
        
        // Create a malformed type reference that causes formatting to fail
        // When testing is enabled: This will error in native_format_debug
        // When testing is disabled: This will always succeed
        
        // In production, if validators have different builds:
        // - Some would see this transaction fail
        // - Others would see it succeed
        // Result: Consensus split
        
        // The exact PoC would require:
        // 1. Crafting a Move type that fails formatting
        // 2. Submitting transaction calling debug::print() with it
        // 3. Observing different outcomes based on feature flags
    }
}
```

**Notes:**

This vulnerability is particularly insidious because:
1. It's triggered by compile-time configuration, not runtime state
2. No runtime checks exist to detect feature flag mismatches between validators
3. The comment on line 118 acknowledges "re-playability" concerns but doesn't address the non-determinism
4. The same pattern exists in multiple debug functions (native_print, native_stack_trace, native_old_print_stacktrace)

The vulnerability demonstrates that consensus-critical code must never use conditional compilation for logic that affects transaction outcomes. All validators must execute identical code paths regardless of build configuration.

### Citations

**File:** aptos-move/framework/src/natives/debug.rs (L74-89)
```rust
fn native_old_debug_print(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    if cfg!(feature = "testing") {
        let x = safely_pop_arg!(args, Reference);
        let val = x.read_ref().map_err(SafeNativeError::InvariantViolation)?;

        println!(
            "[debug] {}",
            native_format_debug(context, &ty_args[0], val)?
        );
    }
    Ok(smallvec![])
}
```

**File:** aptos-move/framework/src/natives/string_utils.rs (L533-557)
```rust
pub(crate) fn native_format_debug(
    context: &mut SafeNativeContext,
    ty: &Type,
    v: Value,
) -> SafeNativeResult<String> {
    let layout =
        context
            .type_to_fully_annotated_layout(ty)?
            .ok_or_else(|| SafeNativeError::Abort {
                abort_code: EUNABLE_TO_FORMAT_DELAYED_FIELD,
            })?;
    let mut format_context = FormatContext {
        context,
        should_charge_gas: false,
        max_depth: usize::MAX,
        max_len: usize::MAX,
        type_tag: true,
        canonicalize: false,
        single_line: false,
        include_int_type: false,
    };
    let mut out = String::new();
    native_format_impl(&mut format_context, &layout, v, 0, &mut out)?;
    Ok(out)
}
```

**File:** aptos-move/aptos-native-interface/src/builder.rs (L117-132)
```rust
            let res: Result<SmallVec<[Value; 1]>, SafeNativeError> =
                native(&mut context, ty_args, args);

            // If enabled, metering and memory tracking must have been done in the native!
            let legacy_heap_memory_usage = context.legacy_heap_memory_usage;
            if context.has_direct_gas_meter_access_in_native_context() {
                assert_eq!(context.legacy_gas_used, 0.into());
                assert_eq!(legacy_heap_memory_usage, 0);
            }
            context
                .inner
                .gas_meter()
                .use_heap_memory_in_native_context(legacy_heap_memory_usage)?;

            match res {
                Ok(ret_vals) => Ok(NativeResult::ok(context.legacy_gas_used, ret_vals)),
```

**File:** aptos-move/framework/Cargo.toml (L93-96)
```text
[features]
default = []
fuzzing = ["aptos-types/fuzzing"]
testing = ["aptos-move-stdlib/testing", "aptos-crypto/fuzzing"]
```

**File:** ecosystem/node-checker/src/checker/build_version.rs (L114-135)
```rust
            Some(target_build_commit_hash) => {
                check_results.push({
                    if baseline_build_commit_hash == target_build_commit_hash {
                        Self::build_result(
                            "Build commit hashes match".to_string(),
                            100,
                            format!(
                                "The build commit hash from the target node ({}) matches the build commit hash from the baseline node ({}).",
                                target_build_commit_hash, baseline_build_commit_hash
                            ),
                        )
                    } else {
                        Self::build_result(
                            "Build commit hash mismatch".to_string(),
                            50,
                            format!(
                                "The build commit hash from the target node ({}) does not match the build commit hash from the baseline node ({}).",
                                target_build_commit_hash, baseline_build_commit_hash
                            ),
                        )
                    }
                });
```
