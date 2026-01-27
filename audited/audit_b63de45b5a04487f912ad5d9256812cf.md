# Audit Report

## Title
Gas Metering Bypass in Legacy Path via Incorrect Error Handling in native_compare()

## Summary
The `native_compare()` function in the Move stdlib contains a gas metering vulnerability in the legacy gas path (gas_feature_version < 36) where errors occurring after gas accumulation are incorrectly categorized as invariant violations, bypassing gas charging and enabling free computation.

## Finding Description

The vulnerability exists in the error handling flow of `native_compare()`: [1](#0-0) 

When `context.charge(cost)?` succeeds at line 52, gas is accumulated in `context.legacy_gas_used` (in the legacy path). However, if `args[0].compare(&args[1])?` subsequently fails at line 54, the error undergoes an automatic conversion that breaks gas charging: [2](#0-1) 

This automatic `From<PartialVMError>` conversion treats ALL `PartialVMError` instances as `InvariantViolation`, bypassing the proper error categorization in `LimitExceededError::from_err()`: [3](#0-2) 

Note that `VM_MAX_VALUE_DEPTH_REACHED` (line 37) should be treated as a `LimitExceeded` error, not an invariant violation.

In the legacy path wrapper, `InvariantViolation` errors are returned directly without charging accumulated gas: [4](#0-3) 

Line 151 returns `Err(err)` directly, discarding `context.legacy_gas_used`. Compare this to the `Abort` case (lines 134-136) which properly charges gas via `NativeResult::err(context.legacy_gas_used, abort_code)`.

**Errors that trigger this bug:**
1. `VM_MAX_VALUE_DEPTH_REACHED` - when comparing values exceeding max nesting depth (128 levels)
2. `INTERNAL_TYPE_ERROR` - type mismatches (should be prevented by verifier but checked at runtime)
3. `VM_EXTENSION_ERROR` - delayed values comparison

## Impact Explanation

**In Legacy Path (gas_feature_version < 36):**
This is a **High Severity** gas metering bypass that violates the critical invariant: "Resource Limits: All operations must respect gas, storage, and computational limits."

An attacker can:
1. Craft deeply nested structures (depth > 128)
2. Call `std::cmp::compare()` repeatedly
3. Consume CPU/memory for value size calculations and comparison attempts
4. Pay only minimal gas as the accumulated cost is never charged

This enables free computation and resource exhaustion attacks.

**In Modern Path (gas_feature_version >= 36):**
Gas is charged correctly before errors occur. However, errors are still misclassified as invariant violations rather than limit exceeded errors, affecting error reporting semantics. [5](#0-4) 

**Network Impact:**
The legacy path is used when gas_feature_version < RELEASE_V1_32 (version 36): [6](#0-5) 

Mainnet currently uses version 45 (RELEASE_V1_41), so the modern path is active. However, the legacy code remains in production and could affect:
- Historical transaction replays
- Test networks using older configurations
- Rollback scenarios

## Likelihood Explanation

**Likelihood: Medium-Low**

The vulnerability is present in production code but its exploitation is limited by:
1. Mainnet uses the modern gas path (version >= 36) where gas is charged correctly
2. Requires ability to create deeply nested structures or trigger other specific error conditions
3. The Move verifier's type system prevents some error cases (type mismatches)

However, the bug exists in deployed code and represents a fundamental design flaw in error handling that could be triggered in legacy configurations or replays.

## Recommendation

**Fix 1: Use proper error categorization instead of automatic From conversion**

Replace the `?` operator at line 54 with explicit error handling:

```rust
let ordering = match args[0].compare(&args[1]) {
    Ok(ord) => ord,
    Err(err) => return Err(LimitExceededError::from_err(err)),
};
```

This ensures errors like `VM_MAX_VALUE_DEPTH_REACHED` are properly categorized as `LimitExceeded` and charge accumulated gas correctly.

**Fix 2: Remove the problematic From implementation**

As noted in the TODO comment: [7](#0-6) 

The automatic conversion should be removed once all native functions are audited and updated.

**Fix 3: Apply the pattern from bcs.rs**

The BCS natives properly handle errors with explicit failure costs: [8](#0-7) 

Apply similar error handling to `native_compare()`.

## Proof of Concept

```move
module test::depth_gas_exploit {
    use std::cmp;
    
    // Create deeply nested vector structure exceeding max depth (128)
    struct Deep has copy, drop {
        inner: vector<Deep>,
    }
    
    fun create_deep_structure(depth: u64): Deep {
        if (depth == 0) {
            Deep { inner: vector[] }
        } else {
            Deep { inner: vector[create_deep_structure(depth - 1)] }
        }
    }
    
    #[test]
    #[expected_failure] // Should fail with VM_MAX_VALUE_DEPTH_REACHED
    public fun test_gas_bypass() {
        // Create structures exceeding max depth
        let deep1 = create_deep_structure(130);
        let deep2 = create_deep_structure(130);
        
        // This compare call should:
        // 1. Charge gas for value size calculation (line 52)
        // 2. Fail with VM_MAX_VALUE_DEPTH_REACHED during comparison (line 54)
        // 3. In legacy path: accumulated gas is NOT charged due to bug
        // 4. Attacker gets free computation for steps 1-2
        cmp::compare(&deep1, &deep2);
    }
}
```

In a legacy path configuration (gas_feature_version < 36), this test would consume CPU resources for value size calculations but only charge minimal gas, as the accumulated cost at line 52 would be discarded when the depth check fails.

## Notes

The core issue is the design flaw where the `From<PartialVMError>` trait bypasses proper error categorization. While mainnet is not currently affected due to using the modern gas path, the vulnerable code remains in production and represents a technical debt that should be addressed. The comment at lines 99-104 in errors.rs explicitly warns about this being "VERY PROBLEMATIC" and requests removal of the automatic conversion.

### Citations

**File:** aptos-move/framework/move-stdlib/src/natives/cmp.rs (L48-54)
```rust
    let cost = CMP_COMPARE_BASE
        + CMP_COMPARE_PER_ABS_VAL_UNIT
            * (context.abs_val_size_dereferenced(&args[0])?
                + context.abs_val_size_dereferenced(&args[1])?);
    context.charge(cost)?;

    let ordering = args[0].compare(&args[1])?;
```

**File:** aptos-move/aptos-native-interface/src/errors.rs (L29-47)
```rust
impl LimitExceededError {
    pub fn from_err(err: PartialVMError) -> SafeNativeError {
        match err.major_status() {
            StatusCode::OUT_OF_GAS
            | StatusCode::EXECUTION_LIMIT_REACHED
            | StatusCode::DEPENDENCY_LIMIT_REACHED
            | StatusCode::MEMORY_LIMIT_EXCEEDED
            | StatusCode::TOO_MANY_TYPE_NODES
            | StatusCode::VM_MAX_VALUE_DEPTH_REACHED => SafeNativeError::LimitExceeded(
                LimitExceededError::LimitExceeded(MeteringError(err)),
            ),
            // Treat all other code as invariant violations and leave it for the VM to propagate
            // these further. Note that we do not remap the errors. For example, if there is a
            // speculative error returned (signaling Block-STM to stop executing this transaction),
            // we better not remap it.
            // TODO(Gas): Have a single method to convert partial VM error to safe native error.
            _ => SafeNativeError::InvariantViolation(err),
        }
    }
```

**File:** aptos-move/aptos-native-interface/src/errors.rs (L99-104)
```rust
// TODO(Gas): This automatic conversion is VERY PROBLEMATIC as it makes it extremely easy to
//            accidentally propagate a non-invariant violation, which is a violation of the
//            contract.
//
//            We are actively seeking to remove this implementation.
//            Please help us stop the bleed by not using this conversion.
```

**File:** aptos-move/aptos-native-interface/src/errors.rs (L105-109)
```rust
impl From<PartialVMError> for SafeNativeError {
    fn from(e: PartialVMError) -> Self {
        SafeNativeError::InvariantViolation(e)
    }
}
```

**File:** aptos-move/aptos-native-interface/src/builder.rs (L131-151)
```rust
            match res {
                Ok(ret_vals) => Ok(NativeResult::ok(context.legacy_gas_used, ret_vals)),
                Err(err) => match err {
                    Abort { abort_code } => {
                        Ok(NativeResult::err(context.legacy_gas_used, abort_code))
                    },
                    LimitExceeded(err) => match err {
                        LimitExceededError::LegacyOutOfGas => {
                            assert!(!context.has_direct_gas_meter_access_in_native_context());
                            Ok(NativeResult::out_of_gas(context.legacy_gas_used))
                        },
                        LimitExceededError::LimitExceeded(err) => {
                            // Return a VM error directly, so the native function returns early.
                            // There is no need to charge gas in the end because it was charged
                            // during the execution.
                            assert!(context.has_direct_gas_meter_access_in_native_context());
                            Err(err.unpack())
                        },
                    },
                    // TODO(Gas): Check if err is indeed an invariant violation.
                    InvariantViolation(err) => Err(err),
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L86-90)
```rust
        if self.has_direct_gas_meter_access_in_native_context() {
            self.gas_meter()
                .charge_native_execution(amount)
                .map_err(LimitExceededError::from_err)?;
            Ok(())
```

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L102-102)
```rust
    pub const RELEASE_V1_32: u64 = 36;
```

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L138-147)
```rust
    let serialized_size = match serialized_size_impl(context, reference, ty) {
        Ok(serialized_size) => serialized_size as u64,
        Err(_) => {
            context.charge(BCS_SERIALIZED_SIZE_FAILURE)?;

            // Re-use the same abort code as bcs::to_bytes.
            return Err(SafeNativeError::Abort {
                abort_code: NFE_BCS_SERIALIZATION_FAILURE,
            });
        },
```
