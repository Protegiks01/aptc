# Audit Report

## Title
Legacy Gas Accumulation Failure in Native Function Error Paths (InvariantViolation)

## Summary
When native functions operate in legacy gas metering mode (gas_feature_version < 36), accumulated gas costs are lost if the function encounters an error that gets converted to `SafeNativeError::InvariantViolation`. This occurs because the error handling in `builder.rs` returns the error directly without wrapping the accumulated `legacy_gas_used` in a `NativeResult`, causing gas undercharging. [1](#0-0) 

## Finding Description

The vulnerability exists in the error handling flow for native functions when legacy gas metering is active:

1. **Legacy Gas Accumulation Setup**: When `gas_feature_version < RELEASE_V1_32` (36), native functions accumulate gas charges in `context.legacy_gas_used` instead of directly charging the gas meter. [2](#0-1) 

2. **Automatic Error Conversion**: Many native functions use the `?` operator on functions returning `PartialVMResult`. Due to an automatic `From<PartialVMError>` trait implementation, these errors are silently converted to `SafeNativeError::InvariantViolation`. [3](#0-2) 

3. **Gas Loss in Error Path**: When `InvariantViolation` errors are returned, the builder's error handling returns `Err(err)` directly, WITHOUT including the accumulated `legacy_gas_used`. [4](#0-3) 

4. **VM Propagates Error Without Gas Charging**: The interpreter's `call_native_impl` uses the `?` operator on the native function result, immediately propagating `PartialVMError` without charging any gas. [5](#0-4) 

**Attack Vectors Identified:**

- **Type Info Natives**: Functions like `type_of` and `type_name` charge base gas, then call `context.type_to_type_tag()` which can fail with `TYPE_TAG_LIMIT_EXCEEDED` or `UNKNOWN_INVARIANT_VIOLATION_ERROR`. [6](#0-5) 

- **BCS Serialization**: `constant_serialized_size` charges base gas before calling `type_to_type_layout()` which can fail. [7](#0-6) 

- **Code Publishing**: `native_request_publish` accumulates gas through multiple charges, then calls `value_as()` and helper functions that can return `PartialVMError`. [8](#0-7) 

## Impact Explanation

**Severity Assessment: Medium to Low (depending on deployment status)**

The vulnerability technically breaks the **Move VM Safety** and **Resource Limits** invariants by allowing gas-metered operations to execute without charging gas. However, the actual impact is LIMITED because:

1. **Legacy Mode Only**: This only affects networks running with `gas_feature_version < 36`. Modern Aptos networks use version 45+ with direct gas metering, completely bypassing this code path. [9](#0-8) 

2. **Partial Gas Loss**: Only the gas accumulated before the error is lost. The transaction still fails, limiting the attacker's ability to perform unbounded free computation.

3. **Deprecated Code Path**: The assertions in the builder indicate this is legacy code maintained for backward compatibility but not actively used on mainnet. [10](#0-9) 

**Potential Impact (if legacy mode were active):**
- Gas undercharging enabling resource exhaustion attacks
- Violation of deterministic gas metering guarantees  
- Potential DoS through repeated undercharged operations

## Likelihood Explanation

**Likelihood: Very Low to None (on active networks)**

While the code vulnerability is real, exploitation likelihood is minimal because:

1. **Modern Networks Use Direct Metering**: All active Aptos networks likely use gas_feature_version ≥ 36, which enables direct gas meter access and completely bypasses the vulnerable legacy path.

2. **Consensus Parameter**: The `gas_feature_version` is a network-wide consensus parameter. All validators must use the same version, preventing cross-validator inconsistencies.

3. **Error Conditions Are Edge Cases**: The errors that trigger this path (type tag limit exceeded, invariant violations) are typically validation errors that shouldn't occur with well-formed transactions.

4. **Limited Attacker Benefit**: Even if exploitable, attackers only save partial gas costs before the transaction fails, limiting the attack value.

## Recommendation

Despite low current risk, this should be fixed for code hygiene and to prevent future issues:

**Fix: Always Include Legacy Gas in InvariantViolation Path**

Modify the error handling in `builder.rs` to wrap `legacy_gas_used` even for invariant violations when in legacy mode:

```rust
InvariantViolation(err) => {
    // If in legacy mode, we still need to return the accumulated gas
    if !context.has_direct_gas_meter_access_in_native_context() {
        // Return an OutOfGas result to ensure gas is charged
        Ok(NativeResult::out_of_gas(context.legacy_gas_used))
    } else {
        Err(err)
    }
}
```

**Alternative: Remove Legacy Code Path Entirely**

If `gas_feature_version < 36` is no longer supported on any network, remove the legacy gas accumulation code entirely to eliminate this attack surface.

## Proof of Concept

```rust
// Conceptual PoC - would need full test harness to execute
// This demonstrates the vulnerable flow in legacy mode

#[test]
fn test_legacy_gas_loss_on_invariant_violation() {
    // Setup: Configure native context with gas_feature_version < 36
    // to enable legacy gas metering
    
    // Call a native function like type_info::type_of with:
    // - A type that will pass initial gas charging
    // - But fail in type_to_type_tag() due to TYPE_TAG_LIMIT_EXCEEDED
    
    // Expected: Transaction fails but gas IS charged for work done
    // Actual: Transaction fails and gas is NOT charged (vulnerability)
    
    // Example type that triggers the error:
    // A deeply nested generic type that exceeds max_cost in PseudoGasContext
    // e.g., vector<vector<vector<...>>> nested beyond type_max_cost limit
}
```

## Notes

This vulnerability represents a **code-level defect** in legacy error handling that technically violates gas metering invariants. However, its **practical exploitability is extremely limited** or non-existent on modern Aptos networks that use direct gas metering (version 36+). 

The issue is documented by the development team via a TODO comment acknowledging the problematic automatic error conversion, but given the migration to direct metering, this may have been deprioritized as legacy code that won't be executed. [11](#0-10) 

**Recommendation Priority**: Low - Fix for completeness and code hygiene, but not urgent for networks using modern gas metering.

### Citations

**File:** aptos-move/aptos-native-interface/src/builder.rs (L122-125)
```rust
            if context.has_direct_gas_meter_access_in_native_context() {
                assert_eq!(context.legacy_gas_used, 0.into());
                assert_eq!(legacy_heap_memory_usage, 0);
            }
```

**File:** aptos-move/aptos-native-interface/src/builder.rs (L131-166)
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
                    FunctionDispatch {
                        module_name,
                        func_name,
                        ty_args,
                        args,
                    } => Ok(NativeResult::CallFunction {
                        cost: context.legacy_gas_used,
                        module_name,
                        func_name,
                        ty_args,
                        args,
                    }),
                    LoadModule { module_name } => Ok(NativeResult::LoadModule { module_name }),
                },
            }
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L86-102)
```rust
        if self.has_direct_gas_meter_access_in_native_context() {
            self.gas_meter()
                .charge_native_execution(amount)
                .map_err(LimitExceededError::from_err)?;
            Ok(())
        } else {
            self.legacy_gas_used += amount;
            if self.legacy_gas_used > self.legacy_gas_budget()
                && self.legacy_enable_incremental_gas_charging
            {
                Err(SafeNativeError::LimitExceeded(
                    LimitExceededError::LegacyOutOfGas,
                ))
            } else {
                Ok(())
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

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1106-1106)
```rust
        let result = native_function(&mut native_context, ty_args, args)?;
```

**File:** aptos-move/framework/src/natives/type_info.rs (L55-57)
```rust
    context.charge(TYPE_INFO_TYPE_OF_BASE)?;

    let type_tag = context.type_to_type_tag(&ty_args[0])?;
```

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L180-183)
```rust
    context.charge(BCS_CONSTANT_SERIALIZED_SIZE_BASE)?;

    let ty = &ty_args[0];
    let ty_layout = context.type_to_type_layout(ty)?;
```

**File:** aptos-move/framework/src/natives/code.rs (L292-299)
```rust
    context.charge(CODE_REQUEST_PUBLISH_BASE)?;

    let policy = safely_pop_arg!(args, u8);
    let mut code = vec![];
    for module in safely_pop_arg!(args, Vec<Value>) {
        let module_code = module.value_as::<Vec<u8>>()?;

        context.charge(CODE_REQUEST_PUBLISH_PER_BYTE * NumBytes::new(module_code.len() as u64))?;
```

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L102-111)
```rust
    pub const RELEASE_V1_32: u64 = 36;
    pub const RELEASE_V1_33: u64 = 37;
    pub const RELEASE_V1_34: u64 = 38;
    pub const RELEASE_V1_35: u64 = 39;
    pub const RELEASE_V1_36: u64 = 40;
    pub const RELEASE_V1_37: u64 = 41;
    pub const RELEASE_V1_38: u64 = 42;
    pub const RELEASE_V1_39: u64 = 43;
    pub const RELEASE_V1_40: u64 = 44;
    pub const RELEASE_V1_41: u64 = 45;
```
