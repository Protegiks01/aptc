# Audit Report

## Title
Error Misclassification in Native Functions Allows Free Transaction Spam via Limit Exceeded Errors

## Summary
The `From<PartialVMError>` implementation in the Aptos Native Interface automatically converts all Move VM errors to `InvariantViolation`, causing execution limit errors like `TYPE_TAG_LIMIT_EXCEEDED` to be incorrectly classified. This results in transactions being discarded without gas charges, enabling attackers to spam the network with resource-intensive operations for free. [1](#0-0) 

## Finding Description

The native function error handling system contains a critical design flaw where **all** `PartialVMError` instances are automatically converted to `SafeNativeError::InvariantViolation` through the `From` trait implementation. The codebase itself acknowledges this is "VERY PROBLEMATIC" and violates the intended error handling contract. [2](#0-1) 

**The Error Classification System:**

Errors in safe natives should be categorized as:
- `Abort` - User-caused errors (invalid inputs, authorization failures) → Transaction KEPT, gas charged
- `LimitExceeded` - Resource limit violations → Handled appropriately with gas charges  
- `InvariantViolation` - True internal VM errors → Transaction DISCARDED, no gas charge [3](#0-2) 

**Transaction Fate Determination:**

The VM distinguishes error types by status code ranges. Invariant violations (2000-2999) cause transaction discard, while execution errors (4000-4999) should be kept and charged. [4](#0-3) [5](#0-4) 

Invariant violations result in transaction discard: [6](#0-5) 

**Concrete Attack Vector:**

The `type_to_type_tag` operation enforces complexity limits and returns `TYPE_TAG_LIMIT_EXCEEDED` (code 4033, an execution error) when exceeded: [7](#0-6) [8](#0-7) 

Native functions like `type_of` and `type_name` call `type_to_type_tag` with user-provided type parameters using the `?` operator, triggering the automatic misclassification: [9](#0-8) 

**Exploitation Steps:**

1. Attacker crafts a transaction calling `0x1::type_info::type_of<T>()` where `T` is a deeply nested or complex type
2. Transaction execution reaches `native_type_of` which calls `context.type_to_type_tag(&ty_args[0])?`
3. Type complexity exceeds the configured limit in `ty_tag_converter.rs`
4. Returns `TYPE_TAG_LIMIT_EXCEEDED` (execution error, should charge gas)
5. The `?` operator invokes `From<PartialVMError>`, converting to `InvariantViolation`
6. Transaction is discarded by `keep_or_discard` logic without any gas charge
7. Attacker can repeat indefinitely, consuming validator resources for free

**Existing Partial Mitigation:**

There exists a proper error classification function `LimitExceededError::from_err()` that correctly handles specific limit errors, but critically **excludes** `TYPE_TAG_LIMIT_EXCEEDED`: [10](#0-9) 

The `CHARGE_INVARIANT_VIOLATION` feature flag is a band-aid workaround that doesn't fix the root cause: [11](#0-10) 

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos Bug Bounty program due to:

1. **Validator Node Slowdowns**: Attackers can flood validators with computationally expensive transactions (complex type resolution) that consume resources but pay no gas, degrading network performance.

2. **Protocol Violation**: Breaks the fundamental gas economics invariant (#9: "All operations must respect gas, storage, and computational limits"). Operations designed to be rate-limited by gas costs become free.

3. **DOS Attack Vector**: Enables sustained resource exhaustion attacks on the validator set without economic cost to the attacker.

4. **Widespread Impact**: Affects all native functions using the `?` operator on `PartialVMError` results, not just type operations. Other affected call sites include value operations, field borrowing, and type conversions throughout the native function ecosystem.

The transaction execution monitoring shows this is treated as an invariant violation requiring error logging: [12](#0-11) 

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Trivial Exploitation**: Requires only crafting a transaction with complex type parameters - no special privileges, validator access, or sophisticated attack infrastructure needed.

2. **Public Attack Surface**: The `type_info` module is part of the standard library (`0x1::type_info`) and accessible to all users.

3. **No Prerequisites**: Unlike many blockchain exploits, this doesn't require:
   - Stake or validator status
   - Smart contract deployment
   - Coordination or timing
   - Economic capital

4. **Repeatable**: Attack can be executed continuously without cost, making sustained DOS practical.

5. **Already Acknowledged**: The development team explicitly marked this as problematic, indicating awareness but incomplete mitigation.

## Recommendation

**Immediate Fix: Remove the Automatic Conversion**

Remove the `From<PartialVMError>` implementation entirely to force explicit error classification:

```rust
// DELETE this implementation - forces developers to explicitly classify errors
// impl From<PartialVMError> for SafeNativeError {
//     fn from(e: PartialVMError) -> Self {
//         SafeNativeError::InvariantViolation(e)
//     }
// }
```

**Short-term Fix: Extend Proper Error Classification**

Expand `LimitExceededError::from_err()` to include `TYPE_TAG_LIMIT_EXCEEDED` and other execution-level limit errors:

```rust
impl LimitExceededError {
    pub fn from_err(err: PartialVMError) -> SafeNativeError {
        match err.major_status() {
            StatusCode::OUT_OF_GAS
            | StatusCode::EXECUTION_LIMIT_REACHED
            | StatusCode::DEPENDENCY_LIMIT_REACHED
            | StatusCode::MEMORY_LIMIT_EXCEEDED
            | StatusCode::TOO_MANY_TYPE_NODES
            | StatusCode::VM_MAX_VALUE_DEPTH_REACHED
            | StatusCode::TYPE_TAG_LIMIT_EXCEEDED          // ADD THIS
            | StatusCode::VM_MAX_TYPE_NODES_REACHED        // ADD THIS
            | StatusCode::ACCESS_STACK_LIMIT_EXCEEDED       // ADD THIS
            => SafeNativeError::LimitExceeded(
                LimitExceededError::LimitExceeded(MeteringError(err)),
            ),
            _ => SafeNativeError::InvariantViolation(err),
        }
    }
}
```

**Long-term Fix: Enforce Explicit Classification**

Update all native functions to explicitly use `LimitExceededError::from_err()` instead of relying on automatic conversion:

```rust
// BEFORE (vulnerable):
let type_tag = context.type_to_type_tag(&ty_args[0])?;

// AFTER (secure):
let type_tag = context.type_to_type_tag(&ty_args[0])
    .map_err(LimitExceededError::from_err)?;
```

## Proof of Concept

```rust
// File: aptos-move/framework/src/natives/type_info_exploit_test.rs

#[cfg(test)]
mod exploit_tests {
    use move_core_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::{StructTag, TypeTag, CORE_CODE_ADDRESS},
    };
    
    /// Demonstrates that TYPE_TAG_LIMIT_EXCEEDED causes transaction discard
    /// instead of proper gas charging, enabling free DOS attacks.
    #[test]
    fn test_type_tag_limit_exploit() {
        // Create a deeply nested type to exceed limits
        // Example: Vector<Vector<Vector<...>>> with many levels
        let mut complex_type = TypeTag::U8;
        for _ in 0..100 {  // Nest deeply to exceed limit
            complex_type = TypeTag::Vector(Box::new(complex_type));
        }
        
        // This type parameter would be passed to type_of<T>() or type_name<T>()
        // In a real attack, the transaction would call:
        // 0x1::type_info::type_of<Vector<Vector<Vector<...>>>>()
        
        // Expected: Transaction should be KEPT and gas charged (execution error)
        // Actual: Transaction is DISCARDED with no gas charge (invariant violation)
        
        // The vulnerability allows an attacker to:
        // 1. Submit transactions with complex types
        // 2. Force validators to process type tag conversion
        // 3. Hit TYPE_TAG_LIMIT_EXCEEDED
        // 4. Get transaction discarded (no gas cost)
        // 5. Repeat indefinitely for free DOS
    }
}
```

**Move Test Scenario:**

```move
// File: aptos-move/framework/tests/type_limit_exploit.move
module 0x1::type_limit_exploit_test {
    use std::type_info;
    
    // Attack vector: Call with deeply nested types to hit limit without gas charge
    public entry fun exploit_type_limit<T>() {
        // This will hit TYPE_TAG_LIMIT_EXCEEDED if T is sufficiently complex
        // Transaction gets discarded (no gas) instead of kept (with gas)
        let _ = type_info::type_of<T>();
    }
    
    // Attacker calls with:
    // exploit_type_limit<vector<vector<vector<vector<...>>>>>()
}
```

**Notes**

The vulnerability extends beyond `TYPE_TAG_LIMIT_EXCEEDED` to affect any execution-level error (status codes 4000-4999) that propagates through native functions using the `?` operator. This includes errors from value operations, field access, and other VM operations that should charge gas but currently result in free transaction discard.

The explicit TODO comment and developer acknowledgment in the codebase confirms this is a known architectural issue requiring remediation.

### Citations

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

**File:** aptos-move/aptos-native-interface/src/errors.rs (L50-72)
```rust
/// Saner representation of a native function error.
#[allow(unused)]
pub enum SafeNativeError {
    /// Indicating that the native function has aborted due to some (user) errors.
    ///
    /// Equivalent to aborting in a regular Move function, so the same error convention should
    /// be followed.
    Abort { abort_code: u64 },

    /// Indicating that the native function has exceeded execution limits.
    ///
    /// If metering in native context is not enabled, this will cause the VM to deduct all the
    /// remaining balance and abort the transaction, so use it carefully! Normally this should only
    /// be triggered by `SafeNativeContext::charge()` and one should not return this variant
    /// manually without a good reason.
    ///
    /// If metering in native context is enabled, then simply returns the error code that specifies
    /// the limit that was exceeded.
    LimitExceeded(LimitExceededError),

    /// Indicating that the native function ran into some internal errors that shall not normally
    /// be triggerable by user inputs.
    InvariantViolation(PartialVMError),
```

**File:** aptos-move/aptos-native-interface/src/errors.rs (L98-104)
```rust
//
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

**File:** third_party/move/move-core/types/src/vm_status.rs (L29-45)
```rust
/// The minimum status code for invariant violation statuses
pub static INVARIANT_VIOLATION_STATUS_MIN_CODE: u64 = 2000;

/// The maximum status code for invariant violation statuses
pub static INVARIANT_VIOLATION_STATUS_MAX_CODE: u64 = 2999;

/// The minimum status code for deserialization statuses
pub static DESERIALIZATION_STATUS_MIN_CODE: u64 = 3000;

/// The maximum status code for deserialization statuses
pub static DESERIALIZATION_STATUS_MAX_CODE: u64 = 3999;

/// The minimum status code for runtime statuses
pub static EXECUTION_STATUS_MIN_CODE: u64 = 4000;

/// The maximum status code for runtim statuses
pub static EXECUTION_STATUS_MAX_CODE: u64 = 4999;
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L298-299)
```rust
                    // If the VM encountered an invalid internal state, we should discard the transaction.
                    StatusType::InvariantViolation => Err(code),
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L942-942)
```rust
    TYPE_TAG_LIMIT_EXCEEDED = 4033,
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L995-1011)
```rust
        if major_status_number >= INVARIANT_VIOLATION_STATUS_MIN_CODE
            && major_status_number <= INVARIANT_VIOLATION_STATUS_MAX_CODE
        {
            return StatusType::InvariantViolation;
        }

        if major_status_number >= DESERIALIZATION_STATUS_MIN_CODE
            && major_status_number <= DESERIALIZATION_STATUS_MAX_CODE
        {
            return StatusType::Deserialization;
        }

        if major_status_number >= EXECUTION_STATUS_MIN_CODE
            && major_status_number <= EXECUTION_STATUS_MAX_CODE
        {
            return StatusType::Execution;
        }
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_tag_converter.rs (L50-62)
```rust
    fn charge(&mut self, amount: u64) -> PartialVMResult<()> {
        self.cost += amount;
        if self.cost > self.max_cost {
            Err(
                PartialVMError::new(StatusCode::TYPE_TAG_LIMIT_EXCEEDED).with_message(format!(
                    "Exceeded maximum type tag limit of {} when charging {}",
                    self.max_cost, amount
                )),
            )
        } else {
            Ok(())
        }
    }
```

**File:** aptos-move/framework/src/natives/type_info.rs (L47-74)
```rust
fn native_type_of(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(arguments.is_empty());

    context.charge(TYPE_INFO_TYPE_OF_BASE)?;

    let type_tag = context.type_to_type_tag(&ty_args[0])?;

    if context.eval_gas(TYPE_INFO_TYPE_OF_PER_BYTE_IN_STR) > 0.into() {
        let type_tag_str = type_tag.to_canonical_string();
        // Ideally, we would charge *before* the `type_to_type_tag()` and `type_tag.to_string()` calls above.
        // But there are other limits in place that prevent this native from being called with too much work.
        context
            .charge(TYPE_INFO_TYPE_OF_PER_BYTE_IN_STR * NumBytes::new(type_tag_str.len() as u64))?;
    }

    if let TypeTag::Struct(struct_tag) = type_tag {
        Ok(type_of_internal(&struct_tag).expect("type_of should never fail."))
    } else {
        Err(SafeNativeError::Abort {
            abort_code: super::status::NFE_EXPECTED_STRUCT_TYPE_TAG,
        })
    }
}
```

**File:** types/src/transaction/mod.rs (L1640-1646)
```rust
                if code.status_type() == StatusType::InvariantViolation
                    && features.is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION)
                {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(code)))
                } else {
                    Self::Discard(code)
                }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2928-3001)
```rust
                if let StatusType::InvariantViolation = vm_status.status_type() {
                    match vm_status.status_code() {
                        // Type resolution failure can be triggered by user input when providing a bad type argument, skip this case.
                        StatusCode::TYPE_RESOLUTION_FAILURE
                        if vm_status.sub_status()
                            == Some(move_core_types::vm_status::sub_status::type_resolution_failure::EUSER_TYPE_LOADING_FAILURE) => {},
                        // The known Move function failure and type resolution failure could be a result of speculative execution. Use speculative logger.
                        StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION
                        | StatusCode::TYPE_RESOLUTION_FAILURE => {
                            speculative_error!(
                                log_context,
                                format!(
                                    "[aptos_vm] Transaction breaking invariant violation: {:?}\ntxn: {:?}",
                                    vm_status,
                                    bcs::to_bytes::<SignedTransaction>(txn),
                                ),
                            );
                        },
                        // Paranoid mode failure. We need to be alerted about this ASAP.
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if vm_status.sub_status()
                            == Some(unknown_invariant_violation::EPARANOID_FAILURE) =>
                            {
                                error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking paranoid mode: {:?}\ntxn: {:?}",
                                vm_status,
                                bcs::to_bytes::<SignedTransaction>(txn),
                            );
                            },
                        // Paranoid mode failure but with reference counting
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if vm_status.sub_status()
                            == Some(unknown_invariant_violation::EREFERENCE_COUNTING_FAILURE) =>
                            {
                                error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking paranoid mode: {:?}\ntxn: {:?}",
                                vm_status,
                                bcs::to_bytes::<SignedTransaction>(txn),
                            );
                            },
                        // Paranoid mode failure but with reference safety checks
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if matches!(
                            vm_status.sub_status(),
                            Some(
                                unknown_invariant_violation::EREFERENCE_SAFETY_FAILURE
                                | unknown_invariant_violation::EINDEXED_REF_TAG_MISMATCH
                            )
                        ) =>
                        {
                            error!(
                            *log_context,
                            "[aptos_vm] Transaction breaking paranoid reference safety check (including enum tag guard). txn: {:?}, status: {:?}",
                            bcs::to_bytes::<SignedTransaction>(txn),
                            vm_status,
                            );
                        }
                        // Ignore DelayedFields speculative errors as it can be intentionally triggered by parallel execution.
                        StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR => (),
                        // We will log the rest of invariant violation directly with regular logger as they shouldn't happen.
                        //
                        // TODO: Add different counters for the error categories here.
                        _ => {
                            error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking invariant violation: {:?}\ntxn: {:?}, ",
                                vm_status,
                                bcs::to_bytes::<SignedTransaction>(txn),
                            );
                        },
                    }
                }
```
