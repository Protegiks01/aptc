# Audit Report

## Title
Production Debug Logging Exposes DelayedFieldID Values and Internal Execution State

## Summary
The `code_invariant_error` function unconditionally logs DelayedFieldID values and internal state information to stdout in production builds, potentially exposing internal execution details to attackers with access to validator logs.

## Finding Description

The codebase contains production logging that exposes DelayedFieldID values and internal traversal state through two mechanisms:

1. **Direct stdout logging via `println!`** in the `code_invariant_error` function [1](#0-0) 

2. **Multiple call sites** that pass DelayedFieldID values to this logging function:
   - DelayedFieldID serialization errors [2](#0-1) 
   - Type conversion failures [3](#0-2) 
   - Width mismatch errors [4](#0-3) 
   - Value parsing errors [5](#0-4) 

3. **BlockSTM executor logging** via the `alert!` macro [6](#0-5)  which logs CodeInvariantErrors containing this information [7](#0-6) 

4. **Additional sensitive logging** in derived string operations [8](#0-7) 

The `find_identifiers_in_value_impl()` function itself does not contain direct logging [9](#0-8) , but it calls `code_invariant_error` when encountering duplicate identifiers [10](#0-9) 

## Impact Explanation

This qualifies as **Low Severity** per the Aptos bug bounty criteria ("Minor information leaks"). The exposed information includes:
- DelayedFieldID values (unique_index and width fields)
- Internal execution state and error conditions
- Timing information about when errors occur
- Scale information (number of delayed fields in use)

However, this does NOT meet the threshold for Medium or higher severity because:
- No direct path to fund theft or consensus violations
- DelayedFieldID values are ephemeral (not persistent state)
- Requires attacker to have access to validator logs (compromised monitoring systems or misconfigured logging)
- Information alone cannot be used to manipulate delayed fields or execution

## Likelihood Explanation

**Likelihood: Low**

For exploitation to occur:
1. Attacker must gain read access to validator logs (through log aggregation systems, compromised monitoring infrastructure, or misconfigured public logging)
2. Specific error conditions must be triggered that invoke `code_invariant_error`
3. Attacker must have the capability to act on the information (no clear attack vector exists)

The errors logged are typically invariant violations that should not occur in normal operation, making them relatively rare events.

## Recommendation

Remove the unconditional `println!` statement from production code:

**Option 1**: Remove the println! entirely and rely only on the error message:
```rust
pub fn code_invariant_error<M: std::fmt::Debug>(message: M) -> PartialVMError {
    let msg = format!(
        "Delayed logic code invariant broken (there is a bug in the code), {:?}",
        message
    );
    // Remove: println!("ERROR: {}", msg);
    PartialVMError::new(StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR)
        .with_message(msg)
}
```

**Option 2**: Make the logging conditional on debug builds only:
```rust
pub fn code_invariant_error<M: std::fmt::Debug>(message: M) -> PartialVMError {
    let msg = format!(
        "Delayed logic code invariant broken (there is a bug in the code), {:?}",
        message
    );
    #[cfg(debug_assertions)]
    println!("ERROR: {}", msg);
    PartialVMError::new(StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR)
        .with_message(msg)
}
```

The `alert!` macro logging is acceptable as it uses the standard logging infrastructure, but consider sanitizing error messages to avoid including raw DelayedFieldID values in structured logs.

## Proof of Concept

```rust
// This test demonstrates that code_invariant_error logs to stdout in production
#[test]
fn test_delayed_field_id_logging_exposure() {
    use move_vm_types::{
        delayed_values::delayed_field_id::DelayedFieldID,
        value_traversal::find_identifiers_in_value,
        values::{Struct, Value},
    };
    use std::collections::HashSet;

    // Create duplicate DelayedFieldID values
    let id = DelayedFieldID::new_with_width(12345, 8);
    let a = Value::delayed_value(id);
    let b = Value::delayed_value(id); // Duplicate
    let c = Value::struct_(Struct::pack(vec![a, b]));

    let mut ids = HashSet::new();
    
    // This will trigger code_invariant_error which logs:
    // "ERROR: Delayed logic code invariant broken (there is a bug in the code), 
    //  \"Duplicated identifiers for Move value\""
    // The error message itself doesn't include the ID value in this case,
    // but other call sites do include DelayedFieldID values in the message.
    let result = find_identifiers_in_value(&c, &mut ids);
    
    assert!(result.is_err());
    // In production, this would print to stdout exposing the error condition
}

// Test case that exposes DelayedFieldID values in error messages
#[test]
fn test_delayed_field_id_value_exposure() {
    use move_vm_types::{
        delayed_values::delayed_field_id::{DelayedFieldID, TryIntoMoveValue},
    };
    use move_core_types::value::MoveTypeLayout;

    let id = DelayedFieldID::new_with_width(99999, 8);
    
    // Try to convert to an invalid layout - this will log the actual ID value
    let invalid_layout = MoveTypeLayout::Bool;
    let result = id.try_into_move_value(&invalid_layout);
    
    // This error message contains: "Failed to convert DelayedFieldID { 
    // unique_index: 99999, width: 8 } into a Move value with Bool layout"
    // which gets printed to stdout via println! in code_invariant_error
    assert!(result.is_err());
}
```

## Notes

While this finding confirms the existence of debug logs that expose DelayedFieldID values and internal state in production, **the exploitability and security impact are minimal**. The information leaked does not provide a direct attack path to compromise funds, consensus, or availability. This is a code quality issue that should be addressed to follow security best practices (avoid logging sensitive implementation details in production), but it does not constitute a high-severity vulnerability requiring urgent remediation.

### Citations

**File:** third_party/move/move-vm/types/src/delayed_values/error.rs (L11-19)
```rust
pub fn code_invariant_error<M: std::fmt::Debug>(message: M) -> PartialVMError {
    let msg = format!(
        "Delayed logic code invariant broken (there is a bug in the code), {:?}",
        message
    );
    println!("ERROR: {}", msg);
    PartialVMError::new(StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR)
        .with_message(msg)
}
```

**File:** third_party/move/move-vm/types/src/delayed_values/delayed_field_id.rs (L62-64)
```rust
            return Err(code_invariant_error(format!(
                "DerivedStringSnapshot size issue for id {self:?}: width: {width}, value_width_upper_bound: {value_len_width_upper_bound}"
            )));
```

**File:** third_party/move/move-vm/types/src/delayed_values/delayed_field_id.rs (L150-153)
```rust
                return Err(code_invariant_error(format!(
                    "Failed to convert {:?} into a Move value with {} layout",
                    self, layout
                )))
```

**File:** third_party/move/move-vm/types/src/delayed_values/delayed_field_id.rs (L191-193)
```rust
                return Err(code_invariant_error(format!(
                    "Failed to convert a Move value with {layout} layout into an identifier, tagged with {hint:?}, with value {value:?}",
                )))
```

**File:** third_party/move/move-vm/types/src/delayed_values/delayed_field_id.rs (L197-200)
```rust
            return Err(code_invariant_error(format!(
                "Extracted identifier has a wrong width: id={id:?}, width={width}, expected={}",
                id.extract_width(),
            )));
```

**File:** aptos-move/aptos-vm-logging/src/lib.rs (L164-169)
```rust
macro_rules! alert {
    ($($args:tt)+) => {
	error!($($args)+);
	CRITICAL_ERRORS.inc();
    };
}
```

**File:** aptos-move/block-executor/src/executor.rs (L1947-1949)
```rust
                        if let PanicOr::CodeInvariantError(err_msg) = err {
                            alert!("[BlockSTM] worker loop: CodeInvariantError({:?})", err_msg);
                        }
```

**File:** third_party/move/move-vm/types/src/delayed_values/derived_string_snapshot.rs (L61-63)
```rust
        return Err(code_invariant_error(format!(
            "u64_to_fixed_size_utf8_bytes: width mismatch: value: {value}, length: {length}, result: {result:?}"
        )));
```

**File:** third_party/move/move-vm/types/src/value_traversal.rs (L22-92)
```rust
fn find_identifiers_in_value_impl(
    value: &Value,
    identifiers: &mut HashSet<u64>,
) -> PartialVMResult<()> {
    match value {
        Value::U8(_)
        | Value::U16(_)
        | Value::U32(_)
        | Value::U64(_)
        | Value::U128(_)
        | Value::U256(_)
        | Value::I8(_)
        | Value::I16(_)
        | Value::I32(_)
        | Value::I64(_)
        | Value::I128(_)
        | Value::I256(_)
        | Value::Bool(_)
        | Value::Address(_) => {},

        Value::Container(c) => match c {
            Container::Locals(_) => {
                return Err(PartialVMError::new(
                    StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                ))
            },

            Container::VecU8(_)
            | Container::VecU64(_)
            | Container::VecU128(_)
            | Container::VecBool(_)
            | Container::VecAddress(_)
            | Container::VecU16(_)
            | Container::VecU32(_)
            | Container::VecU256(_)
            | Container::VecI8(_)
            | Container::VecI16(_)
            | Container::VecI32(_)
            | Container::VecI64(_)
            | Container::VecI128(_)
            | Container::VecI256(_) => {},

            Container::Vec(v) | Container::Struct(v) => {
                for val in v.borrow().iter() {
                    find_identifiers_in_value_impl(val, identifiers)?;
                }
            },
        },

        Value::ClosureValue(Closure(_, captured)) => {
            for val in captured.iter() {
                find_identifiers_in_value_impl(val, identifiers)?;
            }
        },

        Value::Invalid | Value::ContainerRef(_) | Value::IndexedRef(_) => {
            return Err(PartialVMError::new(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
        },

        Value::DelayedFieldID { id } => {
            if !identifiers.insert(id.as_u64()) {
                return Err(code_invariant_error(
                    "Duplicated identifiers for Move value".to_string(),
                ));
            }
        },
    }
    Ok(())
}
```
