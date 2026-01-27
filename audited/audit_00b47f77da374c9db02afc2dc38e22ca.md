# Audit Report

## Title
VMStatus::ExecutionFailure Variants with Special Status Codes Not Passed Through in Error Conversion Functions

## Summary
The error conversion functions `convert_prologue_error()`, `convert_epilogue_error()`, and `expect_only_successful_execution()` in `errors.rs` only pass through `VMStatus::Error` variants with `SPECULATIVE_EXECUTION_ABORT_ERROR` or `DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR` status codes, but fail to handle `VMStatus::ExecutionFailure` variants with the same status codes. This causes critical execution signals to be incorrectly converted to invariant violations, breaking the BlockSTM parallel execution protocol.

## Finding Description

The VMStatus enum has four variants: `Executed`, `Error`, `MoveAbort`, and `ExecutionFailure`. [1](#0-0) 

Both `VMStatus::Error` and `VMStatus::ExecutionFailure` can contain a `status_code` field. [2](#0-1) 

When errors occur during Move function execution with execution state (function index and code offset), they are converted to `VMStatus::ExecutionFailure` with the appropriate status_code. [3](#0-2) 

The error conversion functions have special handling for `SPECULATIVE_EXECUTION_ABORT_ERROR` and `DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR` that passes them through without conversion, but this only applies to the `VMStatus::Error` variant: [4](#0-3) [5](#0-4) [6](#0-5) 

However, `VMStatus::ExecutionFailure` variants (regardless of status_code) are caught by the catch-all patterns and converted to `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION`: [7](#0-6) [8](#0-7) [9](#0-8) 

These special status codes can be created during delayed field and aggregator operations: [10](#0-9) [11](#0-10) 

When prologue or epilogue functions execute and encounter these errors during Move code execution (not just at the top level), the errors will have execution state and become `ExecutionFailure` variants. The block executor relies on detecting these specific status codes to handle speculative execution properly: [12](#0-11) [13](#0-12) 

When `ExecutionFailure` with these status codes is converted to `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION`, the block executor never receives the proper signal to retry the transaction or fall back to sequential execution.

## Impact Explanation

This breaks the **Deterministic Execution** invariant (all validators must produce identical state roots) because different nodes may handle speculative execution errors differently depending on timing and parallel execution order.

The issue qualifies as **High Severity** under the Aptos bug bounty program as it constitutes a "Significant protocol violation" - it breaks the BlockSTM speculative execution protocol. Specifically:

1. **Protocol Violation**: `SPECULATIVE_EXECUTION_ABORT_ERROR` signals that a transaction needs re-execution due to speculative read conflicts. Converting it to an invariant violation causes valid transactions to be incorrectly discarded.

2. **Consensus Divergence Risk**: Different validator nodes executing blocks in parallel may experience different execution orders. If some nodes correctly identify speculative errors while others mishandle them as invariant violations, they may produce different transaction outputs and state roots.

3. **Liveness Impact**: Valid transactions may be repeatedly rejected instead of retried, affecting network liveness.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can be triggered during normal network operation when:
- Prologue or epilogue functions perform delayed field or aggregator operations
- Parallel execution creates speculative read conflicts
- The error occurs within function execution (not at the top level), creating ExecutionFailure

Gas payment operations in prologues may use aggregators, making this scenario realistic. An attacker could increase likelihood by submitting multiple transactions targeting the same aggregators to create speculative conflicts.

## Recommendation

Add explicit checks for `VMStatus::ExecutionFailure` with the special status codes before the catch-all patterns:

```rust
// In convert_prologue_error(), before line 182:
e @ VMStatus::ExecutionFailure {
    status_code:
        StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
        | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
    ..
} => e,

// In convert_epilogue_error(), before line 260:
e @ VMStatus::ExecutionFailure {
    status_code:
        StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
        | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
    ..
} => e,

// In expect_only_successful_execution(), before line 290:
e @ VMStatus::ExecutionFailure {
    status_code:
        StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
        | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
    ..
} => e,
```

Alternatively, refactor to check `status.status_code()` directly rather than pattern matching on variants, ensuring all variants with these status codes are handled consistently.

## Proof of Concept

```rust
// Conceptual PoC showing the bug
#[test]
fn test_execution_failure_speculative_error_mishandled() {
    use move_core_types::vm_status::{StatusCode, VMStatus, AbortLocation};
    use move_binary_format::errors::VMError;
    use aptos_vm::errors::convert_prologue_error;
    
    // Create ExecutionFailure with SPECULATIVE_EXECUTION_ABORT_ERROR
    let exec_failure = VMStatus::ExecutionFailure {
        status_code: StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR,
        sub_status: None,
        location: AbortLocation::Script,
        function: 0,
        code_offset: 0,
        message: Some("Speculative conflict".to_string()),
    };
    
    let vm_error = VMError::new(/* constructed from exec_failure */);
    let log_context = /* ... */;
    
    // This should pass through the ExecutionFailure, but instead converts it
    let result = convert_prologue_error(vm_error, &log_context);
    
    // Bug: result will be UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION
    // instead of preserving SPECULATIVE_EXECUTION_ABORT_ERROR
    assert!(matches!(result, Err(VMStatus::Error { 
        status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION, 
        .. 
    })));
    
    // Expected behavior: should preserve the original status
    // assert!(matches!(result, Err(VMStatus::ExecutionFailure { 
    //     status_code: StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR,
    //     ..
    // })));
}
```

## Notes

This vulnerability demonstrates incomplete pattern matching where the code assumes errors with special status codes will always be `VMStatus::Error` variants, but the Move VM can also create `VMStatus::ExecutionFailure` variants with the same status codes when errors occur during function execution. The fix requires consistent handling across all VMStatus variants that carry these critical status codes.

### Citations

**File:** third_party/move/move-core/types/src/vm_status.rs (L54-84)
```rust
pub enum VMStatus {
    /// The VM status corresponding to an EXECUTED status code
    Executed,

    /// Indicates an error from the VM, e.g. OUT_OF_GAS, INVALID_AUTH_KEY, RET_TYPE_MISMATCH_ERROR
    /// etc.
    /// The code will neither EXECUTED nor ABORTED
    Error {
        status_code: StatusCode,
        sub_status: Option<u64>,
        message: Option<String>,
    },

    /// Indicates an `abort` from inside Move code. Contains the location of the abort and the code
    MoveAbort {
        location: AbortLocation,
        code: u64,
        message: Option<String>,
    },

    /// Indicates an failure from inside Move code, where the VM could not continue exection, e.g.
    /// dividing by zero or a missing resource
    ExecutionFailure {
        status_code: StatusCode,
        sub_status: Option<u64>,
        location: AbortLocation,
        function: u16,
        code_offset: u16,
        message: Option<String>,
    },
}
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L153-167)
```rust
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Executed => StatusCode::EXECUTED,
            Self::MoveAbort { .. } => StatusCode::ABORTED,
            Self::ExecutionFailure { status_code, .. } => *status_code,
            Self::Error {
                status_code: code, ..
            } => {
                let code = *code;
                debug_assert!(code != StatusCode::EXECUTED);
                debug_assert!(code != StatusCode::ABORTED);
                code
            },
        }
    }
```

**File:** third_party/move/move-binary-format/src/errors.rs (L156-163)
```rust
                VMStatus::ExecutionFailure {
                    status_code: major_status,
                    location: abort_location,
                    function,
                    code_offset,
                    sub_status,
                    message,
                }
```

**File:** aptos-move/aptos-vm/src/errors.rs (L176-181)
```rust
        e @ VMStatus::Error {
            status_code:
                StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
                | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
            ..
        } => e,
```

**File:** aptos-move/aptos-vm/src/errors.rs (L182-192)
```rust
        status @ VMStatus::ExecutionFailure { .. } | status @ VMStatus::Error { .. } => {
            speculative_error!(
                log_context,
                format!("[aptos_vm] Unexpected prologue error: {:?}", status),
            );
            VMStatus::Error {
                status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                sub_status: status.sub_status(),
                message: None,
            }
        },
```

**File:** aptos-move/aptos-vm/src/errors.rs (L254-259)
```rust
        e @ VMStatus::Error {
            status_code:
                StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
                | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
            ..
        } => e,
```

**File:** aptos-move/aptos-vm/src/errors.rs (L260-268)
```rust
        status => {
            let err_msg = format!("[aptos_vm] Unexpected success epilogue error: {:?}", status);
            speculative_error!(log_context, err_msg.clone());
            VMStatus::Error {
                status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                sub_status: status.sub_status(),
                message: Some(err_msg),
            }
        },
```

**File:** aptos-move/aptos-vm/src/errors.rs (L284-289)
```rust
        e @ VMStatus::Error {
            status_code:
                StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
                | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
            ..
        } => e,
```

**File:** aptos-move/aptos-vm/src/errors.rs (L290-303)
```rust
        status => {
            // Only trigger a warning here as some errors could be a result of the speculative parallel execution.
            // We will report the errors after we obtained the final transaction output in update_counters_for_processed_chunk
            let err_msg = format!(
                "[aptos_vm] Unexpected error from known Move function, '{}'. Error: {:?}",
                function_name, status
            );
            speculative_warn!(log_context, err_msg.clone());
            VMStatus::Error {
                status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                sub_status: status.sub_status(),
                message: Some(err_msg),
            }
        },
```

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

**File:** aptos-move/aptos-aggregator/src/resolver.rs (L85-88)
```rust
        let base = self.get_aggregator_v1_value(id)?.ok_or_else(|| {
            PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
                .with_message("Cannot convert delta for deleted aggregator".to_string())
        })?;
```

**File:** aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs (L75-84)
```rust
                if vm_status.status_code() == StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR {
                    ExecutionStatus::SpeculativeExecutionAbortError(
                        vm_status.message().cloned().unwrap_or_default(),
                    )
                } else if vm_status.status_code()
                    == StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR
                {
                    ExecutionStatus::DelayedFieldsCodeInvariantError(
                        vm_status.message().cloned().unwrap_or_default(),
                    )
```

**File:** aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs (L102-111)
```rust
                if err.status_code() == StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR {
                    ExecutionStatus::SpeculativeExecutionAbortError(
                        err.message().cloned().unwrap_or_default(),
                    )
                } else if err.status_code()
                    == StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR
                {
                    ExecutionStatus::DelayedFieldsCodeInvariantError(
                        err.message().cloned().unwrap_or_default(),
                    )
```
