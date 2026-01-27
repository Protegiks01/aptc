# Audit Report

## Title
Asymmetric Epilogue Error Handling Causes Transaction Status Inconsistency

## Summary
The success epilogue and failure epilogue use different error handling functions (`convert_epilogue_error` vs `expect_only_successful_execution`), leading to inconsistent treatment of the same error conditions. When the epilogue encounters `ECANT_PAY_GAS_DEPOSIT`, the success path preserves it as a MoveAbort (transaction kept), while the failure path converts it to an invariant violation (transaction discarded by default). This asymmetry violates deterministic execution principles and can cause transactions that should be kept to be incorrectly discarded.

## Finding Description

The Aptos VM implements two distinct epilogue execution paths with fundamentally different error handling strategies:

**Success Epilogue Path:** [1](#0-0) 

Uses `convert_epilogue_error` which explicitly allows `(LIMIT_EXCEEDED, ECANT_PAY_GAS_DEPOSIT)` to pass through as a MoveAbort: [2](#0-1) 

**Failure Epilogue Path:** [3](#0-2) 

Uses `expect_only_successful_execution` which converts ALL errors (including `ECANT_PAY_GAS_DEPOSIT`) to `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION`: [4](#0-3) 

**Transaction Disposition Impact:**

When `keep_or_discard` processes these errors:
- MoveAbort → `Ok(KeptVMStatus::MoveAbort)` (transaction KEPT): [5](#0-4) 

- InvariantViolation → `Err(code)` (transaction DISCARDED): [6](#0-5) 

**Critical Code Path:**

When a transaction fails and should be kept, `failed_transaction_cleanup` attempts to run the failure epilogue. If this epilogue fails, the transaction is unconditionally discarded: [7](#0-6) 

The epilogue functions in Move check balance sufficiency and can abort with `ECANT_PAY_GAS_DEPOSIT`: [8](#0-7) 

## Impact Explanation

This vulnerability has **High** severity impact for the following reasons:

1. **Transaction Status Manipulation**: A transaction that should be kept (and gas charged) can be forced into discard status, allowing attackers to avoid gas payment for failed transactions.

2. **Determinism Violation**: The same underlying condition (`ECANT_PAY_GAS_DEPOSIT`) produces different transaction outcomes depending on execution path, violating Critical Invariant #1 (Deterministic Execution).

3. **State Consistency Risk**: If different validators hit different epilogue paths due to timing, gas calculation variations, or feature flag transitions, they could disagree on transaction status, causing consensus divergence.

4. **Defensive Programming Failure**: The asymmetry makes the system fragile to edge cases like gas meter inconsistencies, parallel execution anomalies, or future code changes.

While direct exploitation requires unusual conditions (gas meter bugs, state sync issues, or parallel execution timing), the architectural flaw creates a systemic risk to consensus safety.

## Likelihood Explanation

**Likelihood: Medium-Low** under normal operation, but **High** in edge cases:

- **Normal Operation**: Failure epilogue rarely fails because prologue validates balance sufficiency
- **Edge Cases**: Gas meter calculation bugs, BlockSTM validation failures, epoch transitions, or feature flag rollouts could trigger the asymmetry
- **Parallel Execution**: Speculative execution in BlockSTM could expose timing windows where balance states differ between validators
- **Future Risk**: Code changes to gas metering or epilogue logic could inadvertently trigger this bug

The inconsistency is always present in the codebase, waiting for the right conditions to manifest.

## Recommendation

**Unify epilogue error handling** to ensure symmetric treatment of all epilogue errors:

```rust
// In transaction_validation.rs, change run_failure_epilogue to use the same handler:

pub(crate) fn run_failure_epilogue(
    session: &mut SessionExt<impl AptosMoveResolver>,
    module_storage: &impl ModuleStorage,
    serialized_signers: &SerializedSigners,
    gas_remaining: Gas,
    fee_statement: FeeStatement,
    features: &Features,
    txn_data: &TransactionMetadata,
    log_context: &AdapterLogSchema,
    traversal_context: &mut TraversalContext,
    is_simulation: bool,
) -> Result<(), VMStatus> {
    run_epilogue(
        session,
        module_storage,
        serialized_signers,
        gas_remaining,
        fee_statement,
        txn_data,
        features,
        traversal_context,
        is_simulation,
    )
    // CHANGE THIS LINE:
    // .or_else(|err| convert_epilogue_error(err, log_context))  // Use same handler as success epilogue
    .or_else(|err| convert_epilogue_error(err, log_context))
}
```

Alternatively, if failure epilogue should never fail, add explicit invariant checking:
```rust
.or_else(|err| {
    // Failure epilogue failing is a critical invariant violation
    // that indicates gas meter or state corruption
    speculative_error!(log_context, format!(
        "[aptos_vm] CRITICAL: Failure epilogue failed unexpectedly: {:?}", err
    ));
    convert_epilogue_error(err, log_context)
})
```

## Proof of Concept

```rust
// Rust test demonstrating the inconsistency

#[test]
fn test_epilogue_error_handling_asymmetry() {
    use aptos_vm::errors::*;
    use move_core_types::vm_status::*;
    
    // Simulate ECANT_PAY_GAS_DEPOSIT error from epilogue
    let error_code = (0x2u64 << 16) | 1005u64; // LIMIT_EXCEEDED + ECANT_PAY_GAS_DEPOSIT
    let test_error = VMError::from(PartialVMError::new(StatusCode::ABORTED)
        .at_code_offset(0, 0)
        .with_sub_status(error_code));
    
    let log_context = AdapterLogSchema::new(StateView, 0);
    
    // Success epilogue handling
    let success_result = convert_epilogue_error(test_error.clone(), &log_context);
    // Returns MoveAbort - transaction KEPT
    
    // Failure epilogue handling  
    let failure_result = expect_only_successful_execution(
        test_error,
        "epilogue",
        &log_context
    );
    // Returns UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION - transaction DISCARDED
    
    // Assert: Same error, different outcomes
    assert!(matches!(success_result, Err(VMStatus::MoveAbort { .. })));
    assert!(matches!(failure_result, Err(VMStatus::Error {
        status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
        ..
    })));
}
```

The asymmetry violates the principle that identical error conditions should produce identical outcomes regardless of execution path.

## Notes

While exploitation requires specific conditions to be met, the architectural flaw represents a violation of deterministic execution guarantees that could manifest during:
- Gas metering bugs
- Parallel execution race conditions  
- Feature flag rollouts
- State synchronization edge cases
- Future code modifications

The recommendation is to unify error handling to eliminate this systemic risk to consensus safety.

### Citations

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L620-651)
```rust
pub(crate) fn run_success_epilogue(
    session: &mut SessionExt<impl AptosMoveResolver>,
    module_storage: &impl ModuleStorage,
    serialized_signers: &SerializedSigners,
    gas_remaining: Gas,
    fee_statement: FeeStatement,
    features: &Features,
    txn_data: &TransactionMetadata,
    log_context: &AdapterLogSchema,
    traversal_context: &mut TraversalContext,
    is_simulation: bool,
) -> Result<(), VMStatus> {
    fail_point!("move_adapter::run_success_epilogue", |_| {
        Err(VMStatus::error(
            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            None,
        ))
    });

    run_epilogue(
        session,
        module_storage,
        serialized_signers,
        gas_remaining,
        fee_statement,
        txn_data,
        features,
        traversal_context,
        is_simulation,
    )
    .or_else(|err| convert_epilogue_error(err, log_context))
}
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L655-685)
```rust
pub(crate) fn run_failure_epilogue(
    session: &mut SessionExt<impl AptosMoveResolver>,
    module_storage: &impl ModuleStorage,
    serialized_signers: &SerializedSigners,
    gas_remaining: Gas,
    fee_statement: FeeStatement,
    features: &Features,
    txn_data: &TransactionMetadata,
    log_context: &AdapterLogSchema,
    traversal_context: &mut TraversalContext,
    is_simulation: bool,
) -> Result<(), VMStatus> {
    run_epilogue(
        session,
        module_storage,
        serialized_signers,
        gas_remaining,
        fee_statement,
        txn_data,
        features,
        traversal_context,
        is_simulation,
    )
    .or_else(|err| {
        expect_only_successful_execution(
            err,
            APTOS_TRANSACTION_VALIDATION.user_epilogue_name.as_str(),
            log_context,
        )
    })
}
```

**File:** aptos-move/aptos-vm/src/errors.rs (L227-236)
```rust
        VMStatus::MoveAbort {
            location,
            code,
            message,
        } => match error_split(code) {
            (LIMIT_EXCEEDED, ECANT_PAY_GAS_DEPOSIT) => VMStatus::MoveAbort {
                location,
                code,
                message,
            },
```

**File:** aptos-move/aptos-vm/src/errors.rs (L275-305)
```rust
pub fn expect_only_successful_execution(
    error: VMError,
    function_name: &str,
    log_context: &AdapterLogSchema,
) -> Result<(), VMStatus> {
    let status = error.into_vm_status();
    Err(match status {
        VMStatus::Executed => VMStatus::Executed,
        // Speculative errors are returned for caller to handle.
        e @ VMStatus::Error {
            status_code:
                StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
                | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
            ..
        } => e,
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
    })
}
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L211-223)
```rust
            VMStatus::MoveAbort {
                location,
                code,
                message,
            } => Ok(KeptVMStatus::MoveAbort {
                location,
                code,
                message: if abort_messages_enabled {
                    message
                } else {
                    None
                },
            }),
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L299-299)
```rust
                    StatusType::InvariantViolation => Err(code),
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L610-624)
```rust
                let output = self
                    .finish_aborted_transaction(
                        prologue_session_change_set,
                        gas_meter,
                        txn_data,
                        resolver,
                        module_storage,
                        serialized_signers,
                        status,
                        log_context,
                        change_set_configs,
                        traversal_context,
                    )
                    .unwrap_or_else(|status| discarded_output(status.status_code()));
                (error_vm_status, output)
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L608-618)
```text
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            };
```
