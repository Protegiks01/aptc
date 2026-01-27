# Audit Report

## Title
Aggregator V1 Validation Errors Incorrectly Classified as User Aborts Instead of Speculative Execution Errors

## Summary
The `abort_error()` function converts aggregator validation failures (Overflow/Underflow) to `ABORTED` status instead of `SPECULATIVE_EXECUTION_ABORT_ERROR`, preventing transaction retry during parallel execution when speculative reads become stale.

## Finding Description

During parallel execution in BlockSTM, transactions can read stale speculative values from aggregators. When these transactions are later validated, the delta history may no longer be compatible with the committed base value, causing validation to fail.

The vulnerability exists in two locations:

**Location 1: Aggregator Validation During Read** [1](#0-0) 

When `validate_history()` detects that the base value is incompatible with the recorded delta history, it converts Overflow/Underflow errors to `ABORTED` status via `abort_error()`: [2](#0-1) 

**Location 2: Delta Materialization** [3](#0-2) 

The code comment incorrectly assumes "aggregator V1 never underflows or overflows" during delta application, but this assumption breaks during parallel execution when the base value changes between speculative execution and validation.

**The Core Issue:**

All four validation failure types indicate stale speculative reads: [4](#0-3) 

However, the code handles them inconsistently:
- `Overflow`/`Underflow` → `ABORTED` (wrong - user-level error)
- `ExpectedOverflow`/`ExpectedUnderflow` → `SPECULATIVE_EXECUTION_ABORT_ERROR` (correct - system-level error)

**Status Code Semantics:** [5](#0-4) [6](#0-5) 

**VM Wrapper Error Handling:** [7](#0-6) 

When `ABORTED` is returned instead of `SPECULATIVE_EXECUTION_ABORT_ERROR`, BlockSTM does not retry the transaction - it commits it as failed.

**Affected Operations:**

Aggregator V1 is heavily used in the Aptos framework for coin supply tracking: [8](#0-7) 

All coin mint/burn operations that update supply counters are vulnerable to incorrect failure during parallel execution.

## Impact Explanation

**Severity: Medium** 

This issue causes state inconsistencies requiring intervention:

1. **Transaction Result Inconsistency**: Transactions that should succeed after retry are permanently failed with `ABORTED` status instead of being retried with fresh data.

2. **Denial of Service**: Legitimate coin minting/burning operations can spuriously fail during high transaction throughput when parallel execution is active.

3. **User Experience Impact**: Applications expecting eventual transaction success will receive permanent failures for operations that should have succeeded.

While this does not cause consensus divergence (all validators execute deterministically), it violates the semantic correctness of transaction execution. The blockchain commits transactions as "user aborted" when they actually failed due to internal speculative execution issues.

## Likelihood Explanation

**Likelihood: Medium-High**

This condition occurs naturally during:
- High transaction throughput on popular coins (AptosCoin, stablecoins)
- Parallel execution of multiple mint/burn operations
- Any scenario where aggregator base values change between transaction read and validation

The vulnerability does not require attacker coordination - it can occur during normal network operation under load. Higher transaction volume increases the probability of stale reads triggering validation failures.

## Recommendation

Modify error handling to treat all aggregator validation failures as speculative execution errors:

```rust
// In aggregator_v1_extension.rs, lines 106-122
fn validate_history(&self, base_value: u128) -> PartialVMResult<()> {
    let history = self
        .history
        .as_ref()
        .expect("History should be set for validation");

    if let Err(e) = history.validate_against_base_value(base_value, self.max_value) {
        // ALL validation failures indicate stale speculative reads
        // and should trigger transaction retry, not user-level abort
        return Err(PartialVMError::from(e)); // Let it convert to SPECULATIVE_EXECUTION_ABORT_ERROR
    }

    Ok(())
}
```

```rust
// In resolver.rs, lines 89-104
fn try_convert_aggregator_v1_delta_into_write_op(
    &self,
    id: &Self::Identifier,
    delta_op: &DeltaOp,
) -> PartialVMResult<WriteOp> {
    let base = self.get_aggregator_v1_value(id)?.ok_or_else(|| {
        PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
            .with_message("Cannot convert delta for deleted aggregator".to_string())
    })?;
    delta_op
        .apply_to(base)
        .map_err(|e| {
            // All delta application failures during materialization indicate
            // speculative execution errors, not user-level errors
            PartialVMError::from(e) // Converts to SPECULATIVE_EXECUTION_ABORT_ERROR
        })
        .map(|result| WriteOp::legacy_modification(serialize(&result).into()))
}
```

Remove the `abort_error()` conversions for aggregator validation errors entirely, allowing them to naturally convert to `SPECULATIVE_EXECUTION_ABORT_ERROR` via the `PanicOr<DelayedFieldsSpeculativeError>` → `PartialVMError` conversion: [9](#0-8) 

## Proof of Concept

This vulnerability manifests during parallel execution and requires specific timing conditions. A conceptual reproduction:

```move
// Conceptual Move test demonstrating the issue
// File: test_aggregator_validation_error.move

#[test(framework = @0x1)]
fun test_parallel_aggregator_validation_failure(framework: signer) {
    use aptos_framework::aggregator_factory;
    use aptos_framework::aggregator;
    
    // Setup: Create aggregator with max_value = 1000, initial value = 100
    let agg_factory = aggregator_factory::create_aggregator_factory(&framework);
    let agg = aggregator_factory::create_aggregator(&agg_factory, 1000);
    aggregator::add(&mut agg, 100);
    
    // Simulate parallel execution scenario:
    // T1: Adds 600 (100 + 600 = 700, valid)
    // T2: Speculatively reads 100, adds 500 (100 + 500 = 600, valid during speculation)
    //     But after T1 commits, base becomes 700
    //     When T2 validates: 700 + 500 = 1200 > 1000 → Overflow
    //     Current code: Returns ABORTED (wrong)
    //     Expected: Returns SPECULATIVE_EXECUTION_ABORT_ERROR (correct, triggers retry)
    
    // When T2 is retried with base=700:
    // Transaction logic might be: "add 500 if balance < 500, else add 200"
    // With base=700, it would add 200 → 700 + 200 = 900 (success)
    // But with ABORTED status, transaction never retries and permanently fails
}
```

The issue cannot be fully reproduced in a simple Move test as it requires BlockSTM parallel execution internals. However, the error handling divergence is evident in the codebase and violates the documented semantics of `SPECULATIVE_EXECUTION_ABORT_ERROR`.

## Notes

This vulnerability represents a semantic error in speculative execution error handling rather than a critical security flaw. While it does not directly cause fund loss or consensus divergence, it violates transaction execution correctness guarantees and can cause legitimate operations to fail spuriously under parallel execution load.

### Citations

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L106-122)
```rust
        if let Err(e) = history.validate_against_base_value(base_value, self.max_value) {
            match e {
                DelayedFieldsSpeculativeError::DeltaApplication {
                    reason: DeltaApplicationFailureReason::Overflow,
                    ..
                } => {
                    return Err(abort_error("overflow", EADD_OVERFLOW));
                },
                DelayedFieldsSpeculativeError::DeltaApplication {
                    reason: DeltaApplicationFailureReason::Underflow,
                    ..
                } => {
                    return Err(abort_error("underflow", ESUB_UNDERFLOW));
                },
                _ => Err(e)?,
            }
        }
```

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L373-377)
```rust
fn abort_error(message: impl ToString, code: u64) -> PartialVMError {
    PartialVMError::new(StatusCode::ABORTED)
        .with_message(message.to_string())
        .with_sub_status(code)
}
```

**File:** aptos-move/aptos-aggregator/src/resolver.rs (L89-104)
```rust
        delta_op
            .apply_to(base)
            .map_err(|e| match &e {
                PanicOr::Or(DelayedFieldsSpeculativeError::DeltaApplication {
                    reason: DeltaApplicationFailureReason::Overflow,
                    ..
                }) => addition_v1_error(e),
                PanicOr::Or(DelayedFieldsSpeculativeError::DeltaApplication {
                    reason: DeltaApplicationFailureReason::Underflow,
                    ..
                }) => subtraction_v1_error(e),
                // Because aggregator V1 never underflows or overflows, all other
                // application errors are bugs.
                _ => code_invariant_error(format!("Unexpected delta application error: {:?}", e))
                    .into(),
            })
```

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L159-194)
```rust
        math.unsigned_add(base_value, self.max_achieved_positive_delta)
            .map_err(|_e| DelayedFieldsSpeculativeError::DeltaApplication {
                base_value,
                max_value,
                delta: SignedU128::Positive(self.max_achieved_positive_delta),
                reason: DeltaApplicationFailureReason::Overflow,
            })?;
        math.unsigned_subtract(base_value, self.min_achieved_negative_delta)
            .map_err(|_e| DelayedFieldsSpeculativeError::DeltaApplication {
                base_value,
                max_value,
                delta: SignedU128::Negative(self.min_achieved_negative_delta),
                reason: DeltaApplicationFailureReason::Underflow,
            })?;

        if let Some(min_overflow_positive_delta) = self.min_overflow_positive_delta {
            if base_value <= max_value - min_overflow_positive_delta {
                return Err(DelayedFieldsSpeculativeError::DeltaApplication {
                    base_value,
                    max_value,
                    delta: SignedU128::Positive(min_overflow_positive_delta),
                    reason: DeltaApplicationFailureReason::ExpectedOverflow,
                });
            }
        }

        if let Some(max_underflow_negative_delta) = self.max_underflow_negative_delta {
            if base_value >= max_underflow_negative_delta {
                return Err(DelayedFieldsSpeculativeError::DeltaApplication {
                    base_value,
                    max_value,
                    delta: SignedU128::Negative(max_underflow_negative_delta),
                    reason: DeltaApplicationFailureReason::ExpectedUnderflow,
                });
            }
        }
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L867-871)
```rust
    // Speculative error means that there was an issue because of speculative
    // reads provided to the transaction, and the transaction needs to
    // be re-executed.
    // Should never be committed on chain
    SPECULATIVE_EXECUTION_ABORT_ERROR = 2024,
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L928-928)
```rust
    ABORTED = 4016,
```

**File:** aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs (L75-96)
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
                } else if AptosVM::should_restart_execution(vm_output.events()) {
                    speculative_info!(
                        &log_context,
                        "Reconfiguration occurred: restart required".into()
                    );
                    ExecutionStatus::SkipRest(AptosTransactionOutput::new(vm_output))
                } else {
                    assert!(
                        Self::is_transaction_dynamic_change_set_capable(txn),
                        "DirectWriteSet should always create SkipRest transaction, validate_waypoint_change_set provides this guarantee"
                    );
                    ExecutionStatus::Success(AptosTransactionOutput::new(vm_output))
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L1-1)
```text
/// This module provides the foundation for typesafe Coins.
```

**File:** types/src/error.rs (L90-100)
```rust
impl<T: std::fmt::Debug> From<PanicOr<T>> for PartialVMError {
    fn from(err: PanicOr<T>) -> Self {
        match err {
            PanicOr::CodeInvariantError(msg) => {
                PartialVMError::new(StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR)
                    .with_message(msg)
            },
            PanicOr::Or(err) => PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
                .with_message(format!("{:?}", err)),
        }
    }
```
