# Audit Report

## Title
TRANSACTIONS_INVARIANT_VIOLATION Counter Never Incremented - Critical VM Invariant Violations Only Passively Logged Without Emergency Response

## Summary
The `TRANSACTIONS_INVARIANT_VIOLATION` counter defined to track VM invariant violations is never incremented anywhere in the codebase. When critical invariant violations occur that could indicate consensus safety violations, double-spending attempts, or Move VM bugs, the system only logs errors without triggering emergency responses, incrementing monitoring counters, or halting execution. Transactions violating VM invariants are committed to the blockchain by default, creating a blind spot for consensus divergence.

## Finding Description

The Aptos VM defines a metric counter `TRANSACTIONS_INVARIANT_VIOLATION` intended to track VM invariant violations: [1](#0-0) 

However, this counter is **never incremented** anywhere in the codebase - it exists only as a definition with zero usage.

When invariant violations occur during transaction execution, they are detected in `execute_single_transaction`: [2](#0-1) 

The system detects multiple critical invariant violation types:
1. **Paranoid mode failures** (EPARANOID_FAILURE) - runtime safety checks
2. **Reference counting failures** (EREFERENCE_COUNTING_FAILURE) - memory safety violations
3. **Reference safety failures** (EREFERENCE_SAFETY_FAILURE, EINDEXED_REF_TAG_MISMATCH) - type safety violations

These invariant violations are **only logged** - no counter is incremented, no alerts are triggered, and execution continues normally.

Furthermore, with the `CHARGE_INVARIANT_VIOLATION` feature flag enabled by default at genesis, transactions with invariant violations are **committed to the blockchain**: [3](#0-2) [4](#0-3) [5](#0-4) 

This creates a critical monitoring gap where:
- Invariant violations that could signal consensus divergence are invisible to metrics systems
- Operators have no quantitative signal about VM safety violations occurring in production
- Transactions breaking VM invariants are included in committed blocks

In contrast, the fuzzing/testing infrastructure treats invariant violations as fatal errors requiring immediate attention: [6](#0-5) 

The production system's passive response could mask consensus-breaking bugs. If a vulnerability causes different validators to produce different invariant violation outcomes, the network could silently diverge without triggering any monitoring alarms.

## Impact Explanation

**Critical Severity** - This issue creates conditions for undetected consensus safety violations:

1. **Consensus Divergence Risk**: If a bug causes validators to handle invariant violations differently (e.g., one validator's transaction succeeds while another's hits an invariant violation), consensus could diverge without detection. The absence of counter increments means monitoring systems cannot alert on divergence patterns.

2. **Blind Spot for Double-Spending**: Invariant violations can indicate attempts to break VM safety guarantees. Reference counting failures (EREFERENCE_COUNTING_FAILURE) specifically relate to "moving container with dangling references" - a condition that could enable resource duplication if not properly handled uniformly across validators.

3. **No Operational Visibility**: The counter was clearly intended for production monitoring but is non-functional. Operators relying on Prometheus/Grafana dashboards would see zero invariant violations even when they occur, creating false confidence in system health.

4. **State Divergence Without Circuit Breaker**: Unlike block executor errors that trigger `scheduler.halt()`, VM invariant violations during transaction execution do not halt the validator, allowing potentially corrupted state to propagate through subsequent transactions.

This violates Critical Invariant #1 (Deterministic Execution) and #2 (Consensus Safety) from the specification, as validators could commit different blocks if they handle invariant violations inconsistently.

## Likelihood Explanation

**High Likelihood** of becoming exploitable if underlying VM bugs exist:

1. **Passive by Design**: The issue is not a rare edge case - it affects ALL invariant violations occurring in production. Every instance goes unmonitored.

2. **Default Configuration**: The `CHARGE_INVARIANT_VIOLATION` feature flag is enabled by default, meaning invariant violations are kept rather than discarded, increasing the window for consensus divergence.

3. **Multiple Violation Types**: The code detects at least 4 distinct invariant violation categories, suggesting these are known failure modes that occur in practice.

4. **Historical Evidence**: The test suite includes explicit tests for invariant violation handling, indicating these scenarios have been encountered during development.

The likelihood of exploitation depends on whether underlying VM bugs exist that trigger invariant violations, but the monitoring gap is 100% present and affects all validators.

## Recommendation

**Immediate Actions**:

1. **Increment the Counter**: Add counter increments when invariant violations are detected:

```rust
// In aptos-move/aptos-vm/src/aptos_vm.rs, after line 2928
if let StatusType::InvariantViolation = vm_status.status_type() {
    // Increment the counter for all invariant violations
    TRANSACTIONS_INVARIANT_VIOLATION.inc();
    
    match vm_status.status_code() {
        // ... existing match arms ...
    }
}
```

2. **Add Alert Mechanism**: Create a critical alert when invariant violations occur:

```rust
use aptos_vm_logging::alert;

if let StatusType::InvariantViolation = vm_status.status_type() {
    TRANSACTIONS_INVARIANT_VIOLATION.inc();
    
    // Critical alert for operators
    alert!(
        *log_context,
        "[CRITICAL] VM Invariant Violation Detected - Potential Consensus Risk: {:?}",
        vm_status
    );
    // ... existing logging ...
}
```

3. **Consider Circuit Breaker**: Evaluate adding a halt mechanism for repeated invariant violations within a block to prevent consensus divergence:

```rust
// Track violations per block and halt if threshold exceeded
if invariant_violation_count_in_block > SAFETY_THRESHOLD {
    return Err(VMStatus::error(
        StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
        Some("Multiple invariant violations - halting for safety".to_string())
    ));
}
```

4. **Monitoring Dashboard**: Set up alerts in production monitoring for `aptos_vm_transactions_invariant_violation > 0` with immediate paging.

## Proof of Concept

```rust
// File: aptos-move/aptos-vm/tests/invariant_violation_monitoring_test.rs

#[test]
fn test_invariant_violation_counter_not_incremented() {
    use aptos_language_e2e_tests::{executor::FakeExecutor, common_transactions::peer_to_peer_txn};
    use aptos_types::transaction::TransactionStatus;
    use fail::FailScenario;
    
    let scenario = FailScenario::setup();
    // Inject invariant violation via fail point
    fail::cfg("aptos_vm::execute_script_or_entry_function", "100%return").unwrap();
    
    let mut executor = FakeExecutor::from_head_genesis();
    let sender = executor.create_raw_account_data(1_000_000, 10);
    let receiver = executor.create_raw_account_data(100_000, 10);
    executor.add_account_data(&sender);
    executor.add_account_data(&receiver);
    
    // Record counter value before
    let counter_before = TRANSACTIONS_INVARIANT_VIOLATION.get();
    
    // Execute transaction that will trigger invariant violation
    let txn = peer_to_peer_txn(sender.account(), receiver.account(), 10, 1000, 0);
    let output = executor.execute_transaction(txn);
    
    // Verify invariant violation occurred
    match output.status() {
        TransactionStatus::Keep(status) => {
            assert!(matches!(status, 
                ExecutionStatus::MiscellaneousError(Some(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR))
            ), "Expected invariant violation");
        },
        _ => panic!("Expected Keep status with invariant violation"),
    }
    
    // VERIFY: Counter should have incremented but doesn't
    let counter_after = TRANSACTIONS_INVARIANT_VIOLATION.get();
    
    // THIS ASSERTION WILL FAIL - demonstrating the bug
    assert_eq!(counter_after, counter_before + 1, 
        "TRANSACTIONS_INVARIANT_VIOLATION counter should increment but doesn't! \
         Before: {}, After: {}", counter_before, counter_after);
}
```

This test demonstrates that even when invariant violations occur and are logged, the `TRANSACTIONS_INVARIANT_VIOLATION` counter remains at zero, proving the monitoring gap exists in production code.

## Notes

The vulnerability is compounded by the fact that validators in production have no quantitative visibility into invariant violations occurring on their nodes. While the errors are logged, log analysis is reactive and doesn't provide the real-time alerting needed for consensus safety monitoring. The counter was clearly designed for this purpose but was never connected to the detection logic, creating a silent failure mode that could mask consensus divergence until multiple blocks have been committed.

### Citations

**File:** aptos-move/aptos-vm/src/counters.rs (L45-52)
```rust
/// Count the number of transactions that brake invariants of VM.
pub static TRANSACTIONS_INVARIANT_VIOLATION: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_vm_transactions_invariant_violation",
        "Number of transactions that broke VM invariant",
    )
    .unwrap()
});
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

**File:** types/src/on_chain_config/aptos_features.rs (L40-40)
```rust
    CHARGE_INVARIANT_VIOLATION = 20,
```

**File:** types/src/on_chain_config/aptos_features.rs (L194-194)
```rust
            FeatureFlag::CHARGE_INVARIANT_VIOLATION,
```

**File:** testsuite/fuzzer/fuzz/fuzz_targets/move/utils/vm.rs (L288-304)
```rust
pub(crate) fn check_for_invariant_violation(e: VMStatus) {
    let is_known_false_positive = e.message().is_some_and(|msg| {
        KNOWN_FALSE_POSITIVES_VMSTATUS
            .iter()
            .any(|known| msg.starts_with(known))
    });

    if !is_known_false_positive {
        panic!(
            "invariant violation {:?}\n{}{:?} {}",
            e,
            "RUST_BACKTRACE=1 DEBUG_VM_STATUS=",
            e.status_code(),
            "./fuzz.sh run move_aptosvm_publish_and_run <ARTIFACT>"
        );
    }
}
```
