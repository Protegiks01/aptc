# Audit Report

## Title
Bypass of CHARGE_INVARIANT_VIOLATION Feature Flag for Prologue Validation Errors

## Summary
The `unwrap_or_discard!` macro in the AptosVM transaction execution path bypasses the `CHARGE_INVARIANT_VIOLATION` feature flag, causing invariant violations during prologue validation to be discarded without gas charges, regardless of whether the flag is enabled. This undermines the security mitigation intended to prevent free VM bug testing.

## Finding Description
The Aptos codebase implements a `CHARGE_INVARIANT_VIOLATION` feature flag to prevent attackers from exploiting invariant violations for free VM security auditing. When enabled (which is the default), invariant violations should result in kept transactions with gas charges. [1](#0-0) 

The intended behavior is implemented in `TransactionStatus::from_vm_status()`, which checks the feature flag: [2](#0-1) 

However, during transaction execution, the `unwrap_or_discard!` macro is used to handle errors from prologue validation: [3](#0-2) [4](#0-3) 

This macro directly calls `discarded_output()`, which creates a `TransactionStatus::Discard` without going through `from_vm_status()`: [5](#0-4) 

When unexpected errors occur during prologue execution, they are converted to `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION`, which is an invariant violation (status code 2015 in the 2000-2999 range): [6](#0-5) [7](#0-6) 

**Critical Gap**: While invariant violations during transaction execution and epilogue are subject to the `CHARGE_INVARIANT_VIOLATION` feature flag check, invariant violations during prologue validation bypass this check entirely due to the `unwrap_or_discard!` macro.

## Impact Explanation
This vulnerability has **Medium** severity. While it doesn't directly cause fund loss or consensus violations, it undermines a deliberate security mitigation. 

The practical impact is limited because:
1. An attacker cannot arbitrarily trigger invariant violations - these only occur when there are actual bugs in the framework or VM
2. The bypass only affects prologue validation errors, not all invariant violations
3. Normal validation errors (like insufficient balance) still work correctly

However, IF a bug exists in prologue code that causes invariant violations, this bypass allows exploitation without gas costs, defeating the purpose of the `CHARGE_INVARIANT_VIOLATION` mitigation. This could enable attackers to probe for and exploit VM bugs more easily.

## Likelihood Explanation
**Likelihood: Low to Medium**

The likelihood depends on the existence of exploitable bugs in the prologue validation code. Since the prologue is framework code that runs before user code execution, bugs there would be rare but impactful.

The bypass itself is deterministic and affects all transactions, but requires a pre-existing vulnerability to be exploitable. An attacker cannot use this for systematic "free security auditing" without finding actual bugs first.

## Recommendation
Apply the `CHARGE_INVARIANT_VIOLATION` feature flag check consistently for all transaction error paths, including prologue validation.

**Recommended Fix:**

Modify the `unwrap_or_discard!` macro or create a new error handling path that uses `TransactionStatus::from_vm_status()` instead of directly calling `discarded_output()`:

```rust
macro_rules! unwrap_or_handle_vm_status {
    ($res:expr, $features:expr, $gas_version:expr, $use_abort_messages:expr) => {
        match $res {
            Ok(s) => s,
            Err(e) => {
                let status: VMStatus = e.into();
                let txn_status = TransactionStatus::from_vm_status(
                    status.clone(),
                    $features,
                    $gas_version,
                );
                
                match txn_status {
                    TransactionStatus::Keep(_) => {
                        // Handle as kept transaction with failure epilogue
                        // This ensures gas is charged for invariant violations
                        // when CHARGE_INVARIANT_VIOLATION is enabled
                    },
                    TransactionStatus::Discard(code) => {
                        let o = discarded_output(code);
                        return (status, o);
                    },
                    _ => unreachable!(),
                }
            },
        }
    };
}
```

Then update the usage in `execute_user_transaction_impl` to use this new macro instead of `unwrap_or_discard!`.

## Proof of Concept
The existing test demonstrates the intended behavior: [8](#0-7) 

This test shows that with `CHARGE_INVARIANT_VIOLATION` enabled, invariant violations should be kept and charged. However, the test uses `fail::cfg` to inject an error during `execute_script_or_entry_function`, which is AFTER prologue validation.

To demonstrate the bypass, a test would need to inject an error during prologue validation itself. Since the `unwrap_or_discard!` macro is used at line 2001 (during prologue validation), errors there bypass the feature flag check entirely.

A complete PoC would require:
1. Creating a scenario that triggers `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION` during `validate_signed_transaction()`
2. Verifying that the transaction is discarded regardless of the `CHARGE_INVARIANT_VIOLATION` flag
3. Comparing with the same error triggered during normal execution (which correctly respects the flag)

**Note**: The practical exploitability is limited because attackers cannot arbitrarily trigger these prologue invariant violations - they require pre-existing bugs in the framework code.

### Citations

**File:** types/src/on_chain_config/aptos_features.rs (L194-194)
```rust
            FeatureFlag::CHARGE_INVARIANT_VIOLATION,
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L176-189)
```rust
macro_rules! unwrap_or_discard {
    ($res:expr) => {
        match $res {
            Ok(s) => s,
            Err(e) => {
                // covers both VMStatus itself and VMError which can convert to VMStatus
                let s: VMStatus = e.into();

                let o = discarded_output(s.status_code());
                return (s, o);
            },
        }
    };
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2001-2012)
```rust
        let serialized_signers = unwrap_or_discard!(prologue_session.execute(|session| {
            self.validate_signed_transaction(
                session,
                code_storage,
                txn,
                &txn_data,
                log_context,
                is_approved_gov_script,
                &mut traversal_context,
                gas_meter,
            )
        }));
```

**File:** aptos-move/aptos-vm/src/errors.rs (L156-170)
```rust
                (category, reason) => {
                    let mut err_msg = format!(
                        "[aptos_vm] Unexpected prologue Move abort: {:?}::{:?} (Category: {:?} Reason: {:?})",
                        location, code, category, reason
                    );
                    if let Some(abort_msg) = message {
                        err_msg.push_str(" Message: ");
                        err_msg.push_str(&abort_msg);
                    }
                    speculative_error!(log_context, err_msg.clone());
                    return Err(VMStatus::Error {
                        status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                        sub_status: None,
                        message: Some(err_msg),
                    });
```

**File:** aptos-move/aptos-vm/src/errors.rs (L307-309)
```rust
pub(crate) fn discarded_output(status_code: StatusCode) -> VMOutput {
    VMOutput::empty_with_status(TransactionStatus::Discard(status_code))
}
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L846-846)
```rust
    UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION = 2015,
```

**File:** aptos-move/e2e-testsuite/src/tests/invariant_violation.rs (L13-61)
```rust
#[test]
fn invariant_violation_error() {
    let _scenario = fail::FailScenario::setup();
    fail::cfg("aptos_vm::execute_script_or_entry_function", "100%return").unwrap();

    ::aptos_logger::Logger::init_for_testing();

    let mut executor = FakeExecutor::from_head_genesis();

    let sender = executor.create_raw_account_data(1_000_000, 10);
    let receiver = executor.create_raw_account_data(100_000, 10);
    executor.add_account_data(&sender);
    executor.add_account_data(&receiver);

    let transfer_amount = 1_000;
    let txn = peer_to_peer_txn(sender.account(), receiver.account(), 10, transfer_amount, 0);

    // execute transaction
    let output = executor.execute_transaction(txn.clone());

    // CHARGE_INVARIANT_VIOLATION enabled at genesis so this txn is kept.
    assert_eq!(
        output.status(),
        &TransactionStatus::Keep(ExecutionStatus::MiscellaneousError(Some(
            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
        ))),
    );

    // Disable the CHARGE_INVARIANT_VIOLATION flag.
    executor.exec("features", "change_feature_flags_internal", vec![], vec![
        MoveValue::Signer(AccountAddress::ONE)
            .simple_serialize()
            .unwrap(),
        MoveValue::Vector(vec![]).simple_serialize().unwrap(),
        MoveValue::Vector(vec![MoveValue::U64(
            FeatureFlag::CHARGE_INVARIANT_VIOLATION as u64,
        )])
        .simple_serialize()
        .unwrap(),
    ]);

    let output = executor.execute_transaction(txn);

    // With CHARGE_INVARIANT_VIOLATION disabled this transaction will be discarded.
    assert_eq!(
        output.status(),
        &TransactionStatus::Discard(DiscardedVMStatus::UNKNOWN_INVARIANT_VIOLATION_ERROR),
    );
}
```
