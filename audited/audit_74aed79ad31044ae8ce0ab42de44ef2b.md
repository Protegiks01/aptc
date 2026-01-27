# Audit Report

## Title
Critical Epilogue Bypass via Double-Fault Error Handling Leading to Zero Gas Charge

## Summary
A critical flaw exists in the transaction epilogue error handling that allows transactions to be discarded with zero gas charged when both success and failure epilogues fail, bypassing the `CHARGE_INVARIANT_VIOLATION` safety feature and violating the fundamental gas charging invariant.

## Finding Description

The Aptos VM enforces a critical invariant: **all executed transactions must charge gas**. This is enforced through the epilogue mechanism, which runs after transaction execution (success or failure) to deduct gas fees and update account state.

The vulnerability exists in the error handling path in `failed_transaction_cleanup`: [1](#0-0) 

When a transaction execution fails, the VM calls `finish_aborted_transaction` to run the failure epilogue. However, if this function returns an error (meaning the failure epilogue itself failed), the error is caught by `unwrap_or_else` and converted to `discarded_output`, which creates a VMOutput with **zero gas charged**: [2](#0-1) [3](#0-2) 

This bypasses the `CHARGE_INVARIANT_VIOLATION` feature (enabled by default), which is designed to keep transactions and charge gas even for invariant violations: [4](#0-3) [5](#0-4) 

The bypass occurs because the error handling in `failed_transaction_cleanup` directly converts the error to `discarded_output` **before** the `TransactionStatus::from_vm_status` logic (which respects `CHARGE_INVARIANT_VIOLATION`) is applied.

**Attack Scenario:**

1. A transaction executes successfully or fails
2. The success epilogue attempts to execute but encounters an error (e.g., unexpected VM state, corrupted account data, or any epilogue assertion failure)
3. The error triggers `on_user_transaction_execution_failure`, which calls `failed_transaction_cleanup`
4. `failed_transaction_cleanup` attempts to run the failure epilogue via `finish_aborted_transaction`
5. The failure epilogue encounters the same or a different error and fails
6. The error is caught by `unwrap_or_else` at line 623 and converted to `discarded_output` with **FeeStatement::zero()**
7. Transaction is discarded without any gas charge, violating the gas payment invariant

The epilogue functions perform critical operations that could fail: [6](#0-5) 

## Impact Explanation

**Severity: HIGH**

This vulnerability breaks multiple critical security guarantees:

1. **Gas Charging Invariant Violation**: The fundamental invariant that all executed transactions must pay gas is violated, allowing transactions to consume computational resources without cost.

2. **Consensus Safety Risk**: If different validators encounter different error conditions (e.g., due to non-deterministic VM behavior or state inconsistencies), they may disagree on whether a transaction should be kept/charged vs. discarded/free, leading to consensus splits and chain forks.

3. **Defense-in-Depth Bypass**: The `CHARGE_INVARIANT_VIOLATION` feature was specifically introduced to ensure gas is charged even during unexpected errors. This bug completely bypasses that safety mechanism.

4. **Economic DoS Vector**: While not directly exploitable by regular users, if any condition triggers both epilogue failures, it could be repeatedly exploited to spam the network without gas costs.

This meets **High Severity** criteria per Aptos bug bounty: "Significant protocol violations" - specifically the gas charging and transaction finalization protocol.

## Likelihood Explanation

**Likelihood: MEDIUM**

While this vulnerability requires specific error conditions to trigger, several realistic scenarios could cause dual epilogue failure:

1. **VM Implementation Bugs**: Any bug in the Move VM that causes incorrect state handling could manifest during epilogue execution
2. **Account State Corruption**: Edge cases in account resource management could leave accounts in states where epilogue operations fail
3. **Numerical Edge Cases**: Overflow or underflow conditions in gas calculations or fee computations
4. **Resource Exhaustion**: While epilogues use `UnmeteredGasMeter`, other resource limits could be hit
5. **Framework Upgrade Issues**: During framework upgrades, incompatibilities could cause epilogue failures

The vulnerability does not require an active attacker to exploit - it manifests automatically whenever the error condition occurs, making it a persistent threat.

## Recommendation

**Fix 1: Never bypass gas charging for kept transactions**

Modify `failed_transaction_cleanup` to ensure that if a transaction should be kept (based on the initial error), gas is always charged even if the failure epilogue fails:

```rust
fn failed_transaction_cleanup(
    &self,
    prologue_session_change_set: SystemSessionChangeSet,
    error_vm_status: VMStatus,
    gas_meter: &mut impl AptosGasMeter,
    txn_data: &TransactionMetadata,
    resolver: &impl AptosMoveResolver,
    module_storage: &impl AptosModuleStorage,
    serialized_signers: &SerializedSigners,
    log_context: &AdapterLogSchema,
    change_set_configs: &ChangeSetConfigs,
    traversal_context: &mut TraversalContext,
) -> (VMStatus, VMOutput) {
    // ... existing gas meter check ...
    
    let txn_status = TransactionStatus::from_vm_status(
        error_vm_status.clone(),
        self.features(),
        self.gas_feature_version() >= RELEASE_V1_38,
    );

    match txn_status {
        TransactionStatus::Keep(status) => {
            let output = self
                .finish_aborted_transaction(...)
                .unwrap_or_else(|epilogue_error| {
                    // CRITICAL: Never return zero gas for kept transactions
                    // Calculate gas based on what was consumed
                    let fee_statement = AptosVM::fee_statement_from_gas_meter(
                        txn_data, 
                        gas_meter, 
                        0 // zero storage refund on error
                    );
                    
                    // Return output with proper gas charging even on epilogue failure
                    VMOutput::new(
                        VMChangeSet::empty(),
                        ModuleWriteSet::empty(),
                        fee_statement,
                        TransactionStatus::Keep(status.clone()),
                    )
                });
            (error_vm_status, output)
        },
        TransactionStatus::Discard(status_code) => {
            // Only discard with zero gas if original error was discardable
            (error_vm_status, discarded_output(status_code))
        },
        TransactionStatus::Retry => unreachable!(),
    }
}
```

**Fix 2: Add safeguard in discarded_output**

Add logging and metrics when discarded_output is called to detect anomalies:

```rust
pub(crate) fn discarded_output(status_code: StatusCode) -> VMOutput {
    // Log critical event - this should rarely happen
    error!("Transaction discarded with zero gas charge: {:?}", status_code);
    DISCARDED_TRANSACTION_COUNTER.inc();
    VMOutput::empty_with_status(TransactionStatus::Discard(status_code))
}
```

## Proof of Concept

The following demonstrates the vulnerable code path (note: this is a conceptual PoC as triggering requires specific error conditions):

```rust
// Test case showing the vulnerable path
#[test]
fn test_double_epilogue_failure_bypass() {
    // Setup: Create a transaction that will succeed
    let mut transaction = create_test_transaction();
    
    // Inject fail_point to force success epilogue to fail
    fail::cfg("move_adapter::run_success_epilogue", "return(error)").unwrap();
    
    // Execute transaction
    let (status, output) = vm.execute_user_transaction(...);
    
    // At this point, failed_transaction_cleanup is called
    // If finish_aborted_transaction also fails...
    fail::cfg("move_adapter::run_failure_epilogue", "return(error)").unwrap();
    
    // Result: Transaction discarded with FeeStatement::zero()
    assert_eq!(output.fee_statement().gas_used(), 0);
    assert!(matches!(output.status(), TransactionStatus::Discard(_)));
    
    // VULNERABILITY: Zero gas charged despite transaction consuming resources
}
```

**Notes:**
- This vulnerability exists in the error recovery path and is triggered by exceptional conditions
- The impact is severe because it violates the fundamental gas charging invariant
- The fix must ensure gas is ALWAYS charged for kept transactions, even if epilogue execution fails
- Proper monitoring and alerting should be added to detect when this code path is exercised

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L610-623)
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
```

**File:** aptos-move/aptos-vm/src/errors.rs (L307-309)
```rust
pub(crate) fn discarded_output(status_code: StatusCode) -> VMOutput {
    VMOutput::empty_with_status(TransactionStatus::Discard(status_code))
}
```

**File:** aptos-move/aptos-vm-types/src/output.rs (L62-70)
```rust
    pub fn empty_with_status(status: TransactionStatus) -> Self {
        Self {
            change_set: VMChangeSet::empty(),
            module_write_set: ModuleWriteSet::empty(),
            fee_statement: FeeStatement::zero(),
            status,
            trace: Trace::empty(),
        }
    }
```

**File:** types/src/transaction/mod.rs (L1639-1647)
```rust
            Err(code) => {
                if code.status_type() == StatusType::InvariantViolation
                    && features.is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION)
                {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(code)))
                } else {
                    Self::Discard(code)
                }
            },
```

**File:** types/src/on_chain_config/aptos_features.rs (L194-194)
```rust
            FeatureFlag::CHARGE_INVARIANT_VIOLATION,
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L596-632)
```text
        assert!(txn_max_gas_units >= gas_units_remaining, error::invalid_argument(EOUT_OF_GAS));
        let gas_used = txn_max_gas_units - gas_units_remaining;

        assert!(
            (txn_gas_price as u128) * (gas_used as u128) <= MAX_U64,
            error::out_of_range(EOUT_OF_GAS)
        );
        let transaction_fee_amount = txn_gas_price * gas_used;

        // it's important to maintain the error code consistent with vm
        // to do failed transaction cleanup.
        if (!skip_gas_payment(is_simulation, gas_payer)) {
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

            if (transaction_fee_amount > storage_fee_refunded) {
                let burn_amount = transaction_fee_amount - storage_fee_refunded;
                transaction_fee::burn_fee(gas_payer, burn_amount);
            } else if (transaction_fee_amount < storage_fee_refunded) {
                let mint_amount = storage_fee_refunded - transaction_fee_amount;
                transaction_fee::mint_and_refund(gas_payer, mint_amount);
            };
        };

        // Increment sequence number
        let addr = signer::address_of(&account);
        account::increment_sequence_number(addr);
    }
```
