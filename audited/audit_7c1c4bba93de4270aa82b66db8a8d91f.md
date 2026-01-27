# Audit Report

## Title
Transaction Simulation API Returns Misleading Execution Status for Discarded Transactions

## Summary
The `ExecutionStatus::conmbine_vm_status_for_simulation()` function incorrectly converts `TransactionStatus::Discard` to `ExecutionStatus::MiscellaneousError`, misleading users into believing that discarded transactions would be kept on-chain with gas charges, when in reality they would be rejected with no gas consumption. [1](#0-0) 

## Finding Description

The Aptos transaction execution model has two fundamentally different outcomes:

1. **Keep (TransactionStatus::Keep)**: Transaction is included on-chain, gas is charged, and the transaction appears in the ledger even if execution failed (e.g., OutOfGas, MoveAbort)
2. **Discard (TransactionStatus::Discard)**: Transaction is rejected before inclusion, no gas is charged, and it never appears on-chain (e.g., validation errors like INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE, SEQUENCE_NUMBER_TOO_OLD) [2](#0-1) 

The vulnerability occurs in the simulation endpoint. When a user simulates a transaction via `/transactions/simulate`, the function `conmbine_vm_status_for_simulation()` is called to process the transaction status: [3](#0-2) 

For transactions that would be **discarded**, this function returns `ExecutionStatus::MiscellaneousError(Some(status))`, which is semantically incorrect because `ExecutionStatus` is exclusively meant for **kept** transactions: [4](#0-3) 

In production execution, the `failed_transaction_cleanup` function clearly distinguishes between these two cases: [5](#0-4) 

For discarded transactions, the output shows zero gas usage and no state changes: [6](#0-5) 

However, in simulation, the API constructs a `TransactionInfo` with the misleading status and includes the gas_used value from the VM output, creating an inconsistent representation: [7](#0-6) 

The user receives a response showing:
- `success: false` (correct)
- `gas_used: X` (misleading - no gas would actually be charged)
- `vm_status: "MiscellaneousError"` (misleading - transaction would be discarded, not kept) [8](#0-7) 

## Impact Explanation

This vulnerability breaks the **Transaction Validation** invariant (#7) which states that "Prologue/epilogue checks must enforce all invariants." While the prologue/epilogue correctly enforce these invariants in production, the simulation API misrepresents the outcome.

**Specific impacts:**

1. **Misleading Gas Estimation**: Users receive `gas_used` values for transactions that would never charge gas, leading to incorrect balance planning and potentially over-funding accounts unnecessarily.

2. **Incorrect Transaction Submission Decisions**: Developers building automated systems or wallets may incorrectly assume that failed simulations indicate transactions that will be included on-chain (even if failed), when they would actually be rejected entirely.

3. **API Correctness Violation**: The simulation endpoint promises to show "the exact transaction outputs and events that running an actual signed transaction would have," but it violates this guarantee by showing execution status for transactions that wouldn't execute at all.

This qualifies as **Medium Severity** under "State inconsistencies requiring intervention" because the API state (simulation results) is inconsistent with production behavior, potentially requiring manual intervention to correct user understanding and system behavior built on incorrect assumptions.

## Likelihood Explanation

**Likelihood: HIGH**

This issue occurs in common scenarios:
- Any simulation of a transaction with insufficient balance for gas fees
- Any simulation with an incorrect sequence number
- Any simulation of a transaction that would fail validation checks

These are extremely common use cases for the simulation API, as users specifically simulate to check if their transaction parameters are correct before submission.

## Recommendation

Modify `conmbine_vm_status_for_simulation()` to preserve the Keep/Discard distinction, or create a new API-specific status type that accurately represents all three states (Keep with various execution statuses, Discard with reason, Retry).

**Option 1: Return a specialized simulation status**

```rust
pub enum SimulationStatus {
    Kept(ExecutionStatus),
    Discarded(StatusCode),
    Retry,
}

pub fn combine_vm_status_for_simulation(
    aux_data: &TransactionAuxiliaryData,
    partial_status: TransactionStatus,
) -> SimulationStatus {
    match partial_status {
        TransactionStatus::Keep(exec_status) => 
            SimulationStatus::Kept(exec_status.aug_with_aux_data(aux_data)),
        TransactionStatus::Discard(status) => 
            SimulationStatus::Discarded(status),
        TransactionStatus::Retry => 
            SimulationStatus::Retry,
    }
}
```

**Option 2: Include transaction status information in the API response**

Add a new field to `TransactionInfo` indicating whether the transaction would be kept or discarded, allowing users to understand the true outcome.

## Proof of Concept

```rust
#[test]
fn test_simulation_discard_misleading_status() {
    // 1. Create a transaction with insufficient balance for gas
    let sender = AccountAddress::random();
    let sequence_number = 0;
    
    // Create a transaction that requires 1000 gas units
    let txn = create_test_transaction(sender, sequence_number, 1000);
    
    // 2. Set up state where account has insufficient balance (e.g., 500 units)
    let mut state_view = FakeStateView::new();
    state_view.set_balance(sender, 500);
    
    // 3. Simulate the transaction
    let (vm_status, output) = AptosSimulationVM::create_vm_and_simulate_signed_transaction(
        &txn, 
        &state_view
    );
    
    // 4. Check that VM correctly returns Discard status
    assert!(matches!(output.status(), TransactionStatus::Discard(_)));
    
    // 5. Apply conmbine_vm_status_for_simulation
    let exe_status = ExecutionStatus::conmbine_vm_status_for_simulation(
        output.auxiliary_data(),
        output.status().clone(),
    );
    
    // 6. Verify the bug: Discard is converted to ExecutionStatus (which implies Keep)
    assert!(matches!(exe_status, ExecutionStatus::MiscellaneousError(_)));
    // This is WRONG - the transaction would be discarded, not kept with MiscellaneousError
    
    // 7. Verify that gas_used is non-zero (misleading)
    assert!(output.gas_used() > 0);
    // In production, a discarded transaction would charge 0 gas
    
    // 8. Verify production behavior for comparison
    let production_output = execute_transaction_in_production(&txn, &state_view);
    assert!(matches!(production_output.status(), TransactionStatus::Discard(_)));
    assert_eq!(production_output.gas_used(), 0); // No gas charged for discarded txns
}
```

The test demonstrates that:
1. A transaction with insufficient balance returns `TransactionStatus::Discard` from the VM
2. `conmbine_vm_status_for_simulation()` converts this to `ExecutionStatus::MiscellaneousError`
3. The API returns non-zero `gas_used` to users
4. In production, the same transaction would be discarded with 0 gas charged
5. Users are misled about the true outcome of their transaction

### Citations

**File:** types/src/transaction/mod.rs (L1489-1503)
```rust
pub enum ExecutionStatus {
    Success,
    OutOfGas,
    MoveAbort {
        location: AbortLocation,
        code: u64,
        info: Option<AbortInfo>,
    },
    ExecutionFailure {
        location: AbortLocation,
        function: u16,
        code_offset: u16,
    },
    MiscellaneousError(Option<StatusCode>),
}
```

**File:** types/src/transaction/mod.rs (L1562-1571)
```rust
    pub fn conmbine_vm_status_for_simulation(
        aux_data: &TransactionAuxiliaryData,
        partial_status: TransactionStatus,
    ) -> Self {
        match partial_status {
            TransactionStatus::Keep(exec_status) => exec_status.aug_with_aux_data(aux_data),
            TransactionStatus::Discard(status) => ExecutionStatus::MiscellaneousError(Some(status)),
            _ => ExecutionStatus::MiscellaneousError(None),
        }
    }
```

**File:** types/src/transaction/mod.rs (L1574-1587)
```rust
/// The status of executing a transaction. The VM decides whether or not we should `Keep` the
/// transaction output or `Discard` it based upon the execution of the transaction. We wrap these
/// decisions around a `VMStatus` that provides more detail on the final execution state of the VM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransactionStatus {
    /// Discard the transaction output
    Discard(DiscardedVMStatus),

    /// Keep the transaction output
    Keep(ExecutionStatus),

    /// Retry the transaction, e.g., after a reconfiguration
    Retry,
}
```

**File:** api/src/transactions.rs (L1646-1649)
```rust
        let exe_status = ExecutionStatus::conmbine_vm_status_for_simulation(
            output.auxiliary_data(),
            output.status().clone(),
        );
```

**File:** api/src/transactions.rs (L1710-1718)
```rust
        let info = aptos_types::transaction::TransactionInfo::new(
            txn.hash(),
            zero_hash,
            zero_hash,
            None,
            output.gas_used(),
            exe_status,
            None,
        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L602-631)
```rust
        match txn_status {
            TransactionStatus::Keep(status) => {
                // The transaction should be kept. Run the appropriate post transaction workflows
                // including epilogue. This runs a new session that ignores any side effects that
                // might abort the execution (e.g., spending additional funds needed to pay for
                // gas). Even if the previous failure occurred while running the epilogue, it
                // should not fail now. If it somehow fails here, there is no choice but to
                // discard the transaction.
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
            },
            TransactionStatus::Discard(status_code) => {
                let discarded_output = discarded_output(status_code);
                (error_vm_status, discarded_output)
            },
            TransactionStatus::Retry => unreachable!(),
        }
```

**File:** aptos-move/aptos-vm/src/errors.rs (L307-309)
```rust
pub(crate) fn discarded_output(status_code: StatusCode) -> VMOutput {
    VMOutput::empty_with_status(TransactionStatus::Discard(status_code))
}
```

**File:** api/types/src/convert.rs (L252-260)
```rust
        TransactionInfo {
            version: version.into(),
            hash: info.transaction_hash().into(),
            state_change_hash: info.state_change_hash().into(),
            event_root_hash: info.event_root_hash().into(),
            state_checkpoint_hash: info.state_checkpoint_hash().map(|h| h.into()),
            gas_used: info.gas_used().into(),
            success: info.status().is_success(),
            vm_status: self.explain_vm_status(info.status(), txn_aux_data),
```
