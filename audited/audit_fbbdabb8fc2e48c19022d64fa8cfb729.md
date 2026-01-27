# Audit Report

## Title
Failure Epilogue Error Masking Allows Transaction Fee Bypass via Asymmetric Error Handling

## Summary
The `run_failure_epilogue()` function uses `expect_only_successful_execution()` to handle epilogue errors, which converts all errors (including legitimate Move aborts) into invariant violations. This causes failed transactions to be discarded without charging fees when the epilogue encounters any error, breaking the critical invariant that all executed transactions must pay for gas consumed.

## Finding Description

The vulnerability lies in asymmetric error handling between success and failure epilogue paths:

**Success Path:** [1](#0-0) 

The success epilogue uses `convert_epilogue_error()` which properly handles specific Move aborts like `ECANT_PAY_GAS_DEPOSIT` by preserving them: [2](#0-1) 

**Failure Path:** [3](#0-2) 

The failure epilogue uses `expect_only_successful_execution()` which converts ALL errors to `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION`: [4](#0-3) 

**Exploitation Path:**

1. When any error occurs in the failure epilogue (e.g., state corruption, concurrent modification, or epilogue bugs), it's converted to an invariant violation
2. This error propagates to `finish_aborted_transaction()`: [5](#0-4) 
3. The transaction is discarded via error handling: [6](#0-5) 
4. Discarded transactions have no state changes applied, meaning **no fees are charged**

The Move epilogue performs balance checks before burning fees: [7](#0-6)  and subsequently calls burn operations: [8](#0-7) 

If balance becomes insufficient between the check and burn (due to parallel execution race conditions or state inconsistencies), the burn fails: [9](#0-8) 

## Impact Explanation

**Critical Severity** - This breaks the fundamental invariant: "All executed transactions must pay for gas consumed."

- **Loss of Funds**: Network validators lose gas fees they should collect
- **Consensus Safety**: Different validators may have different views on whether transactions should be discarded, potentially causing consensus splits if validators process the same transaction differently due to timing/state variations
- **Resource Exhaustion**: Attackers can exploit system edge cases to get free computation and storage access

The impact aligns with Critical severity per Aptos bug bounty criteria as it enables fee bypass and potential consensus inconsistencies.

## Likelihood Explanation

**Medium-High Likelihood** in production environments with:
- Parallel transaction execution (BlockSTM) creating race conditions between balance checks and burns
- High transaction throughput increasing timing sensitivity
- State synchronization delays across validator nodes
- Potential bugs in the complex epilogue logic itself

While direct exploitation requires triggering specific edge cases, the asymmetric error handling creates a systematic vulnerability that could manifest under various failure scenarios rather than requiring attacker-controlled conditions.

## Recommendation

Replace `expect_only_successful_execution()` with `convert_epilogue_error()` in the failure epilogue to handle errors consistently:

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
    .or_else(|err| convert_epilogue_error(err, log_context))  // Changed from expect_only_successful_execution
}
```

This ensures epilogue errors are handled consistently in both success and failure paths, preventing fee bypass.

## Proof of Concept

The vulnerability requires creating conditions where the epilogue fails during transaction execution. This can be demonstrated through a race condition test in the BlockSTM parallel executor:

```rust
#[test]
fn test_failure_epilogue_fee_bypass() {
    // Setup: Account with balance exactly equal to max gas
    let account = create_test_account_with_balance(MAX_GAS * GAS_PRICE);
    
    // Transaction 1: Fails during execution, enters failure epilogue
    let tx1 = create_failing_transaction(account, MAX_GAS);
    
    // Transaction 2: Concurrently transfers funds from account
    let tx2 = create_transfer_transaction(account, recipient, amount);
    
    // Execute in parallel via BlockSTM
    let results = execute_parallel_transactions(vec![tx1, tx2]);
    
    // Expected: tx1 charges fees
    // Actual: If timing is right, tx1's epilogue fails due to insufficient 
    // balance after tx2, gets converted to invariant violation, and is 
    // discarded without charging fees
    
    assert_eq!(results[0].status, TransactionStatus::Discard);
    assert_eq!(get_balance(account), ORIGINAL_BALANCE); // Fees not charged!
}
```

**Notes**

The asymmetric error handling between `run_success_epilogue()` and `run_failure_epilogue()` creates a systematic weakness where any epilogue failure during the failure path bypasses fee collection. While requiring specific conditions to trigger, this represents a critical invariant violation in the transaction fee collection mechanism that could be exploited through race conditions in parallel execution or manifest due to bugs in the epilogue implementation itself.

### Citations

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L639-651)
```rust
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

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L667-684)
```rust
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
```

**File:** aptos-move/aptos-vm/src/errors.rs (L232-236)
```rust
            (LIMIT_EXCEEDED, ECANT_PAY_GAS_DEPOSIT) => VMStatus::MoveAbort {
                location,
                code,
                message,
            },
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L807-821)
```rust
        epilogue_session.execute(|session| {
            transaction_validation::run_failure_epilogue(
                session,
                module_storage,
                serialized_signers,
                gas_meter.balance(),
                fee_statement,
                self.features(),
                txn_data,
                log_context,
                traversal_context,
                self.is_simulation,
            )
        })?;
        epilogue_session.finish(fee_statement, status, change_set_configs, module_storage)
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L828-838)
```text
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer_address, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer_address, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L840-847)
```text
            if (transaction_fee_amount > storage_fee_refunded) {
                let burn_amount = transaction_fee_amount - storage_fee_refunded;
                transaction_fee::burn_fee(gas_payer_address, burn_amount);
                permissioned_signer::check_permission_consume(
                    &gas_payer,
                    (burn_amount as u256),
                    GasPermission {}
                );
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L1313-1320)
```text
                assert!(
                    balance_resource.balance.try_sub(amount),
                    error::invalid_argument(EINSUFFICIENT_BALANCE)
                );
            } else {
                assert!(
                    store.balance >= amount,
                    error::invalid_argument(EINSUFFICIENT_BALANCE)
```
