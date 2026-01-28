# Audit Report

## Title
Storage Fee Charged Without State Commitment When Epilogue Fails After User Execution

## Summary
When a user transaction executes successfully but the epilogue subsequently fails, users are charged storage fees for state changes that are never committed to the blockchain. This occurs because storage fees are permanently deducted from the gas meter based on the user's change set before epilogue execution, but epilogue failures result in only prologue changes being committed while the gas meter retains all charges for discarded user changes.

## Finding Description

The vulnerability exists in the transaction execution flow within the Aptos VM. The critical sequence is:

1. After successful user transaction execution, `charge_change_set_and_respawn_session()` is called to charge storage fees for the user's state changes [1](#0-0) 

2. This invokes `charge_change_set()` which calls `process_storage_fee_for_all()` to charge IO gas and storage fees [2](#0-1) 

3. The comment explicitly states "Gas fee cannot change after this line" [3](#0-2) 

4. `success_transaction_cleanup()` then executes the epilogue [4](#0-3) 

5. The epilogue can fail for multiple reasons, including insufficient balance to pay gas deposit [5](#0-4) 

6. When epilogue fails, `on_user_transaction_execution_failure()` is called with the original prologue change set [6](#0-5) 

7. `failed_transaction_cleanup()` creates a fee statement from the current gas meter state [7](#0-6) 

8. This fee statement includes `storage_fee_used()` from the gas meter [8](#0-7) 

9. However, the final VMOutput only contains prologue changes via `on_user_session_failure()` [9](#0-8) 

The root cause is that `charge_storage_fee()` permanently modifies the gas meter's internal state by incrementing `storage_fee_used` [10](#0-9) 

This breaks the fundamental invariant that users should only pay for resources they actually consume. Storage fees are designed to compensate validators for long-term storage costs, but here users pay these fees without receiving the storage.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "Limited funds loss or manipulation."

The impact includes:
- **Direct fund loss**: Users pay storage fees in APT for state changes that are never written to blockchain storage
- **Economic attack vector**: Malicious actors can craft transactions that maximize storage operations in user execution, then trigger epilogue failures (e.g., by ensuring their balance is insufficient for gas payment after execution)
- **Validator incentive misalignment**: Validators collect storage fees without providing the corresponding storage services
- **User experience degradation**: Users cannot predict actual costs since epilogue failures are not always deterministic

The amount lost per transaction depends on the size of the user's change set. For transactions with large storage operations (creating multiple resources, publishing large modules), the overcharge can be substantial given Aptos's storage pricing model.

## Likelihood Explanation

This vulnerability has **medium-to-high likelihood** of occurring:

**Natural occurrence scenarios:**
- Out-of-gas during epilogue execution after heavy user computation
- Epilogue aborts with `ECANT_PAY_GAS_DEPOSIT` when account balance becomes insufficient [5](#0-4) 
- Gas meter consistency check failures [11](#0-10) 

**Exploitation scenarios:**
- Attacker crafts transactions that consume maximum storage in user execution, ensuring their balance will be insufficient to pay the calculated fee
- Malicious contracts create state changes that predictably cause epilogue failures for other users
- Race conditions where parallel transactions modify account state causing epilogue failures

The vulnerability triggers automatically whenever any transaction succeeds in user execution but fails in epilogue - no special privileges required. Existing tests demonstrate epilogue failure scenarios but don't explicitly flag this as problematic behavior [12](#0-11) 

## Recommendation

Implement one of the following fixes:

**Option 1 (Preferred)**: Rollback storage fee charges when epilogue fails
- Save gas meter state before charging storage fees
- On epilogue failure, restore gas meter to pre-charge state
- Only charge for prologue operations

**Option 2**: Defer storage fee charging until after successful epilogue
- Move `charge_change_set_and_respawn_session()` to after epilogue execution
- Only charge storage fees if epilogue succeeds
- Requires refactoring epilogue session creation

**Option 3**: Commit user changes even on epilogue failure
- If storage fees are charged, commit the corresponding state changes
- Adjust epilogue error handling to still increment sequence number
- May have other semantic implications

The preferred solution is Option 1 as it maintains the current execution model while ensuring users only pay for committed state changes.

## Proof of Concept

While a complete PoC is not provided in the report, the vulnerability can be reproduced by:

1. Creating a transaction that performs substantial storage operations (e.g., creating 100 resources)
2. Ensuring the account has enough balance for user execution but will fall short of the total fee including storage charges
3. The transaction will execute successfully, charge storage fees, then fail in epilogue with `ECANT_PAY_GAS_DEPOSIT`
4. Observing that the fee statement includes storage charges but the final write set contains only prologue changes

The test infrastructure already demonstrates epilogue failure scenarios [12](#0-11)  which can be extended to validate the fee discrepancy.

## Notes

This vulnerability represents a violation of the economic model where storage fees should correspond to actual storage consumption. The code path is deterministic and well-documented in the codebase, with the critical charging happening before the comment "Gas fee cannot change after this line" but the epilogue executing after with potential failure paths. The existing test suite touches this scenario but doesn't explicitly validate the economic invariant, suggesting this behavior may have been overlooked rather than intentionally designed.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L556-556)
```rust
            u64::from(gas_meter.storage_fee_used()),
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L788-790)
```rust
            let fee_statement =
                AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);
            (prologue_session_change_set, fee_statement)
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L840-846)
```rust
            if let Err(err) = gas_meter.algebra().check_consistency() {
                println!(
                    "[aptos-vm][gas-meter][success-epilogue] {}",
                    err.message()
                        .unwrap_or("No message found -- this should not happen.")
                );
                return Err(err.finish(Location::Undefined).into());
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L855-867)
```rust
        epilogue_session.execute(|session| {
            transaction_validation::run_success_epilogue(
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1090-1096)
```rust
        let epilogue_session = self.charge_change_set_and_respawn_session(
            user_session_change_set,
            resolver,
            code_storage,
            gas_meter,
            txn_data,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1098-1098)
```rust
        // ============= Gas fee cannot change after this line =============
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1128-1134)
```rust
        let mut storage_refund = gas_meter.process_storage_fee_for_all(
            change_set,
            txn_data.transaction_size,
            txn_data.gas_unit_price,
            resolver.as_executor_view(),
            module_storage,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2105-2117)
```rust
        let (vm_status, mut output) = result.unwrap_or_else(|err| {
            self.on_user_transaction_execution_failure(
                prologue_change_set,
                err,
                resolver,
                code_storage,
                &serialized_signers,
                &txn_data,
                log_context,
                gas_meter,
                change_set_configs,
                &mut traversal_context,
            )
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L609-617)
```text
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/epilogue.rs (L58-72)
```rust
    pub fn on_user_session_failure(
        vm: &AptosVM,
        txn_meta: &TransactionMetadata,
        resolver: &'r impl AptosMoveResolver,
        previous_session_change_set: SystemSessionChangeSet,
    ) -> Self {
        Self::new(
            vm,
            txn_meta,
            resolver,
            previous_session_change_set.unpack(),
            ModuleWriteSet::empty(),
            0.into(),
        )
    }
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L278-280)
```rust
                self.balance = new_balance;
                self.storage_fee_in_internal_units += gas_consumed_internal;
                self.storage_fee_used += amount;
```

**File:** aptos-move/e2e-move-tests/src/tests/storage_refund.rs (L54-57)
```rust
    // Inject error in epilogue, observe refund is not applied (slot allocation is still charged.)
    // (need to disable parallel execution)
    inject_error_once(InjectedError::EndOfRunEpilogue);
    assert_result(&mut h, &mod_acc, "store_1_pop_2", vec![], 1, false);
```
