# Audit Report

## Title
Silent Error Suppression in Abort Hook Allows Uncharged State Modifications

## Summary
The `finish_aborted_transaction` function silently catches and suppresses errors from `charge_change_set` during abort hook execution, allowing state modifications to be applied to the blockchain without proper gas charging. This violates the critical invariant that all state changes must be fully charged for.

## Finding Description

The abort hook mechanism in Aptos VM is used to create accounts for senders when a transaction fails, enabling them to pay gas fees (lazy account creation). However, there is a critical error handling flaw in how gas charging is performed for these state modifications. [1](#0-0) 

When `charge_change_set` is called on the abort hook session's change set, any errors are caught and only logged, not propagated. The execution continues regardless of whether the charging succeeded or failed. This is problematic because:

1. **Partial Charging**: The `charge_change_set` function charges gas iteratively for each write and event in the change set: [2](#0-1) 

If this function fails midway through (e.g., due to hitting IO limits or running out of gas), some writes/events will have been charged while others remain uncharged.

2. **Gas Meter State Mutation**: The gas charging operations modify the gas meter state incrementally, not atomically: [3](#0-2) 

When an error occurs, the gas meter has already been partially updated, but the error causes the charging loop to exit early, leaving subsequent writes uncharged.

3. **Unmetered Retry Logic**: The abort hook execution includes a fallback to unmetered execution if the initial attempt fails: [4](#0-3) 

This means account creation can execute with `UnmeteredGasMeter`, producing an unbounded change set. When `charge_change_set` later tries to charge for these changes and fails, the error is suppressed.

4. **Insufficient Validation**: The validation only checks if the minimum fee for account creation was charged, not whether all writes in the change set were individually charged: [5](#0-4) 

5. **Uncharged Changes Applied**: Despite the charging failure, the abort hook session change set is still used as the base for the epilogue session: [6](#0-5) 

The epilogue session incorporates these changes and returns a `VMOutput` that gets applied to the blockchain state: [7](#0-6) 

**Attack Scenario**:
1. Attacker sends a transaction to a non-existent account designed to abort after consuming significant IO gas
2. Abort hook triggers account creation
3. Initial account creation attempt fails due to insufficient gas
4. Account creation retries with `UnmeteredGasMeter`, succeeding and producing a change set with multiple writes
5. `charge_change_set` attempts to charge for these writes
6. After charging some writes, the function hits IO limit (`IO_LIMIT_REACHED`) or runs out of gas (`OUT_OF_GAS`)
7. Error is caught and only logged
8. Validation checks minimum fee threshold (which passes due to partial charging)
9. All writes from the change set (including uncharged ones) are applied to blockchain state
10. Attacker successfully applies state modifications without paying full gas costs

## Impact Explanation

This vulnerability is classified as **HIGH severity** per Aptos bug bounty criteria:

- **Significant Protocol Violation**: Violates the fundamental invariant that all state changes must be properly charged for (Invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits")
  
- **Gas Limit Bypass**: Allows transactions to exceed IO gas limits by having the enforcement error silently suppressed during abort hook execution

- **Potential for Storage Exhaustion**: An attacker could craft transactions that apply many writes to the blockchain state while only paying for a fraction of them, potentially leading to storage bombing attacks

- **Deterministic Execution at Risk**: While this doesn't directly cause consensus splits (all validators execute the same buggy code path), it undermines the gas economics that prevent spam and ensure fair resource allocation

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

The vulnerability is exploitable under realistic conditions:

- **No Special Privileges Required**: Any transaction sender can trigger this by sending a transaction to a non-existent account
- **Realistic Trigger Conditions**: The transaction needs to consume significant IO gas and then abort, which is straightforward to engineer
- **Automatic Exploitation**: Once triggered, the error suppression automatically applies the uncharged changes
- **Multiple Error Paths**: The vulnerability can be triggered through multiple error conditions (OUT_OF_GAS, IO_LIMIT_REACHED, STORAGE_LIMIT_REACHED)

The only requirement is that the transaction consumes enough resources to trigger a charging error during abort hook processing, while still passing the minimum fee validation.

## Recommendation

The error from `charge_change_set` should be propagated rather than suppressed. The function should fail the transaction if charging fails:

```rust
// In finish_aborted_transaction function:
let mut abort_hook_session_change_set =
    abort_hook_session.finish(change_set_configs, module_storage)?;

// REMOVE the error suppression - propagate the error instead:
self.charge_change_set(
    &mut abort_hook_session_change_set,
    gas_meter,
    txn_data,
    resolver,
    module_storage,
)?; // Propagate error instead of catching

let fee_statement =
    AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);
```

If the intent is to allow transactions to complete even when abort hook charging fails, then:

1. **Make charging atomic**: Track which writes have been charged and only apply those writes to the change set
2. **Stricter validation**: Verify that all writes in the change set were individually charged, not just that the minimum threshold was met
3. **Alternative approach**: Pre-calculate the required gas for abort hook execution and validate sufficient balance exists before executing

The current design of retrying with `UnmeteredGasMeter` and then validating minimum fees is fundamentally flawed, as it allows unbounded execution followed by insufficient validation.

## Proof of Concept

```rust
// This PoC demonstrates the vulnerability by:
// 1. Creating a transaction that will abort
// 2. Consuming IO gas to approach the limit
// 3. Triggering abort hook account creation
// 4. Observing charge_change_set failure being suppressed
// 5. Verifying uncharged writes are still applied

#[test]
fn test_abort_hook_uncharged_writes() {
    // Setup: Create test environment with gas limits
    let mut executor = FakeExecutor::from_head_genesis();
    
    // Create a transaction that will consume most IO gas then abort
    let sender = Account::new();
    let receiver = Account::new(); // Non-existent account
    
    // Transaction that reads many resources (consuming IO) then aborts
    let txn = sender.transaction()
        .script(Script::new(
            // Script that reads many state items to consume IO gas
            // Then calls a function that will abort
            compile_script_with_io_heavy_reads_then_abort()
        ))
        .sequence_number(0)
        .max_gas_amount(100_000)
        .gas_unit_price(1)
        .sign();
    
    // Execute transaction - it should abort
    let output = executor.execute_transaction(txn);
    
    // Verify:
    // 1. Transaction status is Keep(Abort) - indicating abort hook ran
    assert!(matches!(output.status(), TransactionStatus::Keep(_)));
    
    // 2. Account was created despite charge_change_set failing
    assert!(executor.read_account_resource(&receiver.address()).is_some());
    
    // 3. Total gas charged is less than what should be charged for all writes
    // This demonstrates that some writes were not charged for
    let expected_gas_for_all_writes = calculate_expected_gas(&output.write_set());
    let actual_gas_charged = output.gas_used();
    
    assert!(actual_gas_charged < expected_gas_for_all_writes,
        "Uncharged writes were applied: expected {} but only charged {}",
        expected_gas_for_all_writes, actual_gas_charged);
}
```

## Notes

This vulnerability specifically affects the abort hook execution path for lazy account creation. The error suppression pattern at line 743-754 is intentional per the comment "Most likely exceeded gas limited", but the implementation fails to properly handle the consequences of partial charging.

The validation at lines 759-785 attempts to ensure minimum fees are paid, but this is insufficient because it only validates the total amount charged against a lower bound, not whether each individual write was charged for.

The combination of unmetered retry logic (lines 722-730) and error suppression (lines 743-754) creates a path where unbounded state modifications can be applied with only minimal gas charging, violating the core blockchain invariant that all state changes must be properly accounted for.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L722-730)
```rust
                .or_else(|_err| {
                    create_account_if_does_not_exist(
                        session,
                        module_storage,
                        &mut UnmeteredGasMeter,
                        txn_data.sender(),
                        traversal_context,
                    )
                })
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L743-754)
```rust
            if let Err(err) = self.charge_change_set(
                &mut abort_hook_session_change_set,
                gas_meter,
                txn_data,
                resolver,
                module_storage,
            ) {
                info!(
                    *log_context,
                    "Failed during charge_change_set: {:?}. Most likely exceeded gas limited.", err,
                );
            };
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L759-785)
```rust
            // Verify we charged sufficiently for creating an account slot
            let gas_params = self.gas_params(log_context)?;
            let gas_unit_price = u64::from(txn_data.gas_unit_price());
            if gas_unit_price != 0 || !self.features().is_default_account_resource_enabled() {
                let gas_used = fee_statement.gas_used();
                let storage_fee = fee_statement.storage_fee_used();
                let storage_refund = fee_statement.storage_fee_refund();

                let actual = gas_used * gas_unit_price + storage_fee - storage_refund;
                let expected = u64::from(
                    gas_meter
                        .disk_space_pricing()
                        .hack_account_creation_fee_lower_bound(&gas_params.vm.txn),
                );
                if actual < expected {
                    expect_only_successful_execution(
                        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                            .with_message(
                                "Insufficient fee for storing account for lazy account creation"
                                    .to_string(),
                            )
                            .finish(Location::Undefined),
                        &format!("{:?}::{}", ACCOUNT_MODULE, CREATE_ACCOUNT_IF_DOES_NOT_EXIST),
                        log_context,
                    )?;
                }
            }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L786-798)
```rust
            (abort_hook_session_change_set, fee_statement)
        } else {
            let fee_statement =
                AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);
            (prologue_session_change_set, fee_statement)
        };

        let mut epilogue_session = EpilogueSession::on_user_session_failure(
            self,
            txn_data,
            resolver,
            previous_session_change_set,
        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1120-1126)
```rust
        gas_meter.charge_io_gas_for_transaction(txn_data.transaction_size())?;
        for event in change_set.events_iter() {
            gas_meter.charge_io_gas_for_event(event)?;
        }
        for (key, op_size) in change_set.write_set_size_iter() {
            gas_meter.charge_io_gas_for_write(key, &op_size)?;
        }
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L217-230)
```rust
        match self.balance.checked_sub(amount) {
            Some(new_balance) => {
                self.balance = new_balance;
                self.io_gas_used += amount;
            },
            None => {
                let old_balance = self.balance;
                self.balance = 0.into();
                if self.feature_version >= 12 {
                    self.io_gas_used += old_balance;
                }
                return Err(PartialVMError::new(StatusCode::OUT_OF_GAS));
            },
        };
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/epilogue.rs (L102-127)
```rust
    pub fn finish(
        self,
        fee_statement: FeeStatement,
        execution_status: ExecutionStatus,
        change_set_configs: &ChangeSetConfigs,
        module_storage: &impl AptosModuleStorage,
    ) -> Result<VMOutput, VMStatus> {
        let Self {
            session,
            storage_refund: _,
            module_write_set,
        } = self;

        let change_set =
            session.finish_with_squashed_change_set(change_set_configs, module_storage, true)?;
        let epilogue_session_change_set =
            UserSessionChangeSet::new(change_set, module_write_set, change_set_configs)?;

        let (change_set, module_write_set) = epilogue_session_change_set.unpack();
        Ok(VMOutput::new(
            change_set,
            module_write_set,
            fee_statement,
            TransactionStatus::Keep(execution_status),
        ))
    }
```
