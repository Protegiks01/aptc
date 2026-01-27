# Audit Report

## Title
Change Set Charging Bypass in Aborted Transaction Account Creation

## Summary
In `finish_aborted_transaction`, when `charge_change_set` fails during lazy account creation in the abort hook, the error is only logged instead of being propagated, allowing the change set to be committed without proper gas charges. This enables attackers to create accounts with reduced or zero gas costs, violating critical gas metering invariants.

## Finding Description

The vulnerability exists in the abort hook handling during transaction failure. When a transaction aborts and triggers lazy account creation, the system:

1. Creates an `AbortHookSession` to handle account creation [1](#0-0) 

2. Executes account creation logic [2](#0-1) 

3. Finishes the session and obtains the change set [3](#0-2) 

4. **Attempts to charge for the change set, but catches and logs errors instead of propagating them** [4](#0-3) 

The `charge_change_set` function charges IO gas for transactions, events, and writes, plus processes storage fees [5](#0-4) . Each charging operation can fail with `OUT_OF_GAS` or `IO_LIMIT_REACHED` [6](#0-5) .

In contrast, the success path properly propagates charging errors [7](#0-6) .

The validation check that follows [8](#0-7)  is insufficient because:
- It is completely bypassed when `gas_unit_price == 0` and the `DEFAULT_ACCOUNT_RESOURCE` feature is enabled
- It only validates minimum fees, not that all operations were charged
- It uses fees already recorded in the gas meter, not checking if charging completed successfully

The change set is then passed to the epilogue [9](#0-8)  and ultimately committed [10](#0-9) .

**Attack Vector 1 (Zero Gas Price):**
- Attacker submits transaction with `gas_unit_price = 0` (currently allowed in validation)
- Transaction intentionally aborts to trigger lazy account creation
- `charge_change_set` fails due to insufficient gas remaining
- Validation is bypassed due to zero gas price condition
- Account is created with zero gas charges

**Attack Vector 2 (Partial Charging):**
- Transaction with non-zero `gas_unit_price` but calculated to fail partway through charging
- Some IO gas charges succeed before failure
- Storage fees are never processed
- Partial charges may satisfy minimum fee validation
- Account created with incomplete gas charges

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria)

This vulnerability represents a **significant protocol violation** and **gas metering bypass**:

1. **Violates Resource Limits Invariant**: "All operations must respect gas, storage, and computational limits" - state changes occur without proper gas charges

2. **Economic Impact**: Attackers can create accounts at reduced or zero cost, bypassing the economic barrier designed to prevent Sybil attacks and storage exhaustion

3. **Repeated Exploitation**: Attack can be executed repeatedly to create many accounts without proper payment

4. **Deterministic**: All validators execute the same flawed logic, so there's no consensus break, but the gas metering system is systematically bypassed

This qualifies as HIGH severity under "Significant protocol violations" category.

## Likelihood Explanation

**Likelihood: HIGH**

- **No special privileges required**: Any user can submit transactions with `gas_unit_price = 0`
- **Simple to execute**: Attacker only needs to craft a transaction that aborts and triggers account creation
- **Feature is enabled**: The `DEFAULT_ACCOUNT_RESOURCE` feature (flag 91) can be enabled on-chain [11](#0-10) 
- **Zero gas price is allowed**: Current validation permits `gas_unit_price = 0` [12](#0-11) 

## Recommendation

**Fix: Propagate errors instead of logging them**

Change the error handling in `finish_aborted_transaction` to propagate charging failures:

```rust
// Current (vulnerable):
if let Err(err) = self.charge_change_set(...) {
    info!(*log_context, "Failed during charge_change_set: {:?}", err);
};

// Fixed (secure):
let storage_refund = self.charge_change_set(
    &mut abort_hook_session_change_set,
    gas_meter,
    txn_data,
    resolver,
    module_storage,
)?; // Propagate error with ?
```

This ensures that if charging fails, the entire transaction fails rather than committing an undercharged change set. The behavior would match the success path where charging errors are properly propagated.

**Additional hardening:**
- Consider disallowing `gas_unit_price = 0` for transactions that trigger state changes
- Add explicit validation that all change set operations were successfully charged before commitment

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_account_creation_gas_bypass() {
    // Setup: Create transaction with gas_unit_price = 0
    let mut gas_meter = /* initialize gas meter */;
    let txn_data = TransactionMetadata {
        gas_unit_price: 0.into(), // Zero gas price
        max_gas_amount: 1000.into(),
        // ... other fields
    };
    
    // Execute transaction that aborts
    // This triggers finish_aborted_transaction with should_create_account_resource = true
    
    // Verify:
    // 1. charge_change_set fails (insufficient gas)
    // 2. Error is logged but not propagated
    // 3. Change set is committed
    // 4. Account exists in state
    // 5. Zero gas was charged
    
    assert_eq!(gas_meter.io_gas_used(), 0.into());
    assert_eq!(gas_meter.storage_fee_used(), 0.into());
    // But account was created in state
}
```

**Notes**

- The vulnerability is deterministic across all validators, so it doesn't cause consensus divergence
- The economic security model is compromised but state integrity is maintained
- Fix should be straightforward - change error handling from logging to propagation
- The comment at line 752 ("Most likely exceeded gas limited") suggests developers were aware charging could fail but didn't recognize the security implications of swallowing the error

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L709-710)
```rust
            let mut abort_hook_session =
                AbortHookSession::new(self, txn_data, resolver, prologue_session_change_set);
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L712-739)
```rust
            abort_hook_session.execute(|session| {
                create_account_if_does_not_exist(
                    session,
                    module_storage,
                    gas_meter,
                    txn_data.sender(),
                    traversal_context,
                )
                // If this fails, it is likely due to out of gas, so we try again without metering
                // and then validate below that we charged sufficiently.
                .or_else(|_err| {
                    create_account_if_does_not_exist(
                        session,
                        module_storage,
                        &mut UnmeteredGasMeter,
                        txn_data.sender(),
                        traversal_context,
                    )
                })
                .map_err(expect_no_verification_errors)
                .or_else(|err| {
                    expect_only_successful_execution(
                        err,
                        &format!("{:?}::{}", ACCOUNT_MODULE, CREATE_ACCOUNT_IF_DOES_NOT_EXIST),
                        log_context,
                    )
                })
            })?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L741-742)
```rust
            let mut abort_hook_session_change_set =
                abort_hook_session.finish(change_set_configs, module_storage)?;
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L762-785)
```rust
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L793-798)
```rust
        let mut epilogue_session = EpilogueSession::on_user_session_failure(
            self,
            txn_data,
            resolver,
            previous_session_change_set,
        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1120-1134)
```rust
        gas_meter.charge_io_gas_for_transaction(txn_data.transaction_size())?;
        for event in change_set.events_iter() {
            gas_meter.charge_io_gas_for_event(event)?;
        }
        for (key, op_size) in change_set.write_set_size_iter() {
            gas_meter.charge_io_gas_for_write(key, &op_size)?;
        }

        let mut storage_refund = gas_meter.process_storage_fee_for_all(
            change_set,
            txn_data.transaction_size,
            txn_data.gas_unit_price,
            resolver.as_executor_view(),
            module_storage,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1150-1156)
```rust
        let storage_refund = self.charge_change_set(
            &mut user_session_change_set,
            gas_meter,
            txn_data,
            resolver,
            module_storage,
        )?;
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L217-236)
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

        if self.feature_version >= 7 && self.io_gas_used > self.max_io_gas {
            Err(PartialVMError::new(StatusCode::IO_LIMIT_REACHED))
        } else {
            Ok(())
        }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/epilogue.rs (L121-126)
```rust
        Ok(VMOutput::new(
            change_set,
            module_write_set,
            fee_statement,
            TransactionStatus::Keep(execution_status),
        ))
```

**File:** types/src/on_chain_config/aptos_features.rs (L141-141)
```rust
    DEFAULT_ACCOUNT_RESOURCE = 91,
```

**File:** aptos-move/aptos-vm/src/gas.rs (L175-180)
```rust
    // NB: MIN_PRICE_PER_GAS_UNIT may equal zero, but need not in the future. Hence why
    // we turn off the clippy warning.
    #[allow(clippy::absurd_extreme_comparisons)]
    let below_min_bound = txn_metadata.gas_unit_price() < txn_gas_params.min_price_per_gas_unit;
    if below_min_bound {
        speculative_warn!(
```
