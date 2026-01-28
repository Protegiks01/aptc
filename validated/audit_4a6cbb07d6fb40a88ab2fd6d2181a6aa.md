# Audit Report

## Title
Storage Fee Bypass for Orderless Transaction Nonce Insertions on Failed Transactions

## Summary
When orderless transactions fail during execution, nonces inserted into the global `NonceHistory` table during prologue validation are persisted to blockchain state without charging storage fees, enabling attackers to bloat state at zero cost.

## Finding Description

This vulnerability exploits a discrepancy in how storage fees are charged for failed orderless transactions versus failed sequence-number-based transactions.

**Vulnerability Flow:**

When an orderless transaction executes, the prologue validates the transaction and inserts the nonce into the global `NonceHistory` resource: [1](#0-0) [2](#0-1) 

The prologue runs with an `UnmeteredGasMeter`, so no gas is charged during this phase: [3](#0-2) 

When `gas_feature_version >= 1`, prologue state changes are captured in a `SystemSessionChangeSet`: [4](#0-3) 

If the transaction fails during execution, `failed_transaction_cleanup` is invoked with the prologue change set: [5](#0-4) 

**The Critical Bug:** In `finish_aborted_transaction`, the code checks `should_create_account_resource` to determine whether to charge storage fees. For orderless transactions, this check returns `false` because the replay protector is `Nonce`, not `SequenceNumber(0)`: [6](#0-5) 

When account creation is NOT needed (the else branch), prologue changes are passed through WITHOUT calling `charge_change_set`: [7](#0-6) 

In contrast, when account creation IS needed, `charge_change_set` is called, which properly charges storage fees: [8](#0-7) 

The `charge_change_set` function calls `process_storage_fee_for_all` which iterates through write operations and charges fees: [9](#0-8) [10](#0-9) 

The prologue changes (containing nonce insertions) are then included in the final `VMOutput` via the epilogue session: [11](#0-10) [12](#0-11) 

**Attack Scenario:**
1. Attacker creates an account and submits orderless transactions designed to fail (e.g., calling an entry function that aborts)
2. Each transaction uses a unique nonce value
3. Prologue inserts nonce into `NonceHistory` table (state modification)
4. Transaction fails during user session execution
5. Since account exists, `should_create_account_resource` returns `false`
6. `finish_aborted_transaction` skips `charge_change_set` call
7. Nonce insertion is committed to state without storage fee
8. Attacker repeats with new nonces, bloating state for free

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty criteria)

This vulnerability violates the fundamental blockchain invariant that "All operations must respect gas, storage, and computational limits" by allowing state modifications without corresponding storage fees.

**Concrete Impacts:**

1. **State Bloat Attack**: Attackers can insert unlimited nonces into the global `NonceHistory` table at zero cost, consuming blockchain storage resources without payment.

2. **Limited Funds Loss**: The network loses storage fees that should be collected for nonce insertions, representing a form of "Limited funds loss or manipulation" per the Medium severity criteria.

3. **State Inconsistencies**: Unmetered state growth creates inconsistencies between expected and actual storage costs, falling under "State inconsistencies requiring manual intervention."

This does not constitute a Critical severity issue because it:
- Does not enable direct fund theft or unlimited minting
- Does not cause consensus violations or network partition
- Does not freeze funds or halt the network
- Impact is bounded to orderless transaction nonce insertions

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is exploitable under these conditions:

1. **Feature Flag**: Orderless transactions must be enabled (`is_orderless_txns_enabled()`)
2. **Account Existence**: Attacker's account must already exist
3. **Transaction Failure**: Transaction must fail during execution (not prologue)
4. **Gas Feature Version**: Must be >= 1 (standard in production)

These conditions are readily achievable:
- Any user can create an account
- Attacker controls transaction logic and can craft transactions that fail predictably
- Once orderless transactions are enabled (governance decision), exploitation requires no special privileges
- Attack cost is minimal (only prologue execution gas, no storage fees)
- Attack can be automated and repeated indefinitely with different nonces

## Recommendation

Modify `finish_aborted_transaction` to charge storage fees for prologue changes regardless of account creation status:

```rust
} else {
    let mut prologue_change_set_mut = prologue_session_change_set;
    if let Err(err) = self.charge_change_set(
        &mut prologue_change_set_mut,
        gas_meter,
        txn_data,
        resolver,
        module_storage,
    ) {
        info!(
            *log_context,
            "Failed during charge_change_set for prologue: {:?}", err,
        );
    };
    
    let fee_statement =
        AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);
    (prologue_change_set_mut, fee_statement)
};
```

Alternatively, ensure prologue changes are not persisted for failed orderless transactions, or charge a fixed fee for nonce insertions upfront.

## Proof of Concept

```move
// Deploy this module to create predictably failing transactions
module attacker::exploit {
    public entry fun always_fails() {
        abort 1
    }
}

// Attack flow:
// 1. Submit orderless transactions calling attacker::exploit::always_fails()
// 2. Use different nonces for each transaction (0, 1, 2, 3, ...)
// 3. Each transaction:
//    - Passes prologue validation (inserts nonce into NonceHistory)
//    - Fails during execution (always_fails aborts)
//    - Commits nonce insertion without charging storage fee
// 4. Repeat indefinitely to bloat NonceHistory table at zero cost
```

**Notes**

The test helper `test_failed_transaction_cleanup` incorrectly passes `SystemSessionChangeSet::empty()`, which masks this bug in testing: [13](#0-12) 

This creates a false sense of security as the test doesn't reflect production conditions where prologue changes are non-empty for orderless transactions.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/nonce_validation.move (L195-203)
```text
        // Insert the (address, nonce) pair in the bucket.
        let nonce_key_with_exp_time = NonceKeyWithExpTime {
            txn_expiration_time,
            sender_address,
            nonce,
        };
        bucket.nonces_ordered_by_exp_time.add(nonce_key_with_exp_time, true);
        bucket.nonce_to_exp_time_map.add(nonce_key, txn_expiration_time);
        true
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L262-262)
```text
        assert!(nonce_validation::check_and_insert_nonce(sender, nonce, txn_expiration_time), error::invalid_argument(PROLOGUE_ENONCE_ALREADY_USED));
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L123-123)
```rust
    let mut gas_meter = UnmeteredGasMeter;
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/prologue.rs (L59-80)
```rust
        if vm.gas_feature_version() >= 1 {
            // Create a new session so that the data cache is flushed.
            // This is to ensure we correctly charge for loading certain resources, even if they
            // have been previously cached in the prologue.
            //
            // TODO(Gas): Do this in a better way in the future, perhaps without forcing the data cache to be flushed.
            // By releasing resource group cache, we start with a fresh slate for resource group
            // cost accounting.

            let change_set = session.finish_with_squashed_change_set(
                change_set_configs,
                module_storage,
                false,
            )?;
            let prologue_session_change_set =
                SystemSessionChangeSet::new(change_set.clone(), change_set_configs)?;

            resolver.release_resource_group_cache();
            Ok((
                prologue_session_change_set,
                UserSession::new(vm, txn_meta, resolver, change_set),
            ))
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L561-632)
```rust
    pub(crate) fn failed_transaction_cleanup(
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
        if self.gas_feature_version() >= 12 {
            // Check if the gas meter's internal counters are consistent.
            //
            // Since we are already in the failure epilogue, there is not much we can do
            // other than logging the inconsistency.
            //
            // This is a tradeoff. We have to either
            //   1. Continue to calculate the gas cost based on the numbers we have.
            //   2. Discard the transaction.
            //
            // Option (2) does not work, since it would enable DoS attacks.
            // Option (1) is not ideal, but optimistically, it should allow the network
            // to continue functioning, less the transactions that run into this problem.
            if let Err(err) = gas_meter.algebra().check_consistency() {
                println!(
                    "[aptos-vm][gas-meter][failure-epilogue] {}",
                    err.message()
                        .unwrap_or("No message found -- this should not happen.")
                );
            }
        }

        let txn_status = TransactionStatus::from_vm_status(
            error_vm_status.clone(),
            self.features(),
            self.gas_feature_version() >= RELEASE_V1_38,
        );

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
    }
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L787-791)
```rust
        } else {
            let fee_statement =
                AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);
            (prologue_session_change_set, fee_statement)
        };
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3460-3460)
```rust
        && txn_data.replay_protector == ReplayProtector::SequenceNumber(0)
```

**File:** aptos-move/aptos-gas-meter/src/traits.rs (L179-193)
```rust
        let mut write_fee = Fee::new(0);
        let mut total_refund = Fee::new(0);
        let fix_prev_materialized_size = self.feature_version() > RELEASE_V1_30;
        for res in change_set.write_op_info_iter_mut(
            executor_view,
            module_storage,
            fix_prev_materialized_size,
        ) {
            let ChargeAndRefund { charge, refund } = pricing.charge_refund_write_op(
                params,
                res.map_err(|err| err.finish(Location::Undefined))?,
            );
            write_fee += charge;
            total_refund += refund;
        }
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

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/epilogue.rs (L115-126)
```rust
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
```

**File:** aptos-move/aptos-vm/src/testing.rs (L116-116)
```rust
            SystemSessionChangeSet::empty(),
```
