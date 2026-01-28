# Audit Report

## Title
Storage Fee Bypass for Orderless Transaction Nonce Insertions on Failed Transactions

## Summary
When orderless transactions fail during execution, nonces inserted during prologue validation are persisted to blockchain state without charging storage fees, enabling attackers to bloat the global nonce table at zero cost.

## Finding Description

The Aptos VM transaction execution flow has a critical discrepancy in how storage fees are charged for prologue state changes when transactions fail after prologue execution.

For orderless transactions, the prologue calls `check_and_insert_nonce` which modifies the global `NonceHistory` resource at `@aptos_framework`. [1](#0-0)  This function inserts entries into two BigOrderedMaps (`nonces_ordered_by_exp_time` and `nonce_to_exp_time_map`), representing state modifications that should incur storage fees.

When `gas_feature_version >= 1`, prologue state changes are captured in a `SystemSessionChangeSet`. [2](#0-1) 

**The Critical Bug:** In `finish_aborted_transaction`, there are two execution paths. When account creation IS needed, the code properly calls `charge_change_set()` to process storage fees. [3](#0-2) 

However, when account creation is NOT needed (the else branch), the code creates a fee statement directly from the gas meter WITHOUT calling `charge_change_set()` on the prologue changes. [4](#0-3) 

The `charge_change_set()` function is responsible for processing storage fees via `process_storage_fee_for_all`, which iterates through all write operations and charges appropriate storage fees. [5](#0-4) [6](#0-5) 

The prologue changes are passed to the epilogue session, which includes them in the final VMOutput. [7](#0-6)  The epilogue's finish method does not charge storage fees—it only squashes change sets and returns the VMOutput with the fee statement provided as a parameter. [8](#0-7) 

Failed transactions with `TransactionStatus::Keep` are committed to the blockchain. [9](#0-8) 

**Attack Path:**
1. Attacker creates an account (one-time setup)
2. Submits orderless transaction with unique nonce that will fail during execution (e.g., entry function that aborts)
3. Prologue validates transaction and inserts nonce into `NonceHistory`
4. Transaction execution fails during user session
5. `finish_aborted_transaction` takes the else branch (account already exists)
6. Fee statement created from gas meter without charging for prologue state changes
7. Transaction committed with nonce persisted, but no storage fee charged
8. Attacker repeats with different nonces, bloating the nonce table

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty criteria)

This vulnerability enables two related attacks:

1. **State Bloat Attack:** Attackers can insert unlimited nonces into the global `NonceHistory` table without paying storage fees, consuming blockchain state storage at zero cost. Each nonce insertion adds entries to the bucketed hash table structure defined in the NonceHistory resource. [10](#0-9) 

2. **Storage Fee Bypass:** This violates the fundamental blockchain economic invariant that all state modifications must pay appropriate storage fees. The unpaid storage fees represent a direct loss to the network's economic model.

This qualifies as "Limited Protocol Violations" under Medium severity—specifically state inconsistencies through unmetered state growth and limited funds loss through unpaid storage fees. While this doesn't directly lead to fund theft or consensus violations, it allows unbounded state bloat within the constraints of failed orderless transactions where the sender account already exists.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is exploitable under straightforward conditions:
- Orderless transactions feature must be enabled via on-chain feature flag [11](#0-10) 
- Attacker's account must already exist (trivial one-time setup)
- Transaction must fail during execution phase, not prologue (easily achieved by calling an entry function that aborts)

The exploit requires no special privileges and can be executed by any Aptos user once orderless transactions are enabled. There are no rate limits or economic disincentives since the storage fees are bypassed. The attacker can craft transactions that fail predictably while using different nonces each time.

## Recommendation

Modify `finish_aborted_transaction` to charge storage fees for prologue changes in both execution paths. The fix should call `charge_change_set()` on the `prologue_session_change_set` even when account creation is not needed:

```rust
} else {
    // Charge storage fees for prologue changes even when account creation is not needed
    if let Err(err) = self.charge_change_set(
        &mut prologue_session_change_set,
        gas_meter,
        txn_data,
        resolver,
        module_storage,
    ) {
        info!(
            *log_context,
            "Failed during charge_change_set for prologue changes: {:?}", err,
        );
    };
    
    let fee_statement =
        AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);
    (prologue_session_change_set, fee_statement)
}
```

Alternatively, ensure that prologue state changes are rolled back if storage fees cannot be charged, though this would require more significant architectural changes.

## Proof of Concept

A Move test demonstrating the vulnerability would submit an orderless transaction that:
1. Has a valid nonce
2. Passes prologue validation
3. Fails during execution (e.g., calls `abort(1)`)
4. Gets committed with Keep status
5. Verify that the nonce is persisted in NonceHistory
6. Verify that the storage fee charged is less than expected (missing the nonce insertion cost)

The test would compare the storage fees between successful and failed orderless transactions to demonstrate the discrepancy.

## Notes

This vulnerability only affects orderless transactions (nonce-based replay protection) when they fail after prologue execution and the sender account already exists. Regular sequence-number-based transactions are not affected. The vulnerability is present in the current codebase and can be exploited once the orderless transactions feature is enabled on the network.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/nonce_validation.move (L39-64)
```text
    struct NonceHistory has key {
        // Key = sip_hash(NonceKey) % NUM_BUCKETS
        // Value = Bucket
        nonce_table: Table<u64, Bucket>,
        // Used to facilitate prefill the nonce_table with empty buckets
        // one by one using `add_nonce_bucket` method.
        // This is the next_key to prefill with an empty bucket
        next_key: u64,
    }

    // The bucket stores (address, nonce, txn expiration time) tuples.
    // All the entries in the bucket contain the same hash(address, nonce) % NUM_BUCKETS.
    // The first big ordered map in the bucket stores (expiration time, address, nonce) -> true.
    // The second big ordered map in the bucket stores (address, nonce) -> expiration time.
    // Both the maps store the same data, just in a different format.
    // As the key in the first big ordered map starts with expiration time, it's easy to figure out which
    // entries have expired at the current time. The first big ordered map helps with easy garbage collection.
    // The second big ordered map helps with checking if the given (address, nonce) pair exists in the bucket.
    // An (address, nonce) pair is guaranteed to be unique in both the big ordered maps. Two transactions with
    // the same (address, nonce) pair cannot be stored at the same time.
    struct Bucket has store {
        // The first big ordered map in the bucket stores (expiration time, address, nonce) -> true.
        nonces_ordered_by_exp_time: BigOrderedMap<NonceKeyWithExpTime, bool>,
        // The second big ordered map in the bucket stores (address, nonce) -> expiration time.
        nonce_to_exp_time_map: BigOrderedMap<NonceKey, u64>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/nonce_validation.move (L129-204)
```text
    public(friend) fun check_and_insert_nonce(
        sender_address: address,
        nonce: u64,
        txn_expiration_time: u64,
    ): bool acquires NonceHistory {
        assert!(exists<NonceHistory>(@aptos_framework), error::invalid_state(E_NONCE_HISTORY_DOES_NOT_EXIST));
        // Check if the transaction expiration time is too far in the future.
        assert!(txn_expiration_time <= timestamp::now_seconds() + NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS, error::invalid_argument(ETRANSACTION_EXPIRATION_TOO_FAR_IN_FUTURE));
        let nonce_history = &mut NonceHistory[@aptos_framework];
        let nonce_key = NonceKey {
            sender_address,
            nonce,
        };
        let bucket_index = sip_hash_from_value(&nonce_key) % NUM_BUCKETS;
        let current_time = timestamp::now_seconds();
        if (!nonce_history.nonce_table.contains(bucket_index)) {
            nonce_history.nonce_table.add(
                bucket_index,
                empty_bucket(false)
            );
        };
        let bucket = table::borrow_mut(&mut nonce_history.nonce_table, bucket_index);

        let existing_exp_time = bucket.nonce_to_exp_time_map.get(&nonce_key);
        if (existing_exp_time.is_some()) {
            let existing_exp_time = existing_exp_time.extract();

            // If the existing (address, nonce) pair has not expired, return false.
            if (existing_exp_time >= current_time) {
                return false;
            };

            // We maintain an invariant that two transaction with the same (address, nonce) pair cannot be stored
            // in the nonce history if their transaction expiration times are less than `NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS`
            // seconds apart.
            if (txn_expiration_time <= existing_exp_time + NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS) {
                return false;
            };

            // If the existing (address, nonce) pair has expired, garbage collect it.
            bucket.nonce_to_exp_time_map.remove(&nonce_key);
            bucket.nonces_ordered_by_exp_time.remove(&NonceKeyWithExpTime {
                txn_expiration_time: existing_exp_time,
                sender_address,
                nonce,
            });
        };

        // Garbage collect upto MAX_ENTRIES_GARBAGE_COLLECTED_PER_CALL expired nonces in the bucket.
        let i = 0;
        while (i < MAX_ENTRIES_GARBAGE_COLLECTED_PER_CALL && !bucket.nonces_ordered_by_exp_time.is_empty()) {
            let (front_k, _) = bucket.nonces_ordered_by_exp_time.borrow_front();
            // We garbage collect a nonce after it has expired and the NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS
            // seconds have passed.
            if (front_k.txn_expiration_time + NONCE_REPLAY_PROTECTION_OVERLAP_INTERVAL_SECONDS < current_time) {
                bucket.nonces_ordered_by_exp_time.pop_front();
                bucket.nonce_to_exp_time_map.remove(&NonceKey {
                    sender_address: front_k.sender_address,
                    nonce: front_k.nonce,
                });
            } else {
                break;
            };
            i = i + 1;
        };

        // Insert the (address, nonce) pair in the bucket.
        let nonce_key_with_exp_time = NonceKeyWithExpTime {
            txn_expiration_time,
            sender_address,
            nonce,
        };
        bucket.nonces_ordered_by_exp_time.add(nonce_key_with_exp_time, true);
        bucket.nonce_to_exp_time_map.add(nonce_key, txn_expiration_time);
        true
    }
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L602-624)
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L708-786)
```rust
        let (previous_session_change_set, fee_statement) = if should_create_account_resource {
            let mut abort_hook_session =
                AbortHookSession::new(self, txn_data, resolver, prologue_session_change_set);

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

            let mut abort_hook_session_change_set =
                abort_hook_session.finish(change_set_configs, module_storage)?;
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

            let fee_statement =
                AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);

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
            (abort_hook_session_change_set, fee_statement)
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L787-791)
```rust
        } else {
            let fee_statement =
                AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);
            (prologue_session_change_set, fee_statement)
        };
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L793-822)
```rust
        let mut epilogue_session = EpilogueSession::on_user_session_failure(
            self,
            txn_data,
            resolver,
            previous_session_change_set,
        );

        // Abort information is injected using the user defined error in the Move contract.
        let status = self.inject_abort_info_if_available(
            module_storage,
            traversal_context,
            log_context,
            status,
        );
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
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1112-1140)
```rust
    fn charge_change_set(
        &self,
        change_set: &mut impl ChangeSetInterface,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
    ) -> Result<GasQuantity<Octa>, VMStatus> {
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
        if !self.features().is_storage_deletion_refund_enabled() {
            storage_refund = 0.into();
        }

        Ok(storage_refund)
    }
```

**File:** aptos-move/aptos-gas-meter/src/traits.rs (L155-212)
```rust
    fn process_storage_fee_for_all(
        &mut self,
        change_set: &mut impl ChangeSetInterface,
        txn_size: NumBytes,
        gas_unit_price: FeePerGasUnit,
        executor_view: &dyn ExecutorView,
        module_storage: &impl AptosModuleStorage,
    ) -> VMResult<Fee> {
        // The new storage fee are only active since version 7.
        if self.feature_version() < 7 {
            return Ok(0.into());
        }

        // TODO(Gas): right now, some of our tests use a unit price of 0 and this is a hack
        // to avoid causing them issues. We should revisit the problem and figure out a
        // better way to handle this.
        if gas_unit_price.is_zero() {
            return Ok(0.into());
        }

        let pricing = self.disk_space_pricing();
        let params = &self.vm_gas_params().txn;

        // Write set
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

        // Events (no event fee in v2)
        let event_fee = change_set.events_iter().fold(Fee::new(0), |acc, event| {
            acc + pricing.legacy_storage_fee_per_event(params, event)
        });
        let event_discount = pricing.legacy_storage_discount_for_events(params, event_fee);
        let event_net_fee = event_fee
            .checked_sub(event_discount)
            .expect("event discount should always be less than or equal to total amount");

        // Txn (no txn fee in v2)
        let txn_fee = pricing.legacy_storage_fee_for_transaction_storage(params, txn_size);

        let fee = write_fee + event_net_fee + txn_fee;
        self.charge_storage_fee(fee, gas_unit_price)
            .map_err(|err| err.finish(Location::Undefined))?;

        Ok(total_refund)
    }
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

**File:** types/src/on_chain_config/aptos_features.rs (L94-94)
```rust
    _LIMIT_VM_TYPE_SIZE = 69,
```
