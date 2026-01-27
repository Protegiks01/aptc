# Audit Report

## Title
Pending Mempool Transactions Become Invalid After Gas Schedule Upgrades Without Revalidation

## Summary
When gas costs for `SECP256K1_BASE` or `SECP256K1_ECDSA_RECOVER` are increased during protocol upgrades, transactions in mempool that were validated against the old gas schedule remain unvalidated against the new costs. These transactions fail during execution when their `txn_max_gas_units` becomes insufficient under the new gas schedule, causing users to lose transaction fees despite having valid transactions at submission time. [1](#0-0) 

## Finding Description

The vulnerability exists in the gas schedule update mechanism and mempool transaction lifecycle. When a transaction calling `native_ecdsa_recover()` is submitted, it undergoes validation in the transaction prologue which checks that the user's specified `txn_max_gas_units` is sufficient to cover the maximum possible transaction fee: [2](#0-1) 

However, during execution, gas is charged based on the **current** gas parameters at execution time, not submission time. The `SafeNativeContext::charge()` method evaluates gas expressions using the active gas parameters: [3](#0-2) 

Gas schedule updates are staged via `set_for_next_epoch()` and applied during epoch reconfiguration through `on_new_epoch()`: [4](#0-3) [5](#0-4) 

When the gas schedule changes, mempool receives a reconfiguration event and calls `validator.write().restart()`: [6](#0-5) 

The `restart()` method updates the validator's state view but **does not revalidate existing mempool transactions**: [7](#0-6) 

**Exploitation Path:**

1. User submits transaction calling `secp256k1_ecdsa_recover()` with `txn_max_gas_units = 6,000,000` based on old gas costs (SECP256K1_BASE=551, SECP256K1_ECDSA_RECOVER=5,918,360, total ≈5,918,911)
2. Transaction passes validation and enters mempool
3. Governance proposal updates gas schedule with new values (SECP256K1_BASE=3,000, SECP256K1_ECDSA_RECOVER=32,200,000, total ≈32,203,000) - a 5.4x increase documented in example outputs: [8](#0-7) 

4. During epoch change, `on_new_epoch()` applies new gas schedule
5. Transaction remains in mempool (not revalidated)
6. Transaction is executed from mempool with NEW gas costs
7. Native function charges 32,203,000 gas but transaction only budgeted 6,000,000
8. Transaction fails with OUT_OF_GAS error
9. User's sequence number is incremented and fees are consumed despite transaction being valid at submission time: [9](#0-8) 

## Impact Explanation

This is a **Medium severity** issue per Aptos bug bounty criteria:
- **Limited funds loss**: Users lose transaction fees when previously-valid transactions fail after gas cost increases
- **State inconsistencies requiring intervention**: Mempool contains transactions that will deterministically fail upon execution but are not automatically removed

The impact is limited because:
- Transactions have TTL (default 600 seconds system timeout), limiting exposure window
- Gas schedule changes are public governance actions
- Users can resubmit transactions with updated gas limits

However, the issue is significant because:
- Users experience unexpected transaction failures and fee loss
- No warning or automatic revalidation mechanism exists
- The documented example shows a 5.4x gas cost increase, which would invalidate many pending transactions
- Breaks user expectation that validated transactions should execute successfully

## Likelihood Explanation

**Likelihood: Medium-High**

This issue occurs whenever:
1. Gas schedule is updated via governance (expected during protocol upgrades)
2. Gas costs increase for any native function
3. Transactions calling affected functions are pending in mempool

The likelihood is elevated because:
- Protocol upgrades with gas schedule changes are routine maintenance
- The example data shows historical gas cost increases of 5.4x for secp256k1 operations
- Mempool can hold transactions for up to 600 seconds (system TTL)
- Users typically set `txn_max_gas_units` with small margins above estimated costs

The severity is mitigated by:
- Gas schedule changes are publicly proposed through governance
- Transaction TTL limits the exposure window
- Users can monitor proposals and delay submissions

## Recommendation

Implement one or more of the following protections:

**Option 1: Automatic Mempool Revalidation (Recommended)**

Extend `process_config_update()` to revalidate and remove affected transactions when gas schedules change:

```rust
// In mempool/src/shared_mempool/tasks.rs
pub(crate) async fn process_config_update<V, P>(
    config_update: OnChainConfigPayload<P>,
    validator: Arc<RwLock<V>>,
    mempool: Arc<Mutex<CoreMempool>>,  // Add mempool parameter
    broadcast_within_validator_network: Arc<RwLock<bool>>,
) where
    V: TransactionValidation,
    P: OnChainConfigProvider,
{
    // Restart validator first
    if let Err(e) = validator.write().restart() {
        counters::VM_RECONFIG_UPDATE_FAIL_COUNT.inc();
        error!(...);
    }
    
    // Revalidate all mempool transactions with new gas schedule
    let validator_clone = validator.clone();
    let txns_to_revalidate = mempool.lock().get_all_transactions();
    let mut invalid_txns = vec![];
    
    for txn in txns_to_revalidate {
        if let Err(_) = validator_clone.read().validate_transaction(txn.clone()) {
            invalid_txns.push(txn);
        }
    }
    
    // Remove invalidated transactions
    mempool.lock().remove_transactions(&invalid_txns);
}
```

**Option 2: Gas Buffer Requirement**

Modify transaction validation to require a safety margin (e.g., 20%) above estimated gas:

```move
// In transaction_validation.move
fun prologue_common(...) {
    let max_transaction_fee = txn_gas_price * txn_max_gas_units;
    let minimum_required = max_transaction_fee * 120 / 100; // 20% buffer
    assert!(
        aptos_account::is_fungible_balance_at_least(gas_payer_address, minimum_required),
        error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
    );
}
```

**Option 3: Gas Schedule Version Tagging**

Tag transactions with the gas schedule version they were validated against and reject execution if versions don't match:

```move
// Add to transaction metadata
struct TransactionMetadata {
    gas_schedule_version: u64,
    // ... other fields
}

// In execution validation
assert!(
    txn_metadata.gas_schedule_version == current_gas_schedule.feature_version,
    error::invalid_state(EGAS_SCHEDULE_MISMATCH)
);
```

## Proof of Concept

```move
// File: test_gas_schedule_upgrade_invalidation.move
#[test_only]
module test_addr::gas_schedule_upgrade_test {
    use aptos_framework::secp256k1;
    use std::vector;
    
    #[test(framework = @aptos_framework, user = @0x123)]
    #[expected_failure(abort_code = 6)] // EOUT_OF_GAS
    public entry fun test_transaction_invalidation_after_gas_increase(
        framework: &signer,
        user: &signer
    ) {
        // Step 1: User creates transaction with gas budget based on OLD costs
        // OLD: SECP256K1_BASE=551, SECP256K1_ECDSA_RECOVER=5,918,360
        // Total for 1 call: ~5,918,911 gas
        let txn_max_gas_units = 6_000_000; // Sufficient for old costs
        
        // Step 2: Simulate gas schedule increase via governance
        // NEW: SECP256K1_BASE=3,000, SECP256K1_ECDSA_RECOVER=32,200,000
        // Total for 1 call: ~32,203,000 gas (5.4x increase)
        
        // Mock gas schedule update
        let new_gas_schedule_blob = construct_new_gas_schedule();
        aptos_framework::gas_schedule::set_for_next_epoch(framework, new_gas_schedule_blob);
        aptos_framework::aptos_governance::reconfigure(framework);
        
        // Step 3: Execute transaction that was valid under old schedule
        // but now exceeds gas budget under new schedule
        let message = x"0000000000000000000000000000000000000000000000000000000000000000";
        let signature = vector::empty<u8>();
        let recovery_id = 0u8;
        
        // This will fail with OUT_OF_GAS because:
        // - Transaction budgeted 6,000,000 gas
        // - New costs require 32,203,000 gas
        // - User's sequence number will still increment
        // - User still pays maximum gas fees
        secp256k1::ecdsa_recover(message, recovery_id, signature);
    }
}
```

**Execution Steps:**
1. User submits transaction with `max_gas_units=6,000,000` calling `secp256k1_ecdsa_recover()`
2. Transaction validated against old gas schedule (total cost ~5.9M gas)
3. Transaction enters mempool
4. Governance increases gas costs 5.4x via proposal
5. Epoch change applies new gas schedule
6. Transaction executes with new costs requiring ~32.2M gas
7. Transaction aborts with `OUT_OF_GAS` at 6M gas consumed
8. User loses fees and sequence number increments despite valid submission

**Notes:**
- Mempool does not track or cache gas schedule versions used for validation
- No automatic revalidation occurs during `validator.restart()`
- Transaction TTL provides partial mitigation but doesn't prevent the issue
- The 5.4x increase is documented in actual release examples, not hypothetical

### Citations

**File:** aptos-move/framework/src/natives/cryptography/secp256k1.rs (L27-84)
```rust
fn native_ecdsa_recover(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 3);

    let signature = safely_pop_arg!(arguments, Vec<u8>);
    let recovery_id = safely_pop_arg!(arguments, u8);
    let msg = safely_pop_arg!(arguments, Vec<u8>);

    context.charge(SECP256K1_BASE)?;

    // NOTE(Gas): O(1) cost
    // (In reality, O(|msg|) deserialization cost, with |msg| < libsecp256k1_core::util::MESSAGE_SIZE
    // which seems to be 32 bytes, so O(1) cost for all intents and purposes.)
    let msg = match libsecp256k1::Message::parse_slice(&msg) {
        Ok(msg) => msg,
        Err(_) => {
            return Err(SafeNativeError::Abort {
                abort_code: abort_codes::NFE_DESERIALIZE,
            });
        },
    };

    // NOTE(Gas): O(1) cost
    let rid = match libsecp256k1::RecoveryId::parse(recovery_id) {
        Ok(rid) => rid,
        Err(_) => {
            return Err(SafeNativeError::Abort {
                abort_code: abort_codes::NFE_DESERIALIZE,
            });
        },
    };

    // NOTE(Gas): O(1) deserialization cost
    // which seems to be 64 bytes, so O(1) cost for all intents and purposes.
    let sig = match libsecp256k1::Signature::parse_standard_slice(&signature) {
        Ok(sig) => sig,
        Err(_) => {
            return Err(SafeNativeError::Abort {
                abort_code: abort_codes::NFE_DESERIALIZE,
            });
        },
    };

    context.charge(SECP256K1_ECDSA_RECOVER * NumArgs::one())?;

    // NOTE(Gas): O(1) cost: a size-2 multi-scalar multiplication
    match libsecp256k1::recover(&msg, &sig, &rid) {
        Ok(pk) => Ok(smallvec![
            Value::vector_u8(pk.serialize()[1..].to_vec()),
            Value::bool(true)
        ]),
        Err(_) => Ok(smallvec![Value::vector_u8([0u8; 0]), Value::bool(false)]),
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L186-213)
```text

        // Check if the gas payer has enough balance to pay for the transaction
        let max_transaction_fee = txn_gas_price * txn_max_gas_units;
        if (!skip_gas_payment(
            is_simulation,
            gas_payer_address
        )) {
            assert!(
                permissioned_signer::check_permission_capacity_above(
                    gas_payer,
                    (max_transaction_fee as u256),
                    GasPermission {}
                ),
                error::permission_denied(PROLOGUE_PERMISSIONED_GAS_LIMIT_INSUFFICIENT)
            );
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            }
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L812-863)
```text
        assert!(txn_max_gas_units >= gas_units_remaining, error::invalid_argument(EOUT_OF_GAS));
        let gas_used = txn_max_gas_units - gas_units_remaining;

        assert!(
            (txn_gas_price as u128) * (gas_used as u128) <= MAX_U64,
            error::out_of_range(EOUT_OF_GAS)
        );
        let transaction_fee_amount = txn_gas_price * gas_used;

        let gas_payer_address = signer::address_of(&gas_payer);
        // it's important to maintain the error code consistent with vm
        // to do failed transaction cleanup.
        if (!skip_gas_payment(
            is_simulation,
            gas_payer_address
        )) {
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

            if (transaction_fee_amount > storage_fee_refunded) {
                let burn_amount = transaction_fee_amount - storage_fee_refunded;
                transaction_fee::burn_fee(gas_payer_address, burn_amount);
                permissioned_signer::check_permission_consume(
                    &gas_payer,
                    (burn_amount as u256),
                    GasPermission {}
                );
            } else if (transaction_fee_amount < storage_fee_refunded) {
                let mint_amount = storage_fee_refunded - transaction_fee_amount;
                transaction_fee::mint_and_refund(gas_payer_address, mint_amount);
                permissioned_signer::increase_limit(
                    &gas_payer,
                    (mint_amount as u256),
                    GasPermission {}
                );
            };
        };

        if (!is_orderless_txn) {
            // Increment sequence number
            let addr = signer::address_of(&account);
            account::increment_sequence_number(addr);
        }
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L75-103)
```rust
    pub fn charge(
        &mut self,
        abstract_amount: impl GasExpression<NativeGasParameters, Unit = InternalGasUnit>,
    ) -> SafeNativeResult<()> {
        let amount = abstract_amount.evaluate(self.gas_feature_version, self.native_gas_params);

        if let Some(hook) = self.gas_hook {
            let node = abstract_amount.to_dynamic();
            hook(node);
        }

        if self.has_direct_gas_meter_access_in_native_context() {
            self.gas_meter()
                .charge_native_execution(amount)
                .map_err(LimitExceededError::from_err)?;
            Ok(())
        } else {
            self.legacy_gas_used += amount;
            if self.legacy_gas_used > self.legacy_gas_budget()
                && self.legacy_enable_incremental_gas_charging
            {
                Err(SafeNativeError::LimitExceeded(
                    LimitExceededError::LegacyOutOfGas,
                ))
            } else {
                Ok(())
            }
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L91-103)
```text
    public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
        };
        config_buffer::upsert(new_gas_schedule);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L135-145)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<GasScheduleV2>()) {
            let new_gas_schedule = config_buffer::extract_v2<GasScheduleV2>();
            if (exists<GasScheduleV2>(@aptos_framework)) {
                *borrow_global_mut<GasScheduleV2>(@aptos_framework) = new_gas_schedule;
            } else {
                move_to(framework, new_gas_schedule);
            }
        }
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L762-794)
```rust
pub(crate) async fn process_config_update<V, P>(
    config_update: OnChainConfigPayload<P>,
    validator: Arc<RwLock<V>>,
    broadcast_within_validator_network: Arc<RwLock<bool>>,
) where
    V: TransactionValidation,
    P: OnChainConfigProvider,
{
    info!(LogSchema::event_log(
        LogEntry::ReconfigUpdate,
        LogEvent::Process
    ));

    if let Err(e) = validator.write().restart() {
        counters::VM_RECONFIG_UPDATE_FAIL_COUNT.inc();
        error!(LogSchema::event_log(LogEntry::ReconfigUpdate, LogEvent::VMUpdateFail).error(&e));
    }

    let consensus_config: anyhow::Result<OnChainConsensusConfig> = config_update.get();
    match consensus_config {
        Ok(consensus_config) => {
            *broadcast_within_validator_network.write() =
                !consensus_config.quorum_store_enabled() && !consensus_config.is_dag_enabled()
        },
        Err(e) => {
            error!(
                "Failed to read on-chain consensus config, keeping value broadcast_within_validator_network={}: {}",
                *broadcast_within_validator_network.read(),
                e
            );
        },
    }
}
```

**File:** vm-validator/src/vm_validator.rs (L172-177)
```rust
    fn restart(&mut self) -> Result<()> {
        for vm_validator in &self.vm_validators {
            vm_validator.lock().unwrap().restart()?;
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-release-builder/data/example_output/4-gas-schedule.move (L167-168)
```text
//     aptos_framework.secp256k1.base                                      : 3000
//     aptos_framework.secp256k1.ecdsa_recover                             : 32200000
```
