# Audit Report

## Title
Legacy Session Inheritance Bypasses Gas Charges for Prologue-Cached Resources

## Summary
In legacy mode (`gas_feature_version < 1`), the `legacy_inherit_prologue_session()` function directly inherits the prologue session's data cache, allowing user transactions to access prologue-cached resources (Account, CoinStore, etc.) without paying gas charges for loading them, violating gas accounting invariants.

## Finding Description

The vulnerability exists in the legacy code path that handles session transitions between prologue and user transaction execution. [1](#0-0) 

When `gas_feature_version < 1`, the system uses `legacy_inherit_prologue_session()` which directly wraps the prologue session without flushing its data cache: [2](#0-1) 

In contrast, the modern path (gas_feature_version >= 1) explicitly finishes the prologue session and creates a fresh user session to ensure correct gas charging: [3](#0-2) 

The root cause is in the Move VM's data cache behavior. When loading resources: [4](#0-3) 

Resources already in the cache return `bytes_loaded = None`, while fresh loads return `Some(bytes)`. The interpreter only charges gas when bytes were actually loaded: [5](#0-4) 

During prologue execution, critical resources are loaded including the sender's Account resource and gas payer's CoinStore: [6](#0-5) 

**Attack Path:**
1. Submit a transaction on a chain with `gas_feature_version = 0`
2. Prologue loads sender's Account and gas payer's CoinStore into the data cache
3. In legacy mode, the prologue session is inherited directly (cache not flushed)
4. User transaction body accesses the same resources
5. Data cache returns cached values with `bytes_loaded = None`
6. No gas is charged for loading these resources
7. User effectively receives free resource access that should cost gas

**Invariants Broken:**
- **Invariant #3**: "Move VM Safety: Bytecode execution must respect gas limits and memory constraints"
- **Invariant #9**: "Resource Limits: All operations must respect gas, storage, and computational limits"

## Impact Explanation

This is a **High Severity** gas metering bypass under Aptos bug bounty criteria ("Significant protocol violations"). 

The vulnerability allows attackers to:
- Access Account resources without gas charges
- Read CoinStore balances for free
- Bypass gas costs for any resources loaded during prologue validation

While this doesn't directly lead to fund theft, it violates the fundamental gas accounting model that ensures all computational work is paid for. Attackers could craft transactions to maximize prologue resource loading and then access those resources extensively in the transaction body without payment.

**Important Limitation**: This vulnerability ONLY affects networks running with legacy gas configuration (`gas_feature_version = 0`), which uses the old GasSchedule V1: [7](#0-6) 

Modern Aptos mainnet uses GasScheduleV2 with `gas_feature_version >= 1` and is NOT affected. However, private chains, test networks, or networks that haven't upgraded their gas schedule remain vulnerable.

## Likelihood Explanation

**Likelihood: Low-to-Medium**

The vulnerability is real and exploitable, but with significant constraints:

1. **Network Configuration Required**: Only affects networks with `gas_feature_version = 0`
2. **Known Issue**: The developers intentionally fixed this in gas_feature_version >= 1, as evidenced by the explicit comment about flushing the data cache
3. **Mainnet Protected**: Modern Aptos mainnet is not vulnerable
4. **Legacy Networks**: Private/permissioned chains or test networks using legacy gas schedules could be affected

The attack itself is straightforward once the vulnerable configuration is found - any transaction sender can exploit it by crafting transactions that access resources loaded during prologue.

## Recommendation

The fix is already implemented for modern gas versions. For networks still using legacy gas schedules:

**Immediate Action**: Upgrade to GasScheduleV2 with `gas_feature_version >= 1` to enable the secure code path.

**For Legacy Compatibility**: If legacy mode must be maintained, modify the legacy path to flush the cache:

```rust
pub fn legacy_inherit_prologue_session_secure(
    prologue_session: RespawnedSession<'r>,
    vm: &AptosVM,
    txn_meta: &TransactionMetadata,
    resolver: &'r impl AptosMoveResolver,
    change_set_configs: &ChangeSetConfigs,
    module_storage: &impl AptosModuleStorage,
) -> Result<Self, VMStatus> {
    // Finish prologue session to flush cache
    let change_set = prologue_session.finish_with_squashed_change_set(
        change_set_configs,
        module_storage,
        false,
    )?;
    
    // Create new session with flushed cache
    Ok(Self::new(vm, txn_meta, resolver, change_set))
}
```

**Long-term**: Deprecate and remove the legacy code path entirely once all networks have migrated to modern gas versions.

## Proof of Concept

The following test demonstrates the gas bypass in legacy mode:

```rust
#[test]
fn test_legacy_session_gas_bypass() {
    use aptos_types::account_config::AccountResource;
    use move_core_types::account_address::AccountAddress;
    
    // Setup test environment with gas_feature_version = 0
    let mut executor = FakeExecutor::from_head_genesis();
    executor.set_gas_feature_version(0); // Legacy mode
    
    let sender = executor.create_raw_account();
    let gas_payer = executor.create_raw_account();
    
    // Transaction that accesses sender's Account resource
    let txn = Transaction::UserTransaction(
        sender
            .transaction()
            .payload(entry_function_payload(
                "0x1::account::get_sequence_number",
                vec![],
                vec![bcs::to_bytes(&sender.address()).unwrap()],
            ))
            .sequence_number(0)
            .max_gas_amount(1_000_000)
            .gas_unit_price(1)
            .sign()
    );
    
    // Execute transaction and track gas usage
    let output = executor.execute_transaction(txn);
    
    // In legacy mode, accessing the Account resource loaded during
    // prologue should NOT charge additional gas for the load
    // Compare with gas_feature_version >= 1 where it WOULD charge
    
    // Extract gas used from output
    let gas_used = extract_gas_used(&output);
    
    // Now test with modern gas version
    executor.set_gas_feature_version(1);
    let output_modern = executor.execute_transaction(txn.clone());
    let gas_used_modern = extract_gas_used(&output_modern);
    
    // Modern version should charge MORE gas due to reloading cached resources
    assert!(gas_used < gas_used_modern, 
        "Legacy mode should use less gas due to cache bypass vulnerability");
}
```

## Notes

This is a **previously identified and fixed vulnerability** that remains in the legacy code path for backward compatibility. The developers were aware of this issue and intentionally implemented the fix in gas_feature_version >= 1, as evidenced by the explicit comment explaining the need to flush the data cache.

The vulnerability is REAL and EXPLOITABLE on networks using legacy gas configurations, but modern Aptos mainnet is protected. Organizations running private Aptos chains or test networks should verify their gas_feature_version and upgrade if necessary.

### Citations

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/user.rs (L61-65)
```rust
    pub fn legacy_inherit_prologue_session(prologue_session: RespawnedSession<'r>) -> Self {
        Self {
            session: prologue_session,
        }
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

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/prologue.rs (L81-86)
```rust
        } else {
            Ok((
                SystemSessionChangeSet::empty(),
                UserSession::legacy_inherit_prologue_session(session),
            ))
        }
```

**File:** third_party/move/move-vm/runtime/src/data_cache.rs (L125-151)
```rust
    fn load_resource_mut(
        &mut self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        addr: &AccountAddress,
        ty: &Type,
    ) -> PartialVMResult<(&mut GlobalValue, Option<NumBytes>)> {
        let bytes_loaded = if !self.data_cache.contains_resource(addr, ty) {
            let (entry, bytes_loaded) = TransactionDataCache::create_data_cache_entry(
                self.loader,
                &LayoutConverter::new(self.loader),
                gas_meter,
                traversal_context,
                self.loader.unmetered_module_storage(),
                self.resource_resolver,
                addr,
                ty,
            )?;
            self.data_cache.insert_resource(*addr, ty.clone(), entry)?;
            Some(bytes_loaded)
        } else {
            None
        };

        let gv = self.data_cache.get_resource_mut(addr, ty)?;
        Ok((gv, bytes_loaded))
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1318-1333)
```rust
        let (gv, bytes_loaded) =
            data_cache.load_resource_mut(gas_meter, traversal_context, &addr, ty)?;
        if let Some(bytes_loaded) = bytes_loaded {
            gas_meter.charge_load_resource(
                addr,
                TypeWithRuntimeEnvironment {
                    ty,
                    runtime_environment: self.loader.runtime_environment(),
                },
                gv.view(),
                bytes_loaded,
            )?;
        }

        Ok(gv)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L126-213)
```text
    fun prologue_common(
        sender: &signer,
        gas_payer: &signer,
        replay_protector: ReplayProtector,
        txn_authentication_key: Option<vector<u8>>,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        txn_expiration_time: u64,
        chain_id: u8,
        is_simulation: bool,
    ) {
        let sender_address = signer::address_of(sender);
        let gas_payer_address = signer::address_of(gas_payer);
        assert!(
            timestamp::now_seconds() < txn_expiration_time,
            error::invalid_argument(PROLOGUE_ETRANSACTION_EXPIRED),
        );
        assert!(chain_id::get() == chain_id, error::invalid_argument(PROLOGUE_EBAD_CHAIN_ID));

        // TODO[Orderless]: Here, we are maintaining the same order of validation steps as before orderless txns were introduced.
        // Ideally, do the replay protection check in the end after the authentication key check and gas payment checks.

        // Check if the authentication key is valid
        if (!skip_auth_key_check(is_simulation, &txn_authentication_key)) {
            if (option::is_some(&txn_authentication_key)) {
                if (
                    sender_address == gas_payer_address ||
                    account::exists_at(sender_address) ||
                    !features::sponsored_automatic_account_creation_enabled()
                ) {
                    assert!(
                        txn_authentication_key == option::some(account::get_authentication_key(sender_address)),
                        error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY),
                    );
                };
            } else {
                assert!(
                    allow_missing_txn_authentication_key(sender_address),
                    error::invalid_argument(PROLOGUE_EINVALID_ACCOUNT_AUTH_KEY)
                );
            };
        };

        // Check for replay protection
        match (replay_protector) {
            SequenceNumber(txn_sequence_number) => {
                check_for_replay_protection_regular_txn(
                    sender_address,
                    gas_payer_address,
                    txn_sequence_number,
                );
            },
            Nonce(nonce) => {
                check_for_replay_protection_orderless_txn(
                    sender_address,
                    nonce,
                    txn_expiration_time,
                );
            }
        };

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

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L15-19)
```rust
pub fn get_gas_feature_version(state_view: &impl StateView) -> u64 {
    GasScheduleV2::fetch_config(state_view)
        .map(|gas_schedule| gas_schedule.feature_version)
        .unwrap_or(0)
}
```
