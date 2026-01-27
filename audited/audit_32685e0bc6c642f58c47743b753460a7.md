# Audit Report

## Title
Cross-Session State Leakage in Legacy Transaction Execution Path Causes Non-Deterministic Gas Charging and Consensus Risk

## Summary
In the legacy execution path (`gas_feature_version < 1`), the `PrologueSession` directly inherits its internal session state to the `UserSession` without flushing data caches. This causes resources read during prologue validation (Account, CoinStore) to remain cached and accessible without gas charges during user transaction execution, leading to non-deterministic gas consumption and potential consensus violations.

## Finding Description

The vulnerability exists in the `into_user_session` method of `PrologueSession`: [1](#0-0) 

In the modern path (`gas_feature_version >= 1`), the implementation correctly:
1. Finishes the prologue session and extracts its change set
2. Calls `resolver.release_resource_group_cache()` to flush cached resource groups
3. Spawns a **new** `UserSession` with a fresh session state [2](#0-1) 

However, in the legacy path (`gas_feature_version < 1`), the code directly inherits the same session: [3](#0-2) 

This legacy inheritance means the `UserSession` receives the same `RespawnedSession` object with its `SessionExt` containing a `TransactionDataCache` that has cached reads from the prologue: [4](#0-3) 

The prologue performs critical resource reads including authentication keys, sequence numbers, and coin balances: [5](#0-4) 

Specifically, the prologue reads:
- `account::get_authentication_key()` - reads Account resource
- `account::get_sequence_number()` - reads Account resource  
- `coin::is_balance_at_least()` or `aptos_account::is_fungible_balance_at_least()` - reads CoinStore/FungibleStore resource groups

When these resources are accessed again by user transaction code in legacy mode, they are served from cache without additional gas charges. The resource group cache behavior differs based on `GroupSizeKind`: [6](#0-5) 

In legacy mode, the cache is drained and returned (line 301-308), allowing the VMChangeSet to be prepared with cached group data. This bypasses proper gas accounting for resource group deserialization.

## Impact Explanation

This vulnerability has **Critical severity** impact:

1. **Non-Deterministic Gas Charging**: Transactions accessing resources read during prologue pay different gas costs depending on gas_feature_version, violating deterministic execution guarantees.

2. **Consensus Divergence Risk**: If validators run with mixed gas_feature_versions, identical transactions will consume different amounts of gas, potentially causing:
   - Out-of-gas aborts at different execution points
   - Different state modifications across validators
   - State root mismatches requiring consensus intervention

3. **Breaks Critical Invariant**: Violates the "Deterministic Execution" invariant that all validators must produce identical state roots for identical blocks.

4. **Network Partition Risk**: Sustained divergence could require hard fork intervention if validators split based on gas feature versions.

This meets the Aptos Bug Bounty **Critical Severity** criteria for "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is triggered whenever:
1. A node executes with `gas_feature_version() < 1` (legacy mode)
2. User transaction code accesses resources that were read during prologue
3. Multiple validators run different gas_feature_versions simultaneously

While modern networks likely use `gas_feature_version >= 1`, the legacy path remains in production code for:
- Backwards compatibility during upgrades
- Historical transaction replay
- Development/testing environments
- Potential rollback scenarios

The vulnerability is particularly dangerous during network upgrades when validators may temporarily run different versions.

## Recommendation

**Immediate Fix**: Remove the legacy path entirely or ensure it also flushes caches:

```rust
pub fn into_user_session(
    self,
    vm: &AptosVM,
    txn_meta: &TransactionMetadata,
    resolver: &'r impl AptosMoveResolver,
    change_set_configs: &ChangeSetConfigs,
    module_storage: &impl AptosModuleStorage,
) -> Result<(SystemSessionChangeSet, UserSession<'r>), VMStatus> {
    let Self { session } = self;

    // ALWAYS create a new session with flushed cache
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
}
```

Remove the conditional branching on `gas_feature_version()` and the `legacy_inherit_prologue_session` method entirely: [7](#0-6) 

## Proof of Concept

```rust
#[test]
fn test_prologue_cache_leakage() {
    // Setup: Create two validators with different gas_feature_versions
    let state_view = create_test_state_view();
    let vm_legacy = AptosVM::new_with_gas_feature_version(&state_view, 0); // Legacy
    let vm_modern = AptosVM::new_with_gas_feature_version(&state_view, 1); // Modern
    
    // Create transaction that:
    // 1. Has prologue read Account and CoinStore
    // 2. User code also reads the same resources
    let txn = create_test_transaction_reading_account_and_balance();
    let resolver = TestResolver::new(&state_view);
    
    // Execute with legacy path
    let mut prologue_legacy = PrologueSession::new(&vm_legacy, &txn.metadata(), &resolver);
    run_prologue(&mut prologue_legacy);
    let (_, user_legacy) = prologue_legacy.into_user_session(
        &vm_legacy, &txn.metadata(), &resolver, &configs, &module_storage
    ).unwrap();
    let gas_legacy = execute_user_transaction(user_legacy);
    
    // Execute with modern path  
    let mut prologue_modern = PrologueSession::new(&vm_modern, &txn.metadata(), &resolver);
    run_prologue(&mut prologue_modern);
    let (_, user_modern) = prologue_modern.into_user_session(
        &vm_modern, &txn.metadata(), &resolver, &configs, &module_storage
    ).unwrap();
    let gas_modern = execute_user_transaction(user_modern);
    
    // VULNERABILITY: Gas consumption differs between paths
    assert_ne!(gas_legacy, gas_modern, "Non-deterministic gas charging detected!");
    
    // Legacy path uses less gas because resources are cached
    assert!(gas_legacy < gas_modern, "Legacy path incorrectly benefits from cached resources");
}
```

## Notes

The development team was aware of this issue, as evidenced by the comment "Create a new session so that the data cache is flushed." However, the legacy code path was retained for backwards compatibility, creating a persistent consensus risk. All production networks should enforce `gas_feature_version >= 1` and the legacy path should be deprecated entirely to eliminate this attack surface.

### Citations

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/prologue.rs (L49-87)
```rust
    pub fn into_user_session(
        self,
        vm: &AptosVM,
        txn_meta: &TransactionMetadata,
        resolver: &'r impl AptosMoveResolver,
        change_set_configs: &ChangeSetConfigs,
        module_storage: &impl AptosModuleStorage,
    ) -> Result<(SystemSessionChangeSet, UserSession<'r>), VMStatus> {
        let Self { session } = self;

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
        } else {
            Ok((
                SystemSessionChangeSet::empty(),
                UserSession::legacy_inherit_prologue_session(session),
            ))
        }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L73-78)
```rust
pub struct SessionExt<'r, R> {
    data_cache: TransactionDataCache,
    extensions: NativeContextExtensions<'r>,
    pub(crate) resolver: &'r R,
    is_storage_slot_metadata_enabled: bool,
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

**File:** aptos-move/aptos-vm-types/src/resource_group_adapter.rs (L289-309)
```rust
    fn release_group_cache(
        &self,
    ) -> Option<HashMap<Self::GroupKey, BTreeMap<Self::ResourceTag, Bytes>>> {
        if self.group_size_kind == GroupSizeKind::AsSum {
            // Clear the cache, but do not return the contents to the caller. This leads to
            // the VMChangeSet prepared in a new, granular format that the block executor
            // can handle (combined as a group update at the end).
            self.group_cache.borrow_mut().clear();
            None
        } else {
            // Returning the contents to the caller leads to preparing the VMChangeSet in the
            // backwards compatible way (containing the whole group update).
            Some(
                self.group_cache
                    .borrow_mut()
                    .drain()
                    .map(|(k, v)| (k, v.0))
                    .collect(),
            )
        }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/user.rs (L61-65)
```rust
    pub fn legacy_inherit_prologue_session(prologue_session: RespawnedSession<'r>) -> Self {
        Self {
            session: prologue_session,
        }
    }
```
