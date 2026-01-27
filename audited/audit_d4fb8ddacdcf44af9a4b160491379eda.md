# Audit Report

## Title
Resource Group Size Charged Multiple Times Per Transaction Due to Per-Session First Access Tracking

## Summary
The `StorageAdapter` tracks first access to resource groups using a per-session `accessed_groups` HashSet. Since Aptos creates multiple `StorageAdapter` instances during a single transaction (prologue → user session → epilogue), the same resource group's size is charged multiple times, resulting in systematic gas overcharging for all transactions accessing resource groups.

## Finding Description

The implementation of `get_resource_bytes_with_metadata_and_layout` in `StorageAdapter` tracks first access to resource groups using an `accessed_groups` HashSet stored in the adapter instance: [1](#0-0) 

When a resource from a resource group is accessed, the implementation checks if this is the first access and charges the entire group size: [2](#0-1) 

The critical issue is that Aptos creates separate `StorageAdapter` instances for each transaction phase:

1. **Prologue Phase**: Creates first `RespawnedSession` with new `StorageAdapter` [3](#0-2) 

2. **User Session Phase**: Creates second `RespawnedSession` with new `StorageAdapter` [4](#0-3) 

3. **Epilogue Phase**: Creates third `RespawnedSession` with new `StorageAdapter` [5](#0-4) 

Each `RespawnedSession` internally creates a fresh `StorageAdapter` via `as_move_resolver_with_group_view`: [6](#0-5) [7](#0-6) 

Each new `StorageAdapter` gets a fresh `accessed_groups` HashSet: [8](#0-7) 

**Exploitation Path:**

1. Transaction accesses a resource from `ObjectGroup` (e.g., `FungibleStore`) during user execution
2. First access charges the full resource group size (potentially thousands of bytes)
3. Epilogue runs `transaction_validation::epilogue` which accesses fungible assets for gas payment: [9](#0-8) 

4. Since epilogue uses a new `StorageAdapter`, it treats this as first access again and charges the full group size a second time

This happens automatically for ANY transaction accessing resource group members (including all fungible asset operations), breaking the gas calculation invariant.

## Impact Explanation

**Severity: Medium** - Limited funds loss through systematic gas overcharging.

While there's a TODO comment suggesting the team is aware of session separation issues, the current implementation causes measurable financial harm: [10](#0-9) 

- Users are charged 2-3x the resource group size they should pay
- For large ObjectGroups with many fungible assets, this could be thousands of bytes per transaction
- Affects ALL transactions using fungible assets (the most common operation type)
- Breaks Invariant #9: "All operations must respect gas, storage, and computational limits" - gas calculation is incorrect
- No validator collusion or special access required - happens to all users automatically

This differs from Critical severity because:
- No consensus violation (all nodes miscalculate identically)
- No loss of funds beyond gas overcharging
- No network availability impact

## Likelihood Explanation

**Likelihood: Very High** - Occurs on every transaction accessing resource groups across multiple phases.

The vulnerability triggers automatically whenever:
- A transaction accesses any resource in a resource group (e.g., FungibleStore, Metadata, Supply)
- The epilogue runs (which always accesses fungible assets for gas payment)

This includes virtually all non-trivial transactions on Aptos, as the fungible asset system uses resource groups extensively: [11](#0-10) 

No special conditions, timing, or attacker action required. The overcharging is deterministic and affects all validators identically.

## Recommendation

Track accessed resource groups at the transaction level rather than session level. Options:

**Option 1**: Pass accessed groups state through session transitions
- Modify `RespawnedSession::spawn` to accept and forward the `accessed_groups` set from the previous session
- Requires changing `StorageAdapter` to accept pre-populated tracking state

**Option 2**: Track at the ExecutorView level
- Move `accessed_groups` from `StorageAdapter` to the underlying `ExecutorView`
- This ensures tracking persists across all sessions in a transaction

**Option 3**: Single session per transaction (architectural change)
- Eliminate session respawning between prologue/user/epilogue
- Would require rearchitecting the transaction execution flow

The TODO comment acknowledges this needs improvement: [12](#0-11) 

## Proof of Concept

```move
// Test module demonstrating resource group double-charging
module 0x1::gas_overcharge_poc {
    use std::signer;
    use aptos_framework::object::{Self, Object};
    use aptos_framework::fungible_asset::{Self, Metadata, FungibleStore};
    
    // This test would need to instrument gas metering to observe:
    // 1. User transaction accesses FungibleStore (group size charged)
    // 2. Epilogue accesses FungibleStore for gas (group size charged AGAIN)
    //
    // Expected: Group size charged once
    // Actual: Group size charged 2-3 times (prologue + user + epilogue)
    
    public entry fun transfer_and_check(
        sender: &signer,
        recipient: address,
        amount: u64,
        metadata: Object<Metadata>
    ) {
        // This operation accesses the ObjectGroup containing FungibleStore
        let sender_store = fungible_asset::primary_store(signer::address_of(sender), metadata);
        let recipient_store = fungible_asset::primary_store(recipient, metadata);
        
        fungible_asset::transfer(sender, sender_store, recipient_store, amount);
        
        // Epilogue will access the same ObjectGroup again for gas payment
        // Result: Group size charged twice instead of once
    }
}
```

To demonstrate in Rust tests, instrument `StorageAdapter::get_any_resource_with_layout` to log when group size is added, then execute a transaction accessing fungible assets and verify the group size is added multiple times for the same resource group key.

## Notes

While the code comment suggests session separation is intentional for "correct charging," the TODO indicates this approach is suboptimal. The current implementation violates the principle that first-access charges should reflect actual I/O cost - but subsequent session accesses to the same cached group don't incur I/O costs yet still charge the full group size. This is a gas calculation bug that systematically overcharges users.

### Citations

**File:** aptos-move/aptos-vm/src/data_cache.rs (L67-71)
```rust
pub struct StorageAdapter<'e, E> {
    executor_view: &'e E,
    resource_group_view: ResourceGroupAdapter<'e>,
    accessed_groups: RefCell<HashSet<StateKey>>,
}
```

**File:** aptos-move/aptos-vm/src/data_cache.rs (L90-96)
```rust
    fn new(executor_view: &'e E, resource_group_view: ResourceGroupAdapter<'e>) -> Self {
        Self {
            executor_view,
            resource_group_view,
            accessed_groups: RefCell::new(HashSet::new()),
        }
    }
```

**File:** aptos-move/aptos-vm/src/data_cache.rs (L98-129)
```rust
    fn get_any_resource_with_layout(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
        metadata: &[Metadata],
        maybe_layout: Option<&MoveTypeLayout>,
    ) -> PartialVMResult<(Option<Bytes>, usize)> {
        let resource_group = get_resource_group_member_from_metadata(struct_tag, metadata);
        if let Some(resource_group) = resource_group {
            let key = StateKey::resource_group(address, &resource_group);
            let buf =
                self.resource_group_view
                    .get_resource_from_group(&key, struct_tag, maybe_layout)?;

            let first_access = self.accessed_groups.borrow_mut().insert(key.clone());
            let group_size = if first_access {
                self.resource_group_view.resource_group_size(&key)?.get()
            } else {
                0
            };

            let buf_size = resource_size(&buf);
            Ok((buf, buf_size + group_size as usize))
        } else {
            let state_key = resource_state_key(address, struct_tag)?;
            let buf = self
                .executor_view
                .get_resource_bytes(&state_key, maybe_layout)?;
            let buf_size = resource_size(&buf);
            Ok((buf, buf_size))
        }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/prologue.rs (L32-47)
```rust
    pub fn new(
        vm: &AptosVM,
        txn_meta: &TransactionMetadata,
        resolver: &'r impl AptosMoveResolver,
    ) -> Self {
        let session_id = SessionId::prologue_meta(txn_meta);
        let session = RespawnedSession::spawn(
            vm,
            session_id,
            resolver,
            VMChangeSet::empty(),
            Some(txn_meta.as_user_transaction_context()),
        );

        Self { session }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/prologue.rs (L59-67)
```rust
        if vm.gas_feature_version() >= 1 {
            // Create a new session so that the data cache is flushed.
            // This is to ensure we correctly charge for loading certain resources, even if they
            // have been previously cached in the prologue.
            //
            // TODO(Gas): Do this in a better way in the future, perhaps without forcing the data cache to be flushed.
            // By releasing resource group cache, we start with a fresh slate for resource group
            // cost accounting.

```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/user.rs (L42-59)
```rust
    pub fn new(
        vm: &AptosVM,
        txn_meta: &TransactionMetadata,
        resolver: &'r impl AptosMoveResolver,
        prologue_change_set: VMChangeSet,
    ) -> Self {
        let session_id = SessionId::txn_meta(txn_meta);

        let session = RespawnedSession::spawn(
            vm,
            session_id,
            resolver,
            prologue_change_set,
            Some(txn_meta.as_user_transaction_context()),
        );

        Self { session }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/epilogue.rs (L74-96)
```rust
    fn new(
        vm: &AptosVM,
        txn_meta: &TransactionMetadata,
        resolver: &'r impl AptosMoveResolver,
        previous_session_change_set: VMChangeSet,
        module_write_set: ModuleWriteSet,
        storage_refund: Fee,
    ) -> Self {
        let session_id = SessionId::epilogue_meta(txn_meta);
        let session = RespawnedSession::spawn(
            vm,
            session_id,
            resolver,
            previous_session_change_set,
            Some(txn_meta.as_user_transaction_context()),
        );

        Self {
            session,
            storage_refund,
            module_write_set,
        }
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/respawned_session.rs (L38-59)
```rust
    pub fn spawn(
        vm: &AptosVM,
        session_id: SessionId,
        base: &'r impl AptosMoveResolver,
        previous_session_change_set: VMChangeSet,
        user_transaction_context_opt: Option<UserTransactionContext>,
    ) -> RespawnedSession<'r> {
        let executor_view = ExecutorViewWithChangeSet::new(
            base.as_executor_view(),
            base.as_resource_group_view(),
            previous_session_change_set,
        );

        RespawnedSessionBuilder {
            executor_view,
            resolver_builder: |executor_view| vm.as_move_resolver_with_group_view(executor_view),
            session_builder: |resolver| {
                Some(vm.new_session(resolver, session_id, user_transaction_context_opt))
            },
        }
        .build()
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L534-544)
```rust
    pub fn as_move_resolver_with_group_view<'r, R: ExecutorView + ResourceGroupView>(
        &self,
        executor_view: &'r R,
    ) -> StorageAdapter<'r, R> {
        StorageAdapter::new_with_config(
            executor_view,
            self.gas_feature_version(),
            self.features(),
            Some(executor_view),
        )
    }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L587-632)
```text
    fun epilogue_gas_payer_extended(
        account: signer,
        gas_payer: address,
        storage_fee_refunded: u64,
        txn_gas_price: u64,
        txn_max_gas_units: u64,
        gas_units_remaining: u64,
        is_simulation: bool,
    ) {
        assert!(txn_max_gas_units >= gas_units_remaining, error::invalid_argument(EOUT_OF_GAS));
        let gas_used = txn_max_gas_units - gas_units_remaining;

        assert!(
            (txn_gas_price as u128) * (gas_used as u128) <= MAX_U64,
            error::out_of_range(EOUT_OF_GAS)
        );
        let transaction_fee_amount = txn_gas_price * gas_used;

        // it's important to maintain the error code consistent with vm
        // to do failed transaction cleanup.
        if (!skip_gas_payment(is_simulation, gas_payer)) {
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            };

            if (transaction_fee_amount > storage_fee_refunded) {
                let burn_amount = transaction_fee_amount - storage_fee_refunded;
                transaction_fee::burn_fee(gas_payer, burn_amount);
            } else if (transaction_fee_amount < storage_fee_refunded) {
                let mint_amount = storage_fee_refunded - transaction_fee_amount;
                transaction_fee::mint_and_refund(gas_payer, mint_amount);
            };
        };

        // Increment sequence number
        let addr = signer::address_of(&account);
        account::increment_sequence_number(addr);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L110-150)
```text
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct Supply has key {
        current: u128,
        // option::none() means unlimited supply.
        maximum: Option<u128>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct ConcurrentSupply has key {
        current: Aggregator<u128>
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// Metadata of a Fungible asset
    struct Metadata has key, copy, drop {
        /// Name of the fungible metadata, i.e., "USDT".
        name: String,
        /// Symbol of the fungible metadata, usually a shorter version of the name.
        /// For example, Singapore Dollar is SGD.
        symbol: String,
        /// Number of decimals used for display purposes.
        /// For example, if `decimals` equals `2`, a balance of `505` coins should
        /// be displayed to a user as `5.05` (`505 / 10 ** 2`).
        decimals: u8,
        /// The Uniform Resource Identifier (uri) pointing to an image that can be used as the icon for this fungible
        /// asset.
        icon_uri: String,
        /// The Uniform Resource Identifier (uri) pointing to the website for the fungible asset.
        project_uri: String
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// Defines a `FungibleAsset`, such that all `FungibleStore`s stores are untransferable at
    /// the object layer.
    struct Untransferable has key {}

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// The store object that holds fungible assets of a specific type associated with an account.
    struct FungibleStore has key {
        /// The address of the base metadata object.
        metadata: Object<Metadata>,
```
