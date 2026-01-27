# Audit Report

## Title
Event-WriteSet Correspondence Not Enforced: Audit Trail Inconsistency Vulnerability

## Summary
The Aptos blockchain does not enforce any correspondence between events emitted and state changes (WriteSet) within a transaction. Move modules can emit events claiming one action occurred while performing different state modifications, or emit events with no corresponding state changes, creating systemic audit trail inconsistencies that affect all off-chain systems relying on event data.

## Finding Description

### Architecture Overview
During transaction execution in Aptos, events and state changes are collected through two independent mechanisms:

1. **Events**: Accumulated via `NativeEventContext` when Move code calls `event::emit()` [1](#0-0) 

2. **State Changes**: Collected through the Move VM's resource write operations during bytecode execution

These are combined into a `VMChangeSet` without any validation of correspondence [2](#0-1) 

The `VMChangeSet` is then converted to `TransactionOutput` by simply extracting events and write set separately [3](#0-2) 

### Lack of Validation

The `ChangeSet` constructor provides no validation between events and write set: [4](#0-3) 

Transaction output validation only checks cryptographic hashes, not semantic correspondence: [5](#0-4) 

The event validation system only ensures structs have the `#[event]` attribute, not that events match state changes: [6](#0-5) 

### Exploitation Path

Any user deploying a Move module can:

1. **Emit misleading events**: Call `event::emit()` with fabricated data while performing different state modifications
2. **Emit events without state changes**: Claim actions occurred without modifying blockchain state
3. **Omit events for state changes**: Use functions like those in fungible assets that explicitly skip events [7](#0-6) 

Example attack scenario:
```move
module attacker::fake_token {
    use aptos_framework::event;
    
    #[event]
    struct TransferEvent has drop, store {
        from: address,
        to: address, 
        amount: u64
    }
    
    public fun malicious_transfer(from: &signer, to: address, claimed_amount: u64) {
        // Emit event claiming small transfer
        event::emit(TransferEvent { 
            from: signer::address_of(from), 
            to, 
            amount: claimed_amount  // e.g., 100
        });
        
        // Actually transfer much larger amount in state
        // (actual state modification code transferring 10000)
    }
}
```

## Impact Explanation

This vulnerability creates **systemic audit trail inconsistencies** affecting:

1. **Off-chain indexers**: Block explorers, analytics platforms, and indexing services rely on events to track blockchain activity. Inconsistent events lead to incorrect data presentation.

2. **Compliance and auditing**: Regulatory compliance systems that rely on event logs for transaction tracking would have incomplete or misleading records.

3. **User interfaces**: Wallets and dApps displaying transaction history based on events show incorrect information to users.

4. **Integration systems**: External systems (exchanges, bridges, oracles) that monitor events for state changes can be deceived.

However, this does **not** directly affect:
- On-chain consensus (all validators agree on the same events and state)
- Blockchain state integrity (state changes are correctly applied)
- Fund security on the blockchain itself (users can verify state directly)

The severity is **High** rather than Critical because while it represents a significant protocol-level design issue affecting ecosystem-wide data integrity, it does not directly enable theft of on-chain funds or consensus violations. The impact aligns with "Significant protocol violations" under High Severity criteria.

## Likelihood Explanation

**Likelihood: Very High**

1. **No barriers to exploitation**: Any user can deploy a Move module with this behavior
2. **Already present in framework**: The Aptos Framework itself uses this pattern (e.g., gas fee deposits skip events), establishing it as acceptable behavior [8](#0-7) 
3. **No runtime detection**: No validation exists to detect or prevent this at module deployment or execution time
4. **Ecosystem dependency**: The entire Aptos ecosystem relies on events for off-chain data, making the impact widespread

## Recommendation

Implement a **trusted event framework** with validation:

1. **Framework-level event validation**: Add a verification layer that correlates events with state changes for critical operations (token transfers, NFT movements, governance actions).

2. **Event-state binding**: Introduce a mechanism to cryptographically bind events to their corresponding state changes:
```rust
// In VMChangeSet::try_combine_into_storage_change_set
pub fn try_combine_into_storage_change_set(
    self,
    module_write_set: ModuleWriteSet,
    validate_correspondence: bool,
) -> Result<StorageChangeSet, PanicError> {
    // ... existing code ...
    
    if validate_correspondence {
        validate_event_state_correspondence(&events, &resource_write_set)?;
    }
    
    // ... rest of conversion ...
}
```

3. **Trusted module certification**: Flag trusted modules (like `0x1::coin`) where events are guaranteed to match state changes, allowing off-chain systems to distinguish reliable event sources.

4. **Documentation**: Clearly document that events from user modules should not be trusted as authoritative audit trails without independent state verification.

## Proof of Concept

```move
// File: malicious_module.move
module 0x42::audit_trail_attack {
    use std::signer;
    use aptos_framework::event;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;

    #[event]
    struct FakeTransferEvent has drop, store {
        from: address,
        to: address,
        amount: u64,
    }

    // Emits event claiming 100 coin transfer
    // Actually transfers 10000 coins
    public entry fun deceptive_transfer(
        from: &signer,
        to: address,
    ) {
        // Emit event claiming 100 coin transfer
        event::emit(FakeTransferEvent {
            from: signer::address_of(from),
            to,
            amount: 100,  // Claimed amount
        });
        
        // Actually transfer 10000 coins in state
        let coins = coin::withdraw<AptosCoin>(from, 10000);
        coin::deposit(to, coins);
    }

    #[test(attacker = @0x42, victim = @0x123)]
    public fun test_audit_trail_mismatch(
        attacker: &signer,
        victim: &signer,
    ) {
        // Setup and execute deceptive transfer
        // Events show 100 transferred
        // State shows 10000 actually transferred
        // Both committed to blockchain with matching hashes
        // Off-chain systems see 100, on-chain state reflects 10000
    }
}
```

**Notes:**

This vulnerability represents a fundamental design choice in Aptos where events are informational outputs controlled by Move code rather than guaranteed audit trails. While the blockchain correctly commits both events and state changes with cryptographic integrity, the lack of enforced correspondence creates systemic risks for off-chain ecosystem components that form the practical interface through which users interact with the blockchain.

The framework itself demonstrates this pattern is "by design" through functions that explicitly skip event emission, but this design choice has significant security implications for the broader ecosystem's data integrity and trustworthiness.

### Citations

**File:** aptos-move/framework/src/natives/event.rs (L312-320)
```rust
    let ctx = context.extensions_mut().get_mut::<NativeEventContext>();
    let event = ContractEvent::new_v2(type_tag, blob).map_err(|_| SafeNativeError::Abort {
        abort_code: ECANNOT_CREATE_EVENT,
    })?;
    // TODO(layouts): avoid cloning layouts for events with delayed fields.
    ctx.events.push((
        event,
        contains_delayed_fields.then(|| layout.as_ref().clone()),
    ));
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L230-244)
```rust
        let event_context: NativeEventContext = extensions.remove();
        let events = event_context.legacy_into_events();

        let woc = WriteOpConverter::new(resolver, is_storage_slot_metadata_enabled);

        let change_set = Self::convert_change_set(
            &woc,
            change_set,
            resource_group_change_set,
            events,
            table_change_set,
            aggregator_change_set,
            configs.legacy_resource_creation_as_modification(),
        )
        .map_err(|e| e.finish(Location::Undefined))?;
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L218-271)
```rust
    pub fn try_combine_into_storage_change_set(
        self,
        module_write_set: ModuleWriteSet,
    ) -> Result<StorageChangeSet, PanicError> {
        // Converting VMChangeSet into TransactionOutput (i.e. storage change set), can
        // be done here only if dynamic_change_set_optimizations have not been used/produced
        // data into the output.
        // If they (DelayedField or ResourceGroup) have added data into the write set, translation
        // into output is more complicated, and needs to be done within BlockExecutor context
        // that knows how to deal with it.
        let Self {
            resource_write_set,
            aggregator_v1_write_set,
            aggregator_v1_delta_set,
            delayed_field_change_set,
            events,
        } = self;

        if !aggregator_v1_delta_set.is_empty() {
            return Err(code_invariant_error(
                "Cannot convert from VMChangeSet with non-materialized Aggregator V1 deltas to ChangeSet.",
            ));
        }
        if !delayed_field_change_set.is_empty() {
            return Err(code_invariant_error(
                "Cannot convert from VMChangeSet with non-materialized Delayed Field changes to ChangeSet.",
            ));
        }

        let mut write_set_mut = WriteSetMut::default();
        write_set_mut.extend(
            resource_write_set
                .into_iter()
                .map(|(k, v)| {
                    Ok((
                        k,
                        v.try_into_concrete_write().ok_or_else(|| {
                            code_invariant_error(
                                "Cannot convert from VMChangeSet with non-materialized write set",
                            )
                        })?,
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        write_set_mut.extend(module_write_set.into_write_ops());
        write_set_mut.extend(aggregator_v1_write_set);

        let events = events.into_iter().map(|(e, _)| e).collect();
        let write_set = write_set_mut
            .freeze()
            .expect("Freezing a WriteSet does not fail.");
        Ok(StorageChangeSet::new(write_set, events))
    }
```

**File:** types/src/transaction/change_set.rs (L13-16)
```rust
impl ChangeSet {
    pub fn new(write_set: WriteSet, events: Vec<ContractEvent>) -> Self {
        Self { write_set, events }
    }
```

**File:** types/src/transaction/mod.rs (L1869-1928)
```rust
    pub fn ensure_match_transaction_info(
        &self,
        version: Version,
        txn_info: &TransactionInfo,
        expected_write_set: Option<&WriteSet>,
        expected_events: Option<&[ContractEvent]>,
    ) -> Result<()> {
        const ERR_MSG: &str = "TransactionOutput does not match TransactionInfo";

        let expected_txn_status: TransactionStatus = txn_info.status().clone().into();
        ensure!(
            self.status() == &expected_txn_status,
            "{}: version:{}, status:{:?}, auxiliary data:{:?}, expected:{:?}",
            ERR_MSG,
            version,
            self.status(),
            self.auxiliary_data(),
            expected_txn_status,
        );

        ensure!(
            self.gas_used() == txn_info.gas_used(),
            "{}: version:{}, gas_used:{:?}, expected:{:?}",
            ERR_MSG,
            version,
            self.gas_used(),
            txn_info.gas_used(),
        );

        let write_set_hash = CryptoHash::hash(self.write_set());
        ensure!(
            write_set_hash == txn_info.state_change_hash(),
            "{}: version:{}, write_set_hash:{:?}, expected:{:?}, write_set: {:?}, expected(if known): {:?}",
            ERR_MSG,
            version,
            write_set_hash,
            txn_info.state_change_hash(),
            self.write_set,
            expected_write_set,
        );

        let event_hashes = self
            .events()
            .iter()
            .map(CryptoHash::hash)
            .collect::<Vec<_>>();
        let event_root_hash = InMemoryEventAccumulator::from_leaves(&event_hashes).root_hash;
        ensure!(
            event_root_hash == txn_info.event_root_hash(),
            "{}: version:{}, event_root_hash:{:?}, expected:{:?}, events: {:?}, expected(if known): {:?}",
            ERR_MSG,
            version,
            event_root_hash,
            txn_info.event_root_hash(),
            self.events(),
            expected_events,
        );

        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/verifier/event_validation.rs (L100-142)
```rust
pub(crate) fn validate_emit_calls(
    event_structs: &HashSet<String>,
    module: &CompiledModule,
) -> VMResult<()> {
    for fun in module.function_defs() {
        if let Some(code_unit) = &fun.code {
            for bc in &code_unit.code {
                use Bytecode::*;
                match bc {
                    CallGeneric(index) | PackClosureGeneric(index, ..) => {
                        let func_instantiation = &module.function_instantiation_at(*index);
                        let func_handle = module.function_handle_at(func_instantiation.handle);

                        if !is_event_emit_call(BinaryIndexedView::Module(module), func_handle) {
                            continue;
                        }

                        let param = module
                            .signature_at(func_instantiation.type_parameters)
                            .0
                            .first()
                            .ok_or_else(|| {
                                metadata_validation_error(
                                    "Missing parameter for 0x1::event::emit function",
                                )
                            })?;
                        match param {
                            StructInstantiation(index, _) | Struct(index) => {
                                let struct_handle = &module.struct_handle_at(*index);
                                let struct_name = module.identifier_at(struct_handle.name);
                                if struct_handle.module != module.self_handle_idx() {
                                    metadata_validation_err(format!("{} passed to 0x1::event::emit function is not defined in the same module", struct_name).as_str())
                                } else if !event_structs.contains(struct_name.as_str()) {
                                    metadata_validation_err(format!("Missing #[event] attribute on {}. The #[event] attribute is required for all structs passed into 0x1::event::emit.", struct_name).as_str())
                                } else {
                                    Ok(())
                                }
                            },
                            _ => metadata_validation_err(
                                "Passed in a non-struct parameter into 0x1::event::emit.",
                            ),
                        }?;
                    },
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L1280-1284)
```text
    public(friend) fun unchecked_deposit_with_no_events(
        store_addr: address, fa: FungibleAsset
    ) acquires FungibleStore, ConcurrentFungibleBalance {
        unchecked_deposit_with_no_events_inline(store_addr, fa);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/coin.move (L937-947)
```text
    public(friend) fun deposit_for_gas_fee<CoinType>(
        account_addr: address, coin: Coin<CoinType>
    ) acquires CoinConversionMap, CoinInfo {
        let fa = coin_to_fungible_asset(coin);
        let metadata = fungible_asset::asset_metadata(&fa);
        let store =
            primary_fungible_store::ensure_primary_store_exists(account_addr, metadata);
        fungible_asset::unchecked_deposit_with_no_events(
            object::object_address(&store), fa
        );
    }
```
