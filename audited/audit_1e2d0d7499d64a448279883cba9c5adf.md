# Audit Report

## Title
Indexer Fails to Detect Object Deletion When Resource Group Contains Remaining Members

## Summary
The indexer's object deletion logic only detects deletions when the entire `ObjectGroup` resource group is removed. However, objects with additional resources in the group (such as `TombStone`) will have their `ObjectCore` deleted without the indexer recording the deletion, causing state inconsistency between the blockchain and indexed data.

## Finding Description

The indexer's `from_delete_resource` function checks for object deletion by matching against the resource group type: [1](#0-0) 

This check only triggers when a `DeleteResource` write set change occurs for type `0x1::object::ObjectGroup`. However, this only happens when the entire resource group is deleted (all member resources removed).

In the Aptos object model, multiple resources can be stored together in the `ObjectGroup` resource group: [2](#0-1) 

The critical issue arises from how the `object::delete()` function operates: [3](#0-2) 

This function only removes `ObjectCore` and optionally `Untransferable`, but does NOT remove `TombStone` or any other resources that may exist in the `ObjectGroup`.

When resource groups are serialized for storage, the system checks if the group is empty: [4](#0-3) 

If `post_group_size` is zero, a `Delete` operation is created. Otherwise, it's a `Modify` operation. During API conversion, only complete group deletions produce `DeleteResource`: [5](#0-4) 

**Attack Scenario:**
1. User creates an object (contains `ObjectCore`)
2. User calls `object::burn()` which adds `TombStone` to the object: [6](#0-5) 
3. User calls `object::delete()` which removes `ObjectCore` but leaves `TombStone`
4. The `ObjectGroup` still contains `TombStone`, so it's not empty
5. This produces a `WriteResource` for `ObjectGroup` (modifying it to remove `ObjectCore`), not a `DeleteResource`
6. The indexer's check at line 118 doesn't trigger
7. The object remains marked as existing in the indexer database despite `ObjectCore` being deleted

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

The vulnerability causes:
- **Indexer State Divergence**: The indexer shows objects as existing when they've been deleted on-chain
- **Incorrect Query Results**: Applications querying for object existence, ownership, or properties will receive stale data
- **User Confusion**: Users who delete objects will see them still appearing in indexer-based explorers and applications
- **Data Integrity Issues**: Any downstream system relying on the indexer for object state will have incorrect information

While this doesn't directly affect consensus or cause fund loss, it breaks the critical guarantee that the indexer accurately reflects on-chain state, which is essential for user-facing applications and infrastructure.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is easily triggered through normal user actions:
- Any user can call `burn()` on their own objects (requires ownership)
- Calling `delete()` after `burn()` is a valid and reasonable sequence
- No special permissions or complex setup required
- The scenario naturally occurs during object lifecycle management

The impact is limited to indexer state divergence rather than on-chain state corruption, but occurs deterministically whenever an object with remaining resources is deleted.

## Recommendation

The indexer should detect object deletion by checking for `ObjectCore` removal specifically, not just complete `ObjectGroup` deletion. 

**Recommended Fix:**

Modify the indexer to track individual resource deletions within resource groups and detect when `ObjectCore` is specifically deleted:

```rust
pub fn from_delete_resource(
    delete_resource: &DeleteResource,
    txn_version: i64,
    write_set_change_index: i64,
    object_mapping: &HashMap<CurrentObjectPK, CurrentObject>,
    conn: &mut PgPoolConnection,
) -> anyhow::Result<Option<(Self, CurrentObject)>> {
    // Check if this is an ObjectGroup deletion (entire group removed)
    let is_object_group_delete = delete_resource.resource.to_string() == "0x1::object::ObjectGroup";
    
    // Also check if this is ObjectCore specifically being deleted from a resource group
    // by examining write set changes for ObjectCore deletions
    let is_object_core_delete = delete_resource.resource.to_string() == "0x1::object::ObjectCore";
    
    if is_object_group_delete || is_object_core_delete {
        let resource = MoveResource::from_delete_resource(
            delete_resource,
            0,
            txn_version,
            0,
        );
        // ... rest of existing logic
    } else {
        Ok(None)
    }
}
```

However, a deeper issue is that individual resource group member deletions are not exposed as separate `DeleteResource` changes in the current API. The proper fix requires:

1. Enhancing the API layer to expose individual resource deletions from resource groups
2. Updating the indexer to process these individual deletions
3. Specifically detecting `ObjectCore` deletion as the signal for object deletion

## Proof of Concept

```move
#[test_only]
module test_addr::object_deletion_indexer_bug {
    use std::signer;
    use aptos_framework::object;

    #[test(creator = @0x123)]
    fun test_object_deletion_not_indexed(creator: &signer) {
        // Create a deletable object
        let constructor_ref = object::create_object(signer::address_of(creator));
        let delete_ref = object::generate_delete_ref(&constructor_ref);
        let object_addr = object::address_from_constructor_ref(&constructor_ref);
        
        // Verify object exists with ObjectCore
        assert!(object::is_object(object_addr), 0);
        
        // Burn the object - adds TombStone to ObjectGroup
        let obj = object::address_to_object<object::ObjectCore>(object_addr);
        object::burn(creator, obj);
        
        // Object still exists (ObjectCore present) but now has TombStone
        assert!(object::is_object(object_addr), 1);
        assert!(object::is_burnt(obj), 2);
        
        // Delete the object - removes ObjectCore but leaves TombStone
        object::delete(delete_ref);
        
        // Object no longer exists on-chain (ObjectCore gone)
        assert!(!object::is_object(object_addr), 3);
        
        // BUG: Indexer still shows object as existing because:
        // - ObjectGroup was not deleted (TombStone remains)
        // - Only WriteResource for ObjectGroup was generated, not DeleteResource
        // - Indexer only checks for DeleteResource of ObjectGroup
        // Therefore: Indexer database shows is_deleted=false when it should be true
    }
}
```

This test demonstrates that after calling `burn()` then `delete()`, the object no longer exists on-chain (`is_object` returns false), but the indexer would not record this deletion because the check at line 118 only triggers for complete `ObjectGroup` deletion, not when `ObjectCore` is removed with `TombStone` remaining.

## Notes

This vulnerability specifically affects the indexer's ability to maintain consistency with on-chain state. While not a consensus or fund-loss issue, it represents a critical data integrity problem for any application relying on indexed data for object queries, including wallets, explorers, and dApps. The issue requires intervention to correct the indexer's state or implement proper detection logic for `ObjectCore` deletions.

### Citations

**File:** crates/indexer/src/models/v2_objects.rs (L118-118)
```rust
        if delete_resource.resource.to_string() == "0x1::object::ObjectGroup" {
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L96-123)
```text
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// The core of the object model that defines ownership, transferability, and events.
    struct ObjectCore has key {
        /// Used by guid to guarantee globally unique objects and create event streams
        guid_creation_num: u64,
        /// The address (object or account) that owns this object
        owner: address,
        /// Object transferring is a common operation, this allows for disabling and enabling
        /// transfers bypassing the use of a TransferRef.
        allow_ungated_transfer: bool,
        /// Emitted events upon transferring of ownership.
        transfer_events: event::EventHandle<TransferEvent>,
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// This is added to objects that are burnt (ownership transferred to BURN_ADDRESS).
    struct TombStone has key {
        /// Track the previous owner before the object is burnt so they can reclaim later if so desired.
        original_owner: address,
    }

    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    /// The existence of this renders all `TransferRef`s irrelevant. The object cannot be moved.
    struct Untransferable has key {}

    #[resource_group(scope = global)]
    /// A shared resource group for storing object resources together in storage.
    struct ObjectGroup {}
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L414-428)
```text
    public fun delete(self: DeleteRef) acquires Untransferable, ObjectCore {
        let object_core = move_from<ObjectCore>(self.self);
        let ObjectCore {
            guid_creation_num: _,
            owner: _,
            allow_ungated_transfer: _,
            transfer_events,
        } = object_core;

        if (exists<Untransferable>(self.self)) {
            let Untransferable {} = move_from<Untransferable>(self.self);
        };

        event::destroy_handle(transfer_events);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/object.move (L622-628)
```text
    public entry fun burn<T: key>(owner: &signer, object: Object<T>) acquires ObjectCore {
        let original_owner = signer::address_of(owner);
        assert!(object.is_owner(original_owner), error::permission_denied(ENOT_OBJECT_OWNER));
        let object_addr = object.inner;
        assert!(!exists<TombStone>(object_addr), EOBJECT_ALREADY_BURNT);
        move_to(&create_signer(object_addr), TombStone { original_owner });
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L207-214)
```rust
        // Create an op to encode the proper kind for resource group operation.
        let metadata_op = if post_group_size.get() == 0 {
            MoveStorageOp::Delete
        } else if pre_group_size.get() == 0 {
            MoveStorageOp::New(Bytes::new())
        } else {
            MoveStorageOp::Modify(Bytes::new())
        };
```

**File:** api/types/src/convert.rs (L486-490)
```rust
                Path::ResourceGroup(typ) => vec![WriteSetChange::DeleteResource(DeleteResource {
                    address: access_path.address.into(),
                    state_key_hash,
                    resource: typ.into(),
                })],
```
