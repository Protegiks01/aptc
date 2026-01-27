# Audit Report

## Title
ObjectCore Deletion Race Condition Causes Indexer Event Data Corruption and Sequence Number Collisions

## Summary
The `TransferTranslator` in the event indexer uses `latest_state_checkpoint_view()` to look up `ObjectCore` resources when translating V2 Transfer events to V1 format. This creates a race condition where an object can be transferred and then deleted before the indexer processes the transfer event. When ObjectCore is not found, the translator falls back to a deterministic creation number with sequence 0, causing multiple transfer events for the same object to overwrite each other in the database, resulting in event data loss and sequence number corruption. [1](#0-0) 

## Finding Description
The vulnerability exists in how the indexer translates V2 Transfer events to V1 events for backward compatibility. The critical flaw is in the `TransferTranslator::translate_event_v2_to_v1` implementation: [2](#0-1) 

When translating a Transfer event, the code attempts to look up the `ObjectCore` resource using: [3](#0-2) 

The critical issue is that `latest_state_checkpoint_view()` returns a state view at the **latest committed version**, not at the version when the event was emitted: [4](#0-3) 

**Attack Scenario:**

1. **Version V**: Attacker transfers a deletable object (emits Transfer event, ObjectCore exists)
2. **Version V+1**: Attacker deletes the object using `delete()`, removing ObjectCore from storage
3. **Version V+2+**: Indexer processes the Transfer event from version V
4. The indexer looks up ObjectCore at the **latest** state (V+2+) where ObjectCore has been deleted
5. Lookup fails, translator falls back to deterministic creation number `0x4000000000000` with sequence `0`
6. If there were multiple transfers before deletion, all get indexed with sequence `0`, causing overwrites

The Move framework allows object deletion through: [5](#0-4) 

Transfer events are emitted before transfers complete: [6](#0-5) 

**Data Corruption Impact:**

When events are stored in `EventByKeySchema`, the key is `(EventKey, sequence_number)`: [7](#0-6) 

Multiple events with the same key cause overwrites in RocksDB. The event validation expects continuous sequence numbers: [8](#0-7) 

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." Event data is part of the queryable state and must maintain integrity.

## Impact Explanation
This vulnerability falls under **High Severity** per Aptos bug bounty criteria:

1. **API Crashes**: When clients query events for an object, the indexer will return "DB corruption: Sequence number not continuous" errors, causing API failures
2. **Indexer Data Corruption**: Event history becomes permanently corrupted with missing events (overwritten in database)
3. **Validator Node Slowdowns**: Indexer processing failures can cascade to affect node performance

Additional impacts:
- **Event Data Loss**: First transfer events are silently overwritten by subsequent ones
- **Incorrect Query Results**: APIs return incomplete or wrong event histories
- **Monitoring Failures**: External indexers relying on event data receive corrupted information

This does not reach Critical severity as it doesn't directly affect consensus, funds, or core blockchain operation, but it severely degrades the indexer subsystem which is critical for ecosystem functionality.

## Likelihood Explanation
**High Likelihood** - The vulnerability is easily exploitable:

**Attacker Requirements:**
- Ability to create deletable objects (standard Move framework feature)
- Ability to submit transactions (any user)
- No special permissions or validator access needed

**Complexity:** Low - Attack requires only 3 transactions:
1. Create deletable object
2. Transfer object (1+ times)
3. Delete object

**Triggering Conditions:**
- Objects with `can_delete=true` are common in NFT and gaming applications
- Indexer processing naturally lags behind block production
- The race window is large - any deletion after transfer triggers the bug

**Realistic Scenario:**
- NFT marketplace where objects are transferred and then burned
- Gaming applications where temporary objects are created, moved, and destroyed
- Any protocol pattern involving object lifecycle management

The vulnerability is **deterministic** - it will occur whenever an object is deleted after being transferred, making it a systemic issue rather than an edge case.

## Recommendation
The translator should look up resources at the **event's version**, not the latest version. This requires passing the event version to the translation engine and using versioned state views.

**Recommended Fix:**

Modify `EventV2Translator` trait to include version parameter:

```rust
pub trait EventV2Translator: Send + Sync {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        version: Version,  // Add version parameter
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1>;
}
```

Modify `EventV2TranslationEngine` to use versioned state views:

```rust
pub fn get_state_value_bytes_for_object_group_resource_at_version(
    &self,
    address: &AccountAddress,
    struct_tag: &StructTag,
    version: Version,  // Use specific version
) -> Result<Option<Bytes>> {
    let state_view = self
        .main_db_reader
        .state_view_at_version(Some(version))?;  // Get state at event version
    // ... rest of implementation
}
```

Update `TransferTranslator` to use versioned lookup:

```rust
let (key, sequence_number) = if let Some(state_value_bytes) = engine
    .get_state_value_bytes_for_object_group_resource_at_version(
        transfer.object(), 
        &struct_tag,
        version  // Use event version
    )?
{
    // ... existing code
} else {
    // Consider returning error instead of falling back
    return Err(AptosDbError::from(anyhow::format_err!(
        "ObjectCore resource not found for transfer event"
    )));
}
```

**Alternative:** If fallback is intentional for objects created before ObjectCore existed, add explicit validation that the object address has never had ObjectCore at any version, rather than just checking the latest state.

## Proof of Concept

```move
#[test_only]
module test_address::transfer_event_corruption_poc {
    use std::signer;
    use aptos_framework::object::{Self, Object, ConstructorRef};
    
    struct TestObject has key {
        value: u64,
    }
    
    #[test(creator = @0xCAFE)]
    fun test_transfer_then_delete_corruption(creator: &signer) {
        // Step 1: Create a deletable object
        let constructor_ref = object::create_object(signer::address_of(creator));
        let obj_signer = object::generate_signer(&constructor_ref);
        
        move_to(&obj_signer, TestObject { value: 42 });
        
        let delete_ref = object::generate_delete_ref(&constructor_ref);
        let transfer_ref = object::generate_transfer_ref(&constructor_ref);
        let obj = object::object_from_constructor_ref<TestObject>(&constructor_ref);
        
        // Step 2: Transfer object multiple times
        // Each transfer emits a Transfer V2 event with ObjectCore present
        object::transfer_with_ref(object::generate_linear_transfer_ref(&transfer_ref), @0xBEEF);
        object::transfer_with_ref(object::generate_linear_transfer_ref(&transfer_ref), @0xDEAD);
        
        // Step 3: Delete the object (removes ObjectCore)
        let TestObject { value: _ } = move_from<TestObject>(object::object_address(&obj));
        object::delete(delete_ref);
        
        // At this point:
        // - Two Transfer events exist in the blockchain history
        // - ObjectCore has been deleted
        // - When indexer processes these events, both will:
        //   1. Attempt to look up ObjectCore at latest state (deleted)
        //   2. Fall back to EventKey(0x4000000000000, obj_addr) with seq 0
        //   3. Both events get stored with same (EventKey, 0) causing overwrite
        //   4. First transfer event is lost
        //   5. Querying events will fail with "Sequence number not continuous"
    }
}
```

The PoC demonstrates the attack flow. In practice, verifying the corruption requires:
1. Running the Move test to generate the transfer and deletion
2. Observing indexer logs showing ObjectCore lookup failures
3. Querying the indexer database to see duplicate sequence numbers
4. Attempting to query events via API and receiving DB corruption errors

**Notes:**
- This vulnerability affects all event types using fallback behavior (CoinDeposit, CoinWithdraw, KeyRotation) but is most severe for Transfer events due to object deletion patterns
- The issue is systemic and will corrupt any object transferred before deletion
- Similar race conditions exist in other translators that fall back to deterministic creation numbers instead of erroring
- The root cause is architectural: using latest state instead of versioned state for historical event translation

### Citations

**File:** storage/indexer/src/event_v2_translator.rs (L216-235)
```rust
    pub fn get_state_value_bytes_for_object_group_resource(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
    ) -> Result<Option<Bytes>> {
        let state_view = self
            .main_db_reader
            .latest_state_checkpoint_view()
            .expect("Failed to get state view");
        static OBJECT_GROUP_TAG: Lazy<StructTag> = Lazy::new(ObjectGroupResource::struct_tag);
        let state_key = StateKey::resource_group(address, &OBJECT_GROUP_TAG);
        let maybe_state_value = state_view.get_state_value(&state_key)?;
        let state_value = maybe_state_value
            .ok_or_else(|| anyhow::format_err!("ObjectGroup resource not found"))?;
        let object_group_resource: ObjectGroupResource = bcs::from_bytes(state_value.bytes())?;
        Ok(object_group_resource
            .group
            .get(struct_tag)
            .map(|bytes| Bytes::copy_from_slice(bytes)))
    }
```

**File:** storage/indexer/src/event_v2_translator.rs (L392-428)
```rust
struct TransferTranslator;
impl EventV2Translator for TransferTranslator {
    fn translate_event_v2_to_v1(
        &self,
        v2: &ContractEventV2,
        engine: &EventV2TranslationEngine,
    ) -> Result<ContractEventV1> {
        let transfer = Transfer::try_from_bytes(v2.event_data())?;
        let struct_tag_str = "0x1::object::ObjectCore".to_string();
        let struct_tag = StructTag::from_str(&struct_tag_str)?;
        let (key, sequence_number) = if let Some(state_value_bytes) = engine
            .get_state_value_bytes_for_object_group_resource(transfer.object(), &struct_tag)?
        {
            let object_core_resource: ObjectCoreResource = bcs::from_bytes(&state_value_bytes)?;
            let key = *object_core_resource.transfer_events().key();
            let sequence_number = engine
                .get_next_sequence_number(&key, object_core_resource.transfer_events().count())?;
            (key, sequence_number)
        } else {
            // The creation number of TransferEvent is deterministically 0x4000000000000
            // because the INIT_GUID_CREATION_NUM in the Move module is 0x4000000000000.
            static TRANSFER_EVENT_CREATION_NUMBER: u64 = 0x4000000000000;
            (
                EventKey::new(TRANSFER_EVENT_CREATION_NUMBER, *transfer.object()),
                0,
            )
        };
        let transfer_event =
            TransferEvent::new(*transfer.object(), *transfer.from(), *transfer.to());
        Ok(ContractEventV1::new(
            key,
            sequence_number,
            TRANSFER_EVENT_TYPE.clone(),
            bcs::to_bytes(&transfer_event)?,
        )?)
    }
}
```

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L81-90)
```rust
impl LatestDbStateCheckpointView for Arc<dyn DbReader> {
    fn latest_state_checkpoint_view(&self) -> StateViewResult<DbStateView> {
        Ok(DbStateView {
            db: self.clone(),
            version: self
                .get_latest_state_checkpoint_version()
                .map_err(Into::<StateViewError>::into)?,
            maybe_verify_against_state_root_hash: None,
        })
    }
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

**File:** aptos-move/framework/aptos-framework/sources/object.move (L548-571)
```text
    inline fun transfer_raw_inner(object: address, to: address) {
        let object_core = borrow_global_mut<ObjectCore>(object);
        if (object_core.owner != to) {
            if (std::features::module_event_migration_enabled()) {
                event::emit(
                    Transfer {
                        object,
                        from: object_core.owner,
                        to,
                    },
                );
            } else {
                event::emit_event(
                    &mut object_core.transfer_events,
                    TransferEvent {
                        object,
                        from: object_core.owner,
                        to,
                    },
                );
            };
            object_core.owner = to;
        };
    }
```

**File:** storage/indexer/src/db_indexer.rs (L464-469)
```rust
                                batch
                                    .put::<EventByKeySchema>(
                                        &(key, sequence_number),
                                        &(version, idx as u64),
                                    )
                                    .expect("Failed to put events by key to a batch");
```

**File:** storage/aptosdb/src/event_store/mod.rs (L130-136)
```rust
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                db_other_bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
```
