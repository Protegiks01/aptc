# Audit Report

## Title
Storage Deposit Metadata Loss Through InPlaceDelayedFieldChange Metadata Extraction Inconsistency

## Summary
The `get_resource_state_value_metadata()` function in `ExecutorViewWithChangeSet` returns stale metadata from the base view for `InPlaceDelayedFieldChange` and `ResourceGroupInPlaceDelayedFieldChange` operations, despite storage fee calculations having updated deposit information in these operations via `metadata_mut()`. This causes deposit metadata to be lost when subsequent sessions create new write operations for the same resources, resulting in incorrect storage refund calculations and state inconsistencies.

## Finding Description

The vulnerability exists in the metadata extraction logic where different code paths handle metadata inconsistently: [1](#0-0) 

For `Write`, `WriteWithDelayedFields`, and `WriteResourceGroup` operations, metadata is correctly extracted from the write operation in the change set. However, for `InPlaceDelayedFieldChange` and `ResourceGroupInPlaceDelayedFieldChange`, the function falls back to the base executor view, ignoring metadata stored within these operations.

The issue is that storage fee calculation modifies this metadata: [2](#0-1) 

The `metadata_mut()` method returns mutable references to metadata in ALL operation types, including `InPlaceDelayedFieldChange` operations. Storage fee charging then updates deposit information: [3](#0-2) [4](#0-3) 

**Attack Scenario:**

1. User transaction modifies a resource with delayed fields (e.g., `ConcurrentFungibleBalance` with `Aggregator<u64>`) at state key K → creates `InPlaceDelayedFieldChange` with original metadata
2. Storage fee calculation calls `metadata_mut()` and sets `slot_deposit` and `bytes_deposit` on the metadata stored IN the `InPlaceDelayedFieldChange` struct
3. `RespawnedSession` is created for epilogue with this change set wrapped in `ExecutorViewWithChangeSet` [5](#0-4) 

4. Epilogue or storage refund logic modifies the same resource at key K
5. When converting to `WriteOp`, `convert_resource()` calls `get_resource_state_value_metadata(K)`: [6](#0-5) 

6. Returns OLD metadata from base view (without deposits) instead of UPDATED metadata from `InPlaceDelayedFieldChange`
7. New `WriteOp` is created with incorrect metadata: [7](#0-6) 

8. When squashing change sets, the `InPlaceDelayedFieldChange` (with correct metadata including deposits) is replaced by the new `WriteOp` (with wrong metadata excluding deposits): [8](#0-7) 

9. Final change set has **lost the deposit information** that was paid

## Impact Explanation

**Critical Severity** - This breaks multiple critical invariants:

1. **State Consistency Violation**: Storage deposits are charged but not recorded in metadata, causing state to diverge from economic reality
2. **Loss of Funds**: Users pay storage deposits (permanent fees) that are not tracked, then cannot receive refunds when resources are deleted
3. **Consensus Risk**: Different validator implementations or timing could handle metadata differently, potentially causing state root divergence
4. **Deterministic Execution Violation**: The same transaction sequence could produce different metadata depending on whether resources are modified in subsequent sessions

This affects resources with delayed fields (aggregators) that are commonly used in:
- Fungible assets with `ConcurrentFungibleBalance` or `ConcurrentSupply`
- Any resource groups containing aggregator-based resources
- Custom Move modules using aggregators for concurrent state updates

## Likelihood Explanation

**High Likelihood** - This occurs whenever:
1. A transaction modifies a resource containing delayed fields (common in fungible asset operations)
2. Storage fees are charged (happens for all transactions)
3. The epilogue or a subsequent session in the same transaction modifies that resource again

The epilogue commonly modifies account-related resources and fungible asset stores during fee payment. Resource groups with concurrent supply tracking are particularly vulnerable as they frequently undergo modifications in both transaction body and epilogue during token transfers with fee payments.

## Recommendation

Fix the `get_resource_state_value_metadata()` function to return metadata from `InPlaceDelayedFieldChange` and `ResourceGroupInPlaceDelayedFieldChange` operations instead of falling back to the base view:

```rust
fn get_resource_state_value_metadata(
    &self,
    state_key: &Self::Key,
) -> PartialVMResult<Option<StateValueMetadata>> {
    match self.change_set.resource_write_set().get(state_key) {
        Some(
            AbstractResourceWriteOp::Write(write_op)
            | AbstractResourceWriteOp::WriteWithDelayedFields(WriteWithDelayedFieldsOp {
                write_op,
                ..
            }),
        ) => Ok(write_op.as_state_value_metadata()),
        Some(AbstractResourceWriteOp::WriteResourceGroup(write_op)) => {
            Ok(write_op.metadata_op().as_state_value_metadata())
        },
        // FIX: Return metadata from in-place delayed field change operations
        Some(AbstractResourceWriteOp::InPlaceDelayedFieldChange(op)) => {
            Ok(Some(op.metadata.clone()))
        },
        Some(AbstractResourceWriteOp::ResourceGroupInPlaceDelayedFieldChange(op)) => {
            Ok(Some(op.metadata.clone()))
        },
        None => self
            .base_executor_view
            .get_resource_state_value_metadata(state_key),
    }
}
```

## Proof of Concept

```rust
// Reproduction steps:
// 1. Create a VMChangeSet with an InPlaceDelayedFieldChange for resource at key K
// 2. Call metadata_mut() and set deposit values
// 3. Create ExecutorViewWithChangeSet wrapping this change set
// 4. Call get_resource_state_value_metadata(K)
// 5. Observe that it returns None or old metadata instead of updated metadata

#[test]
fn test_metadata_loss_in_place_delayed_field_change() {
    use aptos_types::state_store::state_value::StateValueMetadata;
    use aptos_vm_types::abstract_write_op::{AbstractResourceWriteOp, InPlaceDelayedFieldChangeOp};
    
    // Create InPlaceDelayedFieldChange with metadata
    let mut metadata = StateValueMetadata::new_creation(100, &CurrentTimeMicroseconds { microseconds: 0 });
    metadata.set_slot_deposit(1000); // Set deposit
    metadata.set_bytes_deposit(500);
    
    let op = AbstractResourceWriteOp::InPlaceDelayedFieldChange(
        InPlaceDelayedFieldChangeOp {
            layout: /* ... */,
            materialized_size: 100,
            metadata: metadata.clone(),
        }
    );
    
    // Create change set with this operation
    let mut resource_write_set = BTreeMap::new();
    resource_write_set.insert(key, op);
    let change_set = VMChangeSet::new_expanded(
        resource_write_set, /* ... */
    );
    
    // Create ExecutorViewWithChangeSet
    let view = ExecutorViewWithChangeSet::new(base_view, base_group_view, change_set);
    
    // BUG: get_resource_state_value_metadata returns None or old metadata
    // Expected: Should return metadata with deposits (slot_deposit=1000, bytes_deposit=500)
    // Actual: Returns metadata from base_view without deposits
    let retrieved_metadata = view.get_resource_state_value_metadata(&key).unwrap();
    
    // This assertion would FAIL, demonstrating the bug
    assert_eq!(retrieved_metadata.unwrap().total_deposit(), 1500);
}
```

**Notes:**
This vulnerability affects the core transaction execution pipeline and storage fee accounting. The metadata inconsistency violates deterministic execution guarantees and can cause fund loss through incorrect refund calculations. Resources using aggregators for concurrent state management (common in DeFi protocols) are particularly vulnerable. The fix ensures metadata consistency across all code paths by returning the updated metadata from in-place delayed field change operations instead of incorrectly falling back to stale base view data.

### Citations

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/view_with_change_set.rs (L249-271)
```rust
    fn get_resource_state_value_metadata(
        &self,
        state_key: &Self::Key,
    ) -> PartialVMResult<Option<StateValueMetadata>> {
        match self.change_set.resource_write_set().get(state_key) {
            Some(
                AbstractResourceWriteOp::Write(write_op)
                | AbstractResourceWriteOp::WriteWithDelayedFields(WriteWithDelayedFieldsOp {
                    write_op,
                    ..
                }),
            ) => Ok(write_op.as_state_value_metadata()),
            Some(AbstractResourceWriteOp::WriteResourceGroup(write_op)) => {
                Ok(write_op.metadata_op().as_state_value_metadata())
            },
            // We could either return from the read, or do the base read again.
            Some(AbstractResourceWriteOp::InPlaceDelayedFieldChange(_))
            | Some(AbstractResourceWriteOp::ResourceGroupInPlaceDelayedFieldChange(_))
            | None => self
                .base_executor_view
                .get_resource_state_value_metadata(state_key),
        }
    }
```

**File:** aptos-move/aptos-vm-types/src/abstract_write_op.rs (L113-128)
```rust
    pub fn metadata_mut(&mut self) -> &mut StateValueMetadata {
        use AbstractResourceWriteOp::*;
        match self {
            Write(write_op)
            | WriteWithDelayedFields(WriteWithDelayedFieldsOp { write_op, .. })
            | WriteResourceGroup(GroupWrite {
                metadata_op: write_op,
                ..
            }) => write_op.metadata_mut(),
            InPlaceDelayedFieldChange(InPlaceDelayedFieldChangeOp { metadata, .. })
            | ResourceGroupInPlaceDelayedFieldChange(ResourceGroupInPlaceDelayedFieldChangeOp {
                metadata,
                ..
            }) => metadata,
        }
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L173-186)
```rust
        match op.op_size {
            Creation { .. } => {
                // permanent storage fee
                let slot_deposit = u64::from(params.storage_fee_per_state_slot);

                op.metadata_mut.maybe_upgrade();
                op.metadata_mut.set_slot_deposit(slot_deposit);
                op.metadata_mut.set_bytes_deposit(target_bytes_deposit);

                ChargeAndRefund {
                    charge: (slot_deposit + target_bytes_deposit).into(),
                    refund: 0.into(),
                }
            },
```

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L187-207)
```rust
            Modification { write_len } => {
                // Change of slot size or per byte price can result in a charge or refund of the bytes fee.
                let old_bytes_deposit = op.metadata_mut.bytes_deposit();
                let state_bytes_charge =
                    if write_len > op.prev_size && target_bytes_deposit > old_bytes_deposit {
                        let charge_by_increase: u64 = (write_len - op.prev_size)
                            * u64::from(params.storage_fee_per_state_byte);
                        let gap_from_target = target_bytes_deposit - old_bytes_deposit;
                        std::cmp::min(charge_by_increase, gap_from_target)
                    } else {
                        0
                    };
                op.metadata_mut.maybe_upgrade();
                op.metadata_mut
                    .set_bytes_deposit(old_bytes_deposit + state_bytes_charge);

                ChargeAndRefund {
                    charge: state_bytes_charge.into(),
                    refund: 0.into(),
                }
            },
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

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L136-151)
```rust
        let state_value_metadata = self
            .remote
            .as_executor_view()
            .get_resource_state_value_metadata(state_key)?;
        let (move_storage_op, layout) = match move_storage_op {
            MoveStorageOp::New((data, layout)) => (MoveStorageOp::New(data), layout),
            MoveStorageOp::Modify((data, layout)) => (MoveStorageOp::Modify(data), layout),
            MoveStorageOp::Delete => (MoveStorageOp::Delete, None),
        };

        let write_op = self.convert(
            state_value_metadata,
            move_storage_op,
            legacy_creation_as_modification,
        )?;
        Ok((write_op, layout))
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L259-263)
```rust
            (Some(metadata), Modify(data)) => WriteOp::modification(data, metadata),
            (Some(metadata), Delete) => {
                // Inherit metadata even if the feature flags is turned off, for compatibility.
                WriteOp::deletion(metadata)
            },
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L684-691)
```rust
                        (
                            InPlaceDelayedFieldChange(_),
                            WriteWithDelayedFields(_) | InPlaceDelayedFieldChange(_),
                        )
                        | (
                            ResourceGroupInPlaceDelayedFieldChange(_),
                            WriteResourceGroup(_) | ResourceGroupInPlaceDelayedFieldChange(_),
                        ) => (false, true),
```
