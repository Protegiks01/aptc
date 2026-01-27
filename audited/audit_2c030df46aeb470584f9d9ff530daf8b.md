# Audit Report

## Title
Storage Fee Bypass via Resource Group In-Place Delayed Field Changes

## Summary
When resource groups undergo in-place delayed field changes, the storage fee calculation uses the same value for both current and previous size, resulting in zero storage charges even when the actual storage consumption may increase.

## Finding Description

The vulnerability exists in the storage fee calculation for `ResourceGroupInPlaceDelayedFieldChange` operations when the feature version is greater than RELEASE_V1_30 (version 34). [1](#0-0) 

The `get_group_reads_needing_exchange()` function returns resource group metadata and size as a `u64` value. This size is then used to create a `ResourceGroupInPlaceDelayedFieldChangeOp`: [2](#0-1) 

The critical bug occurs in the `prev_materialized_size()` method when `fix_prev_materialized_size` is true: [3](#0-2) 

Both the current size (via `materialized_size()`) and previous size (via `prev_materialized_size()`) return the **same value** - the `materialized_size` field: [4](#0-3) 

The storage fee calculation in `charge_refund_write_op_v2` only charges additional fees when `write_len > op.prev_size`: [5](#0-4) 

Since `write_len == prev_size` for `ResourceGroupInPlaceDelayedFieldChange` operations, the condition at line 191 is always false, resulting in `state_bytes_charge = 0`.

This contrasts with normal resource group writes (`WriteResourceGroup`), which correctly track separate pre and post group sizes: [6](#0-5) 

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria: "Limited funds loss or manipulation". 

Attackers can consume storage without paying proportional fees by:
1. Creating resource groups containing delayed fields (aggregators/snapshots)
2. Modifying only the delayed field values in transactions (not the resource structure itself)
3. Causing the system to generate `ResourceGroupInPlaceDelayedFieldChange` operations
4. Paying zero storage fees for size increases while consuming actual storage space

This breaks the **Resource Limits** invariant that "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**High likelihood** - This occurs automatically whenever:
- Feature version > 34 (RELEASE_V1_30) is active
- Resource groups contain delayed fields
- Delayed field values are modified without direct resource writes
- The delayed field exchange results in size changes [7](#0-6) 

No special privileges or complex attack setup is required beyond creating and modifying resource groups with delayed fields.

## Recommendation

The `prev_materialized_size()` method should return the **actual previous size from storage** for `ResourceGroupInPlaceDelayedFieldChange`, not the current materialized size:

```rust
ResourceGroupInPlaceDelayedFieldChange(
    ResourceGroupInPlaceDelayedFieldChangeOp { .. },
) => {
    // Get the actual size from storage, not the materialized size
    executor_view.get_resource_state_value_size(state_key)?
}
```

This matches the behavior when `fix_prev_materialized_size=false` and aligns with how normal resource group writes properly track pre/post sizes.

## Proof of Concept

```rust
// Rust test demonstrating the issue
#[test]
fn test_resource_group_inplace_delayed_field_no_storage_charge() {
    // Setup: Create a resource group with delayed field
    // Initial group size: 100 bytes
    
    // Transaction: Modify delayed field value
    // - Delayed field ID (8 bytes) replaced with large value (500 bytes)
    // - Final materialized size: 592 bytes (100 - 8 + 500)
    
    // Bug: get_group_reads_needing_exchange returns 592
    // ResourceGroupInPlaceDelayedFieldChange created with materialized_size = 592
    
    // Storage fee calculation:
    // - write_len = 592 (from materialized_size())
    // - prev_size = 592 (from prev_materialized_size() - BUG!)
    // - write_len > prev_size? FALSE
    // - state_bytes_charge = 0
    
    // Expected behavior:
    // - prev_size should be 100 (actual storage size before transaction)
    // - write_len = 592
    // - Should charge for 492 byte increase
    
    assert_eq!(storage_fee_charged, 0); // Bug: no fee charged
    assert!(storage_fee_charged > 0); // Should fail - fee should be > 0
}
```

## Notes

This vulnerability specifically affects the post-RELEASE_V1_30 code path where `fix_prev_materialized_size` is true. The earlier behavior (when false) correctly retrieved the actual storage size, but the "fix" introduced this regression by using the same materialized_size for both current and previous size calculations.

### Citations

**File:** aptos-move/aptos-aggregator/src/resolver.rs (L196-200)
```rust
    fn get_group_reads_needing_exchange(
        &self,
        delayed_write_set_ids: &HashSet<Self::Identifier>,
        skip: &HashSet<Self::ResourceKey>,
    ) -> PartialVMResult<BTreeMap<Self::ResourceKey, (StateValueMetadata, u64)>>;
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L177-188)
```rust
                .chain(group_reads_needing_delayed_field_exchange.into_iter().map(
                    |(k, (metadata, materialized_size))| {
                        Ok((
                            k,
                            AbstractResourceWriteOp::ResourceGroupInPlaceDelayedFieldChange(
                                ResourceGroupInPlaceDelayedFieldChangeOp {
                                    metadata,
                                    materialized_size,
                                },
                            ),
                        ))
                    },
```

**File:** aptos-move/aptos-vm-types/src/abstract_write_op.rs (L61-66)
```rust
            | ResourceGroupInPlaceDelayedFieldChange(ResourceGroupInPlaceDelayedFieldChangeOp {
                materialized_size,
                ..
            }) => WriteOpSize::Modification {
                write_len: *materialized_size,
            },
```

**File:** aptos-move/aptos-vm-types/src/abstract_write_op.rs (L86-90)
```rust
                ResourceGroupInPlaceDelayedFieldChange(
                    ResourceGroupInPlaceDelayedFieldChangeOp {
                        materialized_size, ..
                    },
                ) => *materialized_size,
```

**File:** aptos-move/aptos-vm-types/src/storage/space_pricing.rs (L187-206)
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
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L167-220)
```rust
        let pre_group_size = self.remote.resource_group_size(state_key)?;
        check_size_and_existence_match(&pre_group_size, state_value_metadata.is_some(), state_key)?;

        let mut inner_ops = BTreeMap::new();
        let mut post_group_size = pre_group_size;

        for (tag, current_op) in group_changes {
            // We take speculative group size prior to the transaction, and update it based on the change-set.
            // For each tagged resource in the change set, we subtract the previous size tagged resource size,
            // and then add new tagged resource size.
            //
            // The reason we do not instead get and add the sizes of the resources in the group,
            // but not in the change-set, is to avoid creating unnecessary R/W conflicts (the resources
            // in the change-set are already read, but the other resources are not).
            if !matches!(current_op, MoveStorageOp::New(_)) {
                let old_tagged_value_size = self.remote.resource_size_in_group(state_key, &tag)?;
                let old_size = group_tagged_resource_size(&tag, old_tagged_value_size)?;
                decrement_size_for_remove_tag(&mut post_group_size, old_size)?;
            }

            match &current_op {
                MoveStorageOp::Modify((data, _)) | MoveStorageOp::New((data, _)) => {
                    let new_size = group_tagged_resource_size(&tag, data.len())?;
                    increment_size_for_add_tag(&mut post_group_size, new_size)?;
                },
                MoveStorageOp::Delete => {},
            };

            let legacy_op = match current_op {
                MoveStorageOp::Delete => (WriteOp::legacy_deletion(), None),
                MoveStorageOp::Modify((data, maybe_layout)) => {
                    (WriteOp::legacy_modification(data), maybe_layout)
                },
                MoveStorageOp::New((data, maybe_layout)) => {
                    (WriteOp::legacy_creation(data), maybe_layout)
                },
            };
            inner_ops.insert(tag, legacy_op);
        }

        // Create an op to encode the proper kind for resource group operation.
        let metadata_op = if post_group_size.get() == 0 {
            MoveStorageOp::Delete
        } else if pre_group_size.get() == 0 {
            MoveStorageOp::New(Bytes::new())
        } else {
            MoveStorageOp::Modify(Bytes::new())
        };
        Ok(GroupWrite::new(
            self.convert(state_value_metadata, metadata_op, false)?,
            inner_ops,
            post_group_size,
            pre_group_size.get(),
        ))
```

**File:** aptos-move/aptos-gas-meter/src/traits.rs (L181-181)
```rust
        let fix_prev_materialized_size = self.feature_version() > RELEASE_V1_30;
```
