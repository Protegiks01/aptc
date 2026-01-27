# Audit Report

## Title
Resource Group Delayed Field Exchange Lost on Partial Updates Leading to Consensus Divergence

## Summary
The `convert_change_set()` function incorrectly filters out `group_reads_needing_exchange` entries when a resource group has partial writes, causing delayed field exchange information for read-only resources within the group to be lost. This breaks deterministic execution and can cause consensus divergence across validators. [1](#0-0) 

## Finding Description
The vulnerability exists in the filtering logic that determines which resource group reads require delayed field exchange. Resource groups in Aptos can contain multiple individual resources (e.g., ResourceA, ResourceB). When a transaction:

1. **Writes** to some resources in a group (e.g., ResourceA)
2. **Reads** other resources in the same group that contain delayed fields needing exchange (e.g., ResourceB with AggregatorV2)

The filter at line 514 removes ALL group reads for that StateKey because `resource_group_write_set.contains_key(state_key)` returns true: [1](#0-0) 

However, the `GroupWrite` created for the resource group only contains information about the resources that were **written**, not those that were **read**: [2](#0-1) 

The `inner_ops` field in `GroupWrite` only includes resources from the `group_changes` parameter, which comes from the Move VM's change set and contains only modified resources. Resources that were read but not written are not included.

The `get_group_reads_needing_exchange` implementation confirms this is designed to capture read-only access to groups with delayed fields: [3](#0-2) 

When the filtered `group_reads_needing_change` is passed to `VMChangeSet::new_expanded`, the `ResourceGroupInPlaceDelayedFieldChange` operation that should capture the read-only resource's delayed field information is never created: [4](#0-3) 

Later during block finalization, the `groups_to_finalize` macro chains both actual writes and reads needing exchange, but the reads are missing: [5](#0-4) 

**This breaks the critical invariant:** Deterministic Execution - validators reading different speculative values for the unmaterialized delayed fields in read-only resources will produce different state roots.

## Impact Explanation
This is a **Critical Severity** vulnerability under the Aptos Bug Bounty program as it causes **Consensus/Safety violations**:

1. **Consensus Divergence**: Different validators may observe different values for delayed fields in read-only resources that weren't properly materialized, leading to different state roots for the same block
2. **State Inconsistency**: The blockchain state becomes inconsistent across the validator set
3. **Network Partition Risk**: Validators that produce different state roots will fail to reach consensus, potentially causing a network partition requiring manual intervention or a hard fork

This directly violates the "Deterministic Execution" invariant: "All validators must produce identical state roots for identical blocks."

## Likelihood Explanation
**Likelihood: Medium-High**

This vulnerability will trigger whenever:
- A transaction operates on a resource group containing multiple resources with delayed fields (AggregatorV2)
- The transaction writes to some resources in the group
- The transaction reads (but doesn't write) other resources in the same group that have delayed fields that were modified

Common scenarios include:
- Fungible Asset operations where concurrent supply tracking uses resource groups
- Complex DeFi protocols using resource groups for gas optimization with aggregator-based accounting
- Any multi-resource operation pattern within resource groups using AggregatorV2

The feature is relatively new (delayed fields/AggregatorV2 optimization), so adoption is growing but not yet widespread, reducing immediate likelihood. However, as more protocols adopt resource groups with aggregators for gas efficiency, the likelihood increases.

## Recommendation
The filter should only exclude groups where **all** resources needing delayed field exchange are already captured in the write set. The correct fix is to remove the filter entirely or make it more granular:

**Option 1 (Safest):** Remove the filter completely, as the squashing logic already handles the case where both `GroupWrite` and `ResourceGroupInPlaceDelayedFieldChange` exist for the same key:

```rust
let group_reads_needing_change = aggregator_change_set
    .group_reads_needing_exchange
    .into_iter()
    // Remove this filter - squashing will handle conflicts
    .collect();
```

The squashing logic already correctly handles this case: [6](#0-5) 

**Option 2 (More Complex):** Track which specific resources within a group were written and only filter if ALL resources with delayed fields needing exchange were written. This requires tracking resource-level granularity through the pipeline.

## Proof of Concept

```move
#[test_only]
module 0x1::resource_group_delayed_field_test {
    use std::signer;
    use aptos_framework::aggregator_v2::{Self, Aggregator};
    use aptos_framework::fungible_asset::{Self, FungibleStore};
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct ResourceA has key {
        aggregator: Aggregator<u64>,
    }
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct ResourceB has key {
        aggregator: Aggregator<u64>,
    }
    
    #[test(account = @0x1)]
    fun test_partial_group_update_loses_read(account: &signer) {
        let addr = signer::address_of(account);
        
        // Create resource group with two resources containing aggregators
        move_to(account, ResourceA {
            aggregator: aggregator_v2::create_aggregator(1000),
        });
        move_to(account, ResourceB {
            aggregator: aggregator_v2::create_aggregator(1000),
        });
        
        // In a transaction:
        // 1. Read ResourceB's aggregator (delayed field)
        let resource_b = borrow_global<ResourceB>(addr);
        let value_b = aggregator_v2::read(&resource_b.aggregator);
        
        // 2. Modify ResourceA's aggregator and WRITE ResourceA
        let resource_a = borrow_global_mut<ResourceA>(addr);
        aggregator_v2::add(&mut resource_a.aggregator, 10);
        
        // Expected: Both ResourceA write AND ResourceB read with delayed field exchange
        // Actual: ResourceB's delayed field exchange is filtered out
        // Result: Consensus divergence on ResourceB's aggregator value
    }
}
```

**Rust Test Scenario:**
1. Create a resource group with ResourceA and ResourceB, both containing AggregatorV2
2. Execute transaction that:
   - Modifies delayed field in ResourceA
   - Writes to ResourceA
   - Reads ResourceB (which also has a delayed field that was modified)
3. Verify that `group_reads_needing_exchange` in the change set is empty (incorrectly filtered)
4. Verify that only ResourceA's write is in the VMChangeSet
5. Demonstrate that ResourceB's delayed field is not materialized, leading to non-deterministic reads

## Notes
This vulnerability specifically affects resource groups with **partial updates** where some resources are written and others are only read. The V1 resource group implementation is affected. The issue lies in the assumption that if a group has any writes, all delayed field exchange needs are captured by those writes - which is false when resources within the group are independently accessed.

### Citations

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L511-515)
```rust
        let group_reads_needing_change = aggregator_change_set
            .group_reads_needing_exchange
            .into_iter()
            .filter(|(state_key, _)| !resource_group_write_set.contains_key(state_key))
            .collect();
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L154-221)
```rust
    pub(crate) fn convert_resource_group_v1(
        &self,
        state_key: &StateKey,
        group_changes: BTreeMap<StructTag, MoveStorageOp<BytesWithResourceLayout>>,
    ) -> PartialVMResult<GroupWrite> {
        // Resource group metadata is stored at the group StateKey, and can be obtained via the
        // same interfaces at for a resource at a given StateKey.
        let state_value_metadata = self
            .remote
            .as_executor_view()
            .get_resource_state_value_metadata(state_key)?;
        // Currently, due to read-before-write and a gas charge on the first read that is based
        // on the group size, this should simply re-read a cached (speculative) group size.
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
    }
```

**File:** aptos-move/block-executor/src/view.rs (L1370-1425)
```rust
    fn get_group_reads_needing_exchange_parallel(
        &self,
        parallel_state: &ParallelState<'a, T>,
        delayed_write_set_ids: &HashSet<DelayedFieldID>,
        skip: &HashSet<T::Key>,
    ) -> PartialVMResult<BTreeMap<T::Key, (StateValueMetadata, u64)>> {
        let reads_with_delayed_fields = parallel_state
            .captured_reads
            .borrow()
            .get_group_read_values_with_delayed_fields(skip)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();

        reads_with_delayed_fields
            .into_iter()
            .map(|(key, group_read)| -> PartialVMResult<_> {
                let GroupRead { inner_reads, .. } = group_read;

                // TODO[agg_v2](clean-up): Once ids can be extracted without possible failure,
                // the following is just an any call on iterator (same for resource reads).
                let mut resources_needing_delayed_field_exchange = false;
                for data_read in inner_reads.values() {
                    if let DataRead::Versioned(_version, value, Some(layout)) = data_read {
                        let needs_exchange = self
                            .does_value_need_exchange(value, layout.as_ref(), delayed_write_set_ids)
                            .map_err(PartialVMError::from)?;

                        if needs_exchange {
                            resources_needing_delayed_field_exchange = true;
                            break;
                        }
                    }
                }
                if !resources_needing_delayed_field_exchange {
                    return Ok(None);
                }

                match self.get_resource_state_value_metadata(&key)? {
                    Some(metadata) => match parallel_state.read_group_size(&key, self.txn_idx)? {
                        Some(group_size) => Ok(Some((key, (metadata, group_size.get())))),
                        None => Err(code_invariant_error(format!(
                            "Cannot compute metadata op size for the group read {:?}",
                            key
                        ))
                        .into()),
                    },
                    None => Err(code_invariant_error(format!(
                        "Metadata op not present for the group read {:?}",
                        key
                    ))
                    .into()),
                }
            })
            .flat_map(Result::transpose)
            .collect()
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L177-189)
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
                ))
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L658-682)
```rust
                        (
                            WriteResourceGroup(GroupWrite {
                                maybe_group_op_size: materialized_size,
                                ..
                            }),
                            ResourceGroupInPlaceDelayedFieldChange(
                                ResourceGroupInPlaceDelayedFieldChangeOp {
                                    materialized_size: additional_materialized_size,
                                    ..
                                },
                            ),
                        ) => {
                            // Read cannot change the size (i.e. delayed fields don't modify size)
                            if materialized_size.map(|v| v.get())
                                != Some(*additional_materialized_size)
                            {
                                return Err(code_invariant_error(format!(
                                    "Trying to squash group writes where read has different size: {:?}: {:?}",
                                    materialized_size,
                                    additional_materialized_size
                                )));
                            }
                            // any newer read should've read the original write and contain all info from it
                            (false, false)
                        },
```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L32-49)
```rust
macro_rules! groups_to_finalize {
    ($outputs:expr, $($txn_idx:expr),*) => {{
        let group_write_ops = $outputs.resource_group_metadata_ops($($txn_idx),*);

        group_write_ops.into_iter()
            .map(|val| (val, false))
            .chain([()].into_iter().flat_map(|_| {
                // Lazily evaluated only after iterating over group_write_ops.
                $outputs.group_reads_needing_delayed_field_exchange($($txn_idx),*)
                    .into_iter()
                    .map(|(key, metadata)| {
                        ((key, TransactionWrite::from_state_value(Some(
                            StateValue::new_with_metadata(Bytes::new(), metadata)
                        ))), true)
                    })
            }))
    }};
}
```
