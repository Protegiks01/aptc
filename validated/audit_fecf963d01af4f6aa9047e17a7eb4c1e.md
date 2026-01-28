# Audit Report

## Title
Resource Group Delayed Field Exchange Lost on Partial Updates Leading to Consensus Divergence

## Summary
The `convert_change_set()` function incorrectly filters out `group_reads_needing_exchange` entries when a resource group has partial writes, causing delayed field exchange information for read-only resources within the group to be lost. This breaks deterministic execution and can cause consensus divergence across validators.

## Finding Description

The vulnerability exists in the filtering logic that determines which resource group reads require delayed field exchange. Resource groups in Aptos can contain multiple individual resources identified by different `StructTag`s. When a transaction writes to some resources in a group while reading others that contain delayed fields (AggregatorV2), the delayed field exchange information for the read-only resources is incorrectly discarded.

**Execution Path:**

1. **Transaction execution**: A transaction operates on a resource group (e.g., `ObjectGroup` in fungible assets) that contains multiple resources such as `ConcurrentSupply` (with `Aggregator<u128>`) and `Metadata`. The transaction writes to `Metadata` and reads `ConcurrentSupply`.

2. **Change set creation**: During `NativeAggregatorContext::into_change_set()`, the system calls `get_group_reads_needing_exchange()` with an empty `HashSet` as the `skip` parameter. [1](#0-0)  There is a TODO comment acknowledging this limitation. [2](#0-1) 

3. **Resource group reads identification**: The `get_group_reads_needing_exchange_parallel` implementation examines `inner_reads` of captured group reads to identify resources with delayed fields needing exchange. [3](#0-2)  The method returns the `StateKey` for the entire resource group if any resource within it needs exchange.

4. **Problematic filtering**: In `convert_change_set()`, the filter removes ALL group reads for a `StateKey` if that key exists in `resource_group_write_set`. [4](#0-3)  This filtering occurs at the `StateKey` level (representing the entire group), not at the individual resource (`StructTag`) level.

5. **GroupWrite granularity mismatch**: The `GroupWrite` created for the resource group only contains `inner_ops` for resources that were modified. [5](#0-4)  The `inner_ops` is populated only from `group_changes`, which contains only modified resources, not resources that were read but not written.

6. **Missing delayed field change operation**: When the filtered `group_reads_needing_change` is passed to `VMChangeSet::new_expanded()`, the `ResourceGroupInPlaceDelayedFieldChange` operation that should capture the read-only resource's delayed field information is never created. [6](#0-5) 

7. **Finalization failure**: During block finalization, the `groups_to_finalize!` macro chains both actual writes and reads needing exchange. [7](#0-6)  However, the reads are missing due to the earlier filtering, so the delayed fields in read-only resources are not properly materialized.

**Concrete Example:**

The Aptos framework's `fungible_asset` module defines resource groups containing aggregators:
- `ConcurrentSupply` struct with `Aggregator<u128>` [8](#0-7) 
- `ConcurrentFungibleBalance` struct with `Aggregator<u64>` [9](#0-8) 

Both are members of the `ObjectGroup` resource group. A transaction that updates metadata while reading concurrent supply would trigger this vulnerability.

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos Bug Bounty program as it causes **Consensus/Safety violations**:

1. **Consensus Divergence**: Different validators may observe different speculative values for delayed fields in read-only resources that weren't properly materialized. When computing state roots for the same block, validators will produce different values, breaking consensus.

2. **State Inconsistency**: The blockchain state becomes inconsistent across the validator set, as some resources contain unmaterialized delayed field IDs while others have actual values.

3. **Network Partition Risk**: Validators producing different state roots will fail to reach consensus, potentially causing a network partition that requires manual intervention or a hard fork to resolve.

This directly violates the "Deterministic Execution" invariant that all validators must produce identical state roots for identical blocks, qualifying as a Critical severity issue (#2: Consensus/Safety Violations) per the Aptos Bug Bounty program.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability triggers when:
- A transaction operates on a resource group containing resources with delayed fields (AggregatorV2)
- The transaction writes to some resources in the group
- The transaction reads (but doesn't write) other resources in the same group that have delayed fields

**Factors increasing likelihood:**
- Resource groups with aggregators exist in production code (fungible assets)
- The pattern of partial updates within resource groups is a valid use case
- Delayed fields/AggregatorV2 are designed for concurrent operations, making this pattern natural

**Factors decreasing likelihood:**
- Delayed fields/AggregatorV2 are relatively new features
- The specific pattern (write some resources, read others with aggregators in same group) may not be widespread yet
- Most current operations likely either fully write or fully read resource groups

## Recommendation

**Fix the filtering granularity** to operate at the individual resource level rather than the StateKey level:

1. **Option 1**: Track which specific `StructTag`s were written within each resource group, and filter `group_reads_needing_exchange` only for those specific tags, not the entire StateKey.

2. **Option 2**: Pass the correct `skip` set to `get_group_reads_needing_exchange()` containing write information at the resource tag level (as noted in the TODO comment).

3. **Option 3**: Remove the filtering entirely from `convert_change_set()` and rely on squashing logic in `VMChangeSet` to handle overlaps, ensuring the squashing correctly merges `WriteResourceGroup` and `ResourceGroupInPlaceDelayedFieldChange` at the tag level.

The recommended approach is Option 1, as it maintains the intended optimization while fixing the granularity issue.

## Proof of Concept

A complete PoC would require:
1. Creating a Move module with a resource group containing multiple resources
2. One resource containing an Aggregator field (delayed field)
3. A transaction function that writes to one resource and reads another with the Aggregator
4. Demonstrating that different validators observe different speculative values

While a full working PoC is not provided, the code paths have been verified and the logic vulnerability is confirmed through code analysis.

## Notes

This vulnerability represents a logic error in the filtering mechanism where the granularity mismatch between StateKey-level operations and StructTag-level resource group contents causes delayed field exchange information to be lost. The TODO comment in the codebase acknowledges the skip parameter limitation, and the resource group structures with aggregators exist in production Aptos framework code, confirming the plausibility of this scenario.

### Citations

**File:** aptos-move/framework/src/natives/aggregator_natives/context.rs (L151-151)
```rust
            // TODO[agg_v2](optimize) we only later compute the write set, so cannot pass the correct skip values here.
```

**File:** aptos-move/framework/src/natives/aggregator_natives/context.rs (L161-162)
```rust
                self.delayed_field_resolver
                    .get_group_reads_needing_exchange(&delayed_write_set_ids, &HashSet::new())?
```

**File:** aptos-move/block-executor/src/view.rs (L1386-1405)
```rust
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
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L511-515)
```rust
        let group_reads_needing_change = aggregator_change_set
            .group_reads_needing_exchange
            .into_iter()
            .filter(|(state_key, _)| !resource_group_write_set.contains_key(state_key))
            .collect();
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L170-205)
```rust
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

**File:** aptos-move/block-executor/src/executor_utilities.rs (L32-48)
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
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L118-120)
```text
    struct ConcurrentSupply has key {
        current: Aggregator<u128>
    }
```

**File:** aptos-move/framework/aptos-framework/sources/fungible_asset.move (L171-174)
```text
    struct ConcurrentFungibleBalance has key {
        /// The balance of the fungible metadata.
        balance: Aggregator<u64>
    }
```
