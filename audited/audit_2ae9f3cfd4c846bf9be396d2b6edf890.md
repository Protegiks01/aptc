# Audit Report

## Title
Delayed Field Exchange Bypass in Resource Group Finalization Leading to Consensus Divergence

## Summary
The `map_id_to_values_in_group_writes` function in the block executor incorrectly handles `ValueWithLayout::RawFromStorage` values during resource group finalization, using them directly without performing delayed field identifier-to-value exchange. This causes serialized resource groups to contain raw delayed field identifiers instead of materialized values, breaking deterministic execution and potentially causing consensus failures across validators.

## Finding Description

When resource groups are initialized from storage, their values are wrapped as `ValueWithLayout::RawFromStorage`: [1](#0-0) [2](#0-1) 

The `RawFromStorage` variant represents values read from storage that contain raw delayed field identifiers that have not yet been exchanged (replaced with actual values). The types documentation explicitly states this should never be returned to users before exchange: [3](#0-2) 

During normal read operations, when a layout is known, the system correctly upgrades `RawFromStorage` values to `Exchanged` by calling `patch_base_value`: [4](#0-3) 

However, when resource groups are finalized for commitment, the `map_id_to_values_in_group_writes` function handles three `ValueWithLayout` variants differently: [5](#0-4) 

**The vulnerability is at line 216**: when encountering a `RawFromStorage` value, it extracts the raw value directly without calling `replace_ids_with_values`. In contrast, `Exchanged` values with layouts correctly undergo ID-to-value replacement at lines 218-220.

This means if a resource group contains:
- Resource R1 (read from storage, contains delayed fields, remains as `RawFromStorage`)
- Resource R2 (newly written as `Exchanged`)

And a transaction writes R2 but doesn't modify R1, the finalized group will serialize R1's raw bytes containing delayed field **identifiers** instead of their materialized **values**.

The attack scenario:
1. A resource group exists in storage with a resource containing delayed field references
2. Transaction reads the resource (potentially with non-Value read kind to avoid forced exchange)
3. Transaction modifies a different resource in the same group
4. Group finalization includes the unmodified resource as `RawFromStorage`
5. Serialization embeds raw delayed field IDs instead of values
6. Different validators may resolve these IDs to different values depending on timing
7. State root divergence → consensus failure

## Impact Explanation

**Critical Severity** - This breaks the **Deterministic Execution** invariant (#1 in the requirements). All validators must produce identical state roots for identical blocks. By allowing raw delayed field identifiers to be serialized instead of materialized values, different validators processing the same block at different times may observe different delayed field values, producing different state roots.

This can cause:
- **Consensus Safety Violations**: Validators commit different state roots for the same block, breaking AptosBFT safety guarantees
- **Non-recoverable Network Partition**: If validators split on which state root is correct, a hard fork may be required to resolve
- **State Merkle Tree Corruption**: Inconsistent serialization produces different Merkle tree leaves across validators

According to the Aptos Bug Bounty criteria, this qualifies for **Critical Severity (up to $1,000,000)** as it represents a Consensus/Safety violation.

## Likelihood Explanation

**Moderate to High Likelihood**. The vulnerability requires:
1. Resource groups with delayed field-containing resources (increasingly common with aggregator V2 features)
2. Transactions that read one resource and write another in the same group (common pattern)
3. Timing where the read doesn't trigger full value exchange (possible with metadata-only reads or races)

The attack doesn't require validator privileges - any transaction sender can trigger it. As aggregator V2 adoption increases, delayed fields in resource groups become more prevalent, increasing exposure.

## Recommendation

Add delayed field exchange handling for `RawFromStorage` values in resource group finalization. Modify `map_id_to_values_in_group_writes` to treat `RawFromStorage` the same as `Exchanged` values with layouts:

```rust
let value = match value_with_layout {
    ValueWithLayout::RawFromStorage(value) => {
        // RawFromStorage values MUST be exchanged before serialization
        // Return error to force caller to ensure all values are exchanged
        return Err(code_invariant_error(format!(
            "RawFromStorage value found in finalized group at tag {:?}. \
             All resource group values must be exchanged before finalization.",
            tag
        )));
    },
    ValueWithLayout::Exchanged(value, None) => value,
    ValueWithLayout::Exchanged(value, Some(layout)) => TriompheArc::new(
        replace_ids_with_values(&value, layout.as_ref(), latest_view)?,
    ),
};
```

Alternatively, ensure that all resource group base values are eagerly exchanged when their group is first accessed for writing: [6](#0-5) 

Add validation at `update_tagged_base_value_with_layout` to verify values are only set as `Exchanged`, never `RawFromStorage`.

## Proof of Concept

```rust
// Conceptual PoC demonstrating the vulnerability
// Requires integration test setup with resource groups and delayed fields

#[test]
fn test_raw_from_storage_bypass_in_group_finalization() {
    // Setup: Create resource group with delayed field resource
    let group_key = create_test_group_key();
    let delayed_field_id = DelayedFieldID::new_for_test();
    
    // Resource R1 contains a delayed field reference
    let r1_with_delayed_field = create_resource_with_delayed_field(delayed_field_id);
    
    // Initialize group from storage - wraps as RawFromStorage
    versioned_map.group_data().set_raw_base_values(
        group_key.clone(),
        vec![(tag_r1, r1_with_delayed_field)]
    );
    
    // Transaction reads R1 with Exists kind (doesn't force exchange)
    // Then writes R2 (different resource in same group)
    let txn = create_transaction_that_reads_r1_writes_r2();
    
    // Execute transaction
    executor.execute_transaction(txn);
    
    // Finalize group - R1 is still RawFromStorage
    let (finalized_group, _) = versioned_map.group_data()
        .finalize_group(&group_key, txn_idx);
    
    // map_id_to_values_in_group_writes incorrectly uses RawFromStorage directly
    let materialized = map_id_to_values_in_group_writes(
        vec![(group_key.clone(), metadata_op, finalized_group, group_size)],
        &latest_view
    );
    
    // Serialize - this embeds raw delayed field ID instead of value
    let serialized = serialize_groups(materialized);
    
    // Verification: serialized bytes contain delayed field ID, not value
    // This causes different validators to produce different state roots
    assert!(serialized_contains_raw_id(&serialized, delayed_field_id));
}
```

## Notes

This vulnerability specifically affects resource groups, not individual resources, because:
1. Individual resource finalization uses `fetch_exchanged_data` which validates exchanged format
2. Resource groups use `finalize_group` which returns raw `ValueWithLayout` without validation

The vulnerability is latent and may not manifest until:
- Aggregator V2 features increase delayed field usage in resource groups
- Specific transaction patterns trigger the unexchanged path
- Validator timing differences expose the non-determinism

The fix should enforce that ALL finalized values undergo proper exchange, with no exceptions for `RawFromStorage` variants in the output path.

### Citations

**File:** aptos-move/mvhashmap/src/unsync_map.rs (L128-131)
```rust
        let base_map: HashMap<T, ValueWithLayout<V>> = base_values
            .into_iter()
            .map(|(t, v)| (t, ValueWithLayout::RawFromStorage(TriompheArc::new(v))))
            .collect();
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L176-182)
```rust
            for (tag, value) in base_values.into_iter() {
                superset_tags.insert(tag.clone());
                self.values.set_base_value(
                    (group_key.clone(), tag),
                    ValueWithLayout::RawFromStorage(Arc::new(value)),
                );
            }
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L188-199)
```rust
    pub fn update_tagged_base_value_with_layout(
        &self,
        group_key: K,
        tag: T,
        value: V,
        layout: Option<Arc<MoveTypeLayout>>,
    ) {
        self.values.set_base_value(
            (group_key, tag),
            ValueWithLayout::Exchanged(Arc::new(value), layout.clone()),
        );
    }
```

**File:** aptos-move/mvhashmap/src/types.rs (L131-139)
```rust
pub enum ValueWithLayout<V> {
    // When we read from storage, but don't have access to layout, we can only store the raw value.
    // This should never be returned to the user, before exchange is performed.
    RawFromStorage(Arc<V>),
    // We've used the optional layout, and applied exchange to the storage value.
    // The type layout is Some if there is a delayed field in the resource.
    // The type layout is None if there is no delayed field in the resource.
    Exchanged(Arc<V>, Option<Arc<MoveTypeLayout>>),
}
```

**File:** aptos-move/block-executor/src/view.rs (L776-802)
```rust
                Ok((version, value_with_layout)) => {
                    // If we have a known layout, upgrade RawFromStorage value to Exchanged.
                    if let UnknownOrLayout::Known(layout) = layout {
                        if let ValueWithLayout::RawFromStorage(v) = value_with_layout {
                            assert_eq!(version, Err(StorageVersion),
                            "Fetched resource has unknown layout but the version is not Err(StorageVersion)"
                            );
                            match patch_base_value(v.as_ref(), layout) {
                                Ok(patched_value) => {
                                    self.versioned_map
                                        .group_data()
                                        .update_tagged_base_value_with_layout(
                                            group_key.clone(),
                                            resource_tag.clone(),
                                            patched_value,
                                            layout.cloned().map(TriompheArc::new),
                                        );
                                    // Re-fetch in case a concurrent change went through.
                                    continue;
                                },
                                Err(e) => {
                                    error!("Couldn't patch value from versioned group map: {}", e);
                                    self.captured_reads.borrow_mut().mark_incorrect_use();
                                    return Err(e);
                                },
                            }
                        }
```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L214-222)
```rust
        for (tag, value_with_layout) in resource_vec.into_iter() {
            let value = match value_with_layout {
                ValueWithLayout::RawFromStorage(value) => value,
                ValueWithLayout::Exchanged(value, None) => value,
                ValueWithLayout::Exchanged(value, Some(layout)) => TriompheArc::new(
                    replace_ids_with_values(&value, layout.as_ref(), latest_view)?,
                ),
            };
            patched_resource_vec.push((tag, value));
```
