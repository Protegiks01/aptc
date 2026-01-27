# Audit Report

## Title
Unmetered O(N) Resource Group Traversal During Delayed Field Materialization Enables Validator DoS

## Summary
The delayed field materialization process traverses ALL members of a resource group without gas metering, allowing attackers to create resource groups with thousands of members and trigger O(N) CPU exhaustion on validators during transaction finalization.

## Finding Description

The comment at line 249 in `abstract_write_op.rs` acknowledges a design issue: "we need to traverse and materialize all tags anyways". This traversal occurs during the post-execution materialization phase, which is NOT gas-metered. [1](#0-0) 

The critical code path is:

1. After transaction execution completes, `materialize_txn_commit` is called: [2](#0-1) 

2. This calls `finalize_group` which retrieves ALL tags in the group (not just accessed tags): [3](#0-2) 

Note line 531-535: `superset_tags` contains ALL tags ever written to the group, then line 537-553 iterates through every single one.

3. Then `map_id_to_values_in_group_writes` performs expensive deserialization/reserialization for each member with a layout: [4](#0-3) 

Line 214 iterates through `resource_vec` (all members), and line 219 calls `replace_ids_with_values` for each member with a layout - an expensive operation involving deserialization and reserialization.

**Attack Scenario:**

1. Attacker publishes a Move module with hundreds/thousands of struct types marked with `#[resource_group_member(group = aptos_framework::object::ObjectGroup)]`
2. Attacker creates transactions to add all members to a single object's resource group (pays gas once per member)
3. Attacker or any subsequent user reads a single member containing a delayed field from this group
4. The system triggers `finalize_group` which iterates through ALL N members
5. For each member with a layout, expensive deserialization/reserialization occurs
6. This O(N) work happens WITHOUT gas metering, on EVERY validator node

**Key Evidence:**

The production verifier config has NO limit on struct definitions: [5](#0-4) 

Line 168: `max_struct_definitions: None` - no enforced limit.

## Impact Explanation

This vulnerability enables **validator node slowdowns**, which qualifies as **High Severity** (up to $50,000) per the Aptos Bug Bounty program.

The impact:
- O(N) CPU work per transaction reading from large resource groups
- Affects ALL validator nodes (consensus-critical path)
- Not bounded by gas metering (breaks invariant #9: Resource Limits)
- Can be amplified by multiple transactions or multiple large groups
- With N=1000+ members, deserialization/reserialization costs become significant

This breaks the critical invariant: "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**High likelihood:**
- Attacker only needs to publish one module with many struct types (one-time cost)
- Adding members to resource group is standard operation (pays normal gas)
- Any subsequent read of the group triggers the attack
- ObjectGroup is widely used in Aptos (tokens, fungible assets)
- No technical barriers to exploitation

## Recommendation

**Option 1: Limit struct definitions per module**

Set `max_struct_definitions` in production config:
```rust
max_struct_definitions: Some(200),  // Reasonable limit
```

**Option 2: Gas meter the materialization phase**

Track CPU time during materialization and charge gas retroactively or abort transactions exceeding limits.

**Option 3: Optimize finalize_group to only traverse accessed tags**

Modify `finalize_group` to only materialize tags that were actually read/written during transaction execution, rather than all `superset_tags`.

**Recommended fix:** Implement Option 1 immediately (simple), then Option 3 for long-term efficiency.

## Proof of Concept

```move
// Module with many resource group members
module attacker::dos {
    use aptos_framework::object;
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct Member0 has key { value: u64 }
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct Member1 has key { value: u64 }
    
    // ... repeat for Member2 through Member999 ...
    
    #[resource_group_member(group = aptos_framework::object::ObjectGroup)]
    struct Member999 has key { value: u64 }
    
    // Add all members to an object
    public entry fun create_large_group(caller: &signer) {
        let obj = object::create_object(signer::address_of(caller));
        move_to(&obj, Member0 { value: 0 });
        move_to(&obj, Member1 { value: 0 });
        // ... repeat for all 1000 members
        move_to(&obj, Member999 { value: 0 });
    }
    
    // Any subsequent read triggers O(1000) traversal
    public entry fun read_one(obj_addr: address) acquires Member0 {
        let _ = borrow_global<Member0>(obj_addr);
    }
}
```

**Notes:**
- First call to `create_large_group` pays gas for 1000 move_to operations (expensive but one-time)
- Every call to `read_one` triggers O(1000) unmeasured CPU work on all validators
- Attack can be amplified by creating multiple large groups or having multiple users read them

### Citations

**File:** aptos-move/aptos-vm-types/src/abstract_write_op.rs (L247-256)
```rust
/// Actual information of which individual tag has delayed fields was read,
/// or what those fields are unnecessary in the current implementation.
/// That is the case, because we need to traverse and materialize all tags anyways.
///
/// If future implementation needs those - they can be added.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ResourceGroupInPlaceDelayedFieldChangeOp {
    pub materialized_size: u64,
    pub metadata: StateValueMetadata,
}
```

**File:** aptos-move/block-executor/src/executor.rs (L1131-1195)
```rust
    fn materialize_txn_commit(
        &self,
        txn_idx: TxnIndex,
        scheduler: SchedulerWrapper,
        environment: &AptosEnvironment,
        shared_sync_params: &SharedSyncParams<T, E, S>,
    ) -> Result<(), PanicError> {
        let last_input_output = shared_sync_params.last_input_output;

        // Do a final validation for safety as a part of (parallel) post-processing.
        // Delayed fields are already validated in the sequential commit hook.
        if !Self::validate(
            txn_idx,
            last_input_output,
            shared_sync_params.global_module_cache,
            shared_sync_params.versioned_cache,
            // Module cache is not versioned (published at commit), so validation after
            // commit might observe later publishes (higher txn index) and be incorrect.
            // Hence, we skip the paranoid module validation after commit.
            // TODO(BlockSTMv2): Do the additional checking in sequential commit hook,
            // when modules have been published. Update the comment here as skipping
            // in V2 is needed for a different, code cache implementation related reason.
            true,
        ) {
            return Err(code_invariant_error(format!(
                "Final Validation in post-processing failed for txn {}",
                txn_idx
            )));
        }

        let parallel_state = ParallelState::<T>::new(
            shared_sync_params.versioned_cache,
            scheduler,
            shared_sync_params.start_shared_counter,
            shared_sync_params.delayed_field_id_counter,
            0,
            // Incarnation does not matter here (no re-execution & interrupts)
            // TODO(BlockSTMv2): we could still provide the latest incarnation.
        );
        let latest_view = LatestView::new(
            shared_sync_params.base_view,
            shared_sync_params.global_module_cache,
            environment.runtime_environment(),
            ViewState::Sync(parallel_state),
            txn_idx,
        );

        let finalized_groups = groups_to_finalize!(last_input_output, txn_idx)
            .map(|((group_key, metadata_op), is_read_needing_exchange)| {
                let (finalized_group, group_size) = shared_sync_params
                    .versioned_cache
                    .group_data()
                    .finalize_group(&group_key, txn_idx)?;

                map_finalized_group::<T>(
                    group_key,
                    finalized_group,
                    group_size,
                    metadata_op,
                    is_read_needing_exchange,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let materialized_finalized_groups =
            map_id_to_values_in_group_writes(finalized_groups, &latest_view)?;
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L526-564)
```rust
    pub fn finalize_group(
        &self,
        group_key: &K,
        txn_idx: TxnIndex,
    ) -> Result<(Vec<(T, ValueWithLayout<V>)>, ResourceGroupSize), PanicError> {
        let superset_tags = self
            .group_tags
            .get(group_key)
            .expect("Group tags must be set")
            .clone();

        let committed_group = superset_tags
            .into_iter()
            .map(
                |tag| match self.fetch_tagged_data_no_record(group_key, &tag, txn_idx + 1) {
                    Ok((_, value)) => Ok((value.write_op_kind() != WriteOpKind::Deletion)
                        .then(|| (tag, value.clone()))),
                    Err(MVGroupError::TagNotFound) => Ok(None),
                    Err(e) => Err(code_invariant_error(format!(
                        "Unexpected error in finalize group fetching value {:?}",
                        e
                    ))),
                },
            )
            .collect::<Result<Vec<_>, PanicError>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok((
            committed_group,
            self.get_group_size_no_record(group_key, txn_idx + 1)
                .map_err(|e| {
                    code_invariant_error(format!(
                        "Unexpected error in finalize group get size {:?}",
                        e
                    ))
                })?,
        ))
    }
```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L191-232)
```rust
pub(crate) fn map_id_to_values_in_group_writes<
    T: Transaction,
    S: TStateView<Key = T::Key> + Sync,
>(
    finalized_groups: Vec<(
        T::Key,
        T::Value,
        Vec<(T::Tag, ValueWithLayout<T::Value>)>,
        ResourceGroupSize,
    )>,
    latest_view: &LatestView<T, S>,
) -> Result<
    Vec<(
        T::Key,
        T::Value,
        Vec<(T::Tag, TriompheArc<T::Value>)>,
        ResourceGroupSize,
    )>,
    PanicError,
> {
    let mut patched_finalized_groups = Vec::with_capacity(finalized_groups.len());
    for (group_key, group_metadata_op, resource_vec, group_size) in finalized_groups.into_iter() {
        let mut patched_resource_vec = Vec::with_capacity(resource_vec.len());
        for (tag, value_with_layout) in resource_vec.into_iter() {
            let value = match value_with_layout {
                ValueWithLayout::RawFromStorage(value) => value,
                ValueWithLayout::Exchanged(value, None) => value,
                ValueWithLayout::Exchanged(value, Some(layout)) => TriompheArc::new(
                    replace_ids_with_values(&value, layout.as_ref(), latest_view)?,
                ),
            };
            patched_resource_vec.push((tag, value));
        }
        patched_finalized_groups.push((
            group_key,
            group_metadata_op,
            patched_resource_vec,
            group_size,
        ));
    }
    Ok(patched_finalized_groups)
}
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L155-193)
```rust
    VerifierConfig {
        scope: VerificationScope::Everything,
        max_loop_depth: Some(5),
        max_generic_instantiation_length: Some(32),
        max_function_parameters: Some(128),
        max_basic_blocks: Some(1024),
        max_value_stack_size: 1024,
        max_type_nodes: if enable_function_values {
            Some(128)
        } else {
            Some(256)
        },
        max_push_size: Some(10000),
        max_struct_definitions: None,
        max_struct_variants: None,
        max_fields_in_struct: None,
        max_function_definitions: None,
        max_back_edges_per_function: None,
        max_back_edges_per_module: None,
        max_basic_blocks_in_script: None,
        max_per_fun_meter_units: Some(1000 * 80000),
        max_per_mod_meter_units: Some(1000 * 80000),
        _use_signature_checker_v2: true,
        sig_checker_v2_fix_script_ty_param_count,
        sig_checker_v2_fix_function_signatures,
        enable_enum_types,
        enable_resource_access_control,
        enable_function_values,
        max_function_return_values: if enable_function_values {
            Some(128)
        } else {
            None
        },
        max_type_depth: if enable_function_values {
            Some(20)
        } else {
            None
        },
    }
```
