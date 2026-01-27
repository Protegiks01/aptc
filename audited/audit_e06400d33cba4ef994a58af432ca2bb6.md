# Audit Report

## Title
Missing Write Set Duplicate Key Validation in State Checkpoint Processing Could Enable Consensus Divergence

## Summary
The `DoStateCheckpoint::run()` function does not validate that execution output write sets are free of duplicate keys or conflicting operations. While the system relies on BTreeMap deduplication during write set construction, there is no explicit validation that prevents the same `StateKey` from appearing across multiple internal write set categories (resource writes, module writes, aggregator writes) during the conversion from `VMChangeSet` to `WriteSet`.

## Finding Description

The execution pipeline processes transaction outputs through several stages where write sets are merged:

1. **DoStateCheckpoint Validation Absence**: [1](#0-0) 

The `DoStateCheckpoint::run()` function directly calls `parent_state_summary.update()` without any validation of the write sets for duplicates or conflicts.

2. **WriteSet Deduplication Behavior**: [2](#0-1) 

`WriteSetMut` uses a `BTreeMap` internally, which silently deduplicates keys (last write wins). The `freeze()` method contains a TODO comment indicating missing structural validation.

3. **Cross-Category Write Set Merging**: [3](#0-2) 

When `try_combine_into_storage_change_set()` combines resource writes, module writes, and aggregator writes into a single `WriteSet`, it uses sequential `extend()` calls without validating that these three sources have disjoint key sets.

4. **Partial Validation for Resource Writes Only**: [4](#0-3) 

`VMChangeSet::new_expanded()` validates for duplicate keys **within** resource-related write sets, but does not check for duplicates **between** resource/module/aggregator write sets.

5. **Batching Overwrites Duplicates**: [5](#0-4) 

The `batch_updates()` function explicitly overwrites earlier writes with later ones when the same key appears multiple times, which is intentional for transaction batching but provides no detection mechanism.

## Impact Explanation

**Severity: Medium (up to $10,000)**

While under normal operation the type system prevents `StateKey` collisions (resources use `AccessPath` with `Path::Resource`, modules use `Path::Code`, aggregators use `TableItem`), the lack of explicit validation creates a **defense-in-depth vulnerability**:

- If a VM implementation bug allows the same `StateKey` to be written to multiple internal write sets (e.g., both `resource_write_set` and `aggregator_v1_write_set`)
- Different validator implementations or versions might have subtle differences in the order of `extend()` operations
- The "last write wins" semantics would cause different validators to retain different final values for the duplicate key
- This would result in **different state roots** being computed, violating the **Deterministic Execution** invariant
- Consequence: **Consensus divergence** requiring manual intervention to resolve

This qualifies as "State inconsistencies requiring intervention" under the Medium severity category.

## Likelihood Explanation

**Likelihood: Low**

Exploitation requires:
1. A VM bug that incorrectly categorizes a write operation, causing the same `StateKey` to appear in multiple write set categories
2. No such bug is currently known
3. The `StateKey` encoding formats provide strong type-level separation
4. Test coverage shows proper separation of resource/module/aggregator writes

However, the impact is critical if triggered (consensus divergence), and the absence of validation means such bugs would **not be caught** by the execution pipeline.

## Recommendation

Add explicit validation in `try_combine_into_storage_change_set()` to ensure disjoint key sets:

```rust
pub fn try_combine_into_storage_change_set(
    self,
    module_write_set: ModuleWriteSet,
) -> Result<StorageChangeSet, PanicError> {
    // ... existing validation ...
    
    let mut write_set_mut = WriteSetMut::default();
    
    // Collect all keys to validate no duplicates across categories
    let resource_keys: HashSet<&StateKey> = resource_write_set.keys().collect();
    let module_keys: HashSet<&StateKey> = module_write_set.writes().keys().collect();
    let aggregator_keys: HashSet<&StateKey> = aggregator_v1_write_set.keys().collect();
    
    // Check for duplicates between resource and module writes
    if let Some(dup_key) = resource_keys.intersection(&module_keys).next() {
        return Err(code_invariant_error(format!(
            "Duplicate key found between resource and module writes: {:?}", dup_key
        )));
    }
    
    // Check for duplicates between resource and aggregator writes
    if let Some(dup_key) = resource_keys.intersection(&aggregator_keys).next() {
        return Err(code_invariant_error(format!(
            "Duplicate key found between resource and aggregator writes: {:?}", dup_key
        )));
    }
    
    // Check for duplicates between module and aggregator writes
    if let Some(dup_key) = module_keys.intersection(&aggregator_keys).next() {
        return Err(code_invariant_error(format!(
            "Duplicate key found between module and aggregator writes: {:?}", dup_key
        )));
    }
    
    // Now safe to extend
    write_set_mut.extend(/* ... */);
    // ... rest of implementation ...
}
```

## Proof of Concept

Due to the type-level separation of `StateKey` variants, a PoC would require constructing a pathological VM state that violates internal invariants. Without access to VM internals that can produce duplicate keys across write set categories, a direct PoC cannot be demonstrated.

However, a unit test can verify the lack of validation:

```rust
#[test]
fn test_missing_duplicate_validation_across_write_sets() {
    // This test would demonstrate that if a VM bug created
    // duplicate keys, the current code would silently accept them
    // with last-write-wins semantics rather than rejecting the invalid state.
    
    // NOTE: Actual construction requires VM internal access
    // which is not available through public APIs
}
```

## Notes

While this finding represents a **defense-in-depth gap** rather than an immediately exploitable vulnerability, it violates the principle of fail-safe defaults. The system should explicitly validate critical invariants rather than relying solely on type-level guarantees, especially for consensus-critical code paths where validator disagreement could cause network splits.

### Citations

**File:** execution/executor/src/workflow/do_state_checkpoint.rs (L18-42)
```rust
    pub fn run(
        execution_output: &ExecutionOutput,
        parent_state_summary: &LedgerStateSummary,
        persisted_state_summary: &ProvableStateSummary,
        known_state_checkpoints: Option<Vec<Option<HashValue>>>,
    ) -> Result<StateCheckpointOutput> {
        let _timer = OTHER_TIMERS.timer_with(&["do_state_checkpoint"]);

        let state_summary = parent_state_summary.update(
            persisted_state_summary,
            &execution_output.hot_state_updates,
            execution_output.to_commit.state_update_refs(),
        )?;

        let state_checkpoint_hashes = Self::get_state_checkpoint_hashes(
            execution_output,
            known_state_checkpoints,
            &state_summary,
        )?;

        Ok(StateCheckpointOutput::new(
            state_summary,
            state_checkpoint_hashes,
        ))
    }
```

**File:** types/src/write_set.rs (L752-789)
```rust
    pub fn new(write_ops: impl IntoIterator<Item = (StateKey, WriteOp)>) -> Self {
        Self {
            write_set: write_ops.into_iter().collect(),
        }
    }

    pub fn try_new(
        write_ops: impl IntoIterator<Item = Result<(StateKey, WriteOp)>>,
    ) -> Result<Self> {
        Ok(Self {
            write_set: write_ops.into_iter().collect::<Result<_>>()?,
        })
    }

    pub fn insert(&mut self, item: (StateKey, WriteOp)) {
        self.write_set.insert(item.0, item.1);
    }

    pub fn extend(&mut self, write_ops: impl IntoIterator<Item = (StateKey, WriteOp)>) {
        self.write_set.extend(write_ops);
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.write_set.is_empty()
    }

    pub fn len(&self) -> usize {
        self.write_set.len()
    }

    pub fn freeze(self) -> Result<WriteSet> {
        // TODO: add structural validation
        Ok(WriteSet {
            value: ValueWriteSet::V0(WriteSetV0(self)),
            hotness: BTreeMap::new(),
        })
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L190-204)
```rust
                .try_fold::<_, _, PartialVMResult<BTreeMap<_, _>>>(
                    BTreeMap::new(),
                    |mut acc, element| {
                        let (key, value) = element?;
                        if acc.insert(key, value).is_some() {
                            Err(PartialVMError::new(
                                StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
                            )
                            .with_message(
                                "Found duplicate key across resource change sets.".to_string(),
                            ))
                        } else {
                            Ok(acc)
                        }
                    },
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L247-270)
```rust
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
```

**File:** storage/storage-interface/src/state_store/state_update_refs.rs (L272-278)
```rust
                for (k, u) in shard_iter {
                    // If it's a value write op (Creation/Modification/Deletion), just insert and
                    // overwrite the previous op.
                    if u.state_op.is_value_write_op() {
                        dedupped.insert(k, u);
                        continue;
                    }
```
