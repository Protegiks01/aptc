# Audit Report

## Title
Invariant Violation in RegisteredReadDependencies Merge During Resource Group Removal Causes Execution Failure

## Summary
The `remove_v2` method in `versioned_group_data.rs` incorrectly uses `extend_with_higher_dependencies()` when merging read dependencies from a removed entry to a lower entry. This method enforces an invariant that all transaction indices in the source must be strictly higher than all indices in the destination, but this invariant does not hold in the resource group dependency tracking context, causing a `PanicError` that halts parallel execution. [1](#0-0) 

## Finding Description
In BlockSTMv2's parallel execution engine, when a transaction re-executes with a new incarnation, previous writes from earlier incarnations are removed via `remove_v2()`. The method attempts to preserve read dependencies by migrating them to the next lower entry if the values match, using `extend_with_higher_dependencies()`. [2](#0-1) 

However, `extend_with_higher_dependencies()` enforces a strict ordering invariant: [3](#0-2) 

The invariant check validates that the lowest transaction index in the dependencies being merged must be strictly greater than the highest transaction index in the existing dependencies: [4](#0-3) 

**The Bug**: This invariant does NOT hold for resource group dependencies because:
1. Dependencies stored at an entry represent transactions that READ from that entry
2. A later transaction (e.g., txn 20) can read from an earlier entry (e.g., entry at index 5)
3. An earlier transaction (e.g., txn 12) can read from a later entry (e.g., entry at index 10)
4. When removing entry 10 and merging its dependencies {12} into entry 5's dependencies {20}, the check fails: 12 ≤ 20

**Exploitation Scenario**:
1. Transaction 5 writes a resource group with size S (creates entry A)
2. Transaction 20 reads the group size → reads from entry A → entry A has dependency {20: inc}
3. Transaction 10 writes the same group with same size S (creates entry B)
4. Transaction 12 reads the group size → reads from entry B → entry B has dependency {12: inc}
5. Transaction 10 re-executes (new incarnation) and no longer writes to the group
6. `remove_v2()` is called to clean up entry B
7. Code attempts: `entry_A.dependencies.extend_with_higher_dependencies({12: inc})`
8. Invariant check: highest in A = 20, lowest in removed = 12
9. Check: 12 ≤ 20 → **FAILS** with `PanicError` [5](#0-4) 

The `PanicError` propagates through the execution stack and causes the block executor to abort, breaking deterministic execution.

## Impact Explanation
**Severity: High** (up to $50,000 per bug bounty criteria)

This vulnerability causes:
1. **Validator node execution failures**: When the invariant check fails, a `PanicError` is raised, which propagates through the executor and causes the execution to abort
2. **Non-deterministic behavior**: Different validators might encounter this error at different times depending on transaction execution order in their parallel execution threads
3. **Liveness degradation**: Repeated failures could slow down or halt block processing

This qualifies as **High Severity** under "Validator node slowdowns" and "Significant protocol violations" categories. While not immediately Critical, if the error handling is inconsistent across validators, it could escalate to consensus divergence.

## Likelihood Explanation
**Likelihood: Medium-High**

The vulnerability can be triggered whenever:
- A transaction re-executes and changes its resource group write set
- Previous incarnation had writes to resource groups
- Multiple transactions read from different entries in the dependency chain
- The transaction ordering creates overlapping dependency indices

This is a realistic scenario in normal BlockSTM operation, especially under high contention where transactions frequently abort and re-execute. The specific ordering required (later txn reading from earlier entry, earlier txn reading from later entry) is common when transactions have varying read patterns.

## Recommendation
Replace `extend_with_higher_dependencies()` with the general `extend()` method, which correctly handles overlapping transaction indices by keeping the maximum incarnation for each transaction: [6](#0-5) 

The fix should change line 400 in `versioned_group_data.rs` from:
```rust
next_lower_entry
    .value
    .dependencies
    .lock()
    .extend_with_higher_dependencies(std::mem::take(&mut removed_size_deps))?;
```

To:
```rust
next_lower_entry
    .value
    .dependencies
    .lock()
    .extend(std::mem::take(&mut removed_size_deps));
```

The same issue may exist in `versioned_data.rs`: [7](#0-6) 

This location should also be changed to use `extend()` instead.

## Proof of Concept
```rust
#[test]
fn test_dependency_merge_invariant_violation() {
    use aptos_move::mvhashmap::{VersionedGroupData, types::KeyType};
    use std::collections::HashSet;
    
    let group_key = KeyType(b"/test/group".to_vec());
    let tag: usize = 1;
    let group_data = VersionedGroupData::<KeyType<Vec<u8>>, usize, TestValue>::empty();
    
    // Initialize group
    group_data.set_raw_base_values(group_key.clone(), vec![]).unwrap();
    
    let test_size = ResourceGroupSize::Combined {
        num_tagged_resources: 1,
        all_tagged_resources_size: 100,
    };
    
    // Transaction 5 writes with size S
    group_data.write_v2(
        group_key.clone(),
        5,  // txn_idx
        1,  // incarnation
        vec![(tag, (TestValue::creation_with_len(1), None))],
        test_size,
        HashSet::new(),
    ).unwrap();
    
    // Transaction 20 reads (registers dependency at entry 5)
    group_data.get_group_size_and_record_dependency(&group_key, 20, 1).unwrap();
    
    // Transaction 10 writes with same size S
    group_data.write_v2(
        group_key.clone(),
        10, // txn_idx
        1,  // incarnation
        vec![(tag, (TestValue::creation_with_len(1), None))],
        test_size,
        HashSet::new(),
    ).unwrap();
    
    // Transaction 12 reads (registers dependency at entry 10)
    group_data.get_group_size_and_record_dependency(&group_key, 12, 1).unwrap();
    
    // Remove entry 10 - this will trigger the invariant violation
    // Entry 5 has dependencies: {20}
    // Entry 10 has dependencies: {12}
    // Attempting to merge {12} into {20} fails: 12 <= 20
    let result = group_data.remove_v2(&group_key, 10, HashSet::from([&tag]));
    
    // This should return PanicError due to invariant violation
    assert!(result.is_err());
}
```

## Notes
The vulnerability exists because the code makes an incorrect assumption about dependency ordering. While `extend_with_higher_dependencies()` is appropriately used in other contexts where indices are guaranteed to be strictly separated (e.g., when splitting dependencies along a transaction boundary), it is incorrectly applied here where dependencies from different entries can have overlapping transaction index ranges. The general `extend()` method is the correct choice for this use case as it properly handles overlapping indices by keeping the maximum incarnation.

### Citations

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L386-408)
```rust
        let mut removed_size_deps = take_dependencies(&removed_size_entry.value.dependencies);
        if let Some((_, next_lower_entry)) = Self::get_latest_entry(
            &group_sizes.size_entries,
            txn_idx,
            ReadPosition::BeforeCurrentTxn,
        ) {
            // If the entry that will be read after removal contains the same size,
            // then the dependencies on size can be registered there and not invalidated.
            // In this case, removed_size_deps gets drained.
            if next_lower_entry.value.size == removed_size_entry.value.size {
                next_lower_entry
                    .value
                    .dependencies
                    .lock()
                    .extend_with_higher_dependencies(std::mem::take(&mut removed_size_deps))?;
            }
        }

        // If removed_size_deps was not drained (into the preceding entry's dependencies),
        // then those dependencies also need to be invalidated.
        invalidated_dependencies.extend(removed_size_deps);
        Ok(invalidated_dependencies.take())
    }
```

**File:** aptos-move/mvhashmap/src/registered_dependencies.rs (L12-25)
```rust
pub(crate) fn check_lowest_dependency_idx(
    dependencies: &BTreeMap<TxnIndex, Incarnation>,
    txn_idx: TxnIndex,
) -> Result<(), PanicError> {
    if let Some((lowest_dep_idx, _)) = dependencies.first_key_value() {
        if *lowest_dep_idx <= txn_idx {
            return Err(code_invariant_error(format!(
                "Dependency for txn {} recorded at idx {}",
                *lowest_dep_idx, txn_idx
            )));
        }
    }
    Ok(())
}
```

**File:** aptos-move/mvhashmap/src/registered_dependencies.rs (L75-98)
```rust
    fn extend_impl(
        self_dependencies: &mut BTreeMap<TxnIndex, Incarnation>,
        other_dependencies: BTreeMap<TxnIndex, Incarnation>,
    ) {
        for (txn_idx, incarnation) in other_dependencies {
            match self_dependencies.entry(txn_idx) {
                Entry::Occupied(mut entry) => {
                    if *entry.get() < incarnation {
                        entry.insert(incarnation);
                    }
                },
                Entry::Vacant(entry) => {
                    entry.insert(incarnation);
                },
            }
        }
    }

    // When we extend recorded dependencies with other dependencies in a general sense
    // (e.g. these might be invalidated dependencies from different data-structures),
    // we need to make sure to keep the latest incarnation per txn index.
    pub(crate) fn extend(&mut self, other: BTreeMap<TxnIndex, Incarnation>) {
        Self::extend_impl(&mut self.dependencies, other);
    }
```

**File:** aptos-move/mvhashmap/src/registered_dependencies.rs (L104-117)
```rust
    pub(crate) fn extend_with_higher_dependencies(
        &mut self,
        other: BTreeMap<TxnIndex, Incarnation>,
    ) -> Result<(), PanicError> {
        let dependencies = &mut self.dependencies;
        if let Some((highest_dep_idx, _)) = dependencies.last_key_value() {
            // Highest dependency in self should be strictly less than other dependencies.
            check_lowest_dependency_idx(&other, *highest_dep_idx)?;
        }

        Self::extend_impl(dependencies, other);

        Ok(())
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L286-292)
```rust
                        abort_manager.invalidate_dependencies(
                            versioned_cache.group_data().remove_v2(
                                group_key_ref,
                                idx_to_execute,
                                prev_tags,
                            )?,
                        )?;
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L230-234)
```rust
                    if still_valid {
                        next_lower_deps
                            .lock()
                            .extend_with_higher_dependencies(std::mem::take(&mut dependencies))?;
                    }
```
