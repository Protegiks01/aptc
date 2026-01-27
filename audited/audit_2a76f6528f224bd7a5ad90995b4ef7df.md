# Audit Report

## Title
Non-Atomic Group Operations in UnsyncMap Leave State Inconsistent on Mid-Operation Failures

## Summary
The `insert_group_ops()` function in `unsync_map.rs` lacks atomicity when processing multiple resource group operations. If a validation error occurs mid-iteration, previously applied operations are not rolled back, but the group size is never updated, leaving the UnsyncMap in an inconsistent state. There are no tests verifying the function's behavior under partial failure scenarios.

## Finding Description

The `insert_group_ops()` function processes multiple group operations sequentially without transactional semantics: [1](#0-0) 

The function iterates through operations, calling `insert_group_op()` for each. The `insert_group_op()` function validates operation consistency: [2](#0-1) 

The validation enforces that:
- Occupied entries can only accept Deletion or Modification operations
- Vacant entries can only accept Creation operations
- Any mismatch returns an error

**The Vulnerability:**
If operation N in a batch of M operations fails validation, operations 1 through N-1 have already modified the `group_cache`, but the function returns an error before updating `group_size` (lines 224-229). There is no rollback mechanism.

This breaks the **State Consistency** invariant: state transitions must be atomic. The UnsyncMap is left with:
- Partial group operations applied to `group_cache`
- Group size not reflecting those operations
- Future operations seeing inconsistent state

The function is used during sequential block execution: [3](#0-2) 

While the Move VM has validation to prevent inconsistent operations during normal execution: [4](#0-3) 

This validation can fail during speculative execution scenarios or if there are edge case bugs in state tracking, parallel execution coordination, or storage layer interactions.

**Test Coverage Gap:**
Examining all tests in the file: [5](#0-4) 

None verify atomicity on mid-operation failure. Tests at lines 516-533 check that invalid single operations fail, but don't verify state consistency when multi-operation batches fail partway through.

## Impact Explanation

**Severity: Medium (up to $10,000)**

This qualifies as "State inconsistencies requiring intervention" because:

1. **State Corruption**: Group data and group size become desynchronized, violating resource metering invariants
2. **Gas Calculation Errors**: Incorrect group sizes lead to wrong gas charges for subsequent transactions
3. **Storage Fee Miscalculation**: Resource group size-based fees become incorrect
4. **Consensus Risk**: If different validators handle the error differently (e.g., due to timing or memory state), they could diverge on state roots

The impact is not Critical because:
- It requires a pre-existing bug to trigger (Move VM producing inconsistent operations)
- It doesn't directly enable fund theft or consensus safety violations
- The Move VM's validation layer provides primary defense

However, defense-in-depth failures of this type can enable exploitation of other vulnerabilities and make the system fragile.

## Likelihood Explanation

**Likelihood: Low-Medium**

Low because:
- Move VM validation (lines 231-247 in write_op_converter.rs) prevents inconsistent operations under normal execution
- Requires a bug in Move VM, storage layer, or parallel execution coordinator to trigger

Medium because:
- Complex systems like parallel execution and speculative execution have subtle race conditions
- The absence of defensive rollback means any such bug immediately corrupts state
- No test coverage means regressions could introduce triggers
- Historical blockchain bugs often involve state consistency edge cases

## Recommendation

Implement atomic semantics for `insert_group_ops()`:

```rust
pub fn insert_group_ops(
    &self,
    group_key: &K,
    group_ops: impl IntoIterator<Item = (T, (V, Option<TriompheArc<MoveTypeLayout>>))>,
    group_size: ResourceGroupSize,
) -> Result<(), PanicError> {
    // Collect operations to validate all before applying any
    let ops: Vec<_> = group_ops.into_iter().collect();
    
    // Validation phase - check all operations are consistent
    for (value_tag, (group_op, _)) in &ops {
        self.validate_group_op(group_key, value_tag, group_op)?;
    }
    
    // Application phase - only reached if all validations passed
    for (value_tag, (group_op, maybe_layout)) in ops {
        self.apply_group_op(group_key, value_tag, group_op, maybe_layout);
    }
    
    self.group_cache
        .borrow_mut()
        .get_mut(group_key)
        .expect("Resource group must be cached")
        .borrow_mut()
        .1 = group_size;
    Ok(())
}

// Split insert_group_op into validate and apply phases
fn validate_group_op(&self, group_key: &K, value_tag: &T, v: &V) -> Result<(), PanicError> {
    // Validation only, no state modification
    use aptos_types::write_set::WriteOpKind::*;
    use std::collections::hash_map::Entry::*;
    
    let entry_exists = self.group_cache
        .borrow()
        .get(group_key)
        .expect("Resource group must be cached")
        .borrow()
        .0
        .contains_key(value_tag);
    
    match (entry_exists, v.write_op_kind()) {
        (true, Deletion) | (true, Modification) | (false, Creation) => Ok(()),
        _ => Err(code_invariant_error(format!(
            "WriteOp kind {:?} not consistent with previous value at tag {:?}",
            v.write_op_kind(), value_tag
        ))),
    }
}

fn apply_group_op(&self, group_key: &K, value_tag: T, v: V, maybe_layout: Option<TriompheArc<MoveTypeLayout>>) {
    // Application without validation, assumes validate_group_op already called
    // ... existing logic ...
}
```

**Add comprehensive tests:**

```rust
#[test]
fn group_ops_atomicity_on_failure() {
    let ap = KeyType(b"/foo/f".to_vec());
    let map = UnsyncMap::<KeyType<Vec<u8>>, usize, TestValue, ()>::new();
    
    map.set_group_base_values(
        ap.clone(),
        vec![(1, TestValue::with_kind(1, true))],
    ).unwrap();
    
    // Attempt batch with: valid op, then invalid op
    let result = map.insert_group_ops(
        &ap,
        vec![
            (1, (TestValue::with_kind(101, false), None)), // Valid modification
            (2, (TestValue::with_kind(102, false), None)), // Invalid - should be creation
        ],
        ResourceGroupSize::new(100),
    );
    
    assert_err!(result);
    
    // Verify state is unchanged - atomicity
    let data = map.fetch_group_tagged_data(&ap, &1).unwrap();
    assert_eq!(data, ValueWithLayout::RawFromStorage(...)); // Still base value
    assert_eq!(map.get_group_size(&ap), original_size); // Size unchanged
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod atomicity_test {
    use super::*;
    use crate::types::test::{KeyType, TestValue};
    
    #[test]
    fn demonstrate_non_atomic_failure() {
        let group_key = KeyType(b"/test/group".to_vec());
        let map = UnsyncMap::<KeyType<Vec<u8>>, usize, TestValue, ()>::new();
        
        // Setup: base has tag 1 with value 100
        map.set_group_base_values(
            group_key.clone(),
            vec![(1, TestValue::with_kind(100, true))],
        ).unwrap();
        
        let original_size = map.get_group_size(&group_key).unwrap();
        
        // Attempt multi-op batch where second op is invalid
        let result = map.insert_group_ops(
            &group_key,
            vec![
                (1, (TestValue::with_kind(200, false), None)),  // Valid: Modify existing
                (2, (TestValue::with_kind(300, false), None)),  // Invalid: Modify non-existent
            ],
            ResourceGroupSize::new(500),
        );
        
        // Operation fails as expected
        assert!(result.is_err());
        
        // BUG: First operation was already applied!
        let tag1_value = map.fetch_group_tagged_data(&group_key, &1).unwrap();
        match tag1_value {
            ValueWithLayout::Exchanged(v, _) => {
                // This shows tag 1 was modified to 200
                assert_eq!(*v, TestValue::with_kind(200, false));
            },
            _ => panic!("Tag 1 should be Exchanged"),
        }
        
        // BUG: Group size was NOT updated
        assert_eq!(map.get_group_size(&group_key).unwrap(), original_size);
        
        // STATE IS INCONSISTENT: tag 1 modified but size unchanged
        println!("Non-atomic behavior demonstrated: partial update occurred");
    }
}
```

## Notes

This finding represents a **defense-in-depth failure** rather than a directly exploitable vulnerability. The Move VM's validation layer (in `write_op_converter.rs`) provides primary protection against inconsistent operations. However:

1. **Test Coverage Gap is Real**: No tests verify atomicity guarantees, which is the core question asked
2. **Robustness Issue**: System assumes upstream validation always works; doesn't handle its own validation failures gracefully
3. **Future Risk**: Refactoring could introduce bugs; lack of tests means they wouldn't be caught
4. **Complexity Risk**: Parallel execution, speculative execution, and state synchronization are complex and could have edge cases

The issue should be fixed to improve system robustness and to ensure defined behavior under all error conditions, even if those conditions "should never happen" according to current design assumptions.

### Citations

**File:** aptos-move/mvhashmap/src/unsync_map.rs (L215-231)
```rust
    pub fn insert_group_ops(
        &self,
        group_key: &K,
        group_ops: impl IntoIterator<Item = (T, (V, Option<TriompheArc<MoveTypeLayout>>))>,
        group_size: ResourceGroupSize,
    ) -> Result<(), PanicError> {
        for (value_tag, (group_op, maybe_layout)) in group_ops.into_iter() {
            self.insert_group_op(group_key, value_tag, group_op, maybe_layout)?;
        }
        self.group_cache
            .borrow_mut()
            .get_mut(group_key)
            .expect("Resource group must be cached")
            .borrow_mut()
            .1 = group_size;
        Ok(())
    }
```

**File:** aptos-move/mvhashmap/src/unsync_map.rs (L233-279)
```rust
    fn insert_group_op(
        &self,
        group_key: &K,
        value_tag: T,
        v: V,
        maybe_layout: Option<TriompheArc<MoveTypeLayout>>,
    ) -> Result<(), PanicError> {
        use aptos_types::write_set::WriteOpKind::*;
        use std::collections::hash_map::Entry::*;
        match (
            self.group_cache
                .borrow_mut()
                .get_mut(group_key)
                .expect("Resource group must be cached")
                .borrow_mut()
                .0
                .entry(value_tag.clone()),
            v.write_op_kind(),
        ) {
            (Occupied(entry), Deletion) => {
                entry.remove();
            },
            (Occupied(mut entry), Modification) => {
                entry.insert(ValueWithLayout::Exchanged(
                    TriompheArc::new(v),
                    maybe_layout,
                ));
            },
            (Vacant(entry), Creation) => {
                entry.insert(ValueWithLayout::Exchanged(
                    TriompheArc::new(v),
                    maybe_layout,
                ));
            },
            (l, r) => {
                return Err(code_invariant_error(format!(
                    "WriteOp kind {:?} not consistent with previous value at tag {:?}. Existing: {:?}, new: {:?}",
                    v.write_op_kind(),
                    value_tag,
		    l,
		    r,
                )));
            },
        }

        Ok(())
    }
```

**File:** aptos-move/mvhashmap/src/unsync_map.rs (L349-635)
```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::types::test::{KeyType, TestValue};
    use claims::{assert_err, assert_err_eq, assert_none, assert_ok, assert_ok_eq, assert_some_eq};

    fn finalize_group_as_hashmap(
        map: &UnsyncMap<KeyType<Vec<u8>>, usize, TestValue, ()>,
        key: &KeyType<Vec<u8>>,
    ) -> HashMap<usize, ValueWithLayout<TestValue>> {
        map.finalize_group(key).0.collect()
    }

    // TODO[agg_v2](test) Add tests with non trivial layout
    #[test]
    fn group_commit_idx() {
        let ap = KeyType(b"/foo/f".to_vec());
        let map = UnsyncMap::<KeyType<Vec<u8>>, usize, TestValue, ()>::new();

        map.set_group_base_values(
            ap.clone(),
            // base tag 1, 2, 3
            (1..4).map(|i| (i, TestValue::with_kind(i, true))),
        )
        .unwrap();
        assert_ok!(map.insert_group_op(&ap, 2, TestValue::with_kind(202, false), None));
        assert_ok!(map.insert_group_op(&ap, 3, TestValue::with_kind(203, false), None));
        let committed = finalize_group_as_hashmap(&map, &ap);

        // // The value at tag 1 is from base, while 2 and 3 are from txn 3.
        // // (Arc compares with value equality)
        assert_eq!(committed.len(), 3);
        assert_some_eq!(
            committed.get(&1),
            &ValueWithLayout::RawFromStorage(TriompheArc::new(TestValue::with_kind(1, true)))
        );
        assert_some_eq!(
            committed.get(&2),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(202, false)), None)
        );
        assert_some_eq!(
            committed.get(&3),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(203, false)), None)
        );

        assert_ok!(map.insert_group_op(&ap, 3, TestValue::with_kind(303, false), None));
        assert_ok!(map.insert_group_op(&ap, 4, TestValue::with_kind(304, true), None));
        let committed = finalize_group_as_hashmap(&map, &ap);
        assert_eq!(committed.len(), 4);
        assert_some_eq!(
            committed.get(&1),
            &ValueWithLayout::RawFromStorage(TriompheArc::new(TestValue::with_kind(1, true)))
        );
        assert_some_eq!(
            committed.get(&2),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(202, false)), None)
        );
        assert_some_eq!(
            committed.get(&3),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(303, false)), None)
        );
        assert_some_eq!(
            committed.get(&4),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(304, true)), None)
        );

        assert_ok!(map.insert_group_op(&ap, 0, TestValue::with_kind(100, true), None));
        assert_ok!(map.insert_group_op(&ap, 1, TestValue::deletion(), None));
        assert_err!(map.insert_group_op(&ap, 1, TestValue::deletion(), None));
        let committed = finalize_group_as_hashmap(&map, &ap);
        assert_eq!(committed.len(), 4);
        assert_some_eq!(
            committed.get(&0),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(100, true)), None)
        );
        assert_none!(committed.get(&1));
        assert_some_eq!(
            committed.get(&2),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(202, false)), None)
        );
        assert_some_eq!(
            committed.get(&3),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(303, false)), None)
        );
        assert_some_eq!(
            committed.get(&4),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(304, true)), None)
        );

        assert_ok!(map.insert_group_op(&ap, 0, TestValue::deletion(), None));
        assert_ok!(map.insert_group_op(&ap, 1, TestValue::with_kind(400, true), None));
        assert_ok!(map.insert_group_op(&ap, 2, TestValue::deletion(), None));
        assert_ok!(map.insert_group_op(&ap, 3, TestValue::deletion(), None));
        assert_ok!(map.insert_group_op(&ap, 4, TestValue::deletion(), None));
        let committed = finalize_group_as_hashmap(&map, &ap);
        assert_eq!(committed.len(), 1);
        assert_some_eq!(
            committed.get(&1),
            &ValueWithLayout::Exchanged(TriompheArc::new(TestValue::with_kind(400, true)), None)
        );
    }

    #[should_panic]
    #[test]
    fn set_base_twice() {
        let ap = KeyType(b"/foo/f".to_vec());
        let map = UnsyncMap::<KeyType<Vec<u8>>, usize, TestValue, ()>::new();

        assert_ok!(map.set_group_base_values(
            ap.clone(),
            (1..4).map(|i| (i, TestValue::with_kind(i, true))),
        ));
        assert_ok!(map.set_group_base_values(
            ap.clone(),
            (1..4).map(|i| (i, TestValue::with_kind(i, true))),
        ));
    }

    #[should_panic]
    #[test]
    fn group_op_without_base() {
        let ap = KeyType(b"/foo/f".to_vec());
        let map = UnsyncMap::<KeyType<Vec<u8>>, usize, TestValue, ()>::new();

        assert_ok!(map.insert_group_op(&ap, 3, TestValue::with_kind(10, true), None));
    }

    #[should_panic]
    #[test]
    fn group_no_path_exists() {
        let ap = KeyType(b"/foo/b".to_vec());
        let map = UnsyncMap::<KeyType<Vec<u8>>, usize, TestValue, ()>::new();

        let _ = map.finalize_group(&ap).0.collect::<Vec<_>>();
    }

    #[test]
    fn group_size() {
        let ap = KeyType(b"/foo/f".to_vec());
        let map = UnsyncMap::<KeyType<Vec<u8>>, usize, TestValue, ()>::new();

        assert_none!(map.get_group_size(&ap));

        map.set_group_base_values(
            ap.clone(),
            // base tag 1, 2, 3, 4
            (1..5).map(|i| (i, TestValue::creation_with_len(1))),
        )
        .unwrap();

        let tag: usize = 5;
        let one_entry_len = TestValue::creation_with_len(1).bytes().unwrap().len();
        let two_entry_len = TestValue::creation_with_len(2).bytes().unwrap().len();
        let three_entry_len = TestValue::creation_with_len(3).bytes().unwrap().len();
        let four_entry_len = TestValue::creation_with_len(4).bytes().unwrap().len();

        let base_size = group_size_as_sum(vec![(&tag, one_entry_len); 4].into_iter()).unwrap();
        assert_some_eq!(map.get_group_size(&ap), base_size);

        let exp_size = group_size_as_sum(vec![(&tag, two_entry_len); 2].into_iter().chain(vec![
            (
                &tag,
                one_entry_len
            );
            3
        ]))
        .unwrap();
        assert_err!(map.insert_group_ops(
            &ap,
            vec![(0, (TestValue::modification_with_len(2), None))],
            exp_size,
        ));
        assert_err!(map.insert_group_ops(
            &ap,
            vec![(1, (TestValue::creation_with_len(2), None))],
            exp_size,
        ));
        assert_ok!(map.insert_group_ops(
            &ap,
            vec![
                (0, (TestValue::creation_with_len(2), None)),
                (1, (TestValue::modification_with_len(2), None))
            ],
            exp_size
        ));
        assert_some_eq!(map.get_group_size(&ap), exp_size);

        let exp_size = group_size_as_sum(
            vec![(&tag, one_entry_len); 2]
                .into_iter()
                .chain(vec![(&tag, two_entry_len); 2])
                .chain(vec![(&tag, three_entry_len); 2]),
        )
        .unwrap();
        assert_ok!(map.insert_group_ops(
            &ap,
            vec![
                (4, (TestValue::modification_with_len(3), None)),
                (5, (TestValue::creation_with_len(3), None)),
            ],
            exp_size
        ));
        assert_some_eq!(map.get_group_size(&ap), exp_size);

        let exp_size = group_size_as_sum(
            vec![(&tag, one_entry_len); 2]
                .into_iter()
                .chain(vec![(&tag, three_entry_len); 2])
                .chain(vec![(&tag, four_entry_len); 2]),
        )
        .unwrap();
        assert_ok!(map.insert_group_ops(
            &ap,
            vec![
                (0, (TestValue::modification_with_len(4), None)),
                (1, (TestValue::modification_with_len(4), None))
            ],
            exp_size
        ));
        assert_some_eq!(map.get_group_size(&ap), exp_size);
    }

    #[test]
    fn group_value() {
        let ap = KeyType(b"/foo/f".to_vec());
        let map = UnsyncMap::<KeyType<Vec<u8>>, usize, TestValue, ()>::new();

        // Uninitialized before group is set, TagNotFound afterwards
        assert_err_eq!(
            map.fetch_group_tagged_data(&ap, &1),
            UnsyncGroupError::Uninitialized
        );

        map.set_group_base_values(
            ap.clone(),
            // base tag 1, 2, 3, 4
            (1..5).map(|i| (i, TestValue::creation_with_len(i))),
        )
        .unwrap();

        for i in 1..5 {
            assert_ok_eq!(
                map.fetch_group_tagged_data(&ap, &i),
                ValueWithLayout::RawFromStorage(TriompheArc::new(TestValue::creation_with_len(i)),)
            );
        }
        assert_err_eq!(
            map.fetch_group_tagged_data(&ap, &0),
            UnsyncGroupError::TagNotFound
        );
        assert_err_eq!(
            map.fetch_group_tagged_data(&ap, &6),
            UnsyncGroupError::TagNotFound
        );

        assert_ok!(map.insert_group_op(&ap, 1, TestValue::deletion(), None));
        assert_ok!(map.insert_group_op(&ap, 3, TestValue::modification_with_len(8), None));
        assert_ok!(map.insert_group_op(&ap, 6, TestValue::creation_with_len(9), None));

        assert_err_eq!(
            map.fetch_group_tagged_data(&ap, &1),
            UnsyncGroupError::TagNotFound,
        );
        assert_ok_eq!(
            map.fetch_group_tagged_data(&ap, &3),
            ValueWithLayout::Exchanged(TriompheArc::new(TestValue::modification_with_len(8)), None,)
        );
        assert_ok_eq!(
            map.fetch_group_tagged_data(&ap, &6),
            ValueWithLayout::Exchanged(TriompheArc::new(TestValue::creation_with_len(9)), None,)
        );

        // others unaffected.
        assert_err_eq!(
            map.fetch_group_tagged_data(&ap, &0),
            UnsyncGroupError::TagNotFound,
        );
        assert_ok_eq!(
            map.fetch_group_tagged_data(&ap, &2),
            ValueWithLayout::RawFromStorage(TriompheArc::new(TestValue::creation_with_len(2)),)
        );
        assert_ok_eq!(
            map.fetch_group_tagged_data(&ap, &4),
            ValueWithLayout::RawFromStorage(TriompheArc::new(TestValue::creation_with_len(4)),)
        );
    }
}
```

**File:** aptos-move/block-executor/src/executor.rs (L2106-2111)
```rust
        for (group_key, (metadata_op, group_size, group_ops)) in
            output_before_guard.resource_group_write_set().into_iter()
        {
            unsync_map.insert_group_ops(&group_key, group_ops, group_size)?;
            unsync_map.write(group_key, TriompheArc::new(metadata_op), None);
        }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L231-247)
```rust
            (None, Modify(_) | Delete) => {
                // Possible under speculative execution, returning speculative error waiting for re-execution.
                return Err(
                    PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
                        .with_message(
                            "When converting write op: updating non-existent value.".to_string(),
                        ),
                );
            },
            (Some(_), New(_)) => {
                // Possible under speculative execution, returning speculative error waiting for re-execution.
                return Err(
                    PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
                        .with_message(
                            "When converting write op: Recreating existing value.".to_string(),
                        ),
                );
```
