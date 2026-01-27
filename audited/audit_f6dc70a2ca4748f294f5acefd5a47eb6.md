# Audit Report

## Title
Dependency Migration Validation Can Incorrectly Reject Valid Merges Due to Out-of-Order Transaction Execution in BlockSTM

## Summary
The `extend_with_higher_dependencies()` function in `registered_dependencies.rs` enforces an overly strict validation that requires ALL transaction indices in `other` to be strictly greater than ALL indices in `self.dependencies`. When multiple entries are removed in sequence during BlockSTM's parallel execution, dependencies can accumulate in a way that violates this validation, causing the function to incorrectly reject valid dependency merges with a `PanicError`. [1](#0-0) 

## Finding Description
The vulnerability occurs in the BlockSTM multi-version data structure when entries are removed and their dependencies are migrated to lower entries. The validation at line 111 checks that the lowest dependency in `other` must be strictly greater than the highest dependency in `self`: [2](#0-1) 

**Attack Scenario:**

Due to BlockSTM's out-of-order parallel execution, the following sequence can occur:

1. **Initial State:** Three entries exist at transaction indices 5, 15, and 25, all with the same value `V`
2. **Reads (out of order):**
   - Transaction T8 reads key K → gets Entry@5 → `deps@5 = {8}`
   - Transaction T30 reads key K → gets Entry@15 → `deps@15 = {30}`  
   - Transaction T28 reads key K → gets Entry@25 → `deps@25 = {28}`

3. **First Removal:** Transaction T15 is re-executed, triggering `remove_v2`:
   - Entry@15 is removed
   - Attempts to migrate `deps@15 = {30}` to Entry@5
   - Validation: `max({8}) < min({30})` → `8 < 30` ✓ **PASSES**
   - Result: `deps@5 = {8, 30}`

4. **Second Removal:** Transaction T25 is re-executed:
   - Entry@25 is removed
   - Next lower entry after removal of Entry@15 is Entry@5
   - Attempts to migrate `deps@25 = {28}` to Entry@5
   - Validation: `max({8, 30}) < min({28})` → `30 < 28`? ✗ **FAILS**
   - Returns `PanicError`!

The merged set `{8, 28, 30}` is semantically valid (all three transactions did read the same value), but the validation incorrectly rejects it. [3](#0-2) 

The error propagates through the execution pipeline: [4](#0-3) 

## Impact Explanation
This qualifies as **High Severity** (up to $50,000) due to:

1. **Validator Node Failures:** The `PanicError` represents a code invariant violation that can cause transaction execution to fail with status code `DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR` [5](#0-4) 

2. **Consensus Impact:** If different validator nodes encounter this error at different times or handle it differently, it could lead to consensus divergence where some nodes successfully process a block while others fail

3. **Deterministic Execution Violation:** The bug breaks the critical invariant that "all validators must produce identical state roots for identical blocks" because the error depends on the specific timing of parallel execution and entry removals

4. **Availability Impact:** Validator nodes experiencing this error may slow down or require intervention to recover, affecting network liveness

## Likelihood Explanation
**Likelihood: Medium-High**

This issue can occur in production under normal operation when:
- BlockSTM executes transactions in parallel (standard operation)
- Multiple transactions write to the same key with identical values
- Transactions are re-executed (common due to dependencies and validation failures)
- The removal order creates the problematic dependency accumulation pattern

The scenario becomes more likely as:
- Block size increases (more parallel execution)
- Transaction contention increases (more writes to same keys)
- Network conditions cause more re-executions

## Recommendation
The validation should be relaxed to only check the semantic requirement rather than the strict ordering requirement. Since `extend_impl` already handles overlapping indices correctly by keeping the higher incarnation, the strict validation is unnecessary:

**Option 1 (Remove strict validation):**
```rust
pub(crate) fn extend_with_higher_dependencies(
    &mut self,
    other: BTreeMap<TxnIndex, Incarnation>,
) -> Result<(), PanicError> {
    // Note: We expect other to contain higher txn indices in normal operation,
    // but due to out-of-order removals, this may not always hold.
    // The merge logic in extend_impl handles this correctly.
    Self::extend_impl(&mut self.dependencies, other);
    Ok(())
}
```

**Option 2 (Add context-aware validation):**
If the validation serves a defensive purpose, make it context-aware:
```rust
pub(crate) fn extend_with_higher_dependencies(
    &mut self,
    other: BTreeMap<TxnIndex, Incarnation>,
    strict_validation: bool,
) -> Result<(), PanicError> {
    if strict_validation {
        if let Some((highest_dep_idx, _)) = self.dependencies.last_key_value() {
            check_lowest_dependency_idx(&other, *highest_dep_idx)?;
        }
    }
    Self::extend_impl(&mut self.dependencies, other);
    Ok(())
}
```

The safest fix is Option 1, as the validation provides no semantic value and `extend_impl` already ensures correctness.

## Proof of Concept
**Rust Unit Test:**
```rust
#[test]
fn test_out_of_order_removal_dependency_migration() {
    // Simulate the scenario where multiple entries are removed
    // and dependencies accumulate in a way that violates the strict ordering
    
    let mut deps_entry_5 = RegisteredReadDependencies::from_dependencies(
        BTreeMap::from([(8, 0)])
    );
    
    // First migration: entry@15's deps to entry@5
    let deps_from_entry_15 = BTreeMap::from([(30, 0)]);
    assert_ok!(deps_entry_5.extend_with_higher_dependencies(deps_from_entry_15));
    
    // deps_entry_5 now has {8, 30}
    assert_eq!(deps_entry_5.clone_dependencies_for_test().len(), 2);
    
    // Second migration: entry@25's deps to entry@5
    // This should be semantically valid but will fail due to strict validation
    let deps_from_entry_25 = BTreeMap::from([(28, 0)]);
    
    // This will fail with PanicError because max({8, 30}) = 30 is NOT < 28
    let result = deps_entry_5.extend_with_higher_dependencies(deps_from_entry_25);
    assert_err!(result); // This demonstrates the bug
    
    // The merged set {8, 28, 30} would be semantically valid
    // All three transactions legitimately read the same value
}
```

**Notes**

This vulnerability demonstrates a subtle but critical flaw in the dependency migration logic. The code comment claims "This invariant holds when removing an entry from a data-structure" [6](#0-5) , but this is only true for single removals in isolation. When multiple entries are removed sequentially and dependencies accumulate at lower entries, the invariant breaks.

The bug is particularly insidious because it only manifests under specific execution patterns in parallel BlockSTM execution, making it difficult to reproduce consistently but likely enough to occur in production under high load conditions.

### Citations

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

**File:** aptos-move/mvhashmap/src/registered_dependencies.rs (L100-103)
```rust
    // This method merges other dependencies, but expects that it contains strictly
    // larger txn indices. This invariant holds when removing an entry from a data-structure,
    // and migrating dependencies (that still pass validation) to a different entry.
    // The index of the entry acts as a separator between the indices in both sets.
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

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L196-239)
```rust
    fn handle_removed_dependencies<const ONLY_COMPARE_METADATA: bool>(
        &mut self,
        txn_idx: TxnIndex,
        mut dependencies: BTreeMap<TxnIndex, Incarnation>,
        removed_data: &Arc<V>,
        removed_maybe_layout: &Option<Arc<MoveTypeLayout>>,
    ) -> Result<BTreeMap<TxnIndex, Incarnation>, PanicError> {
        // If we have dependencies and a next (lower) entry exists, validate against it.
        if !dependencies.is_empty() {
            if let Some((idx, next_lower_entry)) = self
                .versioned_map
                .range(..=ShiftedTxnIndex::new(txn_idx))
                .next_back()
            {
                assert_ne!(
                    idx.idx(),
                    Ok(txn_idx),
                    "Entry at txn_idx must be removed before calling handle_removed_dependencies"
                );

                // Non-exchanged format is default validation failure.
                if let EntryCell::ResourceWrite {
                    incarnation: _,
                    value_with_layout: ValueWithLayout::Exchanged(entry_value, entry_maybe_layout),
                    dependencies: next_lower_deps,
                } = &next_lower_entry.value
                {
                    let still_valid = compare_values_and_layouts::<ONLY_COMPARE_METADATA, V>(
                        entry_value,
                        removed_data,
                        entry_maybe_layout.as_ref(),
                        removed_maybe_layout.as_ref(),
                    );

                    if still_valid {
                        next_lower_deps
                            .lock()
                            .extend_with_higher_dependencies(std::mem::take(&mut dependencies))?;
                    }
                }
            }
        }
        Ok(dependencies)
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L170-227)
```rust
    fn process_resource_output_v2(
        maybe_output: Option<&E::Output>,
        idx_to_execute: TxnIndex,
        incarnation: Incarnation,
        last_input_output: &TxnLastInputOutput<T, E::Output>,
        versioned_cache: &MVHashMap<T::Key, T::Tag, T::Value, DelayedFieldID>,
        abort_manager: &mut AbortManager,
    ) -> Result<(), PanicError> {
        // The order is reversed in BlockSTMv2 as opposed to V1, avoiding the necessity
        // to clone the previous keys.

        let mut resource_write_set = maybe_output.map_or(Ok(HashMap::new()), |output| {
            output
                .before_materialization()
                .map(|inner| inner.resource_write_set())
        })?;

        last_input_output.for_each_resource_key_no_aggregator_v1(
            idx_to_execute,
            |prev_key_ref| {
                match resource_write_set.remove_entry(prev_key_ref) {
                    Some((key, (value, maybe_layout))) => {
                        abort_manager.invalidate_dependencies(
                            versioned_cache.data().write_v2::<false>(
                                key,
                                idx_to_execute,
                                incarnation,
                                value,
                                maybe_layout,
                            )?,
                        )?;
                    },
                    None => {
                        // Clean up the write from previous incarnation.
                        abort_manager.invalidate_dependencies(
                            versioned_cache
                                .data()
                                .remove_v2::<_, false>(prev_key_ref, idx_to_execute)?,
                        )?;
                    },
                }
                Ok(())
            },
        )?;

        // Handle remaining entries in resource_write_set (new writes)
        for (key, (value, maybe_layout)) in resource_write_set {
            abort_manager.invalidate_dependencies(versioned_cache.data().write_v2::<false>(
                key,
                idx_to_execute,
                incarnation,
                value,
                maybe_layout,
            )?)?;
        }

        Ok(())
    }
```

**File:** types/src/error.rs (L9-31)
```rust
/// Wrapping other errors, to add a variant that represents something that should never
/// happen - i.e. a code invariant error, which we would generally just panic, but since
/// we are inside of the VM, we cannot do that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PanicError {
    CodeInvariantError(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PanicOr<T: std::fmt::Debug> {
    CodeInvariantError(String),
    Or(T),
}

// code_invariant_error is also redefined in third-party/move-vm (for delayed fields errors).
pub fn code_invariant_error<M: std::fmt::Debug>(message: M) -> PanicError {
    let msg = format!(
        "Code invariant broken (there is a bug in the code), {:?}",
        message
    );
    error!("{}", msg);
    PanicError::CodeInvariantError(msg)
}
```
