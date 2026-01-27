# Audit Report

## Title
Validator Node Crash via Improper Error Handling in Dependency Recording (BlockSTMv2)

## Summary
The `fetch_data_and_record_dependency()` function in BlockSTMv2 uses `assert_ok!()` to handle dependency insertion errors, causing validator nodes to panic and crash instead of gracefully propagating `PanicError` results. This violates defense-in-depth principles and transforms potential scheduler bugs into denial-of-service conditions.

## Finding Description

In BlockSTMv2's parallel transaction execution system, when a transaction reads data, it must record itself as a dependency on that data for validation purposes. The dependency recording mechanism enforces a critical invariant: incarnation numbers must increase monotonically for each transaction.

The vulnerability exists in the error handling path: [1](#0-0) 

The `insert()` method is designed to return a `PanicError` when the incarnation ordering invariant is violated: [2](#0-1) 

However, instead of propagating this error through the Result type system, the code uses `assert_ok!()` which panics on error. The TODO comment acknowledges this is improper: [3](#0-2) 

After the dependency recording (which may panic), the function returns success: [4](#0-3) 

The identical issue exists in resource group handling: [5](#0-4) 

**Propagation Path:**
1. Transaction execution calls `fetch_data_and_record_dependency()` during speculative reads
2. The function calls `v.read()` which attempts to record the dependency
3. If a scheduler bug causes incarnation ordering violations, `insert()` returns `PanicError`
4. `assert_ok!()` panics instead of returning the error
5. Validator thread crashes, potentially taking down the node

## Impact Explanation

**Severity: High** (Validator node crashes - up to $50,000 per Aptos Bug Bounty)

This issue transforms recoverable errors into node crashes through improper error handling. While the underlying invariant violation (incarnation reordering) should theoretically never occur, proper defensive programming requires graceful error handling even for "impossible" conditions.

**Impact escalation:**
- **Without this bug**: Scheduler invariant violations → `PanicError` returned → Worker stops with alert log → Investigation triggered
- **With this bug**: Scheduler invariant violations → Panic → Thread crash → Potential node unavailability → Network disruption if multiple validators affected

The error handling pattern used elsewhere in the codebase demonstrates the correct approach - returning `PanicError` for code invariant violations: [6](#0-5) 

## Likelihood Explanation

**Likelihood: Low to Medium**

Direct exploitability is limited because:
- Incarnation numbers are scheduler-controlled, not attacker-controlled
- No demonstrated external trigger for incarnation ordering violations
- Requires underlying scheduler race conditions or bugs to manifest

However, likelihood increases in scenarios involving:
- High transaction throughput stressing the parallel execution system
- Concurrent writes causing frequent re-executions
- Potential undiscovered race conditions in scheduler state management

The TODO comment indicates developers anticipated fixing this during refactoring, suggesting they recognized the risk even if concrete exploit paths are unclear.

## Recommendation

Replace `assert_ok!()` with proper error propagation. The `read()` function signature must be updated to return `Result<MVDataOutput<V>, MVDataError>` where `MVDataError` can represent both dependency errors and data errors, or use a separate error type that encompasses `PanicError`.

**Recommended fix approach:**

1. Update `MVDataError` to include a `DependencyRecordingFailure(PanicError)` variant
2. Change the dependency recording to propagate errors:

```rust
if let Some(reader_incarnation) = maybe_reader_incarnation {
    dependencies
        .lock()
        .insert(reader_txn_idx, reader_incarnation)
        .map_err(MVDataError::DependencyRecordingFailure)?;
}
```

3. Apply the same fix to `versioned_group_data.rs` line 496

This matches the error handling pattern used in `remove_v2` and `write_v2` functions: [7](#0-6) 

## Proof of Concept

While a complete PoC requires triggering scheduler race conditions (beyond external attacker capabilities), the error handling failure can be demonstrated through unit testing:

```rust
#[test]
#[should_panic(expected = "Recording dependency on txn")]
fn test_dependency_recording_panic() {
    use crate::types::{Incarnation, TxnIndex, ValueWithLayout};
    use crate::versioned_data::VersionedData;
    use std::sync::Arc;
    
    let map = VersionedData::<u32, TestValue>::empty();
    
    // Write initial value at txn 5
    map.write(1, 5, 0, Arc::new(TestValue), None);
    
    // First read with incarnation 2
    let _ = map.fetch_data_and_record_dependency(&1, 10, 2);
    
    // Trigger incarnation ordering violation (incarnation 1 < 2)
    // This should return an error but instead panics
    let _ = map.fetch_data_and_record_dependency(&1, 10, 1);
    // Test panics here due to assert_ok!() instead of returning error
}
```

**Notes:**
- This vulnerability represents a defense-in-depth failure rather than a directly exploitable attack
- The primary issue is violation of Rust error handling best practices in safety-critical code
- Even if the scheduler invariant "should never" be violated, production blockchain systems require graceful degradation
- The acknowledged TODO comment indicates this was recognized technical debt that remained unfixed

### Citations

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L279-291)
```rust
                    // Record the read dependency (only in V2 case, not to add contention to V1).
                    if let Some(reader_incarnation) = maybe_reader_incarnation {
                        // TODO(BlockSTMv2): convert to PanicErrors after MVHashMap refactoring.
                        assert_ok!(dependencies
                            .lock()
                            .insert(reader_txn_idx, reader_incarnation));
                    }

                    // Resolve to the write if no deltas were applied in between.
                    return Ok(Versioned(
                        idx.idx().map(|idx| (idx, *incarnation)),
                        value_with_layout.clone(),
                    ));
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L464-512)
```rust
    pub fn remove_v2<Q, const ONLY_COMPARE_METADATA: bool>(
        &self,
        key: &Q,
        txn_idx: TxnIndex,
    ) -> Result<BTreeMap<TxnIndex, Incarnation>, PanicError>
    where
        Q: Equivalent<K> + Hash + Debug,
    {
        let mut v = self.values.get_mut(key).ok_or_else(|| {
            code_invariant_error(format!("Path must exist for remove_v2: {:?}", key))
        })?;

        // Get the entry to be removed
        let removed_entry = v
            .versioned_map
            .remove(&ShiftedTxnIndex::new(txn_idx))
            .ok_or_else(|| {
                code_invariant_error(format!(
                    "Entry for key / idx must exist to be deleted: {:?}, {}",
                    key, txn_idx
                ))
            })?;

        if let EntryCell::ResourceWrite {
            incarnation: _,
            value_with_layout,
            dependencies,
        } = &removed_entry.value
        {
            match value_with_layout {
                ValueWithLayout::RawFromStorage(_) => {
                    unreachable!(
                        "Removed value written by txn {txn_idx} may not be RawFromStorage"
                    );
                },
                ValueWithLayout::Exchanged(data, layout) => {
                    let removed_deps = take_dependencies(dependencies);
                    v.handle_removed_dependencies::<ONLY_COMPARE_METADATA>(
                        txn_idx,
                        removed_deps,
                        data,
                        layout,
                    )
                },
            }
        } else {
            Ok(BTreeMap::new())
        }
    }
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L534-547)
```rust
    pub fn fetch_data_and_record_dependency<Q>(
        &self,
        key: &Q,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
    ) -> Result<MVDataOutput<V>, MVDataError>
    where
        Q: Equivalent<K> + Hash,
    {
        self.values
            .get(key)
            .map(|v| v.read(txn_idx, Some(incarnation)))
            .unwrap_or(Err(MVDataError::Uninitialized))
    }
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L675-712)
```rust
    pub fn write_v2<const ONLY_COMPARE_METADATA: bool>(
        &self,
        key: K,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
        data: Arc<V>,
        maybe_layout: Option<Arc<MoveTypeLayout>>,
    ) -> Result<BTreeMap<TxnIndex, Incarnation>, PanicError> {
        let mut v = self.values.entry(key).or_default();
        let (affected_dependencies, validation_passed) = v
            .split_off_affected_read_dependencies::<ONLY_COMPARE_METADATA>(
                txn_idx,
                &data,
                &maybe_layout,
            );

        // Asserted (local, easily checkable invariant), since affected dependencies are obtained
        // by calling split_off at txn_idx + 1.
        assert!(check_lowest_dependency_idx(&affected_dependencies, txn_idx).is_ok());

        // If validation passed, keep the dependencies (pass to write_impl), o.w. return them
        // (invalidated read dependencies) to the caller.
        let (deps_to_retain, deps_to_return) = if validation_passed {
            (affected_dependencies, BTreeMap::new())
        } else {
            (BTreeMap::new(), affected_dependencies)
        };

        Self::write_impl(
            &mut v,
            txn_idx,
            incarnation,
            ValueWithLayout::Exchanged(data, maybe_layout),
            deps_to_retain,
        );

        Ok(deps_to_return)
    }
```

**File:** aptos-move/mvhashmap/src/registered_dependencies.rs (L52-73)
```rust
    pub(crate) fn insert(
        &mut self,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
    ) -> Result<(), PanicError> {
        if let Some(prev_incarnation) = self.dependencies.insert(txn_idx, incarnation) {
            if prev_incarnation > incarnation {
                // A higher incarnation may not have been recorded before, as
                // incarnations for each txn index are monotonically incremented.
                //
                // TODO(BlockSTMv2): Consider also checking the cases when the
                // incarnations are equal, but local caching should have ensured that the
                // read with the same incarnation was not performed twice.
                return Err(code_invariant_error(format!(
                    "Recording dependency on txn {} incarnation {}, found incarnation {}",
                    txn_idx, incarnation, prev_incarnation
                )));
            }
        }

        Ok(())
    }
```

**File:** aptos-move/mvhashmap/src/versioned_group_data.rs (L495-497)
```rust
                        // TODO(BlockSTMv2): convert to PanicErrors after MVHashMap refactoring.
                        assert_ok!(size.value.dependencies.lock().insert(txn_idx, incarnation));
                        Ok(size.value.size)
```
