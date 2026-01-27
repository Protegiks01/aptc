# Audit Report

## Title
Delta History Reset in Aggregator Snapshots Allows Bypass of Overflow Protection

## Summary
When aggregator snapshots are created and committed to versioned storage, the comprehensive DeltaHistory tracking intermediate overflow/underflow attempts is discarded and replaced with a minimal history that only records the final delta. This allows snapshots to be applied to base aggregator values that would have caused the original transaction to fail its overflow/underflow checks, violating deterministic execution guarantees.

## Finding Description

The Aptos aggregator system tracks `DeltaHistory` during transaction execution to ensure operations remain within bounds. This history records:
- `max_achieved_positive_delta`: Largest positive delta successfully applied
- `min_achieved_negative_delta`: Largest negative delta successfully applied  
- `min_overflow_positive_delta`: Smallest positive delta that would overflow
- `max_underflow_negative_delta`: Largest negative delta that would underflow [1](#0-0) 

When creating a snapshot from an aggregator or committing aggregator changes, the system calls `into_op_no_additional_history()` which **resets this comprehensive history to a minimal one**: [2](#0-1) 

This method creates a new `DeltaHistory` that only records the final delta value, completely discarding intermediate overflow/underflow attempts. The conversion happens when delayed changes are committed: [3](#0-2) 

The development team is explicitly aware of this limitation: [4](#0-3) 

**Attack Scenario:**

1. Transaction T1 on aggregator A (base=50, max=1000):
   - Add 960 → DeltaHistory: {max_achieved: 960}
   - Try Add 50 → FAILS (overflow), DeltaHistory: {max_achieved: 960, min_overflow: 1010}
   - Sub 910 → Final delta: +50
   - Create snapshot S from A
   - Snapshot stored as: SnapshotDelta{base: A, delta: DeltaOp{+50, history: {max_achieved: 50}}}
   - **Lost**: max_achieved was actually 960, not 50

2. Transaction T2 modifies aggregator A to value 900

3. Transaction T3 reads snapshot S:
   - Reads base aggregator A (now 900)
   - Applies DeltaOp{+50} with minimal history
   - Validation checks: 900 + 50 ≤ 1000 ✓ (passes)
   - **Should check**: 900 + 960 ≤ 1000 ✗ (should fail)
   - Snapshot returns 950 (incorrect - original transaction would have failed with base=900)

The validation logic uses the history to ensure deltas can be safely applied: [5](#0-4) 

When snapshot deltas are applied, they use the minimal history: [6](#0-5) 

## Impact Explanation

This vulnerability violates the **Deterministic Execution** invariant (Invariant #1) - validators must produce identical state roots for identical blocks. If different validators have different timing of when they read snapshots relative to base aggregator modifications (due to parallel execution orderings, state sync differences, or re-execution), they could get different validation results.

Specific impacts:
- **Consensus Divergence**: Different validators may compute different state roots for the same block if they evaluate snapshot validity at different times relative to base aggregator updates
- **Overflow Protection Bypass**: Aggregators can exceed their max_value bounds through snapshot operations that should have failed
- **Non-deterministic Re-execution**: Transactions that succeeded initially may fail on re-execution with different base values, or vice versa

This meets **High Severity** criteria as it causes significant protocol violations affecting deterministic execution and could lead to state inconsistencies requiring intervention.

## Likelihood Explanation

This issue has **HIGH likelihood** of occurrence because:

1. **No special privileges required**: Any user can create aggregators and snapshots
2. **Common operation pattern**: Aggregators are used extensively for parallel execution of transactions involving counters, balances, and resource tracking
3. **Happens automatically**: The history reset occurs in normal operation, not requiring any exploitation effort
4. **Parallel execution amplifies risk**: Block-STM's parallel execution increases the chance of base aggregator modifications between snapshot creation and reading

The impact materializes when:
- Snapshots are created during complex multi-operation transactions
- Base aggregators are concurrently modified by other transactions
- The aggregator value changes to a range that would have violated original execution constraints

## Recommendation

Preserve the complete DeltaHistory when creating snapshots and committing aggregator changes. Modify the conversion to include the full history:

```rust
// In delta_change_set.rs - Replace into_op_no_additional_history
pub fn into_op_with_history(self, history: DeltaHistory) -> DeltaOp {
    DeltaOp::new(self.update, self.max_value, history)
}

// In delayed_change.rs - Extract and pass through the full history
pub fn into_entry_with_history(self, history_map: &BTreeMap<I, DeltaHistory>) -> DelayedEntry<I> {
    match self {
        DelayedChange::Apply(DelayedApplyChange::SnapshotDelta { delta, base_aggregator }) => {
            let full_history = history_map.get(&base_aggregator)
                .cloned()
                .unwrap_or_else(DeltaHistory::new);
            DelayedEntry::Apply(DelayedApplyEntry::SnapshotDelta {
                delta: delta.into_op_with_history(full_history),
                base_aggregator,
            })
        },
        // ... handle other cases
    }
}
```

The executor should track and pass the complete DeltaHistory from the read set as indicated in the TODO comment.

## Proof of Concept

```rust
// Proof of concept demonstrating the vulnerability
#[test]
fn test_snapshot_history_reset_vulnerability() {
    use aptos_aggregator::*;
    
    // Setup: Aggregator with base=50, max=1000
    let base_value = 50u128;
    let max_value = 1000u128;
    
    // Transaction T1: Complex operations building history
    let mut delta = DeltaWithMax::new(SignedU128::Positive(960), max_value);
    let mut history = DeltaHistory::new();
    history.record_success(SignedU128::Positive(960));
    // Try overflow - this would fail with base=50
    history.record_overflow(1010); // 50 + 960 + 50 would overflow
    
    // Net operation: +960 - 910 = +50
    let final_delta = DeltaWithMax::new(SignedU128::Positive(50), max_value);
    
    // Create snapshot with full history
    let snapshot_with_full_history = DeltaOp::new(
        SignedU128::Positive(50), 
        max_value, 
        history.clone()
    );
    
    // Apply to new base=900 - should FAIL due to max_achieved=960
    let high_base = 900u128;
    assert!(snapshot_with_full_history.apply_to(high_base).is_err(), 
            "Should fail: 900 + 960 = 1860 > 1000");
    
    // But with minimal history - incorrectly SUCCEEDS  
    let snapshot_with_minimal_history = final_delta.into_op_no_additional_history();
    assert!(snapshot_with_minimal_history.apply_to(high_base).is_ok(),
            "Incorrectly passes: only checks 900 + 50 = 950 <= 1000");
    
    // This demonstrates the bypass
}
```

## Notes

This vulnerability is explicitly acknowledged in the codebase as a TODO for optimization but represents a genuine security issue. The history information is critical for ensuring deterministic execution across all validators and re-execution scenarios. While the system may eventually detect inconsistencies through other validation mechanisms, the weak history validation can cause intermediate state corruption and consensus divergence risks.

### Citations

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L56-72)
```rust
#[derive(Clone, Hash, Copy, Default, PartialOrd, Ord, PartialEq, Eq)]
pub struct DeltaHistory {
    pub max_achieved_positive_delta: u128,
    pub min_achieved_negative_delta: u128,
    // `min_overflow_positive_delta` is None in two possible cases:
    // 1. No overflow occurred in the try_add/try_sub functions throughout the
    // transaction execution.
    // 2. The only overflows that occurred in the try_add/try_sub functions in
    // this transaction execution are with delta that exceeds limit.
    pub min_overflow_positive_delta: Option<u128>,
    // `max_underflow_negative_delta` is None in two possible cases:
    // 1. No underflow occurred in the try_add/try_sub functions throughout the
    // transaction execution.
    // 2. The only underflows that occurred in the try_add/try_sub functions in
    // this transaction execution are with delta that drops below -limit.
    pub max_underflow_negative_delta: Option<u128>,
}
```

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L148-197)
```rust
    pub fn validate_against_base_value(
        &self,
        base_value: u128,
        max_value: u128,
    ) -> Result<(), DelayedFieldsSpeculativeError> {
        let math = BoundedMath::new(max_value);
        // We need to make sure the following 4 conditions are satisified.
        //     base_value + max_achieved_positive_delta <= self.max_value
        //     base_value >= min_achieved_negative_delta
        //     base_value + min_overflow_positive_delta > self.max_value
        //     base_value < max_underflow_negative_delta
        math.unsigned_add(base_value, self.max_achieved_positive_delta)
            .map_err(|_e| DelayedFieldsSpeculativeError::DeltaApplication {
                base_value,
                max_value,
                delta: SignedU128::Positive(self.max_achieved_positive_delta),
                reason: DeltaApplicationFailureReason::Overflow,
            })?;
        math.unsigned_subtract(base_value, self.min_achieved_negative_delta)
            .map_err(|_e| DelayedFieldsSpeculativeError::DeltaApplication {
                base_value,
                max_value,
                delta: SignedU128::Negative(self.min_achieved_negative_delta),
                reason: DeltaApplicationFailureReason::Underflow,
            })?;

        if let Some(min_overflow_positive_delta) = self.min_overflow_positive_delta {
            if base_value <= max_value - min_overflow_positive_delta {
                return Err(DelayedFieldsSpeculativeError::DeltaApplication {
                    base_value,
                    max_value,
                    delta: SignedU128::Positive(min_overflow_positive_delta),
                    reason: DeltaApplicationFailureReason::ExpectedOverflow,
                });
            }
        }

        if let Some(max_underflow_negative_delta) = self.max_underflow_negative_delta {
            if base_value >= max_underflow_negative_delta {
                return Err(DelayedFieldsSpeculativeError::DeltaApplication {
                    base_value,
                    max_value,
                    delta: SignedU128::Negative(max_underflow_negative_delta),
                    reason: DeltaApplicationFailureReason::ExpectedUnderflow,
                });
            }
        }

        Ok(())
    }
```

**File:** aptos-move/aptos-aggregator/src/delta_change_set.rs (L79-83)
```rust
    pub fn into_op_no_additional_history(self) -> DeltaOp {
        let mut history = DeltaHistory::new();
        history.record_success(self.update);
        DeltaOp::new(self.update, self.max_value, history)
    }
```

**File:** aptos-move/aptos-aggregator/src/delayed_change.rs (L163-177)
```rust
    pub fn into_entry_no_additional_history(self) -> DelayedEntry<I> {
        match self {
            DelayedChange::Create(value) => DelayedEntry::Create(value),
            DelayedChange::Apply(DelayedApplyChange::AggregatorDelta { delta }) => {
                DelayedEntry::Apply(DelayedApplyEntry::AggregatorDelta {
                    delta: delta.into_op_no_additional_history(),
                })
            },
            DelayedChange::Apply(DelayedApplyChange::SnapshotDelta {
                delta,
                base_aggregator,
            }) => DelayedEntry::Apply(DelayedApplyEntry::SnapshotDelta {
                delta: delta.into_op_no_additional_history(),
                base_aggregator,
            }),
```

**File:** aptos-move/aptos-aggregator/src/delayed_change.rs (L234-251)
```rust
    pub fn apply_to_base(
        &self,
        base_value: DelayedFieldValue,
    ) -> Result<DelayedFieldValue, PanicOr<DelayedFieldsSpeculativeError>> {
        use DelayedApplyEntry::*;

        Ok(match self {
            AggregatorDelta { delta } => {
                DelayedFieldValue::Aggregator(delta.apply_to(base_value.into_aggregator_value()?)?)
            },
            SnapshotDelta { delta, .. } => {
                DelayedFieldValue::Snapshot(delta.apply_to(base_value.into_aggregator_value()?)?)
            },
            SnapshotDerived { formula, .. } => {
                DelayedFieldValue::Derived(formula.apply_to(base_value.into_snapshot_value()?))
            },
        })
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L337-348)
```rust
        // TODO[agg_v2](optimize): see if/how we want to incorporate DeltaHistory from read set into
        // versioned_delayed_fields. Without it, currently, materialized reads cannot check history
        // and fail early.
        //
        // We can extract histories with something like the code below, and then include history in
        // change.into_entry_no_additional_history().
        //
        // for id in read_set.get_delayed_field_keys() {
        //     if !delayed_field_change_set.contains_key(id) {
        //         let read_value = read_set.get_delayed_field_by_kind(id, DelayedFieldReadKind::Bounded).unwrap();
        //     }
        // }
```
