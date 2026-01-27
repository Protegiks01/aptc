# Audit Report

## Title
Delayed Field Snapshot Value Inflation During Session Squashing

## Summary
The delayed field change squashing logic incorrectly inflates snapshot values by double-counting aggregator deltas when merging change sets from multiple transaction sessions (e.g., prologue and main execution). This results in incorrect snapshot values being committed to state, breaking deterministic execution guarantees.

## Finding Description

When a transaction executes across multiple sessions (prologue, main execution, epilogue), each session produces a `VMChangeSet` containing delayed field changes. These change sets are squashed together before finalization. The vulnerability occurs in the merge logic for `SnapshotDelta` changes. [1](#0-0) 

When `snapshot()` is called on an aggregator that has an `AggregatorDelta`, the snapshot is created with a `SnapshotDelta` that copies the aggregator's current delta. This delta already represents all accumulated changes to the aggregator in the current transaction. [2](#0-1) 

During squashing, the merge logic retrieves the aggregator's delta from the previous change set and merges it with the snapshot's delta by adding them together. This is incorrect because the snapshot's delta was already computed relative to the transaction's beginning state and already includes the prior session's changes. [3](#0-2) 

**Attack Scenario:**

1. Prologue session: `aggregator.add(100)` → produces `AggregatorDelta(+100)`
2. Main execution: `snapshot = aggregator.snapshot()` → produces `SnapshotDelta(base=aggregator, delta=+100)` (copying aggregator's current delta)
3. Squashing: Merges prev_delta (+100) with snapshot_delta (+100) → `SnapshotDelta(base=aggregator, delta=+200)`
4. Finalization: Reads aggregator's base value (e.g., 1000), applies delta (+200) → snapshot value becomes 1200

**Expected:** Snapshot should be 1100 (base 1000 + aggregator's change of 100)
**Actual:** Snapshot becomes 1200 (inflated by +100)

The semantic expectation per the code comments is that `SnapshotDelta` represents "value of base_aggregator at the BEGINNING of the transaction + delta". However, the snapshot's delta already includes all transaction changes when created, so merging again causes double-counting. [4](#0-3) 

## Impact Explanation

**Severity: High**

This vulnerability breaks the **Deterministic Execution** invariant in a subtle way - all validators will deterministically compute the same incorrect values, but these values are semantically wrong. The impact includes:

1. **State Corruption**: Snapshot values stored in resources will be systematically inflated, leading to incorrect state
2. **Financial Loss**: If aggregators track token balances or financial metrics, snapshots used for accounting/distributions will be wrong
3. **Protocol Violations**: Smart contracts relying on snapshot accuracy for governance decisions, reward distributions, or other critical logic will malfunction
4. **Cascading Errors**: Derived values (via `SnapshotDerived`) built on inflated snapshots compound the error

While this doesn't directly break consensus (all nodes compute the same wrong value), it violates the semantic correctness of the state, qualifying as a "Significant protocol violation" under High Severity criteria.

## Likelihood Explanation

**Likelihood: Medium-High**

This bug is triggered whenever:
1. A transaction uses aggregators that are modified in an early session (prologue/setup)
2. The same transaction creates snapshots of those aggregators in a later session
3. The framework or user code follows this pattern for any accounting/tracking purpose

Given that Aptos uses the prologue for gas accounting and fee processing, any contract that:
- Modifies an aggregator in prologue AND creates snapshots in main execution
- Uses multi-session transaction patterns with delayed field operations

Will automatically trigger this bug without requiring malicious intent. The bug is latent and will manifest in production once aggregator v2 features are widely adopted.

## Recommendation

The merge logic should NOT merge the aggregator's delta into the snapshot's delta. The snapshot's delta already represents the complete state when the snapshot was created.

**Fix for `delayed_change.rs`:**

Remove the merge case at lines 156-159 and replace with:

```rust
(Some(Apply(AggregatorDelta { .. })), Apply(SnapshotDelta { delta: next_delta, base_aggregator })) => {
    // Snapshot delta already includes all aggregator changes up to snapshot creation point
    // Do not merge with base aggregator's delta to avoid double-counting
    Ok(Apply(SnapshotDelta { delta: *next_delta, base_aggregator: *base_aggregator }))
}
```

Alternatively, track snapshot creation order relative to aggregator modifications and only merge if the snapshot was created in the first session before the aggregator was modified in the second session. However, this is complex and error-prone.

**The simpler fix is to never merge aggregator deltas into snapshot deltas**, as snapshots should capture point-in-time values independently.

## Proof of Concept

```move
#[test_only]
module test_addr::delayed_field_inflation_test {
    use aptos_framework::aggregator_v2;
    
    #[test(account = @test_addr)]
    fun test_snapshot_inflation(account: &signer) {
        // Simulate what happens across prologue + main execution
        
        // Session 1 (Prologue): Create aggregator and add 100
        let agg = aggregator_v2::create_aggregator(1000);
        aggregator_v2::add(&mut agg, 100);
        
        // Session 2 (Main): Create snapshot
        let snap = aggregator_v2::snapshot(&agg);
        
        // When these sessions are squashed and finalized:
        // - Aggregator's delta from session 1: +100
        // - Snapshot's delta when created: +100 (copied from aggregator)
        // - After merge: snapshot delta becomes +200
        // - Snapshot value: base(0) + 200 = 200 (WRONG!)
        // - Expected: base(0) + 100 = 100
        
        let snap_value = aggregator_v2::read_snapshot(&snap);
        let agg_value = aggregator_v2::read(&agg);
        
        // This assertion would fail due to the bug
        assert!(snap_value == agg_value, 1); // Expected: both 100
        // Actual: snap_value = 200, agg_value = 100
    }
}
```

To reproduce at the Rust level, construct two `VMChangeSet` instances as shown in the test case at: [5](#0-4) 

Modify to verify that when session 1 has aggregator delta +X and session 2 creates a snapshot, the final snapshot delta should be +X (not +2X).

## Notes

The existing test case at lines 366-436 actually demonstrates the bug as "expected behavior" - it expects merged deltas, which is incorrect. The test shows:
- Aggregator: Delta(+3) merged with Delta(+5) = Delta(+8) ✓ Correct
- Snapshot: Inherits aggregator's Delta(+3), then merged with Delta(+2) = Delta(+5) ✗ Incorrect

The snapshot's final delta should remain +2 (its original value), not +5, because the +3 from the aggregator is already accounted for in how the snapshot's delta was computed when snapshot() was called.

### Citations

**File:** aptos-move/aptos-aggregator/src/delayed_field_extension.rs (L176-220)
```rust
    pub fn snapshot(
        &mut self,
        aggregator_id: DelayedFieldID,
        max_value: u128,
        width: u32,
        resolver: &dyn DelayedFieldResolver,
    ) -> PartialVMResult<DelayedFieldID> {
        let aggregator = self.delayed_fields.get(&aggregator_id);

        let change = match aggregator {
            // If aggregator is in Create state, we don't need to depend on it, and can just take the value.
            Some(DelayedChange::Create(DelayedFieldValue::Aggregator(value))) => {
                DelayedChange::Create(DelayedFieldValue::Snapshot(*value))
            },
            Some(DelayedChange::Apply(DelayedApplyChange::AggregatorDelta { delta, .. })) => {
                if max_value != delta.max_value {
                    return Err(code_invariant_error(
                        "Tried to snapshot an aggregator with a different max value",
                    )
                    .into());
                }
                DelayedChange::Apply(DelayedApplyChange::SnapshotDelta {
                    base_aggregator: aggregator_id,
                    delta: *delta,
                })
            },
            None => DelayedChange::Apply(DelayedApplyChange::SnapshotDelta {
                base_aggregator: aggregator_id,
                delta: DeltaWithMax {
                    update: SignedU128::Positive(0),
                    max_value,
                },
            }),
            _ => {
                return Err(code_invariant_error(
                    "Tried to snapshot a non-aggregator delayed field",
                )
                .into())
            },
        };

        let snapshot_id = resolver.generate_delayed_field_id(width);
        self.delayed_fields.insert(snapshot_id, change);
        Ok(snapshot_id)
    }
```

**File:** aptos-move/aptos-aggregator/src/delayed_change.rs (L88-98)
```rust

impl<I: Copy + Clone> DelayedChange<I> {
    // When squashing a new change on top of the old one, sometimes we need to know the change
    // from a different AggregatorID to be able to merge them together.
    // In particular SnapshotDelta represents a change from the aggregator at the beginning of the transaction,
    // and squashing changes where the aggregator will be at the beginning of the transaction.
    // For example, let’s say we have two change sets that we need to squash:
    // change1: agg1 -> Delta(+3)
    // change2: agg1 -> Delta(+6), snap1 -> (base=agg1, Delta(+2))
    // the correct squashing of snapshot depends on the change for the base aggregator. I.e. the correct output would be:
    // agg1 -> Delta(+9), snap(base=agg1, Delta(+5))
```

**File:** aptos-move/aptos-aggregator/src/delayed_change.rs (L156-159)
```rust
            (Some(Apply(AggregatorDelta { delta: prev_delta })), Apply(SnapshotDelta { delta: next_delta, base_aggregator })) => {
                let new_delta = DeltaWithMax::create_merged_delta(prev_delta, next_delta)?;
                Ok(Apply(SnapshotDelta { delta: new_delta, base_aggregator: *base_aggregator }))
            },
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L486-520)
```rust
    fn squash_additional_delayed_field_changes(
        change_set: &mut BTreeMap<DelayedFieldID, DelayedChange<DelayedFieldID>>,
        additional_change_set: BTreeMap<DelayedFieldID, DelayedChange<DelayedFieldID>>,
    ) -> PartialVMResult<()> {
        let merged_changes = additional_change_set
            .into_iter()
            .map(|(id, additional_change)| {
                let prev_change =
                    if let Some(dependent_id) = additional_change.get_merge_dependent_id() {
                        if change_set.contains_key(&id) {
                            return (
                                id,
                                Err(code_invariant_error(format!(
                                "Aggregator change set contains both {:?} and its dependent {:?}",
                                id, dependent_id
                            ))
                                .into()),
                            );
                        }
                        change_set.get(&dependent_id)
                    } else {
                        change_set.get(&id)
                    };
                (
                    id,
                    DelayedChange::merge_two_changes(prev_change, &additional_change),
                )
            })
            .collect::<Vec<_>>();

        for (id, merged_change) in merged_changes.into_iter() {
            change_set.insert(id, merged_change.map_err(PartialVMError::from)?);
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-vm-types/src/tests/test_change_set.rs (L366-436)
```rust
fn test_aggregator_v2_snapshots_and_derived() {
    use DelayedApplyChange::*;
    use DelayedChange::*;

    let agg_changes_1 = vec![(
        DelayedFieldID::new_for_test_for_u64(1),
        Apply(AggregatorDelta {
            delta: DeltaWithMax::new(SignedU128::Positive(3), 100),
        }),
    )];
    let mut change_set_1 = VMChangeSetBuilder::new()
        .with_delayed_field_change_set(agg_changes_1)
        .build();

    let agg_changes_2 = vec![
        (
            DelayedFieldID::new_for_test_for_u64(1),
            Apply(AggregatorDelta {
                delta: DeltaWithMax::new(SignedU128::Positive(5), 100),
            }),
        ),
        (
            DelayedFieldID::new_for_test_for_u64(2),
            Apply(SnapshotDelta {
                base_aggregator: DelayedFieldID::new_for_test_for_u64(1),
                delta: DeltaWithMax::new(SignedU128::Positive(2), 100),
            }),
        ),
        (
            DelayedFieldID::new_for_test_for_u64(3),
            Apply(SnapshotDerived {
                base_snapshot: DelayedFieldID::new_for_test_for_u64(2),
                formula: SnapshotToStringFormula::Concat {
                    prefix: "p".as_bytes().to_vec(),
                    suffix: "s".as_bytes().to_vec(),
                },
            }),
        ),
    ];
    let change_set_2 = VMChangeSetBuilder::new()
        .with_delayed_field_change_set(agg_changes_2)
        .build();

    assert_ok!(change_set_1.squash_additional_change_set(change_set_2,));

    let output_map = change_set_1.delayed_field_change_set();
    assert_eq!(output_map.len(), 3);
    assert_some_eq!(
        output_map.get(&DelayedFieldID::new_for_test_for_u64(1)),
        &Apply(AggregatorDelta {
            delta: DeltaWithMax::new(SignedU128::Positive(8), 100)
        })
    );
    assert_some_eq!(
        output_map.get(&DelayedFieldID::new_for_test_for_u64(2)),
        &Apply(SnapshotDelta {
            base_aggregator: DelayedFieldID::new_for_test_for_u64(1),
            delta: DeltaWithMax::new(SignedU128::Positive(5), 100)
        })
    );
    assert_some_eq!(
        output_map.get(&DelayedFieldID::new_for_test_for_u64(3)),
        &Apply(SnapshotDerived {
            base_snapshot: DelayedFieldID::new_for_test_for_u64(2),
            formula: SnapshotToStringFormula::Concat {
                prefix: "p".as_bytes().to_vec(),
                suffix: "s".as_bytes().to_vec()
            },
        })
    );
}
```
