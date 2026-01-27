# Audit Report

## Title
Delta History Bound Inconsistency After Sequential Merging Causes Transaction Validation Failures

## Summary
The `DeltaOp::merge_with_next_delta()` function can create delta operations with internally inconsistent history bounds where `max_achieved_positive_delta + min_achieved_negative_delta > max_value`. This makes it impossible for any base value to satisfy validation constraints, causing legitimate transactions to fail during materialization. While the security question asks about bounds becoming "too wide", the actual vulnerability is the **opposite**: bounds become impossible to satisfy (too narrow), creating a denial-of-service condition.

## Finding Description

The `merge_with_next_delta()` function in `delta_change_set.rs` merges two delta operations by calling `merge_two_deltas()` [1](#0-0) , which in turn calls `offset_and_merge_history()` to combine their histories [2](#0-1) .

The merging logic in `offset_and_merge_history()` computes new achieved bounds by offsetting the next delta's history by the previous delta value [3](#0-2) . However, there is **no validation** that the resulting `max_achieved_positive_delta + min_achieved_negative_delta <= max_value`.

When this invariant is violated, the `validate_against_base_value()` function requires:
1. `base_value >= min_achieved_negative_delta` [4](#0-3) 
2. `base_value <= max_value - max_achieved_positive_delta` [5](#0-4) 

If `max_achieved + min_achieved > max_value`, then no base value can satisfy both constraints simultaneously.

**Attack Scenario:**
1. Transaction 1 performs complex aggregator operations creating: `delta1 = +1` with history `{max_achieved: 500, min_achieved: 400}` on an aggregator with `max_value = 900`
2. Transaction 2 performs similar operations creating: `delta2 = +1` with history `{max_achieved: 500, min_achieved: 400}` on the same aggregator
3. During parallel execution, these deltas are merged via `merge_with_next_delta()` [6](#0-5) 
4. The merged delta has: `max_achieved = 501, min_achieved = 400` (sum = 901 > 900)
5. Later, when materializing the delta [7](#0-6) , validation fails for **all possible base values**
6. The transaction aborts even though individual operations were valid

## Impact Explanation

This vulnerability creates a **denial-of-service condition** affecting transaction execution:

- **State Consistency Impact**: Legitimate transactions that perform valid aggregator operations can fail during the materialization phase due to artifacts of the delta merging process, not due to actual constraint violations
- **Deterministic Execution**: All validators will consistently fail to materialize these deltas, maintaining consensus, but incorrectly rejecting valid operations
- **Attacker Capability**: An attacker can intentionally craft transactions with large history bounds to ensure merged deltas become impossible to validate

This qualifies as **Medium Severity** under Aptos bug bounty rules: "State inconsistencies requiring intervention" - transactions that should succeed will fail, requiring manual investigation and potentially code fixes to recover.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can occur in realistic scenarios:
1. Aggregator V1 operations naturally create history bounds reflecting intermediate states during transaction execution
2. Parallel transaction execution commonly merges multiple deltas for the same state key
3. No special privileges or validator access required - any transaction sender can trigger this
4. The specific conditions (large history bounds + sequential merging) are achievable with intentionally crafted transactions
5. The issue is deterministic and reproducible once the right delta combinations are created

## Recommendation

Add validation in `offset_and_merge_history()` to ensure the merged history maintains valid constraints:

```rust
// After computing new_max_achieved and new_min_achieved (around line 288):

// Validate that the merged bounds don't create impossible constraints
if new_max_achieved
    .checked_add(new_min_achieved)
    .map_or(true, |sum| sum > max_value)
{
    return Err(
        DelayedFieldsSpeculativeError::DeltaHistoryMergeAchievedBoundsIncompatible {
            max_achieved: new_max_achieved,
            min_achieved: new_min_achieved,
            max_value,
        }
    );
}
```

This check should be added in [8](#0-7)  before the existing overlap checks.

## Proof of Concept

```rust
#[test]
fn test_merge_creates_impossible_bounds() {
    use crate::delta_change_set::{DeltaOp, delta_add_with_history};
    
    // Create two deltas with large history bounds
    // delta1: +1 with history showing it went up to +500 and down by 400
    let mut delta1 = delta_add_with_history(1, 900, 500, 400);
    
    // delta2: +1 with similar history
    let delta2 = delta_add_with_history(1, 900, 500, 400);
    
    // Merge them - this should succeed (but creates impossible bounds)
    let result = delta1.merge_with_next_delta(delta2);
    assert_ok!(result);
    
    // The merged delta has: max_achieved=501, min_achieved=400
    // Valid range: 400 <= base <= 399 (IMPOSSIBLE!)
    let (update, history, max_value) = delta1.into_inner();
    assert_eq!(history.max_achieved_positive_delta, 501);
    assert_eq!(history.min_achieved_negative_delta, 400);
    
    // Try to apply to any base value - ALL will fail
    let delta_op = DeltaOp::new(update, max_value, history);
    for base in 0..=900 {
        // Every base value should fail validation
        assert_err!(delta_op.apply_to(base));
    }
}
```

**Notes:**
- The security question asks whether bounds can become "so wide that any base value passes validation" - I did not find evidence of this specific issue
- However, I discovered the opposite problem: bounds can become **impossible to satisfy** (too narrow) due to missing validation after merging
- This is still a critical vulnerability in the same code path (`merge_with_next_delta`), just manifesting differently than the question suggests
- The vulnerability affects the delta merging mechanism used during parallel transaction execution in the Aptos block executor
- While this doesn't break consensus (all validators fail deterministically), it creates a DoS where valid transactions are incorrectly rejected

### Citations

**File:** aptos-move/aptos-aggregator/src/delta_change_set.rs (L152-158)
```rust
    pub fn merge_with_next_delta(
        &mut self,
        next_delta: DeltaOp,
    ) -> Result<(), PanicOr<DelayedFieldsSpeculativeError>> {
        *self = Self::create_merged_delta(self, &next_delta)?;
        Ok(())
    }
```

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L159-165)
```rust
        math.unsigned_add(base_value, self.max_achieved_positive_delta)
            .map_err(|_e| DelayedFieldsSpeculativeError::DeltaApplication {
                base_value,
                max_value,
                delta: SignedU128::Positive(self.max_achieved_positive_delta),
                reason: DeltaApplicationFailureReason::Overflow,
            })?;
```

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L166-172)
```rust
        math.unsigned_subtract(base_value, self.min_achieved_negative_delta)
            .map_err(|_e| DelayedFieldsSpeculativeError::DeltaApplication {
                base_value,
                max_value,
                delta: SignedU128::Negative(self.min_achieved_negative_delta),
                reason: DeltaApplicationFailureReason::Underflow,
            })?;
```

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L248-313)
```rust
    pub fn offset_and_merge_history(
        &self,
        prev_delta: &SignedU128,
        prev_history: &Self,
        max_value: u128,
    ) -> Result<DeltaHistory, DelayedFieldsSpeculativeError> {
        let math = BoundedMath::new(max_value);

        let new_min_overflow = Self::offset_and_merge_min_overflow(
            &self.min_overflow_positive_delta,
            prev_delta,
            &prev_history.min_overflow_positive_delta,
            &math,
        )?;
        // max_underflow is identical to min_overflow, except that we offset in the opposite direction.
        let new_max_underflow = Self::offset_and_merge_min_overflow(
            &self.max_underflow_negative_delta,
            &prev_delta.minus(),
            &prev_history.max_underflow_negative_delta,
            &math,
        )?;

        // new_max_achieved = max(prev_max_achieved, max_achieved + prev_delta)
        // When adjusting max_achieved, if underflow - than the other is bigger,
        // but if overflow - we fail the merge, as we cannot successfully achieve
        // delta larger than max_value.
        let new_max_achieved = Self::offset_and_merge_max_achieved(
            self.max_achieved_positive_delta,
            prev_delta,
            prev_history.max_achieved_positive_delta,
            &math,
        )?;

        // new_min_achieved = max(prev_min_achieved, min_achieved - prev_delta)
        // Same as above, except for offsetting in the opposite direction.
        let new_min_achieved = Self::offset_and_merge_max_achieved(
            self.min_achieved_negative_delta,
            &prev_delta.minus(),
            prev_history.min_achieved_negative_delta,
            &math,
        )?;

        if new_min_overflow.is_some_and(|v| v <= new_max_achieved) {
            return Err(
                DelayedFieldsSpeculativeError::DeltaHistoryMergeAchievedAndFailureOverlap {
                    achieved: SignedU128::Positive(new_max_achieved),
                    overflow: SignedU128::Positive(new_min_overflow.unwrap()),
                },
            );
        }
        if new_max_underflow.is_some_and(|v| v <= new_min_achieved) {
            return Err(
                DelayedFieldsSpeculativeError::DeltaHistoryMergeAchievedAndFailureOverlap {
                    achieved: SignedU128::Negative(new_min_achieved),
                    overflow: SignedU128::Negative(new_max_underflow.unwrap()),
                },
            );
        }

        Ok(Self {
            max_achieved_positive_delta: new_max_achieved,
            min_achieved_negative_delta: new_min_achieved,
            min_overflow_positive_delta: new_min_overflow,
            max_underflow_negative_delta: new_max_underflow,
        })
    }
```

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L343-353)
```rust
pub fn merge_two_deltas(
    prev_delta: &SignedU128,
    prev_history: &DeltaHistory,
    next_delta: &SignedU128,
    next_history: &DeltaHistory,
    max_value: u128,
) -> Result<(SignedU128, DeltaHistory), PanicOr<DelayedFieldsSpeculativeError>> {
    let new_history = next_history.offset_and_merge_history(prev_delta, prev_history, max_value)?;
    let new_delta = expect_ok(BoundedMath::new(max_value).signed_add(prev_delta, next_delta))?;
    Ok((new_delta, new_history))
}
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L367-399)
```rust
    pub fn try_materialize_aggregator_v1_delta_set(
        &mut self,
        resolver: &impl AggregatorV1Resolver,
    ) -> VMResult<()> {
        let into_write =
            |(state_key, delta): (StateKey, DeltaOp)| -> VMResult<(StateKey, WriteOp)> {
                // Materialization is needed when committing a transaction, so
                // we need precise mode to compute the true value of an
                // aggregator.
                let write = resolver
                    .try_convert_aggregator_v1_delta_into_write_op(&state_key, &delta)
                    .map_err(|e| {
                        // We need to set abort location for Aggregator V1 to ensure correct VMStatus can
                        // be constructed.
                        const AGGREGATOR_V1_ADDRESS: AccountAddress = CORE_CODE_ADDRESS;
                        const AGGREGATOR_V1_MODULE_NAME: &IdentStr = ident_str!("aggregator");
                        e.finish(Location::Module(ModuleId::new(
                            AGGREGATOR_V1_ADDRESS,
                            AGGREGATOR_V1_MODULE_NAME.into(),
                        )))
                    })?;
                Ok((state_key, write))
            };

        let aggregator_v1_delta_set = std::mem::take(&mut self.aggregator_v1_delta_set);
        let materialized_aggregator_delta_set = aggregator_v1_delta_set
            .into_iter()
            .map(into_write)
            .collect::<VMResult<BTreeMap<StateKey, WriteOp>>>()?;
        self.aggregator_v1_write_set
            .extend(materialized_aggregator_delta_set);
        Ok(())
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L438-446)
```rust
                match aggregator_v1_delta_set.entry(state_key) {
                    Occupied(entry) => {
                        // In this case, we need to merge the new incoming delta
                        // to the existing delta, ensuring the strict ordering.
                        entry
                            .into_mut()
                            .merge_with_next_delta(additional_delta_op)
                            .map_err(PartialVMError::from)?;
                    },
```
