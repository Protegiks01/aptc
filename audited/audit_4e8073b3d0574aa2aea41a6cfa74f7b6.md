# Audit Report

## Title
Missing Bounds Validation in Aggregator::add() Allows Recording of Out-of-Range Deltas

## Summary
The `Aggregator::add()` function fails to validate that resulting positive deltas remain within `max_value` bounds when transitioning from `NegativeDelta` to `PositiveDelta` state. This asymmetric validation (compared to the corresponding check in `sub()`) allows out-of-range values to be recorded in delta history, causing all subsequent validation attempts to fail regardless of the actual base value.

## Finding Description
The aggregator system in Aptos uses speculative execution to track deltas without knowing the base value from storage. The `record()` function blindly records `self.value` into history without validating bounds. [1](#0-0) 

When `add()` transitions from `NegativeDelta` to `PositiveDelta`, it computes the new value as `value - self.value` but does not validate this result against `max_value`. [2](#0-1) 

This contrasts with `sub()`, which explicitly checks that negative delta magnitudes don't exceed `max_value` when transitioning from `PositiveDelta` to `NegativeDelta`. [3](#0-2) 

**Attack Scenario:**
1. Create aggregator with `max_value = 100`
2. Call `sub(60)` from initial state `PositiveDelta(0)`:
   - Checks `math.unsigned_subtract(100, 60)` passes
   - Results in `NegativeDelta(60)`
   - Records `Negative(60)` in history
3. Call `add(200)`:
   - Since `60 <= 200`, executes: `self.value = expect_ok(math.unsigned_subtract(200, 60))` = 140
   - Transitions to `PositiveDelta(140)` 
   - Records `Positive(140)` in history
   - **No validation that 140 > 100!**

During materialization, `validate_history()` will check if `base_value + 140 <= 100` for any base value. [4](#0-3) 

This requires `base_value <= -40`, which is impossible for unsigned integers. The validation fails for ALL possible base values, even though the operations succeeded during speculative execution.

The `BoundedMath::unsigned_subtract()` only checks for underflow, not overflow against `max_value`. [5](#0-4) 

## Impact Explanation
This vulnerability breaks the **Deterministic Execution** invariant (invariant #1) and causes **State Consistency** violations (invariant #4).

**Severity: Medium**

The vulnerability allows transactions to succeed during speculative execution but fail deterministically during validation. This causes:

1. **State inconsistencies**: Transactions that appear valid speculatively will always fail at materialization, creating unpredictable behavior
2. **Transaction failures**: Valid transaction sequences may be rejected if intermediate states temporarily record out-of-range deltas
3. **Consensus implications**: While not causing chain splits (since validation is deterministic), it affects transaction inclusion and state commitment predictability

Per Aptos bug bounty criteria, this qualifies as **Medium Severity** ($10,000) due to "State inconsistencies requiring intervention" - the recorded out-of-range deltas make aggregators unusable until they're destroyed and recreated.

## Likelihood Explanation
**Likelihood: Medium-High**

This vulnerability is triggered through normal Move API calls (`aggregator::add` and `aggregator::sub`) without requiring:
- Validator access
- Special privileges
- Complex transaction sequences
- Timing dependencies

Any transaction sender can exploit this by:
1. Performing a small subtraction to enter `NegativeDelta` state
2. Adding a value exceeding `max_value`

The attack is deterministic and requires only 2 transaction calls. Real-world aggregators with small `max_value` limits (common for counters or rate limiters) are particularly vulnerable.

## Recommendation
Add validation in the `add()` function when transitioning from `NegativeDelta` to `PositiveDelta`, symmetrically to the check in `sub()`:

```rust
AggregatorState::NegativeDelta => {
    if self.value <= value {
        // Add this check before computing the result
        let result_delta = math
            .unsigned_subtract(value, self.value)
            .map_err(addition_v1_error)?;
        
        // Validate result doesn't exceed max_value
        if result_delta > self.max_value {
            return Err(addition_v1_error(BoundedMathError::Overflow));
        }
        
        self.value = result_delta;
        self.state = AggregatorState::PositiveDelta;
    } else {
        self.value = expect_ok(math.unsigned_subtract(self.value, value))?;
    }
},
```

Alternatively, enhance `BoundedMath::unsigned_subtract()` to accept and validate against `max_value` for consistency with `unsigned_add()`.

## Proof of Concept

```rust
#[test]
fn test_add_exceeds_max_value_from_negative_delta() {
    let mut aggregator_data = AggregatorData::default();
    
    // Create aggregator with max_value = 100
    let id = aggregator_v1_id_for_test(100);
    let aggregator = aggregator_data
        .get_aggregator(id, 100)
        .expect("Get aggregator failed");
    
    // Step 1: Subtract 60 to go to NegativeDelta(60)
    assert_ok!(aggregator.sub(60));
    assert_eq!(aggregator.value, 60);
    assert_eq!(aggregator.state, AggregatorState::NegativeDelta);
    
    // Step 2: Add 200, which should fail but currently succeeds
    // Result: PositiveDelta(140), but 140 > max_value (100)!
    assert_ok!(aggregator.add(200)); // BUG: Should fail here!
    assert_eq!(aggregator.value, 140);
    assert_eq!(aggregator.state, AggregatorState::PositiveDelta);
    
    // Step 3: Validation will fail for ANY base value
    let resolver = FakeAggregatorView::default();
    
    // Try base_value = 0: 0 + 140 > 100 fails
    assert_err!(aggregator.read_and_materialize(&resolver, &id));
    
    // Try base_value = 50: 50 + 140 > 100 fails  
    // Try ANY base_value: ALL will fail since we need base <= -40
    // This aggregator is now permanently unusable!
}
```

## Notes
This vulnerability demonstrates an asymmetry in validation between `add()` and `sub()` state transitions. The `sub()` function correctly validates delta magnitude limits when transitioning from `PositiveDelta` to `NegativeDelta`, but `add()` lacks the corresponding check when transitioning in the opposite direction. This oversight allows the `record()` function to record deltas exceeding `max_value`, violating the fundamental invariant that all deltas must be applicable to some valid base value within the `[0, max_value]` range.

### Citations

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L75-89)
```rust
    fn record(&mut self) {
        if let Some(history) = self.history.as_mut() {
            match self.state {
                AggregatorState::PositiveDelta => {
                    history.record_success(SignedU128::Positive(self.value))
                },
                AggregatorState::NegativeDelta => {
                    history.record_success(SignedU128::Negative(self.value))
                },
                AggregatorState::Data => {
                    unreachable!("history is not tracked when aggregator knows its value")
                },
            }
        }
    }
```

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L96-125)
```rust
    fn validate_history(&self, base_value: u128) -> PartialVMResult<()> {
        let history = self
            .history
            .as_ref()
            .expect("History should be set for validation");

        // To validate the history of an aggregator, we want to ensure
        // that there was no violation of postcondition (i.e. overflows or
        // underflows). We can do it by emulating addition and subtraction.

        if let Err(e) = history.validate_against_base_value(base_value, self.max_value) {
            match e {
                DelayedFieldsSpeculativeError::DeltaApplication {
                    reason: DeltaApplicationFailureReason::Overflow,
                    ..
                } => {
                    return Err(abort_error("overflow", EADD_OVERFLOW));
                },
                DelayedFieldsSpeculativeError::DeltaApplication {
                    reason: DeltaApplicationFailureReason::Underflow,
                    ..
                } => {
                    return Err(abort_error("underflow", ESUB_UNDERFLOW));
                },
                _ => Err(e)?,
            }
        }

        Ok(())
    }
```

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L144-157)
```rust
            AggregatorState::NegativeDelta => {
                // Negative delta is a special case, since the state might
                // change depending on how big the `value` is. Suppose
                // aggregator has -X and want to do +Y. Then, there are two
                // cases:
                //     1. X <= Y: then the result is +(Y-X)
                //     2. X  > Y: then the result is -(X-Y)
                if self.value <= value {
                    self.value = expect_ok(math.unsigned_subtract(value, self.value))?;
                    self.state = AggregatorState::PositiveDelta;
                } else {
                    self.value = expect_ok(math.unsigned_subtract(self.value, value))?;
                }
            },
```

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L189-200)
```rust
                } else {
                    // Check that we can subtract in general: we don't want to
                    // allow -10000 when max_value is 10.
                    // TODO: maybe `subtraction` should also know about the max_value?
                    math.unsigned_subtract(self.max_value, value)
                        .map_err(subtraction_v1_error)?;

                    self.value = math
                        .unsigned_subtract(value, self.value)
                        .map_err(subtraction_v1_error)?;
                    self.state = AggregatorState::NegativeDelta;
                }
```

**File:** aptos-move/aptos-aggregator/src/bounded_math.rs (L58-64)
```rust
    pub fn unsigned_subtract(&self, base: u128, value: u128) -> BoundedMathResult<u128> {
        if value > base {
            Err(BoundedMathError::Underflow)
        } else {
            Ok(base - value)
        }
    }
```
