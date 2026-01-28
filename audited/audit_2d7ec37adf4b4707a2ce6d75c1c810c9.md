# Audit Report

## Title
Integer Underflow in Aggregator Delta Validation Causes Validator Node Panic

## Summary
A critical integer underflow vulnerability exists in the aggregator delta history validation logic during BlockSTM parallel execution. When a transaction adds an extremely large value to an aggregator, the overflow delta is recorded without bounds checking. Later validation performs an unchecked subtraction that panics when `min_overflow_positive_delta > max_value`, potentially crashing validator nodes.

## Finding Description

The vulnerability stems from an inconsistency in how overflow deltas are recorded between two code paths in the BlockSTM aggregator implementation.

**Path 1 (Vulnerable):** When `compute_delayed_field_try_add_delta_outcome_first_time` handles the first aggregator operation in a transaction, it directly records the overflow delta without bounds checking: [1](#0-0) 

The raw delta value (which can be `u128::MAX`) is stored directly via `record_overflow`.

**Path 2 (Correct):** When `compute_delayed_field_try_add_delta_outcome_from_history` handles subsequent operations, it uses `ok_overflow` to filter out deltas exceeding max_value: [2](#0-1) 

This ensures only valid overflow deltas are recorded.

**The Panic:** During validation via `validate_against_base_value`, an unchecked subtraction occurs: [3](#0-2) 

When `min_overflow_positive_delta > max_value`, the expression `max_value - min_overflow_positive_delta` causes integer underflow. Since Aptos compiles with `overflow-checks = true`: [4](#0-3) 

The subtraction panics immediately, terminating the execution thread.

**Attack Vector:** Any user can call the public aggregator API: [5](#0-4) 

With an arbitrary large value, triggering the vulnerable path.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under Aptos Bug Bounty Category 4: "Total Loss of Liveness/Network Availability":

- **Network-wide Impact**: All validators executing the same malicious transaction during BlockSTM parallel execution will hit the identical panic, causing simultaneous crashes across the network.

- **No Privilege Required**: Any transaction sender can exploit this by creating an aggregator and calling `try_add` with `u128::MAX` or any value exceeding the aggregator's `max_value`.

- **Persistent Failure**: If the malicious transaction remains in the mempool or is included in a proposed block, validators will repeatedly crash when attempting to validate it, preventing network progress.

- **Deterministic Crash**: The panic occurs during the validation phase of BlockSTM execution, making it reproducible and affecting all validators uniformly.

## Likelihood Explanation

**Likelihood: High**

1. **Simple Exploitation**: Requires only a single transaction calling `aggregator_v2::try_add` with a large value - no complex setup or timing requirements.

2. **Publicly Accessible**: The `create_aggregator` and `try_add` functions are public APIs accessible to any Move module: [6](#0-5) 

3. **No Detection**: The transaction appears valid during mempool validation and only triggers the panic during parallel execution validation.

4. **Common Code Path**: Aggregators are used throughout the Aptos framework for parallel transaction processing, making this a frequently exercised path.

## Recommendation

Add bounds checking in `compute_delayed_field_try_add_delta_outcome_first_time` to match the behavior of `compute_delayed_field_try_add_delta_outcome_from_history`:

```rust
match delta {
    SignedU128::Positive(delta_value) => {
        let overflow_delta = expect_ok(ok_overflow(
            math.unsigned_add(*delta_value, &SignedU128::Positive(0)),
        ))?;
        if let Some(overflow_delta) = overflow_delta {
            history.record_overflow(overflow_delta);
        }
    },
    // Similar for Negative case
}
```

Alternatively, add a bounds check in `validate_against_base_value` before the subtraction:

```rust
if let Some(min_overflow_positive_delta) = self.min_overflow_positive_delta {
    if min_overflow_positive_delta <= max_value 
        && base_value <= max_value - min_overflow_positive_delta {
        return Err(DelayedFieldsSpeculativeError::DeltaApplication { ... });
    }
}
```

## Proof of Concept

```move
module attacker::exploit {
    use aptos_framework::aggregator_v2;
    
    public entry fun trigger_panic() {
        // Create aggregator with small max_value
        let agg = aggregator_v2::create_aggregator<u128>(1000);
        
        // Try to add u128::MAX - triggers overflow recording without bounds check
        let _ = aggregator_v2::try_add(&mut agg, 340282366920938463463374607431768211455);
        
        // During validation, max_value (1000) - min_overflow_positive_delta (u128::MAX)
        // causes integer underflow panic
    }
}
```

## Notes

The vulnerability specifically affects the **first-time execution path** for aggregator operations. The inconsistency between the two code paths (`compute_delayed_field_try_add_delta_outcome_first_time` vs `compute_delayed_field_try_add_delta_outcome_from_history`) indicates this is an implementation oversight rather than intentional design. The `ok_overflow` helper function exists precisely to handle this case but is not used in the first-time path.

### Citations

**File:** aptos-move/block-executor/src/view.rs (L316-323)
```rust
                let overflow_delta = expect_ok(ok_overflow(
                    math.unsigned_add_delta(*delta_value, base_delta),
                ))?;

                // We don't need to record the value if it overflowed.
                if let Some(overflow_delta) = overflow_delta {
                    history.record_overflow(overflow_delta);
                }
```

**File:** aptos-move/block-executor/src/view.rs (L357-363)
```rust
    let result = if math
        .unsigned_add_delta(base_aggregator_value, delta)
        .is_err()
    {
        match delta {
            SignedU128::Positive(delta_value) => {
                history.record_overflow(*delta_value);
```

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L174-182)
```rust
        if let Some(min_overflow_positive_delta) = self.min_overflow_positive_delta {
            if base_value <= max_value - min_overflow_positive_delta {
                return Err(DelayedFieldsSpeculativeError::DeltaApplication {
                    base_value,
                    max_value,
                    delta: SignedU128::Positive(min_overflow_positive_delta),
                    reason: DeltaApplicationFailureReason::ExpectedOverflow,
                });
            }
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** aptos-move/framework/aptos-framework/sources/aggregator_v2/aggregator_v2.move (L77-77)
```text
    public native fun create_aggregator<IntElement: copy + drop>(max_value: IntElement): Aggregator<IntElement>;
```

**File:** aptos-move/framework/aptos-framework/sources/aggregator_v2/aggregator_v2.move (L102-102)
```text
    public native fun try_add<IntElement>(self: &mut Aggregator<IntElement>, value: IntElement): bool;
```
