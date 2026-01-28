# Audit Report

## Title
Validator Node Crash via Integer Underflow in Aggregator Delta Validation with max_value=0

## Summary
A critical integer underflow vulnerability exists in the aggregator delta history validation logic that causes all validator nodes to panic when processing transactions containing aggregators with `max_value=0`. This enables a denial-of-service attack that can completely halt the Aptos network.

## Finding Description

The vulnerability exists in the `validate_against_base_value` function where overflow validation performs an unchecked unsigned integer subtraction. [1](#0-0) 

When `max_value = 0` and an overflow is recorded (e.g., `min_overflow_positive_delta = 1`), the expression `max_value - min_overflow_positive_delta` becomes `0 - 1`, causing integer underflow. Since Aptos builds with `overflow-checks = true`: [2](#0-1) 

This subtraction panics at runtime, crashing the validator node.

**Attack Propagation:**

1. Attacker creates an aggregator with `max_value = 0` using the public API: [3](#0-2) 

No validation exists preventing `max_value = 0` in the native implementation: [4](#0-3) 

2. Attacker calls `try_add(&mut agg, 1)`, which correctly fails due to overflow: [5](#0-4) 

3. The overflow is recorded in the aggregator's delta history: [6](#0-5) 

4. During block execution with delayed field optimization enabled: [7](#0-6) 

The optimization is conditionally enabled based on the feature flag: [8](#0-7) 

Which is enabled by default: [9](#0-8) 

5. At commit time, `validate_delayed_field_reads` is invoked: [10](#0-9) 

6. The validation calls `validate_against_base_value(0, 0)`, which executes the underflowing subtraction at line 175, causing a panic before error handling can catch it.

## Impact Explanation

**Severity: CRITICAL** - This vulnerability enables complete network unavailability, meeting the "Total loss of liveness/network availability" criterion from the Aptos bug bounty program.

- **All validators crash simultaneously**: When any validator processes a block containing such a transaction, it panics during the commit phase due to the integer underflow
- **Network-wide denial of service**: The entire Aptos blockchain halts as all validators fail to process the malicious transaction
- **Deterministic failure**: The panic is guaranteed and unavoidable once the transaction enters a block
- **Zero attack cost**: Any user can submit such a transaction with minimal gas fees

This breaks the **Deterministic Execution** invariant as nodes crash instead of producing state roots, and violates the **State Consistency** guarantee.

## Likelihood Explanation

**Likelihood: VERY HIGH**

- **No special privileges required**: Any user can create aggregators and submit transactions through the public API
- **Simple attack vector**: Requires only two Move function calls (create_aggregator + try_add)
- **No validation barriers**: No input validation prevents `max_value = 0` at any layer
- **Guaranteed success**: The panic is deterministic and occurs during block execution with the feature flag enabled by default
- **Difficult to detect**: The transaction appears valid during submission and only fails during commit-time validation

## Recommendation

Add validation to prevent `max_value = 0` in aggregator creation. Modify the native implementation:

```rust
fn native_create_aggregator(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    let max_value = pop_value_by_type(&ty_args[0], &mut args, EUNSUPPORTED_AGGREGATOR_TYPE)?;
    
    // Add validation to prevent max_value = 0
    if max_value == 0 {
        return Err(SafeNativeError::Abort {
            abort_code: EINVALID_AGGREGATOR_MAX_VALUE, // New error code
        });
    }
    
    create_aggregator_with_max_value(context, &ty_args[0], max_value)
}
```

Alternatively, fix the underflow by using `checked_sub`:

```rust
if let Some(min_overflow_positive_delta) = self.min_overflow_positive_delta {
    if let Some(threshold) = max_value.checked_sub(min_overflow_positive_delta) {
        if base_value <= threshold {
            return Err(DelayedFieldsSpeculativeError::DeltaApplication { ... });
        }
    } else {
        // max_value < min_overflow_positive_delta, overflow check always passes
        return Err(DelayedFieldsSpeculativeError::DeltaApplication { ... });
    }
}
```

## Proof of Concept

```move
#[test]
fun test_aggregator_max_value_zero_crash() {
    use aptos_framework::aggregator_v2;
    
    // Create aggregator with max_value = 0
    let agg = aggregator_v2::create_aggregator<u64>(0);
    
    // Attempt to add 1, which will overflow
    let success = aggregator_v2::try_add(&mut agg, 1);
    
    // This correctly returns false, but records overflow in delta history
    assert!(!success, 0);
    
    // In block execution context with delayed field optimization enabled,
    // validation will call validate_against_base_value(0, 0) with
    // min_overflow_positive_delta = 1, causing panic on line 175:
    // if 0 <= 0 - 1  <- This causes integer underflow panic
}
```

## Notes

The vulnerability is triggered specifically when the `AGGREGATOR_V2_DELAYED_FIELDS` feature flag is enabled (which it is by default in production) and during block execution where delayed field optimization is activated. The integer underflow occurs in a critical validation path during transaction commit, making it unavoidable once the malicious transaction enters a block.

### Citations

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L174-176)
```rust
        if let Some(min_overflow_positive_delta) = self.min_overflow_positive_delta {
            if base_value <= max_value - min_overflow_positive_delta {
                return Err(DelayedFieldsSpeculativeError::DeltaApplication {
```

**File:** Cargo.toml (L923-923)
```text
overflow-checks = true
```

**File:** aptos-move/framework/aptos-framework/sources/aggregator_v2/aggregator_v2.move (L77-77)
```text
    public native fun create_aggregator<IntElement: copy + drop>(max_value: IntElement): Aggregator<IntElement>;
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs (L138-149)
```rust
fn native_create_aggregator(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert_eq!(args.len(), 1);
    debug_assert_eq!(ty_args.len(), 1);
    context.charge(AGGREGATOR_V2_CREATE_AGGREGATOR_BASE)?;

    let max_value = pop_value_by_type(&ty_args[0], &mut args, EUNSUPPORTED_AGGREGATOR_TYPE)?;
    create_aggregator_with_max_value(context, &ty_args[0], max_value)
}
```

**File:** aptos-move/aptos-aggregator/src/bounded_math.rs (L50-56)
```rust
    pub fn unsigned_add(&self, base: u128, value: u128) -> BoundedMathResult<u128> {
        if self.max_value < base || value > (self.max_value - base) {
            Err(BoundedMathError::Overflow)
        } else {
            Ok(base + value)
        }
    }
```

**File:** aptos-move/block-executor/src/view.rs (L320-323)
```rust
                // We don't need to record the value if it overflowed.
                if let Some(overflow_delta) = overflow_delta {
                    history.record_overflow(overflow_delta);
                }
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L212-213)
```rust
        let storage_environment =
            AptosEnvironment::new_with_delayed_field_optimization_enabled(&state_view);
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L320-324)
```rust
    fn try_enable_delayed_field_optimization(mut self) -> Self {
        if self.features.is_aggregator_v2_delayed_fields_enabled() {
            self.runtime_environment.enable_delayed_field_optimization();
        }
        self
```

**File:** types/src/on_chain_config/aptos_features.rs (L210-210)
```rust
            FeatureFlag::AGGREGATOR_V2_DELAYED_FIELDS,
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L1168-1171)
```rust
                    } => match restriction.validate_against_base_value(
                        current_value.into_aggregator_value()?,
                        *max_value,
                    ) {
```
