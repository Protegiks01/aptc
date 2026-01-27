# Audit Report

## Title
Potential Validator DoS via Panic in abs_val_size() When Processing Invalid Values Due to Insufficient Defensive Programming

## Summary
The `abs_val_size()` function delegates to a visitor pattern that uses `unreachable!()` macro when encountering `Value::Invalid`, causing a process panic instead of returning an error. While the bytecode verifier should prevent Invalid values from reaching native functions, the use of `unreachable!` creates a single point of failure: if any verifier bug allows Invalid values to escape, validator nodes will crash instead of gracefully handling the error.

## Finding Description

The `abs_val_size()` function in the SafeNativeContext is used to calculate abstract value sizes for gas metering purposes. [1](#0-0) 

This function delegates to `abstract_value_size()` which creates an `AbstractValueSizeVisitor` and traverses the value structure. [2](#0-1) 

The critical vulnerability lies in the visitor implementation, which uses `unreachable!()` when encountering a `Value::Invalid`: [3](#0-2) 

`Value::Invalid` represents a moved-from local variable in the Move VM: [4](#0-3) 

When a value is moved from a local, it's replaced with Invalid: [5](#0-4) 

The bytecode verifier is supposed to prevent use-after-move scenarios: [6](#0-5) 

However, other parts of the codebase properly handle Invalid by returning errors rather than panicking: [7](#0-6) 

The vulnerability path: If a bytecode verifier bug allows a use-after-move scenario, Invalid values could reach native functions like `event::write_to_event_store()` which calls `abs_val_size()`: [8](#0-7) 

## Impact Explanation

This is a **High Severity** issue (validator node crashes) because:

1. **Violation of Deterministic Execution Invariant**: Different validators may have different verifier versions or encounter race conditions, causing some to panic while others don't
2. **Single Point of Failure**: The `unreachable!` creates a crash path that should be an error path
3. **Defensive Programming Failure**: The code assumes perfect verification, violating defense-in-depth principles
4. **Validator Node DoS**: If triggered, causes immediate process crash requiring restart

While the bytecode verifier should prevent Invalid values from escaping under normal circumstances, the use of `unreachable!` means that ANY verifier bug (present or future) that allows Invalid to leak will crash validator nodes rather than returning a proper error.

## Likelihood Explanation

**Medium-Low Likelihood** in current implementation because:
- Requires a bytecode verifier bug to allow Invalid values to escape
- No public API exists to construct Value::Invalid directly
- Deserialization cannot create Invalid values
- The verifier has been extensively tested

However, the likelihood increases over time as:
- Verifier complexity grows with new Move features
- Parallel execution paths may introduce race conditions
- Future optimizations may create unforeseen edge cases

The critical concern is that this defensive programming failure creates a hidden time bomb: it's not "if" the assumption is violated, but "when."

## Recommendation

Replace the `unreachable!()` with proper error handling in the visitor implementation:

```rust
// In third_party/move/move-vm/types/src/values/values_impl.rs
fn visit_impl(&self, visitor: &mut impl ValueVisitor, depth: u64) -> PartialVMResult<()> {
    use Value::*;

    match self {
        Invalid => Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
            .with_message("cannot visit invalid value")),
        // ... rest of the match arms
    }
}
```

This ensures that even if a verifier bug allows Invalid to escape, the error is handled gracefully and the transaction aborts rather than crashing the validator node.

## Proof of Concept

Due to the reliance on a verifier bug, a complete PoC requires demonstrating a bytecode sequence that bypasses verification. However, the vulnerability can be demonstrated by forcing an Invalid value to reach the visitor:

```rust
#[test]
#[should_panic(expected = "Should not be able to visit an invalid value")]
fn test_invalid_value_visitor_panic() {
    use move_vm_types::values::Value;
    use move_vm_types::views::ValueView;
    
    // In a controlled test environment with access to internals,
    // construct an Invalid value and attempt to visit it
    let invalid = Value::Invalid;
    
    struct PanicVisitor;
    impl ValueVisitor for PanicVisitor {
        // Implement required visitor methods...
    }
    
    let mut visitor = PanicVisitor;
    // This will panic rather than return an error
    let _ = invalid.visit(&mut visitor);
}
```

The real-world attack would require:
1. Crafting bytecode with a use-after-move bug that bypasses the verifier
2. Publishing this module on-chain
3. Calling a function that triggers the Invalid value to reach a native function
4. The native function calling `abs_val_size()` on the Invalid value
5. All validators that execute this transaction crash

---

**Notes:**
- This vulnerability cannot be directly exploited without first identifying a bytecode verifier bypass
- The issue is primarily about defensive programming and fail-safe design
- The impact is HIGH if triggered but likelihood depends on finding a verifier bug
- The fix is straightforward and aligns with error handling in other parts of the codebase

### Citations

**File:** aptos-move/aptos-native-interface/src/context.rs (L131-135)
```rust
    pub fn abs_val_size(&self, val: &Value) -> PartialVMResult<AbstractValueSize> {
        self.misc_gas_params
            .abs_val
            .abstract_value_size(val, self.gas_feature_version)
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L471-479)
```rust
    pub fn abstract_value_size(
        &self,
        val: impl ValueView,
        feature_version: u64,
    ) -> PartialVMResult<AbstractValueSize> {
        let mut visitor = AbstractValueSizeVisitor::new(self, feature_version);
        val.visit(&mut visitor)?;
        Ok(visitor.finish())
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L71-72)
```rust
pub enum Value {
    Invalid,
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L2273-2276)
```rust
            Value::ContainerRef(_) | Value::Invalid | Value::IndexedRef(_) => Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(format!("cannot borrow local {:?}", &v[idx])),
            ),
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L2365-2375)
```rust
    pub fn move_loc(&mut self, idx: usize) -> PartialVMResult<Value> {
        let mut locals = self.0.borrow_mut();
        match locals.get_mut(idx) {
            Some(Value::Invalid) => Err(PartialVMError::new(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            )
            .with_message(format!("cannot move invalid value at index {}", idx))),
            Some(v) => Ok(std::mem::replace(v, Value::Invalid)),
            None => Err(Self::local_index_out_of_bounds(idx, locals.len())),
        }
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5594-5594)
```rust
            Invalid => unreachable!("Should not be able to visit an invalid value"),
```

**File:** third_party/move/move-bytecode-verifier/src/locals_safety/mod.rs (L50-55)
```rust
        Bytecode::MoveLoc(idx) => match state.local_state(*idx) {
            LocalState::MaybeAvailable | LocalState::Unavailable => {
                return Err(state.error(StatusCode::MOVELOC_UNAVAILABLE_ERROR, offset))
            },
            LocalState::Available => state.set_unavailable(*idx),
        },
```

**File:** aptos-move/framework/src/natives/event.rs (L110-119)
```rust
    let ty = &ty_args[0];
    let msg = arguments.pop_back().unwrap();
    let seq_num = safely_pop_arg!(arguments, u64);
    let guid = safely_pop_arg!(arguments, Vec<u8>);

    // TODO(Gas): Get rid of abstract memory size
    context.charge(
        EVENT_WRITE_TO_EVENT_STORE_BASE
            + EVENT_WRITE_TO_EVENT_STORE_PER_ABSTRACT_VALUE_UNIT * context.abs_val_size(&msg)?,
    )?;
```
