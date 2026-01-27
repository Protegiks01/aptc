# Audit Report

## Title
Double Removal Logic Vulnerability in AggregatorData::remove_aggregator() Leading to Spurious Transaction Failures

## Summary
The `remove_aggregator` function in `AggregatorData` contains a state tracking bug where calling it twice with the same aggregator ID causes incorrect tracking in `destroyed_aggregators`, leading to spurious `SPECULATIVE_EXECUTION_ABORT_ERROR` failures for valid transactions.

## Finding Description

The `remove_aggregator` function has flawed logic that fails to properly handle duplicate removal calls: [1](#0-0) 

**The Bug:** When an aggregator created in the same transaction is removed twice:

1. **First call**: Removes from both `aggregators` and `new_aggregators` (correct - no side effects expected)
2. **Second call**: Since the ID is no longer in `new_aggregators`, it incorrectly adds the ID to `destroyed_aggregators`

This causes a Delete operation to be generated for an aggregator that never existed in storage: [2](#0-1) 

During write operation conversion, attempting to delete a non-existent aggregator triggers an error: [3](#0-2) 

**Attack Vector:** While Move's type system prevents calling `destroy()` twice on the same aggregator value in normal code, this protection can be bypassed through:

1. **Malicious bytecode** that exploits bytecode verifier bugs to copy non-copyable values
2. **VM implementation bugs** that allow using moved values  
3. **Future native function bugs** that could call `remove_aggregator` multiple times

The native destroy function only verifies Move-level type safety, not Rust-level state consistency: [4](#0-3) 

## Impact Explanation

**Severity: Medium** - State inconsistencies requiring intervention

If triggered, this vulnerability causes:

1. **Transaction Failures**: Valid transactions abort with `SPECULATIVE_EXECUTION_ABORT_ERROR` 
2. **Deterministic Execution Violation**: Different nodes may execute differently if bytecode verifier implementations vary
3. **State Inconsistency**: Incorrect tracking in `destroyed_aggregators` breaks aggregator lifecycle invariants

This represents a violation of **Invariant #1 (Deterministic Execution)** and **Invariant #4 (State Consistency)** from the Aptos specification.

## Likelihood Explanation

**Likelihood: Low-Medium**

- **Current Likelihood**: Low - Move's type system prevents this in normal circumstances
- **Future Likelihood**: Medium - Any bytecode verifier bug, VM bug, or future code changes that allow duplicate calls would trigger this
- **Defensive Programming Failure**: The Rust code assumes Move-level guarantees without validating them, violating defense-in-depth principles

## Recommendation

Add idempotency guards to prevent incorrect state tracking on duplicate calls:

```rust
pub fn remove_aggregator(&mut self, id: AggregatorID) {
    // Only process if aggregator exists in current transaction
    if self.aggregators.remove(&id).is_some() {
        // Check if it was created in this transaction
        if self.new_aggregators.remove(&id) {
            // Created and destroyed in same transaction - no side effects
        } else {
            // Existed in storage - mark for deletion
            self.destroyed_aggregators.insert(id);
        }
    }
    // If aggregator not in map, it was already removed - no action needed
}
```

Alternative fix using early return:

```rust
pub fn remove_aggregator(&mut self, id: AggregatorID) {
    if !self.aggregators.contains_key(&id) {
        return; // Already removed, nothing to do
    }
    
    self.aggregators.remove(&id);
    
    if self.new_aggregators.remove(&id) {
        // No storage side-effects for same-transaction create+destroy
    } else {
        self.destroyed_aggregators.insert(id);
    }
}
```

## Proof of Concept

While Move's type system prevents direct exploitation, here's a Rust-level test demonstrating the vulnerability:

```rust
#[test]
fn test_double_remove_causes_incorrect_destroyed_tracking() {
    let mut aggregator_data = AggregatorData::default();
    let id = aggregator_v1_id_for_test(100);
    
    // Create aggregator in this transaction
    aggregator_data.create_new_aggregator(id.clone(), 100);
    
    // Verify initial state
    assert!(aggregator_data.aggregators.contains_key(&id));
    assert!(aggregator_data.new_aggregators.contains(&id));
    assert!(!aggregator_data.destroyed_aggregators.contains(&id));
    
    // First removal (correct behavior)
    aggregator_data.remove_aggregator(id.clone());
    assert!(!aggregator_data.aggregators.contains_key(&id));
    assert!(!aggregator_data.new_aggregators.contains(&id));
    assert!(!aggregator_data.destroyed_aggregators.contains(&id)); // Correct!
    
    // Second removal (BUG: incorrectly adds to destroyed_aggregators)
    aggregator_data.remove_aggregator(id.clone());
    assert!(aggregator_data.destroyed_aggregators.contains(&id)); // INCORRECT!
    
    // This will cause SPECULATIVE_EXECUTION_ABORT_ERROR when converting to change set
    // because we're trying to delete an aggregator that never existed in storage
}
```

To exploit in practice, an attacker would need to find a way to call `remove_aggregator` twice, such as through bytecode that bypasses Move's type system.

## Notes

This is a **defensive programming vulnerability** where the Rust implementation relies entirely on Move-level type safety without validating its own state invariants. While currently difficult to exploit, this represents a latent bug that could be triggered by:

- Bytecode verifier bugs allowing non-copyable value duplication
- VM bugs allowing use-after-move
- Future changes to native functions or aggregator APIs

The fix is simple and adds necessary defensive checks to maintain state consistency regardless of how the function is called.

### Citations

**File:** aptos-move/aptos-aggregator/src/aggregator_v1_extension.rs (L333-345)
```rust
    pub fn remove_aggregator(&mut self, id: AggregatorID) {
        // Aggregator no longer in use during this transaction: remove it.
        self.aggregators.remove(&id);

        if self.new_aggregators.contains(&id) {
            // Aggregator has been created in the same transaction. Therefore, no
            // side-effects.
            self.new_aggregators.remove(&id);
        } else {
            // Otherwise, aggregator has been created somewhere else.
            self.destroyed_aggregators.insert(id);
        }
    }
```

**File:** aptos-move/framework/src/natives/aggregator_natives/context.rs (L136-139)
```rust
        // Additionally, do not forget to delete destroyed values from storage.
        for id in destroyed_aggregators {
            aggregator_v1_changes.insert(id.0, AggregatorChangeV1::Delete);
        }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/write_op_converter.rs (L231-238)
```rust
            (None, Modify(_) | Delete) => {
                // Possible under speculative execution, returning speculative error waiting for re-execution.
                return Err(
                    PartialVMError::new(StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR)
                        .with_message(
                            "When converting write op: updating non-existent value.".to_string(),
                        ),
                );
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator.rs (L114-136)
```rust
fn native_destroy(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert_eq!(args.len(), 1);

    context.charge(AGGREGATOR_DESTROY_BASE)?;

    // First, unpack the struct.
    let aggregator_struct = safely_pop_arg!(args, Struct);
    let (handle, key, _) = unpack_aggregator_struct(aggregator_struct)?;

    // Get aggregator data.
    let aggregator_context = context.extensions().get::<NativeAggregatorContext>();
    let mut aggregator_data = aggregator_context.aggregator_v1_data.borrow_mut();

    // Actually remove the aggregator.
    let id = AggregatorID::new(handle, key);
    aggregator_data.remove_aggregator(id);

    Ok(smallvec![])
}
```
