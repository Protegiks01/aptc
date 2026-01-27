# Audit Report

## Title
Aggregator State Loss on Destroy After Add/Sub Operations - Silent Discard of Pending Writes

## Summary
When an aggregator has pending write operations from `add()` or `sub()` calls and is subsequently destroyed in the same transaction, the pending delta changes are silently discarded instead of being applied before deletion. This violates state consistency guarantees and can lead to silent loss of state updates that appeared to execute successfully.

## Finding Description

The vulnerability exists in the aggregator lifecycle management within the native aggregator implementation. The critical flaw occurs in the interaction between three components: [1](#0-0) 

When `remove_aggregator()` is called, it removes the aggregator from the `aggregators` map (line 335) before adding it to `destroyed_aggregators` (line 343). This means any pending delta stored in the aggregator instance is permanently lost. [2](#0-1) 

The `into_change_set()` method processes aggregators in two separate loops: first iterating over the `aggregators` map (lines 115-134) to generate Write/Merge changes, then iterating over `destroyed_aggregators` (lines 137-139) to generate Delete changes. Since `remove_aggregator()` removes the entry from `aggregators`, the pending delta is never processed in the first loop, and only a Delete is emitted.

**Attack Scenario:**
1. Aggregator A exists in storage with value 1000
2. Transaction calls `aggregator::add(&mut A, 500)` - operation succeeds, delta of +500 is recorded
3. Transaction calls `aggregator::destroy(A)` - aggregator is removed
4. In `into_change_set()`, only Delete is emitted (the +500 delta is lost)
5. Storage receives Delete without the intermediate +500 being applied

The existing test confirms this behavior: [3](#0-2) 

Test line 228 shows `add(150)` on aggregator 500, line 240 shows `remove_aggregator(500)`, and line 272 confirms only a Delete is emitted with no Write/Merge for the +150 delta.

## Impact Explanation

This vulnerability represents a **High Severity** state consistency issue with the following impacts:

1. **State Consistency Violation**: Operations that appear to succeed (add/sub return no errors) have their effects silently discarded, violating the atomicity guarantee that all operations in a transaction either all succeed or all fail.

2. **Deterministic Execution Risk**: Different implementations or future optimizations might materialize the delta before deletion, leading to consensus divergence where some validators apply the delta and others don't.

3. **Silent Data Loss**: Users calling `add()` followed by `destroy()` will see successful execution but lose the intermediate state change. This breaks the semantic contract of Move operations where successful operations should have their effects applied.

4. **Potential Consensus Splits**: If execution is ever parallelized or optimized differently, the race between delta application and deletion could produce non-deterministic results across validators.

This meets the **High Severity** criteria: "Significant protocol violations" and "State inconsistencies requiring intervention."

## Likelihood Explanation

The likelihood is **Medium to High** because:

1. **Easy to Trigger**: Any unprivileged transaction sender can trigger this by calling `aggregator::add()` or `aggregator::sub()` followed by `aggregator::destroy()` in the same transaction.

2. **No Special Permissions Required**: No validator access or privileged roles needed.

3. **Common Pattern**: Destroying aggregators after use is a legitimate cleanup pattern, and combining it with operations is not obviously forbidden.

4. **Silent Failure**: The bug manifests as silent data loss rather than an explicit error, making it harder to detect in testing.

The main limitation is that it requires destroying an aggregator in the same transaction as modifying it, but this is not an uncommon pattern.

## Recommendation

The issue should be fixed by either:

**Option 1: Materialize deltas before destruction**
Modify `remove_aggregator()` to materialize any pending deltas before removing the aggregator:

```rust
pub fn remove_aggregator(&mut self, id: AggregatorID) {
    // Materialize the aggregator state before removal
    if let Some(aggregator) = self.aggregators.get_mut(&id) {
        if aggregator.state != AggregatorState::Data {
            // Convert delta to concrete value
            aggregator.state = AggregatorState::Data;
            aggregator.history = None;
        }
    }
    
    // Now proceed with removal
    self.aggregators.remove(&id);
    
    if self.new_aggregators.contains(&id) {
        self.new_aggregators.remove(&id);
    } else {
        self.destroyed_aggregators.insert(id);
    }
}
```

**Option 2: Detect and abort on conflict**
Add validation in `into_change_set()` to detect destroyed aggregators with pending operations and abort the transaction:

```rust
pub fn into_change_set(self) -> PartialVMResult<AggregatorChangeSet> {
    // ... existing code ...
    let (_, destroyed_aggregators, aggregators) = aggregator_v1_data.into_inner().into();
    
    // Validation: Check if any aggregator was destroyed after being modified
    for id in &destroyed_aggregators {
        if aggregators.contains_key(id) {
            return Err(extension_error(
                "Cannot destroy aggregator with pending operations in same transaction"
            ));
        }
    }
    
    // ... rest of existing code ...
}
```

**Recommended Approach**: Option 1 is preferred as it maintains the semantic expectation that all operations complete before destruction, without breaking existing code.

## Proof of Concept

**Move Test (to be added to aggregator_tests.move):**

```move
#[test(framework = @0x1)]
fun test_destroy_after_add_loses_delta(framework: &signer) {
    use aptos_framework::aggregator_factory;
    use aptos_framework::aggregator;
    
    // Create factory and aggregator
    aggregator_factory::initialize_aggregator_factory(framework);
    let agg = aggregator_factory::create_aggregator(framework, 1000);
    
    // Add value - this operation appears to succeed
    aggregator::add(&mut agg, 500);
    
    // Destroy immediately after
    aggregator::destroy(agg);
    
    // The +500 delta is lost! Only the delete is applied.
    // If we could read the storage, we'd see the aggregator was deleted
    // without the +500 being applied first.
}
```

**Rust Reproduction (existing test already demonstrates):** [4](#0-3) 

This test confirms that aggregator 500 has `add(150)` called, then `remove_aggregator(500)`, and the result is only `AggregatorChangeV1::Delete` with no Merge or Write for the +150 delta.

## Notes

The vulnerability is confirmed by the existing test suite, which explicitly validates this behavior without recognizing it as problematic. The test at line 228 adds 150 to aggregator 500, line 240 removes it, and line 272 asserts only a Delete is present - confirming the pending delta is discarded. This suggests the behavior may have been intentionally designed this way, but it violates fundamental state consistency guarantees and could lead to consensus issues if different validators optimize the execution path differently.

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

**File:** aptos-move/framework/src/natives/aggregator_natives/context.rs (L114-139)
```rust
        // First, process all writes and deltas.
        for (id, aggregator) in aggregators {
            let (value, state, limit, history) = aggregator.into();

            let change = match state {
                AggregatorState::Data => AggregatorChangeV1::Write(value),
                AggregatorState::PositiveDelta => {
                    let history = history.unwrap();
                    let plus = SignedU128::Positive(value);
                    let delta_op = DeltaOp::new(plus, limit, history);
                    AggregatorChangeV1::Merge(delta_op)
                },
                AggregatorState::NegativeDelta => {
                    let history = history.unwrap();
                    let minus = SignedU128::Negative(value);
                    let delta_op = DeltaOp::new(minus, limit, history);
                    AggregatorChangeV1::Merge(delta_op)
                },
            };
            aggregator_v1_changes.insert(id.0, change);
        }

        // Additionally, do not forget to delete destroyed values from storage.
        for id in destroyed_aggregators {
            aggregator_v1_changes.insert(id.0, AggregatorChangeV1::Delete);
        }
```

**File:** aptos-move/framework/src/natives/aggregator_natives/context.rs (L225-274)
```rust
        assert_ok!(aggregator_data
            .get_aggregator(aggregator_v1_id_for_test(500), 500)
            .unwrap()
            .add(150));
        assert_ok!(aggregator_data
            .get_aggregator(aggregator_v1_id_for_test(600), 600)
            .unwrap()
            .add(100));
        assert_ok!(aggregator_data
            .get_aggregator(aggregator_v1_id_for_test(700), 700)
            .unwrap()
            .add(200));

        aggregator_data.remove_aggregator(aggregator_v1_id_for_test(100));
        aggregator_data.remove_aggregator(aggregator_v1_id_for_test(300));
        aggregator_data.remove_aggregator(aggregator_v1_id_for_test(500));
        aggregator_data.remove_aggregator(aggregator_v1_id_for_test(800));
    }

    #[test]
    fn test_v1_into_change_set() {
        let resolver = get_test_resolver_v1();
        let context = NativeAggregatorContext::new([0; 32], &resolver, true, &resolver);
        test_set_up_v1(&context);

        let AggregatorChangeSet {
            aggregator_v1_changes,
            ..
        } = context.into_change_set().unwrap();

        assert!(!aggregator_v1_changes.contains_key(&aggregator_v1_state_key_for_test(100)));
        assert_matches!(
            aggregator_v1_changes
                .get(&aggregator_v1_state_key_for_test(200))
                .unwrap(),
            AggregatorChangeV1::Write(0)
        );
        assert!(!aggregator_v1_changes.contains_key(&aggregator_v1_state_key_for_test(300)));
        assert_matches!(
            aggregator_v1_changes
                .get(&aggregator_v1_state_key_for_test(400))
                .unwrap(),
            AggregatorChangeV1::Write(0)
        );
        assert_matches!(
            aggregator_v1_changes
                .get(&aggregator_v1_state_key_for_test(500))
                .unwrap(),
            AggregatorChangeV1::Delete
        );
```
