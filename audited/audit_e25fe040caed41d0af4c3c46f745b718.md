# Audit Report

## Title
Type System Unsoundness in Generic Comparison Rewriter Allows Runtime Failure on Aggregator Types

## Summary
The Move Compiler v2's comparison operation rewriter (`cmp_rewriter.rs`) blindly transforms generic comparison operations to use `std::cmp::compare<T>` without verifying that the type parameter `T` can actually be compared at runtime. This creates a type soundness violation where code that passes type checking will deterministically fail at runtime when comparing types containing `DelayedFieldID` values (such as `Aggregator<IntElement>` structs).

## Finding Description

The vulnerability exists in the interaction between three components:

**1. Type System Permits Unrestricted Generic Comparisons**

For language version V2.2+, the type system declares comparison operations with no constraints on the type parameter: [1](#0-0) 

This allows comparison operations on **all types** including those containing aggregators, with no trait bounds or restrictions.

**2. CMP Rewriter Blindly Transforms Non-Integer Comparisons**

The comparison rewriter transforms all non-integer comparison operations to use `std::cmp::compare`: [2](#0-1) 

The only check performed is whether the type is numeric: [3](#0-2) 

For non-numeric types like `Aggregator<u64>`, the rewriter proceeds to transform `a < b` into `std::cmp::compare<Aggregator<u64>>(&a, &b).is_lt()`.

**3. Runtime Comparison Fails on DelayedFieldID**

The native implementation of `std::cmp::compare` calls `Value::compare_with_depth`, which explicitly rejects comparison of `DelayedFieldID` values: [4](#0-3) 

**4. Aggregators Contain DelayedFieldID at Runtime**

When delayed field optimization is enabled, `Aggregator<IntElement>` structs store `DelayedFieldID` in their `value` field: [5](#0-4) 

**Attack Vector:**

An attacker (or unsuspecting user) can write and deploy a Move module that compares aggregator values:

```move
public fun compare_aggregators(agg1: Aggregator<u64>, agg2: Aggregator<u64>): bool {
    agg1 < agg2  // Compiles successfully, fails at runtime
}
```

The code passes all compilation checks but will fail with `VM_EXTENSION_ERROR` when executed with delayed field optimization enabled.

**Documentation confirms the issue:**

The runtime checks test file explicitly documents that aggregators cannot be compared: [6](#0-5) 

However, tests only cover equality operations (`==`, `!=`), not ordering operations (`<`, `<=`, `>`, `>=`): [7](#0-6) 

## Impact Explanation

This vulnerability breaks the **type soundness** guarantee of the Move language and violates the **Deterministic Execution** invariant. Specifically:

1. **Type Soundness Violation**: The type system promises that well-typed programs will execute successfully (barring runtime conditions like out-of-gas). This bug allows code to pass type checking but fail deterministically at runtime.

2. **Transaction Execution Failures**: Users deploying modules with aggregator comparisons will experience unexpected transaction failures with cryptic `VM_EXTENSION_ERROR` messages.

3. **Protocol Violation**: This represents a **significant protocol violation** as defined in the High Severity category - the compiler-runtime mismatch undermines the safety guarantees of the Move language.

While this does not lead to fund loss or consensus divergence (all nodes fail identically), it represents a fundamental correctness issue in the compiler that can cause production code failures.

**Severity: High** - Significant protocol violation through type system unsoundness.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
1. User writes code comparing aggregator types or structs containing aggregators
2. Code is compiled with language version V2.2+
3. Delayed field optimization is enabled at runtime

While developers are likely to use the specialized `is_at_least()` function for aggregator comparisons (as documented), there's nothing preventing them from using standard comparison operators, which appear to work during compilation. The gap in test coverage (no tests for ordering operations on aggregators) suggests this scenario was not fully considered.

## Recommendation

**Option 1: Add Compile-Time Check in CMP Rewriter**

Extend `arg_cannot_transform` to detect and reject types containing delayed fields:

```rust
fn arg_cannot_transform(&mut self, arg: &Exp) -> bool {
    let arg_ty = self.env.get_node_type(arg.as_ref().node_id());
    // Reject integer types (native VM support)
    if arg_ty.is_number() {
        return true;
    }
    // Reject types containing aggregators or other delayed fields
    if self.type_contains_delayed_fields(&arg_ty) {
        self.env.error(
            &self.env.get_node_loc(arg.as_ref().node_id()),
            "comparison operations not supported on types containing aggregators, snapshots, or derived strings"
        );
        return true;
    }
    false
}
```

**Option 2: Add Type Constraints**

Modify the type system to add a `Comparable` trait bound that explicitly excludes types with delayed fields. This would be the more principled solution but requires more extensive changes.

**Option 3: Document and Warn**

At minimum, add compiler warnings when comparing non-copy types or types known to contain aggregators, directing users to use specialized comparison functions.

## Proof of Concept

Create a Move module at `test_aggregator_comparison.move`:

```move
module 0xCAFE::test_aggregator_comparison {
    use aptos_framework::aggregator_v2::{Self, Aggregator};
    
    struct DataWithAggregator has drop {
        counter: Aggregator<u64>,
        value: u64,
    }
    
    // This function compiles successfully
    public fun compare_aggregators(agg1: Aggregator<u64>, agg2: Aggregator<u64>): bool {
        agg1 < agg2
    }
    
    // This function also compiles successfully
    public fun compare_structs_with_aggregators(d1: DataWithAggregator, d2: DataWithAggregator): bool {
        d1 < d2
    }
    
    #[test]
    public fun test_comparison() {
        let agg1 = aggregator_v2::create_unbounded_aggregator<u64>();
        let agg2 = aggregator_v2::create_unbounded_aggregator<u64>();
        
        // This will fail at runtime with VM_EXTENSION_ERROR
        let _ = compare_aggregators(agg1, agg2);
    }
}
```

**Expected Result:**
- Compilation: SUCCESS ✓
- Execution: FAILURE with `VM_EXTENSION_ERROR: cannot compare delayed values` ✗

**Reproduction Steps:**
1. Enable aggregator v2 features
2. Compile the module (succeeds)
3. Execute the test function (fails with VM_EXTENSION_ERROR)

This demonstrates the type soundness violation where well-typed code fails at runtime.

## Notes

The Aptos framework provides specialized comparison functions like `is_at_least()` for aggregators precisely because direct comparison is problematic. However, the compiler does not enforce their use, allowing users to write comparison operations that will fail. The gap between what the type system permits and what the runtime supports represents a fundamental soundness issue that should be addressed at the compiler level.

### Citations

**File:** third_party/move/move-model/src/builder/builtins.rs (L473-492)
```rust
        if trans
            .env
            .language_version()
            .is_at_least(LanguageVersion::V2_2)
        {
            // For LanguageVersion::V2_2 and later, we support comparison on all types.
            // - integer types supported by the VM natively
            // - other types supported by the `compare` native function
            //      - implicitly through compiler rewrite at the AST level
            let ref_param_t = Type::Reference(ReferenceKind::Immutable, Box::new(param_t.clone()));
            // Allow cmp over both generic types and reference types
            for pt in [ref_param_t.clone(), param_t.clone()] {
                declare_cmp_ops(
                    trans,
                    std::slice::from_ref(&param_t_decl),
                    &BTreeMap::default(),
                    pt,
                    Impl, // visible only in the impl language
                );
            }
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/cmp_rewriter.rs (L146-171)
```rust
    fn rewrite_cmp_operation(
        &mut self,
        call_id: NodeId,
        cmp_op: &Operation,
        args: &[Exp],
    ) -> Option<Exp> {
        // Step 1: Check argument types
        if args.iter().any(|arg| self.arg_cannot_transform(arg)) {
            return None;
        }
        // Get the expected type-parameter type for the `std::cmp::compare` function
        let arg_ty = self.env.get_node_type(args[0].node_id());
        let expected_arg_ty = arg_ty.drop_reference();

        // Step 2: Transform `arg1` and `arg2` into `&arg1` and `&arg2` (do nothing if already references)
        let transformed_args: Vec<Exp> = args.iter().map(|arg| self.rewrite_cmp_arg(arg)).collect();

        // Step 3: Create an inner call to `std::cmp::compare(&arg1, &arg2)`
        let call_cmp = self.generate_call_to_compare(call_id, transformed_args, expected_arg_ty)?;

        // Step 4: Create a immutable reference to the result of `std::cmp::compare(&arg1, &arg2)`
        let immref_cmp_res = self.immborrow_compare_res(call_cmp);

        //Step 5: Generate a final call of `is_lt / is_le / is_gt / is_ge` to interpret the result of `std::cmp::compare`
        self.generate_call_to_final_res(call_id, cmp_op, vec![immref_cmp_res])
    }
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/cmp_rewriter.rs (L300-303)
```rust
    fn arg_cannot_transform(&mut self, arg: &Exp) -> bool {
        let arg_ty = self.env.get_node_type(arg.as_ref().node_id());
        arg_ty.is_number()
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L978-983)
```rust
            // Disallow comparison for delayed values.
            // (see `ValueImpl::equals` above for details on reasoning behind it)
            (DelayedFieldID { .. }, DelayedFieldID { .. }) => {
                return Err(PartialVMError::new(StatusCode::VM_EXTENSION_ERROR)
                    .with_message("cannot compare delayed values".to_string()))
            },
```

**File:** aptos-move/framework/src/natives/aggregator_natives/aggregator_v2.rs (L118-132)
```rust
    let value = if let Some((resolver, mut delayed_field_data)) = get_context_data(context) {
        let width = get_width_by_type(aggregator_value_ty, EUNSUPPORTED_AGGREGATOR_TYPE)?;
        let id = resolver.generate_delayed_field_id(width);
        delayed_field_data.create_new_aggregator(id);
        Value::delayed_value(id)
    } else {
        create_value_by_type(aggregator_value_ty, 0, EUNSUPPORTED_AGGREGATOR_TYPE)?
    };

    let max_value =
        create_value_by_type(aggregator_value_ty, max_value, EUNSUPPORTED_AGGREGATOR_TYPE)?;
    Ok(smallvec![Value::struct_(Struct::pack(vec![
        value, max_value,
    ]))])
}
```

**File:** aptos-move/e2e-move-tests/src/tests/aggregator_v2.data/pack/sources/runtime_checks.move (L1-4)
```text
/// Aggregators and other structs that use delayed fields have certain restrictions
/// imposed by runtime, e.g. they cannot be compared, serialized, etc. because delayed
/// field values get exchanged with unique identifiers at runtime.
module 0x1::runtime_checks {
```

**File:** aptos-move/e2e-move-tests/src/tests/aggregator_v2_runtime_checks.rs (L64-82)
```rust
fn test_equality() {
    let func_names = vec![
        // Aggregators.
        "0x1::runtime_checks::test_equality_with_aggregators_I",
        "0x1::runtime_checks::test_equality_with_aggregators_II",
        "0x1::runtime_checks::test_equality_with_aggregators_III",
        // Snapshots.
        "0x1::runtime_checks::test_equality_with_snapshots_I",
        "0x1::runtime_checks::test_equality_with_snapshots_II",
        "0x1::runtime_checks::test_equality_with_snapshots_III",
        // Derived string snapshots.
        "0x1::runtime_checks::test_equality_with_derived_string_snapshots_I",
        "0x1::runtime_checks::test_equality_with_derived_string_snapshots_II",
        "0x1::runtime_checks::test_equality_with_derived_string_snapshots_III",
    ];
    run_entry_functions(func_names, |status: ExecutionStatus| {
        assert_matches!(status, ExecutionStatus::ExecutionFailure { .. });
    });
}
```
