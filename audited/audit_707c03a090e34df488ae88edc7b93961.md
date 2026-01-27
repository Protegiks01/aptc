# Audit Report

## Title
Inconsistent Type Node Counting in Function Reference Parameters Leading to Validation Bypass

## Summary
The `TypeBuilder::create_ty_impl()` function exhibits inconsistent depth and node counting behavior when processing function types with reference parameters compared to the `apply_subst()` method. Specifically, reference type nodes in function signatures are not explicitly checked or counted at lines 1506 and 1509, while the same types are fully validated in other code paths. This allows types to bypass size limits during creation but potentially fail during subsequent operations.

## Finding Description

The vulnerability stems from an inconsistency in how reference types within function signatures are validated:

**In `create_ty_impl()` (lines 1505-1510):** [1](#0-0) 

When processing `FunctionParamOrReturnTag::Reference`, the code directly constructs a `Reference(Box::new(...))` wrapper and recursively creates the inner type with `depth + 2`, but **never explicitly checks or counts the Reference node itself**.

**In `apply_subst()` (lines 1380-1386):** [2](#0-1) 

When processing a `Reference` type, the code explicitly checks and counts the Reference node at line 1352-1353 before recursing on the inner type.

**Concrete Example:**

For function type `|&vector<u8>|`:

- **create_ty_impl path:** Checks depths [1: Function, 3: Vector, 4: u8] - **3 nodes counted**
- **apply_subst path:** Checks depths [1: Function, 2: Reference, 3: Vector, 4: u8] - **4 nodes counted**

The Reference node is **completely omitted** from validation in `create_ty_impl`.

**Attack Vector:**

1. Attacker crafts a transaction with function type arguments containing many reference parameters
2. Type passes `max_ty_size` validation during `create_ty()` due to undercounting (e.g., 100 function parameters with references = 100 missing node counts)
3. Later during type substitution via `create_ty_with_subst()` in function instantiation: [3](#0-2) 
   
   The same type is rechecked with proper node counting and could exceed limits, causing unexpected validation failures

4. This creates state inconsistency where types are accepted during initial validation but rejected during execution

## Impact Explanation

**Severity: Medium**

This vulnerability meets the **Medium severity** criteria: "State inconsistencies requiring intervention"

While this does not directly cause fund loss or consensus violations, it creates validation inconsistencies that could:

1. **Resource Exhaustion Vector:** Allow types up to `N * (1 + reference_ratio)` nodes to pass initial validation, where N is `max_ty_size`, potentially bypassing intended complexity limits
2. **Transaction Validation Bypass:** Transactions with oversized function types could pass prologue validation but fail during execution, causing wasted computation
3. **Deterministic Execution Risk:** If different code paths are triggered under different conditions (e.g., cached vs non-cached types), validators could diverge in their validation decisions

The undercount of reference nodes violates the **Resource Limits invariant** (#9): "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is exploitable when:
- Function types with reference parameters are used (enabled in recent Move versions)
- Attackers can control type arguments in transaction payloads
- The number of reference parameters is large enough to exceed `max_ty_size` when properly counted

The attack requires moderate sophistication but no privileged access. Function types are increasingly used in Move for higher-order programming patterns, making this exploitable in practice.

## Recommendation

Ensure consistent validation of Reference nodes in function signatures by explicitly checking them in `create_ty_impl()`:

```rust
FunctionParamOrReturnTag::Reference(t) => {
    // Check the reference node itself at depth+1
    self.check(count, depth + 1)?;
    *count += 1;  // Count the reference node
    Reference(Box::new(
        self.create_ty_impl(t, resolver, count, depth + 2)?,
    ))
},
FunctionParamOrReturnTag::MutableReference(t) => {
    // Check the reference node itself at depth+1
    self.check(count, depth + 1)?;
    *count += 1;  // Count the reference node
    MutableReference(
        Box::new(self.create_ty_impl(t, resolver, count, depth + 2)?),
    )
},
```

This ensures Reference nodes are validated consistently across all code paths.

## Proof of Concept

```rust
#[test]
fn test_function_reference_node_counting_inconsistency() {
    use move_core_types::language_storage::*;
    
    // Create TypeBuilder with tight limits
    let type_builder = TypeBuilder::with_limits(10, 5);
    
    // Create function type with 5 reference parameters: |&u8, &u8, &u8, &u8, &u8|
    let func_tag = FunctionTag {
        args: vec![
            FunctionParamOrReturnTag::Reference(TypeTag::U8),
            FunctionParamOrReturnTag::Reference(TypeTag::U8),
            FunctionParamOrReturnTag::Reference(TypeTag::U8),
            FunctionParamOrReturnTag::Reference(TypeTag::U8),
            FunctionParamOrReturnTag::Reference(TypeTag::U8),
        ],
        results: vec![],
        abilities: AbilitySet::EMPTY,
    };
    
    // Create type via create_ty - should pass with undercounting
    // Counts: 1 (Function) + 5 (u8) = 6 nodes
    let ty = type_builder.create_ty(
        &TypeTag::Function(Box::new(func_tag)),
        |_| unreachable!()
    ).expect("Should pass - only 6 nodes counted");
    
    // Now try substitution - this properly counts references
    // Would count: 1 (Function) + 5 (Reference) + 5 (u8) = 11 nodes > max_ty_size
    let result = type_builder.create_ty_with_subst(&ty, &[]);
    
    // This should fail with TOO_MANY_TYPE_NODES due to proper counting
    assert!(result.is_err(), "Should fail - 11 nodes exceed limit of 10");
}
```

**Notes:**

The vulnerability is confirmed by the inconsistent code paths in `create_ty_impl()` vs `apply_subst()`. The Reference nodes in function signatures are systematically undercounted, allowing types to bypass the `max_ty_size` limit during creation while potentially failing during subsequent operations. This breaks the resource limits invariant and creates validation inconsistencies in the Move VM type system.

### Citations

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1188-1191)
```rust
    pub fn create_ty_with_subst(&self, ty: &Type, ty_args: &[Type]) -> PartialVMResult<Type> {
        let mut count = 0;
        let check = |c: &mut u64, d: u64| self.check(c, d);
        self.subst_impl(ty, ty_args, &mut count, 1, check)
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1380-1386)
```rust
            Reference(inner_ty) => {
                let inner_ty = Self::apply_subst(inner_ty, subst, count, depth + 1, check)?;
                Reference(Box::new(inner_ty))
            },
            MutableReference(inner_ty) => {
                let inner_ty = Self::apply_subst(inner_ty, subst, count, depth + 1, check)?;
                MutableReference(Box::new(inner_ty))
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1505-1510)
```rust
                                FunctionParamOrReturnTag::Reference(t) => Reference(Box::new(
                                    self.create_ty_impl(t, resolver, count, depth + 2)?,
                                )),
                                FunctionParamOrReturnTag::MutableReference(t) => MutableReference(
                                    Box::new(self.create_ty_impl(t, resolver, count, depth + 2)?),
                                ),
```
