# Audit Report

## Title
Type Confusion in IndexedRef::swap_values() Allows Violation of Container::Vec Type Invariant

## Summary
The `IndexedRef::swap_values()` function allows swapping values between generic containers (`Struct`, `Vec`, `Locals`) without validating that the resulting container states respect Move VM type invariants. Specifically, swapping can insert specialized primitive values (u8, u64, bool, etc.) into `Container::Vec`, which is required by design to only contain non-specialized primitives (DelayedFieldID, ClosureValue) or nested containers. This violates a critical runtime invariant and can cause subsequent VM operations to fail with invariant violation errors. [1](#0-0) 

## Finding Description
The Move VM maintains a critical type-safety invariant for generic vector containers. The `Container::Vec` variant can only store:
- NonSpecializedVecPrimitive types: `DelayedFieldID`, `ClosureValue`
- Container types: nested structs, vectors, or locals

This invariant is explicitly enforced in multiple locations: [2](#0-1) [3](#0-2) [4](#0-3) 

However, the `IndexedRef::swap_values()` implementation has three swap patterns, and the generic-to-generic case uses an unchecked `swap!` macro that performs direct memory swaps without type validation: [5](#0-4) [6](#0-5) 

The pattern match explicitly includes `(Struct(r1), Vec(r2))` and `(Vec(r1), Struct(r2))`, allowing swaps between struct fields and generic vector elements without validation.

**Attack Scenario:**

1. A struct contains a specialized primitive: `Struct([Value::U8(42)])`
2. A generic vector contains a non-specialized value: `Vec([Value::DelayedFieldID{id: 123}])`
3. Create IndexedRef to both: `ref1` → Struct[0], `ref2` → Vec[0]
4. Call `ref1.swap_values(ref2)`
5. The match pattern `(Struct(r1), Vec(r2))` is triggered, executing the unchecked `swap!` macro
6. After swap: `Vec([Value::U8(42)])` ← **INVARIANT VIOLATED**

The `Container::Vec` now contains a `SpecializedVecPrimitive` value, violating the invariant that requires it to only contain `NonSpecializedVecPrimitive` or `Container` values.

**Consequences:**

When the corrupted vector is subsequently accessed, operations fail: [7](#0-6) 

Any call to `borrow_elem()` on the corrupted vector returns `UNKNOWN_INVARIANT_VIOLATION_ERROR`, making the vector unusable for read operations. However, `push_back()` and `pop()` operations may continue to work, potentially propagating the corruption: [8](#0-7) [9](#0-8) 

## Impact Explanation
**Severity: Medium to High**

This violates Move VM Safety (Critical Invariant #3) and can lead to:

1. **Consensus Divergence Risk:** If validators process the corrupted state differently (some detecting the invariant violation early, others propagating it), this could cause state root mismatches, affecting **Deterministic Execution** (Critical Invariant #1).

2. **Transaction Failure DoS:** Once a vector is corrupted, any transaction attempting to borrow from it will fail with `UNKNOWN_INVARIANT_VIOLATION_ERROR`, potentially freezing smart contract functionality.

3. **State Consistency Violation:** The corrupted VM state represents an impossible type configuration that should never exist, violating **State Consistency** (Critical Invariant #4).

This qualifies as **High Severity** under the Aptos bug bounty program due to "Significant protocol violations" and potential validator node issues. If consensus divergence can be demonstrated, it escalates to **Critical Severity**.

## Likelihood Explanation
**Likelihood: Low to Medium**

While the vulnerable code path exists, exploitation requires:

1. A way to create `IndexedRef` instances pointing to incompatible types (struct field with specialized primitive, vector element with non-specialized type)
2. Ability to invoke `swap_values()` on these references

The Move bytecode verifier should prevent type-incompatible swaps at the source level. However, this defense-in-depth check is missing from the runtime, meaning:

- **If a verifier bug exists** that allows type confusion, this runtime vulnerability would allow the exploit to proceed
- **Native function bugs** or unsafe operations that bypass verifier checks could trigger this path
- **Complex type system interactions** (generics, closures, aggregators) may expose edge cases

The test suite demonstrates that cross-type swaps between locals work in the runtime layer, with type checking deferred to higher layers: [10](#0-9) 

## Recommendation
Add type validation to the generic container swap path. Before performing the swap, verify that the resulting container states will respect their type invariants:

```rust
// In IndexedRef::swap_values(), for the generic-generic case:
(Vec(r1), Vec(r2))
| (Vec(r1), Struct(r2))
| (Vec(r1), Locals(r2))
| (Struct(r1), Vec(r2))
| (Struct(r1), Struct(r2))
| (Struct(r1), Locals(r2))
| (Locals(r1), Vec(r2))
| (Locals(r1), Struct(r2))
| (Locals(r1), Locals(r2)) => {
    // NEW: Validate the swap respects container invariants
    let val_self = &r1.borrow()[self_index];
    let val_other = &r2.borrow()[other_index];
    
    // Check if swapping would violate Container::Vec invariants
    if matches!(self.container_ref.container(), Container::Vec(_)) {
        val_other.check_valid_for_value_vector()?;
    }
    if matches!(other.container_ref.container(), Container::Vec(_)) {
        val_self.check_valid_for_value_vector()?;
    }
    
    swap!(r1, r2)
},
```

This ensures that specialized primitives cannot be swapped into `Container::Vec`, maintaining the runtime invariant even if upstream checks fail.

## Proof of Concept

```rust
#[test]
fn test_type_confusion_via_swap() -> PartialVMResult<()> {
    use crate::values::{Locals, Value, Reference};
    use crate::delayed_values::delayed_field_id::DelayedFieldID;
    
    let mut locals = Locals::new(10);
    
    // Create a struct with a specialized primitive (u8)
    locals.store_loc(0, Value::struct_(Struct::pack(vec![Value::u8(42)])))?;
    
    // Create a generic vector containing a non-specialized primitive (DelayedFieldID)
    locals.store_loc(1, Value::vector_unchecked(vec![
        Value::DelayedFieldID { id: DelayedFieldID::from(123) }
    ])?)?;
    
    // Get reference to struct
    let struct_ref = locals.borrow_loc(0)?.value_as::<Reference>()?;
    
    // Get reference to vector
    let vec_ref = locals.borrow_loc(1)?.value_as::<Reference>()?;
    
    // Borrow the struct field (contains u8)
    let struct_field_ref = match struct_ref {
        Value::ContainerRef(c) => c.borrow_elem(0, None)?.value_as::<Reference>()?,
        _ => panic!("Expected ContainerRef"),
    };
    
    // Borrow the vector element (contains DelayedFieldID)
    let vec_elem_ref = match vec_ref {
        Value::ContainerRef(c) => c.borrow_elem(0, None)?.value_as::<Reference>()?,
        _ => panic!("Expected ContainerRef"),
    };
    
    // Attempt to swap - this should fail but currently succeeds!
    // After swap: Container::Vec contains Value::U8(42), violating invariant
    let result = struct_field_ref.swap_values(vec_elem_ref);
    
    // The swap succeeds (BUG!)
    assert!(result.is_ok());
    
    // Now try to borrow from the corrupted vector
    let corrupted_vec_ref = locals.borrow_loc(1)?.value_as::<Reference>()?;
    match corrupted_vec_ref {
        Value::ContainerRef(c) => {
            // This should fail with UNKNOWN_INVARIANT_VIOLATION_ERROR
            // because Container::Vec now contains Value::U8
            let borrow_result = c.borrow_elem(0, None);
            assert!(borrow_result.is_err()); // Demonstrates the corruption
        },
        _ => panic!("Expected ContainerRef"),
    }
    
    Ok(())
}
```

**Notes:**
This vulnerability represents a missing defense-in-depth check at the runtime layer. While the bytecode verifier should prevent type-unsafe operations, the runtime should independently validate critical invariants rather than assuming verifier correctness. The explicit invariant checks exist throughout the codebase (`check_valid_for_value_vector`, `check_valid_for_indexed_ref`, `borrow_elem` validation) but are bypassed in this specific swap path, creating a gap in the defense chain.

### Citations

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L353-364)
```rust
    /// Returns an error if value's kind is not valid for [Container::Vec].
    fn check_valid_for_value_vector(&self) -> PartialVMResult<()> {
        use ValueKind as K;

        match self.kind() {
            K::NonSpecializedVecPrimitive | K::Container => Ok(()),
            K::SpecializedVecPrimitive | K::RefOrInvalid => {
                Err(PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR)
                    .with_message(format!("vector of `Value`s cannot contain {:?}", self)))
            },
        }
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L368-388)
```rust
    fn check_valid_for_indexed_ref(&self, indexed_ref: &IndexedRef) -> PartialVMResult<()> {
        use ValueKind as K;

        let container = indexed_ref.container_ref.container();
        let is_ok = match self.kind() {
            K::NonSpecializedVecPrimitive => true,
            K::SpecializedVecPrimitive => !matches!(container, Container::Vec(_)),
            K::Container | K::RefOrInvalid => false,
        };
        if !is_ok {
            let msg = format!(
                "invalid IndexedRef element {:?} for container {:?}",
                self, container
            );
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(msg),
            );
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L1875-2026)
```rust
impl IndexedRef {
    fn swap_values(self, other: Self) -> PartialVMResult<()> {
        use Container::*;

        self.check_tag()?;
        other.check_tag()?;
        let self_index = self.idx as usize;
        let other_index = other.idx as usize;

        macro_rules! swap {
            ($r1:ident, $r2:ident) => {{
                if Rc::ptr_eq($r1, $r2) {
                    if self_index == other_index {
                        return Err(PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR)
                            .with_message(format!(
                                "cannot swap references to the same item {:?}",
                                self
                            )));
                    }

                    $r1.borrow_mut().swap(self_index, other_index);
                } else {
                    mem::swap(
                        &mut $r1.borrow_mut()[self_index],
                        &mut $r2.borrow_mut()[other_index],
                    )
                }
            }};
        }

        macro_rules! swap_general_with_specialized {
            ($r1:ident, $r2:ident) => {{
                let mut r1 = $r1.borrow_mut();
                let mut r2 = $r2.borrow_mut();

                let v1 = *r1[self_index].as_value_ref()?;
                r1[self_index] = Value::from_primitive(r2[other_index]);
                r2[other_index] = v1;
            }};
        }

        macro_rules! swap_specialized_with_general {
            ($r1:ident, $r2:ident) => {{
                let mut r1 = $r1.borrow_mut();
                let mut r2 = $r2.borrow_mut();

                let v2 = *r2[other_index].as_value_ref()?;
                r2[other_index] = Value::from_primitive(r1[self_index]);
                r1[self_index] = v2;
            }};
        }

        match (
            self.container_ref.container(),
            other.container_ref.container(),
        ) {
            // Case 1: (generic, generic)
            (Vec(r1), Vec(r2))
            | (Vec(r1), Struct(r2))
            | (Vec(r1), Locals(r2))
            | (Struct(r1), Vec(r2))
            | (Struct(r1), Struct(r2))
            | (Struct(r1), Locals(r2))
            | (Locals(r1), Vec(r2))
            | (Locals(r1), Struct(r2))
            | (Locals(r1), Locals(r2)) => swap!(r1, r2),

            // Case 2: (specialized, specialized)
            (VecU8(r1), VecU8(r2)) => swap!(r1, r2),
            (VecU16(r1), VecU16(r2)) => swap!(r1, r2),
            (VecU32(r1), VecU32(r2)) => swap!(r1, r2),
            (VecU64(r1), VecU64(r2)) => swap!(r1, r2),
            (VecU128(r1), VecU128(r2)) => swap!(r1, r2),
            (VecU256(r1), VecU256(r2)) => swap!(r1, r2),
            (VecI8(r1), VecI8(r2)) => swap!(r1, r2),
            (VecI16(r1), VecI16(r2)) => swap!(r1, r2),
            (VecI32(r1), VecI32(r2)) => swap!(r1, r2),
            (VecI64(r1), VecI64(r2)) => swap!(r1, r2),
            (VecI128(r1), VecI128(r2)) => swap!(r1, r2),
            (VecI256(r1), VecI256(r2)) => swap!(r1, r2),
            (VecBool(r1), VecBool(r2)) => swap!(r1, r2),
            (VecAddress(r1), VecAddress(r2)) => swap!(r1, r2),

            // Case 3: (generic, specialized) or (specialized, generic)
            (Locals(r1) | Struct(r1), VecU8(r2)) => swap_general_with_specialized!(r1, r2),
            (VecU8(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecU16(r2)) => swap_general_with_specialized!(r1, r2),
            (VecU16(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecU32(r2)) => swap_general_with_specialized!(r1, r2),
            (VecU32(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecU64(r2)) => swap_general_with_specialized!(r1, r2),
            (VecU64(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecU128(r2)) => swap_general_with_specialized!(r1, r2),
            (VecU128(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecU256(r2)) => swap_general_with_specialized!(r1, r2),
            (VecU256(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecI8(r2)) => swap_general_with_specialized!(r1, r2),
            (VecI8(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecI16(r2)) => swap_general_with_specialized!(r1, r2),
            (VecI16(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecI32(r2)) => swap_general_with_specialized!(r1, r2),
            (VecI32(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecI64(r2)) => swap_general_with_specialized!(r1, r2),
            (VecI64(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecI128(r2)) => swap_general_with_specialized!(r1, r2),
            (VecI128(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecI256(r2)) => swap_general_with_specialized!(r1, r2),
            (VecI256(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecBool(r2)) => swap_general_with_specialized!(r1, r2),
            (VecBool(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            (Locals(r1) | Struct(r1), VecAddress(r2)) => swap_general_with_specialized!(r1, r2),
            (VecAddress(r1), Locals(r2) | Struct(r2)) => swap_specialized_with_general!(r1, r2),

            // All other combinations are illegal.
            (Vec(_), _)
            | (VecU8(_), _)
            | (VecU16(_), _)
            | (VecU32(_), _)
            | (VecU64(_), _)
            | (VecU128(_), _)
            | (VecU256(_), _)
            | (VecI8(_), _)
            | (VecI16(_), _)
            | (VecI32(_), _)
            | (VecI64(_), _)
            | (VecI128(_), _)
            | (VecI256(_), _)
            | (VecBool(_), _)
            | (VecAddress(_), _) => {
                return Err(PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR)
                    .with_message(format!("cannot swap references {:?}, {:?}", self, other)))
            },
        }

        self.container_ref.mark_dirty();
        other.container_ref.mark_dirty();

        Ok(())
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L2113-2141)
```rust
            Container::Vec(r) => {
                let v = r.borrow();
                match &v[idx] {
                    Value::Container(container) => container_ref!(container),
                    Value::ClosureValue(_) | Value::DelayedFieldID { .. } => indexed_ref!(),

                    Value::U8(_)
                    | Value::U16(_)
                    | Value::U32(_)
                    | Value::U64(_)
                    | Value::U128(_)
                    | Value::U256(_)
                    | Value::I8(_)
                    | Value::I16(_)
                    | Value::I32(_)
                    | Value::I64(_)
                    | Value::I128(_)
                    | Value::I256(_)
                    | Value::Bool(_)
                    | Value::Address(_)
                    | Value::ContainerRef(_)
                    | Value::Invalid
                    | Value::IndexedRef(_) => {
                        return Err(PartialVMError::new(
                            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                        )
                        .with_message(format!("cannot borrow vector element {:?}", &v[idx])))
                    },
                }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L3741-3741)
```rust
            Container::Vec(r) => r.borrow_mut().push(e),
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L3836-3838)
```rust
            Container::Vec(r) => match r.borrow_mut().pop() {
                Some(x) => x,
                None => err_pop_empty_vec!(),
```

**File:** third_party/move/move-vm/types/src/values/value_tests.rs (L216-231)
```rust
        for j in ((i + 2)..16).step_by(2) {
            let result = get_local(&locals, i).swap_values(get_local(&locals, j));

            // These would all fail in `call_native` typing checks.
            // But here some do pass:
            if j < 4  // locals are not checked between each other
               || (8 <= i && j < 12) // ContainerRef of containers is not checked between each other
               || (12 <= i && j < 16)
            // ContainerRef of vector is not checked between each other
            //    || i >= 8 // containers are also interchangeable
            {
                assert_ok!(result, "{} and {}", i, j);
            } else {
                assert_err!(result, "{} and {}", i, j);
            }
        }
```
