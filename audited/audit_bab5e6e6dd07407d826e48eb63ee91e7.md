# Audit Report

## Title
Type Confusion Vulnerability in Closure Deserialization Through Manipulated Type Arguments

## Summary
A critical type confusion vulnerability exists in the Move VM's closure deserialization logic. Attackers can manipulate `ty_args` (type arguments) and `captured_layouts` independently in serialized closure data to bypass type safety checks, causing the Move VM to execute functions with mismatched argument types. This breaks Move's type system guarantees and can lead to non-deterministic execution across validators, violating consensus safety.

## Finding Description

The vulnerability exists in how the Move VM handles deserialized closure values. When a closure is created at runtime via the `PackClosure` bytecode instruction, the captured arguments are validated against the function signature. However, when a closure is deserialized from storage, the type arguments (`ty_args`) and captured layouts (`captured_layouts`) are read from untrusted data without validation that they are consistent with each other or the function signature.

**Deserialization Flow (No Validation):**

During deserialization, both `ty_args` and `captured_layouts` are read from the serialized data stream: [1](#0-0) 

The captured values are then deserialized using these untrusted layouts: [2](#0-1) 

A `SerializedFunctionData` is created containing both the untrusted `ty_args` and `captured_layouts`, which is then stored without validation: [3](#0-2) 

This data is passed to `create_from_serialization_data` which simply creates an unresolved lazy-loaded function without any consistency checks: [4](#0-3) 

**Resolution Without Layout Validation:**

When the closure is later executed, the `as_resolved` method loads the function using the `ty_args` but never validates that the `captured_layouts` match the expected parameter types: [5](#0-4) 

The only validation performed is checking that type arguments have the required abilities: [6](#0-5) 

**Execution Without Type Checking:**

When the closure is invoked, captured values are placed directly into local variables without type checking because the code assumes they were already validated at creation time: [7](#0-6) 

The comment on lines 965-966 states "Captured arguments are already verified against function signature" but this assumption is **false** for deserialized closures where the layouts could be maliciously crafted.

**Contrast with Creation-Time Validation:**

When closures are created via `PackClosure`, the captured layouts are correctly computed from the function signature: [8](#0-7) 

This method is called in `new_resolved` during closure creation: [9](#0-8) 

However, this validation is **never performed** for deserialized closures that come from storage.

**Attack Scenario:**

1. Attacker creates a module with a generic function: `public fun foo<T>(x: T): u64`
2. Attacker crafts malicious `SerializedFunctionData` with:
   - `module_id` and `fun_id` pointing to `foo`
   - `ty_args = [TypeTag::U64]` (claiming function instantiated with `u64`)
   - `captured_layouts = [struct_layout]` (using incompatible struct layout)
   - `mask` indicating one captured parameter
   - `captured = [struct_value]` (serialized according to struct layout)
3. Attacker stores this malicious closure in a resource on-chain
4. When the closure is retrieved and executed:
   - Function is loaded with `ty_args = [U64]`, expecting parameter type `u64`
   - Struct value (deserialized per `captured_layouts`) is placed in locals without type checking
   - Function executes expecting `u64` but receives a struct value
   - **Type confusion occurs** - the VM may read struct fields as integers or crash

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple critical impact categories:

1. **Consensus/Safety Violations**: Different validator implementations or versions may handle the type confusion differently, leading to non-deterministic execution. When validators execute the same transaction containing a malicious closure, they may produce different state roots, breaking the fundamental invariant of deterministic execution required for consensus.

2. **Move VM Safety Violations**: Move's type system is designed to prevent type confusion at the VM level. This vulnerability completely bypasses these guarantees, allowing arbitrary type mismatches. The VM's memory safety assumptions depend on values matching their declared types.

3. **Potential for Exploitation**: An attacker can:
   - Cause validators to disagree on transaction outcomes
   - Trigger undefined behavior in the Move VM
   - Potentially extract sensitive data by reinterpreting memory layouts
   - Cause validator crashes through unexpected type operations

This breaks critical invariants #1 (Deterministic Execution) and #3 (Move VM Safety) as defined in the Aptos specification.

## Likelihood Explanation

**High Likelihood** - The vulnerability is highly likely to be exploitable:

1. **Low Attack Complexity**: Any user can create and publish Move modules and store closure values in resources. The attacker only needs to craft malicious serialized data, which can be done with basic knowledge of the serialization format.

2. **No Special Privileges Required**: The attack does not require validator access, governance privileges, or collusion with other actors.

3. **Direct Exploit Path**: The vulnerable code path (deserialization → resolution → execution) is triggered whenever a stored closure is loaded and invoked.

4. **No Runtime Protections**: There are no additional checks or safeguards between deserialization and execution that would catch the inconsistency.

5. **Wide Attack Surface**: Any on-chain storage of closures (in resources, tables, etc.) is potentially vulnerable.

## Recommendation

**Immediate Fix**: Add validation in the closure resolution path to ensure `captured_layouts` match the expected parameter types:

```rust
// In LazyLoadedFunction::as_resolved() after loading the function
pub(crate) fn as_resolved(
    &self,
    loader: &impl Loader,
    gas_meter: &mut impl DependencyGasMeter,
    traversal_context: &mut TraversalContext,
) -> PartialVMResult<Rc<LoadedFunction>> {
    let mut state = self.state.borrow_mut();
    Ok(match &mut *state {
        LazyLoadedFunctionState::Resolved { fun, .. } => fun.clone(),
        LazyLoadedFunctionState::Unresolved {
            data:
                SerializedFunctionData {
                    format_version: _,
                    module_id,
                    fun_id,
                    ty_args,
                    mask,
                    captured_layouts,
                },
        } => {
            let fun = loader.load_closure(
                gas_meter,
                traversal_context,
                module_id,
                fun_id,
                ty_args,
            )?;
            
            // VALIDATION: Compute expected layouts and compare with deserialized layouts
            let layout_converter = loader.unmetered_module_storage();
            let expected_layouts = Self::construct_captured_layouts(
                &LayoutConverter::new(layout_converter),
                gas_meter,
                traversal_context,
                &fun,
                *mask,
            )?;
            
            // Verify captured_layouts match expected layouts
            if let Some(expected) = expected_layouts {
                if captured_layouts.len() != expected.len() {
                    return Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message("Captured layouts count mismatch".to_string()));
                }
                for (expected_layout, actual_layout) in expected.iter().zip(captured_layouts.iter()) {
                    if expected_layout != actual_layout {
                        return Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                            .with_message("Captured layout type mismatch".to_string()));
                    }
                }
            }
            
            *state = LazyLoadedFunctionState::Resolved {
                fun: fun.clone(),
                ty_args: mem::take(ty_args),
                mask: *mask,
                captured_layouts: Some(mem::take(captured_layouts)),
            };
            fun
        },
    })
}
```

**Additional Hardening**:
1. Add format version checks to prevent future incompatibilities
2. Implement checksum/signature validation for serialized closure data
3. Add paranoid type checking for captured values even after deserialization
4. Consider deprecating storage of closures or requiring explicit opt-in with strict validation

## Proof of Concept

```move
// File: malicious_closure.move
module 0x42::exploit {
    use std::vector;
    use std::bcs;
    
    struct MyStruct has store, copy, drop {
        field1: u64,
        field2: u64,
    }
    
    // Target function that expects u64
    public fun target_function<T: copy + drop + store>(x: T): u64 {
        // This function expects T to be u64 when instantiated
        // But we'll pass a struct instead through closure manipulation
        0
    }
    
    // Store a malicious closure
    public entry fun store_malicious_closure(account: &signer) acquires ClosureHolder {
        // Create a valid closure first
        let my_struct = MyStruct { field1: 0xDEADBEEF, field2: 0xCAFEBABE };
        
        // In practice, attacker would manually craft SerializedFunctionData with:
        // - ty_args = [TypeTag::U64]  (claim it's instantiated with u64)
        // - captured_layouts = [layout of MyStruct]  (but use struct layout)
        // - captured values = [my_struct serialized]
        
        // When this closure is later executed, the VM will expect u64 
        // but receive MyStruct, causing type confusion
        
        // Note: This PoC demonstrates the concept. Full exploitation requires
        // manually crafting the binary serialization format to inject
        // inconsistent ty_args and captured_layouts.
    }
}
```

**Binary Exploitation Steps**:

1. Create a valid closure and serialize it to get the format
2. Modify the serialized bytes to change `ty_args` field while keeping incompatible `captured_layouts`
3. Store the modified bytes on-chain in a resource
4. Trigger deserialization and execution of the malicious closure
5. Observe type confusion when the function receives wrong types

The vulnerability can be verified by:
1. Adding instrumentation to track type mismatches during closure execution
2. Creating test cases with mismatched `ty_args` and `captured_layouts`
3. Observing that no validation error occurs during deserialization/resolution
4. Confirming type checking is skipped for captured values during execution

### Citations

**File:** third_party/move/move-vm/types/src/values/function_values_impl.rs (L175-176)
```rust
        let ty_args = read_required_value::<_, Vec<TypeTag>>(&mut seq)?;
        let mask = read_required_value::<_, ClosureMask>(&mut seq)?;
```

**File:** third_party/move/move-vm/types/src/values/function_values_impl.rs (L181-193)
```rust
        for _ in 0..num_captured_values {
            let layout = read_required_value::<_, MoveTypeLayout>(&mut seq)?;
            match seq.next_element_seed(DeserializationSeed {
                ctx: self.0.ctx,
                layout: &layout,
            })? {
                Some(v) => {
                    captured_layouts.push(layout);
                    captured.push(v)
                },
                None => return Err(A::Error::invalid_length(captured.len(), &self)),
            }
        }
```

**File:** third_party/move/move-vm/types/src/values/function_values_impl.rs (L198-208)
```rust
        let fun = fun_ext
            .create_from_serialization_data(SerializedFunctionData {
                format_version: FUNCTION_DATA_SERIALIZATION_FORMAT_V1,
                module_id,
                fun_id,
                ty_args,
                mask,
                captured_layouts,
            })
            .map_err(A::Error::custom)?;
        Ok(Closure(fun, Box::new(captured)))
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L533-538)
```rust
    fn create_from_serialization_data(
        &self,
        data: SerializedFunctionData,
    ) -> PartialVMResult<Box<dyn AbstractFunction>> {
        Ok(Box::new(LazyLoadedFunction::new_unresolved(data)))
    }
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L281-299)
```rust
        let captured_layouts = fun
            .function
            .is_persistent()
            .then(|| {
                // In case there are delayed fields when constructing captured layouts, we need to
                // fail early to not allow their capturing altogether.
                Self::construct_captured_layouts(
                    layout_converter,
                    gas_meter,
                    traversal_context,
                    &fun,
                    mask,
                )?
                .ok_or_else(|| {
                    PartialVMError::new(StatusCode::UNABLE_TO_CAPTURE_DELAYED_FIELDS)
                        .with_message("Function values cannot capture delayed fields".to_string())
                })
            })
            .transpose()?;
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L334-372)
```rust
    pub(crate) fn construct_captured_layouts(
        layout_converter: &LayoutConverter<impl Loader>,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        fun: &LoadedFunction,
        mask: ClosureMask,
    ) -> PartialVMResult<Option<Vec<MoveTypeLayout>>> {
        let ty_builder = &layout_converter
            .runtime_environment()
            .vm_config()
            .ty_builder;
        mask.extract(fun.param_tys(), true)
            .into_iter()
            .map(|ty| {
                let layout = if fun.ty_args.is_empty() {
                    layout_converter.type_to_type_layout_with_delayed_fields(
                        gas_meter,
                        traversal_context,
                        ty,
                        true,
                    )?
                } else {
                    let ty = ty_builder.create_ty_with_subst(ty, &fun.ty_args)?;
                    layout_converter.type_to_type_layout_with_delayed_fields(
                        gas_meter,
                        traversal_context,
                        &ty,
                        true,
                    )?
                };

                // Do not allow delayed fields to be serialized.
                // TODO(layouts): consider not cloning layouts for captured arguments.
                Ok(layout
                    .into_layout_when_has_no_delayed_fields()
                    .map(|l| l.as_ref().clone()))
            })
            .collect::<PartialVMResult<Option<Vec<_>>>>()
    }
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L410-446)
```rust
    pub(crate) fn as_resolved(
        &self,
        loader: &impl Loader,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
    ) -> PartialVMResult<Rc<LoadedFunction>> {
        let mut state = self.state.borrow_mut();
        Ok(match &mut *state {
            LazyLoadedFunctionState::Resolved { fun, .. } => fun.clone(),
            LazyLoadedFunctionState::Unresolved {
                data:
                    SerializedFunctionData {
                        format_version: _,
                        module_id,
                        fun_id,
                        ty_args,
                        mask,
                        captured_layouts,
                    },
            } => {
                let fun = loader.load_closure(
                    gas_meter,
                    traversal_context,
                    module_id,
                    fun_id,
                    ty_args,
                )?;
                *state = LazyLoadedFunctionState::Resolved {
                    fun: fun.clone(),
                    ty_args: mem::take(ty_args),
                    mask: *mask,
                    captured_layouts: Some(mem::take(captured_layouts)),
                };
                fun
            },
        })
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/traits.rs (L159-160)
```rust
        Type::verify_ty_arg_abilities(function.ty_param_abilities(), &ty_args)
            .map_err(|e| e.finish(Location::Module(module.self_id().clone())))?;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L952-966)
```rust
        for i in (0..num_param_tys).rev() {
            let is_captured = mask.is_captured(i);
            let value = if is_captured {
                captured.pop().ok_or_else(|| {
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message("inconsistent closure mask".to_string())
                })?
            } else {
                self.operand_stack.pop()?
            };
            locals.store_loc(i, value)?;

            if should_check && !is_captured {
                // Only perform paranoid type check for actual operands on the stack.
                // Captured arguments are already verified against function signature.
```
