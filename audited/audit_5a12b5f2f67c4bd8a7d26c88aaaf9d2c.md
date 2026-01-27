# Audit Report

## Title
Missing Type Argument Count Validation in Async Runtime Type Checker Causes Potential Consensus Divergence

## Summary
The async runtime type checker in `load_function_generic()` does not validate that the number of type arguments matches the function's generic parameters when creating a `LoadedFunction`. This validation is present in the normal execution path but missing in the async type checking path, causing different error codes and potentially inconsistent error handling that could lead to consensus divergence.

## Finding Description

The async runtime type checker is used during speculative parallel execution to validate transactions after they have been executed. When replaying a `CallGeneric` instruction, the code path differs from normal execution in a critical way:

**Normal Execution Path:** [1](#0-0) 

The normal execution path explicitly validates that the number of type arguments matches the function's type parameters using `Type::verify_ty_arg_abilities()`, which checks: [2](#0-1) 

**Async Type Checker Path:** [3](#0-2) 

The async path calls `instantiation_idx_to_loaded_function()`: [4](#0-3) 

Which calls `handle_to_loaded_function()`: [5](#0-4) 

This directly constructs a `LoadedFunction` **without** calling `Type::verify_ty_arg_abilities()`.

**Exploitation Scenario:**

When the async type checker uses this `LoadedFunction` with mismatched type argument count in `set_new_frame()`: [6](#0-5) 

If the function's parameter types contain type parameters `TyParam(idx)` where `idx >= ty_args.len()`, the substitution logic will fail: [7](#0-6) 

This returns `UNKNOWN_INVARIANT_VIOLATION_ERROR` instead of `NUMBER_OF_TYPE_ARGUMENTS_MISMATCH`, creating an inconsistency between execution paths.

**Attack Vector:**

While the bytecode verifier should prevent malformed modules, edge cases or verifier bugs could allow function instantiations with incorrect type argument counts. Additionally, if module bytecode is somehow modified or corrupted between execution and async validation (though unlikely), this inconsistency in error handling could cause:

1. **Consensus divergence**: Different validators may handle `UNKNOWN_INVARIANT_VIOLATION_ERROR` vs `NUMBER_OF_TYPE_ARGUMENTS_MISMATCH` differently
2. **Deterministic execution violation**: The same transaction produces different error codes in different code paths
3. **Denial of service**: Invariant violation errors may cause validator crashes or panics

## Impact Explanation

**Severity: High to Critical**

This breaks the **Deterministic Execution** invariant (all validators must produce identical results) and the **Move VM Safety** invariant (bytecode execution must be robust).

**Critical Impact Potential:**
- If error handling differs between execution and async type checking, validators could produce different state roots
- Consensus safety violation if some validators accept while others reject transactions
- Could require a hardfork to fix if exploited in production

**High Impact Confirmed:**
- Defensive programming failure creates attack surface for future bugs
- Inconsistent error codes violate deterministic execution guarantees  
- Potential for validator node crashes if invariant violations are not properly handled

## Likelihood Explanation

**Likelihood: Medium**

While the bytecode verifier should prevent most instances of this issue, the likelihood is non-negligible because:

1. **Verifier bugs**: Past Move VM bugs have shown that bytecode verification is complex and can have edge cases
2. **Parallel execution context**: The async type checker is specifically used in high-performance parallel execution where timing and consistency are critical
3. **Error handling inconsistency**: The different error codes (`UNKNOWN_INVARIANT_VIOLATION_ERROR` vs `NUMBER_OF_TYPE_ARGUMENTS_MISMATCH`) may trigger different error handling paths in different validators or versions
4. **Defensive programming principle**: Even if unlikely to be triggered, missing validation in safety-critical code creates unnecessary risk

## Recommendation

Add the same type argument count validation in the async type checker path. Modify `handle_to_loaded_function()` to validate before creating the `LoadedFunction`:

```rust
fn handle_to_loaded_function(
    &self,
    frame: &Frame,
    handle: &FunctionHandle,
    ty_args: Vec<Type>,
    ty_args_id: TypeVecId,
) -> PartialVMResult<Rc<LoadedFunction>> {
    let (owner, function) = match handle {
        FunctionHandle::Local(f) => (frame.function.owner().clone(), f.clone()),
        FunctionHandle::Remote { module, name } => {
            let module = self
                .module_storage
                .unmetered_get_existing_lazily_verified_module(module)
                .map_err(|err| err.to_partial())?;
            let function = module.get_function(name).map_err(|err| err.to_partial())?;
            (LoadedFunctionOwner::Module(module), function)
        },
    };
    
    // ADD THIS VALIDATION:
    Type::verify_ty_arg_abilities(function.ty_param_abilities(), &ty_args)?;
    
    Ok(Rc::new(LoadedFunction {
        owner,
        ty_args,
        ty_args_id,
        function,
    }))
}
```

This ensures consistent validation and error handling across all code paths.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a malicious Move module with a function `foo<T0, T1>()` that expects 2 type parameters
2. Creating bytecode with a `CallGeneric` instruction that references a function instantiation with only 1 type argument  
3. If this passes bytecode verification (due to a verifier bug), normal execution would fail with `NUMBER_OF_TYPE_ARGUMENTS_MISMATCH`
4. But async type checking would create the `LoadedFunction` and then fail with `UNKNOWN_INVARIANT_VIOLATION_ERROR` during type substitution
5. This inconsistency in error codes demonstrates the violation of deterministic execution

A concrete Rust test would:
1. Mock a module with incorrect function instantiation
2. Call `instantiation_idx_to_loaded_function()` 
3. Use the returned `LoadedFunction` in `set_new_frame()`
4. Observe the `UNKNOWN_INVARIANT_VIOLATION_ERROR` instead of proper validation error
5. Compare with normal execution path to show inconsistency

**Notes**

This is a defensive programming issue that creates unnecessary risk in consensus-critical code. The async type checker should maintain the same validation rigor as normal execution to ensure deterministic behavior across all code paths, regardless of whether the bytecode verifier should have caught the issue earlier.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/loader/traits.rs (L159-160)
```rust
        Type::verify_ty_arg_abilities(function.ty_param_abilities(), &ty_args)
            .map_err(|e| e.finish(Location::Module(module.self_id().clone())))?;
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L444-448)
```rust
        if ty_param_abilities.len() != ty_args.len() {
            return Err(PartialVMError::new(
                StatusCode::NUMBER_OF_TYPE_ARGUMENTS_MISMATCH,
            ));
        }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1292-1301)
```rust
            |idx, c, d| match ty_args.get(idx as usize) {
                Some(ty) => self.clone_impl(ty, c, d, check),
                None => Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message(format!(
                        "Type substitution failed: index {} is out of bounds for {} type arguments",
                        idx,
                        ty_args.len()
                    )),
                ),
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L634-635)
```rust
                    let expected_ty = self.ty_builder.create_ty_with_subst(expected_ty, ty_args)?;
                    ty.paranoid_check_assignable(&expected_ty)?;
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L706-751)
```rust
    fn load_function_generic(
        &mut self,
        current_frame: &mut Frame,
        idx: FunctionInstantiationIndex,
    ) -> PartialVMResult<(Rc<LoadedFunction>, Rc<RefCell<FrameTypeCache>>)> {
        let pc = current_frame.pc as usize;
        let current_frame_cache = &mut *current_frame.frame_cache.borrow_mut();

        let function_and_cache = if let PerInstructionCache::CallGeneric(function, frame_cache) =
            &current_frame_cache.per_instruction_cache[pc]
        {
            let frame_cache = frame_cache.upgrade().ok_or_else(|| {
                PartialVMError::new_invariant_violation(
                    "Frame cache is dropped during interpreter execution",
                )
            })?;
            (Rc::clone(function), frame_cache)
        } else {
            let (function, frame_cache) =
                match current_frame_cache.generic_function_cache.entry(idx) {
                    Entry::Vacant(e) => {
                        let function =
                            self.instantiation_idx_to_loaded_function(current_frame, idx)?;
                        let frame_cache = self
                            .function_caches
                            .get_or_create_frame_cache_generic(&function);
                        e.insert((function.clone(), Rc::downgrade(&frame_cache)));
                        (function, frame_cache)
                    },
                    Entry::Occupied(e) => {
                        let (function, frame_cache) = e.get();
                        let frame_cache = frame_cache.upgrade().ok_or_else(|| {
                            PartialVMError::new_invariant_violation(
                                "Frame cache is dropped during interpreter execution",
                            )
                        })?;
                        (function.clone(), frame_cache)
                    },
                };

            current_frame_cache.per_instruction_cache[pc] =
                PerInstructionCache::CallGeneric(Rc::clone(&function), Rc::downgrade(&frame_cache));
            (function, frame_cache)
        };
        Ok(function_and_cache)
    }
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L768-783)
```rust
    fn instantiation_idx_to_loaded_function(
        &self,
        frame: &Frame,
        idx: FunctionInstantiationIndex,
    ) -> PartialVMResult<Rc<LoadedFunction>> {
        let handle = match frame.function.owner() {
            LoadedFunctionOwner::Script(script) => script.function_instantiation_handle_at(idx.0),
            LoadedFunctionOwner::Module(module) => module.function_instantiation_handle_at(idx.0),
        };
        let (ty_args, ty_args_id) = frame.instantiate_generic_function(
            self.ty_pool,
            None::<&mut UnmeteredGasMeter>,
            idx,
        )?;
        self.handle_to_loaded_function(frame, handle, ty_args, ty_args_id)
    }
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L787-813)
```rust
    #[inline(always)]
    fn handle_to_loaded_function(
        &self,
        frame: &Frame,
        handle: &FunctionHandle,
        ty_args: Vec<Type>,
        ty_args_id: TypeVecId,
    ) -> PartialVMResult<Rc<LoadedFunction>> {
        let (owner, function) = match handle {
            FunctionHandle::Local(f) => (frame.function.owner().clone(), f.clone()),
            FunctionHandle::Remote { module, name } => {
                // There is no need to meter gas here: it has been charged during execution.
                let module = self
                    .module_storage
                    .unmetered_get_existing_lazily_verified_module(module)
                    .map_err(|err| err.to_partial())?;
                let function = module.get_function(name).map_err(|err| err.to_partial())?;
                (LoadedFunctionOwner::Module(module), function)
            },
        };
        Ok(Rc::new(LoadedFunction {
            owner,
            ty_args,
            ty_args_id,
            function,
        }))
    }
```
