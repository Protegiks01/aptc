# Audit Report

## Title
Missing Type Argument Ability Validation in Native Dynamic Dispatch (CallFunction)

## Summary
The Move VM's native dynamic dispatch mechanism (`NativeResult::CallFunction`) lacks defensive validation of type arguments against the target function's type parameter constraints. While not currently exploitable due to trusted native implementations, this represents a missing safety check that could enable future vulnerabilities.

## Finding Description

When native functions perform dynamic dispatch via `NativeResult::CallFunction`, the type arguments provided in the `ty_args` vector are not validated against the target function's type parameter ability constraints before execution. [1](#0-0) 

In the normal function instantiation path, type arguments undergo explicit validation: [2](#0-1) 

This validation ensures each type argument's abilities satisfy the function's type parameter constraints using `Type::verify_ty_arg_abilities`: [3](#0-2) 

However, in the `CallFunction` dispatch handler, this validation is **completely absent**: [4](#0-3) 

The only check performed is signature compatibility (line 1204-1211), which verifies that type parameter **constraints match** between the native and target functions, but does **not** verify that the actual type arguments **satisfy** those constraints: [5](#0-4) 

Current native dispatch implementations simply forward type arguments without validation: [6](#0-5) 

## Impact Explanation

**Current Impact: LOW** - This is a **defensive programming gap** rather than an actively exploitable vulnerability because:

1. Native functions are part of the trusted Aptos framework, not user-deployable
2. Type arguments originate from Move bytecode that has already been verified
3. Existing implementations correctly forward pre-validated type arguments

**Potential Future Impact: MEDIUM-HIGH** - This missing validation could enable vulnerabilities if:
- A future native function implementation contains a bug that constructs invalid `Type` objects
- Native function code is modified to programmatically generate type arguments
- The type argument construction logic in the VM has subtle bugs

If exploited, invalid type arguments could cause:
- **Type safety violations** leading to undefined behavior
- **Consensus divergence** if validators interpret invalid types differently  
- **Memory corruption** if type abilities (copy, drop, store, key) are violated during execution

## Likelihood Explanation

**Current Likelihood: Very Low** - Exploitation requires:
- Malicious or buggy native function implementation (insider threat)
- Or undiscovered bug in VM's type construction logic
- Cannot be triggered by external attackers deploying Move modules

**Future Likelihood: Low-Medium** - As the codebase evolves:
- New native functions may be added with complex type manipulation
- Refactoring could introduce type construction bugs
- The missing validation provides no safety net against such issues

## Recommendation

Add defensive type argument validation in the `CallFunction` handler to match the validation performed in normal function instantiation:

**Location**: `third_party/move/move-vm/runtime/src/interpreter.rs`, after line 1186

```rust
// Validate that type arguments satisfy target function's constraints
Type::verify_ty_arg_abilities(target_func.ty_param_abilities(), &ty_args)
    .map_err(|e| e.to_partial())?;
```

This single line adds the missing validation, ensuring defense-in-depth against potential future bugs in native function implementations or type construction logic.

## Proof of Concept

This vulnerability cannot be demonstrated with a practical PoC because:
1. It requires modifying trusted native function code (insider threat scenario)
2. External attackers cannot deploy custom native functions
3. Current implementations do not exhibit the vulnerability

However, the missing validation can be confirmed by:

1. Examining the `CallFunction` handler showing no call to `Type::verify_ty_arg_abilities`
2. Comparing with the normal instantiation path which includes this validation
3. Observing that the signature compatibility check validates constraints but not the type arguments themselves

**Theoretical exploit scenario** (requires compromised native function):
```rust
// Hypothetical malicious native that constructs invalid Type
// (This cannot be done by external attackers)
fn malicious_native(...) -> NativeResult {
    // Construct a Type without required abilities
    let invalid_type = /* Type without 'key' ability */;
    
    NativeResult::CallFunction {
        ty_args: vec![invalid_type], // Missing validation allows this
        ...
    }
}
```

---

## Notes

While this represents a missing safety check in the codebase, it does **not** constitute an immediately exploitable vulnerability by unprivileged attackers. The issue is classified as a **defensive programming concern** that should be addressed to prevent potential future vulnerabilities as the codebase evolves. The recommended fix is simple, low-risk, and aligns with existing validation patterns in the codebase.

### Citations

**File:** third_party/move/move-vm/types/src/natives/function.rs (L54-60)
```rust
    CallFunction {
        cost: InternalGas,
        module_name: ModuleId,
        func_name: Identifier,
        ty_args: Vec<Type>,
        args: SmallVec<[Value; 1]>,
    },
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/traits.rs (L159-160)
```rust
        Type::verify_ty_arg_abilities(function.ty_param_abilities(), &ty_args)
            .map_err(|e| e.finish(Location::Module(module.self_id().clone())))?;
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L435-455)
```rust
    pub fn verify_ty_arg_abilities<'a, I>(
        ty_param_abilities: I,
        ty_args: &[Self],
    ) -> PartialVMResult<()>
    where
        I: IntoIterator<Item = &'a AbilitySet>,
        I::IntoIter: ExactSizeIterator,
    {
        let ty_param_abilities = ty_param_abilities.into_iter();
        if ty_param_abilities.len() != ty_args.len() {
            return Err(PartialVMError::new(
                StatusCode::NUMBER_OF_TYPE_ARGUMENTS_MISMATCH,
            ));
        }
        for (ty, expected_ability_set) in ty_args.iter().zip(ty_param_abilities) {
            if !expected_ability_set.is_subset(ty.abilities()?) {
                return Err(PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED));
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1168-1186)
```rust
            NativeResult::CallFunction {
                cost,
                module_name,
                func_name,
                ty_args,
                args,
            } => {
                gas_meter.charge_native_function(cost, Option::<std::iter::Empty<&Value>>::None)?;

                let ty_args_id = self.ty_pool.intern_ty_args(&ty_args);
                let target_func = current_frame.build_loaded_function_from_name_and_ty_args(
                    self.loader,
                    gas_meter,
                    traversal_context,
                    &module_name,
                    &func_name,
                    ty_args,
                    ty_args_id,
                )?;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1204-1211)
```rust
                if function.ty_param_abilities() != target_func.ty_param_abilities()
                    || function.return_tys() != target_func.return_tys()
                    || &function.param_tys()[0..function.param_tys().len() - 1]
                        != target_func.param_tys()
                {
                    return Err(PartialVMError::new(StatusCode::RUNTIME_DISPATCH_ERROR)
                        .with_message("Invoking function with incompatible type".to_string()));
                }
```

**File:** aptos-move/framework/src/natives/dispatchable_fungible_asset.rs (L50-55)
```rust
    Err(SafeNativeError::FunctionDispatch {
        module_name,
        func_name,
        ty_args: ty_args.to_vec(),
        args: arguments.into_iter().collect(),
    })
```
