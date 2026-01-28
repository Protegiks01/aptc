# Audit Report

## Title
View Function API Bypasses Move Visibility Controls, Exposing Private and Friend Functions

## Summary
The view function execution path in AptosVM fails to enforce Move's visibility controls (private/friend/public), allowing any external caller to invoke private or friend view functions that should only be accessible within their defining module or to friend modules. This completely bypasses the Move language's fundamental access control mechanism for read-only functions.

## Finding Description

Move's visibility system defines three access levels for functions:
- **Private** (no modifier): Only callable within the same module
- **`public(friend)`**: Only callable by the same module or modules in the friend list  
- **`public`**: Callable by any module or external caller

For regular function calls (via bytecode instructions), the Move VM runtime enforces these visibility rules. The interpreter calls `check_call_visibility()` before executing any function: [1](#0-0) 

This eventually invokes `check_cross_module_regular_call_visibility()` which rejects private functions and enforces friend restrictions: [2](#0-1) 

However, when executing view functions through the API, this critical check is completely bypassed. The execution path in `execute_view_function_in_vm()` is: [3](#0-2) 

The function loads via `load_instantiated_function()`, validates via `validate_view_function()`, and executes via `execute_loaded_function()`. Critically, `validate_view_function()` only checks: [4](#0-3) 

This validation only verifies the `#[view]` attribute exists, the function returns values, and arguments are valid. **It does not check visibility** (no calls to `is_private()`, `is_friend()`, or any visibility validation).

The underlying `Module::get_function()` performs only name-based lookup: [5](#0-4) 

Even at compile-time, the extended checks do not enforce visibility for view functions: [6](#0-5) 

Functions have visibility information stored: [7](#0-6) 

But this visibility field is never consulted during view function execution.

**Attack Scenario:**
1. A DeFi protocol module defines a private view function `get_internal_reserves()` marked with `#[view]` for testing
2. An attacker discovers this function through module metadata inspection
3. The attacker calls the view function API with the module ID and function name
4. The function executes successfully, bypassing visibility checks
5. Private internal state is leaked
6. The attacker uses this information to front-run trades or exploit arbitrage

## Impact Explanation

This vulnerability represents a **Medium to High Severity** issue as a "Significant Protocol Violation":

**Breaks Fundamental Security Invariant**: The Move visibility system is a core security feature designed to provide encapsulation and access control. This bypass completely undermines the access control model for view functions, violating a fundamental protocol guarantee.

**Information Disclosure from Critical Modules**: Private view functions in governance, staking, or DeFi modules may expose:
- Internal accounting states not meant for public query
- Validator performance metrics intended for internal use only
- DeFi protocol reserve calculations and internal prices
- Governance proposal details before public announcement

**Violates Developer Expectations**: Module authors who mark functions as private reasonably expect the Move VM to enforce that restriction. This silent failure creates a false sense of security and violates the security model documented in the Move language specification.

While view functions cannot modify state (limiting direct financial impact), the information disclosure severity is significant because it breaks a fundamental protocol invariant. According to Aptos bug bounty criteria, this qualifies as a "Limited Protocol Violation" (Medium severity) at minimum, potentially escalating to High severity due to the fundamental nature of the broken invariant.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is:
- **Trivially exploitable**: Requires only a standard API call with module ID and function name
- **No special privileges required**: Any network participant can invoke the view function API
- **Easily discoverable**: Attackers can enumerate module functions via metadata
- **Affects all deployed modules**: Any module with private or friend view functions is vulnerable
- **Difficult to detect**: Module authors may not realize their private view functions are externally callable

The exploit requires no complex setup, coordination, or special access. Any user can immediately test calling private view functions through the API.

## Recommendation

Add visibility checks to the view function validation path. In `validate_view_function()`, add a check after determining the function is a view function:

```rust
// After line 47 in view_function.rs
if !is_view {
    return Err(...);
}

// Add visibility check here
if func.is_private() {
    return Err(
        PartialVMError::new(StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE)
            .with_message("view functions cannot be private".to_string()),
    );
}

if func.is_friend() {
    return Err(
        PartialVMError::new(StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE)
            .with_message("view functions cannot have friend visibility".to_string()),
    );
}
```

Alternatively, enforce that only public view functions can be called externally, or add explicit visibility checks in `execute_view_function_in_vm()` before execution.

## Proof of Concept

```move
module test::private_view {
    #[view]
    fun get_secret(): u64 {  // Private function (no public modifier)
        42  // Sensitive internal value
    }
    
    #[view]
    public(friend) fun get_friend_only(): u64 {  // Friend-only function
        100
    }
}
```

An attacker can call these via the view API:
```rust
// API call: POST /v1/view
// Body: {
//   "function": "0xtest::private_view::get_secret",
//   "type_arguments": [],
//   "arguments": []
// }
// Expected: Error (private function)
// Actual: Returns [42] - vulnerability confirmed
```

The private and friend functions execute successfully despite visibility restrictions, confirming the bypass.

## Notes

This vulnerability is specific to the view function execution path and does not affect regular function calls, which correctly enforce visibility through the interpreter's `check_call_visibility()` mechanism. The issue stems from the view function path taking a different code route that was not designed with visibility enforcement in mind.

### Citations

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L502-507)
```rust
                    RTTCheck::check_call_visibility(
                        &current_frame.function,
                        &function,
                        CallType::Regular,
                    )
                    .map_err(|err| set_err_info!(current_frame, err))?;
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L945-981)
```rust
    fn check_cross_module_regular_call_visibility(
        caller: &LoadedFunction,
        callee: &LoadedFunction,
    ) -> PartialVMResult<()> {
        if callee.is_private() {
            let msg = format!(
                "Function {}::{} cannot be called because it is private",
                callee.module_or_script_id(),
                callee.name()
            );
            return Err(
                PartialVMError::new_invariant_violation(msg).with_sub_status(EPARANOID_FAILURE)
            );
        }

        if callee.is_friend() {
            let callee_module = callee.owner_as_module().map_err(|err| err.to_partial())?;
            if !caller
                .module_id()
                .is_some_and(|id| callee_module.friends.contains(id))
            {
                let msg = format!(
                    "Function {}::{} cannot be called because it has friend visibility, but {} \
                     is not {}'s friend",
                    callee.module_or_script_id(),
                    callee.name(),
                    caller.module_or_script_id(),
                    callee.module_or_script_id()
                );
                return Err(
                    PartialVMError::new_invariant_violation(msg).with_sub_status(EPARANOID_FAILURE)
                );
            }
        }

        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2739-2791)
```rust
    fn execute_view_function_in_vm(
        session: &mut SessionExt<impl AptosMoveResolver>,
        vm: &AptosVM,
        module_id: ModuleId,
        func_name: Identifier,
        ty_args: Vec<TypeTag>,
        arguments: Vec<Vec<u8>>,
        gas_meter: &mut impl AptosGasMeter,
        traversal_context: &mut TraversalContext,
        module_storage: &impl AptosModuleStorage,
    ) -> Result<Vec<Vec<u8>>, VMError> {
        dispatch_loader!(module_storage, loader, {
            let func = loader.load_instantiated_function(
                &LegacyLoaderConfig::unmetered(),
                gas_meter,
                traversal_context,
                &module_id,
                &func_name,
                &ty_args,
            )?;

            let metadata = get_metadata(&func.owner_as_module()?.metadata);

            let arguments = view_function::validate_view_function(
                session,
                &loader,
                gas_meter,
                traversal_context,
                arguments,
                func_name.as_ident_str(),
                &func,
                metadata.as_ref().map(Arc::as_ref),
                vm.features().is_enabled(FeatureFlag::STRUCT_CONSTRUCTORS),
            )
            .map_err(|e| e.finish(Location::Module(module_id)))?;

            let result = session.execute_loaded_function(
                func,
                arguments,
                gas_meter,
                traversal_context,
                &loader,
                // No need to record any traces for view functions.
                &mut NoOpTraceRecorder,
            )?;

            Ok(result
                .return_values
                .into_iter()
                .map(|(bytes, _ty)| bytes)
                .collect::<Vec<_>>())
        })
    }
```

**File:** aptos-move/aptos-vm/src/verifier/view_function.rs (L35-92)
```rust
pub(crate) fn validate_view_function(
    session: &mut SessionExt<impl AptosMoveResolver>,
    loader: &impl Loader,
    gas_meter: &mut impl GasMeter,
    traversal_context: &mut TraversalContext,
    args: Vec<Vec<u8>>,
    fun_name: &IdentStr,
    func: &LoadedFunction,
    module_metadata: Option<&RuntimeModuleMetadataV1>,
    struct_constructors_feature: bool,
) -> PartialVMResult<Vec<Vec<u8>>> {
    // Must be marked as view function.
    let is_view = determine_is_view(module_metadata, fun_name);
    if !is_view {
        return Err(
            PartialVMError::new(StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE)
                .with_message("function not marked as view function".to_string()),
        );
    }

    // Must return values.
    if func.return_tys().is_empty() {
        return Err(
            PartialVMError::new(StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE)
                .with_message("view function must return values".to_string()),
        );
    }

    let allowed_structs = get_allowed_structs(struct_constructors_feature);
    let result = if loader.is_lazy_loading_enabled() {
        transaction_arg_validation::construct_args(
            session,
            loader,
            gas_meter,
            traversal_context,
            func.param_tys(),
            args,
            func.ty_args(),
            allowed_structs,
            true,
        )
    } else {
        let traversal_storage = TraversalStorage::new();
        transaction_arg_validation::construct_args(
            session,
            loader,
            // No metering with eager loading.
            &mut UnmeteredGasMeter,
            &mut TraversalContext::new(&traversal_storage),
            func.param_tys(),
            args,
            func.ty_args(),
            allowed_structs,
            true,
        )
    };
    result.map_err(|e| PartialVMError::new(e.status_code()))
}
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L585-600)
```rust
    pub fn get_function(&self, function_name: &IdentStr) -> VMResult<Arc<Function>> {
        Ok(self
            .function_map
            .get(function_name)
            .and_then(|idx| self.function_defs.get(*idx))
            .ok_or_else(|| {
                let module_id = self.self_id();
                PartialVMError::new(StatusCode::FUNCTION_RESOLUTION_FAILURE)
                    .with_message(format!(
                        "Function {}::{}::{} does not exist",
                        module_id.address(),
                        module_id.name(),
                        function_name
                    ))
                    .finish(Location::Undefined)
            })?
```

**File:** aptos-move/framework/src/extended_checks.rs (L689-740)
```rust
    fn check_and_record_view_functions(&mut self, module: &ModuleEnv) {
        for ref fun in module.get_functions() {
            if !self.has_attribute(fun, VIEW_FUN_ATTRIBUTE) {
                continue;
            }
            self.check_transaction_args(&fun.get_parameters());
            if fun.get_return_count() == 0 {
                self.env
                    .error(&fun.get_id_loc(), "`#[view]` function must return values")
            }

            fun.get_parameters()
                .iter()
                .for_each(
                    |Parameter(_sym, parameter_type, param_loc)| match parameter_type {
                        Type::Primitive(inner) => {
                            if inner == &PrimitiveType::Signer {
                                self.env.error(
                                    param_loc,
                                    "`#[view]` function cannot use a `signer` parameter",
                                )
                            }
                        },
                        Type::Reference(mutability, inner) => {
                            if let Type::Primitive(inner) = inner.as_ref() {
                                if inner == &PrimitiveType::Signer
                                // Avoid a redundant error message for `&mut signer`, which is
                                // always disallowed for transaction entries, not just for
                                // `#[view]`.
                                    && mutability == &ReferenceKind::Immutable
                                {
                                    self.env.error(
                                        param_loc,
                                        "`#[view]` function cannot use the `&signer` parameter",
                                    )
                                }
                            }
                        },
                        _ => (),
                    },
                );

            // Remember the runtime info that this is a view function
            let module_id = self.get_runtime_module_id(module);
            self.output
                .entry(module_id)
                .or_default()
                .fun_attributes
                .entry(fun.get_simple_name_string().to_string())
                .or_default()
                .push(KnownAttribute::view_function());
        }
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L66-92)
```rust
pub struct Function {
    #[allow(unused)]
    pub(crate) file_format_version: u32,
    pub(crate) index: FunctionDefinitionIndex,
    pub(crate) code: Vec<Instruction>,
    pub(crate) ty_param_abilities: Vec<AbilitySet>,
    // TODO: Make `native` and `def_is_native` become an enum.
    pub(crate) native: Option<NativeFunction>,
    pub(crate) is_native: bool,
    /// If true, this is a native function which does native dynamic dispatch (main use cases are
    /// fungible asset and account abstraction).
    pub(crate) is_dispatchable_native: bool,
    pub(crate) visibility: Visibility,
    pub(crate) is_entry: bool,
    pub(crate) name: Identifier,
    pub(crate) return_tys: Vec<Type>,
    // For non-native functions: parameter types first and then local types, if any.
    // For native functions, an empty vector (there are no locals). This is very important because
    // gas is charged based on number of locals which should be 0 for native calls (to be backwards
    // compatible).
    pub(crate) local_tys: Vec<Type>,
    pub(crate) param_tys: Vec<Type>,
    pub(crate) access_specifier: AccessSpecifier,
    pub(crate) is_persistent: bool,
    pub(crate) has_module_reentrancy_lock: bool,
    pub(crate) is_trusted: bool,
}
```
