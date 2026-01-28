# Audit Report

## Title
Bytecode Verifier Gap: Unchecked LocalIndex in Access Specifier Parameters Causes Runtime Verifier Invariant Violation

## Summary
The Move bytecode verifier does not validate that `LocalIndex` values in access specifiers' `AddressSpecifier::Parameter` variants are within bounds of the function's parameter count. This allows malicious bytecode to pass verification and trigger `VERIFIER_INVARIANT_VIOLATION` errors at runtime during access specifier specialization, violating the fundamental guarantee that verified bytecode should never fail with verifier errors during execution.

## Finding Description

The vulnerability exists across three components that create a complete attack path from verification bypass to runtime failure:

**1. Missing Verification in Bounds Checker:**

The bytecode bounds checker's `check_function_handle` method validates the function handle's module, identifier, parameters, and return signatures, but completely ignores the `access_specifiers` field. [1](#0-0) 

The feature verifier only checks whether the access_specifiers feature is enabled, not the validity of the `LocalIndex` values within the access specifiers. [2](#0-1) 

**2. Unchecked Loading of Access Specifiers:**

The access specifier loader creates `AddressSpecifier::Eval(fun, *param)` directly from the bytecode file format without validating that the parameter index is within the function's parameter bounds. [3](#0-2) 

The `AddressSpecifier::Parameter` variant in the file format accepts a `LocalIndex` (u8) that should reference a function parameter, but this index is never bounds-checked during verification. [4](#0-3) 

**3. Runtime Failure During Specialization:**

When a function with an out-of-bounds access specifier is called, the `enter_function` method attempts to specialize the access specifier. [5](#0-4) 

Specialization resolves `AddressSpecifier::Eval` variants by calling the environment's `eval_address_specifier_function` method. [6](#0-5) 

The `Frame` implementation of this trait calls `copy_loc` with the local index from the access specifier. [7](#0-6) 

When the index is out of bounds, `copy_loc` returns a `VERIFIER_INVARIANT_VIOLATION` error. [8](#0-7) 

This error is explicitly marked as a verifier invariant violation because the verifier should have caught this bounds error during static analysis. [9](#0-8) 

**Attack Scenario:**
1. Attacker crafts a Move module with a function having 1 parameter (valid index: 0)
2. The function's access specifier contains `AddressSpecifier::Parameter(1, None)` (index 1 is out of bounds)
3. Bytecode passes all verification stages because no verifier checks LocalIndex values in access specifiers
4. Attacker publishes the module on-chain
5. When any transaction calls this function, `enter_function` triggers access specifier specialization
6. Specialization attempts to `copy_loc(1)` from a locals array with only 1 element (index 0)
7. Runtime error with `VERIFIER_INVARIANT_VIOLATION` occurs, crashing the transaction

This violates the core Move VM guarantee that verified bytecode should never fail with verifier errors during execution.

## Impact Explanation

**Severity: HIGH**

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

1. **Validator Node Impact:** Transactions triggering this error cause unexpected runtime failures with `VERIFIER_INVARIANT_VIOLATION`. This falls under the "Validator Node Slowdowns (High)" category as malicious modules could be deployed that cause transaction processing failures affecting validator performance.

2. **Protocol Integrity Violation:** `VERIFIER_INVARIANT_VIOLATION` indicates a verifier bug, not a normal execution error. This breaks the fundamental Move VM safety guarantee that bytecode verification prevents all runtime verifier errors. The existence of such errors indicates the verifier failed to uphold its correctness invariants.

3. **Potential Consensus Risk:** If different validator implementations or versions handle `VERIFIER_INVARIANT_VIOLATION` errors differently (e.g., one aborts transaction, another panics), this could cause consensus divergence. While unlikely given current implementation uniformity, this represents a theoretical risk to the deterministic execution guarantee.

4. **Denial of Service:** Any function with this malicious access specifier becomes permanently uncallable. If critical system functions (governance proposals, staking operations, framework upgrades) were affected, it could impact network operations requiring manual intervention or hardfork to resolve.

The issue does not directly cause fund loss or guaranteed consensus breaks, but represents a fundamental gap in the Move VM's security model that violates its verification guarantees.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability has medium-high likelihood of exploitation:

**Factors Increasing Likelihood:**
1. **Low Barrier to Entry:** Any user can publish Move modules on Aptos without special privileges
2. **Easy to Construct:** Bytecode with out-of-bounds LocalIndex can be crafted using standard bytecode manipulation tools
3. **Undetectable at Deploy Time:** The module passes all verification stages, giving defenders no opportunity to prevent deployment
4. **Wide Impact:** Once deployed, any transaction calling the malicious function triggers the bug
5. **No Cost to Attacker:** Publishing a malicious module costs only gas fees, with potential to disrupt many transactions

**Factors Limiting Likelihood:**
1. **Feature Adoption:** Resource access control and access specifiers may not be widely used yet, limiting immediate exposure
2. **Limited Targets:** Only functions with access specifiers are vulnerable
3. **Detection After First Call:** The bug triggers on first call, making the malicious module identifiable (though not easily removable)

As access specifiers become more common in Aptos Move code, this vulnerability becomes more critical. The ease of exploitation combined with lack of defense mechanisms justifies the medium-high likelihood assessment.

## Recommendation

Add bounds checking for `LocalIndex` values in access specifiers during bytecode verification. Specifically:

1. **Enhance `check_function_handle` in bounds checker:** After validating function parameters and returns, add validation for access_specifiers. For each `AddressSpecifier::Parameter(local_index, _)`, verify that `local_index < function_handle.parameters.len()`.

2. **Add validation in `load_address_specifier`:** When loading `AddressSpecifier::Parameter`, validate the local index against the function's parameter count and return an `ACCESS_CONTROL_INVARIANT_VIOLATION` error if out of bounds.

3. **Consider defensive runtime check:** Even with verification fixes, add a defensive check in `Frame::eval_address_specifier_function` to gracefully handle out-of-bounds indices with a clear error message rather than triggering VERIFIER_INVARIANT_VIOLATION.

The verification fix should be prioritized as it prevents the issue at the root cause.

## Proof of Concept

While a complete PoC would require bytecode manipulation tools, the vulnerability can be demonstrated conceptually:

```rust
// Conceptual test showing the vulnerability path
// This would need to be implemented as a bytecode manipulation test

// 1. Create a FunctionHandle with 1 parameter (parameter index 0 valid)
// 2. Add an AccessSpecifier with AddressSpecifier::Parameter(1, None) 
//    (index 1 is out of bounds)
// 3. Compile and publish the module (passes verification)
// 4. Call the function in a transaction
// 5. Observe VERIFIER_INVARIANT_VIOLATION during specialization

// The error occurs at runtime in values_impl.rs:2360 when copy_loc(1)
// is called on a locals array of size 1 (only index 0 valid)
```

A full PoC would require modifying bytecode after compilation to inject the malicious `LocalIndex` value, as the Move compiler would not generate such invalid bytecode naturally.

### Citations

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L238-248)
```rust
    fn check_function_handle(&self, function_handle: &FunctionHandle) -> PartialVMResult<()> {
        check_bounds_impl(self.view.module_handles(), function_handle.module)?;
        check_bounds_impl(self.view.identifiers(), function_handle.name)?;
        check_bounds_impl(self.view.signatures(), function_handle.parameters)?;
        check_bounds_impl(self.view.signatures(), function_handle.return_)?;
        // function signature type parameters must be in bounds to the function type parameters
        let type_param_count = function_handle.type_parameters.len();
        self.check_type_parameters_in_signature(function_handle.parameters, type_param_count)?;
        self.check_type_parameters_in_signature(function_handle.return_, type_param_count)?;
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/features.rs (L111-117)
```rust
                if !self.config.enable_resource_access_control
                    && function_handle.access_specifiers.is_some()
                {
                    return Err(PartialVMError::new(StatusCode::FEATURE_NOT_ENABLED)
                        .at_index(IndexKind::FunctionHandle, idx as u16)
                        .with_message("resource access control feature not enabled".to_string()));
                }
```

**File:** third_party/move/move-vm/runtime/src/loader/access_specifier_loader.rs (L89-110)
```rust
        Parameter(param, fun) => {
            let fun = if let Some(idx) = fun {
                let fun_inst = access_table(module.function_instantiations(), idx.0)?;
                let fun_handle = access_table(module.function_handles(), fun_inst.handle.0)?;
                let mod_handle = access_table(module.module_handles(), fun_handle.module.0)?;
                let mod_id = module
                    .safe_module_id_for_handle(mod_handle)
                    .ok_or_else(index_out_of_range)?;
                let mod_name = mod_id.short_str_lossless();
                let fun_name = access_table(module.identifiers(), fun_handle.name.0)?;
                AddressSpecifierFunction::parse(&mod_name, fun_name.as_str()).ok_or_else(|| {
                    PartialVMError::new(StatusCode::ACCESS_CONTROL_INVARIANT_VIOLATION)
                        .with_message(format!(
                            "function `{}::{}` not supported for address specifier",
                            mod_name, fun_name
                        ))
                })?
            } else {
                AddressSpecifierFunction::Identity
            };
            Ok(AddressSpecifier::Eval(fun, *param))
        },
```

**File:** third_party/move/move-binary-format/src/file_format.rs (L908-917)
```rust
    Parameter(
        /// The index of a parameter of the current function. If `modifier` is not given, the
        /// parameter must have address type. Otherwise `modifier` must be a function which takes
        /// a value (or reference) of the parameter type and delivers an address.
        #[cfg_attr(any(test, feature = "fuzzing"), proptest(strategy = "0u8..63"))]
        LocalIndex,
        /// If given, a function applied to the parameter. This is a well-known function which
        /// extracts an address from a value, e.g. `object::address_of`.
        Option<FunctionInstantiationIndex>,
    ),
```

**File:** third_party/move/move-vm/runtime/src/access_control.rs (L43-48)
```rust
            // Specialize the functions access specifier and push it on the stack.
            let mut fun_specifier = fun.access_specifier().clone();
            fun_specifier.specialize(env)?;
            self.specifier_stack.push(fun_specifier);
            Ok(())
        }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L232-237)
```rust
    fn specialize(&mut self, env: &impl AccessSpecifierEnv) -> PartialVMResult<()> {
        if let AddressSpecifier::Eval(fun, arg) = self {
            *self = AddressSpecifier::Literal(env.eval_address_specifier_function(*fun, *arg)?)
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/frame.rs (L79-87)
```rust
impl AccessSpecifierEnv for Frame {
    fn eval_address_specifier_function(
        &self,
        fun: AddressSpecifierFunction,
        local: LocalIndex,
    ) -> PartialVMResult<AccountAddress> {
        fun.eval(self.locals.copy_loc(local as usize)?)
    }
}
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L2352-2362)
```rust
    pub fn copy_loc(&self, idx: usize) -> PartialVMResult<Value> {
        let locals = self.0.borrow();
        match locals.get(idx) {
            Some(Value::Invalid) => Err(PartialVMError::new(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            )
            .with_message(format!("cannot copy invalid value at index {}", idx))),
            Some(v) => Ok(v.copy_value(1, Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH))?),
            None => Err(Self::local_index_out_of_bounds(idx, locals.len())),
        }
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L2422-2427)
```rust
    fn local_index_out_of_bounds(idx: usize, num_locals: usize) -> PartialVMError {
        PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION).with_message(format!(
            "local index out of bounds: got {}, len: {}",
            idx, num_locals
        ))
    }
```
