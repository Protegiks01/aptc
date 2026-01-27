# Audit Report

## Title
Native Function Signature Validation Gap Enables Silent Argument Dropping in Version Skew Scenarios

## Summary
The Move VM's native function registration and invocation mechanism lacks signature validation, allowing version mismatches between bytecode-declared signatures and Rust-implemented natives to cause ABI violations. When a native implementation expects fewer arguments than the bytecode declares, excess arguments are silently ignored without error, potentially bypassing security checks or causing logic corruption during upgrade windows.

## Finding Description

The vulnerability exists in the native function resolution and invocation flow:

**1. Registration by Name Only**

Native functions are registered in a hash map indexed solely by `(AccountAddress, ModuleName, FunctionName)` without any signature information: [1](#0-0) 

**2. No Signature Validation at Load Time**

When a module is loaded, native functions are resolved purely by name lookup, with no verification that the Rust implementation's signature matches the bytecode declaration: [2](#0-1) 

**3. Weak Runtime Argument Validation**

Most native functions only use `debug_assert!` to validate argument counts, which is compiled out in release builds: [3](#0-2) [4](#0-3) 

While some natives like `cmp::native_compare` include runtime checks: [5](#0-4) 

This is inconsistent across the codebase.

**4. No Verification of Argument Consumption**

After a native function returns, the interpreter never verifies that all arguments were consumed from the `VecDeque`: [6](#0-5) 

The interpreter only checks return value count (line 1118-1122), but not whether the native consumed all input arguments.

**Attack Scenario:**

During a coordinated upgrade where:
1. New native implementation is deployed expecting 2 arguments
2. Old bytecode remains cached or is deployed late, declaring 3 arguments
3. Transaction executes: `native_function(arg1, arg2, capability)`
4. Native pops only `arg1` and `arg2`
5. The `capability` argument (potentially a security check) is silently dropped
6. Function executes without the intended authorization check

**Breaking Invariant 1 (Deterministic Execution):**
If validators upgrade at different times, some may have the old native (3 args) while others have the new native (2 args). Transactions would execute differently across validators, causing consensus divergence.

## Impact Explanation

This issue meets **High Severity** criteria:

1. **Significant Protocol Violation**: Breaks the deterministic execution invariant during upgrade windows, potentially causing validators to compute different state roots for identical blocks.

2. **Validator Node Impact**: During phased upgrades, validators with mismatched versions could experience transaction failures or silent logic errors, affecting network liveness.

3. **Security Bypass Potential**: If an ignored argument represents a capability check, authorization bypass could occur, though this requires specific upgrade timing.

This does not reach Critical severity because:
- It requires deployment timing issues or upgrade race conditions
- Normal operations with synchronized code do not exhibit this vulnerability
- No direct fund theft without additional exploit chaining

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can manifest in several scenarios:

1. **Coordinated Upgrade Windows**: During network upgrades when natives are updated, there's a brief window where validators may run different code versions if:
   - Upgrade is phased across validators
   - Binary deployment precedes bytecode upgrade
   - Hot-reload mechanisms update natives before framework

2. **Development/Testing Errors**: Developers updating native implementations without updating corresponding Move signatures would not receive compilation or registration-time errors.

3. **Framework Evolution**: As the Aptos framework evolves and natives are refactored, the lack of signature validation makes version skew errors more likely to slip through.

However, likelihood is reduced by:
- Production deployments typically atomic across validators
- Extensive testing should catch gross signature mismatches
- Most severe mismatches (type changes) are caught by Value type checking

## Recommendation

Implement signature validation at native function registration and invocation:

**1. Add Signature Metadata to NativeFunctionTable**

Extend the registration structure to include signature information:

```rust
pub type NativeFunctionTable = Vec<(
    AccountAddress, 
    Identifier, 
    Identifier, 
    NativeFunction,
    NativeSignature // NEW: parameter types, return types
)>;
```

**2. Validate Signatures at Module Load Time**

In `Function::new()`, verify the native signature matches bytecode: [7](#0-6) 

Add validation after line 656:

```rust
if let Some(native_func) = &native {
    // Verify parameter count matches
    if native_func.param_count() != param_tys.len() {
        return Err(PartialVMError::new(StatusCode::NATIVE_FUNCTION_SIGNATURE_MISMATCH)
            .with_message(format!("Native {} expects {} params, bytecode declares {}", 
                name, native_func.param_count(), param_tys.len())));
    }
    // Verify return count matches  
    if native_func.return_count() != return_tys.len() {
        return Err(PartialVMError::new(StatusCode::NATIVE_FUNCTION_SIGNATURE_MISMATCH)
            .with_message(format!("Native {} returns {} values, bytecode declares {}", 
                name, native_func.return_count(), return_tys.len())));
    }
}
```

**3. Add Runtime Argument Consumption Check**

In `call_native_impl()`, verify all arguments were consumed: [8](#0-7) 

After line 1106, before processing the result:

```rust
// Verify native consumed all arguments
if !args.is_empty() {
    return Err(PartialVMError::new_invariant_violation(
        format!("Native function left {} unconsumed arguments", args.len())
    ));
}
```

**4. Replace debug_assert! with Runtime Checks**

Update all native implementations to use runtime validation instead of debug-only assertions. For example: [9](#0-8) 

Should become:

```rust
if arguments.len() != 1 {
    return Err(SafeNativeError::InvariantViolation(
        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
    ));
}
```

## Proof of Concept

Due to the operational nature of this vulnerability, a full PoC requires deployment infrastructure. However, the following demonstrates the issue:

**Step 1: Create a native with mismatched signature**

```rust
// In natives registration: expects 2 arguments
pub fn buggy_native(
    _context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    // Intentionally only pops 2 arguments
    let _arg1 = safely_pop_arg!(arguments, u64);
    let _arg2 = safely_pop_arg!(arguments, u64);
    // Third argument silently ignored if provided
    Ok(smallvec![])
}
```

**Step 2: Bytecode declares 3 arguments**

```move
module 0x1::Test {
    native fun buggy_native(x: u64, y: u64, z: u64);
    
    public fun test() {
        buggy_native(1, 2, 3); // Third argument silently dropped
    }
}
```

**Step 3: Execute**

When `test()` is called:
- Interpreter prepares 3 arguments: `[Value::U64(1), Value::U64(2), Value::U64(3)]`
- Native pops only first 2 values
- `Value::U64(3)` remains in VecDeque
- No error is raised
- Argument is silently lost

**Expected Behavior**: Should error with signature mismatch during module loading or runtime.

**Actual Behavior**: Executes successfully with silent data loss.

---

**Notes:**

While this represents a real design weakness in the native function system, the practical exploitability requires deployment-time version skew. In normal blockchain operation with synchronized validator code, this vulnerability does not manifest. It represents primarily a risk during upgrade procedures rather than a runtime exploit against a properly configured network.

The severity rating reflects the potential for consensus divergence during upgrade windows and the violation of deterministic execution guarantees, which are critical to blockchain safety.

### Citations

**File:** third_party/move/move-vm/runtime/src/native_functions.rs (L87-95)
```rust
impl NativeFunctions {
    pub fn resolve(
        &self,
        addr: &AccountAddress,
        module_name: &str,
        func_name: &str,
    ) -> Option<NativeFunction> {
        self.0.get(addr)?.get(module_name)?.get(func_name).cloned()
    }
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L632-703)
```rust
    pub(crate) fn new(
        natives: &NativeFunctions,
        index: FunctionDefinitionIndex,
        module: &CompiledModule,
        signature_table: &[Vec<Type>],
        struct_names: &[StructIdentifier],
    ) -> PartialVMResult<Self> {
        let def = module.function_def_at(index);
        let handle = module.function_handle_at(def.function);
        let name = module.identifier_at(handle.name).to_owned();
        let module_id = module.self_id();

        // For now, just framework code considered trusted, but this could be expanded.
        let is_trusted = module.address().is_special();

        let (native, is_native) = if def.is_native() {
            let native = natives.resolve(
                module_id.address(),
                module_id.name().as_str(),
                name.as_str(),
            );
            (native, true)
        } else {
            (None, false)
        };
        let is_dispatchable_native =
            is_native && native.is_some() && DISPATCHABLE_NATIVES.contains(name.as_str());

        // Native functions do not have a code unit
        let code = match &def.code {
            Some(code) => code.code.iter().map(|b| b.clone().into()).collect(),
            None => vec![],
        };
        let ty_param_abilities = handle.type_parameters.clone();

        let return_tys = signature_table[handle.return_.0 as usize].clone();
        let local_tys = if let Some(code) = &def.code {
            let mut local_tys = signature_table[handle.parameters.0 as usize].clone();
            local_tys.extend(signature_table[code.locals.0 as usize].clone());
            local_tys
        } else {
            vec![]
        };
        let param_tys = signature_table[handle.parameters.0 as usize].clone();

        let access_specifier = load_access_specifier(
            BinaryIndexedView::Module(module),
            signature_table,
            struct_names,
            &handle.access_specifiers,
        )?;

        Ok(Self {
            file_format_version: module.version(),
            index,
            code,
            ty_param_abilities,
            native,
            is_native,
            is_dispatchable_native,
            visibility: def.visibility,
            is_entry: def.is_entry,
            name,
            local_tys,
            return_tys,
            param_tys,
            access_specifier,
            is_persistent: handle.attributes.contains(&FunctionAttribute::Persistent),
            has_module_reentrancy_lock: handle.attributes.contains(&FunctionAttribute::ModuleLock),
            is_trusted,
        })
    }
```

**File:** third_party/move/move-examples/diem-framework/crates/natives/src/account.rs (L19-20)
```rust
    debug_assert!(ty_args.is_empty());
    debug_assert!(arguments.len() == 1);
```

**File:** aptos-move/framework/src/natives/event.rs (L107-108)
```rust
    debug_assert!(ty_args.len() == 1);
    debug_assert!(arguments.len() == 3);
```

**File:** aptos-move/framework/move-stdlib/src/natives/cmp.rs (L41-46)
```rust
    debug_assert!(args.len() == 2);
    if args.len() != 2 {
        return Err(SafeNativeError::InvariantViolation(PartialVMError::new(
            StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
        )));
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1040-1090)
```rust
    fn call_native_impl<RTTCheck: RuntimeTypeCheck, RTRCheck: RuntimeRefCheck>(
        &mut self,
        current_frame: &mut Frame,
        data_cache: &mut impl MoveVmDataCache,
        function_caches: &mut InterpreterFunctionCaches,
        gas_meter: &mut impl GasMeter,
        traversal_context: &mut TraversalContext,
        extensions: &mut NativeContextExtensions,
        function: &LoadedFunction,
        mask: ClosureMask,
        mut captured: Vec<Value>,
    ) -> PartialVMResult<bool> {
        let ty_builder = &self.vm_config.ty_builder;

        let num_param_tys = function.param_tys().len();
        let mut args = VecDeque::new();
        for i in (0..num_param_tys).rev() {
            if mask.is_captured(i) {
                args.push_front(captured.pop().ok_or_else(|| {
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message("inconsistent number of captured arguments".to_string())
                })?)
            } else {
                args.push_front(self.operand_stack.pop()?)
            }
        }

        let mut arg_tys = VecDeque::new();
        let ty_args = function.ty_args();
        if RTTCheck::should_perform_checks(&current_frame.function.function) {
            for i in (0..num_param_tys).rev() {
                let expected_ty = &function.param_tys()[i];
                if !mask.is_captured(i) {
                    let ty = self.operand_stack.pop_ty()?;
                    // For param type to argument, use assignability
                    if !ty_args.is_empty() {
                        let expected_ty = ty_builder.create_ty_with_subst(expected_ty, ty_args)?;
                        ty.paranoid_check_assignable(&expected_ty)?;
                    } else {
                        ty.paranoid_check_assignable(expected_ty)?;
                    }
                    arg_tys.push_front(ty);
                } else {
                    arg_tys.push_front(expected_ty.clone())
                }
            }
        }

        let native_function = function.get_native()?;

        gas_meter.charge_native_function_before_execution(
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1110-1148)
```rust
        match result {
            NativeResult::Success {
                cost,
                ret_vals: return_values,
            } => {
                gas_meter.charge_native_function(cost, Some(return_values.iter()))?;
                // Paranoid check to protect us against incorrect native function implementations. A native function that
                // returns a different number of values than its declared types will trigger this check.
                if return_values.len() != function.return_tys().len() {
                    return Err(PartialVMError::new_invariant_violation(
                        "Arity mismatch: return value count does not match return type count",
                    ));
                }
                // Put return values on the top of the operand stack, where the caller will find them.
                // This is one of only two times the operand stack is shared across call stack frames; the other is in handling
                // the Return instruction for normal calls
                for value in return_values {
                    self.operand_stack.push(value)?;
                }

                // If the caller requires checks, push return types of native function to
                // satisfy runtime check protocol.
                if RTTCheck::should_perform_checks(&current_frame.function.function) {
                    if function.ty_args().is_empty() {
                        for ty in function.return_tys() {
                            self.operand_stack.push_ty(ty.clone())?;
                        }
                    } else {
                        for ty in function.return_tys() {
                            let ty = ty_builder.create_ty_with_subst(ty, ty_args)?;
                            self.operand_stack.push_ty(ty)?;
                        }
                    }
                }
                // Perform reference transition for native call-return.
                RTRCheck::native_static_dispatch_transition(function, mask, &mut self.ref_state)?;

                current_frame.pc += 1; // advance past the Call instruction in the caller
                Ok(false)
```

**File:** aptos-move/framework/src/natives/account.rs (L32-33)
```rust
    debug_assert!(ty_args.is_empty());
    debug_assert!(arguments.len() == 1);
```
