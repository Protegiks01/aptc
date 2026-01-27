# Audit Report

## Title
Access Control Bypass in Move VM Native Function Dynamic Dispatch

## Summary
The Move VM's access control system fails to enforce access specifiers for native functions that perform dynamic dispatch, allowing the call chain to bypass intended access restrictions on resource operations.

## Finding Description
The Move VM implements an access control system that restricts what resource operations functions can perform through access specifiers (reads/writes/acquires). This system maintains a stack of active access specifiers, and all specifiers in the call chain must allow a resource operation for it to succeed. [1](#0-0) 

The vulnerability exists in how native functions are handled. When a Move function is called, its access specifier is pushed onto the control stack: [2](#0-1) 

However, when a native function is called, it does NOT push its access specifier onto the stack: [3](#0-2) 

Native functions have access specifiers loaded from bytecode: [4](#0-3) 

When a native function performs dynamic dispatch (returns `NativeResult::CallFunction`), only the target function's access specifier is enforced, not the native function's own access specifier: [5](#0-4) 

This creates an access control bypass where a native function with restrictive access specifiers can dispatch to a Move function that performs operations the native function itself should not be allowed to perform.

## Impact Explanation
This represents a **High severity** protocol violation. While no current native functions exploit this vulnerability (as they lack restrictive access specifiers), the architectural flaw violates the fundamental access control invariant that ALL functions in a call chain must have their restrictions enforced. If exploited through bytecode manipulation or future native functions with restrictive access specifiers, this could allow unauthorized resource operations, breaking the "Access Control" critical invariant.

## Likelihood Explanation
**Current likelihood: Low**. Exploitation requires either:
1. Deploying bytecode with a native function that has restrictive access specifiers (requires framework-level access)
2. Future addition of native functions with restrictive access specifiers that perform dynamic dispatch

However, the architectural flaw creates systemic risk as the implementation is incomplete - access specifiers are loaded but not enforced for native functions.

## Recommendation
Enforce access specifiers for native functions by pushing their access specifiers onto the stack before execution. Modify the native function call path to include access control enforcement:

```rust
// In interpreter.rs, around line 521
if function.is_native() {
    // Add access control for native function BEFORE calling it
    self.access_control
        .enter_function(&current_frame, &function)
        .map_err(|e| set_err_info!(current_frame, e))?;
    
    let dispatched = self.call_native::<RTTCheck, RTRCheck>(
        &mut current_frame,
        data_cache,
        function_caches,
        gas_meter,
        traversal_context,
        extensions,
        &function,
        ClosureMask::empty(),
        vec![],
    )?;
    
    // Exit access control for native function after completion
    if !dispatched {
        self.access_control
            .exit_function(&function)
            .map_err(|e| set_err_info!(current_frame, e))?;
    }
    // If dispatched, exit happens when returning from dispatched function
    
    trace_recorder.record_successful_instruction(&Instruction::Call(fh_idx));
    if dispatched {
        trace_recorder.record_entrypoint(&current_frame.function)
    }
    continue;
}
```

## Proof of Concept
Due to the nature of this vulnerability, a complete PoC requires either bytecode manipulation or framework-level changes. A conceptual PoC would involve:

1. Creating a native function in bytecode with access specifier `reads ResourceX`
2. Implementing that native to return `NativeResult::CallFunction` dispatching to a Move function with `writes ResourceX`
3. The dispatched function successfully writes to ResourceX despite the native function only having read permissions
4. The access control check passes because the native function's `reads` specifier was never added to the stack

This demonstrates the architectural vulnerability where the access control invariant (all call chain specifiers must be enforced) is violated for native functions.

**Notes:**
- This vulnerability exists due to incomplete implementation of the access control feature for native functions
- Access specifiers are correctly loaded from bytecode for all functions including natives, but enforcement only happens for non-native functions
- The DISPATCHABLE_NATIVES list confirms that native dynamic dispatch is an intended feature
- No current native functions in the codebase have restrictive access specifiers, limiting immediate exploitability
- The vulnerability requires either framework-level access or bytecode manipulation to exploit

### Citations

**File:** third_party/move/move-vm/runtime/src/access_control.rs (L13-19)
```rust
/// The state of access control. Maintains a stack of active access specifiers.
///
/// Every access to a resource must satisfy every specifier on the stack.
#[derive(Clone, Debug, Default)]
pub struct AccessControlState {
    specifier_stack: Vec<AccessSpecifier>,
}
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L521-537)
```rust
                    if function.is_native() {
                        let dispatched = self.call_native::<RTTCheck, RTRCheck>(
                            &mut current_frame,
                            data_cache,
                            function_caches,
                            gas_meter,
                            traversal_context,
                            extensions,
                            &function,
                            ClosureMask::empty(),
                            vec![],
                        )?;
                        trace_recorder.record_successful_instruction(&Instruction::Call(fh_idx));
                        if dispatched {
                            trace_recorder.record_entrypoint(&current_frame.function)
                        }
                        continue;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L916-918)
```rust
        self.access_control
            .enter_function(&frame, &frame.function)
            .map_err(|e| self.set_location(e))?;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1238-1248)
```rust
                self.set_new_call_frame::<RTTCheck, RTRCheck>(
                    current_frame,
                    gas_meter,
                    Rc::new(target_func),
                    fn_guard,
                    CallType::NativeDynamicDispatch,
                    frame_cache,
                    ClosureMask::empty(),
                    vec![],
                )
                .map_err(|err| err.to_partial())?;
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L677-682)
```rust
        let access_specifier = load_access_specifier(
            BinaryIndexedView::Module(module),
            signature_table,
            struct_names,
            &handle.access_specifiers,
        )?;
```
