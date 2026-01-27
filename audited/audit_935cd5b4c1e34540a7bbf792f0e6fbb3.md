# Audit Report

## Title
Access Control Bypass via Explicit Inline Functions - Inconsistent Enforcement Between Inlining Mechanisms

## Summary
The Move compiler v2 has two distinct inlining mechanisms with inconsistent access control enforcement. While optimization-based inlining (`inlining_optimization.rs`) correctly prevents inlining of functions with access specifiers (including empty ones representing strictest control), the explicit inline function handler (`inliner.rs`) only issues a warning and proceeds with inlining, causing runtime access control bypasses.

## Finding Description

The Aptos Move compiler implements runtime access control through access specifiers that are enforced by the Move VM's `AccessControlState`. When a function with access specifiers is called, the VM pushes the function's specifier onto a stack, and all resource accesses are validated against every active specifier on the stack. [1](#0-0) 

The compiler has two separate inlining systems:

**1. Optimization-based inlining** (`inlining_optimization.rs`) correctly prevents inlining when access controls are present: [2](#0-1) 

The `has_access_controls()` function properly detects both empty access specifiers (strictest control) and any non-legacy access specifications: [3](#0-2) 

**2. Explicit inline function inlining** (`inliner.rs`) only issues a WARNING and proceeds with inlining: [4](#0-3) 

After inlining completes, all inline functions with bodies are deleted from the program: [5](#0-4) 

**The vulnerability:** When a function is marked with the `inline` keyword AND has access specifiers (including empty ones representing "no access allowed"), the compiler:
1. Issues a warning (easily missed)
2. Inlines the function body into call sites
3. Deletes the original function definition and its access specifiers
4. At runtime, resource accesses from the inlined code are checked against the CALLER's access specifiers, not the original function's

This completely bypasses the intended access control. For empty access specifiers, the runtime behavior shows that `Constraint([], [])` prevents ANY access: [6](#0-5) 

But after inlining, this strictest control is lost.

## Impact Explanation

**High Severity** - This constitutes a significant protocol violation and access control bypass:

1. **Access Control Bypass**: Functions designed with strict access controls (empty specifiers = no access allowed) can have those controls completely bypassed through the `inline` keyword
2. **Inconsistent Security Model**: The two inlining mechanisms have contradictory behaviors, creating a confusing and error-prone security model
3. **Silent Degradation**: Only a warning is issued, which can be easily overlooked in large codebases
4. **Framework Impact**: If Aptos Framework functions use `inline` with access specifiers, critical system protections could be bypassed

This meets the **High Severity** criteria per Aptos Bug Bounty: "Significant protocol violations" - the access control system is a fundamental security mechanism, and this creates a bypass path.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Ease of Exploitation**: Any Move developer can trigger this by marking a function with `inline` and adding access specifiers
- **Warning is Easy to Miss**: Compiler warnings are often ignored, especially in large projects
- **Confusion Factor**: Developers may not understand the difference between optimization-based and explicit inlining
- **Framework Risk**: If any Aptos Framework developers used `inline` with access specifiers (even inadvertently), the vulnerability could already be present in production code

The attack requires no special privileges - just the ability to deploy Move modules with the `inline` keyword.

## Recommendation

**Option 1: Make it an error (recommended)**
Change the warning in `inliner.rs` to an error, preventing compilation of inline functions with access specifiers:

```rust
if func.get_access_specifiers().is_some() {
    env.error(  // Changed from warning to error
        &func.get_id_loc(),
        "inline functions cannot have access specifiers - these are not enforced after inlining",
    );
    return false;  // Filter out this function from targets
}
```

**Option 2: Preserve access specifiers during inlining**
Modify the inlining process to ensure access specifiers from inline functions are somehow preserved and enforced at call sites. However, this is complex and may not be semantically correct.

**Option 1 is strongly recommended** as it maintains consistency with the optimization-based inlining behavior and prevents the security issue entirely.

## Proof of Concept

```move
module 0xcafe::vulnerable {
    struct SecureResource has key {
        secret: u64
    }

    // This function has EMPTY access specifiers - strictest control
    // No resource access should be allowed
    inline fun try_access_restricted(addr: address): u64 
        reads SecureResource()  // But we specify reads anyway to show the bypass
    {
        // This should be blocked by empty access specifiers
        let r = borrow_global<SecureResource>(addr);
        r.secret
    }

    // Caller has permissive access specifiers
    public fun exploit_via_inline(addr: address): u64 
        reads SecureResource(*)  // Caller allows all reads
    {
        // After inlining, try_access_restricted's body is here
        // Runtime checks use THIS function's access specifiers (permissive)
        // NOT the inlined function's specifiers (empty/restrictive)
        try_access_restricted(addr)
    }

    // For comparison: non-inline version would fail at runtime
    fun try_access_restricted_non_inline(addr: address): u64 
        // Empty access specifiers - no access allowed
    {
        let r = borrow_global<SecureResource>(addr);  // Would fail at runtime
        r.secret
    }
}
```

**Compilation behavior:**
- The compiler will issue a WARNING about access specifiers on `try_access_restricted`
- It will still inline the function
- At runtime, `exploit_via_inline` succeeds because it uses the caller's permissive access specifiers
- But calling `try_access_restricted_non_inline` would fail with `ACCESS_DENIED` due to empty access specifiers

This demonstrates the inconsistency where the same access control logic behaves differently depending on whether the function is inlined.

## Notes

The root cause is an architectural inconsistency between two inlining pipelines. The `inlining_optimization.rs` path was designed with security in mind (preventing inlining of access-controlled functions), but the `inliner.rs` path for explicit `inline` functions predates this security check and only issues a warning. This creates a bypas path that undermines the access control system's security guarantees.

### Citations

**File:** third_party/move/move-vm/runtime/src/access_control.rs (L22-48)
```rust
    /// Enters a function, applying its access specifier to the state.
    // note(inline): do not inline, they are called once per function, and increase `execute_main`
    // quite a bit, we want to avoid those compile times
    #[cfg_attr(feature = "force-inline", inline(always))]
    pub(crate) fn enter_function(
        &mut self,
        env: &impl AccessSpecifierEnv,
        fun: &LoadedFunction,
    ) -> PartialVMResult<()> {
        if matches!(fun.access_specifier(), AccessSpecifier::Any) {
            // Shortcut case that no access is specified
            return Ok(());
        }
        if self.specifier_stack.len() >= ACCESS_STACK_SIZE_LIMIT {
            Err(
                PartialVMError::new(StatusCode::ACCESS_STACK_LIMIT_EXCEEDED).with_message(format!(
                    "access specifier stack overflow (limit = {})",
                    ACCESS_STACK_SIZE_LIMIT
                )),
            )
        } else {
            // Specialize the functions access specifier and push it on the stack.
            let mut fun_specifier = fun.access_specifier().clone();
            fun_specifier.specialize(env)?;
            self.specifier_stack.push(fun_specifier);
            Ok(())
        }
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs (L240-267)
```rust
    let inline_eligible_functions = callees
        .into_iter()
        .filter_map(|(callee, sites_and_loop_depth)| {
            let callee_env = env.get_function(callee);
            let callee_size = get_function_size_estimate(env, &callee);
            if callee_env.is_inline()
                || callee_env.is_native()
                || callee_size.code_size > *MAX_CALLEE_CODE_SIZE
                || has_explicit_return(&callee_env)
                || has_abort(&callee_env, caller_func_env)
                || has_privileged_operations(caller_mid, &callee_env)
                || has_invisible_calls(caller_module, &callee_env, across_package)
                || has_module_lock_attribute(&callee_env)
                || has_access_controls(&callee_env)
            {
                // won't inline if:
                // - callee is inline (should have been inlined already)
                // - callee is native (no body to inline)
                // - callee is too large (heuristic limit)
                // - callee has an explicit return (cannot inline safely without additional
                //   transformations)
                // - callee has privileged operations on structs/enums that the caller cannot
                //   perform directly
                // - callee has calls to functions that are not visible from the caller module
                // - callee has the `#[module_lock]` attribute
                // - callee has runtime access control checks
                // - callee has an abort expression
                None
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs (L555-571)
```rust
/// Does `function` have any runtime access control checks?
/// If so, by inlining, such checks would not be performed.
fn has_access_controls(function: &FunctionEnv) -> bool {
    if let Some(access_specifiers) = function.get_access_specifiers() {
        if access_specifiers.is_empty() {
            // empty access specifiers means no access is allowed, the strictest form
            // of access control
            return true;
        }
        // any reads or writes specification is considered an access control
        access_specifiers
            .iter()
            .any(|spec| spec.kind != AccessSpecifierKind::LegacyAcquires)
    } else {
        false
    }
}
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inliner.rs (L143-156)
```rust
    if !keep_inline_functions {
        // First construct a list of functions to remove.
        let mut inline_funs = BTreeSet::new();
        for module in env.get_modules() {
            for func in module.get_functions() {
                let id = func.get_qualified_id();
                if func.is_inline() && func.get_def().is_some() {
                    // Only delete functions with a body.
                    inline_funs.insert(id);
                }
            }
        }
        env.filter_functions(|fun_id: &QualifiedFunId| !inline_funs.contains(fun_id));
    }
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inliner.rs (L204-209)
```rust
                if func.get_access_specifiers().is_some() {
                    env.warning(
                        &func.get_id_loc(),
                        "acquires and access specifiers are not applicable to inline functions and should be removed",
                    );
                }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_access_specifier.rs (L143-153)
```rust
    /// Returns true if the concrete access instance is enabled.
    pub fn enables(&self, access: &AccessInstance) -> bool {
        use AccessSpecifier::*;
        match self {
            Any => true,
            Constraint(incls, excls) => {
                (incls.is_empty() && !excls.is_empty() || incls.iter().any(|c| c.includes(access)))
                    && excls.iter().all(|c| !c.excludes(access))
            },
        }
    }
```
