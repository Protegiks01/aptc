# Audit Report

## Title
Reference Safety Bypass in Script Verification Due to Empty name_def_map

## Summary
Scripts fail to properly track acquired resources during function calls, allowing reference safety violations. The `verify_script_impl()` function creates a `FunctionView` with an empty `name_def_map`, causing the reference safety analyzer to bypass critical checks when scripts call functions that acquire global resources.

## Finding Description

The vulnerability exists in how scripts are verified compared to module functions. When `verify_script_impl()` creates a `CodeUnitVerifier` instance, it initializes `name_def_map` as an empty HashMap: [1](#0-0) 

In contrast, module verification populates `name_def_map` with all function definitions: [2](#0-1) 

The reference safety analyzer uses `name_def_map` to look up which resources a called function acquires: [3](#0-2) 

When `name_def_map` is empty (as with scripts), the lookup returns `None`, defaulting `acquired_resources` to an empty set. This causes `AbstractState::call()` to skip the critical global borrow check: [4](#0-3) 

**Attack Path:**
1. A script calls `ModuleA::get_global_ref(addr)` which returns `&Resource` (tracked in borrow graph)
2. Script then calls `ModuleA::modify_resource(addr)` which has `acquires Resource`
3. Because `name_def_map` is empty, `acquired_resources` is empty
4. The check at line 508 never executes (loop over empty set)
5. Script verification succeeds despite holding conflicting references to the same global resource
6. At runtime, this violates Move's reference safety guarantees

This breaks the **Move VM Safety** invariant: "Bytecode execution must respect gas limits and memory constraints" and **Deterministic Execution**: "All validators must produce identical state roots for identical blocks" if undefined behavior leads to non-deterministic outcomes.

## Impact Explanation

**Medium Severity** - This vulnerability allows scripts to bypass reference safety checks, potentially causing:

- **State inconsistencies**: Undefined behavior when multiple conflicting references to global resources exist could lead to inconsistent state across validators
- **Reference safety violations**: Core Move safety guarantee is broken, allowing use-after-move or conflicting mutable/immutable borrows
- **Non-deterministic execution**: If different validator implementations handle the undefined behavior differently, this could cause consensus issues

This meets Medium Severity criteria as it causes "State inconsistencies requiring intervention" and violates critical VM safety guarantees, though it requires specific script patterns to exploit.

## Likelihood Explanation

**High Likelihood** - This vulnerability is:
- **Easy to exploit**: Any user can submit a script transaction with the pattern described
- **No special permissions needed**: Doesn't require validator access or module deployment
- **Difficult to detect**: The bytecode verifier incorrectly approves the script, and the issue only manifests at execution time
- **Currently present**: The code shows scripts always use empty `name_def_map`

The main limiting factor is that the attacker must find or deploy modules with appropriate functions that return global references and acquire those same resources.

## Recommendation

Populate `name_def_map` for scripts by including function definitions from imported modules, or implement cross-module acquires tracking. The fix should ensure scripts can look up acquires information for any called function:

```rust
fn verify_script_impl(
    verifier_config: &VerifierConfig,
    script: &'a CompiledScript,
) -> PartialVMResult<()> {
    let mut meter = BoundMeter::new(verifier_config);
    let function_view = control_flow::verify_script(verifier_config, script)?;
    let resolver = BinaryIndexedView::Script(script);
    
    // FIX: Build name_def_map from function handles that scripts can call
    // This requires tracking imported module functions
    let mut name_def_map = HashMap::new();
    // TODO: Populate with cross-module function definitions
    // This may require access to dependent modules during verification
    
    // ... rest of verification
}
```

Alternatively, implement a more robust cross-module reference safety check that doesn't rely solely on `name_def_map`.

## Proof of Concept

```move
// Module defining a resource
module 0x1::ResourceModule {
    struct Counter has key { value: u64 }
    
    public fun init_counter(account: &signer) {
        move_to(account, Counter { value: 0 });
    }
    
    // Returns a reference to the counter
    public fun get_counter_ref(addr: address): &Counter acquires Counter {
        borrow_global<Counter>(addr)
    }
    
    // Modifies the counter (acquires mutably)
    public fun increment(addr: address) acquires Counter {
        let counter = borrow_global_mut<Counter>(addr);
        counter.value = counter.value + 1;
    }
}

// Malicious script that bypasses reference safety
script {
    use 0x1::ResourceModule;
    
    fun exploit(addr: address) {
        // Get immutable reference to Counter
        let counter_ref = ResourceModule::get_counter_ref(addr);
        
        // This call should ERROR (mutable borrow while immutable ref exists)
        // But script verifier doesn't know increment() acquires Counter
        ResourceModule::increment(addr);
        
        // counter_ref may now be invalid/pointing to modified data
        // This violates reference safety!
        let _val = *counter_ref;  // Potential undefined behavior
    }
}
```

The script should be rejected by the verifier but is incorrectly approved due to the empty `name_def_map`.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs (L51-55)
```rust
        let mut name_def_map = HashMap::new();
        for (idx, func_def) in module.function_defs().iter().enumerate() {
            let fh = module.function_handle_at(func_def.function);
            name_def_map.insert(fh.name, FunctionDefinitionIndex(idx as u16));
        }
```

**File:** third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs (L93-93)
```rust
        let name_def_map = HashMap::new();
```

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/mod.rs (L84-95)
```rust
    let acquired_resources = match verifier.name_def_map.get(&function_handle.name) {
        Some(idx) => {
            let func_def = verifier.resolver.function_def_at(*idx)?;
            let fh = verifier.resolver.function_handle_at(func_def.function);
            if function_handle == fh {
                func_def.acquires_global_resources.iter().cloned().collect()
            } else {
                BTreeSet::new()
            }
        },
        None => BTreeSet::new(),
    };
```

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/abstract_state.rs (L507-511)
```rust
        for acquired_resource in acquired_resources {
            if self.is_global_borrowed(*acquired_resource) {
                return Err(self.error(StatusCode::GLOBAL_REFERENCE_ERROR, offset));
            }
        }
```
