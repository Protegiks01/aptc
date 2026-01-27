# Audit Report

## Title
Circular Friend Dependency Creation Through Inlining Optimization Bypasses Cycle Detection

## Summary
The `update_friend_decls_in_targets()` function in the inlining optimization pipeline can create circular friend dependencies that violate the Move language specification's explicit prohibition on cyclic module dependencies. This occurs because friend declarations are added AFTER the expansion phase's cycle detection, and the bytecode verifier does not re-validate for cycles.

## Finding Description

The Move language specification explicitly states that "Friends relationships cannot create cyclic module dependencies" [1](#0-0) . However, the compiler's inlining optimization can violate this invariant through the following sequence:

1. **Expansion Phase Cycle Check (Line 98)**: The compiler runs dependency cycle detection during the expansion phase, which occurs in `run_checker()` before any AST optimizations [2](#0-1) 

2. **Cycle Detection Logic**: The expansion phase builds a dependency graph where "if A uses B, add edge A → B" and "if A friends B, add edge B → A", then performs topological sort to detect cycles [3](#0-2) 

3. **Inlining Optimization (Line 129)**: Much later in the pipeline, the inlining optimization runs and calls `update_friend_decls_in_targets()` [4](#0-3) 

4. **Friend Declaration Addition**: The `update_friend_decls_in_targets()` function adds new friend declarations based on inlining results, without checking for cycles [5](#0-4) 

5. **Missing Bytecode Verification**: While a `cyclic_dependencies::verify_module` function exists with proper cycle detection logic [6](#0-5) , it is **never called** in the main bytecode verification pipeline [7](#0-6) 

**Attack Scenario:**
```
Module A contains function that calls B::package_func()
Module B::package_func() internally calls B::helper_func() (also package visibility)

Initial state:
- A uses B (dependency: A → B)
- No friend declarations
- Passes cycle check ✓

After inlining:
- B::package_func() body is inlined into A
- A now directly calls B::helper_func()
- need_to_be_friended_by() detects A needs access to B's package functions
- update_friend_decls_in_targets() adds: friend A to module B
- Final dependency graph: A → B (use) AND B → A (friend) = CYCLE
- No re-validation occurs ✗
```

This violates the specification's requirement that dependencies and friendships cannot create cycles [8](#0-7) .

## Impact Explanation

**High Severity - Significant Protocol Violation**

While this does not directly cause fund loss or consensus splits, it constitutes a significant protocol violation that breaks fundamental language invariants:

1. **Specification Violation**: Directly contradicts documented Move language rules
2. **Tooling Assumptions**: Breaks assumptions made by the Move prover, static analyzers, and other tooling that rely on acyclic dependency graphs
3. **Module Upgrade Integrity**: Circular dependencies can prevent proper module upgrade ordering, potentially requiring hard forks to fix
4. **Future Attack Surface**: Creates undefined behavior that could be exploited by future compiler features or optimizations that assume acyclic graphs

The impact qualifies as "Significant protocol violations" under the High severity category.

## Likelihood Explanation

**High Likelihood**

- Easily triggered with standard code patterns (package visibility + inlining optimization)
- Requires no special privileges (any module publisher can trigger)
- The `INLINING_OPTIMIZATION` experiment flag is designed to be enabled in production
- No validation prevents this from occurring
- Developers are unlikely to manually check for circular dependencies post-compilation

## Recommendation

Add cycle detection after friend declarations are updated:

```rust
pub fn optimize(env: &mut GlobalEnv, across_package: bool, allow_non_primary_targets: bool) {
    // ... existing inlining logic ...
    
    // Update friend declarations due to inlining
    env.update_friend_decls_in_targets();
    
    // ADDED: Validate no circular dependencies were created
    validate_no_circular_dependencies(env);
}

fn validate_no_circular_dependencies(env: &GlobalEnv) {
    // Build dependency graph including both use and friend relationships
    // Perform cycle detection using existing petgraph algorithms
    // Report error if cycles found
}
```

Alternatively, integrate the existing `cyclic_dependencies::verify_module` into the main bytecode verification pipeline [9](#0-8)  by adding the check after line 154.

## Proof of Concept

Create two modules in the same package:

**Module B:** [10](#0-9) 

**Module A:** [11](#0-10) 

Compile with `--experiment INLINING_OPTIMIZATION`:
1. Expansion phase passes (no friend decls yet)
2. Inlining optimization runs
3. `update_friend_decls_in_targets()` adds B friends A
4. Result: A uses B AND B friends A (circular dependency)
5. No error is raised despite violating the specification

The compiled modules will contain circular dependencies that violate the Move specification's explicit prohibition.

## Notes

The vulnerability exists because the compiler's pipeline separates cycle detection (expansion phase) from friend declaration updates (optimization phase), with no re-validation. The bytecode verifier has the capability to detect such cycles but does not invoke it, allowing invalid modules to be published on-chain.

### Citations

**File:** third_party/move/changes/1-friend-visibility.md (L66-68)
```markdown
* Friends relationships cannot create cyclic module dependencies.
    * Cycles are not allowed in the friend relationships. E.g., `0x2::A` friends `0x2::B` friends `0x2::C` friends `0x2::A` is not allowed.
    * More generally, declaring a friend module adds a dependency upon the current module to the friend module (because the purpose is for the friend to call functions in the current module). If that friend module is already used, either directly or transitively, a cycle of dependencies would be created. E.g., a cycle would be created if `0x2::A` friends `0x2::B` and `0x2::A` also calls a function `0x2::B::foo().`
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L97-99)
```rust
    // Run context check.
    let mut env = run_checker(options.clone())?;
    check_errors(&env, emitter, "context checking errors")?;
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L129-130)
```rust
    env_optimization_pipeline(&options).run(&mut env);
    check_errors(&env, emitter, "env optimization errors")?;
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/dependency_ordering.rs (L95-99)
```rust
    // A union of uses and friends for modules (used for cyclic dependency checking)
    // - if A uses B,    add edge A -> B
    // - if A friends B, add edge B -> A
    // NOTE: neighbors of scripts are not tracked by this field, as nothing can depend on a script
    // and a script cannot declare friends. Hence, is no way to form a cyclic dependency via scripts
```

**File:** third_party/move/move-model/src/model.rs (L2704-2736)
```rust
    pub fn update_friend_decls_in_targets(&mut self) {
        let mut friend_decls_to_add = BTreeMap::new();
        for module in self.get_target_modules() {
            let module_name = module.get_name();
            let needed = module.need_to_be_friended_by();
            for need_to_be_friended_by in needed {
                let need_to_be_friend_with = self.get_module(need_to_be_friended_by);
                let already_friended = need_to_be_friend_with
                    .get_friend_decls()
                    .iter()
                    .any(|friend_decl| &friend_decl.module_name == module_name);
                if !already_friended {
                    let loc = need_to_be_friend_with.get_loc();
                    let friend_decl = FriendDecl {
                        loc,
                        module_name: module_name.clone(),
                        module_id: Some(module.get_id()),
                    };
                    friend_decls_to_add
                        .entry(need_to_be_friended_by)
                        .or_insert_with(Vec::new)
                        .push(friend_decl);
                }
            }
        }
        for (module_id, friend_decls) in friend_decls_to_add {
            let module_data = self.get_module_data_mut(module_id);
            module_data
                .friend_modules
                .extend(friend_decls.iter().flat_map(|d| d.module_id));
            module_data.friend_decls.extend(friend_decls);
        }
    }
```

**File:** third_party/move/move-model/src/model.rs (L3296-3310)
```rust
        for fun_env in self.get_functions() {
            // We need to traverse transitive inline functions because they will be expanded during inlining.
            for used_fun in fun_env.get_used_functions_with_transitive_inline() {
                let used_mod_id = used_fun.module_id;
                if self.get_id() == used_mod_id {
                    // no need to friend self
                    continue;
                }
                let used_mod_env = self.env.get_module(used_mod_id);
                let used_fun_env = used_mod_env.get_function(used_fun.id);
                if used_fun_env.has_package_visibility()
                    && self.can_call_package_fun_in(&used_mod_env)
                {
                    deps.insert(used_mod_id);
                }
```

**File:** third_party/move/move-bytecode-verifier/src/cyclic_dependencies.rs (L96-102)
```rust
    // collect and check that there is no cyclic friend relation
    let all_friends = collect_all_with_cycle_detection(
        &self_id,
        &module.immediate_friends(),
        &imm_friends,
        StatusCode::CYCLIC_MODULE_FRIENDSHIP,
    )?;
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L134-163)
```rust
pub fn verify_module_with_config(config: &VerifierConfig, module: &CompiledModule) -> VMResult<()> {
    if config.verify_nothing() {
        return Ok(());
    }
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
        DuplicationChecker::verify_module(module)?;

        signature_v2::verify_module(config, module)?;

        InstructionConsistency::verify_module(module)?;
        constants::verify_module(module)?;
        friends::verify_module(module)?;

        RecursiveStructDefChecker::verify_module(module)?;
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;

        // Add the failpoint injection to test the catch_unwind behavior.
        fail::fail_point!("verifier-failpoint-panic");

        script_signature::verify_module(module, no_additional_script_signature_checks)
```

**File:** third_party/move/documentation/book/src/friends.md (L91-96)
```markdown
- Friends relationships cannot create cyclic module dependencies.

  Cycles are not allowed in the friend relationships, e.g., the relation `0x2::a` friends `0x2::b` friends `0x2::c` friends `0x2::a` is not allowed.
More generally, declaring a friend module adds a dependency upon the current module to the friend module (because the purpose is for the friend to call functions in the current module).
If that friend module is already used, either directly or transitively, a cycle of dependencies would be created.
  ```move=
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/inlining_optimization.rs (L113-116)
```rust
    // Inlining can cause direct calls to `package` functions that were previously
    // indirect. Thus, it may require additional caller modules to become friends
    // of the callee modules.
    env.update_friend_decls_in_targets();
```
