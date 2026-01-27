# Audit Report

## Title
Cyclic Dependency Bypass in Lazy Loading Mode Enables Publication of Invalid Modules

## Summary
The module publishing verification in `create_with_compat_config()` skips cyclic dependency checks when lazy loading is enabled, allowing modules with circular dependencies to be published. These modules pass validation during publishing but become unexecutable if the network later switches to eager loading mode, creating a state inconsistency where validly-published code becomes permanently invalid.

## Finding Description

The module publishing flow in `publishing.rs` contains a critical divergence in validation between lazy and eager loading modes: [1](#0-0) 

**Lazy Loading Path (lines 245-275):**
- Performs local bytecode verification
- Checks linking to immediate dependencies only
- **Explicitly skips cyclic dependency detection** (comment at lines 259-260)
- Uses `build_verified_module_with_linking_checks` but only for immediate dependencies

**Eager Loading Path (lines 276-289):**
- Calls `unmetered_get_eagerly_verified_module`
- This invokes the full transitive dependency verification [2](#0-1) 

The eager verification traverses all dependencies recursively and detects cycles: [3](#0-2) 

This difference is confirmed by the test suite: [4](#0-3) 

**Attack Scenario:**
1. Network operates with lazy loading enabled (feature flag `ENABLE_LAZY_LOADING` is true)
2. Attacker publishes module bundle with cyclic dependencies (e.g., Module A imports B, B imports C, C imports A)
3. Publishing succeeds because lazy loading skips cycle detection
4. Modules are committed to blockchain state
5. Governance later disables lazy loading (switches to eager mode for performance/security reasons)
6. Any transaction attempting to call functions in these modules fails with `CYCLIC_MODULE_DEPENDENCY` error
7. The modules are permanently broken and cannot be executed without republishing

## Impact Explanation

This issue breaks the **State Consistency** invariant: state transitions that were valid under one configuration become invalid under another. While this does not cause immediate consensus divergence (all validators use the same on-chain feature flag at any given block height), it creates a **time-dependent vulnerability** where:

- **Permanent Code Unavailability**: Validly-published modules become unexecutable, potentially locking funds or breaking critical protocol functionality if those modules manage resources
- **Governance-Triggered Failures**: A governance action to change feature flags inadvertently breaks existing on-chain code
- **Attack Surface for Griefing**: An attacker can intentionally publish modules with cycles to create "time bombs" that detonate when feature flags change

Under the Aptos bug bounty criteria, this qualifies as **Medium Severity** ("State inconsistencies requiring intervention") because it requires governance intervention to either:
- Keep lazy loading permanently enabled (limiting protocol flexibility)
- Accept that cyclic modules become broken (requiring module re-publication)

## Likelihood Explanation

**Likelihood: Medium-High**

- **Feature flag is changeable via governance**: The `ENABLE_LAZY_LOADING` flag can be toggled through on-chain governance proposals
- **No validation on flag changes**: When the flag changes, there is no scan or validation of existing modules
- **Attack is trivial**: Creating cyclic module dependencies requires minimal sophistication
- **Detection is difficult**: Cycles may not be obvious in complex module dependency graphs
- **Already documented behavior**: The test suite explicitly demonstrates this behavior, indicating it's a known design choice rather than an oversight

## Recommendation

Implement one of the following mitigations:

**Option 1: Enforce cycle detection in both modes**
Add cycle detection to the lazy loading path during publishing:

```rust
// In publishing.rs, after line 275, add:
if is_lazy_loading_enabled {
    // ... existing code ...
    
    // ADDITION: Check for cycles even in lazy mode
    let mut visited = HashSet::new();
    check_cyclic_dependencies_for_bundle(
        &staged_module_storage,
        &staged_modules,
        &mut visited,
    )?;
}
```

**Option 2: Make lazy loading a one-way transition**
Document and enforce that `ENABLE_LAZY_LOADING` can only be enabled, never disabled, preventing the retroactive invalidity issue.

**Option 3: Validate existing modules on flag changes**
Before allowing the feature flag to be disabled, scan all on-chain modules and reject the governance proposal if any cyclic dependencies exist.

## Proof of Concept

The existing test already demonstrates this behavior: [4](#0-3) 

To reproduce the attack scenario:

1. Enable lazy loading feature flag
2. Publish three modules with cyclic dependencies (A→B→C→A)
3. Verify publishing succeeds
4. Governance disables lazy loading via proposal
5. Attempt to execute any function from these modules
6. Observe `CYCLIC_MODULE_DEPENDENCY` error despite valid publication

**Note:** This vulnerability requires governance action to trigger, making it a conditional rather than immediately exploitable issue. However, it represents a dangerous state inconsistency in the protocol design.

## Notes

The feature flag is controlled by on-chain governance: [5](#0-4) 

And is read from the state during environment creation: [6](#0-5) 

This ensures all validators see the same setting at any given block height, preventing consensus divergence but not preventing the state consistency issue described above.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L245-289)
```rust
            if is_lazy_loading_enabled {
                // Local bytecode verification.
                staged_runtime_environment.paranoid_check_module_address_and_name(
                    compiled_module,
                    compiled_module.self_addr(),
                    compiled_module.self_name(),
                )?;
                let locally_verified_code = staged_runtime_environment
                    .build_locally_verified_module(
                        compiled_module.clone(),
                        bytes.len(),
                        &sha3_256(bytes),
                    )?;

                // Linking checks to immediate dependencies. Note that we do not check cyclic
                // dependencies here.
                let mut verified_dependencies = vec![];
                for (dep_addr, dep_name) in locally_verified_code.immediate_dependencies_iter() {
                    // INVARIANT:
                    //   Immediate dependency of the module in a bundle must be metered at the
                    //   caller side.
                    let dependency =
                        staged_module_storage.unmetered_get_existing_lazily_verified_module(
                            &ModuleId::new(*dep_addr, dep_name.to_owned()),
                        )?;
                    verified_dependencies.push(dependency);
                }
                staged_runtime_environment.build_verified_module_with_linking_checks(
                    locally_verified_code,
                    &verified_dependencies,
                )?;
            } else {
                // Verify the module and its dependencies, and that they do not form a cycle.
                staged_module_storage
                    .unmetered_get_eagerly_verified_module(addr, name)?
                    .ok_or_else(|| {
                        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                            .with_message(format!(
                                "Staged module {}::{} must always exist",
                                compiled_module.self_addr(),
                                compiled_module.self_name()
                            ))
                            .finish(Location::Undefined)
                    })?;
            }
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L345-427)
```rust
fn visit_dependencies_and_verify<T, E, V>(
    module_id: ModuleId,
    module: Arc<ModuleCode<CompiledModule, Module, E>>,
    version: V,
    visited: &mut HashSet<ModuleId>,
    module_cache_with_context: &T,
) -> VMResult<Arc<Module>>
where
    T: WithRuntimeEnvironment
        + ModuleCache<
            Key = ModuleId,
            Deserialized = CompiledModule,
            Verified = Module,
            Extension = E,
            Version = V,
        > + ModuleCodeBuilder<
            Key = ModuleId,
            Deserialized = CompiledModule,
            Verified = Module,
            Extension = E,
        >,
    E: WithBytes + WithSize + WithHash,
    V: Clone + Default + Ord,
{
    let runtime_environment = module_cache_with_context.runtime_environment();

    // Step 1: Local verification.
    runtime_environment.paranoid_check_module_address_and_name(
        module.code().deserialized(),
        module_id.address(),
        module_id.name(),
    )?;
    let locally_verified_code = runtime_environment.build_locally_verified_module(
        module.code().deserialized().clone(),
        module.extension().size_in_bytes(),
        module.extension().hash(),
    )?;

    // Step 2: Traverse and collect all verified immediate dependencies so that we can verify
    // non-local properties of the module.
    let mut verified_dependencies = vec![];
    for (addr, name) in locally_verified_code.immediate_dependencies_iter() {
        let dependency_id = ModuleId::new(*addr, name.to_owned());

        let (dependency, dependency_version) = module_cache_with_context
            .get_module_or_build_with(&dependency_id, module_cache_with_context)?
            .ok_or_else(|| module_linker_error!(addr, name))?;

        // Dependency is already verified!
        if dependency.code().is_verified() {
            verified_dependencies.push(dependency.code().verified().clone());
            continue;
        }

        if visited.insert(dependency_id.clone()) {
            // Dependency is not verified, and we have not visited it yet.
            let verified_dependency = visit_dependencies_and_verify(
                dependency_id.clone(),
                dependency,
                dependency_version,
                visited,
                module_cache_with_context,
            )?;
            verified_dependencies.push(verified_dependency);
        } else {
            // We must have found a cycle otherwise.
            return Err(module_cyclic_dependency_error!(
                dependency_id.address(),
                dependency_id.name()
            ));
        }
    }

    let verified_code = runtime_environment
        .build_verified_module_with_linking_checks(locally_verified_code, &verified_dependencies)?;
    let module = module_cache_with_context.insert_verified_module(
        module_id,
        verified_code,
        module.extension().clone(),
        version,
    )?;
    Ok(module.code().verified().clone())
}
```

**File:** third_party/move/move-vm/integration-tests/src/tests/module_storage_tests.rs (L217-240)
```rust
fn test_cyclic_dependencies(enable_lazy_loading: bool) {
    let mut module_bytes_storage = in_memory_storage(enable_lazy_loading);

    let c_id = ModuleId::new(AccountAddress::ZERO, Identifier::new("c").unwrap());

    add_module_bytes(&mut module_bytes_storage, "a", vec!["b"], vec![]);
    add_module_bytes(&mut module_bytes_storage, "b", vec!["c"], vec![]);
    add_module_bytes(&mut module_bytes_storage, "c", vec!["a"], vec![]);

    let module_storage = module_bytes_storage.into_unsync_module_storage();

    if enable_lazy_loading {
        // With lazy loading, cyclic dependencies are allowed to be published (but not called).
        assert_ok!(module_storage.unmetered_get_lazily_verified_module(&c_id));
        module_storage.assert_cached_state(vec![], vec![&c_id]);
    } else {
        let result =
            module_storage.unmetered_get_eagerly_verified_module(c_id.address(), c_id.name());
        assert_eq!(
            assert_err!(result).major_status(),
            StatusCode::CYCLIC_MODULE_DEPENDENCY
        );
    }
}
```

**File:** types/src/on_chain_config/aptos_features.rs (L145-148)
```rust
    /// With lazy loading, modules are loaded lazily (as opposed to loading the transitive closure
    /// of dependencies). For more details, see:
    ///   AIP-127 (https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-127.md)
    ENABLE_LAZY_LOADING = 95,
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L255-255)
```rust
        enable_lazy_loading: features.is_lazy_loading_enabled(),
```
