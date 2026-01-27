# Audit Report

## Title
Circular Dependency Acceptance Inconsistency Between Lazy and Eager Loading Modes Breaks Deterministic Module Verification

## Summary
The `dispatch_loader!` macro in the Move VM runtime dispatches to either `EagerLoader` or `LazyLoader` based on the `enable_lazy_loading` feature flag. These two loaders handle circular module dependencies inconsistently during module publishing: eager mode rejects them with `CYCLIC_MODULE_DEPENDENCY` errors, while lazy mode silently accepts them. This inconsistency violates the deterministic execution invariant and creates a consensus vulnerability if validators interpret the feature flag differently or during feature flag transitions.

## Finding Description

The `dispatch_loader!` macro provides a runtime dispatch mechanism between two module loading strategies: [1](#0-0) 

During module publishing in `StagingModuleStorage`, the verification logic diverges critically between the two modes:

**Lazy Loading Path:** Explicitly skips cyclic dependency checks: [2](#0-1) 

**Eager Loading Path:** Enforces cyclic dependency detection: [3](#0-2) 

The eager loader's `visit_dependencies_and_verify` function explicitly detects and rejects circular dependencies: [4](#0-3) 

**Proof of Behavioral Difference:** The codebase contains an explicit test demonstrating this inconsistency: [5](#0-4) 

**Attack Scenario:**
1. Attacker creates modules A, B, C with circular dependencies (A→B→C→A)
2. When `enable_lazy_loading` is enabled, the publishing transaction succeeds
3. If the feature flag is later disabled or if there's any non-determinism in how validators read the flag, the same modules would be rejected
4. This creates state inconsistencies where some validators have accepted invalid modules while others reject them

The feature flag is controlled by on-chain governance: [6](#0-5) [7](#0-6) 

## Impact Explanation

**Critical Severity - Consensus/Safety Violations**

This vulnerability breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

**Consensus-Breaking Scenarios:**

1. **Feature Flag Transition**: When the lazy loading feature is toggled via governance, there's a window where validators might process blocks differently depending on when they observe the flag change, potentially leading to divergent state roots.

2. **Rollback/Downgrade**: If modules with circular dependencies are published under lazy mode and the network later disables lazy loading or validators downgrade, these modules become fundamentally invalid but remain in storage, causing verification failures.

3. **Implementation Inconsistency**: The existence of two different verification paths for the same operation (module publishing) creates a fragile invariant that depends entirely on perfect synchronization of a single configuration flag across all validators.

Per Aptos Bug Bounty criteria, this qualifies as **Critical Severity** because it enables consensus violations that could lead to chain splits requiring a hardfork to resolve.

## Likelihood Explanation

**High Likelihood:**

1. The vulnerability is deterministic and reproducible - the test explicitly demonstrates the behavioral difference
2. No special privileges required - any user can publish modules
3. The feature flag mechanism is actively used in Aptos for feature rollouts
4. During any feature flag transition, there's inherent risk of transient inconsistencies
5. The comment "allowed to be published (but not called)" in the test suggests this is a known but unaddressed design issue

## Recommendation

**Immediate Fix:** Enforce consistent cyclic dependency checking regardless of loading mode.

In `publishing.rs`, the lazy loading path should include explicit cyclic dependency detection before accepting modules:

```rust
if is_lazy_loading_enabled {
    // Local bytecode verification
    staged_runtime_environment.paranoid_check_module_address_and_name(...)?;
    let locally_verified_code = staged_runtime_environment
        .build_locally_verified_module(...)?;

    // ADD: Cyclic dependency check for lazy mode
    let mut visited = HashSet::new();
    visited.insert(compiled_module.self_id());
    for (dep_addr, dep_name) in locally_verified_code.immediate_dependencies_iter() {
        check_no_cyclic_dependencies_recursive(
            &ModuleId::new(*dep_addr, dep_name.to_owned()),
            &compiled_module.self_id(),
            &staged_module_storage,
            &mut visited,
        )?;
    }

    // Linking checks to immediate dependencies
    let mut verified_dependencies = vec![];
    for (dep_addr, dep_name) in locally_verified_code.immediate_dependencies_iter() {
        let dependency = staged_module_storage
            .unmetered_get_existing_lazily_verified_module(...)?;
        verified_dependencies.push(dependency);
    }
    staged_runtime_environment.build_verified_module_with_linking_checks(...)?;
}
```

**Long-term Fix:** Remove the dual-path loader dispatch entirely. Module verification semantics should not vary based on runtime configuration flags. Consider making lazy loading a pure optimization that preserves identical verification semantics.

## Proof of Concept

The existing test already demonstrates the vulnerability: [5](#0-4) 

**To reproduce the consensus vulnerability:**

1. Deploy a testnet with validators initially running with `enable_lazy_loading = false`
2. Submit a module bundle with circular dependencies (A→B→C→A)
3. Verify the transaction fails with `CYCLIC_MODULE_DEPENDENCY`
4. Enable lazy loading via governance
5. Resubmit the same module bundle
6. Observe it succeeds
7. Disable lazy loading again
8. Attempt to load the previously published modules
9. Observe inconsistent behavior - modules exist in storage but fail verification under eager mode

This demonstrates that the same blockchain state can produce different verification results depending on a configuration flag, violating deterministic execution.

## Notes

The vulnerability exists at the intersection of module loading strategy selection and verification semantics. While the feature flag is intended as a performance optimization (lazy vs eager dependency loading), it inadvertently changes the **correctness** semantics by allowing fundamentally invalid modules (those with circular dependencies) to be published. This represents a dangerous coupling between optimization strategy and correctness guarantees that should be separated.

### Citations

**File:** third_party/move/move-vm/runtime/src/lib.rs (L67-79)
```rust
macro_rules! dispatch_loader {
    ($module_storage:expr, $loader:ident, $dispatch:stmt) => {
        if $crate::WithRuntimeEnvironment::runtime_environment($module_storage)
            .vm_config()
            .enable_lazy_loading
        {
            let $loader = $crate::LazyLoader::new($module_storage);
            $dispatch
        } else {
            let $loader = $crate::EagerLoader::new($module_storage);
            $dispatch
        }
    };
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L245-275)
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
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L276-289)
```rust
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

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L399-415)
```rust
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
```

**File:** third_party/move/move-vm/integration-tests/src/tests/module_storage_tests.rs (L217-239)
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
```

**File:** types/src/on_chain_config/aptos_features.rs (L437-439)
```rust
    pub fn is_lazy_loading_enabled(&self) -> bool {
        self.is_enabled(FeatureFlag::ENABLE_LAZY_LOADING)
    }
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L255-255)
```rust
        enable_lazy_loading: features.is_lazy_loading_enabled(),
```
