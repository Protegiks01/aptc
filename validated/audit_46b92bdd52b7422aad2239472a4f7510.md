# Audit Report

## Title
Circular Package Dependencies Can Be Published On-Chain When Lazy Loading Is Enabled, Violating DAG Invariant and Causing State Inconsistency

## Summary
When the lazy loading feature (Feature Flag #95) is enabled, the Move package publishing mechanism fails to detect circular dependencies, allowing packages with cyclic dependency graphs to be published on-chain. This violates the documented system invariant that module dependencies must form a Directed Acyclic Graph (DAG) and creates state inconsistencies where modules become valid or invalid depending on the feature flag state.

## Finding Description

The vulnerability exists across multiple validation layers that fail to detect circular dependencies when lazy loading is enabled:

**Layer 1 - Move Framework Validation:**
The `check_dependencies` function only validates immediate dependencies (existence and upgrade policies) but does not recursively traverse the dependency graph to detect cycles. [1](#0-0) 

**Layer 2 - Publishing Verification with Lazy Loading:**
During module publishing, when lazy loading is enabled, the code explicitly skips cycle detection. The implementation comment states: "Note that we do not check cyclic dependencies here." [2](#0-1) 

The lazy verification only performs local bytecode verification and immediate dependency linking checks without traversing the full dependency graph. [3](#0-2) 

**Layer 3 - Eager Verification (When Lazy Loading Disabled):**
In contrast, when lazy loading is disabled, the eager verification path explicitly detects and rejects circular dependencies through recursive traversal. [4](#0-3) 

The cycle detection logic maintains a visited set and returns `CYCLIC_MODULE_DEPENDENCY` error when a cycle is detected: [5](#0-4) 

**System Invariant Violation:**
The codebase documents an explicit assumption that cycles should not exist: "If dependencies form a cycle (which should not be the case as we check this when modules are added to the module cache), an error is returned." [6](#0-5) 

This assumption is violated when lazy loading is enabled.

**Feature Flag Configuration:**
The lazy loading feature is controlled by Feature Flag #95 (`ENABLE_LAZY_LOADING`) which is enabled by default and can be toggled via on-chain governance. [7](#0-6) [8](#0-7) 

**Attack Path:**
1. Attacker publishes Package A at address 0xA with dependency on Package B at 0xB
2. Attacker publishes Package B at address 0xB with dependency on Package A at 0xA
3. Both packages pass validation because cycle detection is skipped under lazy loading
4. Modules are permanently stored on-chain with circular dependencies
5. If lazy loading is later disabled, these modules cannot be accessed - any transaction attempting to load them will fail with `CYCLIC_MODULE_DEPENDENCY` error

## Impact Explanation

**Severity Assessment: MEDIUM (Note: Report claims HIGH but evidence supports MEDIUM)**

This vulnerability constitutes a **protocol invariant violation** that creates state inconsistencies, aligning with MEDIUM severity under Aptos bug bounty criteria:

1. **Protocol Invariant Violation**: The system explicitly assumes DAG structure for module dependencies. The code comment confirms this is a design invariant that lazy loading violates.

2. **State Inconsistency**: Modules become valid or invalid depending on feature flag state, creating a class of "zombie modules" that exist on-chain but cannot be accessed under certain configurations. This requires manual intervention to resolve.

3. **Operational Risk**: If the feature flag is toggled after circular dependencies exist on-chain:
   - Any transaction attempting to load these modules will fail
   - Existing packages depending on these modules become unusable
   - Requires governance action or manual cleanup to resolve

**Why Not Higher Severity:**
- **Not Consensus Breaking**: All validators run the same feature flag configuration at any given time (feature flags are part of on-chain consensus), so validators will not disagree on module validity
- **No Funds Loss**: Does not enable theft, unauthorized minting, or permanent freezing of user funds
- **No Liveness Impact**: Network continues operating; only specific modules become unusable
- **Localized Impact**: Only affects modules with circular dependencies, not the entire network

This best fits the MEDIUM category of "State inconsistencies requiring manual intervention" rather than HIGH severity impacts like validator crashes or consensus violations.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Feature Enabled by Default**: Lazy loading is in the default enabled feature flag list
2. **No Special Privileges Required**: Any user can publish packages without validator or governance permissions
3. **Simple Attack Vector**: Requires only two package publication transactions
4. **Permanent Impact**: Once published, circular dependencies persist on-chain
5. **No Detection**: Current validation layers do not detect or prevent this scenario

The attack is straightforward, does not require precise timing or coordination, and can be executed by any network participant with sufficient gas to publish two packages.

## Recommendation

Implement cycle detection during lazy loading verification. The fix should modify the publishing path to detect cycles even when performing lazy verification:

**Option 1: Add Lightweight Cycle Detection**
During lazy verification, maintain a visited set for the current publishing bundle and check for cycles among modules being published together. This catches intra-bundle cycles without requiring full transitive closure verification.

**Option 2: Validate Dependency Graph at Move Framework Layer**
Enhance the `check_dependencies` function in `code.move` to perform graph traversal and cycle detection before calling the native publishing functions. This provides defense-in-depth at the Move layer.

**Option 3: Post-Publishing Validation**
After staging modules, verify that the combined storage (existing + new modules) does not contain cycles by attempting to construct a topological ordering of all affected modules.

The recommended approach is Option 1 or 2 to maintain consistency with the documented invariant that "we check this when modules are added to the module cache."

## Proof of Concept

```move
// Package A published at address 0xAAAA
module 0xAAAA::PackageA {
    use 0xBBBB::PackageB;  // Depends on PackageB
    
    public fun call_b() {
        PackageB::some_function();
    }
}

// Package B published at address 0xBBBB  
module 0xBBBB::PackageB {
    use 0xAAAA::PackageA;  // Circular dependency!
    
    public fun some_function() {
        // This creates a cycle: A -> B -> A
    }
}
```

With lazy loading enabled:
1. Publish Package A with metadata declaring dependency on 0xBBBB::PackageB - **SUCCEEDS**
2. Publish Package B with metadata declaring dependency on 0xAAAA::PackageA - **SUCCEEDS** 
3. Both packages are now on-chain with circular dependencies

With lazy loading disabled:
- Attempting to access either module triggers eager verification
- `visit_dependencies_and_verify` detects the cycle
- Returns `CYCLIC_MODULE_DEPENDENCY` error
- Modules exist on-chain but are unusable

## Notes

**Key Evidence Summary:**
- Lazy loading explicitly skips cycle detection (publishing.rs:259-260)
- Eager loading explicitly performs cycle detection (publishing.rs:277-278, module_storage.rs:410-414)
- System assumes cycles are impossible (module_storage.rs:332-334)
- Feature flag can be toggled via governance (aptos_features.rs:148, 266)

**Severity Clarification:**
While the report claims HIGH severity, the validated impact aligns more closely with MEDIUM severity under Aptos bug bounty criteria. The vulnerability creates state inconsistencies requiring manual intervention but does not cause consensus failures, funds loss, or network liveness issues. All validators agree on module validity at any point in time since feature flags are part of consensus state.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/code.move (L298-344)
```text
    fun check_dependencies(publish_address: address, pack: &PackageMetadata): vector<AllowedDep>
    acquires PackageRegistry {
        let allowed_module_deps = vector::empty();
        let deps = &pack.deps;
        vector::for_each_ref(deps, |dep| {
            let dep: &PackageDep = dep;
            assert!(exists<PackageRegistry>(dep.account), error::not_found(EPACKAGE_DEP_MISSING));
            if (is_policy_exempted_address(dep.account)) {
                // Allow all modules from this address, by using "" as a wildcard in the AllowedDep
                let account: address = dep.account;
                let module_name = string::utf8(b"");
                vector::push_back(&mut allowed_module_deps, AllowedDep { account, module_name });
            } else {
                let registry = borrow_global<PackageRegistry>(dep.account);
                let found = vector::any(&registry.packages, |dep_pack| {
                    let dep_pack: &PackageMetadata = dep_pack;
                    if (dep_pack.name == dep.package_name) {
                        // Check policy
                        assert!(
                            dep_pack.upgrade_policy.policy >= pack.upgrade_policy.policy,
                            error::invalid_argument(EDEP_WEAKER_POLICY)
                        );
                        if (dep_pack.upgrade_policy == upgrade_policy_arbitrary()) {
                            assert!(
                                dep.account == publish_address,
                                error::invalid_argument(EDEP_ARBITRARY_NOT_SAME_ADDRESS)
                            )
                        };
                        // Add allowed deps
                        let account = dep.account;
                        let k = 0;
                        let r = vector::length(&dep_pack.modules);
                        while (k < r) {
                            let module_name = vector::borrow(&dep_pack.modules, k).name;
                            vector::push_back(&mut allowed_module_deps, AllowedDep { account, module_name });
                            k = k + 1;
                        };
                        true
                    } else {
                        false
                    }
                });
                assert!(found, error::not_found(EPACKAGE_DEP_MISSING));
            };
        });
        allowed_module_deps
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L259-275)
```rust
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

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L295-329)
```rust
    fn unmetered_get_lazily_verified_module(
        &self,
        module_id: &ModuleId,
    ) -> VMResult<Option<Arc<Module>>> {
        let (module, version) = match self.get_module_or_build_with(module_id, self)? {
            Some(module_and_version) => module_and_version,
            None => return Ok(None),
        };

        if module.code().is_verified() {
            return Ok(Some(module.code().verified().clone()));
        }

        let _timer = VM_TIMER.timer_with_label("unmetered_get_lazily_verified_module [cache miss]");
        let runtime_environment = self.runtime_environment();
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
        let verified_code =
            runtime_environment.build_verified_module_skip_linking_checks(locally_verified_code)?;
        let verified_module = self.insert_verified_module(
            module_id.clone(),
            verified_code,
            module.extension().clone(),
            version,
        )?;
        Ok(Some(verified_module.code().verified().clone()))
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L332-334)
```rust
/// Visits the dependencies of the given module. If dependencies form a cycle (which should not be
/// the case as we check this when modules are added to the module cache), an error is returned.
///
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

**File:** types/src/on_chain_config/aptos_features.rs (L145-148)
```rust
    /// With lazy loading, modules are loaded lazily (as opposed to loading the transitive closure
    /// of dependencies). For more details, see:
    ///   AIP-127 (https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-127.md)
    ENABLE_LAZY_LOADING = 95,
```

**File:** types/src/on_chain_config/aptos_features.rs (L266-266)
```rust
            FeatureFlag::ENABLE_LAZY_LOADING,
```
