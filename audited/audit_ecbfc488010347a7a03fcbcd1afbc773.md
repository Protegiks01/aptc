# Audit Report

## Title
Gas Charging Bypass via Traversal Context Manipulation in Lazy Module Loading

## Summary
The `charge_package_dependencies()` function in lazy loading mode can be exploited to avoid paying gas for module dependencies. By pre-loading dependency modules during entry function execution, an attacker can publish new modules that depend on already-visited modules without being charged for those dependencies, violating the gas metering invariant.

## Finding Description

The vulnerability exists in the interaction between entry function execution and module publishing within a single transaction when lazy loading is enabled. [1](#0-0) 

During transaction execution, a single `TraversalContext` is created and reused throughout the entire transaction. This context tracks which modules have been visited to prevent redundant gas charging. [2](#0-1) 

When an entry function executes, the lazy loader loads required modules and marks them as visited in the traversal context: [3](#0-2) 

The `charge_module` function only charges gas if `visit_if_not_special_module_id` returns `true` (first visit). For subsequent accesses to the same module, no gas is charged.

Later in the same transaction, if the entry function publishes a module via `code::publish_package`, the `charge_package_dependencies` function is called: [4](#0-3) 

In lazy loading mode, this function iterates through immediate dependencies and attempts to charge gas: [5](#0-4) 

The critical flaw is at line 1642: if a dependency was already loaded during entry function execution, `visit_if_not_special_address` returns `false`, and the gas charging block (lines 1643-1654) is skipped entirely.

**Attack Scenario:**
1. Attacker deploys Module A at address `0xAttacker`
2. Attacker creates an entry function in Module Evil that:
   - First calls a function from Module A (causing A to be loaded and added to `traversal_context`)
   - Then calls `code::publish_package` to publish Module B that declares Module A as a dependency
3. When `charge_package_dependencies` executes for Module B, it finds Module A already in `traversal_context` and skips gas charging

The `publish_package` function is accessible because master signers (regular users) have all permissions by default: [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability represents a **High Severity** gas metering bypass that violates Critical Invariant #9: "Resource Limits: All operations must respect gas, storage, and computational limits."

**Direct Impact:**
- Attackers can publish modules with large dependencies without paying gas for those dependencies
- For dependencies totaling multiple megabytes, savings could be substantial (potentially thousands of gas units)
- Enables economic attacks by artificially reducing the cost of module publishing

**Systemic Impact:**
- Breaks the fundamental gas metering assumption that all dependency loading is charged
- Could enable spam attacks by reducing the cost barrier for publishing modules
- Undermines the economic security model of the blockchain
- May enable resource exhaustion attacks if combined with other vectors

**Consensus Impact:**
All validators will execute identically (deterministic execution is preserved), but the gas charged will be incorrect, allowing underpriced transactions to be included in blocks.

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is highly likely to be exploited because:

1. **Low Complexity:** The attack requires only standard Move module development skills
2. **No Special Access:** Any user can publish modules (master signers have default permissions)
3. **Easy Detection:** Attackers can locally test to verify the gas savings before deploying
4. **Economic Incentive:** Large dependencies provide clear financial benefit (reduced gas costs)
5. **No Prerequisites:** Doesn't require special network conditions or timing
6. **Repeatable:** The attack can be executed multiple times by the same or different attackers

The only requirement is that lazy loading must be enabled, which is the current production configuration for Aptos.

## Recommendation

**Immediate Fix:**
Separate the `TraversalContext` used for entry function execution from the one used for module publishing gas charging. Create a fresh `TraversalContext` specifically for `charge_package_dependencies`:

```rust
fn charge_package_dependencies<'a>(
    &self,
    module_storage: &impl AptosModuleStorage,
    gas_meter: &mut impl AptosGasMeter,
    traversal_context: &mut TraversalContext<'a>,  // Existing context for validation
    modules: &'a [CompiledModule],
) -> Result<(), VMStatus> {
    // ... existing code ...

    // Lazy loading path
    if self.features().is_lazy_loading_enabled() {
        // CREATE A NEW TRAVERSAL CONTEXT FOR DEPENDENCY CHARGING
        // This ensures pre-loaded modules don't bypass gas charging
        let traversal_storage_for_deps = TraversalStorage::new();
        let mut dependency_charging_context = TraversalContext::new(&traversal_storage_for_deps);
        
        // Mark modules being published as visited to avoid charging them
        for module in modules.iter() {
            let addr = module.self_addr();
            let name = module.self_name();
            dependency_charging_context.visit_if_not_special_address(addr, name);
        }
        
        // Charge for immediate dependencies using the new context
        for (dep_addr, dep_name) in modules
            .iter()
            .flat_map(|module| module.immediate_dependencies_iter())
            .filter(|addr_and_name| !module_ids_in_bundle.contains(addr_and_name))
        {
            if dependency_charging_context.visit_if_not_special_address(dep_addr, dep_name) {
                let size = module_storage
                    .unmetered_get_existing_module_size(dep_addr, dep_name)
                    .map(|v| v as u64)?;
                gas_meter
                    .charge_dependency(
                        DependencyKind::Existing,
                        dep_addr,
                        dep_name,
                        NumBytes::new(size),
                    )
                    .map_err(|err| err.finish(Location::Undefined))?;
            }
        }
        
        // Friend checking remains the same
        // ...
    }
    
    Ok(())
}
```

**Alternative Fix:**
Track separately which modules were loaded for dependency gas charging vs. regular execution to ensure all publishing dependencies are always charged.

## Proof of Concept

```move
// Module A - Will be used as a dependency
module 0xAttacker::ModuleA {
    public fun helper_function() {
        // Some logic
    }
}

// Evil module that exploits the vulnerability
module 0xAttacker::EvilPublisher {
    use 0xAttacker::ModuleA;
    use aptos_framework::code;
    use std::vector;
    use std::string;
    
    public entry fun exploit_gas_bypass(
        attacker: &signer,
        metadata_serialized: vector<u8>,
        module_b_bytecode: vector<vector<u8>>
    ) {
        // Step 1: Load ModuleA into traversal_context
        // This charges gas once for ModuleA
        ModuleA::helper_function();
        
        // Step 2: Publish ModuleB which depends on ModuleA
        // ModuleB's bytecode should include ModuleA in its immediate_dependencies
        // When charge_package_dependencies runs:
        // - It will check if ModuleA needs gas charging
        // - visit_if_not_special_address returns FALSE (already visited in Step 1)
        // - NO GAS IS CHARGED for ModuleA as a dependency of ModuleB!
        code::publish_package_txn(attacker, metadata_serialized, module_b_bytecode);
        
        // Result: ModuleB is published with ModuleA as a dependency,
        // but the attacker only paid gas for ModuleA once (in step 1),
        // not the second time when it should be charged as a dependency.
    }
}
```

**Test Steps:**
1. Deploy ModuleA with a simple function
2. Compile ModuleB with ModuleA as an explicit dependency
3. Create transaction calling `exploit_gas_bypass` with ModuleB's bytecode
4. Compare gas charged vs. expected: the dependency charging for ModuleA will be missing
5. Verify via gas meter logs that ModuleA appears in traversal_context before `charge_package_dependencies` executes

**Notes**

This vulnerability breaks the invariant that all module dependencies must be charged for gas during publishing. The root cause is the reuse of a single `TraversalContext` throughout the entire transaction lifetime, allowing state pollution between different execution phases. The fix requires isolating the dependency charging context from the execution context to ensure accurate gas metering regardless of prior module loading within the transaction.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1599-1677)
```rust
    fn charge_package_dependencies<'a>(
        &self,
        module_storage: &impl AptosModuleStorage,
        gas_meter: &mut impl AptosGasMeter,
        traversal_context: &mut TraversalContext<'a>,
        modules: &'a [CompiledModule],
    ) -> Result<(), VMStatus> {
        // Compute all IDs used in the bundle. Later, exclude these from the set of immediate
        // dependencies and friends of the bundle for charging / checks.
        let module_ids_in_bundle = modules
            .iter()
            .map(|module| (module.self_addr(), module.self_name()))
            .collect::<BTreeSet<_>>();

        // Not lazy loading: traverse all transitive dependencies and charge gas. This will
        // recursively traverse all dependencies of the immediate dependencies and friends of the
        // published bundle.
        if !self.features().is_lazy_loading_enabled() {
            check_dependencies_and_charge_gas(
                module_storage,
                gas_meter,
                traversal_context,
                modules
                    .iter()
                    .flat_map(|module| {
                        module
                            .immediate_dependencies_iter()
                            .chain(module.immediate_friends_iter())
                    })
                    .filter(|addr_and_name| !module_ids_in_bundle.contains(addr_and_name)),
            )?;
            return Ok(());
        }

        // Lazy loading otherwise.

        // With lazy loading, we will check only immediate dependencies for linking checks,
        // not the whole dependencies closure, so charge gas here for them.
        for (dep_addr, dep_name) in modules
            .iter()
            .flat_map(|module| module.immediate_dependencies_iter())
            .filter(|addr_and_name| !module_ids_in_bundle.contains(addr_and_name))
        {
            if traversal_context.visit_if_not_special_address(dep_addr, dep_name) {
                let size = module_storage
                    .unmetered_get_existing_module_size(dep_addr, dep_name)
                    .map(|v| v as u64)?;
                gas_meter
                    .charge_dependency(
                        DependencyKind::Existing,
                        dep_addr,
                        dep_name,
                        NumBytes::new(size),
                    )
                    .map_err(|err| err.finish(Location::Undefined))?;
            }
        }

        // Also, we need to make sure friends, when published, are limited to the same
        // package (bundle).
        for (friend_addr, friend_name) in modules
            .iter()
            .flat_map(|module| module.immediate_friends_iter())
        {
            if !module_ids_in_bundle.contains(&(friend_addr, friend_name)) {
                let msg = format!(
                    "Module {}::{} is declared as a friend and should be part of the \
                             module bundle, but it is not",
                    friend_addr, friend_name
                );
                let err = PartialVMError::new(StatusCode::FRIEND_NOT_FOUND_IN_MODULE_BUNDLE)
                    .with_message(msg)
                    .finish(Location::Undefined)
                    .into_vm_status();
                return Err(err);
            }
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1995-1996)
```rust
        let traversal_storage = TraversalStorage::new();
        let mut traversal_context = TraversalContext::new(&traversal_storage);
```

**File:** third_party/move/move-vm/runtime/src/module_traversal.rs (L23-30)
```rust
pub struct TraversalContext<'a> {
    visited: BTreeMap<(&'a AccountAddress, &'a IdentStr), ()>,

    pub referenced_scripts: &'a Arena<Arc<CompiledScript>>,
    pub referenced_modules: &'a Arena<Arc<CompiledModule>>,
    pub referenced_module_ids: &'a Arena<ModuleId>,
    pub referenced_module_bundles: &'a Arena<Vec<CompiledModule>>,
}
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L54-77)
```rust
    /// Charges gas for the module load if the module has not been loaded already.
    fn charge_module(
        &self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        module_id: &ModuleId,
    ) -> PartialVMResult<()> {
        if traversal_context.visit_if_not_special_module_id(module_id) {
            let addr = module_id.address();
            let name = module_id.name();

            let size = self
                .module_storage
                .unmetered_get_existing_module_size(addr, name)
                .map_err(|err| err.to_partial())?;
            gas_meter.charge_dependency(
                DependencyKind::Existing,
                addr,
                name,
                NumBytes::new(size as u64),
            )?;
        }
        Ok(())
    }
```

**File:** aptos-move/framework/aptos-framework/sources/permissioned_signer.move (L561-563)
```text
        if (!is_permissioned_signer(s)) {
            // master signer has all permissions
            return true
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L168-228)
```text
    public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) acquires PackageRegistry {
        check_code_publishing_permission(owner);
        // Disallow incompatible upgrade mode. Governance can decide later if this should be reconsidered.
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );

        let addr = signer::address_of(owner);
        if (!exists<PackageRegistry>(addr)) {
            move_to(owner, PackageRegistry { packages: vector::empty() })
        };

        // Checks for valid dependencies to other packages
        let allowed_deps = check_dependencies(addr, &pack);

        // Check package against conflicts
        // To avoid prover compiler error on spec
        // the package need to be an immutable variable
        let module_names = get_module_names(&pack);
        let package_immutable = &borrow_global<PackageRegistry>(addr).packages;
        let len = vector::length(package_immutable);
        let index = len;
        let upgrade_number = 0;
        vector::enumerate_ref(package_immutable
        , |i, old| {
            let old: &PackageMetadata = old;
            if (old.name == pack.name) {
                upgrade_number = old.upgrade_number + 1;
                check_upgradability(old, &pack, &module_names);
                index = i;
            } else {
                check_coexistence(old, &module_names)
            };
        });

        // Assign the upgrade counter.
        pack.upgrade_number = upgrade_number;

        let packages = &mut borrow_global_mut<PackageRegistry>(addr).packages;
        // Update registry
        let policy = pack.upgrade_policy;
        if (index < len) {
            *vector::borrow_mut(packages, index) = pack
        } else {
            vector::push_back(packages, pack)
        };

        event::emit(PublishPackage {
            code_address: addr,
            is_upgrade: upgrade_number > 0
        });

        // Request publish
        if (features::code_dependency_check_enabled())
            request_publish_with_allowed_deps(addr, module_names, allowed_deps, code, policy.policy)
        else
        // The new `request_publish_with_allowed_deps` has not yet rolled out, so call downwards
        // compatible code.
            request_publish(addr, module_names, code, policy.policy)
    }
```
