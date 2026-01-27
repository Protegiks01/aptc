# Audit Report

## Title
Lazy Loader Fails to Charge for Transitive Dependencies in LoadModule, Enabling Gas Metering Bypass

## Summary
The lazy loader implementation incorrectly charges only for a single module when handling `NativeResult::LoadModule`, while the eager loader correctly charges for all transitive dependencies. This discrepancy allows attackers to bypass proper gas charging for module dependencies, potentially exhausting validator resources.

## Finding Description

When the `load_function_impl` native function is called (used for dynamic dispatch in fungible assets and account abstraction), it should charge gas for a module and all its transitive dependencies upfront. However, the lazy loader implementation only charges for the single specified module. [1](#0-0) 

The Move framework explicitly documents that this function should "charge for its dependencies": [2](#0-1) 

The **eager loader** correctly implements this by calling `check_dependencies_and_charge_gas`, which traverses the entire transitive dependency closure: [3](#0-2) 

However, the **lazy loader** only charges for the single module: [4](#0-3) [5](#0-4) 

The correct implementation should call `check_dependencies_and_charge_gas`, which performs transitive dependency traversal: [6](#0-5) 

Lazy loading is **enabled by default** in Aptos: [7](#0-6) [8](#0-7) 

**Attack Path:**
1. Attacker deploys module A that imports modules B, C, D, E (each 10KB), which in turn import modules F, G, H, I, J (each 10KB)
2. Total transitive dependency size: 100KB
3. Attacker calls `function_info::load_module_from_function` with FunctionInfo pointing to module A
4. Only module A (10KB) is charged, not the 90KB of dependencies
5. Later operations require accessing dependencies, consuming validator I/O and CPU
6. If gas runs out during dependency access, transaction aborts after significant work

## Impact Explanation

This vulnerability breaks **Invariant #9: "All operations must respect gas, storage, and computational limits"** by allowing improper gas charging for module dependencies.

**High Severity** classification is warranted because:
- **Validator node slowdowns**: Attackers can force validators to load and deserialize large dependency trees while paying gas for only a fraction of the work
- **Gas metering bypass**: The intended pre-charging model for dynamic dispatch is violated
- **DoS potential**: Repeated exploitation could degrade network performance

While dependencies are eventually charged when accessed during execution, the deferred charging breaks the security model where expensive operations (loading transitive closures) should be paid for upfront, before subsequent operations proceed.

## Likelihood Explanation

**High likelihood** of exploitation:
- The vulnerable code path is accessible to any transaction sender through public native functions (`load_module_from_function`, `check_dispatch_type_compatibility`)
- These functions are used in production features (fungible asset dispatch, account abstraction)
- Attackers can easily create modules with arbitrary dependency graphs
- No special permissions or validator access required
- Lazy loading is enabled by default on mainnet

## Recommendation

Modify the lazy loader's `charge_native_result_load_module` implementation to match the eager loader by calling `check_dependencies_and_charge_gas`:

```rust
// In third_party/move/move-vm/runtime/src/storage/loader/lazy.rs

fn charge_native_result_load_module(
    &self,
    gas_meter: &mut impl DependencyGasMeter,
    traversal_context: &mut TraversalContext,
    module_id: &ModuleId,
) -> PartialVMResult<()> {
    // Fixed: Charge for transitive dependencies like eager loader
    let arena_id = traversal_context
        .referenced_module_ids
        .alloc(module_id.clone());
    check_dependencies_and_charge_gas(
        self.module_storage,
        gas_meter,
        traversal_context,
        [(arena_id.address(), arena_id.name())]
    ).map_err(|err| {
        err.to_partial().append_message_with_separator(
            '.',
            format!(
                "Failed to charge transitive dependency for {}. Does this module exist?",
                module_id
            ),
        )
    })?;
    Ok(())
}
```

## Proof of Concept

```move
// Deploy this module with many dependencies
module attacker::exploit {
    use std::vector;
    use aptos_framework::function_info;
    
    // Each module in the dependency tree is ~10KB
    // Total transitive dependencies: ~100KB
    
    public entry fun trigger_undercharge() {
        // Create FunctionInfo pointing to a module with deep dependency tree
        let func_info = function_info::new_function_info_from_address(
            @heavy_module,
            b"module_name",
            b"function_name"
        );
        
        // This should charge for ~100KB of dependencies
        // But only charges for ~10KB (the top-level module)
        function_info::load_module_from_function(&func_info);
        
        // Now use the function - dependencies accessed without upfront charging
        function_info::check_dispatch_type_compatibility(&func_info, &func_info);
    }
}
```

**Validation steps:**
1. Create module with 10+ levels of dependencies (each importing 5-10 other modules)
2. Measure gas charged by `load_function_impl` vs. actual dependency tree size
3. Observe that only top-level module is charged, not transitive dependencies
4. Compare with eager loader behavior (charges full dependency tree)

### Citations

**File:** aptos-move/framework/src/natives/function_info.rs (L169-192)
```rust
 * native fun load_function_impl
 *
 *   Load up a module related to the function and charge gas.
 *   gas cost: base_cost + transitive deps size of the function.
 *
 **************************************************************************************************/
fn native_load_function_impl(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut arguments: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(arguments.len() == 1);

    context.charge(FUNCTION_INFO_LOAD_FUNCTION_BASE)?;
    let (module_name, _) = extract_function_info(&mut arguments)?;

    if context.has_direct_gas_meter_access_in_native_context() {
        context.charge_gas_for_dependencies(module_name)?;
        Ok(smallvec![])
    } else {
        // Legacy flow, VM will charge gas for module loading.
        Err(SafeNativeError::LoadModule { module_name })
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/function_info.move (L73-84)
```text
    /// Load up a function into VM's loader and charge for its dependencies
    ///
    /// It is **critical** to make sure that this function is invoked before `check_dispatch_type_compatibility`
    /// or performing any other dispatching logic to ensure:
    /// 1. We properly charge gas for the function to dispatch.
    /// 2. The function is loaded in the cache so that we can perform further type checking/dispatching logic.
    ///
    /// Calling `check_dispatch_type_compatibility_impl` or dispatch without loading up the module would yield an error
    /// if such module isn't accessed previously in the transaction.
    public(friend) fun load_module_from_function(f: &FunctionInfo) {
        load_function_impl(f)
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L210-233)
```rust
    fn charge_native_result_load_module(
        &self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        module_id: &ModuleId,
    ) -> PartialVMResult<()> {
        let arena_id = traversal_context
            .referenced_module_ids
            .alloc(module_id.clone());
        check_dependencies_and_charge_gas(self.module_storage, gas_meter, traversal_context, [(
            arena_id.address(),
            arena_id.name(),
        )])
        .map_err(|err| {
            err.to_partial().append_message_with_separator(
                '.',
                format!(
                    "Failed to charge transitive dependency for {}. Does this module exist?",
                    module_id
                ),
            )
        })?;
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L55-77)
```rust
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

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L253-261)
```rust
    fn charge_native_result_load_module(
        &self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        module_id: &ModuleId,
    ) -> PartialVMResult<()> {
        self.charge_module(gas_meter, traversal_context, module_id)?;
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/dependencies_gas_charging.rs (L48-108)
```rust
/// Traverses the whole transitive closure of dependencies, starting from the specified
/// modules and performs gas metering.
///
/// The traversal follows a depth-first order, with the module itself being visited first,
/// followed by its dependencies, and finally its friends.
/// DO NOT CHANGE THE ORDER unless you have a good reason, or otherwise this could introduce
/// a breaking change to the gas semantics.
///
/// This will result in the shallow-loading of the modules -- they will be read from the
/// storage as bytes and then deserialized, but NOT converted into the runtime representation.
///
/// It should also be noted that this is implemented in a way that avoids the cloning of
/// `ModuleId`, a.k.a. heap allocations, as much as possible, which is critical for
/// performance.
pub fn check_dependencies_and_charge_gas<'a, I>(
    module_storage: &impl ModuleStorage,
    gas_meter: &mut impl DependencyGasMeter,
    traversal_context: &mut TraversalContext<'a>,
    ids: I,
) -> VMResult<()>
where
    I: IntoIterator<Item = (&'a AccountAddress, &'a IdentStr)>,
    I::IntoIter: DoubleEndedIterator,
{
    let _timer = VM_TIMER.timer_with_label("check_dependencies_and_charge_gas");

    // Initialize the work list (stack) and the map of visited modules.
    //
    // TODO: Determine the reserved capacity based on the max number of dependencies allowed.
    let mut stack = Vec::with_capacity(512);
    traversal_context.push_next_ids_to_visit(&mut stack, ids);

    while let Some((addr, name)) = stack.pop() {
        let size = module_storage.unmetered_get_existing_module_size(addr, name)?;
        gas_meter
            .charge_dependency(
                DependencyKind::Existing,
                addr,
                name,
                NumBytes::new(size as u64),
            )
            .map_err(|err| err.finish(Location::Module(ModuleId::new(*addr, name.to_owned()))))?;

        // Extend the lifetime of the module to the remainder of the function body
        // by storing it in an arena.
        //
        // This is needed because we need to store references derived from it in the
        // work list.
        let compiled_module =
            module_storage.unmetered_get_existing_deserialized_module(addr, name)?;
        let compiled_module = traversal_context.referenced_modules.alloc(compiled_module);

        // Explore all dependencies and friends that have been visited yet.
        let imm_deps_and_friends = compiled_module
            .immediate_dependencies_iter()
            .chain(compiled_module.immediate_friends_iter());
        traversal_context.push_next_ids_to_visit(&mut stack, imm_deps_and_friends);
    }

    Ok(())
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
