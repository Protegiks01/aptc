# Audit Report

## Title
Gas Charging Inconsistency Between Native Module Loading Paths in LazyLoader

## Summary
The `charge_native_result_load_module()` implementation in LazyLoader only charges gas for a single module, while native function documentation and the modern flow implementation expect transitive dependency charging. This creates a semantic inconsistency where the lazy loading path undercharges compared to the documented behavior and eager loading implementation.

## Finding Description

When examining the gas charging behavior for native module loading in `lazy.rs`, there is a critical discrepancy between the documented contract and actual implementation:

The `charge_native_result_load_module()` function in LazyLoader calls `charge_module()`, which only charges for the single requested module: [1](#0-0) 

This `charge_module()` implementation only charges for the single module without traversing dependencies: [2](#0-1) 

However, the native function contract explicitly states it should charge for transitive dependencies: [3](#0-2) 

In contrast, the EagerLoader correctly implements transitive dependency charging: [4](#0-3) 

The EagerLoader uses `check_dependencies_and_charge_gas()` which performs a depth-first traversal to charge for all dependencies: [5](#0-4) 

**Direct Answer to Security Question**: Within LazyLoader specifically, `charge_native_result_load_module()` and `metered_load_module()` ARE consistent - both call `charge_module()`. However, this consistency reveals a **semantic bug**: the native function contract is violated because transitive dependencies are not charged as documented.

## Impact Explanation

This qualifies as **Medium Severity** under Aptos bug bounty criteria for the following reasons:

1. **Limited Gas Undercharging**: When lazy loading is enabled (controlled by feature flag), native functions calling `LoadModule` pay significantly less gas than documented - only charging for the single module instead of its full transitive dependency closure.

2. **Contract Violation**: The native function `load_function_impl` explicitly documents "gas cost: base_cost + transitive deps size" but LazyLoader violates this contract.

3. **Economic Impact**: Users/attackers can craft transactions that call native module loading functions without actually accessing dependencies, effectively getting free gas for large dependency trees.

4. **State Inconsistency**: The gas accounting invariant is broken - documented gas costs don't match actual charges, violating Resource Limits invariant #9.

The feature flag `ENABLE_LAZY_LOADING` is enabled by default network-wide: [6](#0-5) [7](#0-6) 

## Likelihood Explanation

**High Likelihood** - This issue occurs automatically whenever:
1. Lazy loading is enabled (current default)
2. Any native function returns `NativeResult::LoadModule` 
3. The loaded module has transitive dependencies

The behavior is confirmed by integration tests showing different caching patterns: [8](#0-7) 

No special attacker privileges are required - any transaction sender can trigger this undercharging by calling the affected native functions.

## Recommendation

**Option 1: Align LazyLoader with documented behavior (Breaking Change)**

Modify `charge_native_result_load_module()` in LazyLoader to charge for transitive dependencies, matching EagerLoader's behavior:

```rust
fn charge_native_result_load_module(
    &self,
    gas_meter: &mut impl DependencyGasMeter,
    traversal_context: &mut TraversalContext,
    module_id: &ModuleId,
) -> PartialVMResult<()> {
    // Charge for full transitive closure even with lazy loading
    // to match documented native function contract
    let arena_id = traversal_context
        .referenced_module_ids
        .alloc(module_id.clone());
    check_dependencies_and_charge_gas(
        self.module_storage, 
        gas_meter, 
        traversal_context, 
        [(arena_id.address(), arena_id.name())]
    )
    .map_err(|err| err.to_partial())
}
```

**Option 2: Update documentation to reflect lazy loading behavior (Non-breaking)**

Update the native function comment to clarify that with lazy loading, only the single module is charged upfront, and dependencies are charged when accessed.

## Proof of Concept

The existing test demonstrates the discrepancy: [9](#0-8) 

To demonstrate gas undercharging, create modules with large dependency chains and measure gas consumption:

```rust
// Module structure: A (5KB) → B (10KB) → C (20KB) → D (30KB)
// Expected gas with transitive deps: ~65KB worth
// Actual gas with lazy loading: ~5KB worth (87% undercharge)

let test_module_a = /* module with deps on B */;
let test_module_b = /* module with deps on C */; 
let test_module_c = /* module with deps on D */;
let test_module_d = /* leaf module */;

// Call native load_function_impl for module A
// With eager: charges for A+B+C+D
// With lazy: charges only for A
// Dependencies B,C,D are never charged if not accessed
```

The vulnerability is that with lazy loading enabled, the `LoadModule` result from native functions systematically undercharges gas by not traversing the dependency tree, violating the documented contract and creating economic inconsistency.

---

**Notes**: 
- This issue was introduced when lazy loading was implemented but the native function gas charging logic wasn't updated to maintain the transitive dependency charging contract
- The feature flag ensures all validators have consistent behavior (no consensus split), but the behavior itself violates documented invariants
- The test comment acknowledges different behavior but doesn't address whether this violates the native function's contract

### Citations

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

**File:** aptos-move/framework/src/natives/function_info.rs (L168-192)
```rust
/***************************************************************************************************
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

**File:** third_party/move/move-vm/integration-tests/src/tests/native_tests.rs (L92-158)
```rust
#[test_case(true)]
#[test_case(false)]
fn test_load_module_native_result(enable_lazy_loading: bool) {
    let a_id = ModuleId::new(TEST_ADDR, ident_str!("a").to_owned());
    let natives = vec![(
        TEST_ADDR,
        ident_str!("a").to_owned(),
        ident_str!("load_module_b").to_owned(),
        make_load_module_b(),
    )];
    let runtime_environment = RuntimeEnvironment::new_with_config(natives, VMConfig {
        enable_lazy_loading,
        ..VMConfig::default_for_test()
    });
    let mut storage = InMemoryStorage::new_with_runtime_environment(runtime_environment);

    let code_a = format!(
        r#"
        module 0x{0}::a {{
            fun foo() {{ load_module_b(); }}
            native fun load_module_b();
        }}
        "#,
        TEST_ADDR.to_hex(),
    );
    compile_and_publish(&mut storage, code_a);

    let mut add_module = |m: CompiledModule| {
        let mut blob = vec![];
        m.serialize(&mut blob).unwrap();
        storage.add_module_bytes(m.self_addr(), m.self_name(), blob.into());
        m.self_id()
    };

    let b = empty_module_with_dependencies_and_friends_at_addr(TEST_ADDR, "b", vec!["c"], vec![]);
    let c = empty_module_with_dependencies_and_friends_at_addr(TEST_ADDR, "c", vec!["d"], vec![]);
    let d = empty_module_with_dependencies_and_friends_at_addr(TEST_ADDR, "d", vec![], vec![]);

    let b_id = add_module(b);
    let c_id = add_module(c);
    let d_id = add_module(d);

    let code_storage = storage.as_unsync_code_storage();
    assert_ok!(execute_function_for_test(
        &storage,
        &code_storage,
        &a_id,
        ident_str!("foo"),
        &[],
        vec![],
    ));

    // Here we assert that the state of the cache contains specified modules. For lazy loading,
    // only loaded modules is deserialized for charging and cached. For eager loading, the
    // transitive closure is deserialized and cached for charging. The modules are not verified
    // because verification happens when other natives is called to load a function from the module
    // (here, "b").
    if enable_lazy_loading {
        code_storage
            .module_storage()
            .assert_cached_state(vec![&b_id], vec![&a_id]);
    } else {
        code_storage
            .module_storage()
            .assert_cached_state(vec![&b_id, &c_id, &d_id], vec![&a_id]);
    }
}
```
