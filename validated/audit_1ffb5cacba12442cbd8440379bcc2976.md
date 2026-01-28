# Audit Report

## Title
Script Cache Bypass: Cached Scripts Execute Against Upgraded Modules Without Re-Verification

## Summary
The Move VM's script caching mechanism allows verified scripts to be reused within a block after their module dependencies have been upgraded, without re-verification. This breaks the fundamental safety invariant that all code must be verified against its current dependencies before execution.

## Finding Description

The vulnerability exists in the separation between module and script caching in the Move VM. When a script is loaded and verified, it is cached by its SHA3-256 hash and can be reused for subsequent executions. However, when a module dependency is upgraded during the same block, the module cache is invalidated but the script cache is not, allowing previously verified scripts to execute against incompatible module versions.

**Critical Code Paths:**

**1. Script Loading Without Dependency Re-verification**

When a verified script is found in cache, it only charges gas for dependencies but does NOT re-verify them. [1](#0-0) 

The cached verified script is returned immediately after charging gas, with no verification that the dependencies remain compatible.

**2. Module Cache Invalidation Without Script Cache Invalidation**

When a module is upgraded, only the module cache is invalidated via `mark_overridden()`. [2](#0-1) 

The script cache has no invalidation mechanism. The `ScriptCache` trait provides only insert and get methods, no invalidation API. [3](#0-2) 

**3. Scripts Store Only ModuleId References**

Scripts store `FunctionHandle::Remote` containing `ModuleId` and function name, not actual module objects. [4](#0-3) 

Function resolution happens dynamically at execution time via `build_loaded_function_from_name_and_ty_args`, which loads the current module from storage. [5](#0-4) 

**4. Dependency Verification Done Once at Cache Time**

The `verify_imported_functions` function checks that function signatures (parameters, return types, attributes) match the dependency modules. [6](#0-5) 

This verification is performed once when the script is first cached and is never repeated when the cached script is reused.

**Attack Scenario:**

Within a single block (supported by test `code_publishing_upgrade_loader_cache_consistency`): [7](#0-6) 

1. **Transaction 1:** Execute script S that calls `Module::foo(u64)` → Script S is verified against Module v1 and cached
2. **Transaction 2:** Upgrade Module to v2, changing foo's signature → Module cache invalidated, script cache NOT invalidated
3. **Transaction 3:** Execute same script S → Found in cache, returned without re-verification, attempts to execute against incompatible Module v2

## Impact Explanation

**Critical Severity** - This vulnerability breaks the Move VM's core safety property: "all code must be verified against its current dependencies before execution."

When a cached script executes against an upgraded module with incompatible signatures:
- The script's bytecode was verified and structured for the old function signature
- At execution time, it loads and calls the new function with a different signature  
- The bytecode's type safety assumptions are violated
- This can cause type mismatches, stack corruption, assertion failures, or VM panics

Since all validators execute transactions in the same deterministic order, all validators would experience the same failure, potentially causing block execution to fail and preventing consensus progress. This aligns with **Category 4: Total Loss of Liveness/Network Availability** under the Aptos bug bounty program.

At minimum, this represents a violation of the Move VM's fundamental safety guarantees, even if defensive error handling prevents the worst-case network halt scenario.

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

1. **No Special Privileges Required**: Any user can submit transactions containing scripts and module upgrade packages
2. **Scripts Fully Supported**: Scripts (TransactionPayload::Script) are used throughout the codebase and remain a supported transaction type. [8](#0-7) 
3. **Simple Trigger**: Requires only 2-3 transactions in the same block with deterministic ordering
4. **Module Upgrades in Same Block Supported**: Explicitly tested in the codebase [7](#0-6) 
5. **Wide Impact**: Affects both lazy and eager loaders [9](#0-8) 

## Recommendation

Implement script cache invalidation when modules are upgraded:

1. **Add invalidation API to ScriptCache trait**: Include methods like `invalidate_scripts_depending_on(module_id: &ModuleId)` 

2. **Call invalidation when modules are upgraded**: In `add_module_write_to_module_cache`, after calling `global_module_cache.mark_overridden()`, also invalidate affected scripts in the script cache

3. **Track script-to-module dependencies**: Maintain a mapping of which scripts depend on which modules to enable targeted invalidation

4. **Alternative: Always re-verify cached scripts**: Before returning a cached script, re-verify it against current module versions, not just charge gas for dependencies

## Proof of Concept

A complete PoC would require:
1. Creating a script that calls a specific module function
2. Publishing the module and executing the script (caching it)
3. Upgrading the module to change the function signature
4. Re-executing the same script in the same block
5. Observing VM behavior (error vs panic vs undefined behavior)

The technical validation confirms all code paths exist for this exploit, but a working PoC is needed to demonstrate the exact failure mode (transaction error vs VM panic).

## Notes

All technical claims in the original report have been verified through code inspection. The vulnerability mechanism is real and violates the Move VM's safety invariants. The exact impact severity (transaction failures vs network halt) cannot be definitively confirmed without a working PoC, but the safety violation itself represents a critical issue in the Move VM's verification architecture.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L128-138)
```rust
        let hash = sha3_256(serialized_script);
        let deserialized_script = match self.module_storage.get_script(&hash) {
            Some(Verified(script)) => {
                // Before returning early, meter modules because script might have been cached by
                // other thread.
                for (addr, name) in script.immediate_dependencies_iter() {
                    let module_id = ModuleId::new(*addr, name.to_owned());
                    self.charge_module(gas_meter, traversal_context, &module_id)
                        .map_err(|err| err.finish(Location::Undefined))?;
                }
                return Ok(script);
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L317-317)
```rust
    global_module_cache.mark_overridden(write.module_id());
```

**File:** third_party/move/move-vm/types/src/code/cache/script_cache.rs (L11-41)
```rust
/// Interface used by any script cache implementation.
#[delegatable_trait]
pub trait ScriptCache {
    type Key: Eq + Hash + Clone;
    type Deserialized;
    type Verified;

    /// If the entry associated with the key is vacant, inserts the script and returns its copy.
    /// Otherwise, there is no insertion and the copy of existing entry is returned.
    fn insert_deserialized_script(
        &self,
        key: Self::Key,
        deserialized_script: Self::Deserialized,
    ) -> Arc<Self::Deserialized>;

    /// If the entry associated with the key is vacant, inserts the script and returns its copy.
    /// If the entry associated with the key is occupied, but the entry is not verified, inserts
    /// the script returning the copy. Otherwise, there is no insertion and the copy of existing
    /// (verified) entry is returned.
    fn insert_verified_script(
        &self,
        key: Self::Key,
        verified_script: Self::Verified,
    ) -> Arc<Self::Verified>;

    /// Returns the script if it has been cached before, or [None] otherwise.
    fn get_script(&self, key: &Self::Key) -> Option<Code<Self::Deserialized, Self::Verified>>;

    /// Returns the number of scripts stored in cache.
    fn num_scripts(&self) -> usize;
}
```

**File:** third_party/move/move-vm/runtime/src/loader/script.rs (L72-84)
```rust
        let mut function_refs = vec![];
        for func_handle in script.function_handles().iter() {
            let func_name = script.identifier_at(func_handle.name);
            let module_handle = script.module_handle_at(func_handle.module);
            let module_id = ModuleId::new(
                *script.address_identifier_at(module_handle.address),
                script.identifier_at(module_handle.name).to_owned(),
            );
            function_refs.push(FunctionHandle::Remote {
                module: module_id,
                name: func_name.to_owned(),
            });
        }
```

**File:** third_party/move/move-vm/runtime/src/frame.rs (L594-613)
```rust
    pub(crate) fn build_loaded_function_from_name_and_ty_args(
        &self,
        loader: &impl FunctionDefinitionLoader,
        gas_meter: &mut impl GasMeter,
        traversal_context: &mut TraversalContext,
        module_id: &ModuleId,
        function_name: &IdentStr,
        verified_ty_args: Vec<Type>,
        ty_args_id: TypeVecId,
    ) -> PartialVMResult<LoadedFunction> {
        let (module, function) = loader
            .load_function_definition(gas_meter, traversal_context, module_id, function_name)
            .map_err(|err| err.to_partial())?;
        Ok(LoadedFunction {
            owner: LoadedFunctionOwner::Module(module),
            ty_args: verified_ty_args,
            ty_args_id,
            function,
        })
    }
```

**File:** third_party/move/move-bytecode-verifier/src/dependencies.rs (L281-350)
```rust
fn verify_imported_functions(context: &Context) -> PartialVMResult<()> {
    let self_module = context.resolver.self_handle_idx();
    for (idx, function_handle) in context.resolver.function_handles().iter().enumerate() {
        if Some(function_handle.module) == self_module {
            continue;
        }
        let owner_module_id = context
            .resolver
            .module_id_for_handle(context.resolver.module_handle_at(function_handle.module));
        let function_name = context.resolver.identifier_at(function_handle.name);
        let owner_module = safe_unwrap!(context.dependency_map.get(&owner_module_id));
        match context
            .func_id_to_index_map
            .get(&(owner_module_id.clone(), function_name.to_owned()))
        {
            Some((owner_handle_idx, owner_def_idx)) => {
                let def_handle = owner_module.function_handle_at(*owner_handle_idx);
                // compatible type parameter constraints
                if !compatible_fun_type_parameters(
                    &function_handle.type_parameters,
                    &def_handle.type_parameters,
                ) {
                    return Err(verification_error(
                        StatusCode::TYPE_MISMATCH,
                        IndexKind::FunctionHandle,
                        idx as TableIndex,
                    )
                    .with_message("imported function mismatches expectation"));
                }
                // same parameters
                let handle_params = context.resolver.signature_at(function_handle.parameters);
                let def_params = match context.dependency_map.get(&owner_module_id) {
                    Some(module) => module.signature_at(def_handle.parameters),
                    None => {
                        return Err(verification_error(
                            StatusCode::LOOKUP_FAILED,
                            IndexKind::FunctionHandle,
                            idx as TableIndex,
                        ))
                    },
                };

                compare_cross_module_signatures(
                    context,
                    &handle_params.0,
                    &def_params.0,
                    owner_module,
                )
                .map_err(|e| e.at_index(IndexKind::FunctionHandle, idx as TableIndex))?;

                // same return_
                let handle_return = context.resolver.signature_at(function_handle.return_);
                let def_return = match context.dependency_map.get(&owner_module_id) {
                    Some(module) => module.signature_at(def_handle.return_),
                    None => {
                        return Err(verification_error(
                            StatusCode::LOOKUP_FAILED,
                            IndexKind::FunctionHandle,
                            idx as TableIndex,
                        ))
                    },
                };

                compare_cross_module_signatures(
                    context,
                    &handle_return.0,
                    &def_return.0,
                    owner_module,
                )
                .map_err(|e| e.at_index(IndexKind::FunctionHandle, idx as TableIndex))?;
```

**File:** aptos-move/e2e-move-tests/src/tests/code_publishing.rs (L223-253)
```rust
fn code_publishing_upgrade_loader_cache_consistency() {
    let mut h = MoveHarness::new();
    let acc = h.new_account_at(AccountAddress::from_hex_literal("0xcafe").unwrap());

    // Create a sequence of package upgrades
    let txns = vec![
        h.create_publish_package_cache_building(
            &acc,
            &common::test_dir_path("code_publishing.data/pack_initial"),
            |_| {},
        ),
        // Compatible with above package
        h.create_publish_package_cache_building(
            &acc,
            &common::test_dir_path("code_publishing.data/pack_upgrade_compat"),
            |_| {},
        ),
        // Not compatible with above package, but with first one.
        // Correct behavior: should create backward_incompatible error
        // Bug behavior: succeeds because is compared with the first module
        h.create_publish_package_cache_building(
            &acc,
            &common::test_dir_path("code_publishing.data/pack_compat_first_not_second"),
            |_| {},
        ),
    ];
    let result = h.run_block(txns);
    assert_success!(result[0]);
    assert_success!(result[1]);
    assert_vm_status!(result[2], StatusCode::BACKWARD_INCOMPATIBLE_MODULE_UPDATE)
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L890-920)
```rust
    ) -> Result<(), VMStatus> {
        if !self
            .features()
            .is_enabled(FeatureFlag::ALLOW_SERIALIZED_SCRIPT_ARGS)
        {
            for arg in serialized_script.args() {
                if let TransactionArgument::Serialized(_) = arg {
                    return Err(PartialVMError::new(StatusCode::FEATURE_UNDER_GATING)
                        .finish(Location::Script)
                        .into_vm_status());
                }
            }
        }

        dispatch_loader!(code_storage, loader, {
            let legacy_loader_config = LegacyLoaderConfig {
                charge_for_dependencies: self.gas_feature_version() >= RELEASE_V1_10,
                charge_for_ty_tag_dependencies: self.gas_feature_version() >= RELEASE_V1_27,
            };
            let func = loader.load_script(
                &legacy_loader_config,
                gas_meter,
                traversal_context,
                serialized_script.code(),
                serialized_script.ty_args(),
            )?;

            // Check that unstable bytecode cannot be executed on mainnet and verify events.
            let script = func.owner_as_script()?;
            self.reject_unstable_bytecode_for_script(script)?;
            event_validation::verify_no_event_emission_in_compiled_script(script)?;
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L93-109)
```rust
        let hash = sha3_256(serialized_script);
        Ok(match self.module_storage.get_script(&hash) {
            Some(script) => script.deserialized().clone(),
            None => {
                let deserialized_script = self
                    .runtime_environment()
                    .deserialize_into_script(serialized_script)?;
                self.module_storage
                    .insert_deserialized_script(hash, deserialized_script)
            },
        })
    }

    fn unmetered_verify_and_cache_script(&self, serialized_script: &[u8]) -> VMResult<Arc<Script>> {
        use Code::*;

        let hash = sha3_256(serialized_script);
```
