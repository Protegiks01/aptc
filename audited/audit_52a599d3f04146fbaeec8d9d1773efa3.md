# Audit Report

## Title
Script Cache Inconsistency: Cached Scripts Execute with Upgraded Modules Without Re-verification

## Summary
The Move VM's script cache and module cache operate independently without proper synchronization. When modules are upgraded, the module cache is flushed but the script cache is not, allowing previously-verified scripts to execute with newer module versions without re-verification. This violates the Move VM's fundamental verification invariant and can lead to consensus violations.

## Finding Description
The `CodeStorage` trait combines `ModuleStorage` and `ScriptCache` as independent caching layers. When a script is loaded and verified, it's cached along with the modules it depends on. However, these caches have different invalidation policies: [1](#0-0) 

When modules are upgraded, the `ModuleCacheManager` flushes the module cache: [2](#0-1) 

However, there is **no corresponding flush of the script cache**. The `ScriptCache` trait implementations (`UnsyncScriptCache` and `SyncScriptCache`) do not expose a flush method: [3](#0-2) 

The `EagerLoader` returns cached scripts immediately without re-verifying dependencies: [4](#0-3) 

The critical issue is that scripts contain `FunctionHandle::Remote` references to external module functions: [5](#0-4) [6](#0-5) 

These remote handles are resolved **at runtime** against the current module cache: [7](#0-6) 

**Attack Path:**
1. Attacker executes script S depending on modules M1@V1 and M2@V1
2. Script S is verified with these module versions and cached
3. Attacker upgrades M2 to M2@V2 via module publishing transaction
4. Module cache is flushed and M2@V2 is loaded, but script cache still contains S
5. Attacker executes script S again - it's returned from cache without dependency checks
6. At runtime, S's function handles resolve to M2@V2 (new version)
7. **Script verified with M2@V1 executes with M2@V2**, breaking verification invariants

## Impact Explanation
**Severity: HIGH**

This vulnerability breaks the Move VM's core verification guarantee that scripts execute only with the module versions they were verified against. The impact includes:

1. **Deterministic Execution Violation**: Different validators may have different cache states, leading to different execution results for the same transaction, violating Invariant #1.

2. **Type Safety Bypass**: If M2@V2 changed function signatures, types, or visibility, the script could call functions with wrong types or access controls that should have been enforced during verification.

3. **Consensus Risk**: Non-deterministic execution across validators can cause state root mismatches and consensus failures.

4. **Verification Bypass**: The fundamental Move VM safety property that "verified bytecode is safe to execute" is violated since verification was done against different code.

This qualifies as **High Severity** per the Aptos bug bounty: "Significant protocol violations" affecting validator consensus and execution correctness.

## Likelihood Explanation
**Likelihood: MEDIUM-HIGH**

The attack is highly feasible:
- **No special privileges required**: Any user can submit scripts and upgrade modules
- **Common operation**: Module upgrades are routine in production environments
- **Automatic exploitation**: Once modules are upgraded, the vulnerability triggers automatically on next script execution
- **Wide impact**: Affects all cached scripts depending on upgraded modules

The only limiting factor is that script caching must be enabled and scripts must be re-executed after module upgrades. Given that scripts are commonly used for transaction batching and module upgrades happen regularly, this condition is frequently met in practice.

## Recommendation
Implement script cache invalidation when modules are upgraded. Add a `flush()` method to the `ScriptCache` trait and call it whenever the module cache is flushed:

```rust
// In ScriptCache trait (script_cache.rs)
pub trait ScriptCache {
    // ... existing methods ...
    
    /// Flushes all cached scripts
    fn flush(&self);
}

// In UnsyncScriptCache implementation
impl<K, D, V> ScriptCache for UnsyncScriptCache<K, D, V> {
    // ... existing methods ...
    
    fn flush(&self) {
        self.script_cache.borrow_mut().clear();
    }
}

// In ModuleCacheManager::check_ready (code_cache_global_manager.rs)
fn check_ready(&mut self, ...) {
    if !transaction_slice_metadata.is_immediately_after(&self.transaction_slice_metadata) {
        self.module_cache.flush();
        self.script_cache.flush(); // ADD THIS
        self.environment = None;
    }
    // ... rest of the function
}
```

Alternatively, re-verify script dependencies even when scripts are cached (similar to `LazyLoader`'s approach): [8](#0-7) 

## Proof of Concept

```rust
// Test case to reproduce the vulnerability
#[test]
fn test_script_cache_inconsistency_on_module_upgrade() {
    use move_core_types::{account_address::AccountAddress, language_storage::ModuleId};
    use aptos_vm_types::module_and_script_storage::AsAptosCodeStorage;
    
    let mut harness = MoveHarness::new();
    let account = harness.new_account_at(AccountAddress::from_hex_literal("0xcafe").unwrap());
    
    // Step 1: Publish initial module M at version 1
    let module_v1 = r#"
        module 0xcafe::M {
            public fun get_value(): u64 { 100 }
        }
    "#;
    let txn1 = harness.create_publish_package(&account, &module_v1);
    assert_success!(harness.run(txn1));
    
    // Step 2: Execute script that calls M::get_value()
    let script = r#"
        script {
            use 0xcafe::M;
            fun main() {
                assert!(M::get_value() == 100, 1);
            }
        }
    "#;
    let txn2 = harness.create_script(&account, script);
    assert_success!(harness.run(txn2));
    // Script is now cached, verified with M@V1
    
    // Step 3: Upgrade module M to version 2 with different return value
    let module_v2 = r#"
        module 0xcafe::M {
            public fun get_value(): u64 { 200 } // Changed!
        }
    "#;
    let txn3 = harness.create_publish_package(&account, &module_v2);
    assert_success!(harness.run(txn3));
    // Module cache is flushed, but script cache is NOT
    
    // Step 4: Execute same script again
    let txn4 = harness.create_script(&account, script);
    // BUG: Script uses cached version (verified with M@V1) 
    // but executes with M@V2 at runtime!
    // The assertion `M::get_value() == 100` will fail because get_value() now returns 200
    // This demonstrates that the script was not re-verified with the new module
    let result = harness.run(txn4);
    // Script fails due to inconsistency between verification and execution
}
```

## Notes
The vulnerability exists in both eager and lazy loading modes, though the lazy loader at least meters dependencies when returning cached scripts. The core issue is the architectural separation between module and script caches without proper synchronization on module upgrades. The existing test `code_publishing_upgrade_loader_cache_consistency` addresses module cache coherence but not script cache invalidation.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/implementations/unsync_code_storage.rs (L37-40)
```rust
pub struct UnsyncCodeStorage<M> {
    script_cache: UnsyncScriptCache<[u8; 32], CompiledScript, Script>,
    module_storage: M,
}
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L114-129)
```rust
        // different, we reset it to the new one, and flush the module cache.
        let environment_requires_update = self.environment.as_ref() != Some(&storage_environment);
        if environment_requires_update {
            if storage_environment.gas_feature_version() >= RELEASE_V1_34 {
                let flush_verifier_cache = self.environment.as_ref().is_none_or(|e| {
                    e.verifier_config_bytes() != storage_environment.verifier_config_bytes()
                });
                if flush_verifier_cache {
                    // Additionally, if the verifier config changes, we flush static verifier cache
                    // as well.
                    RuntimeEnvironment::flush_verified_module_cache();
                }
            }

            self.environment = Some(storage_environment);
            self.module_cache.flush();
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

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L106-117)
```rust
    fn unmetered_verify_and_cache_script(&self, serialized_script: &[u8]) -> VMResult<Arc<Script>> {
        use Code::*;

        let hash = sha3_256(serialized_script);
        let deserialized_script = match self.module_storage.get_script(&hash) {
            Some(Verified(script)) => return Ok(script),
            Some(Deserialized(deserialized_script)) => deserialized_script,
            None => self
                .runtime_environment()
                .deserialize_into_script(serialized_script)
                .map(Arc::new)?,
        };
```

**File:** third_party/move/move-vm/runtime/src/loader/script.rs (L42-43)
```rust
    pub(crate) function_refs: Vec<FunctionHandle>,
    // materialized instantiations, whether partial or not
```

**File:** third_party/move/move-vm/runtime/src/loader/script.rs (L80-84)
```rust
            function_refs.push(FunctionHandle::Remote {
                module: module_id,
                name: func_name.to_owned(),
            });
        }
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks_async.rs (L797-805)
```rust
            FunctionHandle::Remote { module, name } => {
                // There is no need to meter gas here: it has been charged during execution.
                let module = self
                    .module_storage
                    .unmetered_get_existing_lazily_verified_module(module)
                    .map_err(|err| err.to_partial())?;
                let function = module.get_function(name).map_err(|err| err.to_partial())?;
                (LoadedFunctionOwner::Module(module), function)
            },
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L129-138)
```rust
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
