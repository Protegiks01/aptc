# Audit Report

## Title
Script Cache Lacks Version Tracking Leading to Verification Bypass When Modules Are Republished

## Summary
The blanket implementation in `code_storage.rs` does not enforce atomic consistency between module and script caches. Scripts are cached by hash without version tracking, while modules support versioning. When a module is republished within a block, scripts verified against the old version remain cached and can execute against the new version, breaking verification invariants.

## Finding Description

The `CodeStorage` trait in [1](#0-0)  provides a blanket implementation that combines `ModuleStorage` and `ScriptCache` traits without any synchronization logic.

During parallel block execution, both caches are stored as separate fields in `MVHashMap`: [2](#0-1) 

The module cache supports versioning with `Version = Option<TxnIndex>`: [3](#0-2) 

However, the script cache has no versioning mechanism and only uses hash-based keys: [4](#0-3) 

When scripts are verified and cached, they return immediately if found in cache: [5](#0-4) 

When modules are republished via `add_module_write_to_module_cache`, the module cache is updated with the new version: [6](#0-5) 

Critically, only the layout cache is flushed, not the script cache: [7](#0-6) 

**Attack Scenario:**
1. Transaction T1 executes script S that depends on module M at version v1
2. Script S is verified against M v1 and cached with hash H
3. Transaction T2 publishes a new version of module M (v2) in the same block
4. Module cache is updated with M v2, but script cache retains cached S
5. Transaction T3 executes the same script S
6. Cached script S (verified against M v1) is returned and executed with M v2
7. Verification invariant is violated - script executes against incompatible module version

## Impact Explanation

This vulnerability achieves **High Severity** under the Aptos bug bounty criteria for "Significant protocol violations":

1. **Verification Bypass**: Scripts verified against one module version execute against different versions, breaking the fundamental security guarantee that bytecode verification provides

2. **Deterministic Execution Violation**: Different validators may have different cache states depending on transaction execution order and timing, potentially leading to consensus divergence

3. **Type Safety Compromise**: Function signatures, struct layouts, or type constraints verified in the original module version may not hold in the new version, leading to memory safety violations or unexpected behavior

The comment in the codebase confirms cache inconsistency issues existed previously: [8](#0-7) 

## Likelihood Explanation

**Likelihood: Medium**

The attack requires:
- Module republishing within a single block (common operation in upgrades)
- Script execution (less common than entry functions, but supported)
- Specific transaction ordering where script executes, module publishes, then script executes again

While scripts are less commonly used than entry functions in production Aptos, they are fully supported by the VM. The vulnerability is deterministic and reproducible whenever these conditions are met.

## Recommendation

Add version tracking to the script cache or invalidate script cache entries when their dependent modules are republished.

**Option 1: Invalidate script cache on module publish**
When `flush_layout_cache()` is called, also clear the script cache:

```rust
// In txn_last_input_output.rs, publish_module_write_set
if published {
    global_module_cache.flush_layout_cache();
    // Add: Clear script cache to invalidate scripts verified against old modules
    versioned_cache.flush_script_cache();
    scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
}
```

**Option 2: Add dependency version tracking to scripts**
Modify `ScriptCache` to track which module versions each script was verified against, and invalidate on version mismatch.

## Proof of Concept

```rust
// Pseudo-code test demonstrating the vulnerability
#[test]
fn test_script_cache_inconsistency_on_module_upgrade() {
    let mut harness = MoveHarness::new();
    let account = harness.new_account();
    
    // Publish initial module version
    harness.publish_module(&account, "module M { public fun foo(): u64 { 1 } }");
    
    // Execute script that calls M::foo() - gets cached
    let script = compile_script("script { use M; fun main() { assert!(M::foo() == 1, 0); } }");
    harness.run_script(&account, &script); // Success, cached
    
    // Republish module with incompatible change
    harness.publish_module(&account, "module M { public fun foo(): u128 { 2 } }");
    
    // Execute same script again - retrieves from cache, verified against old M
    // but executes with new M, causing type mismatch
    let result = harness.run_script(&account, &script);
    // Expected: Verification error or type mismatch
    // Actual: May succeed or cause undefined behavior
}
```

## Notes

This vulnerability specifically affects parallel block execution where `MVHashMap` is shared across transactions. In sequential execution, `UnsyncMap` is also created once per block and shared: [9](#0-8) 

The blanket implementation provides no atomicity guarantees between the two caches: [10](#0-9)

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/code_storage.rs (L9-18)
```rust
pub trait CodeStorage:
    ModuleStorage + ScriptCache<Key = [u8; 32], Deserialized = CompiledScript, Verified = Script>
{
}

impl<T> CodeStorage for T where
    T: ModuleStorage
        + ScriptCache<Key = [u8; 32], Deserialized = CompiledScript, Verified = Script>
{
}
```

**File:** aptos-move/mvhashmap/src/lib.rs (L46-48)
```rust
    module_cache:
        SyncModuleCache<ModuleId, CompiledModule, Module, AptosModuleExtension, Option<TxnIndex>>,
    script_cache: SyncScriptCache<[u8; 32], CompiledScript, Script>,
```

**File:** third_party/move/move-vm/types/src/code/cache/module_cache.rs (L82-88)
```rust
#[delegatable_trait]
pub trait ModuleCache {
    type Key: Eq + Hash + Clone;
    type Deserialized;
    type Verified;
    type Extension;
    type Version: Clone + Default + Ord;
```

**File:** third_party/move/move-vm/types/src/code/cache/script_cache.rs (L12-16)
```rust
#[delegatable_trait]
pub trait ScriptCache {
    type Key: Eq + Hash + Clone;
    type Deserialized;
    type Verified;
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

**File:** aptos-move/block-executor/src/code_cache_global.rs (L300-318)
```rust
    per_block_module_cache
        .insert_deserialized_module(
            write.module_id().clone(),
            compiled_module,
            extension,
            Some(txn_idx),
        )
        .map_err(|err| {
            let msg = format!(
                "Failed to insert code for module {}::{} at version {} to module cache: {:?}",
                write.module_address(),
                write.module_name(),
                txn_idx,
                err
            );
            PanicError::CodeInvariantError(msg)
        })?;
    global_module_cache.mark_overridden(write.module_id());
    Ok(())
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L572-576)
```rust
        if published {
            // Record validation requirements after the modules are published.
            global_module_cache.flush_layout_cache();
            scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
        }
```

**File:** aptos-move/e2e-move-tests/src/tests/code_publishing.rs (L215-219)
```rust
/// This test verifies that the cache incoherence bug on module upgrade is fixed. This bug
/// exposes itself by that after module upgrade the old version of the module stays
/// active until the MoveVM terminates. In order to workaround this until there is a better
/// fix, we flush the cache in `MoveVmExt::new_session`. One can verify the fix by commenting
/// the flush operation out, then this test fails.
```

**File:** aptos-move/block-executor/src/executor.rs (L2205-2230)
```rust
        let unsync_map = UnsyncMap::new();

        let mut ret = Vec::with_capacity(num_txns + 1);

        let mut block_limit_processor = BlockGasLimitProcessor::<T>::new(
            self.config.onchain.block_gas_limit_type.clone(),
            self.config.onchain.block_gas_limit_override(),
            num_txns + 1,
        );

        let mut block_epilogue_txn = None;
        let mut idx = 0;
        while idx <= num_txns {
            let txn = if idx != num_txns {
                signature_verified_block.get_txn(idx as TxnIndex)
            } else if block_epilogue_txn.is_some() {
                block_epilogue_txn.as_ref().unwrap()
            } else {
                break;
            };
            let auxiliary_info = signature_verified_block.get_auxiliary_info(idx as TxnIndex);
            let latest_view = LatestView::<T, S>::new(
                base_view,
                module_cache_manager_guard.module_cache(),
                runtime_environment,
                ViewState::Unsync(SequentialState::new(&unsync_map, start_counter, &counter)),
```
