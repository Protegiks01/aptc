# Audit Report

## Title
Script Verification DoS via Missing Global Cache for Repeated Script Submissions

## Summary
Scripts are not cached in the global `VERIFIED_MODULES_CACHE` unlike modules, and their verification is performed unmetered (without gas charges). The per-block `ScriptCache` in `MVHashMap` is recreated for each block, allowing attackers to submit identical script transactions across multiple blocks, forcing validators to repeatedly perform expensive bytecode verification at no cost to the attacker.

## Finding Description

The Aptos Move VM implements two different caching strategies for bytecode verification:

**Modules**: Use the global `VERIFIED_MODULES_CACHE`, an LRU cache with 100,000 entry capacity that persists across blocks. When `build_locally_verified_module()` is called, it checks if the module hash exists in the cache and skips verification if present. [1](#0-0) 

**Scripts**: Do NOT use `VERIFIED_MODULES_CACHE`. Instead, `build_locally_verified_script()` always performs full bytecode verification without checking any persistent cache. [2](#0-1) 

Scripts do have a `ScriptCache`, but this cache is part of `MVHashMap` which is created fresh at the start of each block execution: [3](#0-2) [4](#0-3) 

Furthermore, script verification is performed via `unmetered_verify_and_cache_script()`, meaning validators bear the CPU cost without charging gas to the transaction sender: [5](#0-4) [6](#0-5) 

**Attack Path:**
1. Attacker crafts a valid but complex script with large bytecode that passes verification
2. Attacker submits the same script transaction in every block (one per block to avoid within-block cache)
3. Each block execution creates a new `MVHashMap` with empty `ScriptCache`
4. Each submission forces full unmetered bytecode verification including:
   - Bounds checking
   - Type safety verification
   - Control flow analysis  
   - Reference safety checks
   - Instruction consistency verification
5. Validators spend CPU cycles on repeated verification of the same bytecode
6. Attacker only pays normal transaction gas, not verification costs

## Impact Explanation

This vulnerability enables a **Medium severity** resource exhaustion attack against validators. Per the Aptos bug bounty criteria, this falls under:
- **High Severity**: "Validator node slowdowns" - The repeated expensive verification operations consume validator CPU resources unnecessarily

However, it's more accurately **Medium severity** because:
- It doesn't cause complete node failure or API crashes
- It causes gradual performance degradation rather than immediate failure
- The impact is bounded by block gas limits (attacker can only submit limited scripts per block)
- It doesn't violate consensus safety or cause state inconsistencies

The attack breaks **Invariant #9**: "Resource Limits: All operations must respect gas, storage, and computational limits" - script verification is an expensive operation that should be gas-metered but isn't.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Low attack complexity**: Attacker only needs to submit script transactions, which any user can do
2. **No special privileges required**: Any account with gas can execute the attack
3. **Undetectable**: Identical scripts submitted across blocks appear as normal transactions
4. **Cost-effective for attacker**: Only pays regular transaction fees, not verification costs
5. **Repeatable**: Can be sustained across multiple blocks/epochs
6. **Amplification potential**: Large, complex scripts amplify verification cost while transaction size fees remain constant

Move bytecode verification is computationally expensive, involving multiple passes through the bytecode for type checking, control flow analysis, and safety verification. The cost scales with script complexity (number of instructions, type parameters, control flow branches).

## Recommendation

**Option 1 (Preferred)**: Add scripts to `VERIFIED_MODULES_CACHE` by their SHA3-256 hash, similar to modules:

```rust
// In build_locally_verified_script()
pub fn build_locally_verified_script(
    &self,
    compiled_script: Arc<CompiledScript>,
) -> VMResult<LocallyVerifiedScript> {
    let script_bytes = /* serialize compiled_script */;
    let script_hash = sha3_256(&script_bytes);
    
    if !VERIFIED_MODULES_CACHE.contains(&script_hash) {
        move_bytecode_verifier::verify_script_with_config(
            &self.vm_config().verifier_config,
            compiled_script.as_ref(),
        )?;
        VERIFIED_MODULES_CACHE.put(script_hash);
    }
    Ok(LocallyVerifiedScript(compiled_script))
}
```

**Option 2**: Charge gas for script verification proportional to script complexity, ensuring attackers pay for the computational cost they impose on validators.

**Option 3**: Implement rate limiting for script transactions from the same sender or for identical script hashes.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_script_verification_dos() {
    // Create a complex valid script with many type parameters and instructions
    let complex_script = create_large_valid_script();
    let script_bytes = complex_script.serialize();
    let script_hash = sha3_256(&script_bytes);
    
    // Simulate multiple block executions
    for block_num in 0..100 {
        // Each block creates new MVHashMap with empty ScriptCache
        let mut versioned_cache = MVHashMap::new();
        let module_storage = create_test_storage(&versioned_cache);
        
        let start = Instant::now();
        
        // Script verification happens here - NOT cached across blocks
        let loader = EagerLoader::new(&module_storage);
        let _result = loader.load_script(
            &LegacyLoaderConfig::unmetered(),
            &mut UnmeteredGasMeter,
            &mut traversal_context,
            &script_bytes,
            &[],
        );
        
        let verification_time = start.elapsed();
        println!("Block {}: Verification took {:?}", block_num, verification_time);
        
        // Verify that VERIFIED_MODULES_CACHE does NOT contain the script
        assert!(!VERIFIED_MODULES_CACHE.contains(&script_hash));
    }
    
    // Each block re-verified the same script at validator's expense
    // Attacker only paid transaction fees, not verification costs
}

fn create_large_valid_script() -> CompiledScript {
    // Create script with:
    // - Many type parameters (increase type checking cost)
    // - Complex control flow (increase CFG analysis cost)  
    // - Deep type nesting (increase type safety verification cost)
    // - Many local variables (increase reference safety cost)
    // Script remains valid to pass verification
    // ...
}
```

**Notes**

The vulnerability stems from an asymmetry in caching strategy between modules and scripts. While modules benefit from persistent global caching to avoid repeated verification, scripts are verified fresh on each block where they appear. This design choice likely assumed scripts would be rare or unique, but it creates a DoS vector when attackers intentionally resubmit identical scripts across blocks. The unmetered nature of verification compounds the issue by allowing attackers to impose validator costs without proportional gas payment.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L141-150)
```rust
    pub fn build_locally_verified_script(
        &self,
        compiled_script: Arc<CompiledScript>,
    ) -> VMResult<LocallyVerifiedScript> {
        move_bytecode_verifier::verify_script_with_config(
            &self.vm_config().verifier_config,
            compiled_script.as_ref(),
        )?;
        Ok(LocallyVerifiedScript(compiled_script))
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L178-201)
```rust
    pub fn build_locally_verified_module(
        &self,
        compiled_module: Arc<CompiledModule>,
        module_size: usize,
        module_hash: &[u8; 32],
    ) -> VMResult<LocallyVerifiedModule> {
        if !VERIFIED_MODULES_CACHE.contains(module_hash) {
            let _timer =
                VM_TIMER.timer_with_label("move_bytecode_verifier::verify_module_with_config");

            // For regular execution, we cache already verified modules. Note that this even caches
            // verification for the published modules. This should be ok because as long as the
            // hash is the same, the deployed bytecode and any dependencies are the same, and so
            // the cached verification result can be used.
            move_bytecode_verifier::verify_module_with_config(
                &self.vm_config().verifier_config,
                compiled_module.as_ref(),
            )?;
            check_natives(compiled_module.as_ref())?;
            VERIFIED_MODULES_CACHE.put(*module_hash);
        }

        Ok(LocallyVerifiedModule(compiled_module, module_size))
    }
```

**File:** aptos-move/mvhashmap/src/lib.rs (L46-68)
```rust
    module_cache:
        SyncModuleCache<ModuleId, CompiledModule, Module, AptosModuleExtension, Option<TxnIndex>>,
    script_cache: SyncScriptCache<[u8; 32], CompiledScript, Script>,
}

impl<K, T, V, I> MVHashMap<K, T, V, I>
where
    K: ModulePath + Hash + Clone + Eq + Debug,
    T: Hash + Clone + Eq + Debug + Serialize,
    V: TransactionWrite + PartialEq,
    I: Copy + Clone + Eq + Hash + Debug,
{
    #[allow(clippy::new_without_default)]
    pub fn new() -> MVHashMap<K, T, V, I> {
        #[allow(deprecated)]
        MVHashMap {
            data: VersionedData::empty(),
            group_data: VersionedGroupData::empty(),
            delayed_fields: VersionedDelayedFields::empty(),

            module_cache: SyncModuleCache::empty(),
            script_cache: SyncScriptCache::empty(),
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L1741-1741)
```rust
        let mut versioned_cache = MVHashMap::new();
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L106-121)
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

        let locally_verified_script = self
            .runtime_environment()
            .build_locally_verified_script(deserialized_script)?;
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L355-356)
```rust
        let script = self.unmetered_verify_and_cache_script(serialized_script)?;
        self.build_instantiated_script(gas_meter, traversal_context, script, ty_args)
```
