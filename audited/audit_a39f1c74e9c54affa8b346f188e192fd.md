# Audit Report

## Title
Cache Invalidation Bug Allows Modules Exceeding Current Verification Limits to Bypass Re-verification

## Summary
The `VERIFIED_MODULES_CACHE` in the Move VM runtime fails to properly invalidate cached verification results when the `VerifierConfig` changes, allowing previously-deployed modules that would fail under stricter verification limits to continue executing. This occurs because the cache invalidation logic is only active for networks with `gas_feature_version >= 38`, and the cache is keyed solely by module hash without considering the verification configuration used. [1](#0-0) 

## Finding Description

The verification cache system has a critical flaw in how it handles configuration changes:

1. **Cache Key Issue**: The `VERIFIED_MODULES_CACHE` stores module hashes to skip bytecode re-verification, but is keyed only by the 32-byte module hash without incorporating the `VerifierConfig` parameters used during verification. [2](#0-1) 

2. **Verification Skip Logic**: When loading a module, if its hash exists in the cache, verification is completely skipped regardless of whether the `VerifierConfig` has changed since the module was cached. [3](#0-2) 

3. **Incomplete Cache Invalidation**: The cache flush logic only activates when `gas_feature_version >= RELEASE_V1_34` (version 38), meaning networks on earlier versions never flush the verification cache when configuration changes.

4. **Dynamic Configuration Changes**: The `VerifierConfig` changes dynamically based on feature flags. For example, enabling `ENABLE_FUNCTION_VALUES` changes:
   - `max_type_nodes`: `Some(256)` → `Some(128)`
   - `max_type_depth`: `None` → `Some(20)`
   - `max_function_return_values`: `None` → `Some(128)` [4](#0-3) 

**Attack Scenario:**

1. Attacker deploys module M with 200 type nodes when `ENABLE_FUNCTION_VALUES = false` (limit: 256)
2. Module M passes verification and its hash is cached in `VERIFIED_MODULES_CACHE`
3. Governance enables `ENABLE_FUNCTION_VALUES` via proposal, changing limit to 128
4. If `gas_feature_version < 38`: Cache flush is skipped entirely
5. Module M is loaded again: cache hit occurs, verification skipped
6. Module M with 200 type nodes executes despite current limit being 128
7. New modules with >128 type nodes are rejected, creating inconsistency

## Impact Explanation

This is a **Critical Severity** vulnerability per Aptos bug bounty criteria:

**Consensus/Safety Violation**: Different validator nodes may have different cache states depending on when they joined the network, were restarted, or had their cache evicted via LRU. When processing the same block containing a cached module that violates current limits:
- Nodes with cached verification: Accept the module, skip verification
- Nodes without cache entry: Reject the module, fail verification
- Result: Chain split, consensus failure requiring hard fork to resolve

**Resource Limits Bypass**: The verification limits exist to prevent DoS attacks via:
- Excessive type complexity causing VM slowdown during type checking
- Deep type nesting causing stack overflow during type traversal  
- Large function signatures consuming excessive memory during execution

Bypassing these limits allows attackers to deploy modules that can degrade validator performance or crash nodes.

**Protocol Invariant Violation**: Breaks the fundamental guarantee that "all modules must pass current verification limits" - a critical safety property of the Move VM.

## Likelihood Explanation

**Likelihood: HIGH**

Required conditions are realistic:

1. **Networks on gas_feature_version < 38**: While mainnet may be on newer versions, testnets, private deployments, or during upgrade periods may still be vulnerable. The current latest version is 45, but on-chain configuration can lag behind code capabilities. [5](#0-4) 

2. **Feature Flag Changes**: Governance regularly enables new features via `Features` on-chain config, which directly modifies `VerifierConfig`. This is a routine operational requirement, not a rare event.

3. **Module Persistence**: Modules deployed before limit tightening remain on-chain indefinitely. The cache has 100,000 entry capacity with LRU eviction, so frequently-accessed modules stay cached.

4. **Validator Cache State Divergence**: Different validators naturally have different cache states due to:
   - Different restart times
   - Different traffic patterns affecting LRU
   - New validators joining with empty cache
   - Manual cache flushes for maintenance

## Recommendation

**Immediate Fix**: Include the serialized `VerifierConfig` bytes in the cache key to ensure cached entries are tied to specific verification parameters:

```rust
// In verified_module_cache.rs
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<VerificationKey, ()>>);

#[derive(Hash, Eq, PartialEq)]
struct VerificationKey {
    module_hash: [u8; 32],
    verifier_config_hash: [u8; 32], // Hash of serialized VerifierConfig
}

impl VerifiedModuleCache {
    pub(crate) fn contains(&self, module_hash: &[u8; 32], config_hash: &[u8; 32]) -> bool {
        let key = VerificationKey {
            module_hash: *module_hash,
            verifier_config_hash: *config_hash,
        };
        verifier_cache_enabled() && self.0.lock().get(&key).is_some()
    }
    
    pub(crate) fn put(&self, module_hash: [u8; 32], config_hash: [u8; 32]) {
        if verifier_cache_enabled() {
            let key = VerificationKey {
                module_hash,
                verifier_config_hash: config_hash,
            };
            let mut cache = self.0.lock();
            cache.put(key, ());
        }
    }
}
```

**Alternative Fix**: Remove the `gas_feature_version` check so cache flushing occurs on all networks when verifier config changes:

```rust
// In code_cache_global_manager.rs, line 117-126
let flush_verifier_cache = self.environment.as_ref().is_none_or(|e| {
    e.verifier_config_bytes() != storage_environment.verifier_config_bytes()
});
if flush_verifier_cache {
    RuntimeEnvironment::flush_verified_module_cache();
}
```

**Defense in Depth**: Add periodic cache flushing at epoch boundaries to ensure all nodes eventually synchronize their cache state.

## Proof of Concept

**Reproduction Steps:**

1. **Setup Network on gas_feature_version < 38**:
   ```rust
   // Configure a test network with older gas version
   let state_view = create_state_view_with_gas_version(37);
   ```

2. **Deploy Module with Loose Limits**:
   ```move
   module attacker::complex_types {
       // Module with 200 type nodes (passes with max=256)
       struct DeepStruct<T1, T2, T3, /* ... 50 type parameters */> {
           field1: vector<vector<vector<T1>>>,
           field2: vector<vector<vector<T2>>>,
           // ... many deeply nested fields totaling 200 type nodes
       }
   }
   ```

3. **Verify Cache Entry Exists**:
   ```rust
   // After deployment, check cache
   let module_hash = compute_module_hash(&compiled_module);
   assert!(VERIFIED_MODULES_CACHE.contains(&module_hash));
   ```

4. **Enable Feature Flag to Tighten Limits**:
   ```rust
   // Enable ENABLE_FUNCTION_VALUES via governance
   features.enable(FeatureFlag::ENABLE_FUNCTION_VALUES);
   // This changes max_type_nodes from 256 to 128
   ```

5. **Attempt to Deploy Identical Module on New Validator**:
   ```rust
   // New validator without cache should reject module
   let new_validator = create_validator_with_empty_cache();
   let result = new_validator.verify_module(&compiled_module);
   assert!(result.is_err()); // Should fail: 200 > 128
   ```

6. **Load Module on Validator with Cache**:
   ```rust
   // Validator with cache accepts module despite limit violation
   let cached_validator = existing_validator_with_cache();
   let result = cached_validator.load_module(&module_id);
   assert!(result.is_ok()); // VULNERABILITY: Succeeds due to cache hit
   ```

7. **Observe Consensus Divergence**:
   - Block containing transaction using `attacker::complex_types`
   - Cached validators: Execute successfully
   - Uncached validators: Fail verification
   - **Result: Chain split**

## Notes

The vulnerability affects the core determinism guarantee of the Aptos blockchain. The verification cache was likely introduced as a performance optimization, but the implementation failed to account for the dynamic nature of verification parameters. This is particularly dangerous because:

1. Cache state is not consensus-critical data, so different validators can legitimately have different cache contents
2. There's no mechanism to detect or recover from cache-induced consensus splits
3. The bug is silent - no errors occur during normal operation until a divergence manifests

The fix requires either making the cache configuration-aware or ensuring aggressive cache invalidation on all configuration changes regardless of gas version.

### Citations

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L117-126)
```rust
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
```

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L9-29)
```rust
/// Cache for already verified modules. Since loader V1 uses such a cache to not perform repeated
/// verifications, possibly even across blocks, for comparative performance we need to have it as
/// well. For now, we keep it as a separate cache to make sure there is no interference between V1
/// and V2 implementations.
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<[u8; 32], ()>>);

impl VerifiedModuleCache {
    /// Maximum size of the cache. When modules are cached, they can skip re-verification.
    const VERIFIED_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(100_000).unwrap();

    /// Returns new empty verified module cache.
    pub(crate) fn empty() -> Self {
        Self(Mutex::new(lru::LruCache::new(Self::VERIFIED_CACHE_SIZE)))
    }

    /// Returns true if the module hash is contained in the cache. For tests, the cache is treated
    /// as empty at all times.
    pub(crate) fn contains(&self, module_hash: &[u8; 32]) -> bool {
        // Note: need to use get to update LRU queue.
        verifier_cache_enabled() && self.0.lock().get(module_hash).is_some()
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

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L145-194)
```rust
pub fn aptos_prod_verifier_config(gas_feature_version: u64, features: &Features) -> VerifierConfig {
    let sig_checker_v2_fix_script_ty_param_count =
        features.is_enabled(FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX);
    let sig_checker_v2_fix_function_signatures = gas_feature_version >= RELEASE_V1_34;
    let enable_enum_types = features.is_enabled(FeatureFlag::ENABLE_ENUM_TYPES);
    let enable_resource_access_control =
        features.is_enabled(FeatureFlag::ENABLE_RESOURCE_ACCESS_CONTROL);
    let enable_function_values = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
    // Note: we reuse the `enable_function_values` flag to set various stricter limits on types.

    VerifierConfig {
        scope: VerificationScope::Everything,
        max_loop_depth: Some(5),
        max_generic_instantiation_length: Some(32),
        max_function_parameters: Some(128),
        max_basic_blocks: Some(1024),
        max_value_stack_size: 1024,
        max_type_nodes: if enable_function_values {
            Some(128)
        } else {
            Some(256)
        },
        max_push_size: Some(10000),
        max_struct_definitions: None,
        max_struct_variants: None,
        max_fields_in_struct: None,
        max_function_definitions: None,
        max_back_edges_per_function: None,
        max_back_edges_per_module: None,
        max_basic_blocks_in_script: None,
        max_per_fun_meter_units: Some(1000 * 80000),
        max_per_mod_meter_units: Some(1000 * 80000),
        _use_signature_checker_v2: true,
        sig_checker_v2_fix_script_ty_param_count,
        sig_checker_v2_fix_function_signatures,
        enable_enum_types,
        enable_resource_access_control,
        enable_function_values,
        max_function_return_values: if enable_function_values {
            Some(128)
        } else {
            None
        },
        max_type_depth: if enable_function_values {
            Some(20)
        } else {
            None
        },
    }
}
```

**File:** aptos-move/aptos-gas-schedule/src/ver.rs (L104-112)
```rust
    pub const RELEASE_V1_34: u64 = 38;
    pub const RELEASE_V1_35: u64 = 39;
    pub const RELEASE_V1_36: u64 = 40;
    pub const RELEASE_V1_37: u64 = 41;
    pub const RELEASE_V1_38: u64 = 42;
    pub const RELEASE_V1_39: u64 = 43;
    pub const RELEASE_V1_40: u64 = 44;
    pub const RELEASE_V1_41: u64 = 45;
}
```
