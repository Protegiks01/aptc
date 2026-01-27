# Audit Report

## Title
Verified Module Cache Does Not Invalidate on Verifier Configuration Changes (Historical Issue - Fixed in V1.34)

## Summary
A cache invalidation vulnerability existed where the global `VERIFIED_MODULES_CACHE` did not flush when verifier feature flags changed, allowing previously-verified modules with restricted features (closures, enums, etc.) to bypass verification after those features were disabled via governance. This issue was fixed in gas_feature_version 38 (RELEASE_V1_34).

## Finding Description

The Move VM maintains a global singleton cache of verified module hashes to avoid re-verification overhead. [1](#0-0) 

When building a locally verified module, the system checks if the module hash exists in the cache and skips verification if found. [2](#0-1) 

The vulnerability occurs because the cache key is only the module hash, without considering the verifier configuration. [3](#0-2) 

**Attack Scenario (for gas_feature_version < 38):**

1. Initial state: `VM_BINARY_FORMAT_V8=enabled`, `ENABLE_FUNCTION_VALUES=enabled`
2. Attacker publishes module M containing closure opcodes (PACK_CLOSURE, CALL_CLOSURE)
3. Module M passes verification with `enable_function_values=true` and its hash is cached
4. Governance disables `ENABLE_FUNCTION_VALUES` but keeps `VM_BINARY_FORMAT_V8` enabled
5. The verifier config changes but `VERIFIED_MODULES_CACHE` is NOT flushed (for gas < V1.34)
6. Module M is loaded again - cache hit occurs at line 184
7. Verification is skipped, allowing closure opcodes to execute despite feature being disabled

The deserializer accepts VERSION_8 bytecode based on `VM_BINARY_FORMAT_V8`. [4](#0-3) 

The verifier separately checks `enable_function_values` for closure opcodes. [5](#0-4) 

However, this check is bypassed when verification is skipped due to the cache hit.

## Impact Explanation

This is a **High Severity** issue under "Significant protocol violations" because:
- It breaks the governance invariant that feature flags should be enforceable
- Allows deprecated or restricted features to remain active after being disabled
- Could cause consensus issues if nodes have different cache states
- Undermines the security model for bytecode version and feature flag coordination

The mitigation was implemented in `code_cache_global_manager.rs` where the cache is now flushed when verifier config changes, but only for gas_feature_version >= RELEASE_V1_34. [6](#0-5) 

## Likelihood Explanation

**For deployments with gas_feature_version >= 38:** This issue is fully mitigated.

**For deployments with gas_feature_version < 38:** The likelihood is HIGH when:
- Governance frequently changes feature flags
- Multiple bytecode versions are enabled/disabled
- The network operates for extended periods with the same cache

This primarily affects testnets, devnets, or private deployments that haven't upgraded to gas_feature_version 38 or higher.

## Recommendation

**The fix has already been implemented.** For any remaining deployments with gas_feature_version < 38, upgrade to at least gas_feature_version 38 to enable proper cache invalidation.

For additional defense-in-depth, consider:
1. Including verifier config hash in the cache key structure
2. Adding cache versioning that auto-invalidates on any environment change
3. Periodic cache flushes as a safety measure

The current implementation correctly serializes the verifier config to detect changes. [7](#0-6) 

## Proof of Concept

This vulnerability cannot be demonstrated on current mainnet (gas_feature_version >= 38) as the fix is active. For historical verification on deployments with gas < V1.34:

```rust
// Setup: Deploy with gas_feature_version = 37
// Enable VM_BINARY_FORMAT_V8 and ENABLE_FUNCTION_VALUES
// Publish a module with closure opcodes
// Module verification succeeds and hash is cached

// Change governance to disable ENABLE_FUNCTION_VALUES
// For gas < 38, VERIFIED_MODULES_CACHE is NOT flushed

// Load the module again - it will skip verification
// despite enable_function_values now being false
// Closure opcodes execute successfully
```

## Notes

This analysis confirms that while the deserializer_config allowing newer binary formats CAN enable attacks through the cache bypass mechanism, the vulnerability was recognized and mitigated in RELEASE_V1_34. The separate feature flags (ENABLE_ENUM_TYPES, ENABLE_FUNCTION_VALUES, ENABLE_RESOURCE_ACCESS_CONTROL) provide proper defense-in-depth when the cache is correctly invalidated, which is now the case for modern deployments.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L13-13)
```rust
pub(crate) struct VerifiedModuleCache(Mutex<lru::LruCache<[u8; 32], ()>>);
```

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L51-54)
```rust
lazy_static! {
    pub(crate) static ref VERIFIED_MODULES_CACHE: VerifiedModuleCache =
        VerifiedModuleCache::empty();
}
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L184-198)
```rust
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
```

**File:** types/src/on_chain_config/aptos_features.rs (L485-499)
```rust
    pub fn get_max_binary_format_version(&self) -> u32 {
        if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V10) {
            file_format_common::VERSION_10
        } else if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V9) {
            file_format_common::VERSION_9
        } else if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V8) {
            file_format_common::VERSION_8
        } else if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V7) {
            file_format_common::VERSION_7
        } else if self.is_enabled(FeatureFlag::VM_BINARY_FORMAT_V6) {
            file_format_common::VERSION_6
        } else {
            file_format_common::VERSION_5
        }
    }
```

**File:** third_party/move/move-bytecode-verifier/src/features.rs (L139-157)
```rust
    fn verify_code(&self, code: &[Bytecode], idx: Option<TableIndex>) -> PartialVMResult<()> {
        if !self.config.enable_function_values {
            for bc in code {
                if matches!(
                    bc,
                    Bytecode::PackClosure(..)
                        | Bytecode::PackClosureGeneric(..)
                        | Bytecode::CallClosure(..)
                ) {
                    let mut err = PartialVMError::new(StatusCode::FEATURE_NOT_ENABLED);
                    if let Some(idx) = idx {
                        err = err.at_index(IndexKind::FunctionDefinition, idx);
                    }
                    return Err(err.with_message("function value feature not enabled".to_string()));
                }
            }
        }
        Ok(())
    }
```

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

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L283-284)
```rust
        let verifier_bytes =
            bcs::to_bytes(&vm_config.verifier_config).expect("Verifier config is serializable");
```
