# Audit Report

## Title
Verified Module Cache Persistence Across Validator Hot Restarts Bypasses Updated Verification Rules

## Summary
The global `VERIFIED_MODULES_CACHE` is not flushed during validator hot restarts (reconfiguration events), allowing modules verified under outdated verification rules to be used without re-verification when stricter rules are applied. This affects mempool transaction validation and, for networks with `gas_feature_version < RELEASE_V1_34`, also affects block execution.

## Finding Description
The `VERIFIED_MODULES_CACHE` is a global static LRU cache that tracks which module hashes have been successfully verified to optimize re-verification overhead. [1](#0-0) 

During on-chain reconfiguration events (which change blockchain configuration including verifier rules), the mempool validator performs a "hot restart" without terminating the process. [2](#0-1) 

This restart creates a new `AptosEnvironment` with updated verification configuration [3](#0-2)  but does NOT flush the `VERIFIED_MODULES_CACHE`. When modules are subsequently loaded and verified, the cache is checked first [4](#0-3)  and if a hash is found, verification is completely skipped, even though the verification rules have changed.

**Attack Scenario:**
1. Network operates with verifier config V1 (e.g., `max_type_nodes = 256`)
2. Modules are verified and cached under these rules
3. Governance proposal changes verifier config to V2 (e.g., `max_type_nodes = 128` due to security concerns)
4. Reconfiguration triggers `validator.restart()` - new environment created but cache persists
5. Transactions containing modules with cached hashes bypass re-verification
6. Modules that should fail under stricter V2 rules are accepted without verification

For block execution, there is partial mitigation: the `ModuleCacheManager::check_ready()` flushes the verified cache when verifier config changes, but ONLY for `gas_feature_version >= RELEASE_V1_34` (38). [5](#0-4)  For older networks or during the window between mempool validation and block execution, the vulnerability remains exploitable.

## Impact Explanation
This is a **Low Severity** issue per Aptos bug bounty criteria because:

1. **Limited Scope**: Modern networks with `gas_feature_version >= 38` have partial protection at block execution layer, limiting impact to mempool resource consumption
2. **Rare Trigger**: Requires governance-driven verifier configuration changes, which are infrequent
3. **Bounded Exposure**: Affects primarily validator transaction validation, not consensus safety or fund security
4. **No Fund Loss**: Does not enable theft or minting of funds
5. **Transient Impact**: For modern networks, invalid transactions are rejected at execution even if accepted by mempool

However, for networks with `gas_feature_version < 38` or during transition periods, modules verified under weaker security rules could be used without re-verification, potentially bypassing security fixes in the verifier.

## Likelihood Explanation
**Likelihood: Medium**

This issue occurs automatically whenever:
- A governance proposal changes verifier configuration (e.g., enabling new features, tightening limits)
- The change happens without full process restart
- Modules exist in cache from before the configuration change

The issue does NOT require:
- Attacker-controlled governance (changes are legitimate)
- Hash collisions or cryptographic breaks  
- Byzantine validator behavior
- Complex timing attacks

However, practical exploitation is limited because:
- Verifier configuration changes are rare in production
- Modern networks have partial mitigation at block execution
- The vulnerability window is transient (until next block execution flush)

## Recommendation
Flush the `VERIFIED_MODULES_CACHE` during validator hot restarts when the environment is updated. Modify the `reset_all` method to detect verifier configuration changes:

```rust
// In aptos-move/aptos-resource-viewer/src/module_view.rs
pub fn reset_all(&mut self, state_view: S) {
    let old_verifier_bytes = self.environment.verifier_config_bytes();
    self.state_view = state_view;
    self.environment = AptosEnvironment::new(&self.state_view);
    
    // Flush verified modules cache if verifier config changed
    if old_verifier_bytes != self.environment.verifier_config_bytes() {
        RuntimeEnvironment::flush_verified_module_cache();
    }
    
    self.module_cache = UnsyncModuleCache::empty();
}
```

Additionally, remove the `gas_feature_version >= RELEASE_V1_34` guard in `code_cache_global_manager.rs` to ensure all networks benefit from cache flushing on verifier config changes, or ensure all production networks are upgraded to v1.34+.

## Proof of Concept
```rust
// Conceptual PoC - demonstrates the cache persistence issue
// This would need to be integrated into existing test infrastructure

#[test]
fn test_verified_cache_persists_across_hot_restart() {
    // 1. Setup validator with initial verifier config
    let mut validator = create_test_validator();
    
    // 2. Verify a module, adding its hash to VERIFIED_MODULES_CACHE
    let module = create_test_module_with_large_types(200); // Within old limit
    let result = validator.validate_transaction_with_module(module);
    assert!(result.is_ok());
    
    // 3. Update on-chain config to stricter verification rules
    update_verifier_config_max_type_nodes(128); // Tighter limit
    
    // 4. Trigger validator hot restart (as happens during reconfiguration)
    validator.restart(); // Creates new environment, doesn't flush cache
    
    // 5. Attempt to validate the same module again
    // Under new rules, this should fail (200 > 128)
    // But cache persists, so verification is skipped
    let result_after_restart = validator.validate_transaction_with_module(module);
    
    // BUG: This passes when it should fail
    assert!(result_after_restart.is_ok()); // Should be Err but passes due to cache
    
    // Expected behavior: Cache should be flushed, module re-verified, and rejected
    // assert!(result_after_restart.is_err());
}
```

## Notes
This vulnerability specifically affects "hot restarts" during reconfiguration, not full process restarts where memory is cleared. The issue is more severe for networks with `gas_feature_version < 38` where even block execution lacks cache flush logic. The developer comment at line 1575 in `aptos_vm.rs` suggests v1.34 should already be in production, indicating this may be a legacy issue for older or custom deployments. [6](#0-5)

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/verified_module_cache.rs (L51-54)
```rust
lazy_static! {
    pub(crate) static ref VERIFIED_MODULES_CACHE: VerifiedModuleCache =
        VerifiedModuleCache::empty();
}
```

**File:** mempool/src/shared_mempool/tasks.rs (L775-778)
```rust
    if let Err(e) = validator.write().restart() {
        counters::VM_RECONFIG_UPDATE_FAIL_COUNT.inc();
        error!(LogSchema::event_log(LogEntry::ReconfigUpdate, LogEvent::VMUpdateFail).error(&e));
    }
```

**File:** aptos-move/aptos-resource-viewer/src/module_view.rs (L134-138)
```rust
    pub fn reset_all(&mut self, state_view: S) {
        self.state_view = state_view;
        self.environment = AptosEnvironment::new(&self.state_view);
        self.module_cache = UnsyncModuleCache::empty();
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1574-1575)
```rust
        // TODO(#17171): remove this once 1.34 is in production.
        let function_compat_bug = self.gas_feature_version() < gas_feature_versions::RELEASE_V1_34;
```
