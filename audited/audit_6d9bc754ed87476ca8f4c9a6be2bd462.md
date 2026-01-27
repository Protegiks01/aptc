# Audit Report

## Title
Stale VM Environment in Transaction Validation Causes Feature Flag and Gas Parameter Inconsistency

## Summary
The VM validator's `CachedModuleView` environment becomes stale when `notify_commit()` updates only the `state_view` via `reset_state_view()` but not the `environment`. This causes transaction validation at line 159 in `vm-validator/src/vm_validator.rs` to use outdated feature flags and gas parameters while reading from current state, leading to incorrect validation decisions that persist until an explicit `restart()` call. [1](#0-0) 

## Finding Description

The vulnerability exists in how the VM validator manages its execution environment across block commits:

**Root Cause**: When `notify_commit()` is called after each block commit, it determines whether to call `reset_state_view()` or `reset_all()` based on state view ID compatibility: [2](#0-1) 

In the normal case where both state views are `TransactionValidation` type and `old_version <= new_version`, it calls `reset_state_view()`, which ONLY updates the `state_view` field: [3](#0-2) 

The `environment` field, which contains critical execution parameters, remains unchanged. The `environment` is only updated when `reset_all()` is called: [4](#0-3) 

**What the Environment Contains**: The `AptosEnvironment` stores on-chain configuration fetched from state during initialization: [5](#0-4) 

This includes:
- Feature flags (enabled/disabled features)
- Gas parameters (gas costs for operations)
- Storage gas parameters
- VM configuration (verifier config, deserializer config)
- Keyless account verification keys
- Chain ID and timed features

**The Inconsistency**: When governance updates these parameters via `toggle_features()`: [6](#0-5) 

The new configuration is written to state and triggers reconfiguration. After the block commits:
1. `notify_commit()` calls `reset_state_view()` (line 93)
2. The `state_view` now reflects the NEW configuration in state
3. But the `environment` still contains the OLD configuration
4. This persists until `restart()` is explicitly called via `process_config_update()` [7](#0-6) 

**Exploitation During Validation**: When `validate_transaction()` is called: [8](#0-7) 

Line 159 creates `AptosVM` with the stale environment, then validates using methods that read from that environment: [9](#0-8) 

The validation logic checks feature flags from the stale environment: [10](#0-9) 

And uses stale gas parameters: [11](#0-10) 

**Attack Scenario**:
1. Governance proposal passes to enable `WEBAUTHN_SIGNATURE` feature
2. Feature change commits to state in block N
3. VM validator's `notify_commit()` updates `state_view` but not `environment`
4. User submits transaction with WebAuthn signature
5. Validation checks `self.features().is_enabled(FeatureFlag::WEBAUTHN_SIGNATURE)` which returns FALSE from stale environment
6. Valid transaction is rejected with `FEATURE_UNDER_GATING`
7. This persists until `restart()` processes the reconfiguration notification

**Comparison with Block Execution**: Note that block execution does NOT have this issue because it creates a fresh environment for each block: [12](#0-11) 

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Validator Node Impact**: Transaction validation is a critical mempool function. Using stale configuration causes:
   - Valid transactions to be incorrectly rejected (DoS for users)
   - Invalid transactions to potentially be accepted (if features disabled but environment stale)
   - Mempool state divergence across validators if they process reconfig notifications at different times

2. **Protocol Violations**: Breaks the "Transaction Validation" invariant that prologue/epilogue checks must enforce all invariants using current state configuration.

3. **Deterministic Execution Violation**: Different validators may have different validation results for the same transaction depending on when their environments were last refreshed, violating the determinism requirement.

4. **No Consensus Break**: Block execution always uses fresh environment, so this only affects mempool validation, not actual execution or consensus safety.

The issue qualifies as **High Severity** under "Validator node slowdowns" and "Significant protocol violations" categories.

## Likelihood Explanation

**High Likelihood**:
- Occurs automatically on every governance configuration change (feature flags, gas schedules)
- No attacker action required - normal governance operation triggers it
- Persists for indeterminate duration until `restart()` is called
- Affects all validators running the vulnerable code
- Governance proposals to update features/gas parameters are regular occurrences on mainnet

The time window depends on how quickly the mempool processes reconfiguration notifications, but could be significant.

## Recommendation

**Fix**: Ensure the environment is updated whenever the state view is updated. Modify `CachedModuleView::reset_state_view()` to also refresh the environment:

```rust
/// Resets the state view snapshot to the new one and updates the environment.
pub fn reset_state_view(&mut self, state_view: S) {
    self.state_view = state_view;
    self.environment = AptosEnvironment::new(&self.state_view);
}
```

Alternatively, always use `reset_all()` instead of `reset_state_view()` in `notify_commit()` to ensure both state and environment stay synchronized:

```rust
fn notify_commit(&mut self) {
    let db_state_view = self.db_state_view();
    // Always fully reset to ensure environment stays synchronized
    self.state.reset_all(db_state_view.into());
}
```

The performance impact of recreating the environment more frequently should be measured, as `AptosEnvironment::new()` fetches and hashes on-chain configs. However, correctness must take precedence.

## Proof of Concept

**Rust Test Demonstrating the Issue**:

```rust
#[test]
fn test_stale_environment_after_feature_change() {
    use aptos_types::on_chain_config::{Features, FeatureFlag};
    use aptos_types::state_store::MockStateView;
    use std::collections::HashMap;
    
    // Create initial state with WEBAUTHN_SIGNATURE disabled
    let mut features = Features::default();
    features.disable(FeatureFlag::WEBAUTHN_SIGNATURE);
    let state_view_v1 = MockStateView::new(HashMap::from([
        (StateKey::on_chain_config::<Features>().unwrap(), 
         StateValue::new_legacy(bcs::to_bytes(&features).unwrap().into()))
    ]));
    
    // Create validator with initial state
    let mut validator = VMValidator::new(Arc::new(state_view_v1));
    
    // Simulate governance enabling WEBAUTHN_SIGNATURE
    features.enable(FeatureFlag::WEBAUTHN_SIGNATURE);
    let state_view_v2 = MockStateView::new(HashMap::from([
        (StateKey::on_chain_config::<Features>().unwrap(),
         StateValue::new_legacy(bcs::to_bytes(&features).unwrap().into()))
    ]));
    
    // Simulate commit notification - this calls reset_state_view()
    validator.state.reset_state_view(CachedDbStateView::from(state_view_v2));
    
    // The state_view now sees WEBAUTHN_SIGNATURE enabled
    let features_from_state = Features::fetch_config(&validator.state.state_view).unwrap();
    assert!(features_from_state.is_enabled(FeatureFlag::WEBAUTHN_SIGNATURE));
    
    // But the environment still has it DISABLED!
    assert!(!validator.state.environment.features().is_enabled(FeatureFlag::WEBAUTHN_SIGNATURE));
    
    // This causes validation to use stale feature flags
    // A transaction with WebAuthn signature would be incorrectly rejected
}
```

**Notes**
- This vulnerability only affects mempool transaction validation, not block execution or consensus
- Block execution creates fresh environments per block and is unaffected
- The issue manifests as a time-window vulnerability between state changes and environment updates
- Different validators may process reconfiguration notifications at slightly different times, causing temporary mempool divergence
- The fix should ensure environment synchronization without significantly impacting performance

### Citations

**File:** vm-validator/src/vm_validator.rs (L76-99)
```rust
    fn notify_commit(&mut self) {
        let db_state_view = self.db_state_view();

        // On commit, we need to update the state view so that we can see the latest resources.
        let base_view_id = self.state.state_view_id();
        let new_view_id = db_state_view.id();
        match (base_view_id, new_view_id) {
            (
                StateViewId::TransactionValidation {
                    base_version: old_version,
                },
                StateViewId::TransactionValidation {
                    base_version: new_version,
                },
            ) => {
                // if the state view forms a linear history, just update the state view
                if old_version <= new_version {
                    self.state.reset_state_view(db_state_view.into());
                }
            },
            // if the version is incompatible, we flush the cache
            _ => self.state.reset_all(db_state_view.into()),
        }
    }
```

**File:** vm-validator/src/vm_validator.rs (L155-164)
```rust
        let result = std::panic::catch_unwind(move || {
            let vm_validator_locked = vm_validator.lock().unwrap();

            use aptos_vm::VMValidator;
            let vm = AptosVM::new(&vm_validator_locked.state.environment);
            vm.validate_transaction(
                txn,
                &vm_validator_locked.state.state_view,
                &vm_validator_locked.state,
            )
```

**File:** aptos-move/aptos-resource-viewer/src/module_view.rs (L123-125)
```rust
    pub fn reset_state_view(&mut self, state_view: S) {
        self.state_view = state_view;
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

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L166-209)
```rust
struct Environment {
    /// Specifies the chain, i.e., testnet, mainnet, etc.
    chain_id: ChainId,

    /// Set of features enabled in this environment.
    features: Features,
    /// Set of timed features enabled in this environment.
    timed_features: TimedFeatures,

    /// The prepared verification key for keyless accounts. Optional because it might not be set
    /// on-chain or might fail to parse.
    keyless_pvk: Option<PreparedVerifyingKey<Bn254>>,
    /// Some keyless configurations which are not frequently updated.
    keyless_configuration: Option<Configuration>,

    /// Gas feature version used in this environment.
    gas_feature_version: u64,
    /// Gas parameters used in this environment. Error is stored if gas parameters were not found
    /// on-chain.
    gas_params: Result<AptosGasParameters, String>,
    /// Storage gas parameters used in this environment. Error is stored if gas parameters were not
    /// found on-chain.
    storage_gas_params: Result<StorageGasParameters, String>,

    /// The runtime environment, containing global struct type and name caches, and VM configs.
    runtime_environment: RuntimeEnvironment,

    /// True if we need to inject create signer native for government proposal simulation.
    /// Deprecated, and will be removed in the future.
    #[deprecated]
    inject_create_signer_for_gov_sim: bool,

    /// Hash of configs used in this environment. Used to be able to compare environments.
    hash: [u8; 32],
    /// Bytes of serialized verifier config. Used to detect any changes in verification configs.
    /// We stored bytes instead of hash because config is expected to be smaller than the crypto
    /// hash itself.
    verifier_bytes: Vec<u8>,

    /// If true, runtime checks such as paranoid may not be performed during speculative execution
    /// of transactions, but instead once at post-commit time based on the collected execution
    /// trace. This is a node config and will never change for the lifetime of the environment.
    async_runtime_checks_enabled: bool,
}
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L714-718)
```text
    public fun toggle_features(aptos_framework: &signer, enable: vector<u64>, disable: vector<u64>) {
        system_addresses::assert_aptos_framework(aptos_framework);
        features::change_feature_flags_for_next_epoch(aptos_framework, enable, disable);
        reconfigure(aptos_framework);
    }
```

**File:** mempool/src/shared_mempool/tasks.rs (L775-775)
```rust
    if let Err(e) = validator.write().restart() {
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L348-350)
```rust
    fn features(&self) -> &Features {
        self.move_vm.env.features()
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3172-3179)
```rust
        if !self
            .features()
            .is_enabled(FeatureFlag::SINGLE_SENDER_AUTHENTICATOR)
        {
            if let aptos_types::transaction::authenticator::TransactionAuthenticator::SingleSender{ .. } = transaction.authenticator_ref() {
                return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
            }
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3250-3261)
```rust
        let vm_params = match self.gas_params(&log_context) {
            Ok(vm_params) => vm_params.vm.clone(),
            Err(err) => {
                return VMValidatorResult::new(Some(err.status_code()), 0);
            },
        };
        let storage_gas_params = match self.storage_gas_params(&log_context) {
            Ok(storage_params) => storage_params.clone(),
            Err(err) => {
                return VMValidatorResult::new(Some(err.status_code()), 0);
            },
        };
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L211-213)
```rust
        // Get the current environment from storage.
        let storage_environment =
            AptosEnvironment::new_with_delayed_field_optimization_enabled(&state_view);
```
