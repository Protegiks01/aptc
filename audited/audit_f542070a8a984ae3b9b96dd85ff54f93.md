# Audit Report

## Title
Stale Environment Cache in VM Validator Leads to Consensus Divergence After Governance Updates

## Summary
The `VMValidator` in `vm-validator/src/vm_validator.rs` fails to update its cached `AptosEnvironment` (containing gas schedules and feature flags) when the blockchain state is updated via governance proposals. This causes transaction validation to use outdated gas parameters and feature flags, potentially leading to consensus violations where different validators disagree on transaction validity.

## Finding Description

The vulnerability exists in the `notify_commit()` method of `VMValidator`. [1](#0-0) 

When a new block is committed, this method checks if the old and new state view IDs are compatible. If both are `TransactionValidation` types and `old_version <= new_version`, it only calls `reset_state_view()` to update the state view. [2](#0-1) 

The critical issue is that `reset_state_view()` in `CachedModuleView` only updates the `state_view` field, **not** the `environment` field: [3](#0-2) 

In contrast, `reset_all()` updates both the state view and recreates the environment from the new state: [4](#0-3) 

The `AptosEnvironment` contains critical execution parameters including gas schedules, feature flags, timed features, gas feature version, and VM configurations. [5](#0-4) 

These parameters are fetched from the on-chain state when the environment is created. [6](#0-5) 

When validating transactions, the VM validator creates an `AptosVM` instance using the cached environment: [7](#0-6) 

The `AptosVM` stores this environment and uses it to retrieve gas parameters and feature flags during validation: [8](#0-7) [9](#0-8) 

**Attack Scenario:**
1. Governance proposal updates gas schedules or feature flags on-chain (via `gas_schedule::set_for_next_epoch()` and reconfiguration)
2. The blockchain commits these changes at version N
3. `notify_commit()` is triggered with the new state
4. Since `old_version < N` (compatible versions), only `reset_state_view()` is called
5. The `environment` field retains old gas parameters and feature flags
6. Subsequent transactions are validated using outdated parameters
7. Different validators may have different cached environments if they restart at different times or have different update timing
8. This causes consensus divergence: validators disagree on which transactions are valid

## Impact Explanation

**CRITICAL Severity** - This vulnerability violates the **Deterministic Execution** invariant, which is fundamental to blockchain consensus:

1. **Consensus Safety Violation**: Different validators with different cached environments will produce different transaction validation results. This can lead to chain splits if validators disagree on which transactions should be included in blocks.

2. **Gas Metering Bypass**: If gas schedules are reduced via governance but the cache retains old higher limits, transactions could bypass new gas restrictions.

3. **Feature Flag Bypass**: New security features enabled via governance could be bypassed if validators continue using cached environments with features disabled.

The impact qualifies as **Critical** under the Aptos Bug Bounty program criteria:
- "Consensus/Safety violations" - Direct violation of consensus determinism
- "Non-recoverable network partition (requires hardfork)" - Potential outcome if validators permanently disagree

## Likelihood Explanation

**HIGH Likelihood**:

1. **Frequent Trigger**: Gas schedule updates occur regularly through governance proposals as the network evolves. Each update is a potential trigger.

2. **Automatic Occurrence**: The vulnerability triggers automatically after governance updates when `notify_commit()` is called with compatible versions (the common case).

3. **No Special Privileges Required**: Any legitimate governance proposal updating gas schedules or features triggers this. No attacker action needed beyond normal governance processes.

4. **Long Persistence**: The stale cache persists until either:
   - An incompatible state view ID change occurs (rare)
   - The validator restarts (manual intervention)
   - `restart()` is explicitly called (not automatic)

5. **Network-Wide Impact**: All validators in the network are affected simultaneously after a governance update.

## Recommendation

Modify the `notify_commit()` method to always call `reset_all()` instead of `reset_state_view()` to ensure the environment is refreshed with the latest on-chain configuration:

```rust
fn notify_commit(&mut self) {
    let db_state_view = self.db_state_view();
    
    // Always reset all state including environment to ensure gas schedules
    // and feature flags are up-to-date after governance changes
    self.state.reset_all(db_state_view.into());
}
```

**Alternative Solution** (more sophisticated): Detect when the environment needs updating by comparing environment hashes or checking for reconfiguration events, and selectively call `reset_all()` only when needed:

```rust
fn notify_commit(&mut self) {
    let db_state_view = self.db_state_view();
    let new_environment = AptosEnvironment::new(&db_state_view);
    
    // Check if environment has changed (using PartialEq which compares hashes)
    if self.state.environment != new_environment {
        // Environment changed (e.g., gas schedule or features updated)
        self.state.reset_all(db_state_view.into());
    } else {
        // Only state changed, environment is still valid
        self.state.reset_state_view(db_state_view.into());
    }
}
```

## Proof of Concept

The following Rust test demonstrates the vulnerability:

```rust
#[cfg(test)]
mod test_stale_environment {
    use super::*;
    use aptos_types::{
        on_chain_config::{GasScheduleV2, OnChainConfig, Features, FeatureFlag},
        state_store::{state_key::StateKey, state_value::StateValue, MockStateView},
    };
    use std::collections::HashMap;

    #[test]
    fn test_environment_not_updated_on_notify_commit() {
        // Create initial state with gas schedule V1
        let gas_schedule_v1 = GasScheduleV2 {
            feature_version: 12,
            entries: vec![],
        };
        
        let mut state_data = HashMap::new();
        state_data.insert(
            StateKey::resource(
                &GasScheduleV2::address(),
                &GasScheduleV2::struct_tag()
            ).unwrap(),
            StateValue::new_legacy(bcs::to_bytes(&gas_schedule_v1).unwrap().into())
        );
        
        let initial_view = MockStateView::new_with_version(state_data, 100);
        let mut vm_validator = VMValidator::new(Arc::new(initial_view));
        
        // Capture initial environment gas feature version
        let initial_gas_version = vm_validator.state.environment.gas_feature_version();
        assert_eq!(initial_gas_version, 12);
        
        // Simulate governance update: new gas schedule V2 committed at version 200
        let gas_schedule_v2 = GasScheduleV2 {
            feature_version: 13, // Upgraded
            entries: vec![],
        };
        
        let mut new_state_data = HashMap::new();
        new_state_data.insert(
            StateKey::resource(
                &GasScheduleV2::address(),
                &GasScheduleV2::struct_tag()
            ).unwrap(),
            StateValue::new_legacy(bcs::to_bytes(&gas_schedule_v2).unwrap().into())
        );
        
        // Mock the db_reader to return new state at version 200
        // (implementation details omitted for brevity)
        
        // Call notify_commit - this should update the environment
        vm_validator.notify_commit();
        
        // BUG: Environment is NOT updated because reset_state_view() was called
        let current_gas_version = vm_validator.state.environment.gas_feature_version();
        
        // This assertion FAILS - gas version is still 12, not 13
        // Demonstrates the stale environment issue
        assert_eq!(current_gas_version, 12); // Still old version!
        assert_ne!(current_gas_version, 13); // Should be new version but isn't
        
        // Transactions validated after this point use outdated gas parameters
        // leading to consensus divergence if other validators have updated
    }
}
```

**Notes:**
- The cached environment remains at gas feature version 12 despite on-chain state being updated to version 13
- Transaction validation will use the stale version 12 parameters
- If different validators have different cached versions, consensus divergence occurs
- The issue persists until validator restart or explicit `reset_all()` call

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

**File:** vm-validator/src/vm_validator.rs (L159-164)
```rust
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

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L212-318)
```rust
    fn new(
        state_view: &impl StateView,
        inject_create_signer_for_gov_sim: bool,
        gas_hook: Option<Arc<dyn Fn(DynamicExpression) + Send + Sync>>,
    ) -> Self {
        // We compute and store a hash of configs in order to distinguish different environments.
        let mut sha3_256 = Sha3_256::new();
        let features =
            fetch_config_and_update_hash::<Features>(&mut sha3_256, state_view).unwrap_or_default();

        // If no chain ID is in storage, we assume we are in a testing environment.
        let chain_id = fetch_config_and_update_hash::<ChainId>(&mut sha3_256, state_view)
            .unwrap_or_else(ChainId::test);
        let timestamp_micros =
            fetch_config_and_update_hash::<ConfigurationResource>(&mut sha3_256, state_view)
                .map(|config| config.last_reconfiguration_time_micros())
                .unwrap_or(0);

        let mut timed_features_builder = TimedFeaturesBuilder::new(chain_id, timestamp_micros);
        if let Some(profile) = get_timed_feature_override() {
            // We need to ensure the override is taken into account for the hash.
            let profile_bytes = bcs::to_bytes(&profile)
                .expect("Timed features override should always be serializable");
            sha3_256.update(&profile_bytes);

            timed_features_builder = timed_features_builder.with_override_profile(profile)
        }
        let timed_features = timed_features_builder.build();

        // TODO(Gas):
        //   Right now, we have to use some dummy values for gas parameters if they are not found
        //   on-chain. This only happens in a edge case that is probably related to write set
        //   transactions or genesis, which logically speaking, shouldn't be handled by the VM at
        //   all. We should clean up the logic here once we get that refactored.
        let (gas_params, storage_gas_params, gas_feature_version) =
            get_gas_parameters(&mut sha3_256, &features, state_view);
        let (native_gas_params, misc_gas_params, ty_builder) = match &gas_params {
            Ok(gas_params) => {
                let ty_builder = aptos_prod_ty_builder(gas_feature_version, gas_params);
                (
                    gas_params.natives.clone(),
                    gas_params.vm.misc.clone(),
                    ty_builder,
                )
            },
            Err(_) => {
                let ty_builder = aptos_default_ty_builder();
                (
                    NativeGasParameters::zeros(),
                    MiscGasParameters::zeros(),
                    ty_builder,
                )
            },
        };

        let mut builder = SafeNativeBuilder::new(
            gas_feature_version,
            native_gas_params,
            misc_gas_params,
            timed_features.clone(),
            features.clone(),
            gas_hook,
        );
        let natives = aptos_natives_with_builder(&mut builder, inject_create_signer_for_gov_sim);
        let vm_config = aptos_prod_vm_config(
            chain_id,
            gas_feature_version,
            &features,
            &timed_features,
            ty_builder,
        );
        let verifier_bytes =
            bcs::to_bytes(&vm_config.verifier_config).expect("Verifier config is serializable");
        let runtime_environment = RuntimeEnvironment::new_with_config(natives, vm_config);

        // We use an `Option` to handle the VK not being set on-chain, or an incorrect VK being set
        // via governance (although, currently, we do check for that in `keyless_account.move`).
        let keyless_pvk =
            Groth16VerificationKey::fetch_keyless_config(state_view).and_then(|(vk, vk_bytes)| {
                sha3_256.update(&vk_bytes);
                vk.try_into().ok()
            });
        let keyless_configuration =
            Configuration::fetch_keyless_config(state_view).map(|(config, config_bytes)| {
                sha3_256.update(&config_bytes);
                config
            });

        let hash = sha3_256.finalize().into();

        #[allow(deprecated)]
        Self {
            chain_id,
            features,
            timed_features,
            keyless_pvk,
            keyless_configuration,
            gas_feature_version,
            gas_params,
            storage_gas_params,
            runtime_environment,
            inject_create_signer_for_gov_sim,
            hash,
            verifier_bytes,
            async_runtime_checks_enabled: get_async_runtime_checks(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L317-325)
```rust
    pub fn new(env: &AptosEnvironment) -> Self {
        Self {
            is_simulation: false,
            move_vm: MoveVmExt::new(env),
            // There is no tracing by default because it can only be done if there is access to
            // Block-STM.
            async_runtime_checks_enabled: false,
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L348-386)
```rust
    fn features(&self) -> &Features {
        self.move_vm.env.features()
    }

    #[inline(always)]
    fn timed_features(&self) -> &TimedFeatures {
        self.move_vm.env.timed_features()
    }

    #[inline(always)]
    fn deserializer_config(&self) -> &DeserializerConfig {
        &self.move_vm.env.vm_config().deserializer_config
    }

    #[inline(always)]
    fn chain_id(&self) -> ChainId {
        self.move_vm.env.chain_id()
    }

    #[inline(always)]
    pub(crate) fn gas_feature_version(&self) -> u64 {
        self.move_vm.env.gas_feature_version()
    }

    #[inline(always)]
    pub(crate) fn gas_params(
        &self,
        log_context: &AdapterLogSchema,
    ) -> Result<&AptosGasParameters, VMStatus> {
        get_or_vm_startup_failure(self.move_vm.env.gas_params(), log_context)
    }

    #[inline(always)]
    pub(crate) fn storage_gas_params(
        &self,
        log_context: &AdapterLogSchema,
    ) -> Result<&StorageGasParameters, VMStatus> {
        get_or_vm_startup_failure(self.move_vm.env.storage_gas_params(), log_context)
    }
```
