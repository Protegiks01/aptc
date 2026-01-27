# Audit Report

## Title
VMConfig Node-Local Parameters Not Included in Consensus Environment Hash Enabling Potential Consensus Divergence During Upgrades

## Summary
The `VMConfig` structure contains critical execution parameters that are sourced from both on-chain state and node-local configuration files. However, several node-local parameters (`paranoid_type_checks`, `paranoid_ref_checks`, `enable_layout_caches`, `async_runtime_checks_enabled`) that directly affect execution behavior are not included in the `AptosEnvironment` hash used for configuration compatibility checks. During version upgrades, validators with different `NodeConfig` settings could execute transactions differently, causing consensus divergence. Additionally, there are no tests validating that config changes across version boundaries maintain consensus.

## Finding Description

The `VMConfig` struct defines the Move VM's runtime configuration, including multiple boolean flags that control execution behavior: [1](#0-0) 

These parameters are populated via `aptos_prod_vm_config()` which reads from both on-chain state (Features, gas_feature_version) and node-local global static variables: [2](#0-1) 

The critical issue is that node-local parameters are set via global `OnceCell` variables from the node's configuration file: [3](#0-2) 

These parameters directly affect bytecode execution by selecting different runtime type checking implementations: [4](#0-3) 

When `paranoid_type_checks` is enabled, runtime type safety checks are performed that can cause transactions to fail with `EPARANOID_FAILURE`: [5](#0-4) 

**The Consensus Break Mechanism:**

The `AptosEnvironment` hash is computed to detect configuration differences between nodes: [6](#0-5) 

However, this hash computation includes on-chain configs (Features, ChainId, GasScheduleV2, etc.) but **excludes** the node-local VMConfig parameters. The `async_runtime_checks_enabled` is stored but never hashed (line 316), and `paranoid_type_checks`/`paranoid_ref_checks` are read during VMConfig creation (lines 205-206 in prod_configs.rs) but never contribute to the environment hash.

Environment equality is determined solely by hash comparison: [7](#0-6) 

**Attack Scenario:**

During a rolling upgrade or configuration change:
1. Some validators have `execution.paranoid_type_verification = true` in their NodeConfig
2. Others have it set to `false` (due to misconfiguration, using testnet configs on mainnet, or during gradual rollout)
3. Both sets of validators pass the environment hash check (same on-chain state)
4. A transaction that would trigger a paranoid type check failure arrives
5. Validators with `paranoid_type_checks=true` reject it with `EPARANOID_FAILURE` 
6. Validators with `paranoid_type_checks=false` accept it
7. Different state roots are produced → consensus breaks

**Missing Test Coverage:**

Examination of existing upgrade tests shows no validation of VMConfig consistency across nodes: [8](#0-7) [9](#0-8) 

These tests only validate binary version upgrades and on-chain config changes (ConsensusConfig V1/V2), but do not test scenarios where validators have different node-local VMConfig settings.

## Impact Explanation

**Severity: High**

This issue qualifies as **High Severity** under the Aptos bug bounty program because it can cause "Significant protocol violations" through consensus divergence during upgrades. While there is a configuration sanitizer that enforces `paranoid_type_verification=true` for mainnet: [10](#0-9) 

This mitigation has gaps:
1. **Timing Windows**: During rolling upgrades, nodes restart sequentially. A misconfiguration could escape detection until multiple nodes are affected.
2. **Other Parameters**: The sanitizer only checks `paranoid_type_verification` and `paranoid_hot_potato_verification`, not `enable_layout_caches` or `async_runtime_checks`.
3. **Non-Mainnet Networks**: Testnet and devnet lack these sanitizers, making them vulnerable to operational errors that could cascade into mainnet.
4. **Configuration Drift**: Over time, validators might update their configs independently, creating subtle divergences.

If exploited (even accidentally), this breaks the **Deterministic Execution** invariant, causing different validators to compute different state roots for identical blocks, leading to chain splits requiring manual intervention or hard forks to resolve.

## Likelihood Explanation

**Likelihood: Medium**

While direct external exploitation is difficult, the likelihood is elevated by operational realities:

1. **No Programmatic Enforcement**: The environment hash doesn't include these parameters, so validators with different configs appear compatible
2. **Configuration Complexity**: NodeConfig has multiple execution parameters that operators must set correctly
3. **Upgrade Windows**: During version upgrades spanning hours/days, configuration drift is more likely
4. **No Testing Coverage**: Absence of tests means this scenario isn't validated in CI/CD pipelines
5. **Silent Failures**: Validators don't receive warnings when their configs differ from peers

The issue is more likely to manifest as an operational incident during upgrades rather than a targeted attack, but the consensus impact is the same regardless of intent.

## Recommendation

**Immediate Fix:**

1. **Include VMConfig in Environment Hash**: Serialize the complete `VMConfig` (not just `verifier_config`) and include it in the SHA3-256 hash computation:

```rust
// In environment.rs, after line 284:
let vm_config_bytes = bcs::to_bytes(&vm_config)
    .expect("VMConfig is serializable");
sha3_256.update(&vm_config_bytes);
```

2. **Add Cross-Node Config Validation Tests**: Create integration tests that:
   - Start multiple validators with intentionally different NodeConfig values
   - Verify they either reject incompatible configs or stay in consensus
   - Test all VMConfig parameters that affect execution

3. **Extend Configuration Sanitizer**: Validate all execution-affecting parameters, not just `paranoid_type_verification`:

```rust
// In execution_config.rs:
if chain_id.is_mainnet() {
    // Check all consensus-critical parameters
    if !execution_config.layout_caches_enabled {
        return Err(Error::ConfigSanitizerFailed(
            sanitizer_name,
            "layout_caches must be enabled for mainnet".into()
        ));
    }
    // Add checks for other parameters...
}
```

4. **Runtime Config Comparison**: Add validator startup checks that fetch peer configs (via diagnostic APIs) and warn if local VMConfig differs from the majority.

## Proof of Concept

Due to the nature of this vulnerability requiring multiple validator nodes with different configurations, a full PoC requires integration test infrastructure. However, the concept can be demonstrated:

```rust
// Pseudo-code demonstrating the issue
#[test]
fn test_vmconfig_consensus_divergence() {
    // Setup two nodes
    let mut node1_config = NodeConfig::default();
    node1_config.execution.paranoid_type_verification = true;
    
    let mut node2_config = NodeConfig::default(); 
    node2_config.execution.paranoid_type_verification = false;
    
    // Both nodes read same on-chain state
    let state_view = create_test_state_view();
    
    // Create environments
    set_paranoid_type_checks(true);
    let env1 = AptosEnvironment::new(&state_view);
    
    set_paranoid_type_checks(false);
    let env2 = AptosEnvironment::new(&state_view);
    
    // Environments appear equal (same hash)!
    assert_eq!(env1, env2); // This passes, but they have different VMConfigs
    
    // But VMConfigs are different
    assert_ne!(
        env1.vm_config().paranoid_type_checks,
        env2.vm_config().paranoid_type_checks
    );
    
    // Execute a transaction that triggers paranoid checks
    // Node1 would fail it, Node2 would accept it → consensus break
}
```

To properly test this, the existing upgrade test frameworks in `testsuite/testcases/` should be extended to include VMConfig variation scenarios.

---

**Notes:**

While the mainnet configuration sanitizer provides some protection, the fundamental architectural issue remains: critical execution parameters from node-local configuration are not included in the mechanism designed to detect configuration incompatibilities between validators. The absence of tests for config changes across version boundaries means this risk category is not validated during development or deployment.

### Citations

**File:** third_party/move/move-vm/runtime/src/config.rs (L14-59)
```rust
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VMConfig {
    pub verifier_config: VerifierConfig,
    pub deserializer_config: DeserializerConfig,
    /// When this flag is set to true, MoveVM will perform type checks at every instruction
    /// execution to ensure that type safety cannot be violated at runtime. Note: these
    /// are more than type checks, for example, stack balancing, visibility, but the name
    /// is kept for historical reasons.
    pub paranoid_type_checks: bool,
    /// Always set to false, no longer used, kept for compatibility.
    pub legacy_check_invariant_in_swap_loc: bool,
    /// Maximum value nest depth for structs.
    pub max_value_nest_depth: Option<u64>,
    /// Maximum allowed number of nodes in a type layout. This includes the types of fields for
    /// struct types.
    pub layout_max_size: u64,
    /// Maximum depth (in number of nodes) of the type layout tree.
    pub layout_max_depth: u64,
    pub type_max_cost: u64,
    pub type_base_cost: u64,
    pub type_byte_cost: u64,
    pub delayed_field_optimization_enabled: bool,
    pub ty_builder: TypeBuilder,
    pub enable_function_caches: bool,
    pub enable_lazy_loading: bool,
    pub enable_depth_checks: bool,
    /// Whether trusted code should be optimized, for example, excluding it from expensive
    /// paranoid checks. Checks may still not be done in place, and instead delayed to later time.
    /// Instead, a trace can be recorded which is sufficient for type checking.
    pub optimize_trusted_code: bool,
    /// When this flag is set to true, Move VM will perform additional checks to ensure that
    /// reference safety is maintained during execution. Note that the checks might be delayed and
    /// instead execution trace can be recorded (so that checks are done based on the trace later).
    pub paranoid_ref_checks: bool,
    pub enable_capture_option: bool,
    pub enable_enum_option: bool,
    /// If true, Move VM will try to fetch layout from remote cache.
    pub enable_layout_caches: bool,
    pub propagate_dependency_limit_error: bool,
    pub enable_framework_for_option: bool,
    /// Same as enable_function_caches, but gates missed gating for native dynamic dispatch.
    pub enable_function_caches_for_native_dynamic_dispatch: bool,
    /// Whether this VM should support debugging. If set, environment variables
    /// `MOVE_VM_TRACE` and `MOVE_VM_STEP` will be recognized.
    pub enable_debugging: bool,
}
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L198-276)
```rust
pub fn aptos_prod_vm_config(
    chain_id: ChainId,
    gas_feature_version: u64,
    features: &Features,
    timed_features: &TimedFeatures,
    ty_builder: TypeBuilder,
) -> VMConfig {
    let paranoid_type_checks = get_paranoid_type_checks();
    let paranoid_ref_checks = get_paranoid_ref_checks();
    let enable_layout_caches = get_layout_caches();
    let enable_debugging = get_debugging_enabled();

    let deserializer_config = aptos_prod_deserializer_config(features);
    let verifier_config = aptos_prod_verifier_config(gas_feature_version, features);
    let enable_enum_option = features.is_enabled(FeatureFlag::ENABLE_ENUM_OPTION);
    let enable_framework_for_option = features.is_enabled(FeatureFlag::ENABLE_FRAMEWORK_FOR_OPTION);

    let layout_max_size = if gas_feature_version >= RELEASE_V1_30 {
        512
    } else {
        256
    };

    // Value runtime depth checks have been introduced together with function values and are only
    // enabled when the function values are enabled. Previously, checks were performed over types
    // to bound the value depth (checking the size of a packed struct type bounds the value), but
    // this no longer applies once function values are enabled. With function values, types can be
    // shallow while the value can be deeply nested, thanks to captured arguments not visible in a
    // type. Hence, depth checks have been adjusted to operate on values.
    let enable_depth_checks = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
    let enable_capture_option = !timed_features.is_enabled(TimedFeatureFlag::DisabledCaptureOption)
        || features.is_enabled(FeatureFlag::ENABLE_CAPTURE_OPTION);

    // Some feature gating was missed, so for native dynamic dispatch the feature is always on for
    // testnet after 1.38 release.
    let enable_function_caches = features.is_call_tree_and_instruction_vm_cache_enabled();
    let enable_function_caches_for_native_dynamic_dispatch =
        enable_function_caches || (chain_id.is_testnet() && gas_feature_version >= RELEASE_V1_38);

    let config = VMConfig {
        verifier_config,
        deserializer_config,
        paranoid_type_checks,
        legacy_check_invariant_in_swap_loc: false,
        // Note: if updating, make sure the constant is in-sync.
        max_value_nest_depth: Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH),
        layout_max_size,
        layout_max_depth: 128,
        // 5000 limits type tag total size < 5000 bytes and < 50 nodes.
        type_max_cost: 5000,
        type_base_cost: 100,
        type_byte_cost: 1,
        // By default, do not use delayed field optimization. Instead, clients should enable it
        // manually where applicable.
        delayed_field_optimization_enabled: false,
        ty_builder,
        enable_function_caches,
        enable_lazy_loading: features.is_lazy_loading_enabled(),
        enable_depth_checks,
        optimize_trusted_code: features.is_trusted_code_enabled(),
        paranoid_ref_checks,
        enable_capture_option,
        enable_enum_option,
        enable_layout_caches,
        propagate_dependency_limit_error: gas_feature_version >= RELEASE_V1_38,
        enable_framework_for_option,
        enable_function_caches_for_native_dynamic_dispatch,
        enable_debugging,
    };

    // Note: if max_value_nest_depth changed, make sure the constant is in-sync. Do not remove this
    // assertion as it ensures the constant value is set correctly.
    assert_eq!(
        config.max_value_nest_depth,
        Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH)
    );

    config
}
```

**File:** aptos-node/src/utils.rs (L52-75)
```rust
/// Sets the Aptos VM configuration based on the node configurations
pub fn set_aptos_vm_configurations(node_config: &NodeConfig) {
    set_layout_caches(node_config.execution.layout_caches_enabled);
    set_paranoid_type_checks(node_config.execution.paranoid_type_verification);
    set_async_runtime_checks(node_config.execution.async_runtime_checks);
    let effective_concurrency_level = if node_config.execution.concurrency_level == 0 {
        ((num_cpus::get() / 2) as u16).clamp(1, DEFAULT_EXECUTION_CONCURRENCY_LEVEL)
    } else {
        node_config.execution.concurrency_level
    };
    AptosVM::set_concurrency_level_once(effective_concurrency_level as usize);
    AptosVM::set_discard_failed_blocks(node_config.execution.discard_failed_blocks);
    AptosVM::set_num_proof_reading_threads_once(
        node_config.execution.num_proof_reading_threads as usize,
    );
    AptosVM::set_blockstm_v2_enabled_once(node_config.execution.blockstm_v2_enabled);

    if node_config
        .execution
        .processed_transactions_detailed_counters
    {
        AptosVM::set_processed_transactions_detailed_counters();
    }
}
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L244-278)
```rust
        let paranoid_type_checks =
            !trace_recorder.is_enabled() && interpreter.vm_config.paranoid_type_checks;
        let optimize_trusted_code =
            !trace_recorder.is_enabled() && interpreter.vm_config.optimize_trusted_code;
        let paranoid_ref_checks = interpreter.vm_config.paranoid_ref_checks;

        let function = Rc::new(function);
        macro_rules! execute_main {
            ($type_check:ty, $ref_check:ty) => {
                interpreter.execute_main::<$type_check, $ref_check>(
                    data_cache,
                    function_caches,
                    gas_meter,
                    traversal_context,
                    extensions,
                    trace_recorder,
                    function,
                    args,
                )
            };
        }

        // Note: we have organized the code below from most-likely config to least-likely config.
        match (
            paranoid_type_checks,
            optimize_trusted_code,
            paranoid_ref_checks,
        ) {
            (true, true, false) => execute_main!(UntrustedOnlyRuntimeTypeCheck, NoRuntimeRefCheck),
            (true, false, false) => execute_main!(FullRuntimeTypeCheck, NoRuntimeRefCheck),
            (true, true, true) => execute_main!(UntrustedOnlyRuntimeTypeCheck, FullRuntimeRefCheck),
            (true, false, true) => execute_main!(FullRuntimeTypeCheck, FullRuntimeRefCheck),
            (false, _, false) => execute_main!(NoRuntimeTypeCheck, NoRuntimeRefCheck),
            (false, _, true) => execute_main!(NoRuntimeTypeCheck, FullRuntimeRefCheck),
        }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L424-432)
```rust
macro_rules! paranoid_failure {
    ($msg:ident) => {
        Err(
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message($msg)
                .with_sub_status(EPARANOID_FAILURE),
        )
    };
}
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L152-158)
```rust
impl PartialEq for AptosEnvironment {
    fn eq(&self, other: &Self) -> bool {
        self.0.hash == other.0.hash
    }
}

impl Eq for AptosEnvironment {}
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L217-300)
```rust
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
```

**File:** testsuite/testcases/src/compatibility_test.rs (L12-50)
```rust
pub struct SimpleValidatorUpgrade;

impl SimpleValidatorUpgrade {
    pub const EPOCH_DURATION_SECS: u64 = 30;
}

impl Test for SimpleValidatorUpgrade {
    fn name(&self) -> &'static str {
        "compatibility::simple-validator-upgrade"
    }
}

#[async_trait]
impl NetworkTest for SimpleValidatorUpgrade {
    async fn run<'a>(&self, ctxa: NetworkContextSynchronizer<'a>) -> Result<()> {
        let upgrade_wait_for_healthy = true;
        let upgrade_node_delay = Duration::from_secs(20);
        let upgrade_max_wait = Duration::from_secs(40);

        let epoch_duration = Duration::from_secs(Self::EPOCH_DURATION_SECS);

        // Get the different versions we're testing with
        let (old_version, new_version) = {
            let mut versions = ctxa
                .ctx
                .lock()
                .await
                .swarm
                .read()
                .await
                .versions()
                .collect::<Vec<_>>();
            versions.sort();
            if versions.len() != 2 {
                bail!("exactly two different versions needed to run compat test");
            }

            (versions[0].clone(), versions[1].clone())
        };
```

**File:** testsuite/testcases/src/framework_upgrade.rs (L20-75)
```rust
pub struct FrameworkUpgrade;

impl FrameworkUpgrade {
    pub const EPOCH_DURATION_SECS: u64 = 10;
}

impl Test for FrameworkUpgrade {
    fn name(&self) -> &'static str {
        "framework_upgrade::framework-upgrade"
    }
}

const RELEASE_YAML_PATH: &str = "aptos-move/aptos-release-builder/data";
const IGNORED_YAMLS: [&str; 2] = ["release.yaml", "example.yaml"];

fn is_release_yaml(path: &Path) -> bool {
    let basename = path.file_name().unwrap().to_str().unwrap();
    path.is_file()
        && path.extension().unwrap_or_default() == "yaml"
        && !IGNORED_YAMLS.contains(&basename)
}

#[async_trait]
impl NetworkTest for FrameworkUpgrade {
    async fn run<'a>(&self, ctx: NetworkContextSynchronizer<'a>) -> Result<()> {
        let mut ctx_locker = ctx.ctx.lock().await;
        let ctx = ctx_locker.deref_mut();

        let epoch_duration = Duration::from_secs(Self::EPOCH_DURATION_SECS);

        // Get the different versions we're testing with
        let (old_version, new_version) = {
            let mut versions = ctx.swarm.read().await.versions().collect::<Vec<_>>();
            versions.sort();
            if versions.len() != 2 {
                bail!("exactly two different versions needed to run compat test");
            }

            (versions[0].clone(), versions[1].clone())
        };

        let all_validators = {
            ctx.swarm
                .read()
                .await
                .validators()
                .map(|v| v.peer_id())
                .collect::<Vec<_>>()
        };

        let msg = format!(
            "Compatibility test results for {} ==> {} (PR)",
            old_version, new_version
        );
        info!("{}", msg);
        ctx.report.report_text(msg);
```

**File:** config/src/config/execution_config.rs (L157-186)
```rust
impl ConfigSanitizer for ExecutionConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let execution_config = &node_config.execution;

        // If this is a mainnet node, ensure that additional verifiers are enabled
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if !execution_config.paranoid_hot_potato_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_hot_potato_verification must be enabled for mainnet nodes!"
                            .into(),
                    ));
                }
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
            }
        }

        Ok(())
    }
```
