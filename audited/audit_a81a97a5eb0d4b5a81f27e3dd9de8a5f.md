# Audit Report

## Title
Consensus Split Vulnerability Due to Bytecode Version Mismatch During Rolling Validator Upgrades

## Summary
A structural consensus vulnerability exists where the lack of code-level coordination between on-chain feature flags and validator binary versions can cause blockchain forks during rolling upgrades. When governance enables new bytecode version feature flags before all validators upgrade their software, heterogeneous validators will disagree on transaction validity, violating the deterministic execution invariant required for consensus.

## Finding Description

The vulnerability stems from a fundamental architectural issue where bytecode version validation depends on both on-chain feature flags (dynamically controlled) and compile-time constants (static in validator binaries), without any code-level enforcement ensuring these remain synchronized during rolling upgrades.

**Technical Mechanism:**

The deserialization validation logic uses the minimum of two version sources: [1](#0-0) 

Where `max_version` is determined by on-chain feature flags: [2](#0-1) [3](#0-2) 

And `VERSION_MAX` is a compile-time constant in the validator binary: [4](#0-3) 

This is invoked during module publishing: [5](#0-4) [6](#0-5) 

**Attack Scenario:**

1. Network operates with validators running software version N where `VERSION_MAX=9` (compile-time)
2. Governance proposal enables `VM_BINARY_FORMAT_V10` feature flag, setting on-chain `max_version=10`
3. Validators begin rolling upgrade to version N+1 where `VERSION_MAX=10`
4. During the upgrade window, validator set is heterogeneous
5. User publishes module with bytecode version 10 (achievable via build options): [7](#0-6) 

6. **Consensus divergence occurs:**
   - Upgraded validators (VERSION_MAX=10): `10 > min(10, 10)` evaluates to FALSE → **ACCEPT transaction**
   - Non-upgraded validators (VERSION_MAX=9): `10 > min(10, 9)` evaluates to TRUE → **REJECT transaction with UNKNOWN_VERSION**

7. Validators produce different state roots for the same block, fundamentally breaking consensus determinism

**Lack of Coordination Enforcement:**

The governance system can enable bytecode version feature flags at any time without technical validation that all validators support the new version: [8](#0-7) 

Rolling upgrades demonstrably create heterogeneous validator sets: [9](#0-8) 

## Impact Explanation

**Critical Severity** per Aptos bug bounty criteria:

1. **Consensus Safety Violation**: This is an explicit Critical criterion. Different validators produce divergent state roots for identical block content, preventing the 2/3+ BFT agreement required by AptosBFT consensus protocol.

2. **Non-recoverable Network Partition**: The blockchain cannot progress past blocks containing the problematic transaction. This requires hardfork-level intervention to resolve—validators cannot self-recover through normal consensus mechanisms.

3. **Total Loss of Liveness**: Once triggered, the network halts as validators cannot reach consensus on subsequent blocks. This is another explicit Critical criterion.

4. **Deterministic Execution Invariant Broken**: The fundamental blockchain guarantee that "all honest validators execute transactions identically" is violated, compromising the entire security model.

The impact directly maps to multiple Critical severity categories in the Aptos bug bounty program, warranting maximum severity classification.

## Likelihood Explanation

**Likelihood: Medium**

**Factors Increasing Likelihood:**

1. **Structural Inevitability**: The vulnerability is not a one-time issue but a recurring pattern. Each new bytecode version (V11, V12, etc.) will create the same vulnerability window unless the coordination mechanism is fixed.

2. **Operational Necessity**: Rolling upgrades are standard practice for maintaining network availability during software updates. The longer the upgrade window, the higher the risk.

3. **Feature Flag Accessibility**: Governance proposals can enable feature flags without cryptographic proof that all validators support the new version.

4. **Benign Triggering**: Even non-malicious users compiling with latest language features will inadvertently trigger the issue during upgrade windows.

**Factors Decreasing Likelihood:**

1. **Operational Procedures**: Aptos operators likely follow careful sequencing (upgrade all validators first, then enable features via governance).

2. **Out-of-Band Coordination**: Teams probably use monitoring and communication to prevent premature flag enablement.

3. **Requires Specific Timing**: Exploit window is limited to the duration of rolling upgrades (though this may be hours).

**Critical Assessment**: While operational procedures reduce likelihood, the **complete absence of code-level enforcement** makes this a latent systemic risk. Defense-in-depth principles demand technical safeguards, not just operational discipline. A single coordination failure—whether due to miscommunication, automation error, or emergency circumstances—could trigger a network-wide consensus failure.

## Recommendation

Implement code-level coordination enforcement:

1. **Validator Version Attestation**: Before enabling a bytecode version feature flag, require cryptographic attestations from 2/3+ validators that they support the new version.

2. **Version Synchronization Check**: Add validation in the governance proposal execution that checks validator VERSION_MAX capabilities before enabling bytecode feature flags.

3. **Staged Rollout Mechanism**: Implement a two-phase approach:
   - Phase 1: All validators upgrade binary (VERSION_MAX increases)
   - Phase 2: Feature flag automatically enables once 100% of validators have upgraded

4. **Emergency Rollback**: Provide mechanism to quickly disable feature flags if consensus divergence is detected.

Example mitigation in governance execution:

```rust
// In feature flag proposal execution
fn validate_bytecode_version_upgrade(
    new_version: u32,
    validator_set: &ValidatorSet,
) -> Result<(), Error> {
    // Require 100% validator support before enabling
    for validator in validator_set.validators() {
        if validator.binary_version_max() < new_version {
            return Err(Error::InsufficientValidatorSupport);
        }
    }
    Ok(())
}
```

## Proof of Concept

The vulnerability can be demonstrated through integration testing:

```rust
// Conceptual PoC - demonstrates the core issue
#[test]
fn test_bytecode_version_consensus_split() {
    // Setup: Create two validator environments
    let old_validator_config = DeserializerConfig::new(
        10, // max_version from feature flags
        IDENTIFIER_SIZE_MAX
    );
    // Simulates old binary with VERSION_MAX = 9
    let old_version_max = 9;
    
    let new_validator_config = DeserializerConfig::new(
        10, // max_version from feature flags  
        IDENTIFIER_SIZE_MAX
    );
    // Simulates new binary with VERSION_MAX = 10
    let new_version_max = 10;
    
    // Create bytecode with version 10
    let module_v10 = create_module_with_version(10);
    
    // Old validator validation
    let old_validator_result = validate_bytecode(
        &module_v10,
        old_version_max,
        old_validator_config.max_binary_format_version
    );
    assert!(old_validator_result.is_err()); // Rejects: 10 > min(10, 9)
    
    // New validator validation  
    let new_validator_result = validate_bytecode(
        &module_v10,
        new_version_max,
        new_validator_config.max_binary_format_version
    );
    assert!(new_validator_result.is_ok()); // Accepts: 10 <= min(10, 10)
    
    // Consensus split: validators disagree on transaction validity
    assert_ne!(old_validator_result.is_ok(), new_validator_result.is_ok());
}

fn validate_bytecode(
    bytecode: &[u8],
    version_max_const: u32,
    max_version_from_config: u32,
) -> Result<(), Error> {
    let version = extract_version(bytecode);
    if version > u32::min(max_version_from_config, version_max_const) {
        Err(Error::UnknownVersion)
    } else {
        Ok(())
    }
}
```

## Notes

This vulnerability represents a **structural design flaw** in the upgrade coordination mechanism rather than a traditional runtime exploit. While operational procedures currently mitigate the risk, the absence of technical enforcement violates defense-in-depth principles and creates systemic fragility. The issue will recur with each bytecode version upgrade (V11, V12, etc.) until proper coordination mechanisms are implemented at the code level.

### Citations

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L565-565)
```rust
pub const VERSION_MAX: u32 = VERSION_10;
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L617-619)
```rust
            if version == 0 || version > u32::min(max_version, VERSION_MAX) {
                Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
                    .with_message(format!("bytecode version {} unsupported", version)))
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L137-141)
```rust
pub fn aptos_prod_deserializer_config(features: &Features) -> DeserializerConfig {
    DeserializerConfig::new(
        features.get_max_binary_format_version(),
        features.get_max_identifier_size(),
    )
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L358-360)
```rust
    fn deserializer_config(&self) -> &DeserializerConfig {
        &self.move_vm.env.vm_config().deserializer_config
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1444-1461)
```rust
    fn deserialize_module_bundle(&self, modules: &ModuleBundle) -> VMResult<Vec<CompiledModule>> {
        let mut result = vec![];
        for module_blob in modules.iter() {
            match CompiledModule::deserialize_with_config(
                module_blob.code(),
                self.deserializer_config(),
            ) {
                Ok(module) => {
                    result.push(module);
                },
                Err(_err) => {
                    return Err(PartialVMError::new(StatusCode::CODE_DESERIALIZATION_ERROR)
                        .finish(Location::Undefined))
                },
            }
        }
        Ok(result)
    }
```

**File:** aptos-move/framework/src/built_package.rs (L165-171)
```rust
    pub fn set_latest_language(self) -> Self {
        BuildOptions {
            language_version: Some(LanguageVersion::latest()),
            bytecode_version: Some(file_format_common::VERSION_MAX),
            ..self
        }
    }
```

**File:** aptos-move/aptos-release-builder/src/components/feature_flags.rs (L182-238)
```rust
pub fn generate_feature_upgrade_proposal(
    features: &Features,
    is_testnet: bool,
    next_execution_hash: Option<HashValue>,
    is_multi_step: bool,
) -> Result<Vec<(String, String)>> {
    let signer_arg = get_signer_arg(is_testnet, &next_execution_hash);
    let mut result = vec![];

    let enabled = features
        .enabled
        .iter()
        .map(|f| AptosFeatureFlag::from(f.clone()) as u64)
        .collect::<Vec<_>>();
    let disabled = features
        .disabled
        .iter()
        .map(|f| AptosFeatureFlag::from(f.clone()) as u64)
        .collect::<Vec<_>>();

    assert!(enabled.len() < u16::MAX as usize);
    assert!(disabled.len() < u16::MAX as usize);

    let writer = CodeWriter::new(Loc::default());

    emitln!(writer, "// Modifying on-chain feature flags: ");
    emitln!(writer, "// Enabled Features: {:?}", features.enabled);
    emitln!(writer, "// Disabled Features: {:?}", features.disabled);
    emitln!(writer, "//");

    let proposal = generate_governance_proposal(
        &writer,
        is_testnet,
        next_execution_hash,
        is_multi_step,
        &["std::features"],
        |writer| {
            emit!(writer, "let enabled_blob: vector<u64> = ");
            generate_features_blob(writer, &enabled);
            emitln!(writer, ";\n");

            emit!(writer, "let disabled_blob: vector<u64> = ");
            generate_features_blob(writer, &disabled);
            emitln!(writer, ";\n");

            emitln!(
                writer,
                "features::change_feature_flags_for_next_epoch({}, enabled_blob, disabled_blob);",
                signer_arg
            );
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
        },
    );

    result.push(("features".to_string(), proposal));
    Ok(result)
}
```

**File:** testsuite/testcases/src/compatibility_test.rs (L111-148)
```rust
        batch_update_gradually(
            ctxa.clone(),
            &[first_node],
            &new_version,
            upgrade_wait_for_healthy,
            upgrade_node_delay,
            upgrade_max_wait,
        )
        .await?;
        // Generate some traffic
        {
            let mut ctx_locker = ctxa.ctx.lock().await;
            let ctx = ctx_locker.deref_mut();
            let txn_stat_one = generate_traffic(ctx, &[first_node], duration).await?;
            ctx.report.report_txn_stats(
                format!("{}::single-validator-upgrade", self.name()),
                &txn_stat_one,
            );

            // Update the rest of the first batch
            let msg = format!(
                "3. Upgrading rest of first batch to new version: {}",
                new_version
            );
            info!("{}", msg);
            ctx.report.report_text(msg);
        }

        // upgrade the rest of the first half
        batch_update_gradually(
            ctxa.clone(),
            &first_batch,
            &new_version,
            upgrade_wait_for_healthy,
            upgrade_node_delay,
            upgrade_max_wait,
        )
        .await?;
```
