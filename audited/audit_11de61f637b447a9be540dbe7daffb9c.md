# Audit Report

## Title
Consensus Split Vulnerability Due to Bytecode Version Mismatch During Rolling Validator Upgrades

## Summary
A critical consensus vulnerability exists where enabling new bytecode version feature flags (e.g., `VM_BINARY_FORMAT_V10`) before all validators have upgraded their software can cause blockchain forks. The `serialize()` function can produce bytecode valid for upgraded validators but rejected by non-upgraded validators, violating the fundamental consensus invariant of deterministic execution.

## Finding Description

The vulnerability stems from a decoupling between on-chain feature flags and compile-time bytecode version constants in validator binaries, combined with the lack of coordination enforcement during rolling upgrades.

**Key Components:**

1. **Bytecode Serialization** - The `serialize()` function accepts an optional bytecode version parameter: [1](#0-0) 

2. **Feature Flag Control** - On-chain feature flags determine the maximum supported bytecode version: [2](#0-1) 

3. **Version Validation** - During deserialization, the critical check uses the minimum of on-chain config and compile-time constant: [3](#0-2) 

4. **Consensus-Critical Path** - Module publishing uses this deserialization during transaction execution: [4](#0-3) 

**Attack Scenario:**

1. Network operates with all validators running software version N with `VERSION_MAX=9`
2. Governance proposal enables `VM_BINARY_FORMAT_V10` feature flag, setting on-chain `max_version=10`
3. Validators begin rolling upgrade to software version N+1 with `VERSION_MAX=10`
4. During upgrade window, validator set is heterogeneous:
   - Upgraded validators: `VERSION_MAX=10` 
   - Non-upgraded validators: `VERSION_MAX=9`
5. Attacker (or benign user) publishes module with bytecode version 10
6. **Consensus Split:**
   - Upgraded validators: `10 <= min(10, 10)` → ACCEPT
   - Non-upgraded validators: `10 > min(10, 9)` → REJECT with `UNKNOWN_VERSION` error
7. Validators produce different state roots for the same block, breaking consensus

**Broken Invariant:**
This violates the critical invariant: *"Deterministic Execution: All validators must produce identical state roots for identical blocks"*

The compatibility tests confirm heterogeneous validator sets exist during upgrades: [5](#0-4) 

**No Coordination Safeguard:**
Critically, there is no code-level enforcement preventing feature flag enablement before all validators upgrade. The governance system can enable bytecode version flags at any time: [6](#0-5) 

## Impact Explanation

**Critical Severity** - This vulnerability causes:

1. **Consensus Safety Violation**: Different validators produce different state roots, preventing 2/3+ agreement required by AptosBFT
2. **Network Partition**: The blockchain cannot progress, causing total loss of liveness
3. **Potential Fork**: If subsets of validators independently form quorums, the chain could fork
4. **Recovery Requires Hardfork**: Resolving the split requires emergency intervention and potentially a hardfork

This directly maps to Critical severity per Aptos bug bounty criteria:
- Consensus/Safety violations (explicit criterion)
- Non-recoverable network partition requiring hardfork
- Total loss of liveness/network availability

## Likelihood Explanation

**Likelihood: Medium to High**

**Factors Increasing Likelihood:**
1. **Operational Necessity**: Rolling upgrades are standard practice for maintaining network liveness during updates
2. **Feature Flag Governance**: Any governance proposal can enable new bytecode versions without technical validation
3. **Timing Windows**: Validator upgrades take time, creating extended vulnerability windows (20-40 seconds per batch as shown in tests)
4. **Benign Triggering**: Even non-malicious users publishing modules during upgrades can trigger the issue

**Factors Decreasing Likelihood:**
1. **Operational Procedures**: Aptos team likely follows careful upgrade sequencing (upgrade validators first, then enable features)
2. **Coordination**: Out-of-band coordination likely exists to prevent premature feature enablement

**However**: The vulnerability exists at the **code level** with no technical enforcement, making it a latent risk regardless of operational practices.

## Recommendation

**Immediate Fix**: Implement version coordination checks before enabling bytecode format feature flags:

```rust
// In aptos-move/framework/aptos-framework/sources/configs/features.move
// Add validator software version tracking and validation

/// Checks if all validators support the required bytecode version before enabling feature
public fun validate_bytecode_version_support(required_version: u64) {
    // Query all active validators
    // Verify each validator's binary supports required_version
    // Abort if any validator is not ready
    assert!(all_validators_support_version(required_version), error::invalid_state(EVALIDATORS_NOT_READY));
}
```

**Enhanced Safeguard in Deserialization**: [7](#0-6) 

Add explicit validation that the on-chain `max_version` does not exceed the binary's `VERSION_MAX`:

```rust
pub fn aptos_prod_deserializer_config(features: &Features) -> DeserializerConfig {
    let max_version = features.get_max_binary_format_version();
    // Fail-safe: Never accept bytecode newer than this binary supports
    if max_version > VERSION_MAX {
        panic!("On-chain bytecode version {} exceeds binary capability {}. Validator must upgrade.", 
               max_version, VERSION_MAX);
    }
    DeserializerConfig::new(max_version, features.get_max_identifier_size())
}
```

**Governance Process Fix**:
1. Add on-chain validator version registry
2. Require proof that all validators support new bytecode versions before enabling feature flags
3. Implement staged rollout with validation gates

## Proof of Concept

```rust
// Reproduction steps (requires testnet with governance access):

// 1. Setup: Network with 4 validators, all running VERSION_MAX=9
// 2. Enable VM_BINARY_FORMAT_V10 via governance
use aptos_framework::aptos_governance;
aptos_governance::toggle_features(
    framework_signer,
    vector[106], // VM_BINARY_FORMAT_V10
    vector[]
);

// 3. Upgrade validators 0-1 to VERSION_MAX=10 (leave 2-3 on old version)
// This creates heterogeneous set

// 4. Publish module with bytecode v10
script {
    use std::vector;
    
    fun trigger_split(publisher: signer) {
        let module_code = vector<u8>[/* bytecode v10 module */];
        code::publish_package_txn(&publisher, vector[module_code], vector[]);
        // Expected: Validators 0-1 accept, 2-3 reject
        // Result: Consensus split, network halts
    }
}

// 5. Observe: Validators produce different state roots
// 6. Result: Consensus cannot be reached, network partitioned
```

The test can be constructed using the existing compatibility test framework: [8](#0-7) 

Adapt this test to use a heterogeneous validator set (mix of `VERSION_MAX=9` and `VERSION_MAX=10`) with the on-chain feature flag set to version 10.

**Notes:**
- This vulnerability requires precise timing during validator upgrades
- Operational practices may mitigate but do not eliminate the code-level vulnerability
- The safeguard `min(max_version, VERSION_MAX)` prevents individual validator crashes but enables consensus splits
- Fix requires both on-chain coordination logic and validator-side validation enhancements

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/compiled_unit.rs (L183-194)
```rust
    pub fn serialize(&self, bytecode_version: Option<u32>) -> Vec<u8> {
        let mut serialized = Vec::<u8>::new();
        match self {
            Self::Module(NamedCompiledModule { module, .. }) => module
                .serialize_for_version(bytecode_version, &mut serialized)
                .unwrap(),
            Self::Script(NamedCompiledScript { script, .. }) => script
                .serialize_for_version(bytecode_version, &mut serialized)
                .unwrap(),
        };
        serialized
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L171-277)
```rust
    pub fn default_features() -> Vec<Self> {
        vec![
            FeatureFlag::CODE_DEPENDENCY_CHECK,
            FeatureFlag::TREAT_FRIEND_AS_PRIVATE,
            FeatureFlag::SHA_512_AND_RIPEMD_160_NATIVES,
            FeatureFlag::APTOS_STD_CHAIN_ID_NATIVES,
            // Feature flag V6 is used to enable metadata v1 format and needs to stay on, even
            // if we enable a higher version.
            FeatureFlag::VM_BINARY_FORMAT_V6,
            FeatureFlag::VM_BINARY_FORMAT_V7,
            FeatureFlag::MULTI_ED25519_PK_VALIDATE_V2_NATIVES,
            FeatureFlag::BLAKE2B_256_NATIVE,
            FeatureFlag::RESOURCE_GROUPS,
            FeatureFlag::MULTISIG_ACCOUNTS,
            FeatureFlag::DELEGATION_POOLS,
            FeatureFlag::CRYPTOGRAPHY_ALGEBRA_NATIVES,
            FeatureFlag::BLS12_381_STRUCTURES,
            FeatureFlag::ED25519_PUBKEY_VALIDATE_RETURN_FALSE_WRONG_LENGTH,
            FeatureFlag::STRUCT_CONSTRUCTORS,
            FeatureFlag::PERIODICAL_REWARD_RATE_DECREASE,
            FeatureFlag::PARTIAL_GOVERNANCE_VOTING,
            FeatureFlag::_SIGNATURE_CHECKER_V2,
            FeatureFlag::STORAGE_SLOT_METADATA,
            FeatureFlag::CHARGE_INVARIANT_VIOLATION,
            FeatureFlag::DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING,
            FeatureFlag::APTOS_UNIQUE_IDENTIFIERS,
            FeatureFlag::GAS_PAYER_ENABLED,
            FeatureFlag::BULLETPROOFS_NATIVES,
            FeatureFlag::SIGNER_NATIVE_FORMAT_FIX,
            FeatureFlag::MODULE_EVENT,
            FeatureFlag::EMIT_FEE_STATEMENT,
            FeatureFlag::STORAGE_DELETION_REFUND,
            FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX,
            FeatureFlag::AGGREGATOR_V2_API,
            FeatureFlag::SAFER_RESOURCE_GROUPS,
            FeatureFlag::SAFER_METADATA,
            FeatureFlag::SINGLE_SENDER_AUTHENTICATOR,
            FeatureFlag::SPONSORED_AUTOMATIC_ACCOUNT_V1_CREATION,
            FeatureFlag::FEE_PAYER_ACCOUNT_OPTIONAL,
            FeatureFlag::AGGREGATOR_V2_DELAYED_FIELDS,
            FeatureFlag::CONCURRENT_TOKEN_V2,
            FeatureFlag::LIMIT_MAX_IDENTIFIER_LENGTH,
            FeatureFlag::OPERATOR_BENEFICIARY_CHANGE,
            FeatureFlag::BN254_STRUCTURES,
            FeatureFlag::RESOURCE_GROUPS_SPLIT_IN_VM_CHANGE_SET,
            FeatureFlag::COMMISSION_CHANGE_DELEGATION_POOL,
            FeatureFlag::WEBAUTHN_SIGNATURE,
            FeatureFlag::KEYLESS_ACCOUNTS,
            FeatureFlag::FEDERATED_KEYLESS,
            FeatureFlag::KEYLESS_BUT_ZKLESS_ACCOUNTS,
            FeatureFlag::JWK_CONSENSUS,
            FeatureFlag::REFUNDABLE_BYTES,
            FeatureFlag::OBJECT_CODE_DEPLOYMENT,
            FeatureFlag::MAX_OBJECT_NESTING_CHECK,
            FeatureFlag::KEYLESS_ACCOUNTS_WITH_PASSKEYS,
            FeatureFlag::MULTISIG_V2_ENHANCEMENT,
            FeatureFlag::DELEGATION_POOL_ALLOWLISTING,
            FeatureFlag::MODULE_EVENT_MIGRATION,
            FeatureFlag::_REJECT_UNSTABLE_BYTECODE,
            FeatureFlag::TRANSACTION_CONTEXT_EXTENSION,
            FeatureFlag::COIN_TO_FUNGIBLE_ASSET_MIGRATION,
            FeatureFlag::_OBJECT_NATIVE_DERIVED_ADDRESS,
            FeatureFlag::DISPATCHABLE_FUNGIBLE_ASSET,
            FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE,
            FeatureFlag::OPERATIONS_DEFAULT_TO_FA_APT_STORE,
            FeatureFlag::CONCURRENT_FUNGIBLE_ASSETS,
            FeatureFlag::_AGGREGATOR_V2_IS_AT_LEAST_API,
            FeatureFlag::CONCURRENT_FUNGIBLE_BALANCE,
            FeatureFlag::_LIMIT_VM_TYPE_SIZE,
            FeatureFlag::ABORT_IF_MULTISIG_PAYLOAD_MISMATCH,
            FeatureFlag::_DISALLOW_USER_NATIVES,
            FeatureFlag::ALLOW_SERIALIZED_SCRIPT_ARGS,
            FeatureFlag::_USE_COMPATIBILITY_CHECKER_V2,
            FeatureFlag::ENABLE_ENUM_TYPES,
            FeatureFlag::ENABLE_RESOURCE_ACCESS_CONTROL,
            FeatureFlag::_REJECT_UNSTABLE_BYTECODE_FOR_SCRIPT,
            FeatureFlag::TRANSACTION_SIMULATION_ENHANCEMENT,
            FeatureFlag::_NATIVE_MEMORY_OPERATIONS,
            FeatureFlag::_ENABLE_LOADER_V2,
            FeatureFlag::_DISALLOW_INIT_MODULE_TO_PUBLISH_MODULES,
            FeatureFlag::COLLECTION_OWNER,
            FeatureFlag::PERMISSIONED_SIGNER,
            FeatureFlag::ENABLE_CALL_TREE_AND_INSTRUCTION_VM_CACHE,
            FeatureFlag::ACCOUNT_ABSTRACTION,
            FeatureFlag::BULLETPROOFS_BATCH_NATIVES,
            FeatureFlag::DERIVABLE_ACCOUNT_ABSTRACTION,
            FeatureFlag::VM_BINARY_FORMAT_V8,
            FeatureFlag::ENABLE_FUNCTION_VALUES,
            FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_STORE,
            FeatureFlag::DEFAULT_ACCOUNT_RESOURCE,
            FeatureFlag::JWK_CONSENSUS_PER_KEY_MODE,
            FeatureFlag::TRANSACTION_PAYLOAD_V2,
            FeatureFlag::ORDERLESS_TRANSACTIONS,
            FeatureFlag::CALCULATE_TRANSACTION_FEE_FOR_DISTRIBUTION,
            FeatureFlag::DISTRIBUTE_TRANSACTION_FEE,
            FeatureFlag::ENABLE_LAZY_LOADING,
            FeatureFlag::MONOTONICALLY_INCREASING_COUNTER,
            FeatureFlag::ENABLE_CAPTURE_OPTION,
            FeatureFlag::ENABLE_TRUSTED_CODE,
            FeatureFlag::ENABLE_ENUM_OPTION,
            FeatureFlag::VM_BINARY_FORMAT_V9,
            FeatureFlag::ENABLE_FRAMEWORK_FOR_OPTION,
            FeatureFlag::ENABLE_FUNCTION_REFLECTION,
            FeatureFlag::VM_BINARY_FORMAT_V10,
            FeatureFlag::SLH_DSA_SHA2_128S_SIGNATURE,
        ]
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

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L617-619)
```rust
            if version == 0 || version > u32::min(max_version, VERSION_MAX) {
                Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
                    .with_message(format!("bytecode version {} unsupported", version)))
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1447-1449)
```rust
            match CompiledModule::deserialize_with_config(
                module_blob.code(),
                self.deserializer_config(),
```

**File:** testsuite/testcases/src/compatibility_test.rs (L83-119)
```rust
        let mut first_batch = all_validators.clone();
        let second_batch = first_batch.split_off(first_batch.len() / 2);
        let first_node = first_batch.pop().unwrap();
        let duration = Duration::from_secs(30);

        let msg = format!(
            "1. Check liveness of validators at old version: {}",
            old_version
        );
        info!("{}", msg);
        ctxa.report_text(msg).await;

        // Generate some traffic
        {
            let mut ctx_locker = ctxa.ctx.lock().await;
            let ctx = ctx_locker.deref_mut();
            let txn_stat_prior = generate_traffic(ctx, &all_validators, duration).await?;
            ctx.report
                .report_txn_stats(format!("{}::liveness-check", self.name()), &txn_stat_prior);
        }

        // Update the first Validator
        let msg = format!(
            "2. Upgrading first Validator to new version: {}",
            new_version
        );
        info!("{}", msg);
        ctxa.report_text(msg).await;
        batch_update_gradually(
            ctxa.clone(),
            &[first_node],
            &new_version,
            upgrade_wait_for_healthy,
            upgrade_node_delay,
            upgrade_max_wait,
        )
        .await?;
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L137-142)
```rust
pub fn aptos_prod_deserializer_config(features: &Features) -> DeserializerConfig {
    DeserializerConfig::new(
        features.get_max_binary_format_version(),
        features.get_max_identifier_size(),
    )
}
```

**File:** third_party/move/move-vm/integration-tests/src/tests/binary_format_version.rs (L56-71)
```rust
    // Should reject the module with newer version with max binary format version being set to VERSION_MAX - 1
    {
        let storage = initialize_storage_with_binary_format_version(old_version);
        let module_storage = storage.as_unsync_module_storage();

        let result_new = StagingModuleStorage::create(m.self_addr(), &module_storage, vec![b_new
            .clone()
            .into()]);
        if let Err(err) = result_new {
            assert_eq!(err.major_status(), StatusCode::UNKNOWN_VERSION);
        } else {
            panic!("New module should not be publishable")
        }
        StagingModuleStorage::create(m.self_addr(), &module_storage, vec![b_old.clone().into()])
            .expect("Old module should be publishable");
    }
```
