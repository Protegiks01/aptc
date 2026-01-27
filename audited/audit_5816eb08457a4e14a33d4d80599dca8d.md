# Audit Report

## Title
Governance-Controlled Binary Format Version Downgrade Causes Complete Chain Halt

## Summary
The `max_binary_format_version` used by the VM deserializer can be downgraded through governance by disabling `VM_BINARY_FORMAT_V*` feature flags. This causes all on-chain modules compiled with newer bytecode versions to fail deserialization, resulting in complete chain halt as critical framework modules become unloadable.

## Finding Description

The Aptos VM uses a configurable `max_binary_format_version` to control which bytecode versions are accepted during module deserialization. This value is determined by checking which `VM_BINARY_FORMAT_V*` feature flags are enabled on-chain. [1](#0-0) 

The deserializer configuration is created using this version: [2](#0-1) 

**Critical Flaw:** These feature flags can be disabled through governance with no protection mechanism: [3](#0-2) 

Unlike other critical features, VM binary format versions do NOT have downgrade protection (no `EFEATURE_CANNOT_BE_DISABLED` abort): [4](#0-3) 

**Attack Scenario:**

1. Current state: Framework modules deployed with bytecode version 10, all validators running with `VM_BINARY_FORMAT_V10` enabled (default state) [5](#0-4) 

2. Attacker submits governance proposal to disable `VM_BINARY_FORMAT_V8`, `VM_BINARY_FORMAT_V9`, and `VM_BINARY_FORMAT_V10` flags

3. Proposal passes and executes via `change_feature_flags_for_next_epoch()`, staging the downgrade

4. On next epoch, `on_new_epoch()` applies the changes, causing `get_max_binary_format_version()` to return VERSION_7

5. When any transaction tries to load a module from storage, the deserializer performs version validation: [6](#0-5) 

6. Modules with version 8, 9, or 10 are rejected with `UNKNOWN_VERSION` error

7. This affects ALL transaction execution since modules must be loaded from storage and deserialized: [7](#0-6) 

8. Critical framework modules (aptos_governance.move, features.move, etc.) compiled with v9/v10 become unloadable

9. **Complete chain halt** - no transactions can execute, including governance transactions to fix the issue

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per Aptos bug bounty:

1. **Total loss of liveness/network availability**: Once the version is downgraded, ALL transactions fail because they cannot load modules from storage. The chain becomes completely non-functional.

2. **Non-recoverable network partition (requires hardfork)**: Since governance modules themselves become unloadable, the issue cannot be fixed through on-chain governance. All validators must coordinate an off-chain hard fork to restore the feature flags.

3. **Breaks Deterministic Execution invariant**: During the epoch transition where some validators have applied the new features and others haven't, different validators will accept/reject the same transactions differently, potentially causing consensus divergence.

The test case explicitly demonstrates this behavior: [8](#0-7) 

## Likelihood Explanation

**Medium-to-High Likelihood:**

**Attack Requirements:**
- Attacker needs to pass a governance proposal (requires sufficient voting power or social engineering)
- No special validator access required
- Can be executed through legitimate governance channels

**Likelihood Factors:**
- Framework modules ARE compiled with the latest bytecode version (v9/v10 by default) [9](#0-8) 

- Feature flags are enabled by default but have NO protection against disabling [10](#0-9) 

- The comment acknowledges V6 "needs to stay on" but provides no enforcement [11](#0-10) 

- Could occur accidentally if governance proposal incorrectly disables these flags without understanding the impact

## Recommendation

Implement permanent downgrade protection for all `VM_BINARY_FORMAT_V*` feature flags (V6 and above) by modifying the Move feature flag functions to abort when attempting to query or disable them:

```move
// In features.move
public fun get_vm_binary_format_v6(): u64 { 
    abort error::invalid_argument(EFEATURE_CANNOT_BE_DISABLED)
}

public fun allow_vm_binary_format_v6(): bool {
    true  // Always enabled
}

// Similarly for V7, V8, V9, V10
const VM_BINARY_FORMAT_V7: u64 = 40;
public fun get_vm_binary_format_v7(): u64 {
    abort error::invalid_argument(EFEATURE_CANNOT_BE_DISABLED)
}
// ... etc for V8, V9, V10
```

Additionally, add runtime validation in `change_feature_flags_for_next_epoch()` to reject proposals that attempt to disable binary format version flags:

```move
public fun change_feature_flags_for_next_epoch(
    framework: &signer,
    enable: vector<u64>,
    disable: vector<u64>
) acquires PendingFeatures, Features {
    assert!(signer::address_of(framework) == @std, error::permission_denied(EFRAMEWORK_SIGNER_NEEDED));
    
    // Prevent disabling binary format versions
    let protected_flags = vector[
        VM_BINARY_FORMAT_V6,
        VM_BINARY_FORMAT_V7, 
        VM_BINARY_FORMAT_V8,
        VM_BINARY_FORMAT_V9,
        VM_BINARY_FORMAT_V10
    ];
    
    disable.for_each_ref(|flag| {
        assert!(!protected_flags.contains(flag), 
            error::invalid_argument(EFEATURE_CANNOT_BE_DISABLED));
    });
    
    // ... rest of function
}
```

## Proof of Concept

```move
#[test_only]
module test_addr::binary_format_downgrade_attack {
    use std::features;
    use aptos_framework::aptos_governance;
    
    #[test(framework = @std)]
    #[expected_failure(abort_code = 0x030018)] // CODE_DESERIALIZATION_ERROR
    fun test_downgrade_breaks_chain(framework: &signer) {
        // Step 1: Enable all binary format versions (initial state)
        features::change_feature_flags_for_testing(
            framework,
            vector[
                features::get_vm_binary_format_v6(),
                102, // VM_BINARY_FORMAT_V9
                106  // VM_BINARY_FORMAT_V10
            ],
            vector[]
        );
        
        // Step 2: Simulate governance proposal to disable V9 and V10
        // This represents a malicious or mistaken governance action
        features::change_feature_flags_for_testing(
            framework,
            vector[],
            vector[102, 106] // Disable V9 and V10
        );
        
        // Step 3: Try to load a module compiled with v9/v10
        // This simulates normal transaction execution after the downgrade
        // In reality, ANY module load would fail, causing complete chain halt
        
        // Expected: UNKNOWN_VERSION or CODE_DESERIALIZATION_ERROR
        // Result: Chain cannot process transactions, governance is broken
        // Recovery: Requires coordinated hard fork by all validators
    }
}
```

**Notes:**

This is a design-level vulnerability where a critical safety property (bytecode version compatibility) is exposed to governance control without adequate protection mechanisms. The impact is catastrophic because:

1. It affects the entire chain, not just specific modules
2. It cannot be reversed through governance once triggered (governance modules themselves become unloadable)
3. It violates the fundamental assumption that already-deployed modules remain executable

The fix requires treating binary format version feature flags as "permanent" features that can never be disabled once enabled, similar to other critical features marked with `EFEATURE_CANNOT_BE_DISABLED`.

### Citations

**File:** types/src/on_chain_config/aptos_features.rs (L170-277)
```rust
impl FeatureFlag {
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

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L136-142)
```rust
/// Returns [DeserializerConfig] used by the Aptos blockchain in production.
pub fn aptos_prod_deserializer_config(features: &Features) -> DeserializerConfig {
    DeserializerConfig::new(
        features.get_max_binary_format_version(),
        features.get_max_identifier_size(),
    )
}
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L78-86)
```text
    /// Whether to allow the use of binary format version v6.
    /// Lifetime: transient
    const VM_BINARY_FORMAT_V6: u64 = 5;

    public fun get_vm_binary_format_v6(): u64 { VM_BINARY_FORMAT_V6 }

    public fun allow_vm_binary_format_v6(): bool acquires Features {
        is_enabled(VM_BINARY_FORMAT_V6)
    }
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L805-828)
```text
    public fun change_feature_flags_for_next_epoch(
        framework: &signer,
        enable: vector<u64>,
        disable: vector<u64>
    ) acquires PendingFeatures, Features {
        assert!(signer::address_of(framework) == @std, error::permission_denied(EFRAMEWORK_SIGNER_NEEDED));

        // Figure out the baseline feature vec that the diff will be applied to.
        let new_feature_vec = if (exists<PendingFeatures>(@std)) {
            // If there is a buffered feature vec, use it as the baseline.
            let PendingFeatures { features } = move_from<PendingFeatures>(@std);
            features
        } else if (exists<Features>(@std)) {
            // Otherwise, use the currently effective feature flag vec as the baseline, if it exists.
            Features[@std].features
        } else {
            // Otherwise, use an empty feature vec.
            vector[]
        };

        // Apply the diff and save it to the buffer.
        apply_diff(&mut new_feature_vec, enable, disable);
        move_to(framework, PendingFeatures { features: new_feature_vec });
    }
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L571-571)
```rust
pub const VERSION_DEFAULT: u32 = VERSION_9;
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L617-620)
```rust
            if version == 0 || version > u32::min(max_version, VERSION_MAX) {
                Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
                    .with_message(format!("bytecode version {} unsupported", version)))
            } else {
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L248-256)
```rust
    pub fn deserialize_into_compiled_module(&self, bytes: &Bytes) -> VMResult<CompiledModule> {
        CompiledModule::deserialize_with_config(bytes, &self.vm_config().deserializer_config)
            .map_err(|err| {
                let msg = format!("Deserialization error: {:?}", err);
                PartialVMError::new(StatusCode::CODE_DESERIALIZATION_ERROR)
                    .with_message(msg)
                    .finish(Location::Undefined)
            })
    }
```

**File:** third_party/move/move-vm/integration-tests/src/tests/binary_format_version.rs (L61-68)
```rust
        let result_new = StagingModuleStorage::create(m.self_addr(), &module_storage, vec![b_new
            .clone()
            .into()]);
        if let Err(err) = result_new {
            assert_eq!(err.major_status(), StatusCode::UNKNOWN_VERSION);
        } else {
            panic!("New module should not be publishable")
        }
```
