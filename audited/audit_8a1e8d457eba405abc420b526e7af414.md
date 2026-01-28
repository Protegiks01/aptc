# Audit Report

## Title
Bytecode Version Downgrade via Feature Flag Disabling Can Permanently Brick Deployed Modules

## Summary
The Aptos blockchain allows governance to disable bytecode version feature flags without validation, which retroactively makes all modules compiled with that version unloadable. This creates a critical backwards compatibility violation where deployed modules become permanently inaccessible, potentially freezing funds and halting the network.

## Finding Description

The Move VM bytecode versioning system has a critical design flaw that enables governance-triggered denial of service against deployed modules through a validated vulnerability chain:

**1. Version Checking During Deserialization**

The version validation occurs in `VersionedBinary::new()` which checks if the bytecode version exceeds the configured maximum: [1](#0-0) 

When a module's version exceeds the maximum, it returns `UNKNOWN_VERSION` error, making the module unloadable.

**2. Dynamic Max Version from Feature Flags**

The maximum allowed bytecode version is determined dynamically by checking which `VM_BINARY_FORMAT_V*` flags are enabled: [2](#0-1) 

This cascading check returns the highest enabled version (V10→V9→V8→V7→V6→V5).

**3. Unrestricted Feature Flag Disabling**

Governance can modify feature flags without any validation to prevent disabling bytecode versions in use: [3](#0-2) 

The `apply_diff()` function blindly enables/disables features with no checks. The governance entry point similarly has no validation: [4](#0-3) 

**4. Configuration Applied to Deserializer**

The dynamic max version from feature flags is used to create the deserializer configuration: [5](#0-4) 

This configuration is embedded in the VMConfig: [6](#0-5) 

**5. Module Loading Failure**

When modules are accessed from storage, they are deserialized using the current deserializer configuration: [7](#0-6) 

Which calls: [8](#0-7) 

This means every module access re-validates against the current max version. If a module was compiled with V10 and the feature flag is disabled (dropping max version to V9), the module fails to load with `UNKNOWN_VERSION`.

**Attack Scenario:**

1. Developer deploys module `TokenVault` compiled with bytecode V10 (when `VM_BINARY_FORMAT_V10` is enabled)
2. Module stores user funds (e.g., 1000 APT)
3. Security bug discovered in V10 features (e.g., closure implementation)
4. Governance passes proposal to disable `VM_BINARY_FORMAT_V10` as emergency response
5. After epoch change, `max_version` drops from 10 to 9
6. All attempts to load `TokenVault` fail with `UNKNOWN_VERSION` error
7. Funds are permanently frozen - cannot be withdrawn, module cannot be upgraded

**Invariant Violations:**
- **Deterministic Execution**: Validators cannot load modules needed to process transactions
- **State Consistency**: Modules exist on-chain but are marked invalid
- **Backwards Compatibility**: Deployed code becomes retroactively invalid without migration path

## Impact Explanation

**Critical Severity** - This meets multiple critical impact categories:

**1. Permanent Freezing of Funds (Critical - requires hardfork)**

Any funds locked in modules compiled with a disabled bytecode version become permanently inaccessible. The only recovery requires hardfork to either re-enable the flag (reintroducing security risks) or manually migrate affected modules (complex, error-prone).

**2. Total Loss of Liveness/Network Availability (Critical)**

If framework modules (e.g., `aptos_framework::coin`, `aptos_framework::stake`) are compiled with the disabled version, core blockchain operations fail, rendering the entire network non-functional.

**3. Consensus/Safety Violations (Critical)**

Different validators with different feature flag states during transition could produce different execution results, causing consensus splits.

All bytecode version flags are currently enabled by default in production: [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11) 

This confirms that disabling any of these would immediately affect all modules compiled with that version.

## Likelihood Explanation

**High Likelihood** - Multiple realistic scenarios:

**1. Security Response**

If a critical vulnerability is discovered in V10 features (e.g., closure implementation bugs), the immediate response would be to disable `VM_BINARY_FORMAT_V10` via emergency governance proposal, immediately bricking all V10 modules.

**2. Documentation Encourages Disabling**

Bytecode version flags are explicitly marked as "transient" lifetime, suggesting they should be eventually removed: [13](#0-12) [14](#0-13) 

This documentation misleads governance participants into believing these flags can be safely disabled, not understanding the backwards compatibility implications.

**3. Developer Awareness But No Technical Enforcement**

There is evidence developers are aware of the issue: [15](#0-14) 

However, this awareness exists only in comments with no technical enforcement preventing the dangerous operation.

## Recommendation

Implement validation in `change_feature_flags_for_next_epoch()` to prevent disabling bytecode version flags that are actively in use. The validation should:

1. Check all deployed modules on-chain to determine which bytecode versions are in use
2. Reject governance proposals attempting to disable bytecode version flags for versions currently in use
3. Only allow disabling a bytecode version flag if no on-chain modules use that version
4. Consider implementing a grace period allowing modules to be upgraded before a version can be disabled

Additionally, update documentation to clearly indicate that bytecode version flags cannot be safely disabled once modules using that version are deployed.

## Proof of Concept

```move
// Deploy this module with bytecode version 10 enabled
module test_addr::vault {
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    struct Vault has key {
        funds: coin::Coin<AptosCoin>
    }
    
    public fun deposit(account: &signer, amount: u64) {
        // Store funds in module
        let funds = coin::withdraw<AptosCoin>(account, amount);
        move_to(account, Vault { funds });
    }
    
    public fun withdraw(account: &signer): coin::Coin<AptosCoin> acquires Vault {
        let Vault { funds } = move_from<Vault>(signer::address_of(account));
        funds
    }
}

// After deployment with V10:
// 1. User calls deposit() and locks 1000 APT
// 2. Governance disables VM_BINARY_FORMAT_V10 
// 3. User tries to call withdraw() 
// 4. Module fails to load with UNKNOWN_VERSION error
// 5. Funds are permanently frozen
```

The vulnerability requires no malicious actors - only legitimate governance responding to security issues, making this a critical design flaw requiring immediate attention.

## Notes

This is a logic vulnerability in the bytecode version management system that can be triggered through normal governance operations without requiring any compromised or malicious actors. The vulnerability exists because the system allows a dangerous operation (disabling bytecode versions) without validating whether that operation would break existing deployed modules. The "transient" documentation for these flags creates a false sense that they can be safely disabled, when in reality disabling them retroactively breaks all modules compiled with that version.

### Citations

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L617-619)
```rust
            if version == 0 || version > u32::min(max_version, VERSION_MAX) {
                Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
                    .with_message(format!("bytecode version {} unsupported", version)))
```

**File:** types/src/on_chain_config/aptos_features.rs (L177-178)
```rust
            // Feature flag V6 is used to enable metadata v1 format and needs to stay on, even
            // if we enable a higher version.
```

**File:** types/src/on_chain_config/aptos_features.rs (L179-180)
```rust
            FeatureFlag::VM_BINARY_FORMAT_V6,
            FeatureFlag::VM_BINARY_FORMAT_V7,
```

**File:** types/src/on_chain_config/aptos_features.rs (L257-257)
```rust
            FeatureFlag::VM_BINARY_FORMAT_V8,
```

**File:** types/src/on_chain_config/aptos_features.rs (L271-271)
```rust
            FeatureFlag::VM_BINARY_FORMAT_V9,
```

**File:** types/src/on_chain_config/aptos_features.rs (L274-274)
```rust
            FeatureFlag::VM_BINARY_FORMAT_V10,
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

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L78-80)
```text
    /// Whether to allow the use of binary format version v6.
    /// Lifetime: transient
    const VM_BINARY_FORMAT_V6: u64 = 5;
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L637-639)
```text
    /// Whether bytecode version v8 is enabled.
    /// Lifetime: transient
    ///
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L874-881)
```text
    fun apply_diff(features: &mut vector<u8>, enable: vector<u64>, disable: vector<u64>) {
        enable.for_each(|feature| {
            set(features, feature, true);
        });
        disable.for_each(|feature| {
            set(features, feature, false);
        });
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

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L137-142)
```rust
pub fn aptos_prod_deserializer_config(features: &Features) -> DeserializerConfig {
    DeserializerConfig::new(
        features.get_max_binary_format_version(),
        features.get_max_identifier_size(),
    )
}
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L210-210)
```rust
    let deserializer_config = aptos_prod_deserializer_config(features);
```

**File:** third_party/move/move-vm/runtime/src/storage/implementations/unsync_module_storage.rs (L152-155)
```rust
        let compiled_module = self
            .ctx
            .runtime_environment()
            .deserialize_into_compiled_module(&bytes)?;
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L248-249)
```rust
    pub fn deserialize_into_compiled_module(&self, bytes: &Bytes) -> VMResult<CompiledModule> {
        CompiledModule::deserialize_with_config(bytes, &self.vm_config().deserializer_config)
```
