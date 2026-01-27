# Audit Report

## Title
Bytecode Version Downgrade Can Permanently Break Existing Modules Through Governance

## Summary
The Move IR compiler uses a hardcoded `VERSION_DEFAULT` when compiling modules, while runtime module loading validates against a dynamic `max_binary_format_version` controlled by on-chain governance. A governance-initiated bytecode version downgrade can make all existing higher-version modules permanently unloadable, causing denial of service and potential fund lock.

## Finding Description

The compilation and runtime loading processes are decoupled in their version handling, creating a backward compatibility gap:

**At Compilation Time:** [1](#0-0) 

Modules are compiled with `VERSION_DEFAULT` (currently VERSION_9), which is hardcoded.

**At Runtime Loading:** [2](#0-1) 

Modules loaded from storage are validated against the current `max_binary_format_version` from the on-chain Features config.

**Version Validation Logic:** [3](#0-2) 

If a module's embedded version exceeds the current `max_version`, deserialization fails with `UNKNOWN_VERSION` error.

**Governance Control:** [4](#0-3) 

The `max_binary_format_version` is determined by which `VM_BINARY_FORMAT_V*` feature flags are enabled. Governance can disable these flags: [5](#0-4) 

**No Safeguards:** [6](#0-5) 

The `apply_diff` function allows disabling any feature flag without validation. Unlike some critical features marked with `EFEATURE_CANNOT_BE_DISABLED`, bytecode version flags have no such protection: [7](#0-6) [8](#0-7) [9](#0-8) 

**Attack Scenario:**
1. Modules are published when `VM_BINARY_FORMAT_V9` is enabled (bytecode version 9 stored in state)
2. A governance proposal disables `VM_BINARY_FORMAT_V9` and `VM_BINARY_FORMAT_V10`, keeping only V8 enabled
3. `get_max_binary_format_version()` now returns VERSION_8
4. All existing version 9 modules fail deserialization when loaded: `9 > 8` triggers `UNKNOWN_VERSION`
5. Any transaction attempting to use these modules fails
6. If modules manage assets (fungible assets, NFTs, stake pools), funds become inaccessible until the feature is re-enabled

This breaks the **State Consistency** invariant: blockchain state contains valid modules that become invalid due to runtime configuration changes.

## Impact Explanation

**Medium Severity** - This qualifies as "State inconsistencies requiring intervention":
- Existing valid modules in blockchain state become unloadable
- Denial of service on affected modules and their dependent contracts
- Potential temporary fund lock if asset-managing modules are affected
- Requires governance intervention (re-enabling the feature flag) to restore access
- Does not result in permanent fund loss or consensus violations as the state itself is not corrupted

While the impact can be severe (e.g., if the Aptos Framework modules were affected), it's recoverable through governance re-enabling the feature flag, preventing classification as Critical.

## Likelihood Explanation

**Medium Likelihood** - While this requires governance action, it's plausible:
- Governance participants are trusted but can make mistakes during protocol upgrades
- No warnings or checks prevent accidentally downgrading bytecode versions
- The comment on V6 shows awareness of backward compatibility concerns, but no enforcement mechanism exists: [10](#0-9) 
- A well-intentioned proposal to "clean up old feature flags" or "optimize version checking" could inadvertently disable intermediate versions

## Recommendation

Implement safeguards to prevent bytecode version downgrades:

1. **Mark bytecode version flags as non-disableable** once enabled in production (similar to `EFEATURE_CANNOT_BE_DISABLED`)
2. **Add validation in `apply_diff`** to prevent disabling bytecode version features if higher versions are still enabled
3. **Enforce monotonic version enabling** - if V9 is enabled, V6-V8 must remain enabled
4. **Add pre-upgrade validation** that scans existing modules and warns if any would become incompatible

Example fix for features.move:
```move
fun apply_diff(features: &mut vector<u8>, enable: vector<u64>, disable: vector<u64>) {
    // Validate no bytecode version downgrades
    disable.for_each_ref(|feature| {
        assert!(
            !is_bytecode_version_feature(*feature) || can_disable_bytecode_version(*feature, features),
            error::invalid_argument(EFEATURE_CANNOT_BE_DISABLED)
        );
    });
    // ... rest of implementation
}
```

## Proof of Concept

This vulnerability exists in the design but requires governance privileges to exploit, making a complete PoC dependent on governance access. However, the issue can be demonstrated through the following trace:

1. **Module compilation** with V9: `do_compile_module()` → `compile_module()` → `VERSION_DEFAULT` (V9)
2. **Module publishing** validates against current config (V9 enabled, check passes)
3. **Governance disables V9**: `toggle_features()` → `change_feature_flags_for_next_epoch()` → disables `VM_BINARY_FORMAT_V9`
4. **Module loading fails**: `deserialize_into_compiled_module()` → `VersionedBinary::new()` → `version (9) > max_version (8)` → `UNKNOWN_VERSION` error

The vulnerability is architectural: the system lacks safeguards against governance-initiated backward-incompatible changes, violating the principle that on-chain state should remain valid regardless of configuration changes.

## Notes

While this vulnerability requires governance action (privileged operation), it represents a **protocol design flaw** where the system fails to protect against backwards-incompatible changes. The compilation process hardcodes bytecode versions but runtime enforcement is dynamic, creating a mismatch that can break existing modules. Unlike other critical features that are explicitly marked as non-disableable once enabled on mainnet, bytecode version features lack this protection despite having similar backward compatibility requirements.

### Citations

**File:** third_party/move/move-ir-compiler/move-ir-to-bytecode/src/compiler.rs (L474-474)
```rust
        version: VERSION_DEFAULT,
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

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L617-619)
```rust
            if version == 0 || version > u32::min(max_version, VERSION_MAX) {
                Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
                    .with_message(format!("bytecode version {} unsupported", version)))
```

**File:** types/src/on_chain_config/aptos_features.rs (L135-135)
```rust
    VM_BINARY_FORMAT_V8 = 86,
```

**File:** types/src/on_chain_config/aptos_features.rs (L157-157)
```rust
    VM_BINARY_FORMAT_V9 = 102,
```

**File:** types/src/on_chain_config/aptos_features.rs (L165-165)
```rust
    VM_BINARY_FORMAT_V10 = 106,
```

**File:** types/src/on_chain_config/aptos_features.rs (L177-179)
```rust
            // Feature flag V6 is used to enable metadata v1 format and needs to stay on, even
            // if we enable a higher version.
            FeatureFlag::VM_BINARY_FORMAT_V6,
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

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L714-718)
```text
    public fun toggle_features(aptos_framework: &signer, enable: vector<u64>, disable: vector<u64>) {
        system_addresses::assert_aptos_framework(aptos_framework);
        features::change_feature_flags_for_next_epoch(aptos_framework, enable, disable);
        reconfigure(aptos_framework);
    }
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
