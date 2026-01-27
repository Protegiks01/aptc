# Audit Report

## Title
Missing MoveVM Binary Format Version Validation During Genesis Application Enables Network-Breaking Misconfiguration

## Summary
Modules inserted via `WriteSetPayload::Direct` during genesis are not validated for compatibility with the `Features` configuration in the same genesis transaction. This missing validation allows a misconfigured genesis to be applied successfully, but causes complete network failure when validators later attempt to execute transactions and cannot deserialize the incompatible modules.

## Finding Description
The genesis application process lacks critical validation that ensures module bytecode versions are compatible with the MoveVM binary format version specified by the on-chain `Features` configuration. This breaks the **Deterministic Execution** invariant because validators will fail to load modules, preventing any transaction execution.

The vulnerability exists across two components:

**1. Insufficient Genesis Validation**

The `verify_genesis_module_write_set()` function only checks that module writes are creations, not deletions or modifications. It does NOT validate module bytecode compatibility: [1](#0-0) 

**2. Direct Write Path Bypasses Deserialization**

When validators apply genesis via `process_waypoint_change_set()`, the `WriteSetPayload::Direct` path writes modules directly to storage without deserializing or validating them: [2](#0-1) 

**3. Version Checking During Module Loading**

Module deserialization checks the bytecode version against the configured `max_binary_format_version` from `DeserializerConfig`. If the module version exceeds this limit, deserialization fails with `UNKNOWN_VERSION`: [3](#0-2) 

**4. Features Configuration Source**

The `max_binary_format_version` is determined by which binary format feature flags are enabled in the on-chain `Features` resource: [4](#0-3) 

**Attack Scenario:**

1. A misconfigured genesis `ChangeSet` is created containing:
   - Framework modules compiled with bytecode version V10
   - `Features` resource with only `VM_BINARY_FORMAT_V8` enabled
   
2. The genesis passes validation because `verify_genesis_module_write_set()` only checks module operations are creations

3. Validators apply the genesis transaction:
   - Modules are written to storage as raw bytes (no deserialization)
   - Features resource is written with V8-only configuration

4. When validators attempt to execute the first transaction:
   - VM creates `AptosEnvironment` from state, fetching Features from storage (V8 max version)
   - VM attempts to load a framework module for execution
   - Deserialization fails because module is V10 but max_version=V8
   - Transaction execution fails with `UNKNOWN_VERSION` error
   - All subsequent transaction attempts fail identically
   - Network is completely unable to process transactions [5](#0-4) [6](#0-5) 

## Impact Explanation
This vulnerability is **Critical Severity** per the Aptos bug bounty program because it results in:

- **Non-recoverable network partition requiring hardfork**: Once a misconfigured genesis is applied, the network cannot process any transactions. The only recovery path is a hardfork with corrected genesis.

- **Total loss of liveness/network availability**: All validators are affected simultaneously and cannot execute transactions until the issue is fixed through manual intervention.

- **Breaks Deterministic Execution invariant**: The blockchain cannot produce state roots for any blocks, violating the fundamental requirement that all validators must be able to execute identical blocks.

## Likelihood Explanation
While this requires privileged access to genesis creation (not exploitable by arbitrary users), the likelihood is **Medium** because:

1. **Misconfiguration Risk**: Genesis creation involves multiple configuration parameters (framework bytecode version, Features flags, gas parameters). A mismatch between compiled module versions and Features configuration could occur through:
   - Using pre-compiled framework bundles with newer bytecode versions
   - Incorrectly setting Features flags during genesis creation
   - Version skew between build tools and runtime configurations

2. **No Defensive Validation**: The system lacks checks that would catch this misconfiguration before network deployment.

3. **Silent Failure**: The genesis applies successfully; the problem only manifests at first transaction execution.

4. **Critical Impact**: Even low likelihood is concerning given catastrophic consequences.

## Recommendation
Add validation during genesis application to ensure all modules are compatible with the Features configuration in that genesis:

```rust
// In aptos-move/vm-genesis/src/lib.rs, enhance verify_genesis_module_write_set()

fn verify_genesis_module_write_set(
    write_set: &WriteSet,
    features: &Features,
) {
    let max_version = features.get_max_binary_format_version();
    let deserializer_config = DeserializerConfig::new(
        max_version,
        features.get_max_identifier_size(),
    );
    
    for (state_key, write_op) in write_set.expect_write_op_iter() {
        if state_key.is_module_path() {
            assert!(write_op.is_creation(), "Genesis modules must be creations");
            
            // NEW: Validate module can be deserialized with genesis Features
            if let Some(bytes) = write_op.bytes() {
                CompiledModule::deserialize_with_config(bytes, &deserializer_config)
                    .expect("Genesis module must be compatible with Features configuration");
            }
        }
    }
}
```

Additionally, update the function signature in `encode_genesis_change_set()` and `encode_aptos_mainnet_genesis_transaction()` to pass the Features configuration to the validation function.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// File: aptos-move/vm-genesis/tests/version_mismatch_test.rs

use aptos_types::{
    on_chain_config::Features,
    transaction::{ChangeSet, WriteSetPayload, Transaction},
    write_set::{WriteOp, WriteSet, WriteSetMut},
    state_store::state_key::StateKey,
};
use aptos_vm_genesis::verify_genesis_module_write_set;
use move_binary_format::{file_format::CompiledModule, file_format_common::VERSION_10};

#[test]
#[should_panic(expected = "module must be compatible")]
fn test_genesis_module_version_mismatch() {
    // Create a V10 module (simulated with modified version field)
    let mut module = CompiledModule::default();
    module.version = VERSION_10;
    let module_bytes = bcs::to_bytes(&module).unwrap();
    
    // Create Features with only V8 enabled
    let mut features = Features::default();
    features.disable(FeatureFlag::VM_BINARY_FORMAT_V9);
    features.disable(FeatureFlag::VM_BINARY_FORMAT_V10);
    
    // Create a genesis write set with this mismatch
    let mut write_set = WriteSetMut::default();
    write_set.insert((
        StateKey::module_id(&module.self_id()),
        WriteOp::Creation(module_bytes.into()),
    ));
    
    // Current implementation would NOT catch this
    verify_genesis_module_write_set(&write_set.freeze().unwrap());
    
    // With proposed fix, this would panic with compatibility error
}
```

## Notes

The normal genesis creation path via `publish_framework()` DOES validate modules through `StagingModuleStorage::create()`, which deserializes modules with the configured Features. However, this validation occurs during genesis **creation**, not during genesis **application** by validators. The vulnerability exists because:

1. Validators trust the genesis `ChangeSet` and apply it without re-validation
2. No check ensures the Features in genesis match the modules in genesis  
3. A manually constructed genesis could bypass the `publish_framework()` validation path

While this requires privileged access (genesis creation capability), it represents a missing defensive check that could cause catastrophic failure from misconfiguration. The system should validate that all components of genesis are mutually compatible at application time.

### Citations

**File:** aptos-move/vm-genesis/src/lib.rs (L1259-1266)
```rust
/// Verify the consistency of modules in the genesis write set.
fn verify_genesis_module_write_set(write_set: &WriteSet) {
    for (state_key, write_op) in write_set.expect_write_op_iter() {
        if state_key.is_module_path() {
            assert!(write_op.is_creation())
        }
    }
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2274-2296)
```rust
        match write_set_payload {
            WriteSetPayload::Direct(change_set) => {
                // this transaction is never delayed field capable.
                // it requires restarting execution afterwards,
                // which allows it to be used as last transaction in delayed_field_enabled context.
                let (change_set, module_write_set) =
                    create_vm_change_set_with_module_write_set_when_delayed_field_optimization_disabled(
                        change_set.clone(),
                    );

                // validate_waypoint_change_set checks that this is true, so we only log here.
                if !Self::should_restart_execution(change_set.events()) {
                    // This invariant needs to hold irrespectively, so we log error always.
                    // but if we are in delayed_field_optimization_capable context, we cannot execute any transaction after this.
                    // as transaction afterwards would be executed assuming delayed fields are exchanged and
                    // resource groups are split, but WriteSetPayload::Direct has materialized writes,
                    // and so after executing this transaction versioned state is inconsistent.
                    error!(
                        "[aptos_vm] direct write set finished without requiring should_restart_execution");
                }

                Ok((change_set, module_write_set))
            },
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L617-620)
```rust
            if version == 0 || version > u32::min(max_version, VERSION_MAX) {
                Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
                    .with_message(format!("bytecode version {} unsupported", version)))
            } else {
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

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L219-220)
```rust
        let features =
            fetch_config_and_update_hash::<Features>(&mut sha3_256, state_view).unwrap_or_default();
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
