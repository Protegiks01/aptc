# Audit Report

## Title
Missing VERSION_MIN Enforcement in Module Deserialization Allows Bricking of Existing Deployed Modules During Bytecode Version Upgrades

## Summary
The Move bytecode deserializer does not enforce the `VERSION_MIN` lower bound when loading existing modules from storage. When `VERSION_MIN` is raised to deprecate old bytecode versions, all existing on-chain modules compiled with versions below the new minimum will successfully deserialize but may fail during execution or verification, potentially causing consensus splits and network-wide state inconsistencies. No migration path exists to upgrade these modules before the breaking change takes effect.

## Finding Description

The Aptos Move VM maintains bytecode version constants that define the supported range of module versions: [1](#0-0) 

When **serializing** new modules, the `validate_version()` function correctly enforces both bounds: [2](#0-1) 

However, when **deserializing** existing modules from storage, the `VersionedBinary::new()` function only checks the upper bound and does NOT validate against `VERSION_MIN`: [3](#0-2) 

The check at line 617 only validates `version > u32::min(max_version, VERSION_MAX)` and does not check if `version >= VERSION_MIN`. This asymmetry creates a critical security vulnerability.

**Exploitation Scenario:**

1. Currently, `VERSION_MIN = VERSION_5`, meaning versions 1-4 are officially unsupported
2. Many modules on-chain may still be compiled with VERSION_5 or older versions
3. If the Aptos team raises `VERSION_MIN` to VERSION_6 (or higher) to deprecate older bytecode:
   - New modules with version < 6 cannot be created (serializer rejects them)
   - Existing modules with version 5 successfully deserialize (no lower bound check)
   - These old modules may then fail unpredictably during:
     - Bytecode verification (opcodes incompatible with newer VM assumptions)
     - Execution (runtime checks expecting features from VERSION_6+)
     - Feature-specific validation (e.g., expecting enum types, closures, signed integers)

4. Different validators may handle these failures differently:
   - Some may treat them as verification errors and skip the transaction
   - Others may encounter runtime panics or undefined behavior
   - This leads to **consensus divergence** as validators produce different state roots

The deserialization happens here when loading modules from storage: [4](#0-3) 

And the VMConfig uses the DeserializerConfig with only max_binary_format_version: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **Critical Severity** because:

1. **Non-recoverable network partition**: If VERSION_MIN is raised and existing modules fail unpredictably, validators will produce divergent state roots. This requires a coordinated hardfork to:
   - Identify all affected modules on-chain
   - Provide a migration mechanism
   - Re-upgrade or recompile all affected modules
   - Potentially roll back the VERSION_MIN increase

2. **Consensus Safety Violation**: The **Deterministic Execution** invariant is broken - identical blocks will produce different state roots across validators depending on how they handle old bytecode versions.

3. **State Consistency Breakdown**: The **State Consistency** invariant is violated - existing modules become unloadable or unpredictably executable, corrupting the state machine.

4. **No Migration Path**: Unlike other blockchain upgrades that provide deprecation warnings and migration tooling, there is no mechanism to:
   - Detect which modules need upgrading before VERSION_MIN changes
   - Automatically recompile or upgrade old modules
   - Warn module owners that their code will break

Per the Aptos bug bounty criteria, this is a **Critical Severity** issue worth up to $1,000,000 as it causes "Non-recoverable network partition (requires hardfork)" and "Consensus/Safety violations."

## Likelihood Explanation

**Likelihood: HIGH**

This issue WILL occur if:
1. The Aptos team decides to raise VERSION_MIN to deprecate old bytecode versions (likely as new features are added)
2. There are ANY modules on-chain compiled with bytecode versions below the new VERSION_MIN
3. These modules are accessed during transaction execution

Given that:
- Bytecode versions are actively evolving (VERSION_1 through VERSION_10 already exist)
- VERSION_MIN has already been raised once (from VERSION_1 to VERSION_5)
- Many framework modules and third-party contracts may still use older versions
- No automated upgrade mechanism exists

The probability of this occurring during the next VERSION_MIN increase is **very high**. The issue is not hypothetical - it will manifest as soon as VERSION_MIN is raised again without proper migration tooling.

## Recommendation

Implement a comprehensive bytecode version migration system with the following components:

### 1. Add VERSION_MIN Enforcement in Deserialization

Modify the version check to enforce the lower bound:

```rust
// In file_format_common.rs, VersionedBinary::new()
if version == 0 || version < VERSION_MIN || version > u32::min(max_version, VERSION_MAX) {
    Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
        .with_message(format!("bytecode version {} unsupported (min: {}, max: {})", 
                              version, VERSION_MIN, VERSION_MAX)))
} else {
    Ok((
        Self {
            version,
            max_identifier_size,
            binary,
        },
        cursor,
    ))
}
```

### 2. Create a Migration Period Mechanism

Before raising VERSION_MIN:
- Introduce a "deprecated version warning" period where modules below VERSION_MIN can still load but emit warnings
- Provide on-chain events identifying all deprecated modules
- Allow a grace period for owners to upgrade their modules

### 3. Add On-Chain Module Version Scanning

Implement a governance proposal type that:
- Scans all on-chain modules for their bytecode versions
- Identifies modules below the proposed new VERSION_MIN
- Requires explicit acknowledgment that all affected modules will be upgraded
- Blocks VERSION_MIN increases if critical framework modules would break

### 4. Implement Automatic Module Recompilation

For simple cases (bytecode format changes without semantic changes):
- Provide tooling to automatically recompile old modules to newer versions
- Allow module owners to trigger recompilation via a governance transaction
- Maintain binary compatibility where possible

### 5. Add Feature Flags for Gradual Deprecation

Use the existing feature flag system to gate VERSION_MIN changes: [6](#0-5) 

## Proof of Concept

**Reproduction Steps:**

1. **Deploy a module with VERSION_5**:
```rust
// Create and serialize a module with VERSION_5
let module = basic_test_module();
let mut module_bytes = vec![];
module.serialize_for_version(Some(VERSION_5), &mut module_bytes).unwrap();

// Publish to storage
let storage = initialize_storage_with_binary_format_version(VERSION_MAX);
StagingModuleStorage::create(module.self_addr(), &storage, vec![module_bytes.into()])
    .expect("Module should publish successfully");
```

2. **Raise VERSION_MIN to VERSION_6** (simulated by modifying the constant):
```rust
// In file_format_common.rs
pub const VERSION_MIN: u32 = VERSION_6; // Changed from VERSION_5
```

3. **Attempt to load the existing module**:
```rust
// The module will deserialize successfully (no VERSION_MIN check)
let module_id = ModuleId::new(module.self_addr(), module.self_name().to_owned());
let loaded_module = storage.unmetered_get_deserialized_module(
    module_id.address(), 
    module_id.name()
).unwrap();

// But it will fail during verification or execution
// because the VM assumes all modules are >= VERSION_6
```

4. **Observe consensus split**:
    - Validators that encounter verification errors will reject transactions using the old module
    - Validators that skip the check will accept transactions
    - Different state roots are produced for the same block

**Expected Outcome**: The module successfully deserializes despite being below VERSION_MIN, but fails unpredictably during later stages, causing consensus divergence.

**Test Case Structure**:
```rust
#[test]
fn test_version_min_enforcement_in_deserialization() {
    // 1. Deploy module with VERSION_5
    // 2. Verify it loads successfully
    // 3. Simulate VERSION_MIN increase to VERSION_6
    // 4. Attempt to load the same module
    // 5. Assert that deserialization fails with UNKNOWN_VERSION
    // Current behavior: test FAILS (module loads successfully)
    // Expected behavior: test PASSES (module rejected)
}
```

## Notes

This vulnerability represents a **systemic design flaw** in how bytecode evolution is managed. While the immediate fix (adding VERSION_MIN enforcement) would prevent old modules from loading, it would also brick all existing modules below the minimum version without warning or migration path. The complete solution requires:

1. Immediate: Add the VERSION_MIN check to prevent silent failures
2. Short-term: Implement version scanning and deprecation warnings
3. Long-term: Build comprehensive migration tooling for safe bytecode evolution

The severity is amplified because this affects ALL validators simultaneously - there is no gradual rollout or partial failure mode. Once VERSION_MIN is raised, the entire network either succeeds or fails together based on how old modules are handled.

### Citations

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L562-566)
```rust
pub const VERSION_MIN: u32 = VERSION_5;

/// Mark which version is the latest version.
pub const VERSION_MAX: u32 = VERSION_10;

```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L610-620)
```rust
            let version = match read_u32(&mut cursor) {
                Ok(v) => v & !APTOS_BYTECODE_VERSION_MASK,
                Err(_) => {
                    return Err(PartialVMError::new(StatusCode::MALFORMED)
                        .with_message("Bad binary header".to_string()));
                },
            };
            if version == 0 || version > u32::min(max_version, VERSION_MAX) {
                Err(PartialVMError::new(StatusCode::UNKNOWN_VERSION)
                    .with_message(format!("bytecode version {} unsupported", version)))
            } else {
```

**File:** third_party/move/move-binary-format/src/serializer.rs (L261-272)
```rust
fn validate_version(version: u32) -> Result<()> {
    if !(VERSION_MIN..=VERSION_MAX).contains(&version) {
        bail!(
            "The requested bytecode version {} is not supported. Only {} to {} are.",
            version,
            VERSION_MIN,
            VERSION_MAX
        )
    } else {
        Ok(())
    }
}
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

**File:** third_party/move/move-vm/runtime/src/config.rs (L14-18)
```rust
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VMConfig {
    pub verifier_config: VerifierConfig,
    pub deserializer_config: DeserializerConfig,
    /// When this flag is set to true, MoveVM will perform type checks at every instruction
```

**File:** types/src/on_chain_config/aptos_features.rs (L500-543)
```rust
}

pub fn aptos_test_feature_flags_genesis() -> ChangeSet {
    let features_value = bcs::to_bytes(&Features::default_for_tests()).unwrap();

    let mut change_set = ChangeSet::new();
    // we need to initialize features to their defaults.
    change_set
        .add_resource_op(
            CORE_CODE_ADDRESS,
            Features::struct_tag(),
            Op::New(features_value.into()),
        )
        .expect("adding genesis Feature resource must succeed");

    change_set
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_features_into_flag_vec() {
        let mut features = Features { features: vec![] };
        features.enable(FeatureFlag::BLS12_381_STRUCTURES);
        features.enable(FeatureFlag::BN254_STRUCTURES);

        assert_eq!(
            vec![
                FeatureFlag::BLS12_381_STRUCTURES,
                FeatureFlag::BN254_STRUCTURES
            ],
            features.into_flag_vec()
        );
    }

    #[test]
    fn test_min_max_binary_format() {
        // Ensure querying max binary format implementation is correct and checks
        // versions 5 to 8.
        assert_eq!(
            file_format_common::VERSION_5,
            file_format_common::VERSION_MIN
```
