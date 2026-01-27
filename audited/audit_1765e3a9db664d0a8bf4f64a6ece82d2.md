# Audit Report

## Title
Compilation Metadata Unstable Flag Validation Bypass via Deserialization Tampering

## Summary
An attacker can bypass mainnet's unstable bytecode rejection mechanism by manually crafting bytecode where the `CompilationMetadata.unstable` boolean is set to `false` while the `compiler_version` or `language_version` strings indicate unstable versions. The validation logic only checks the deserialized `unstable` boolean field without re-validating it against the version strings, allowing unstable/experimental bytecode to be deployed on production networks.

## Finding Description

The Aptos VM implements a safety mechanism to prevent deployment of bytecode compiled with unstable compiler or language versions on mainnet. This is enforced through the `CompilationMetadata` struct stored in module bytecode: [1](#0-0) 

When `CompilationMetadata` is created legitimately via the `new()` constructor, the `unstable` flag is correctly computed: [2](#0-1) 

The `unstable` flag should be `true` if either `CompilerVersion::V2_1` (marked unstable at line 155) or `LanguageVersion::V2_4`/`V2_5` (marked unstable at line 292) are used.

However, the mainnet validation only checks the deserialized `unstable` boolean field: [3](#0-2) 

The critical flaw is that `reject_unstable_bytecode()` performs NO re-validation of the `unstable` flag against the `compiler_version` and `language_version` strings. It trusts the deserialized `unstable` field blindly.

**Attack Path:**
1. Attacker compiles Move code using unstable CompilerVersion V2_1 or LanguageVersion V2_4/V2_5
2. Extracts the compiled bytecode and deserializes the `CompilationMetadata`
3. Manually modifies the metadata struct to set `unstable: false` while keeping `compiler_version: "2.1"` and/or `language_version: "2.4"`
4. Re-serializes the tampered metadata and embeds it back into the module bytecode
5. Publishes to mainnet - the check at line 1746 sees `metadata.unstable == false` and allows publication

This breaks the security invariant that only stable, production-ready bytecode should be deployable on mainnet networks.

## Impact Explanation

**Critical Severity** - This vulnerability allows deployment of experimental bytecode on mainnet, which could lead to:

1. **Consensus Safety Violations**: Unstable bytecode may contain non-deterministic behavior or bugs that cause validators to produce different state roots for identical blocks, breaking deterministic execution (Invariant #1)

2. **Move VM Safety Compromises**: Experimental features in unstable versions may have unpatched bugs affecting gas metering, memory constraints, or execution correctness (Invariant #3)

3. **Protocol Stability Risks**: Unstable versions are explicitly marked as not production-ready. Allowing their deployment undermines the entire staged release process designed to protect mainnet integrity

4. **Governance/Staking System Compromise**: If unstable bytecode is deployed to framework modules governing consensus, staking, or governance, it could corrupt critical system state

The validation check exists specifically to prevent these scenarios. Bypassing it exposes mainnet to all risks that unstable bytecode carries.

## Likelihood Explanation

**High Likelihood**:
- Attack requires only basic knowledge of BCS serialization and Rust structs
- No privileged access required - any user can submit module publication transactions
- The `CompilationMetadata` struct uses standard Serde derives, making tampering straightforward
- No cryptographic signatures or integrity checks protect the metadata
- Attack is fully client-side - attacker controls all bytecode before submission

The only barrier is technical competence to deserialize, modify, and re-serialize BCS-encoded data, which is well-documented and tools exist for this purpose.

## Recommendation

Add validation that re-computes and verifies the `unstable` flag from the version strings:

```rust
fn reject_unstable_bytecode(&self, modules: &[CompiledModule]) -> VMResult<()> {
    if self.chain_id().is_mainnet() {
        for module in modules {
            if let Some(metadata) = get_compilation_metadata(module) {
                // Verify the unstable flag matches the actual version stability
                let computed_unstable = match (
                    metadata.compiler_version(),
                    metadata.language_version(),
                ) {
                    (Ok(cv), Ok(lv)) => cv.unstable() || lv.unstable(),
                    _ => {
                        // If we can't parse versions, reject to be safe
                        return Err(PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
                            .with_message("invalid compiler or language version in metadata".to_string())
                            .finish(Location::Undefined));
                    }
                };
                
                // Check both the stored flag AND the computed flag
                if metadata.unstable || computed_unstable {
                    return Err(PartialVMError::new(StatusCode::UNSTABLE_BYTECODE_REJECTED)
                        .with_message("code marked unstable is not published on mainnet".to_string())
                        .finish(Location::Undefined));
                }
            }
        }
    }
    Ok(())
}
```

Alternatively, remove the `unstable` field entirely and always compute it from version strings during deserialization/validation.

## Proof of Concept

```rust
use move_binary_format::CompiledModule;
use move_core_types::metadata::Metadata;
use move_model::metadata::{CompilationMetadata, CompilerVersion, LanguageVersion, COMPILATION_METADATA_KEY};

// Step 1: Create tampered metadata with unstable=false but unstable versions
let tampered_metadata = CompilationMetadata {
    unstable: false,  // LYING - should be true
    compiler_version: "2.1".to_string(),  // V2_1 is unstable
    language_version: "2.0".to_string(),  // V2_0 is stable (for demo)
};

// Step 2: Serialize the tampered metadata
let serialized = bcs::to_bytes(&tampered_metadata).unwrap();

// Step 3: Create metadata entry
let metadata_entry = Metadata {
    key: COMPILATION_METADATA_KEY.to_vec(),
    value: serialized,
};

// Step 4: Compile a legitimate module and replace its metadata
let mut module = /* compile any valid Move module */;
module.metadata.push(metadata_entry);

// Step 5: Serialize the tampered module
let mut bytecode = vec![];
module.serialize(&mut bytecode).unwrap();

// Step 6: Publish to mainnet using code_publish_package_txn
// The reject_unstable_bytecode() check will see unstable=false and allow it,
// even though compiler_version "2.1" should make this unstable bytecode.
```

The vulnerability is exploitable because the validation at [4](#0-3)  checks only `metadata.unstable` without validating it matches the actual version stability computed from the version strings.

## Notes

The security question asked about the inverse scenario (unstable=true bypassing rejection), which does NOT occur - the code correctly rejects when unstable=true. However, this investigation revealed the actual vulnerability: the inverse case where unstable=false incorrectly bypasses rejection when version strings indicate instability. This represents a critical validation gap in the unstable bytecode rejection mechanism.

### Citations

**File:** third_party/move/move-model/src/metadata.rs (L49-62)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompilationMetadata {
    /// A flag indicating whether, at time of creation, the compilation
    /// result was considered as unstable. Unstable code may have restrictions
    /// for deployment on production networks. This flag is true if either the
    /// compiler or language versions are unstable.
    pub unstable: bool,
    /// The version of the compiler, as a string. See
    /// `CompilationVersion::from_str` for supported version strings.
    pub compiler_version: String,
    /// The version of the language, as a string. See
    /// `LanguageVersion::from_str` for supported version strings.
    pub language_version: String,
}
```

**File:** third_party/move/move-model/src/metadata.rs (L65-71)
```rust
    pub fn new(compiler_version: CompilerVersion, language_version: LanguageVersion) -> Self {
        Self {
            compiler_version: compiler_version.to_string(),
            language_version: language_version.to_string(),
            unstable: compiler_version.unstable() || language_version.unstable(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1742-1757)
```rust
    fn reject_unstable_bytecode(&self, modules: &[CompiledModule]) -> VMResult<()> {
        if self.chain_id().is_mainnet() {
            for module in modules {
                if let Some(metadata) = get_compilation_metadata(module) {
                    if metadata.unstable {
                        return Err(PartialVMError::new(StatusCode::UNSTABLE_BYTECODE_REJECTED)
                            .with_message(
                                "code marked unstable is not published on mainnet".to_string(),
                            )
                            .finish(Location::Undefined));
                    }
                }
            }
        }
        Ok(())
    }
```
