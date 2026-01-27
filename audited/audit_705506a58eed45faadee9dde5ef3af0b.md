# Audit Report

## Title
Metadata Manipulation Bypass: Unstable Language Version Protection Can Be Defeated Through `unstable` Flag Tampering

## Summary
The validation logic in `reject_unstable_bytecode()` only checks the boolean `unstable` flag in `CompilationMetadata` without verifying it matches the actual `compiler_version` and `language_version` strings. An attacker can manipulate serialized bytecode to set `unstable: false` while keeping `language_version: "2.5"` (or other unstable versions), bypassing mainnet's protection against experimental language features and potentially causing consensus violations.

## Finding Description

The `CompilationMetadata` struct contains three fields that describe bytecode provenance: [1](#0-0) 

During compilation, this metadata is correctly initialized: [2](#0-1) 

The `unstable` flag is properly set based on version checks: [3](#0-2) 

However, during module publishing on mainnet, the validation only checks the `unstable` boolean: [4](#0-3) 

The validation extracts metadata via: [5](#0-4) 

Critically, the `check_metadata_format()` function only validates deserialization, NOT semantic consistency: [6](#0-5) 

**Attack Path:**
1. Attacker compiles Move code with unstable `LanguageVersion::V2_5` (marked unstable at line 292 of metadata.rs)
2. Compiler generates metadata: `{language_version: "2.5", compiler_version: "2.0", unstable: true}`
3. Attacker deserializes the compiled module's metadata section
4. Attacker modifies the BCS-serialized `CompilationMetadata` to change `unstable: true` → `unstable: false`
5. Attacker re-serializes and publishes the manipulated bytecode to mainnet
6. Validation calls `reject_unstable_bytecode()` which only checks `metadata.unstable` (now false)
7. Bytecode with experimental V2.5 language features is accepted on mainnet

This breaks the critical invariant that **unstable/experimental bytecode must not execute on mainnet**.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability enables:

1. **Consensus Safety Violations**: Unstable language versions (V2.4, V2.5) contain experimental features that may have determinism bugs. If execution behavior differs between validators due to untested features, this violates **Invariant #1: Deterministic Execution**, potentially causing state root mismatches and consensus splits.

2. **Protocol Integrity Compromise**: The entire purpose of marking versions as "unstable" is to prevent unvetted code from reaching production. Bypassing this protection undermines the blockchain's security model.

3. **Validator Risk**: Experimental features may have performance issues, memory leaks, or unexpected gas consumption patterns, affecting validator operations (**Invariant #3: Move VM Safety**).

This qualifies as **"Significant protocol violations"** under the High severity category. While not an immediate consensus break, it creates conditions where consensus could fail if the unstable features contain bugs.

## Likelihood Explanation

**Likelihood: Medium-High**

- **Attacker Requirements**: Only requires ability to publish modules (standard user capability) and basic bytecode manipulation skills
- **Complexity**: Low - modifying BCS-serialized data is straightforward
- **Detection Difficulty**: Hard to detect without cross-validation of metadata fields
- **Motivation**: Attackers could exploit experimental features with known issues or use bleeding-edge capabilities unavailable in stable versions

The attack is feasible for any sophisticated attacker. The only barrier is that unstable versions must actually have exploitable differences from stable ones.

## Recommendation

Add semantic validation in `reject_unstable_bytecode()` to verify the `unstable` flag matches the actual version strings:

```rust
fn reject_unstable_bytecode(&self, modules: &[CompiledModule]) -> VMResult<()> {
    if self.chain_id().is_mainnet() {
        for module in modules {
            if let Some(metadata) = get_compilation_metadata(module) {
                // Existing check
                if metadata.unstable {
                    return Err(PartialVMError::new(StatusCode::UNSTABLE_BYTECODE_REJECTED)
                        .with_message("code marked unstable is not published on mainnet".to_string())
                        .finish(Location::Undefined));
                }
                
                // NEW: Cross-validate unstable flag with version strings
                let compiler_version = metadata.compiler_version()
                    .map_err(|_| PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
                        .with_message("invalid compiler version in metadata".to_string())
                        .finish(Location::Undefined))?;
                let language_version = metadata.language_version()
                    .map_err(|_| PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
                        .with_message("invalid language version in metadata".to_string())
                        .finish(Location::Undefined))?;
                
                // Verify unstable flag is consistent
                let should_be_unstable = compiler_version.unstable() || language_version.unstable();
                if should_be_unstable {
                    return Err(PartialVMError::new(StatusCode::UNSTABLE_BYTECODE_REJECTED)
                        .with_message(format!(
                            "bytecode compiled with unstable versions (compiler: {}, language: {}) cannot be published on mainnet",
                            compiler_version, language_version
                        ))
                        .finish(Location::Undefined));
                }
            }
        }
    }
    Ok(())
}
```

Apply the same fix to `reject_unstable_bytecode_for_script()`.

## Proof of Concept

```rust
// Test demonstrating metadata manipulation bypass
#[test]
fn test_metadata_unstable_flag_manipulation() {
    use move_model::metadata::{CompilationMetadata, CompilerVersion, LanguageVersion};
    use move_core_types::metadata::Metadata;
    use move_binary_format::CompiledModule;
    
    // Step 1: Create metadata with unstable language version
    let unstable_metadata = CompilationMetadata::new(
        CompilerVersion::V2_0,  // stable
        LanguageVersion::V2_5,  // UNSTABLE
    );
    assert!(unstable_metadata.unstable); // Should be true
    
    // Step 2: Manually create manipulated metadata with same versions but false flag
    let manipulated_metadata = CompilationMetadata {
        unstable: false,  // MANIPULATED to false
        compiler_version: "2.0".to_string(),
        language_version: "2.5".to_string(),  // Still unstable version!
    };
    
    // Step 3: Serialize manipulated metadata
    let metadata_bytes = bcs::to_bytes(&manipulated_metadata).unwrap();
    let metadata = Metadata {
        key: move_model::metadata::COMPILATION_METADATA_KEY.to_vec(),
        value: metadata_bytes,
    };
    
    // Step 4: Create module with manipulated metadata
    let mut module = CompiledModule::default();
    module.metadata.push(metadata);
    
    // Step 5: Verify that get_compilation_metadata returns manipulated version
    let extracted = get_compilation_metadata(&module).unwrap();
    assert!(!extracted.unstable); // Flag shows stable
    assert_eq!(extracted.language_version, "2.5"); // But version is unstable!
    
    // This bytecode would pass reject_unstable_bytecode() check on mainnet
    // because it only checks extracted.unstable (which is false)
    // but actually contains unstable language version 2.5 features!
}
```

## Notes

While the security question mentions "older, vulnerable language version" (downgrade attacks), the more critical vulnerability is actually in the opposite direction: forcing acceptance of NEWER unstable versions. The root cause is identical—lack of semantic validation of the `unstable` flag—but the upgrade attack has higher practical impact since unstable versions contain experimental, potentially buggy features that could break consensus determinism.

The downgrade variant (claiming old versions) has limited impact since bytecode execution depends on binary format version (validated separately), not metadata. However, the upgrade variant directly defeats a security control designed to protect mainnet from experimental code.

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

**File:** third_party/move/move-model/src/metadata.rs (L64-71)
```rust
impl CompilationMetadata {
    pub fn new(compiler_version: CompilerVersion, language_version: LanguageVersion) -> Self {
        Self {
            compiler_version: compiler_version.to_string(),
            language_version: language_version.to_string(),
            unstable: compiler_version.unstable() || language_version.unstable(),
        }
    }
```

**File:** third_party/move/move-model/src/metadata.rs (L286-294)
```rust
    /// Whether the language version is unstable. An unstable version
    /// should not be allowed on production networks.
    pub const fn unstable(self) -> bool {
        use LanguageVersion::*;
        match self {
            V1 | V2_0 | V2_1 | V2_2 | V2_3 => false,
            V2_4 | V2_5 => true,
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

**File:** types/src/vm/module_metadata.rs (L253-283)
```rust
fn check_metadata_format(module: &CompiledModule) -> Result<(), MalformedError> {
    let mut exist = false;
    let mut compilation_key_exist = false;
    for data in module.metadata.iter() {
        if data.key == *APTOS_METADATA_KEY || data.key == *APTOS_METADATA_KEY_V1 {
            if exist {
                return Err(MalformedError::DuplicateKey);
            }
            exist = true;

            if data.key == *APTOS_METADATA_KEY {
                bcs::from_bytes::<RuntimeModuleMetadata>(&data.value)
                    .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
            } else if data.key == *APTOS_METADATA_KEY_V1 {
                bcs::from_bytes::<RuntimeModuleMetadataV1>(&data.value)
                    .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
            }
        } else if data.key == *COMPILATION_METADATA_KEY {
            if compilation_key_exist {
                return Err(MalformedError::DuplicateKey);
            }
            compilation_key_exist = true;
            bcs::from_bytes::<CompilationMetadata>(&data.value)
                .map_err(|e| MalformedError::DeserializedError(data.key.clone(), e))?;
        } else {
            return Err(MalformedError::UnknownKey(data.key.clone()));
        }
    }

    Ok(())
}
```

**File:** types/src/vm/module_metadata.rs (L310-317)
```rust
/// Extract compilation metadata from a compiled module or script.
pub fn get_compilation_metadata(code: &impl CompiledCodeMetadata) -> Option<CompilationMetadata> {
    if let Some(data) = find_metadata(code.metadata(), COMPILATION_METADATA_KEY) {
        bcs::from_bytes::<CompilationMetadata>(&data.value).ok()
    } else {
        None
    }
}
```
