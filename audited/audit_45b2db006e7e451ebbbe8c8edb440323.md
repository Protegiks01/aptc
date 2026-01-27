# Audit Report

## Title
Unstable Bytecode Deployment Bypass via CompilationMetadata Stripping on Mainnet

## Summary
The mainnet protection mechanism that prevents deployment of bytecode compiled with unstable compiler/language versions can be bypassed by removing the `CompilationMetadata` from compiled modules. When `CompilationMetadata` is absent, the system assumes the bytecode is stable and allows it on mainnet, violating the production readiness guarantees.

## Finding Description

The Aptos blockchain enforces that bytecode compiled with unstable compiler or language versions cannot be published or executed on mainnet. This is implemented in the `reject_unstable_bytecode` function: [1](#0-0) 

The function checks if `CompilationMetadata` exists and whether it marks the code as unstable. However, when `get_compilation_metadata(module)` returns `None` (bytecode without metadata), the check is completely skipped: [2](#0-1) 

The `CompilationMetadata` structure uses the `Default` trait: [3](#0-2) 

When metadata is absent, the function returns `None` and the unstable check is bypassed. Currently, `CompilerVersion::V2_1` and language versions `V2_4` and `V2_5` are marked as unstable: [4](#0-3) [5](#0-4) 

**Attack Path:**
1. Attacker compiles Move code using an unstable compiler version (e.g., V2_1) or language version (e.g., V2_4)
2. The compiler embeds `CompilationMetadata` with `unstable: true`
3. Attacker deserializes the `CompiledModule` bytecode
4. Attacker removes the `CompilationMetadata` entry from the metadata vector
5. Attacker re-serializes the modified bytecode
6. Attacker publishes to mainnet
7. In `validate_publish_request`, the `reject_unstable_bytecode` check passes because `get_compilation_metadata()` returns `None`
8. Unstable bytecode is accepted and deployed on mainnet

The metadata format validation does not require `CompilationMetadata` to be present: [6](#0-5) 

## Impact Explanation

This vulnerability allows bypassing a critical production safety control. The impact qualifies as **High Severity** under the "Significant protocol violations" category because:

1. **Protocol Violation**: Mainnet explicitly forbids unstable bytecode, as demonstrated by the test suite expectations: [7](#0-6) 

2. **Production Risk**: Unstable versions are marked as such because they may contain experimental features, compiler bugs, or untested semantic changes that could:
   - Cause consensus divergence if behavior differs from expectations
   - Introduce non-deterministic execution under edge cases
   - Contain bytecode generation bugs leading to incorrect state transitions

3. **Validator Impact**: All validators would execute the unstable bytecode, potentially causing network-wide issues if the experimental features behave incorrectly.

4. **Lack of Integrity Protection**: The metadata has no cryptographic binding to the bytecode, making stripping trivial.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is straightforward to execute:
- Requires only standard bytecode manipulation tools (deserialization/serialization)
- No special privileges needed beyond normal module publishing rights
- The attack surface is permanent (any code can be manipulated before publication)

However, the attacker must:
- Have access to unstable compiler versions
- Deliberately strip metadata (not accidental)
- Have a reason to use unstable features on mainnet

The likelihood increases if:
- Unstable versions offer desirable features unavailable in stable releases
- Developers test with unstable versions and inadvertently try to deploy
- Malicious actors specifically target mainnet with experimental features

## Recommendation

**Fix 1: Require CompilationMetadata on Mainnet**

Modify the validation logic to reject bytecode without `CompilationMetadata` when deploying to mainnet:

```rust
fn reject_unstable_bytecode(&self, modules: &[CompiledModule]) -> VMResult<()> {
    if self.chain_id().is_mainnet() {
        for module in modules {
            let metadata = get_compilation_metadata(module).ok_or_else(|| {
                PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
                    .with_message(
                        "compilation metadata required on mainnet".to_string(),
                    )
                    .finish(Location::Undefined)
            })?;
            
            if metadata.unstable {
                return Err(PartialVMError::new(StatusCode::UNSTABLE_BYTECODE_REJECTED)
                    .with_message(
                        "code marked unstable is not published on mainnet".to_string(),
                    )
                    .finish(Location::Undefined));
            }
        }
    }
    Ok(())
}
```

**Fix 2: Cryptographic Binding (Stronger)**

Add a cryptographic commitment to the metadata within the module's binary format that the verifier can check, preventing metadata tampering.

**Fix 3: Bytecode Version Gating**

Since unstable language versions use `VERSION_DEFAULT_LANG_V2_4` (version 10), ensure version 10 is not enabled on mainnet via feature flags, providing defense-in-depth.

## Proof of Concept

```rust
use move_binary_format::CompiledModule;
use move_model::metadata::{CompilationMetadata, CompilerVersion, LanguageVersion, COMPILATION_METADATA_KEY};
use aptos_framework::{BuildOptions, BuiltPackage};

fn demonstrate_metadata_stripping_attack() {
    // Step 1: Compile with unstable compiler
    let package = BuiltPackage::build(
        package_path,
        BuildOptions {
            compiler_version: Some(CompilerVersion::V2_1), // UNSTABLE
            ..Default::default()
        }
    ).unwrap();
    
    // Step 2: Extract and deserialize bytecode
    let code = package.extract_code();
    let mut module = CompiledModule::deserialize(&code[0]).unwrap();
    
    // Step 3: Verify metadata exists and marks code as unstable
    let original_metadata = module.metadata
        .iter()
        .find(|m| m.key == COMPILATION_METADATA_KEY)
        .expect("Compilation metadata should exist");
    
    let compilation_meta: CompilationMetadata = 
        bcs::from_bytes(&original_metadata.value).unwrap();
    assert!(compilation_meta.unstable, "Should be marked unstable");
    
    // Step 4: Strip compilation metadata
    module.metadata.retain(|m| m.key != COMPILATION_METADATA_KEY);
    
    // Step 5: Re-serialize
    let mut modified_code = vec![];
    module.serialize(&mut modified_code).unwrap();
    
    // Step 6: Attempt to publish on mainnet
    // This would succeed when it should fail!
    // The reject_unstable_bytecode check will pass because 
    // get_compilation_metadata returns None
}
```

## Notes

- This vulnerability affects both module publishing and script execution (via `reject_unstable_bytecode_for_script`)
- The same issue applies to historical bytecode that genuinely lacks `CompilationMetadata`, but this is less concerning as truly old bytecode predates unstable versions
- The fix should grandfather existing on-chain modules but enforce the requirement for new publications
- Defense-in-depth through bytecode version feature flags provides partial mitigation but not complete protection

### Citations

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

**File:** third_party/move/move-model/src/metadata.rs (L148-157)
```rust
impl CompilerVersion {
    /// Return true if this is a stable compiler version. A non-stable version
    /// should not be allowed on production networks.
    pub fn unstable(self) -> bool {
        match self {
            CompilerVersion::V1 => false,
            CompilerVersion::V2_0 => false,
            CompilerVersion::V2_1 => true,
        }
    }
```

**File:** third_party/move/move-model/src/metadata.rs (L285-294)
```rust
impl LanguageVersion {
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

**File:** aptos-move/e2e-move-tests/src/tests/metadata.rs (L318-331)
```rust
#[test]
fn test_compilation_metadata() {
    // publish unstable compiler code to mainnet
    assert_vm_status!(
        test_compilation_metadata_internal(true, true),
        StatusCode::UNSTABLE_BYTECODE_REJECTED
    );
    // publish stable compiler code to mainnet
    assert_success!(test_compilation_metadata_internal(true, false,));
    // publish unstable compiler code to test
    assert_success!(test_compilation_metadata_internal(false, true,));
    // publish stable compiler code to test
    assert_success!(test_compilation_metadata_internal(false, false,));
}
```
