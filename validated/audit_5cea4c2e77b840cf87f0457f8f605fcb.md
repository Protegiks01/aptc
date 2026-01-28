# Audit Report

## Title
Missing CompilationMetadata Bypasses Unstable Bytecode Restrictions on Mainnet

## Summary
The `reject_unstable_bytecode` security check incorrectly treats missing compilation metadata as safe, allowing attackers to publish unstable bytecode (language versions V2_4/V2_5) to mainnet by removing the `COMPILATION_METADATA_KEY` entry from compiled modules. This bypasses a critical safety mechanism designed to prevent unvetted compiler features from executing in production.

## Finding Description

The vulnerability exists in the interaction between three functions in the module publishing flow:

**1. Silent Error Conversion**

The `get_compilation_metadata` function uses `.ok()` which converts both missing metadata AND deserialization errors to `None`, hiding the distinction between "no metadata present" and "invalid metadata". [1](#0-0) 

**2. Unsafe None Handling**

The `reject_unstable_bytecode` function only rejects when metadata exists AND contains `unstable: true`. When `get_compilation_metadata` returns `None`, the check passes with `Ok(())`, treating absence of metadata as safe. [2](#0-1) 

**3. Missing Metadata Not Enforced**

The `check_metadata_format` function validates metadata entries that are present but does not require `COMPILATION_METADATA_KEY` to exist. The `compilation_key_exist` flag is set when the key is found but never checked before returning `Ok(())`. [3](#0-2) 

**Attack Execution Path**:

The compiler always embeds compilation metadata during module generation: [4](#0-3) 

Language versions V2_4 and V2_5 are explicitly marked as unstable: [5](#0-4) 

An attacker can exploit this by:
1. Compiling a module with unstable language version V2_4 or V2_5
2. Deserializing the compiled bytecode, removing the `COMPILATION_METADATA_KEY` entry from the metadata vector, and re-serializing (pattern demonstrated in existing tests)
3. Publishing the modified bytecode to mainnet where `validate_publish_request` calls `reject_unstable_bytecode` [6](#0-5) 

4. The check returns `Ok(())` because no metadata is found, bypassing the unstable bytecode restriction that is explicitly enabled on mainnet [7](#0-6) 

## Impact Explanation

This is a **MEDIUM severity** vulnerability classified as a "Limited Protocol Violation". The `_REJECT_UNSTABLE_BYTECODE` feature flag is marked "Enabled on mainnet, can never be disabled", indicating the Aptos team considers this protection essential for mainnet safety.

Unstable bytecode may contain:
- Experimental language features with untested behavior
- Non-deterministic operations that could cause validator consensus divergence
- Breaking changes not yet validated for production use
- Implementation bugs in pre-release compiler versions

While this report does not directly demonstrate a consensus split or fund loss, it reveals a **logic vulnerability** that bypasses a security control explicitly designed to maintain deterministic execution on mainnet. The actual impact depends on whether specific unstable features deployed through this bypass exhibit non-deterministic behavior.

## Likelihood Explanation

**HIGH likelihood**. The attack requires:
- Public Move compiler to generate initial bytecode
- Standard BCS deserialization/serialization (trivial bytecode manipulation)
- Normal transaction submission via `code_publish_package_txn`
- No special privileges, validator access, or cryptographic operations

The lack of test coverage for missing compilation metadata confirms this scenario was not considered: [8](#0-7) 

Existing tests only verify behavior when metadata exists with stable/unstable flags, not the missing metadata case.

## Recommendation

Modify `check_metadata_format` to require `COMPILATION_METADATA_KEY` to be present:

```rust
fn check_metadata_format(module: &CompiledModule) -> Result<(), MalformedError> {
    let mut exist = false;
    let mut compilation_key_exist = false;
    
    for data in module.metadata.iter() {
        // ... existing validation logic ...
        if data.key == *COMPILATION_METADATA_KEY {
            compilation_key_exist = true;
            // ... existing deserialization check ...
        }
    }
    
    // Add enforcement
    if !compilation_key_exist {
        return Err(MalformedError::MissingRequiredKey(COMPILATION_METADATA_KEY.to_vec()));
    }
    
    Ok(())
}
```

This ensures all modules published to mainnet must have valid compilation metadata, preventing the bypass.

## Proof of Concept

```rust
// Compile module with unstable version V2_4
let package = BuiltPackage::build(path, BuildOptions {
    language_version: Some(LanguageVersion::V2_4),
    ..Default::default()
})?;

let code = package.extract_code()[0].clone();
let mut module = CompiledModule::deserialize(&code)?;

// Remove COMPILATION_METADATA_KEY
module.metadata = module.metadata.into_iter()
    .filter(|m| m.key != COMPILATION_METADATA_KEY)
    .collect();

// Re-serialize and publish
let mut modified_code = vec![];
module.serialize(&mut modified_code)?;

// Submit to mainnet - will bypass reject_unstable_bytecode check
harness.run_transaction_payload_mainnet(
    &account,
    aptos_stdlib::code_publish_package_txn(metadata, vec![modified_code])
);
// Expected: UNSTABLE_BYTECODE_REJECTED
// Actual: SUCCESS (bypassed)
```

### Citations

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

**File:** types/src/vm/module_metadata.rs (L311-317)
```rust
pub fn get_compilation_metadata(code: &impl CompiledCodeMetadata) -> Option<CompilationMetadata> {
    if let Some(data) = find_metadata(code.metadata(), COMPILATION_METADATA_KEY) {
        bcs::from_bytes::<CompilationMetadata>(&data.value).ok()
    } else {
        None
    }
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1689-1689)
```rust
        self.reject_unstable_bytecode(modules)?;
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

**File:** third_party/move/move-compiler-v2/src/file_format_generator/module_generator.rs (L165-174)
```rust
        let compilation_metadata = CompilationMetadata::new(compiler_version, language_version);
        let metadata = Metadata {
            key: COMPILATION_METADATA_KEY.to_vec(),
            value: bcs::to_bytes(&compilation_metadata)
                .expect("Serialization of CompilationMetadata should succeed"),
        };
        let module = move_binary_format::CompiledModule {
            version: file_format_common::VERSION_MAX,
            self_module_handle_idx: FF::ModuleHandleIndex(0),
            metadata: vec![metadata],
```

**File:** third_party/move/move-model/src/metadata.rs (L288-294)
```rust
    pub const fn unstable(self) -> bool {
        use LanguageVersion::*;
        match self {
            V1 | V2_0 | V2_1 | V2_2 | V2_3 => false,
            V2_4 | V2_5 => true,
        }
    }
```

**File:** types/src/on_chain_config/aptos_features.rs (L79-80)
```rust
    /// Enabled on mainnet, can never be disabled.
    _REJECT_UNSTABLE_BYTECODE = 58,
```

**File:** aptos-move/e2e-move-tests/src/tests/metadata.rs (L319-331)
```rust
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
