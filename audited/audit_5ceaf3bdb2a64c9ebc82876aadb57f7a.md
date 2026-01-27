# Audit Report

## Title
Unstable Bytecode Protection Bypass via CompilationMetadata Stripping

## Summary
Attackers can bypass the mainnet unstable bytecode rejection mechanism by stripping CompilationMetadata from modules compiled with unstable compiler or language versions. When `get_compilation_metadata()` returns `None`, the `reject_unstable_bytecode()` function silently accepts the bytecode without performing the stability check, allowing potentially buggy or untested code to be deployed to production networks.

## Finding Description

The Aptos VM implements a security control to prevent unstable bytecode from being published to mainnet. This is enforced through the `reject_unstable_bytecode()` function which checks the `unstable` flag in CompilationMetadata. [1](#0-0) 

However, this check has a critical flaw: when CompilationMetadata is absent (returns `None`), the function silently returns `Ok(())` without performing any validation: [2](#0-1) 

The function only checks the `unstable` flag **if metadata exists**. When `get_compilation_metadata()` returns `None`, the loop continues to the next module without rejection. [3](#0-2) 

**Attack Scenario:**

1. Attacker compiles code using unstable CompilerVersion::V2_1 (marked as unstable): [4](#0-3) 

2. The compiler generates bytecode with CompilationMetadata containing `unstable: true` [5](#0-4) 

3. Attacker deserializes the compiled module, removes the CompilationMetadata entry from the `metadata` vector, and re-serializes

4. Attacker publishes to mainnet - the bytecode passes `reject_unstable_bytecode()` because metadata is `None`

5. Code compiled with untested/buggy unstable compilers now executes on mainnet, potentially introducing consensus violations or security issues

The unstable designation exists for a reason - unstable compiler versions may have bugs in bytecode generation, optimization passes, or feature implementations that haven't been fully tested and could affect deterministic execution across validators.

## Impact Explanation

This is a **High severity** vulnerability that undermines a critical security control. The impact justification:

1. **Breaks Security Invariant**: The Aptos team explicitly created the `_REJECT_UNSTABLE_BYTECODE` feature flag (marked as "Enabled on mainnet, can never be disabled"): [6](#0-5) 

2. **Potential Consensus Risk**: Unstable compilers may generate bytecode that passes verification but produces non-deterministic behavior across validators, potentially causing state divergence and consensus violations (Critical invariant #1: Deterministic Execution)

3. **Bypasses Intended Protection**: The existence of tests validating unstable rejection proves this is an intended security control: [7](#0-6) 

4. **Production Network Risk**: While the specific exploits depend on bugs in unstable compilers, allowing this bypass violates defense-in-depth principles and exposes mainnet to untested code paths

This meets **High Severity** criteria: "Significant protocol violations" by bypassing security controls designed to protect mainnet integrity.

## Likelihood Explanation

**Likelihood: High**

1. **Easy to Execute**: An attacker only needs to:
   - Use the unstable compiler to build a package
   - Deserialize the bytecode using `CompiledModule::deserialize()`
   - Remove metadata entries where `key == COMPILATION_METADATA_KEY`
   - Re-serialize with `module.serialize()`
   - Publish normally

2. **No Special Privileges Required**: Any account with sufficient gas can publish modules

3. **Current Gap**: There are no tests validating behavior when CompilationMetadata is absent, suggesting this scenario wasn't considered: [8](#0-7) 

4. **No Secondary Validation**: The `check_metadata_format()` function only validates metadata IF present, not whether it's required: [9](#0-8) 

## Recommendation

**Solution 1: Require CompilationMetadata for New Bytecode (Recommended)**

Modify the validation to require CompilationMetadata for bytecode versions above a threshold (e.g., VERSION_6+) and reject modules without it on mainnet:

```rust
fn reject_unstable_bytecode(&self, modules: &[CompiledModule]) -> VMResult<()> {
    if self.chain_id().is_mainnet() {
        for module in modules {
            // Require CompilationMetadata for newer bytecode versions
            if module.version() >= METADATA_V1_MIN_FILE_FORMAT_VERSION {
                let metadata = get_compilation_metadata(module).ok_or_else(|| {
                    PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
                        .with_message("CompilationMetadata required for bytecode v6+".to_string())
                        .finish(Location::Undefined)
                })?;
                
                if metadata.unstable {
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

**Solution 2: Assume Unstable if Metadata Missing**

If backward compatibility with old bytecode is critical, treat missing metadata as potentially unstable and require explicit stable marking:

```rust
fn reject_unstable_bytecode(&self, modules: &[CompiledModule]) -> VMResult<()> {
    if self.chain_id().is_mainnet() {
        for module in modules {
            match get_compilation_metadata(module) {
                Some(metadata) => {
                    if metadata.unstable {
                        return Err(/*rejection error*/);
                    }
                }
                None => {
                    // Treat missing metadata as unsafe for new deployments
                    if module.version() >= METADATA_V1_MIN_FILE_FORMAT_VERSION {
                        return Err(PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
                            .with_message("Missing CompilationMetadata on mainnet".to_string())
                            .finish(Location::Undefined));
                    }
                }
            }
        }
    }
    Ok(())
}
```

## Proof of Concept

```rust
// Test demonstrating the bypass
#[test]
fn test_unstable_bytecode_bypass_via_metadata_stripping() {
    use move_binary_format::CompiledModule;
    use move_model::metadata::COMPILATION_METADATA_KEY;
    
    // 1. Build with unstable compiler (simulated)
    let mut h = MoveHarness::new();
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xf00d").unwrap());
    
    let mut builder = PackageBuilder::new("Package");
    builder.add_source("m.move", r#"
        module 0xf00d::M {
            public fun vulnerable() { }
        }
    "#);
    let path = builder.write_to_temp().unwrap();
    
    // Build with unstable compiler
    let package = BuiltPackage::build(
        path.path().to_path_buf(),
        BuildOptions {
            compiler_version: Some(CompilerVersion::latest()), // V2.1 unstable
            ..BuildOptions::default()
        }
    ).expect("building must succeed");
    
    // 2. Strip CompilationMetadata
    let code = package.extract_code();
    let mut module = CompiledModule::deserialize(&code[0]).unwrap();
    
    // Remove CompilationMetadata entry
    module.metadata.retain(|m| m.key != COMPILATION_METADATA_KEY.to_vec());
    
    let mut stripped_code = vec![];
    module.serialize(&mut stripped_code).unwrap();
    
    // 3. Publish to mainnet - should be rejected but isn't!
    h.set_resource(CORE_CODE_ADDRESS, ChainId::struct_tag(), &ChainId::mainnet().id());
    
    let result = h.run_transaction_payload_mainnet(
        &account,
        aptos_stdlib::code_publish_package_txn(
            bcs::to_bytes(&package.extract_metadata().unwrap()).unwrap(),
            vec![stripped_code],
        ),
    );
    
    // This SHOULD fail with UNSTABLE_BYTECODE_REJECTED but succeeds
    assert_success!(result); // Attack succeeds!
}
```

This PoC demonstrates that unstable bytecode can be published to mainnet by simply removing the CompilationMetadata, bypassing the intended security control.

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

**File:** types/src/on_chain_config/aptos_features.rs (L80-80)
```rust
    _REJECT_UNSTABLE_BYTECODE = 58,
```

**File:** aptos-move/e2e-move-tests/src/tests/metadata.rs (L303-316)
```rust
#[test]
fn test_compilation_metadata_for_script() {
    // run unstable compiler code to mainnet
    assert_vm_status!(
        test_compilation_metadata_script_internal(true, true),
        StatusCode::UNSTABLE_BYTECODE_REJECTED
    );
    // run stable compiler code to mainnet
    assert_success!(test_compilation_metadata_script_internal(true, false,));
    // run unstable compiler code to test
    assert_success!(test_compilation_metadata_script_internal(false, true,));
    // run stable compiler code to test
    assert_success!(test_compilation_metadata_script_internal(false, false,));
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
