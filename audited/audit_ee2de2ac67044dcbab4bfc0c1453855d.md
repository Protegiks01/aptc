# Audit Report

## Title
Script Execution Bypass: Unstable Bytecode Can Execute on Mainnet via Metadata Manipulation

## Summary
A CompiledScript with manipulated metadata can bypass mainnet's unstable bytecode rejection mechanism. The `reject_unstable_bytecode_for_script()` function relies on unprotected metadata that can be trivially modified by an attacker, allowing scripts compiled with unstable compilers to execute on mainnet despite explicit policy controls designed to prevent this.

## Finding Description

The Aptos VM implements a security policy to prevent scripts compiled with unstable compiler versions from executing on mainnet. This check is performed in the `reject_unstable_bytecode_for_script()` function [1](#0-0) , which is called during script execution [2](#0-1) .

The vulnerability exists because:

1. **No Cryptographic Protection**: During CompiledScript deserialization, metadata is loaded directly from the binary format without any cryptographic validation or integrity checking [3](#0-2) 

2. **Metadata Lookup Without Validation**: The `get_compilation_metadata()` function simply searches for a metadata entry with a specific key and deserializes it [4](#0-3) 

3. **Bypassable Check Logic**: The rejection logic returns `Ok()` if no compilation metadata is found, rather than failing securely [5](#0-4) 

4. **No Bytecode Verifier Protection**: The comprehensive bytecode verification process does not validate metadata authenticity [6](#0-5) 

**Attack Path:**
1. Compile a script using an unstable compiler, which embeds `CompilationMetadata` with `unstable: true` [7](#0-6) 
2. Deserialize the compiled bytecode
3. Either:
   - Remove the `COMPILATION_METADATA_KEY` entry from the metadata array entirely
   - Modify the metadata value to set `unstable: false`
4. Re-serialize the bytecode
5. Submit the script transaction to mainnet
6. The script passes all bytecode verification checks
7. The `reject_unstable_bytecode_for_script()` check either finds no metadata (returns `Ok()`) or finds metadata with `unstable=false` (returns `Ok()`)
8. The unstable script executes on mainnet

## Impact Explanation

This vulnerability represents a **High to Critical severity** issue:

**Critical Severity Justification:**
- **Consensus Safety Risk**: If an unstable compiler produces bytecode with subtle bugs, different validators might execute it differently, potentially violating the Deterministic Execution invariant and causing consensus splits
- **Policy Bypass**: Circumvents an explicitly implemented security control that was designed to protect mainnet from potentially buggy code
- **Network Stability**: The Aptos team implemented this check specifically because unstable compilers may introduce non-deterministic behavior or other serious issues

The actual severity depends on whether unstable compiler versions can produce bytecode that passes all verification but exhibits problematic behavior. However, the fact that Aptos implemented this specific protection (with dedicated StatusCode `UNSTABLE_BYTECODE_REJECTED` [8](#0-7) ) indicates they consider unstable bytecode a genuine threat to mainnet safety.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Trivial Exploitation**: Any user can manipulate bytecode metadata using standard serialization libraries
2. **No Special Privileges Required**: Does not require validator access or any special permissions
3. **Undetectable**: There is no monitoring or alerting for metadata manipulation since it appears as normal bytecode
4. **No Cost Barrier**: Standard transaction gas fees apply, making testing and exploitation cheap
5. **Motivation Exists**: Developers using cutting-edge unstable compiler features may be motivated to bypass the restriction

The existing test suite confirms the check works for properly-formed metadata [9](#0-8) , but does not test against metadata manipulation attacks.

## Recommendation

Implement cryptographic protection for compilation metadata:

1. **Add Metadata Signing**: Have the compiler sign the compilation metadata with a key controlled by Aptos
2. **Verify Signature On-Chain**: Modify `reject_unstable_bytecode_for_script()` to verify the metadata signature before trusting its contents
3. **Fail Securely**: If metadata is missing or invalid on mainnet, reject the script by default
4. **Alternative Approach**: Since metadata can be stripped, implement bytecode feature detection to identify unstable opcodes or patterns directly from bytecode structure rather than relying on metadata

Example fix for secure failure:

```rust
pub fn reject_unstable_bytecode_for_script(&self, script: &CompiledScript) -> VMResult<()> {
    if self.chain_id().is_mainnet() {
        match get_compilation_metadata(script) {
            Some(metadata) => {
                // Verify metadata signature here
                if metadata.unstable {
                    return Err(PartialVMError::new(StatusCode::UNSTABLE_BYTECODE_REJECTED)
                        .with_message("script marked unstable cannot be run on mainnet".to_string())
                        .finish(Location::Script));
                }
            },
            None => {
                // FAIL SECURE: Reject scripts without valid metadata on mainnet
                return Err(PartialVMError::new(StatusCode::UNSTABLE_BYTECODE_REJECTED)
                    .with_message("script missing compilation metadata on mainnet".to_string())
                    .finish(Location::Script));
            }
        }
    }
    Ok(())
}
```

## Proof of Concept

```rust
use move_binary_format::file_format::{CompiledScript, Metadata};
use move_core_types::metadata::Metadata as CoreMetadata;
use move_model::metadata::{CompilationMetadata, COMPILATION_METADATA_KEY};

fn exploit_unstable_bytecode_bypass() {
    // Step 1: Start with a script compiled by unstable compiler
    // (with unstable=true in metadata)
    let original_bytecode = compile_with_unstable_compiler();
    
    // Step 2: Deserialize the script
    let mut script = CompiledScript::deserialize(&original_bytecode).unwrap();
    
    // Step 3: Attack Method 1 - Remove compilation metadata entirely
    script.metadata.retain(|m| m.key != COMPILATION_METADATA_KEY);
    
    // OR Attack Method 2 - Modify metadata to mark as stable
    for metadata in &mut script.metadata {
        if metadata.key == COMPILATION_METADATA_KEY {
            let fake_metadata = CompilationMetadata {
                unstable: false,  // LIE: Mark as stable
                compiler_version: "1.0.0".to_string(),
                language_version: "1.0.0".to_string(),
            };
            metadata.value = bcs::to_bytes(&fake_metadata).unwrap();
        }
    }
    
    // Step 4: Re-serialize the manipulated script
    let mut manipulated_bytecode = vec![];
    script.serialize(&mut manipulated_bytecode).unwrap();
    
    // Step 5: Submit to mainnet - will execute despite being unstable
    // submit_script_to_mainnet(manipulated_bytecode);
    
    // The script now bypasses reject_unstable_bytecode_for_script()
    // because either:
    // - No metadata found -> returns Ok()
    // - Metadata with unstable=false -> returns Ok()
}
```

To test this vulnerability, modify the existing test at [10](#0-9)  to manipulate the script bytecode before submission and observe that the previously-failing test now passes.

## Notes

This vulnerability demonstrates a fundamental design flaw: security-critical metadata lacks cryptographic protection. While the Move bytecode verifier provides strong defense-in-depth, the explicit unstable bytecode check exists because the Aptos team identified scenarios where unstable compilers could pose risks that verification alone cannot catch. The trivial bypass of this control represents a critical gap in mainnet security guarantees.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L919-919)
```rust
            self.reject_unstable_bytecode_for_script(script)?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1760-1771)
```rust
    pub fn reject_unstable_bytecode_for_script(&self, script: &CompiledScript) -> VMResult<()> {
        if self.chain_id().is_mainnet() {
            if let Some(metadata) = get_compilation_metadata(script) {
                if metadata.unstable {
                    return Err(PartialVMError::new(StatusCode::UNSTABLE_BYTECODE_REJECTED)
                        .with_message("script marked unstable cannot be run on mainnet".to_string())
                        .finish(Location::Script));
                }
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L1025-1029)
```rust
fn load_metadata_entry(cursor: &mut VersionedCursor) -> BinaryLoaderResult<Metadata> {
    let key = load_byte_blob(cursor, load_metadata_key_size)?;
    let value = load_byte_blob(cursor, load_metadata_value_size)?;
    Ok(Metadata { key, value })
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

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L196-210)
```rust
        BoundsChecker::verify_script(script).map_err(|e| {
            // We can't point the error at the script, because if bounds-checking
            // failed, we cannot safely index into script
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_script(config, script)?;
        LimitsVerifier::verify_script(config, script)?;
        DuplicationChecker::verify_script(script)?;

        signature_v2::verify_script(config, script)?;

        InstructionConsistency::verify_script(script)?;
        constants::verify_script(script)?;
        CodeUnitVerifier::verify_script(config, script)?;
        script_signature::verify_script(script, no_additional_script_signature_checks)
```

**File:** third_party/move/move-model/src/metadata.rs (L50-62)
```rust
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

**File:** third_party/move/move-core/types/src/vm_status.rs (L801-801)
```rust
    UNSTABLE_BYTECODE_REJECTED = 1125,
```

**File:** aptos-move/e2e-move-tests/src/tests/metadata.rs (L259-301)
```rust
fn test_compilation_metadata_script_internal(
    mainnet_flag: bool,
    unstable_flag: bool,
) -> TransactionStatus {
    let mut h = MoveHarness::new();
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xf00d").unwrap());
    let mut builder = PackageBuilder::new("Package");
    builder.add_source(
        "m.move",
        r#"
        script {
            fun main() { }
        }
        "#,
    );
    let path = builder.write_to_temp().unwrap();

    let compiler_version = if unstable_flag {
        CompilerVersion::latest()
    } else {
        CompilerVersion::latest_stable()
    };
    let package = BuiltPackage::build(path.path().to_path_buf(), BuildOptions {
        compiler_version: Some(compiler_version),
        ..BuildOptions::default()
    })
    .expect("building package must succeed");

    let code = package.extract_script_code().into_iter().next().unwrap();

    let script = TransactionPayload::Script(Script::new(code, vec![], vec![]));

    if mainnet_flag {
        h.set_resource(
            CORE_CODE_ADDRESS,
            ChainId::struct_tag(),
            &ChainId::mainnet().id(),
        );
        h.run_transaction_payload_mainnet(&account, script)
    } else {
        h.run_transaction_payload(&account, script)
    }
}
```

**File:** aptos-move/e2e-move-tests/src/tests/metadata.rs (L306-309)
```rust
    assert_vm_status!(
        test_compilation_metadata_script_internal(true, true),
        StatusCode::UNSTABLE_BYTECODE_REJECTED
    );
```
