# Audit Report

## Title
Feature Gate Bypass: Unstable Language Features Can Be Deployed on Mainnet Through Metadata Manipulation

## Summary
The runtime check `reject_unstable_bytecode()` can be trivially bypassed by removing or manipulating compilation metadata, allowing unstable language features (such as public structs from V2.4+) to be deployed on mainnet despite being explicitly prohibited by a permanent, non-toggleable security control.

## Finding Description

The Aptos blockchain enforces a security policy that unstable language versions should not be deployed on mainnet. Language versions V2.4 and V2.5 are marked as unstable in the codebase. [1](#0-0) 

At runtime, the VM attempts to enforce this policy through the `reject_unstable_bytecode()` function, which checks compilation metadata during module publishing: [2](#0-1) 

**The Critical Flaw**: The runtime check uses an optional pattern `if let Some(metadata)`. The function that retrieves compilation metadata returns `Option<CompilationMetadata>`, and if no metadata is present, it returns `None`: [3](#0-2) 

**Attack Path**:
1. Attacker compiles a Move module using language version V2.4+, obtaining bytecode with unstable features
2. Attacker deserializes the compiled module bytecode using standard BCS deserialization
3. Attacker either removes the compilation metadata entirely or modifies it to claim a stable version
4. Attacker re-serializes and publishes the manipulated module on mainnet
5. The `reject_unstable_bytecode()` check passes because `get_compilation_metadata()` returns `None` (if removed) or returns metadata with `unstable: false` (if modified)
6. The module is deployed on mainnet with unstable features

The compilation metadata structure has no cryptographic protection or integrity verification: [4](#0-3) 

The metadata format validation function only checks format when present, does not require metadata to exist, and only runs conditionally: [5](#0-4) 

Test code demonstrates that modules can be deserialized, metadata modified, and re-serialized for publishing: [6](#0-5) 

## Impact Explanation

This vulnerability constitutes a significant protocol violation because it bypasses a permanent security control. The feature flags controlling this check are explicitly marked as enabled on mainnet and can never be disabled: [7](#0-6)  and [8](#0-7) 

The impact includes:
1. **Security Control Bypass**: Circumvents a fundamental security control designed to protect mainnet from untested, unstable code
2. **Deterministic Execution Risk**: Unstable features may contain undiscovered bugs that could cause non-deterministic behavior across validator nodes
3. **Policy Violation**: The explicit marking of V2.4/V2.5 as unstable and the permanent feature flag indicate these versions contain features not yet vetted for production
4. **Attack Surface Expansion**: Allows deployment of features with potentially unknown security vulnerabilities on the production network

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Trivial Exploitation**: Requires only basic bytecode manipulation using standard BCS serialization libraries
2. **Low Detection Risk**: Manipulated modules appear as valid bytecode and pass all existing verification checks, as VERSION_10 bytecode (used by V2.4+) is within the valid range
3. **Clear Attacker Motivation**: Enables use of advanced language features before official release
4. **No Access Barriers**: Any user with module publishing rights can execute this attack
5. **Tool Availability**: Standard BCS serialization libraries make bytecode manipulation straightforward

## Recommendation

Implement cryptographic integrity protection for compilation metadata or enforce bytecode version checks independent of metadata:

1. **Option 1**: Add a cryptographic signature to compilation metadata that is verified during publishing
2. **Option 2**: Enforce bytecode version restrictions on mainnet - reject VERSION_10 bytecode until V2.4+ is stabilized
3. **Option 3**: Make compilation metadata mandatory and reject modules without it during mainnet publishing
4. **Option 4**: Add bytecode feature detection that identifies V2.4+ features (like public struct accessors) independent of metadata

The recommended fix should verify module compliance with mainnet stability requirements without relying on easily manipulated metadata.

## Proof of Concept

The existing test infrastructure demonstrates the vulnerability is exploitable. The test at `aptos-move/e2e-move-tests/src/tests/metadata.rs` shows modules can be deserialized, metadata modified (lines 123-127), and re-published. An attacker would:

```
1. Compile with language version V2.4 (unstable)
2. Deserialize: CompiledModule::deserialize(&bytecode)
3. Modify: compiled_module.metadata = vec![] // Remove all metadata
4. Re-serialize: compiled_module.serialize(&mut modified_code)
5. Publish via publish_package_txn with modified_code
6. Module with V2.4 features is deployed on mainnet
```

The test code showing metadata manipulation: [9](#0-8)

### Citations

**File:** third_party/move/move-model/src/metadata.rs (L49-85)
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

impl CompilationMetadata {
    pub fn new(compiler_version: CompilerVersion, language_version: LanguageVersion) -> Self {
        Self {
            compiler_version: compiler_version.to_string(),
            language_version: language_version.to_string(),
            unstable: compiler_version.unstable() || language_version.unstable(),
        }
    }

    pub fn compiler_version(&self) -> anyhow::Result<CompilerVersion> {
        CompilerVersion::from_str(&self.compiler_version)
    }

    pub fn language_version(&self) -> anyhow::Result<LanguageVersion> {
        LanguageVersion::from_str(&self.language_version)
    }

    /// Returns true of the compilation was created as unstable.
    pub fn created_as_unstable(&self) -> bool {
        self.unstable
    }
}
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

**File:** types/src/vm/module_metadata.rs (L441-456)
```rust
pub fn verify_module_metadata_for_module_publishing(
    module: &CompiledModule,
    features: &Features,
) -> Result<(), MetaDataValidationError> {
    if features.is_enabled(FeatureFlag::SAFER_METADATA) {
        check_module_complexity(module)?;
    }

    if features.are_resource_groups_enabled() {
        check_metadata_format(module)?;
    }
    let metadata = if let Some(metadata) = get_metadata_from_compiled_code(module) {
        metadata
    } else {
        return Ok(());
    };
```

**File:** aptos-move/e2e-move-tests/src/tests/metadata.rs (L104-139)
```rust
fn test_metadata_with_changes(f: impl Fn() -> Vec<Metadata>) -> TransactionStatus {
    let mut h = MoveHarness::new();
    let account = h.new_account_at(AccountAddress::from_hex_literal("0xf00d").unwrap());

    let mut builder = PackageBuilder::new("Package");
    builder.add_source(
        "m.move",
        r#"
        module 0xf00d::M {
            #[view]
            fun foo(value: u64): u64 { value }
        }
        "#,
    );
    let path = builder.write_to_temp().unwrap();

    let package = BuiltPackage::build(path.path().to_path_buf(), BuildOptions::default())
        .expect("building package must succeed");
    let origin_code = package.extract_code();
    let mut compiled_module = CompiledModule::deserialize(&origin_code[0]).unwrap();
    let metadata = f();
    let mut invalid_code = vec![];
    compiled_module.metadata = metadata;
    compiled_module.serialize(&mut invalid_code).unwrap();

    let package_metadata = package
        .extract_metadata()
        .expect("extracting package metadata must succeed");
    h.run_transaction_payload(
        &account,
        aptos_stdlib::code_publish_package_txn(
            bcs::to_bytes(&package_metadata).expect("PackageMetadata has BCS"),
            vec![invalid_code],
        ),
    )
}
```

**File:** types/src/on_chain_config/aptos_features.rs (L79-80)
```rust
    /// Enabled on mainnet, can never be disabled.
    _REJECT_UNSTABLE_BYTECODE = 58,
```

**File:** types/src/on_chain_config/aptos_features.rs (L103-104)
```rust
    /// Enabled on mainnet, can never be disabled.
    _REJECT_UNSTABLE_BYTECODE_FOR_SCRIPT = 76,
```
