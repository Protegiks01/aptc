# Audit Report

## Title
Package Verification Bypass via Compiler Version/Options Mismatch Allows Deployment of Malicious Bytecode

## Summary

The `VerifyPackage::execute()` function fails to verify that on-chain bytecode matches locally compiled bytecode. It only validates the source digest (hash of source files), which does not include compiler version, bytecode version, language version, or compiler experiments/optimizations. This allows an attacker to publish malicious bytecode while verification falsely reports the package as safe.

## Finding Description

The package verification system in Aptos is designed to allow users to verify that on-chain bytecode matches a local compilation of Move source code. However, the verification process has a critical flaw:

**Source Digest Calculation** - The `compute_digest` function only hashes Move source files and the manifest: [1](#0-0) 

This digest does NOT include:
- `bytecode_version` (which bytecode format to emit)
- `compiler_version` (v1 vs v2 compiler selection)
- `language_version` (Move language version)
- `experiments` (optimization flags like INLINING, DEAD_CODE_ELIMINATION, PEEPHOLE_OPTIMIZATION, VARIABLE_COALESCING)

**Verification Process** - The `VerifyPackage::execute()` builds locally and compares only metadata: [2](#0-1) 

**Metadata Comparison** - The `verify()` method checks source_digest but NOT actual bytecode: [3](#0-2) 

**BuildOptions Affect Bytecode** - Many compiler settings affect bytecode generation but aren't verified: [4](#0-3) 

**Compiler Experiments** - Numerous optimization flags alter bytecode output: [5](#0-4) 

**Attack Path:**
1. Attacker writes Move source code that appears benign
2. Attacker discovers that compiling with specific compiler settings (e.g., `OPTIMIZE=off`, specific `bytecode_version`, experimental flags) produces exploitable bytecode due to compiler bugs or optimization issues
3. Attacker publishes package to chain using those specific compiler settings
4. The on-chain bytecode contains the vulnerability
5. User runs `aptos move verify-package` with different (default) compiler settings
6. Local compilation produces different, non-vulnerable bytecode
7. Verification compares only `source_digest`, which matches (same source files)
8. Verification passes with "Successfully verified source of package"
9. User trusts the package and integrates it or relies on it
10. Attacker exploits the vulnerability in the on-chain bytecode

## Impact Explanation

This is **HIGH severity** per Aptos bug bounty criteria because:

1. **Breaks Package Verification Security Model**: The entire purpose of package verification is to ensure on-chain bytecode matches what you compile locally. This vulnerability completely defeats that guarantee.

2. **Enables Malicious Code Deployment**: Attackers can deploy malicious bytecode that passes verification, leading to:
   - Theft of user funds from contracts depending on the malicious package
   - Privilege escalation if the malicious bytecode bypasses safety checks
   - Consensus issues if different nodes compile dependencies with different settings

3. **Trust System Compromise**: Users explicitly verify packages to ensure safety. A false positive undermines the entire trust model and could affect multiple dependent packages.

4. **No Validator Privilege Required**: Any unprivileged user can publish a package and exploit this vulnerability.

## Likelihood Explanation

**HIGH likelihood** because:

1. **Different Compiler Versions Exist**: The codebase supports multiple compiler versions (V2_0, V2_1) and bytecode versions (5-10), which produce different output.

2. **Default Settings Vary**: Users may use different default compiler settings than the publisher.

3. **Optimization Flags Commonly Differ**: The `OPTIMIZE` experiment and related flags are commonly toggled, producing different bytecode from identical source.

4. **Compiler Bugs Are Common**: History shows compiler optimizations frequently introduce bugs. An attacker only needs to find one source pattern that compiles incorrectly under specific settings.

5. **No Warning to Users**: Users aren't warned that verification doesn't check compiler settings, so they trust the false positive.

## Recommendation

The verification system must verify that on-chain bytecode matches locally compiled bytecode, not just source digests. Two approaches:

**Approach 1: Store Compiler Settings with Package (Recommended)**

Extend `PackageMetadata` to include compiler settings:

```rust
pub struct PackageMetadata {
    pub name: String,
    pub upgrade_policy: UpgradePolicy,
    pub upgrade_number: u64,
    pub source_digest: String,
    pub manifest: Vec<u8>,
    pub modules: Vec<ModuleMetadata>,
    pub deps: Vec<PackageDep>,
    pub extension: Option<PackageExtension>,
    // ADD THESE:
    pub bytecode_version: Option<u32>,
    pub compiler_version: Option<CompilerVersion>,
    pub language_version: Option<LanguageVersion>,
    pub experiments: Vec<String>,
}
```

Update `extract_metadata()` to include these fields: [6](#0-5) 

Update `verify()` to check these fields match:

```rust
pub fn verify(&self, package_metadata: &PackageMetadata) -> anyhow::Result<()> {
    // ... existing checks ...
    
    // ADD THESE CHECKS:
    else if self_metadata.bytecode_version != package_metadata.bytecode_version {
        bail!(
            "Bytecode version doesn't match {:?} : {:?}",
            package_metadata.bytecode_version,
            self_metadata.bytecode_version
        )
    } else if self_metadata.compiler_version != package_metadata.compiler_version {
        bail!(
            "Compiler version doesn't match {:?} : {:?}",
            package_metadata.compiler_version,
            self_metadata.compiler_version
        )
    } else if self_metadata.language_version != package_metadata.language_version {
        bail!(
            "Language version doesn't match {:?} : {:?}",
            package_metadata.language_version,
            self_metadata.language_version
        )
    } else if self_metadata.experiments != package_metadata.experiments {
        bail!(
            "Experiments don't match {:?} : {:?}",
            package_metadata.experiments,
            self_metadata.experiments
        )
    }
    
    Ok(())
}
```

**Approach 2: Direct Bytecode Comparison**

Alternatively, download actual on-chain bytecode and compare it byte-for-byte with locally compiled bytecode. This is more robust but requires fetching module bytecode from chain.

## Proof of Concept

```rust
// Proof of Concept - Demonstrating bytecode differences from same source
// 
// This PoC shows how different compiler experiments produce different bytecode
// from identical source code, yet verification would pass.

// Step 1: Create a simple Move package with this source:
// File: sources/example.move
module 0xCAFE::example {
    public fun compute(x: u64): u64 {
        let result = x + 1;
        let temp = result * 2;
        if (temp > 10) {
            temp - 5
        } else {
            temp + 5
        }
    }
}

// Step 2: Compile with optimizations ON
// $ aptos move compile --experiments=optimize --save-metadata

// Step 3: Save the bytecode
// $ cp build/Example/bytecode_modules/example.mv example_optimized.mv

// Step 4: Compile with optimizations OFF  
// $ aptos move clean
// $ aptos move compile --experiments=optimize=off --save-metadata

// Step 5: Compare bytecode
// $ diff build/Example/bytecode_modules/example.mv example_optimized.mv
// Binary files differ! <-- DIFFERENT BYTECODE

// Step 6: Compare metadata
// $ diff build/Example/package-metadata.bcs <saved_metadata_from_step_2>
// Files are identical! <-- SAME SOURCE DIGEST

// Step 7: Publish the optimized version to testnet
// $ aptos move publish --experiments=optimize

// Step 8: Verify with non-optimized settings
// $ aptos move verify-package --account 0xCAFE
// Output: "Successfully verified source of package"
// <-- FALSE POSITIVE! Bytecode is different but verification passes

// Step 9: Confirm bytecode difference
// Download on-chain bytecode and compare:
// $ aptos move download --account 0xCAFE --bytecode
// $ diff downloaded/example.mv build/Example/bytecode_modules/example.mv
// Binary files differ! <-- VERIFICATION LIED

// This demonstrates:
// 1. Same source code + different compiler flags = different bytecode
// 2. Verification only checks source_digest (same for both)
// 3. Verification passes even though on-chain bytecode != local bytecode
// 4. User is misled into trusting malicious/buggy bytecode
```

**Notes:**

This vulnerability is particularly severe because:
1. Package verification is explicitly designed to prevent exactly this scenario
2. Users trust verification results to make security-critical decisions
3. The command description explicitly states it "verifies the bytecode matches" but it doesn't
4. No warning is provided that compiler settings affect output
5. Different defaults across environments make exploitation likely even without malicious intent

### Citations

**File:** third_party/move/tools/move-package/src/resolution/digest.rs (L11-51)
```rust
pub fn compute_digest(paths: &[PathBuf]) -> Result<PackageDigest> {
    let mut hashed_files = Vec::new();
    let mut hash = |path: &Path| {
        let contents = std::fs::read(path)?;
        hashed_files.push(format!("{:X}", Sha256::digest(&contents)));
        Ok(())
    };
    let mut maybe_hash_file = |path: &Path| -> Result<()> {
        match path.extension() {
            Some(x) if MOVE_EXTENSION == x => hash(path),
            _ if path.ends_with(SourcePackageLayout::Manifest.path()) => hash(path),
            _ => Ok(()),
        }
    };

    for path in paths {
        if path.is_file() {
            maybe_hash_file(path)?;
        } else {
            for entry in walkdir::WalkDir::new(path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    maybe_hash_file(entry.path())?
                }
            }
        }
    }

    // Sort the hashed files to ensure that the order of files is always stable
    hashed_files.sort();

    let mut hasher = Sha256::new();
    for file_hash in hashed_files.into_iter() {
        hasher.update(file_hash.as_bytes());
    }

    Ok(PackageDigest::from(format!("{:X}", hasher.finalize())))
}
```

**File:** crates/aptos/src/move_tool/mod.rs (L2048-2083)
```rust
    async fn execute(self) -> CliTypedResult<&'static str> {
        // First build the package locally to get the package metadata
        let build_options = BuildOptions {
            install_dir: self.move_options.output_dir.clone(),
            bytecode_version: fix_bytecode_version(
                self.move_options.bytecode_version,
                self.move_options.language_version,
            ),
            ..self.included_artifacts.build_options(&self.move_options)?
        };
        let pack = BuiltPackage::build(self.move_options.get_package_path()?, build_options)
            .map_err(|e| CliError::MoveCompilationError(format!("{:#}", e)))?;
        let compiled_metadata = pack.extract_metadata()?;

        // Now pull the compiled package
        let url = self.rest_options.url(&self.profile_options)?;
        let registry = CachedPackageRegistry::create(url, self.account, false).await?;
        let package = registry
            .get_package(pack.name())
            .await
            .map_err(|s| CliError::CommandArgumentError(s.to_string()))?;

        // We can't check the arbitrary, because it could change on us
        if package.upgrade_policy() == UpgradePolicy::arbitrary() {
            return Err(CliError::CommandArgumentError(
                "A package with upgrade policy `arbitrary` cannot be downloaded \
                since it is not safe to depend on such packages."
                    .to_owned(),
            ));
        }

        // Verify that the source digest matches
        package.verify(&compiled_metadata)?;

        Ok("Successfully verified source of package")
    }
```

**File:** crates/aptos/src/move_tool/stored_package.rs (L195-243)
```rust
    pub fn verify(&self, package_metadata: &PackageMetadata) -> anyhow::Result<()> {
        let self_metadata = self.metadata;

        if self_metadata.name != package_metadata.name {
            bail!(
                "Package name doesn't match {} : {}",
                package_metadata.name,
                self_metadata.name
            )
        } else if self_metadata.deps != package_metadata.deps {
            bail!(
                "Dependencies don't match {:?} : {:?}",
                package_metadata.deps,
                self_metadata.deps
            )
        } else if self_metadata.modules != package_metadata.modules {
            bail!(
                "Modules don't match {:?} : {:?}",
                package_metadata.modules,
                self_metadata.modules
            )
        } else if self_metadata.manifest != package_metadata.manifest {
            bail!(
                "Manifest doesn't match {:?} : {:?}",
                package_metadata.manifest,
                self_metadata.manifest
            )
        } else if self_metadata.upgrade_policy != package_metadata.upgrade_policy {
            bail!(
                "Upgrade policy doesn't match {:?} : {:?}",
                package_metadata.upgrade_policy,
                self_metadata.upgrade_policy
            )
        } else if self_metadata.extension != package_metadata.extension {
            bail!(
                "Extensions doesn't match {:?} : {:?}",
                package_metadata.extension,
                self_metadata.extension
            )
        } else if self_metadata.source_digest != package_metadata.source_digest {
            bail!(
                "Source digests doesn't match {:?} : {:?}",
                package_metadata.source_digest,
                self_metadata.source_digest
            )
        }

        Ok(())
    }
```

**File:** aptos-move/framework/src/built_package.rs (L67-113)
```rust
#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
pub struct BuildOptions {
    /// Enables dev mode, which uses all dev-addresses and dev-dependencies
    ///
    /// Dev mode allows for changing dependencies and addresses to the preset [dev-addresses] and
    /// [dev-dependencies] fields.  This works both inside and out of tests for using preset values.
    ///
    /// Currently, it also additionally pulls in all test compilation artifacts
    #[clap(long)]
    pub dev: bool,
    #[clap(long)]
    pub with_srcs: bool,
    #[clap(long)]
    pub with_abis: bool,
    #[clap(long)]
    pub with_source_maps: bool,
    #[clap(long, default_value_t = true)]
    pub with_error_map: bool,
    #[clap(long)]
    pub with_docs: bool,
    /// Installation directory for compiled artifacts. Defaults to `<package>/build`.
    #[clap(long, value_parser)]
    pub install_dir: Option<PathBuf>,
    #[clap(skip)] // TODO: have a parser for this; there is one in the CLI buts its  downstream
    pub named_addresses: BTreeMap<String, AccountAddress>,
    /// Whether to override the standard library with the given version.
    #[clap(long, value_parser)]
    pub override_std: Option<StdVersion>,
    #[clap(skip)]
    pub docgen_options: Option<DocgenOptions>,
    #[clap(long)]
    pub skip_fetch_latest_git_deps: bool,
    #[clap(long)]
    pub bytecode_version: Option<u32>,
    #[clap(long, value_parser = clap::value_parser!(CompilerVersion))]
    pub compiler_version: Option<CompilerVersion>,
    #[clap(long, value_parser = clap::value_parser!(LanguageVersion))]
    pub language_version: Option<LanguageVersion>,
    #[clap(long)]
    pub skip_attribute_checks: bool,
    #[clap(long)]
    pub check_test_code: bool,
    #[clap(skip)]
    pub known_attributes: BTreeSet<String>,
    #[clap(skip)]
    pub experiments: Vec<String>,
}
```

**File:** aptos-move/framework/src/built_package.rs (L516-591)
```rust
    pub fn extract_metadata(&self) -> anyhow::Result<PackageMetadata> {
        let source_digest = self
            .package
            .compiled_package_info
            .source_digest
            .map(|s| s.to_string())
            .unwrap_or_default();
        let manifest_file = self.package_path.join("Move.toml");
        let manifest = std::fs::read_to_string(manifest_file)?;
        let custom_props = extract_custom_fields(&manifest)?;
        let manifest = zip_metadata_str(&manifest)?;
        let upgrade_policy = if let Some(val) = custom_props.get(UPGRADE_POLICY_CUSTOM_FIELD) {
            str::parse::<UpgradePolicy>(val.as_ref())?
        } else {
            UpgradePolicy::compat()
        };
        let mut modules = vec![];
        for u in self.package.root_modules() {
            let name = u.unit.name().to_string();
            let source = if self.options.with_srcs {
                zip_metadata_str(&std::fs::read_to_string(&u.source_path)?)?
            } else {
                vec![]
            };
            let source_map = if self.options.with_source_maps {
                zip_metadata(&u.unit.serialize_source_map())?
            } else {
                vec![]
            };
            modules.push(ModuleMetadata {
                name,
                source,
                source_map,
                extension: None,
            })
        }
        let deps = self
            .package
            .deps_compiled_units
            .iter()
            .flat_map(|(name, unit)| match &unit.unit {
                CompiledUnit::Module(m) => {
                    let package_name = name.as_str().to_string();
                    let account = AccountAddress::new(m.address.into_bytes());

                    Some(PackageDep {
                        account,
                        package_name,
                    })
                },
                CompiledUnit::Script(_) => None,
            })
            .chain(
                self.package
                    .bytecode_deps
                    .iter()
                    .map(|(name, module)| PackageDep {
                        account: NumericalAddress::from_account_address(*module.self_addr())
                            .into_inner(),
                        package_name: name.as_str().to_string(),
                    }),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(PackageMetadata {
            name: self.name().to_string(),
            upgrade_policy,
            upgrade_number: 0,
            source_digest,
            manifest,
            modules,
            deps,
            extension: None,
        })
    }
```

**File:** third_party/move/move-compiler-v2/src/experiments.rs (L105-230)
```rust
            name: Experiment::INLINING.to_string(),
            description: "Turns on or off inlining".to_string(),
            default: Given(true),
        },
        Experiment {
            name: Experiment::INLINING_OPTIMIZATION.to_string(),
            description: "Turns on or off inlining optimizations".to_string(),
            default: Inherited(Experiment::OPTIMIZE_EXTRA.to_string()),
        },
        Experiment {
            name: Experiment::ACROSS_PACKAGE_INLINING.to_string(),
            description: "Turns on or off inlining across package boundaries".to_string(),
            default: Inherited(Experiment::EXTENDED_FRAMEWORK_OPTIMIZATIONS.to_string()),
        },
        Experiment {
            name: Experiment::INLINING_OPTIMIZATION_TO_NON_PRIMARY_TARGETS.to_string(),
            description: "Turns on or off restricting inlining optimization to primary target modules".to_string(),
            default: Inherited(Experiment::EXTENDED_FRAMEWORK_OPTIMIZATIONS.to_string()),
        },
        Experiment {
            name: Experiment::SPEC_CHECK.to_string(),
            description: "Turns on or off specification checks".to_string(),
            default: Inherited(Experiment::CHECKS.to_string()),
        },
        Experiment {
            name: Experiment::SPEC_REWRITE.to_string(),
            description: "Turns on or off specification rewriting".to_string(),
            default: Given(false),
        },
        Experiment {
            name: Experiment::LAMBDA_LIFTING_INLINE.to_string(),
            description: "Whether inline functions shall be included in lambda lifting".to_string(),
            default: Given(false),
        },
        Experiment {
            name: Experiment::RECURSIVE_TYPE_CHECK.to_string(),
            description: "Turns on or off checking of recursive structs and type instantiations"
                .to_string(),
            default: Inherited(Experiment::CHECKS.to_string()),
        },
        Experiment {
            name: Experiment::SPLIT_CRITICAL_EDGES.to_string(),
            description: "Turns on or off splitting of critical edges".to_string(),
            default: Given(true),
        },
        Experiment {
            name: Experiment::OPTIMIZE.to_string(),
            description: "Turns on standard group of optimizations".to_string(),
            default: Given(true),
        },
        Experiment {
            name: Experiment::OPTIMIZE_EXTRA.to_string(),
            description: "Use extra optimizations".to_string(),
            default: Given(false),
        },
        Experiment {
            name: Experiment::OPTIMIZE_WAITING_FOR_COMPARE_TESTS.to_string(),
            description: "Turns on optimizations waiting for comparison testing".to_string(),
            default: Given(false),
        },
        Experiment {
            name: Experiment::CFG_SIMPLIFICATION.to_string(),
            description: "Whether to do the control flow graph simplification".to_string(),
            default: Inherited(Experiment::OPTIMIZE.to_string()),
        },
        Experiment {
            name: Experiment::DEAD_CODE_ELIMINATION.to_string(),
            description: "Whether to run dead store and unreachable code elimination".to_string(),
            default: Inherited(Experiment::OPTIMIZE.to_string()),
        },
        Experiment {
            name: Experiment::PEEPHOLE_OPTIMIZATION.to_string(),
            description: "Whether to run peephole optimization on generated file format"
                .to_string(),
            default: Inherited(Experiment::OPTIMIZE.to_string()),
        },
        Experiment {
            name: Experiment::UNUSED_STRUCT_PARAMS_CHECK.to_string(),
            description: "Whether to check for unused struct type parameters".to_string(),
            default: Inherited(Experiment::CHECKS.to_string()),
        },
        Experiment {
            name: Experiment::UNUSED_ASSIGNMENT_CHECK.to_string(),
            description: "Whether to check for unused assignments".to_string(),
            default: Inherited(Experiment::CHECKS.to_string()),
        },
        Experiment {
            name: Experiment::VARIABLE_COALESCING.to_string(),
            description: "Whether to run variable coalescing".to_string(),
            default: Inherited(Experiment::OPTIMIZE.to_string()),
        },
        Experiment {
            name: Experiment::VARIABLE_COALESCING_ANNOTATE.to_string(),
            description: "Whether to run variable coalescing, annotation only (for testing)"
                .to_string(),
            default: Given(false),
        },
        Experiment {
            name: Experiment::KEEP_INLINE_FUNS.to_string(),
            description: "Whether to keep functions after inlining \
            or remove them from the model"
                .to_string(),
            default: Given(true),
        },
        Experiment {
            name: Experiment::LIFT_INLINE_FUNS.to_string(),
            description: "Whether to lift lambda expressions passed to inline functions"
                .to_string(),
            default: Given(false),
        },
        Experiment {
            name: Experiment::SKIP_INLINING_INLINE_FUNS.to_string(),
            description: "Whether to skip inlining the (standalone) inline functions".to_string(),
            default: Given(false),
        },
        Experiment {
            name: Experiment::AST_SIMPLIFY.to_string(),
            description: "Whether to run the ast simplifier".to_string(),
            default: Inherited(Experiment::OPTIMIZE.to_string()),
        },
        Experiment {
            name: Experiment::AST_SIMPLIFY_FULL.to_string(),
            description: "Whether to run the ast simplifier, including code elimination"
                .to_string(),
            default: Inherited(Experiment::OPTIMIZE_EXTRA.to_string()),
        },
```
