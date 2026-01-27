# Audit Report

## Title
Source Digest Verification Does Not Validate Bytecode Integrity - Supply Chain Attack Vector

## Summary
The Move package system's source digest verification provides a false sense of security. While it validates that source code is reproducible, it does NOT verify that published on-chain bytecode was actually compiled from the corresponding source code, creating a critical supply chain attack vector.

## Finding Description

The vulnerability exists in the disconnect between source code verification and bytecode publication. The attack flow proceeds as follows:

**Attack Preparation:**
1. Attacker creates legitimate Move source code and compiles it to obtain `source_digest_A` [1](#0-0) 

2. Attacker crafts malicious bytecode with identical module names and public API signatures, but backdoored implementation logic

3. Attacker publishes the malicious bytecode along with metadata containing `source_digest_A` and optionally empty source field [2](#0-1) 

**Publishing Validation Gap:**
The native publishing function accepts bytecode and metadata separately without cryptographic binding: [3](#0-2) 

The validation only checks:
- Module names match expected names
- Bytecode passes structural verification  
- Dependencies are allowed [4](#0-3) 

**No bytecode-to-source binding exists**. The `source_digest` field is stored in metadata but never validated against the actual published bytecode.

**Verification Bypass:**
When victims verify the package using `VerifyPackage`: [5](#0-4) 

The verification compares metadata fields including `source_digest`, but NOT the actual bytecode: [6](#0-5) 

If the attacker hosts matching source code externally (e.g., GitHub), victims who compile it will produce `source_digest_A`, and verification passes despite bytecode mismatch.

**Exploitation:**
Users who depend on the package will execute the malicious on-chain bytecode when interacting with it, while believing they've verified its integrity through source digest matching.

## Impact Explanation

**Critical Severity** - This breaks the fundamental security guarantee that "verified packages are safe to depend on."

The impact includes:
- **Loss of Funds**: Malicious bytecode can steal assets when invoked by victim contracts
- **State Manipulation**: Backdoored modules in critical infrastructure (governance, staking) could corrupt chain state
- **Supply Chain Compromise**: A single malicious dependency can compromise entire ecosystems

This qualifies as **Critical** under Aptos bug bounty criteria as it enables:
- Direct theft of funds through malicious move code execution
- Violation of the deterministic execution invariant (if different nodes trust different sources)
- Compromise of governance integrity if malicious packages are used in governance modules

## Likelihood Explanation

**Likelihood: Medium-High**

Factors increasing likelihood:
- Package source code being optional in metadata enables publishing without source [7](#0-6) 

- Developers commonly trust "verified" packages without auditing source code
- The attack requires moderate skill (bytecode crafting) but well-documented Move bytecode format makes this feasible
- No automated detection exists for bytecode-source mismatch

Factors decreasing likelihood:
- Manual bytecode crafting requires expertise in Move bytecode format
- Bytecode must pass comprehensive structural verification
- Suspicious packages (no source in metadata) may be avoided by cautious developers

## Recommendation

**Immediate Fix**: Implement cryptographic binding between source digest and bytecode by:

1. **Compute bytecode hash during compilation and include in metadata**:
```rust
// In built_package.rs extract_metadata()
let bytecode_digest = compute_bytecode_digest(&self.package.root_modules());
// Add bytecode_digest field to PackageMetadata
```

2. **Validate bytecode hash during publishing**:
```rust
// In aptos_vm.rs validate_publish_request()
fn validate_bytecode_matches_metadata(
    modules: &[CompiledModule],
    expected_digest: &str,
) -> VMResult<()> {
    let actual_digest = compute_bytecode_digest(modules);
    if actual_digest != expected_digest {
        return Err(metadata_validation_error(
            "Bytecode does not match claimed source digest"
        ));
    }
    Ok(())
}
```

3. **Enforce source code inclusion in metadata** for packages with non-arbitrary upgrade policy to enable verification.

4. **Update VerifyPackage to compare bytecode hashes** in addition to source digests.

**Long-term**: Consider requiring all published packages to include source code in metadata, or implement a trusted reproducible build service that verifies bytecode was correctly compiled from source.

## Proof of Concept

```move
// File: malicious_package/sources/token.move
// Legitimate-looking source code
module attacker::token {
    public fun transfer(from: &signer, to: address, amount: u64) {
        // Normal transfer logic
        // ... (compile to get source_digest_A)
    }
}

// Attacker manually crafts bytecode with:
// - Same module name: attacker::token  
// - Same public function: transfer(from: &signer, to: address, amount: u64)
// - Malicious implementation that backdoors to attacker's address
// - Passes bytecode verifier structural checks

// Publish:
// 1. Bytecode: malicious_crafted.mv
// 2. Metadata: { source_digest: "HASH_A", source: vec![] }
// 3. Host legitimate source on GitHub that compiles to HASH_A

// Victim verification:
// $ aptos move verify-package --account 0xAttacker
// > Compiles GitHub source -> produces HASH_A
// > Compares with on-chain metadata source_digest -> MATCH
// > "Successfully verified source of package" ✓
// > BUT on-chain bytecode is MALICIOUS

// Victim usage:
// module victim::defi {
//     use attacker::token;
//     public fun deposit(from: &signer, amount: u64) {
//         token::transfer(from, @defi_vault, amount); 
//         // Executes MALICIOUS bytecode, steals funds
//     }
// }
```

**Notes**

While the theoretical vulnerability exists, practical exploitation requires significant technical sophistication in Move bytecode manipulation. However, the lack of bytecode-to-source verification represents a critical gap in the package security model that violates the principle of cryptographic verifiability fundamental to blockchain systems.

The current design assumes compilation is deterministic and bytecode matches source, but provides no enforcement mechanism. This assumption breaks down when attackers can publish arbitrary bytecode with misleading metadata.

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

**File:** aptos-move/framework/aptos-framework/sources/code.move (L168-228)
```text
    public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) acquires PackageRegistry {
        check_code_publishing_permission(owner);
        // Disallow incompatible upgrade mode. Governance can decide later if this should be reconsidered.
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );

        let addr = signer::address_of(owner);
        if (!exists<PackageRegistry>(addr)) {
            move_to(owner, PackageRegistry { packages: vector::empty() })
        };

        // Checks for valid dependencies to other packages
        let allowed_deps = check_dependencies(addr, &pack);

        // Check package against conflicts
        // To avoid prover compiler error on spec
        // the package need to be an immutable variable
        let module_names = get_module_names(&pack);
        let package_immutable = &borrow_global<PackageRegistry>(addr).packages;
        let len = vector::length(package_immutable);
        let index = len;
        let upgrade_number = 0;
        vector::enumerate_ref(package_immutable
        , |i, old| {
            let old: &PackageMetadata = old;
            if (old.name == pack.name) {
                upgrade_number = old.upgrade_number + 1;
                check_upgradability(old, &pack, &module_names);
                index = i;
            } else {
                check_coexistence(old, &module_names)
            };
        });

        // Assign the upgrade counter.
        pack.upgrade_number = upgrade_number;

        let packages = &mut borrow_global_mut<PackageRegistry>(addr).packages;
        // Update registry
        let policy = pack.upgrade_policy;
        if (index < len) {
            *vector::borrow_mut(packages, index) = pack
        } else {
            vector::push_back(packages, pack)
        };

        event::emit(PublishPackage {
            code_address: addr,
            is_upgrade: upgrade_number > 0
        });

        // Request publish
        if (features::code_dependency_check_enabled())
            request_publish_with_allowed_deps(addr, module_names, allowed_deps, code, policy.policy)
        else
        // The new `request_publish_with_allowed_deps` has not yet rolled out, so call downwards
        // compatible code.
            request_publish(addr, module_names, code, policy.policy)
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1680-1739)
```rust
    fn validate_publish_request(
        &self,
        module_storage: &impl AptosModuleStorage,
        traversal_context: &mut TraversalContext,
        gas_meter: &mut impl GasMeter,
        modules: &[CompiledModule],
        mut expected_modules: BTreeSet<String>,
        allowed_deps: Option<BTreeMap<AccountAddress, BTreeSet<String>>>,
    ) -> VMResult<()> {
        self.reject_unstable_bytecode(modules)?;
        native_validation::validate_module_natives(modules)?;

        for m in modules {
            if !expected_modules.remove(m.self_id().name().as_str()) {
                return Err(Self::metadata_validation_error(&format!(
                    "unregistered module: '{}'",
                    m.self_id().name()
                )));
            }
            if let Some(allowed) = &allowed_deps {
                for dep in m.immediate_dependencies() {
                    if !allowed
                        .get(dep.address())
                        .map(|modules| {
                            modules.contains("") || modules.contains(dep.name().as_str())
                        })
                        .unwrap_or(false)
                    {
                        return Err(Self::metadata_validation_error(&format!(
                            "unregistered dependency: '{}'",
                            dep
                        )));
                    }
                }
            }
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
        }

        resource_groups::validate_resource_groups(
            self.features(),
            module_storage,
            traversal_context,
            gas_meter,
            modules,
        )?;
        event_validation::validate_module_events(
            self.features(),
            module_storage,
            traversal_context,
            modules,
        )?;

        if !expected_modules.is_empty() {
            return Err(Self::metadata_validation_error(
                "not all registered modules published",
            ));
        }
        Ok(())
    }
```

**File:** crates/aptos/src/move_tool/mod.rs (L2048-2084)
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
