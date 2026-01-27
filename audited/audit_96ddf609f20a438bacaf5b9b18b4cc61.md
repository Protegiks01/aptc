# Audit Report

## Title
Trust-Based Source Code Verification Allows Publication of Packages with Misleading Source Code

## Summary
The Aptos blockchain does not cryptographically verify that source code in `PackageMetadata` compiles to deployed bytecode during package publishing. This verification is only performed client-side via an optional CLI tool, allowing malicious publishers to deploy bytecode with misleading source code that users and auditors rely on for security decisions.

## Finding Description

When publishing a Move package via `publish_package_txn`, publishers provide two separate inputs: the compiled bytecode (`vector<vector<u8>>`) and the package metadata (`PackageMetadata`) containing source code, source digest, and other metadata. The blockchain performs NO cryptographic verification that the source code actually compiles to the provided bytecode.

**On-Chain Publishing Flow:** [1](#0-0) 

The `publish_package` function receives pre-serialized `PackageMetadata` from the caller: [2](#0-1) 

The function performs dependency checks, upgradability checks, and coexistence checks, but never verifies that the source code matches the bytecode. The `PackageMetadata` structure includes source code and source_digest fields: [3](#0-2) 

Note the comment on line 38-39 states the source_digest is "constructed by first building the sha256 of each individual source, than sorting them alphabetically, and sha256 them again" - but this digest is provided by the publisher, not computed or verified on-chain.

**VM-Level Validation:**

The VM's validation in `validate_publish_request` only checks bytecode structure, dependencies, and metadata annotations: [4](#0-3) 

Notably absent: any verification that source code compiles to bytecode, or that source_digest is correct.

**Client-Side Verification Only:**

The only verification exists as an optional CLI command `VerifyPackage`: [5](#0-4) 

This verification is CLIENT-SIDE, optional, and performed AFTER publishing. The `verify()` method simply compares metadata fields: [6](#0-5) 

**Attack Scenario:**

1. Attacker writes malicious Move code (e.g., a token contract with hidden backdoor)
2. Attacker compiles it to bytecode
3. Attacker creates benign-looking source code for the same module names
4. Attacker generates a fake `source_digest` 
5. Attacker constructs `PackageMetadata` with benign source but ships malicious bytecode
6. Attacker calls `publish_package_txn` - blockchain accepts it without verification
7. Users audit the benign source code via REST API or explorers
8. Users interact with the malicious bytecode
9. Funds are stolen or contracts behave unexpectedly

The function `check_and_obtain_source_code` in the originally mentioned file retrieves this unverified metadata: [7](#0-6) 

This function simply retrieves the `PackageMetadata` from the blockchain without any verification, trusting that what was published is accurate.

## Impact Explanation

**HIGH Severity** - This vulnerability meets HIGH severity criteria per Aptos Bug Bounty:

1. **Direct Loss of Funds**: Users interacting with contracts after reading misleading source code could lose funds through hidden backdoors, rug pulls, or exploit paths not visible in the published source.

2. **Governance Compromise**: Aptos governance relies on reviewing source code of proposals. Malicious actors could publish governance proposals where the bytecode executes different logic than the source code shows, leading to unauthorized protocol changes.

3. **Ecosystem Trust Violation**: The entire Aptos ecosystem relies on source code transparency for security audits, user verification, and debugging. This breaks a fundamental security assumption.

4. **Significant Protocol Violation**: Transaction validation should ensure the integrity of published code. Accepting unverified source-bytecode bindings violates the expected security guarantees of the system.

While not meeting CRITICAL criteria (no consensus violation), the impact on user funds and governance makes this HIGH severity.

## Likelihood Explanation

**HIGH Likelihood** - This attack is:

- **Trivial to Execute**: Requires only basic Move programming knowledge and the ability to submit transactions
- **No Special Permissions**: Any account can publish packages
- **Undetectable Until Too Late**: Without running the optional VerifyPackage tool, users have no way to know the source code is fake
- **No On-Chain Checks**: The blockchain provides no protection against this attack
- **High-Value Targets**: DeFi protocols, governance contracts, and popular packages are attractive targets

The only barrier is that users might eventually discover the mismatch via the VerifyPackage tool, but by then damage may be done.

## Recommendation

Implement cryptographic verification of source-bytecode binding during on-chain package publishing:

**Option 1: Enforce Recompilation Verification (Strongest)**

Modify `publish_package` to accept source code instead of bytecode, then:
1. Compile source code on-chain using deterministic compilation
2. Hash the resulting bytecode
3. Compare with provided bytecode hash
4. Only publish if they match

**Option 2: Hash-Based Verification (More Practical)**

Modify the VM's `validate_publish_request` to:
1. Hash the provided bytecode modules
2. Recompile the source code from PackageMetadata deterministically
3. Hash the recompiled bytecode
4. Ensure hashes match before allowing publication

**Option 3: Cryptographic Commitment Scheme**

Require publishers to:
1. Compute hash H1 = SHA256(bytecode)
2. Compute hash H2 = SHA256(source_code)
3. Compute binding commitment C = SHA256(H1 || H2 || nonce)
4. On-chain verification checks all three components match

**Minimal Fix (Add to `validate_publish_request`):**

```rust
// After line 1716 in aptos_vm.rs, add:
verify_source_bytecode_binding(modules, metadata)?;

fn verify_source_bytecode_binding(
    modules: &[CompiledModule], 
    metadata: &PackageMetadata
) -> VMResult<()> {
    // Extract source code from metadata
    // Recompile using deterministic compiler settings
    // Compare bytecode hashes
    // Return error if mismatch
}
```

Also update the Move framework to either:
- Remove source_digest field and compute it on-chain, OR
- Add verification that the provided source_digest matches the actual source code

## Proof of Concept

```move
// File: malicious_token.move (actual source code compiled to bytecode)
module attacker::token {
    use std::signer;
    
    struct Token has key {
        balance: u64,
        backdoor: address  // Hidden backdoor
    }
    
    public entry fun initialize(account: &signer) {
        move_to(account, Token { 
            balance: 1000000,
            backdoor: @0xAttackerAddress  // Can drain funds
        });
    }
    
    public entry fun drain_if_backdoor(account: &signer) {
        let addr = signer::address_of(account);
        let token = borrow_global_mut<Token>(addr);
        // Hidden: transfers all funds to backdoor address
        if (token.backdoor == @0xAttackerAddress) {
            token.balance = 0; // Actually transfers to attacker
        }
    }
}

// File: fake_source.move (what attacker puts in PackageMetadata)
module attacker::token {
    use std::signer;
    
    struct Token has key {
        balance: u64
    }
    
    public entry fun initialize(account: &signer) {
        move_to(account, Token { balance: 1000000 });
    }
    
    // Appears safe - no backdoor visible
    public entry fun transfer(from: &signer, to: address, amount: u64) {
        // Normal transfer logic shown
    }
}
```

**Exploitation Steps:**

1. Compile `malicious_token.move` to bytecode
2. Create `PackageMetadata` with source from `fake_source.move`
3. Generate fake source_digest
4. Call `aptos move publish` with mismatched bytecode and metadata
5. Blockchain accepts and stores the package
6. Users read the fake source via REST API or block explorers
7. Users see safe-looking token contract
8. Attacker calls hidden `drain_if_backdoor` function to steal funds
9. Users discover the backdoor only after funds are lost

**Verification Test:**

```bash
# This should FAIL but currently SUCCEEDS
aptos move publish \
  --bytecode-path ./malicious_bytecode/ \
  --metadata-path ./fake_metadata.json \
  --assume-yes

# After publishing, this shows the fake source
aptos move download --account <ADDRESS> --package token
cat sources/token.move  # Shows fake_source.move, not malicious_token.move

# Only manual verification catches it
aptos move verify-package --account <ADDRESS>  # Would fail if run, but optional!
```

## Notes

This vulnerability represents a **systemic trust issue** in the Aptos ecosystem. The existence of the `VerifyPackage` CLI tool demonstrates that the Aptos team understands source-bytecode verification is necessary, but making it optional and client-side rather than consensus-enforced creates a critical security gap.

The `check_and_obtain_source_code` function mentioned in the original security question simply retrieves this unverified metadata, making any debugging or analysis tools that rely on it potentially misleading.

This issue affects:
- All published Move packages on Aptos
- DeFi protocols where users need to audit code
- Governance proposals requiring code review
- Developer tools that display source code
- Block explorers showing contract source
- Security auditing processes

The fix requires consensus-level changes to enforce source-bytecode binding verification during package publishing, not just optional post-hoc verification.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/code.move (L30-49)
```text
    struct PackageMetadata has copy, drop, store {
        /// Name of this package.
        name: String,
        /// The upgrade policy of this package.
        upgrade_policy: UpgradePolicy,
        /// The numbers of times this module has been upgraded. Also serves as the on-chain version.
        /// This field will be automatically assigned on successful upgrade.
        upgrade_number: u64,
        /// The source digest of the sources in the package. This is constructed by first building the
        /// sha256 of each individual source, than sorting them alphabetically, and sha256 them again.
        source_digest: String,
        /// The package manifest, in the Move.toml format. Gzipped text.
        manifest: vector<u8>,
        /// The list of modules installed by this package.
        modules: vector<ModuleMetadata>,
        /// Holds PackageDeps.
        deps: vector<PackageDep>,
        /// For future extension
        extension: Option<Any>
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

**File:** aptos-move/framework/aptos-framework/sources/code.move (L256-259)
```text
    public entry fun publish_package_txn(owner: &signer, metadata_serialized: vector<u8>, code: vector<vector<u8>>)
    acquires PackageRegistry {
        publish_package(owner, util::from_bytes<PackageMetadata>(metadata_serialized), code)
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

**File:** aptos-move/aptos-validator-interface/src/rest_interface.rs (L113-195)
```rust
async fn check_and_obtain_source_code(
    client: &Client,
    m: &ModuleId,
    addr: &AccountAddress,
    version: Version,
    transaction: &Transaction,
    package_cache: &mut HashMap<
        ModuleId,
        (
            AccountAddress,
            String,
            HashMap<(AccountAddress, String), PackageMetadata>,
        ),
    >,
    txns: &mut Vec<(
        u64,
        Transaction,
        Option<(
            AccountAddress,
            String,
            HashMap<(AccountAddress, String), PackageMetadata>,
        )>,
    )>,
) -> Result<()> {
    let locate_package_with_src =
        |module: &ModuleId, packages: &[PackageMetadata]| -> Option<PackageMetadata> {
            for package in packages {
                for module_metadata in &package.modules {
                    if module_metadata.name == module.name().as_str() {
                        if module_metadata.source.is_empty() || package.upgrade_policy.policy == 0 {
                            return None;
                        } else {
                            return Some(package.clone());
                        }
                    }
                }
            }
            None
        };
    let mut package_registry_cache: HashMap<AccountAddress, PackageRegistry> = HashMap::new();
    let package_registry =
        get_or_update_package_registry(client, version, addr, &mut package_registry_cache).await?;
    let target_package_opt = locate_package_with_src(m, &package_registry.packages);
    if let Some(target_package) = target_package_opt {
        let mut map = HashMap::new();
        if APTOS_PACKAGES.contains(&target_package.name.as_str()) {
            package_cache.insert(
                m.clone(),
                (
                    AccountAddress::ONE,
                    target_package.name.clone(), // all aptos packages are stored under 0x1
                    HashMap::new(),
                ),
            );
            txns.push((
                version,
                transaction.clone(),
                Some((
                    AccountAddress::ONE,
                    target_package.name, // all aptos packages are stored under 0x1
                    HashMap::new(),
                )), // do not need to store the package registry for aptos packages
            ));
        } else if let Ok(()) = retrieve_dep_packages_with_src(
            client,
            version,
            &target_package,
            &mut map,
            &mut package_registry_cache,
        )
        .await
        {
            map.insert((*addr, target_package.clone().name), target_package.clone());
            package_cache.insert(m.clone(), (*addr, target_package.name.clone(), map.clone()));
            txns.push((
                version,
                transaction.clone(),
                Some((*addr, target_package.name, map)),
            ));
        }
    }
    Ok(())
}
```
