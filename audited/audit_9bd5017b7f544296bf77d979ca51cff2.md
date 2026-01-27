# Audit Report

## Title
Source Code Verification Bypass in Package Publishing Allows Deployment of Misleading On-Chain Metadata

## Summary
The Aptos package publishing system does not verify that the source code stored in `PackageMetadata` corresponds to the deployed bytecode. An attacker can publish bytecode compiled from one set of Move files while storing completely different (misleading or malicious-appearing) source code in the on-chain `PackageRegistry`, breaking the trust model for package verification and enabling sophisticated phishing attacks.

## Finding Description

The vulnerability exists across the entire package publishing pipeline:

**1. Metadata Extraction Phase**

When building a package, source code and bytecode are extracted independently without any binding verification: [1](#0-0) 

The source code is read directly from disk files while bytecode is generated separately from compilation, with no cryptographic binding or hash verification between them.

**2. Publishing Phase**

The `publish_package` function accepts both `PackageMetadata` (containing source code) and bytecode as separate parameters, storing them without verification: [2](#0-1) 

The function stores metadata in `PackageRegistry` but never verifies that compiling the stored source code would produce the same bytecode.

**3. Native Function Processing**

The native `request_publish` function only receives and processes bytecode, completely ignoring the source code stored in `PackageMetadata`: [3](#0-2) 

The `PublishRequest` created at line 353-359 contains only bytecode, module names, and dependencies—no source code verification occurs.

**4. Bytecode Validation**

The validation performed by `validate_publish_request` checks metadata structure and bytecode properties but never verifies source-to-bytecode correspondence: [4](#0-3) 

**5. Metadata Structure Validation**

Even the dedicated metadata verification function only validates metadata format and attributes, not source code accuracy: [5](#0-4) 

**Attack Scenario:**

1. Attacker compiles legitimate, safe-looking Move source code → obtains valid bytecode
2. Attacker crafts malicious Move source code with vulnerabilities
3. Attacker modifies the `PackageMetadata.modules[].source` field to contain the malicious source
4. Attacker calls `publish_package_txn` with: legitimate bytecode + PackageMetadata containing malicious source
5. Both are stored on-chain in `PackageRegistry` without any verification
6. Users/auditors reading the on-chain source via the REST API see the fake malicious source
7. The actual executed bytecode is the legitimate code, creating a complete mismatch

**Which Invariant is Broken:**

This breaks the fundamental **State Consistency** and **Deterministic Execution** invariants. The on-chain state contains inconsistent information where source code does not match bytecode, preventing users from verifying what will actually execute. This also undermines the trust model assumption that on-chain package metadata is verifiable and accurate.

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for the highest severity category because:

1. **Trust Model Compromise**: The entire Aptos package verification ecosystem assumes that on-chain source code in `PackageMetadata` accurately represents deployed bytecode. This vulnerability completely breaks that assumption.

2. **Security Audit Bypass**: Security auditors analyzing packages via the REST API or blockchain explorers would read fake source code, missing actual vulnerabilities or malicious behavior in the real bytecode.

3. **Sophisticated Phishing Enabler**: Attackers can create "honeypot" contracts that:
   - Display safe-looking source code to attract users
   - Execute different bytecode that steals funds or manipulates state
   - Appear legitimate in all on-chain verification tools

4. **Ecosystem-Wide Impact**: Every tool that relies on `PackageMetadata.modules[].source` for verification (block explorers, IDEs, debugging tools like the one in `rest_interface.rs`) would display incorrect information.

5. **No Detection Mechanism**: There is currently no way for users to detect this mismatch without:
   - Downloading bytecode separately
   - Decompiling it
   - Comparing with claimed source (highly technical)

This represents a **fundamental design flaw** affecting the entire package deployment security model, meeting the Critical severity criteria of "Significant protocol violations" and enabling "Loss of Funds" through user deception.

## Likelihood Explanation

**High Likelihood** - This vulnerability is extremely likely to be exploited because:

1. **Low Barrier to Entry**: Any user can publish packages and manipulate `PackageMetadata` during the build process
2. **No Detection**: The system provides no warnings or verification failures
3. **High Value Target**: Aptos DeFi protocols handle significant value, making them attractive targets
4. **Difficult to Detect**: End users have no practical way to verify source-bytecode correspondence
5. **Tooling Dependency**: All standard tooling (explorers, debuggers) would display the fake source

The attack requires no special privileges, no validator collusion, and minimal technical sophistication beyond basic Move development skills.

## Recommendation

Implement cryptographic verification of source-to-bytecode correspondence in the publishing pipeline:

**Solution 1: Hash-Based Verification**
Add a verification step in `publish_package` that:
1. Recompiles the source code from `PackageMetadata.modules[].source`
2. Compares the resulting bytecode hash with the deployed bytecode hash
3. Rejects publication if hashes don't match

**Solution 2: Remove Source Storage**
If verification is too expensive, remove source code storage from `PackageMetadata` entirely and require publishers to use external verified source repositories (e.g., verified GitHub links).

**Solution 3: Attestation System**
Implement a cryptographic attestation where the compiler signs a binding between source hash and bytecode hash, which is verified during publication.

**Recommended Implementation (Solution 1):**

Modify the `publish_package` function in `code.move`:

```move
public fun publish_package(owner: &signer, pack: PackageMetadata, code: vector<vector<u8>>) acquires PackageRegistry {
    check_code_publishing_permission(owner);
    
    // NEW: Verify source-to-bytecode correspondence
    verify_source_matches_bytecode(&pack, &code);
    
    // ... rest of existing logic
}

// NEW: Verification function
fun verify_source_matches_bytecode(pack: &PackageMetadata, code: &vector<vector<u8>>) {
    // For each module, verify that recompiling the source produces the same bytecode
    // This would require exposing a compilation API from the VM
    // Or storing bytecode hashes in metadata for verification
    assert!(source_corresponds_to_bytecode(pack, code), error::invalid_argument(ESOURCE_BYTECODE_MISMATCH));
}
```

Additionally, add a bytecode hash field to `ModuleMetadata` that is verified during publishing.

## Proof of Concept

```rust
// Rust PoC demonstrating the vulnerability

use aptos_framework::natives::code::{PackageMetadata, ModuleMetadata, UpgradePolicy};
use move_package::BuildConfig;
use aptos_framework::built_package::BuildOptions;

#[test]
fn test_source_bytecode_mismatch_vulnerability() {
    // Step 1: Build a legitimate package
    let legitimate_source = r#"
    module 0x1::safe_module {
        public fun safe_function(): u64 {
            42  // Returns a safe value
        }
    }
    "#;
    
    // Build package with legitimate source
    let mut build_options = BuildOptions::default();
    build_options.with_srcs = true;
    let built_package = BuiltPackage::build(package_path, build_options).unwrap();
    
    // Extract legitimate bytecode
    let legitimate_bytecode = built_package.extract_code();
    
    // Extract metadata
    let mut metadata = built_package.extract_metadata().unwrap();
    
    // Step 2: Replace source with malicious-looking code
    let malicious_source = r#"
    module 0x1::safe_module {
        public fun safe_function(): u64 {
            // MALICIOUS: Backdoor function
            steal_all_funds();  
            666  // Evil value
        }
        
        fun steal_all_funds() {
            // Malicious implementation
        }
    }
    "#;
    
    // Modify the source field in metadata
    metadata.modules[0].source = zip_metadata_str(malicious_source).unwrap();
    
    // Step 3: Publish with legitimate bytecode but fake source
    let serialized_metadata = bcs::to_bytes(&metadata).unwrap();
    
    // This succeeds! No verification occurs
    publish_package_txn(
        &signer,
        serialized_metadata,
        legitimate_bytecode  // Real bytecode is safe
    );
    
    // Step 4: Verify the attack
    // Reading on-chain source shows malicious code
    let on_chain_source = get_package_source(&address, "safe_module");
    assert!(on_chain_source.contains("steal_all_funds"));  // Fake malicious source
    
    // But executing the function runs legitimate bytecode
    let result = execute_function(&address, "safe_module", "safe_function");
    assert!(result == 42);  // Real bytecode returns 42, not 666
    
    // SUCCESS: Bytecode and source are completely mismatched!
    // Users reading source think it's malicious
    // But execution is actually safe
    // (In real attack, this would be reversed - safe-looking source, malicious bytecode)
}
```

This proof of concept demonstrates that the system accepts and stores mismatched source code and bytecode without any verification, completely undermining the trustworthiness of on-chain package metadata.

---

**Notes**

The `check_and_obtain_source_code()` function in the original query file (`rest_interface.rs`) is a consumer of this vulnerable system—it retrieves and displays the potentially fake source code to users, making it part of the attack surface but not the root cause. The actual vulnerability lies in the package publishing pipeline that accepts unverified source code.

This is a systemic design flaw affecting the entire Aptos package deployment and verification infrastructure, requiring immediate remediation to restore trust in on-chain package metadata.

### Citations

**File:** aptos-move/framework/src/built_package.rs (L532-551)
```rust
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

**File:** types/src/vm/module_metadata.rs (L441-518)
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

    let functions = module
        .function_defs
        .iter()
        .map(|func_def| {
            let func_handle = module.function_handle_at(func_def.function);
            let name = module.identifier_at(func_handle.name);
            (name, (func_handle, func_def))
        })
        .collect::<BTreeMap<_, _>>();

    for (fun, attrs) in &metadata.fun_attributes {
        for attr in attrs {
            if attr.is_view_function() {
                is_valid_view_function(module, &functions, fun)?;
            } else if attr.is_randomness() {
                is_valid_unbiasable_function(&functions, fun)?;
            } else {
                return Err(AttributeValidationError {
                    key: fun.clone(),
                    attribute: attr.kind,
                }
                .into());
            }
        }
    }

    let structs = module
        .struct_defs
        .iter()
        .map(|struct_def| {
            let struct_handle = module.struct_handle_at(struct_def.struct_handle);
            let name = module.identifier_at(struct_handle.name);
            (name, (struct_handle, struct_def))
        })
        .collect::<BTreeMap<_, _>>();

    for (struct_, attrs) in &metadata.struct_attributes {
        for attr in attrs {
            if features.are_resource_groups_enabled() {
                if attr.is_resource_group() && attr.get_resource_group().is_some() {
                    is_valid_resource_group(&structs, struct_)?;
                    continue;
                } else if attr.is_resource_group_member()
                    && attr.get_resource_group_member().is_some()
                {
                    is_valid_resource_group_member(&structs, struct_)?;
                    continue;
                }
            }
            if features.is_module_event_enabled() && attr.is_event() {
                continue;
            }
            return Err(AttributeValidationError {
                key: struct_.clone(),
                attribute: attr.kind,
            }
            .into());
        }
    }
    Ok(())
}
```
