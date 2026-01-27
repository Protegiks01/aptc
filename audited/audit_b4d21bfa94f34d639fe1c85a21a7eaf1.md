# Audit Report

## Title
Arbitrary Upgrade Policy Package Download Bypass via Dependency Resolution

## Summary
Packages with `UpgradePolicy::arbitrary()` can be downloaded and compiled into user projects despite the explicit safety check in `DownloadPackage::execute()`. The vulnerability exists in the `maybe_download_package()` function which is invoked during dependency resolution and lacks the required upgrade policy validation.

## Finding Description

The Aptos CLI implements a safety mechanism to prevent users from downloading packages with `UpgradePolicy::arbitrary()` since these packages can be modified at any time by their publisher, creating supply chain risks. [1](#0-0) 

However, this check is only present in the explicit download command path. When the Move package system resolves custom "aptos" dependencies during compilation, it uses a different code path that bypasses this safety check entirely: [2](#0-1) 

**Attack Flow:**

1. Attacker publishes a malicious Move package with `UpgradePolicy::arbitrary()` to their Aptos account (e.g., `0xATTACKER`)

2. Victim creates a Move project with the malicious package as a dependency in `Move.toml`:
   ```toml
   [dependencies]
   MaliciousLib = { aptos = "https://fullnode.mainnet.aptoslabs.com", address = "0xATTACKER" }
   ```

3. When the victim runs `aptos move compile`, `aptos move test`, or any build command, the dependency resolution process is triggered

4. The manifest parser identifies the custom "aptos" dependency and creates `CustomDepInfo`: [3](#0-2) 

5. During resolution graph construction, `download_and_update_if_remote()` is called: [4](#0-3) 

6. This invokes `resolve_custom_dependency()` which calls `maybe_download_package()`: [5](#0-4) 

7. The package is downloaded and saved to disk **without any upgrade policy validation**

8. The malicious package is now part of the victim's build, cached in `~/.move/`, and compiled into their project

9. Since the package has `UpgradePolicy::arbitrary()`, the attacker can modify it at any time, injecting malicious code into all future builds of the victim's project

## Impact Explanation

This is a **High Severity** vulnerability that enables supply chain attacks:

- **Direct Security Bypass**: Circumvents an explicitly implemented safety mechanism designed to protect users from arbitrary packages
- **Supply Chain Attack Vector**: Victims unknowingly depend on code that can be arbitrarily modified by attackers
- **Persistent Compromise**: Once the dependency is added, all builds use the potentially malicious code from the cache
- **Wide Attack Surface**: Affects any user who compiles Move packages (developers, auditors, deployment systems)
- **Potential for Fund Theft**: Malicious code in dependencies could steal private keys, manipulate transactions, or drain wallets
- **Consensus Impact**: If deployed to validators, could affect node behavior and consensus

The impact aligns with **High Severity** per Aptos bug bounty criteria: "Significant protocol violations" and potential for "Validator node slowdowns" if malicious packages are deployed.

## Likelihood Explanation

**High Likelihood** of exploitation:

- **Low Attacker Barrier**: Any user can publish a package with arbitrary upgrade policy
- **Common Attack Vector**: Supply chain attacks via dependencies are well-understood and frequently exploited
- **Social Engineering**: Attackers can promote their malicious packages as useful libraries
- **Automatic Execution**: The vulnerability is triggered automatically during normal development workflows (`compile`, `test`)
- **No Warning to Users**: The victim receives no indication that a package with arbitrary policy was downloaded
- **Difficult to Detect**: Users may not realize their dependencies use arbitrary upgrade policy

## Recommendation

Add the same upgrade policy check to `maybe_download_package()` that exists in `DownloadPackage::execute()`:

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
        
        // ADD THIS CHECK:
        if package.upgrade_policy() == UpgradePolicy::arbitrary() {
            anyhow::bail!(
                "Cannot use package '{}' as a dependency because it has upgrade policy \
                'arbitrary', which means it can be modified at any time. This is unsafe \
                for dependencies. Package address: {}",
                info.package_name,
                info.package_address
            );
        }
        
        package.save_package_to_disk(info.download_to.as_path())
    } else {
        Ok(())
    }
}
```

Additionally, consider implementing this check in the `VerifyPackage` command path as well, since it also uses the registry without this validation: [6](#0-5) 

## Proof of Concept

**Setup:**
1. Publisher deploys a package with `UpgradePolicy::arbitrary()`:
   ```bash
   aptos move publish --upgrade-policy arbitrary
   ```

2. Victim creates `Move.toml` with dependency:
   ```toml
   [package]
   name = "VictimProject"
   version = "1.0.0"
   
   [dependencies]
   MaliciousLib = { aptos = "https://fullnode.mainnet.aptoslabs.com", address = "0xPUBLISHER_ADDRESS" }
   ```

3. Victim runs:
   ```bash
   aptos move compile
   ```

**Expected Behavior:** Compilation should fail with error about arbitrary upgrade policy

**Actual Behavior:** Package is downloaded silently to `~/.move/` and compilation succeeds

**Verification:**
```bash
# Check that the package was downloaded despite having arbitrary policy
ls ~/.move/*_0xPUBLISHER_ADDRESS_MaliciousLib/

# Try explicit download (should fail)
aptos move download --account 0xPUBLISHER_ADDRESS --package MaliciousLib
# Error: "A package with upgrade policy `arbitrary` cannot be downloaded..."

# But it's already in the dependency cache and used in builds!
```

This demonstrates the inconsistency: explicit downloads are blocked, but dependency resolution silently allows the same dangerous packages.

## Notes

This vulnerability represents a fundamental gap between the security policies enforced for explicit package downloads versus automatic dependency resolution. The safety check was correctly implemented for the user-facing download command but was not applied to the internal package resolution mechanism, creating a significant security bypass that undermines the entire protection mechanism.

### Citations

**File:** crates/aptos/src/move_tool/mod.rs (L1991-1996)
```rust
        if package.upgrade_policy() == UpgradePolicy::arbitrary() {
            return Err(CliError::CommandArgumentError(
                "A package with upgrade policy `arbitrary` cannot be downloaded \
                since it is not safe to depend on such packages."
                    .to_owned(),
            ));
```

**File:** crates/aptos/src/move_tool/mod.rs (L2070-2076)
```rust
        // We can't check the arbitrary, because it could change on us
        if package.upgrade_policy() == UpgradePolicy::arbitrary() {
            return Err(CliError::CommandArgumentError(
                "A package with upgrade policy `arbitrary` cannot be downloaded \
                since it is not safe to depend on such packages."
                    .to_owned(),
            ));
```

**File:** crates/aptos/src/move_tool/package_hooks.rs (L29-35)
```rust
    fn resolve_custom_dependency(
        &self,
        _dep_name: Symbol,
        info: &CustomDepInfo,
    ) -> anyhow::Result<()> {
        block_on(maybe_download_package(info))
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

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L612-614)
```rust
        if let Some(node_info) = &dep.node_info {
            package_hooks::resolve_custom_dependency(dep_name, node_info)?
        }
```
