# Audit Report

## Title
Arbitrary Upgrade Policy Safety Check Bypass Through Custom Dependency Resolution

## Summary
The `DownloadPackage::execute()` function includes a safety check that prevents downloading packages with `UpgradePolicy::arbitrary()`, but this check is completely absent in the `maybe_download_package()` function used during custom dependency resolution. This allows packages with arbitrary upgrade policies to be downloaded and used as dependencies, bypassing the intended security control.

## Finding Description

The Aptos CLI implements a critical safety check to prevent downloading packages with arbitrary upgrade policies, as these packages can be modified without compatibility checks and are considered unsafe dependencies. [1](#0-0) 

However, when packages are downloaded as custom dependencies during package resolution (using the `aptos = "node_url"` syntax in Move.toml), a different code path is executed through the `maybe_download_package()` function in the package hooks module: [2](#0-1) 

This function fetches and saves packages to disk without performing any upgrade policy validation. The safety check is completely absent, creating a direct bypass of the security control.

**Attack Path:**

1. A package with `UpgradePolicy::arbitrary()` exists on-chain (could be Genesis packages, test/dev environments, or packages at system addresses)
2. Attacker creates a malicious package B with a custom dependency on package A: `aptos = "https://node.url"` with the arbitrary package's address
3. Developer attempts to compile or test package B using `aptos move compile` or `aptos move test`
4. During dependency resolution, `download_and_update_if_remote()` calls `package_hooks::resolve_custom_dependency()` [3](#0-2) 

5. This invokes `maybe_download_package()` which downloads package A without any safety checks
6. The arbitrary policy package is now cached and used as a dependency, despite being explicitly blocked by the direct download path

**Additional Cache Manipulation Vector:**

The function also checks if a package already exists in the local cache by verifying the presence of `BuildInfo.path()`. If it exists, the download is skipped entirely, meaning even if a safety check were added later, pre-existing cached packages would bypass it. [4](#0-3) 

## Impact Explanation

**Severity: HIGH**

This vulnerability bypasses an explicit security control designed to protect developers from depending on unsafe packages. The impact qualifies as HIGH severity per the Aptos bug bounty criteria for "Significant protocol violations."

**Security Guarantees Broken:**

1. **Package Supply Chain Security**: The safety check exists to prevent developers from unknowingly depending on packages with arbitrary upgrade policies, which can be modified without compatibility checks
2. **Defense in Depth**: Creates an inconsistency where security controls apply to direct operations but not to indirect operations
3. **Malicious Code Injection Risk**: Arbitrary packages can be upgraded with completely different code, potentially introducing vulnerabilities or malicious functionality into dependent projects

While the Move framework's `publish_package()` function explicitly rejects arbitrary policies for normal users, the CLI should still defend against:
- Genesis packages that may have arbitrary policies
- Test/development networks with different rules  
- Packages at exempted system addresses (0x1-0xa)
- Future changes to on-chain policy enforcement [5](#0-4) 

The Move framework itself recognizes arbitrary packages at the same address are allowed as dependencies, but treats them specially: [6](#0-5) 

## Likelihood Explanation

**Likelihood: MEDIUM**

While packages with arbitrary upgrade policies are rare in production (due to `publish_package()` rejection), the likelihood is medium because:

1. **Realistic Scenarios Exist**: Genesis packages, system packages, and test/dev environments may have arbitrary policies
2. **Easy to Exploit**: Only requires creating a Move.toml with a custom dependency
3. **Unintentional Exposure**: Developers may not realize they're depending on arbitrary packages when compiling seemingly benign code
4. **No User Warning**: The bypass is silent - users receive no indication that the safety check was bypassed
5. **Persistent Cache**: Once downloaded, the package remains in the local cache for future use

## Recommendation

Add the same upgrade policy safety check to `maybe_download_package()` that exists in `DownloadPackage::execute()`:

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
        
        // ADD THIS CHECK
        if package.upgrade_policy() == UpgradePolicy::arbitrary() {
            bail!(
                "Package '{}' has upgrade policy 'arbitrary' and cannot be downloaded \
                as it is not safe to depend on such packages. Arbitrary packages can be \
                modified without compatibility checks.",
                info.package_name
            );
        }
        
        package.save_package_to_disk(info.download_to.as_path())
    } else {
        Ok(())
    }
}
```

Additionally, consider adding a warning when cached packages are used without re-validation, or implement periodic cache validation to ensure upgrade policies haven't changed.

## Proof of Concept

**Step 1: Verify the safety check exists in direct download**

```bash
# Attempt to download a package with arbitrary policy (would fail with the check)
aptos move download --account <ADDRESS_WITH_ARBITRARY_PACKAGE> --package <PACKAGE_NAME>
# Expected: Error "A package with upgrade policy `arbitrary` cannot be downloaded..."
```

**Step 2: Create a malicious package with custom dependency**

Create `Move.toml`:
```toml
[package]
name = "MaliciousPackage"
version = "1.0.0"

[dependencies]
AptosFramework = { git = "https://github.com/aptos-labs/aptos-framework.git", rev = "mainnet", subdir = "aptos-framework" }
ArbitraryPackage = { aptos = "https://fullnode.devnet.aptoslabs.com/v1", address = "<ADDRESS_WITH_ARBITRARY_PACKAGE>" }

[addresses]
malicious = "_"
```

**Step 3: Trigger the bypass**

```bash
# Compile the package - this will download ArbitraryPackage without safety checks
aptos move compile --package-dir <MALICIOUS_PACKAGE_DIR>
# Expected: Package downloads successfully, bypassing the arbitrary policy check
```

**Step 4: Verify the bypass**

The package would be downloaded to the cache location without any error, despite having an arbitrary upgrade policy. You can verify by checking:
```bash
ls -la ~/.move/on-chain/<ADDRESS_WITH_ARBITRARY_PACKAGE>/<PACKAGE_NAME>/
# BuildInfo and source files should exist
```

**Notes**

- This vulnerability represents an inconsistency in security controls between direct and indirect code paths
- The Move framework allows arbitrary packages as dependencies at the same address, but the CLI should consistently enforce its stricter policy across all download paths
- The safety check exists explicitly to protect developers from supply chain attacks, and bypassing it undermines that protection
- Even if currently rare, the code should defensively handle all cases where arbitrary packages might exist

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

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L612-614)
```rust
        if let Some(node_info) = &dep.node_info {
            package_hooks::resolve_custom_dependency(dep_name, node_info)?
        }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L171-174)
```text
        assert!(
            pack.upgrade_policy.policy > upgrade_policy_arbitrary().policy,
            error::invalid_argument(EINCOMPATIBLE_POLICY_DISABLED),
        );
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L320-325)
```text
                        if (dep_pack.upgrade_policy == upgrade_policy_arbitrary()) {
                            assert!(
                                dep.account == publish_address,
                                error::invalid_argument(EDEP_ARBITRARY_NOT_SAME_ADDRESS)
                            )
                        };
```
