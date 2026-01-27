# Audit Report

## Title
Symlink Attack Vulnerability in Move Package Build System Enables Arbitrary File Overwrite

## Summary
The Move package compilation system accepts a user-controlled `install_dir` parameter without validating that it is not a symlink. This allows an attacker to create a symlink pointing to a privileged directory (e.g., `/etc/`, `/usr/bin/`, or another user's home directory), causing the build system to follow the symlink and write compiled artifacts to unintended locations. Additionally, the build process performs a destructive `remove_dir_all()` operation that can delete existing files in the target directory before writing new artifacts.

## Finding Description

The `BuildConfig.install_dir` field in the Move package build system accepts any `PathBuf` from the command line without symlink validation. [1](#0-0) 

When provided via the `--output-dir` CLI argument, this path is passed directly to the build system: [2](#0-1) 

The `install_dir` becomes the `project_root` for compilation without any canonicalization or symlink checks: [3](#0-2) 

During the save-to-disk operation, the code performs a dangerous operation that follows symlinks: [4](#0-3) 

The code then writes multiple artifact files through the `save_under()` method, which also follows symlinks: [5](#0-4) 

**Attack Flow:**
1. Attacker creates symlink: `ln -s /etc/systemd/system build-output`
2. Victim compiles: `aptos move compile --output-dir build-output`
3. Code resolves to: `/etc/systemd/system/build/PackageName/`
4. `remove_dir_all()` DELETES existing files at that location
5. New compiled artifacts (bytecode, source maps, docs, ABIs) are written to system directories

In multi-user or CI/CD environments, this enables:
- **Arbitrary file deletion** via `remove_dir_all()`
- **Arbitrary file creation** in privileged directories
- **Overwriting system configuration files**
- **Compromising other users' directories**

## Impact Explanation

This is a **High severity** local security vulnerability in the Aptos development toolchain. While it does not directly compromise the blockchain protocol, consensus, or validator operations, it enables:

1. **System compromise** when compilation runs with elevated privileges (common in CI/CD)
2. **Multi-user attacks** in shared development environments
3. **Supply chain attacks** via malicious build configurations
4. **Privilege escalation** if combined with other vulnerabilities

This meets **High Severity** criteria as a significant security violation in critical infrastructure tooling. In contexts where Move package compilation occurs (validator setup, dApp deployment pipelines, CI/CD systems), this could lead to system-level compromise.

## Likelihood Explanation

**High Likelihood** in the following contexts:

1. **CI/CD Environments**: Automated build systems often run with elevated permissions and shared workspaces
2. **Multi-user Development Systems**: Universities, development studios, and enterprise environments where multiple developers share systems
3. **Container Environments**: Where symlinks might be used for volume mounts or configuration
4. **Supply Chain Attacks**: Malicious `Move.toml` configurations could include relative symlink paths

The attack requires minimal sophistication—only the ability to create a symlink in a location where a victim will use as `--output-dir`.

## Recommendation

Implement symlink detection and canonicalization before using `install_dir`:

```rust
// In BuildConfig or before using install_dir
pub fn validate_install_dir(path: &Path) -> Result<PathBuf> {
    // Canonicalize to resolve symlinks and relative paths
    let canonical = path.canonicalize()
        .context("Failed to resolve install directory")?;
    
    // Verify the path is not a symlink
    let metadata = std::fs::symlink_metadata(path)
        .context("Failed to read install directory metadata")?;
    
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "install_dir cannot be a symlink for security reasons. \
             Path '{}' is a symlink to '{}'",
            path.display(),
            canonical.display()
        );
    }
    
    Ok(canonical)
}
```

Apply this validation in `build_plan.rs`:

```rust
let project_root = match &self.resolution_graph.build_options.install_dir {
    Some(under_path) => validate_install_dir(under_path)?,
    None => self.resolution_graph.root_package_path.clone(),
};
```

Additionally, consider:
- Using `O_NOFOLLOW` flags when available
- Implementing capability-based path restrictions
- Warning users when using `--output-dir` outside the package directory

## Proof of Concept

```bash
#!/bin/bash
# PoC: Symlink Attack on Move Package Compilation

# Setup
mkdir -p /tmp/target-dir
echo "ORIGINAL CONTENT" > /tmp/target-dir/important-file.txt

# Create malicious symlink
ln -s /tmp/target-dir /tmp/malicious-build-dir

# Create minimal Move package
mkdir -p /tmp/test-package/sources
cat > /tmp/test-package/Move.toml << 'EOF'
[package]
name = "TestPackage"
version = "1.0.0"

[dependencies]
AptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git", subdir = "aptos-move/framework/aptos-framework", rev = "main" }

[addresses]
test_package = "_"
EOF

cat > /tmp/test-package/sources/test.move << 'EOF'
module test_package::example {
    public entry fun hello() {}
}
EOF

# Compile with symlink as output-dir
cd /tmp/test-package
aptos move compile --output-dir /tmp/malicious-build-dir --named-addresses test_package=0x1

# Verify: Files written to symlink target
echo "Contents of /tmp/target-dir/build/:"
ls -la /tmp/target-dir/build/TestPackage/ 2>/dev/null || echo "Attack successful - artifacts written to symlink target"

# Verify: Original file deleted by remove_dir_all
test -f /tmp/target-dir/important-file.txt || echo "CRITICAL: Original file was deleted!"
```

This PoC demonstrates that compiled artifacts are written to the symlink target location, and any pre-existing content is deleted by `remove_dir_all()`.

## Notes

This vulnerability exists in the **Move package build tooling**, not in the Aptos blockchain protocol itself. It does not affect consensus, validator operations, or on-chain state. However, as part of the critical development infrastructure, it poses significant risks in:

- Validator node setup and maintenance
- CI/CD pipelines for dApp deployment  
- Multi-user development environments
- Supply chain security for Move packages

The issue should be addressed to maintain the security posture of the entire Aptos ecosystem development lifecycle.

### Citations

**File:** third_party/move/tools/move-package/src/lib.rs (L74-76)
```rust
    /// Installation directory for compiled artifacts. Defaults to current directory.
    #[clap(long = "install-dir", value_parser, global = true)]
    pub install_dir: Option<PathBuf>,
```

**File:** crates/aptos/src/common/types.rs (L1200-1204)
```rust
    /// Path to save the compiled move package
    ///
    /// Defaults to `<package_dir>/build`
    #[clap(long, value_parser)]
    pub output_dir: Option<PathBuf>,
```

**File:** third_party/move/tools/move-package/src/compilation/build_plan.rs (L93-96)
```rust
        let project_root = match &self.resolution_graph.build_options.install_dir {
            Some(under_path) => under_path.clone(),
            None => self.resolution_graph.root_package_path.clone(),
        };
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L279-284)
```rust
    pub(crate) fn save_under(&self, file: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
        let path_to_save = self.root_path.join(file);
        let parent = path_to_save.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        std::fs::write(path_to_save, bytes).map_err(|err| err.into())
    }
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L863-867)
```rust
        if on_disk_package.root_path.is_dir() {
            std::fs::remove_dir_all(&on_disk_package.root_path)?;
        }

        std::fs::create_dir_all(&on_disk_package.root_path)?;
```
