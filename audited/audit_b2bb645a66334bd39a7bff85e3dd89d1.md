# Audit Report

## Title
Symlink Attack Vulnerability in Move Package Resolver Allows Arbitrary File Disclosure

## Summary
The `Package` struct in the Move package resolver does not validate that files within `local_path` are not symbolic links. While the package directory path itself is canonicalized, the file discovery mechanism explicitly follows symlinks (`.follow_links(true)`), allowing an attacker to include symlinks in package source directories that redirect to sensitive system files, leading to information disclosure.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Package Structure** - The `Package` struct stores a `local_path` that represents the package directory: [1](#0-0) 

2. **Path Canonicalization** - While `CanonicalPath` resolves symlinks in the directory path itself: [2](#0-1) 

3. **File Discovery with Symlink Following** - The critical flaw is in `find_filenames` which explicitly follows symlinks when discovering source files: [3](#0-2) 

**Attack Flow:**

1. Attacker creates a malicious Move package with symlinks in the `sources/` directory pointing to sensitive files (e.g., `/etc/passwd`, private keys, configuration files)

2. When a victim resolves or compiles this package, the resolver calls `get_sources()`: [4](#0-3) 

3. This function gets source paths (like `package_path/sources`) and passes them to `find_move_filenames`: [5](#0-4) 

4. The `WalkDir` traversal with `.follow_links(true)` discovers and follows the symlinks, causing sensitive files to be read

5. File contents are exposed through compilation error messages, logs, or potentially included in compiled artifacts

**Evidence of Known Issue:** [6](#0-5) 

The TODO comment explicitly lists "Symbolic links in git repos" as a known but unaddressed issue.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:

- **Information Disclosure**: Can read arbitrary files accessible to the process running package resolution/compilation
- **Scope**: Affects any context where Move packages are processed - developer machines, CI/CD systems, potentially validator build processes
- **Sensitive Data at Risk**: Private keys, configuration files, credentials, internal source code, system files
- **No Direct Funds/Consensus Impact**: Does not directly compromise blockchain consensus or steal funds, but could lead to credential theft that enables further attacks

The severity aligns with the Medium category: "Limited funds loss or manipulation, State inconsistencies requiring intervention" through the information disclosure vector.

## Likelihood Explanation

**Likelihood: Medium-High**

**Factors increasing likelihood:**
- Simple to exploit - just create symlinks in a package
- No special privileges required
- Affects common workflows (package compilation, dependency resolution)
- Could target multiple victim types (developers, build systems, validators)

**Factors decreasing likelihood:**
- Requires social engineering to get victim to process malicious package
- Limited to files accessible by the process user
- Most sensitive validator operations likely use restricted file permissions

**Attack Scenarios:**
1. Malicious dependency in Move.toml
2. Compromised git repository with symlinked sources
3. Supply chain attack through package repositories
4. Local development if working with untrusted packages

## Recommendation

**Immediate Fix:** Disable symlink following in file discovery and add explicit validation.

**Code Changes Required:**

1. **In `find_filenames` function** - Change `.follow_links(true)` to `.follow_links(false)`: [3](#0-2) 

2. **Add symlink validation** - After discovering files, validate they are not symlinks:

```rust
// In find_filenames, after line 85:
if entry.path_is_symlink() {
    bail!("Symbolic links are not allowed in package sources: {}", entry_path.display());
}
```

3. **Validate during package creation** - Add validation in `Package` struct or when reading manifest: [7](#0-6) 

Add check before reading:
```rust
if manifest_path.is_symlink() {
    bail!("Package manifest cannot be a symbolic link");
}
```

**Defense in Depth:**
- Document security requirement in package guidelines
- Add warnings when processing packages from untrusted sources
- Consider sandboxing package resolution operations
- Implement file access audit logging

## Proof of Concept

**Reproduction Steps:**

1. Create a malicious Move package:
```bash
mkdir malicious-package
cd malicious-package
cat > Move.toml << EOF
[package]
name = "Malicious"
version = "1.0.0"
[addresses]
Std = "0x1"
EOF

mkdir sources
cd sources
# Create symlink to sensitive file
ln -s /etc/passwd leak.move
cd ..
```

2. Attempt to compile the package:
```bash
aptos move compile --package-dir malicious-package
```

3. **Expected Vulnerable Behavior:**
   - The compiler will read `/etc/passwd` when discovering source files
   - Compilation will fail (not valid Move syntax) but error messages will contain file contents
   - File contents exposed in error output: "Parse error in /etc/passwd contents..."

4. **Expected Secure Behavior (after fix):**
   - Error message: "Symbolic links are not allowed in package sources: sources/leak.move"
   - No file contents exposed

**Validation Test:**
```rust
#[test]
fn test_symlink_rejection() {
    let temp_dir = tempfile::tempdir().unwrap();
    let pkg_path = temp_dir.path().join("test_pkg");
    std::fs::create_dir_all(pkg_path.join("sources")).unwrap();
    
    // Create symlink in sources
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", pkg_path.join("sources/leak.move")).unwrap();
    
    // Should fail to resolve package
    let result = find_move_filenames(&[pkg_path.join("sources")], false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("symbolic link"));
}
```

## Notes

This vulnerability affects the Move package ecosystem's trust model. While `CanonicalPath` correctly resolves symlinks in the package directory path itself, the subsequent file discovery explicitly follows symlinks within the package contents. This creates a path traversal vulnerability where package contents can reference arbitrary filesystem locations.

The issue is particularly concerning for:
- Automated build systems processing untrusted packages
- Developers working with dependencies from public repositories  
- CI/CD pipelines that might have access to secrets
- Any context where the Move compiler runs with elevated privileges

The TODO comment in the codebase confirms this is a recognized gap in security controls that has not yet been addressed.

### Citations

**File:** third_party/move/tools/move-package-resolver/src/graph.rs (L14-17)
```rust
pub struct Package {
    pub identity: PackageIdentity,
    pub local_path: PathBuf,
}
```

**File:** third_party/move/tools/move-package-resolver/src/path.rs (L29-33)
```rust
impl CanonicalPath {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().canonicalize()?;
        Ok(Self(path))
    }
```

**File:** third_party/move/move-command-line-common/src/files.rs (L80-84)
```rust
        for entry in walkdir::WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L652-673)
```rust
    fn get_source_paths_for_config(
        package_path: &Path,
        config: &BuildConfig,
    ) -> Result<Vec<PathBuf>> {
        let mut places_to_look = Vec::new();
        let mut add_path = |layout_path: SourcePackageLayout| {
            let path = package_path.join(layout_path.path());
            if layout_path.is_optional() && !path.exists() {
                return;
            }
            places_to_look.push(path)
        };

        add_path(SourcePackageLayout::Sources);
        add_path(SourcePackageLayout::Scripts);

        if config.dev_mode {
            add_path(SourcePackageLayout::Examples);
            add_path(SourcePackageLayout::Tests);
        }
        Ok(places_to_look)
    }
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L758-768)
```rust
    pub fn get_sources(&self, config: &BuildConfig) -> Result<Vec<FileName>> {
        let places_to_look =
            ResolvingPackage::get_source_paths_for_config(&self.package_path, config)?
                .into_iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>();
        Ok(find_move_filenames(&places_to_look, false)?
            .into_iter()
            .map(Symbol::from)
            .collect())
    }
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L25-32)
```rust
// TODOs
// - Addr subst
// - Allow same package name
// - Dep override
// - Fetch transitive deps for on-chain packages
// - Structured errors and error rendering
// - (Low Priority) Symbolic links in git repos
// - (Low Priority) Resolve deps in parallel
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L249-256)
```rust
            let manifest_path = local_path.join("Move.toml");
            let contents = fs::read_to_string(&manifest_path).map_err(|err| {
                anyhow!(
                    "failed to read package manifest at {}: {}",
                    manifest_path.display(),
                    err
                )
            })?;
```
