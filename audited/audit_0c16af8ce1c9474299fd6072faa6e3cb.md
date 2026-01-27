# Audit Report

## Title
Path Traversal Vulnerability in Move Package Local Dependency Resolution Allows Arbitrary Filesystem Access

## Summary
The Move package manifest deserialization in `manifest.rs` accepts local dependency paths without validation, and the dependency resolver in `resolver.rs` fails to check for path traversal sequences when resolving local-to-local dependencies. This allows an attacker to craft malicious `Move.toml` files that escape the package directory and access arbitrary filesystem locations during package compilation.

## Finding Description

The vulnerability exists in the Move package dependency resolution system and manifests through two key components:

**1. Unrestricted Path Acceptance (manifest.rs)** [1](#0-0) 

At line 283, when deserializing a `Dependency` with a local path, the code directly accepts the `PathBuf` without any validation or sanitization. The path can contain arbitrary traversal sequences like `../../../etc`.

**2. Missing Path Traversal Validation (resolver.rs)** [2](#0-1) 

When both parent and child packages are local, the resolver joins the paths and calls `CanonicalPath::new()`, which only canonicalizes the path without checking if it escapes the package root: [3](#0-2) 

The `canonicalize()` method resolves `..` sequences but does NOT prevent them from escaping to parent directories. This is in stark contrast to the Git dependency case where explicit validation exists:

**3. Inconsistent Security Controls** [4](#0-3) 

When a parent is a Git dependency and child is local, the code explicitly checks for parent directory traversal and rejects paths that escape the repository root. This same protection is **completely absent** for local-to-local dependencies.

Similarly, for Git-to-Git dependencies: [5](#0-4) 

**4. Exploitation Path**

Once a malicious path is resolved, the system:
1. Reads `Move.toml` from the traversed directory
2. Uses `find_move_filenames` to recursively walk the directory [6](#0-5) 

The walkdir traversal with `follow_links(true)` will read all `.move` files from arbitrary filesystem locations.

## Impact Explanation

This vulnerability has **Medium** severity under the Aptos bug bounty criteria, though it's borderline as a developer tooling issue rather than direct blockchain runtime vulnerability:

**Direct Impacts:**
- **Information Disclosure**: Attackers can probe filesystem structure by observing which paths successfully canonicalize
- **Arbitrary File System Access**: If an attacker can place a valid `Move.toml` in a traversable location (e.g., `/tmp/malicious_package` referenced via `../../tmp/malicious_package`), the build system will read and compile arbitrary `.move` files from that location
- **Supply Chain Attack Vector**: Malicious packages distributed via package registries could exploit developer machines during compilation
- **CI/CD Compromise**: In automated build environments, this could access secrets, SSH keys, or other sensitive files if properly structured

**Blockchain-Specific Concerns:**
- **Validator Operator Risk**: If validator operators build untrusted Move packages, their systems could be compromised, indirectly affecting validator security
- **Deterministic Compilation Failure**: Different build environments might resolve paths differently, breaking reproducible builds
- **Package Verification Bypass**: Security audits of Move packages might miss malicious dependencies loaded via path traversal

However, this is primarily a **build-time vulnerability** affecting developers and operators, not a runtime blockchain consensus or execution vulnerability. It does not directly compromise on-chain funds, consensus safety, or Move VM execution integrity.

## Likelihood Explanation

**High Likelihood** for exploitation in practice:

1. **Easy to Exploit**: Requires only crafting a malicious `Move.toml` with `[dependencies] Evil = { local = "../../../target/path" }`
2. **Common Attack Vector**: Path traversal is a well-known vulnerability class
3. **Wide Distribution**: Malicious packages could be distributed via package repositories or social engineering
4. **No Authentication Required**: Any developer or CI/CD system building the package is vulnerable
5. **Silent Failure**: The vulnerability may go unnoticed until sensitive files are accessed

**Mitigating Factors:**
- Requires target path to contain a valid `Move.toml` or attacker control over accessible directories
- Most sensitive system files don't contain `Move.toml`, limiting immediate impact
- Primarily affects development/build environments rather than production blockchain nodes

## Recommendation

Implement the same path traversal validation for local-to-local dependencies that already exists for Git dependencies:

```rust
// In resolver.rs, lines 325-340, add validation after joining paths:
let dep_manifest_path = if local_path.is_absolute() {
    local_path
} else {
    parent_path.join(local_path)
};

// NEW: Validate the path doesn't escape using parent directories
let normalized_path = NormalizedPath::new(&dep_manifest_path);
if let Some(std::path::Component::ParentDir) = normalized_path.components().next() {
    bail!(
        "local dependency path escapes package root: {}",
        dep_manifest_path.display()
    );
}

let canonical_path = CanonicalPath::new(&dep_manifest_path).map_err(|err| {
    anyhow!(
        "failed to find package at {}: {}",
        dep_manifest_path.display(),
        err
    )
})?;
```

Additionally, consider:
1. **Reject absolute paths** for local dependencies entirely (already done for Git subdirs)
2. **Sandbox package resolution** to operate within a restricted directory
3. **Add security warnings** when building packages with unusual dependency paths
4. **Implement dependency pinning** with cryptographic verification

## Proof of Concept

```rust
// Create a test case in third_party/move/tools/move-package-resolver/tests/

#[test]
fn test_path_traversal_vulnerability() {
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;
    
    // Create temporary directories
    let root_dir = tempdir().unwrap();
    let root_path = root_dir.path();
    
    // Create a target directory outside the package root
    let target_dir = tempdir().unwrap();
    let target_path = target_dir.path();
    
    // Setup target with a valid Move.toml
    fs::write(
        target_path.join("Move.toml"),
        r#"
[package]
name = "MaliciousTarget"
version = "1.0.0"
        "#,
    ).unwrap();
    
    // Create a sources directory with a .move file
    fs::create_dir(target_path.join("sources")).unwrap();
    fs::write(
        target_path.join("sources/malicious.move"),
        "module MaliciousTarget::test { }"
    ).unwrap();
    
    // Calculate relative path from root to target using ../..
    let relative_traversal = calculate_traversal_path(root_path, target_path);
    
    // Create malicious Move.toml in root package
    fs::write(
        root_path.join("Move.toml"),
        format!(r#"
[package]
name = "RootPackage"
version = "1.0.0"

[dependencies]
MaliciousDep = {{ local = "{}" }}
        "#, relative_traversal),
    ).unwrap();
    
    fs::create_dir(root_path.join("sources")).unwrap();
    fs::write(
        root_path.join("sources/root.move"),
        "module RootPackage::main { }"
    ).unwrap();
    
    // Attempt to resolve dependencies
    // This SHOULD fail with a path traversal error, but currently succeeds
    let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let cache = PackageCache::new(...);
        let mut lock = PackageLock::new();
        resolve(&cache, &mut lock, root_path, false).await
    });
    
    // Currently, this assertion FAILS because the vulnerability allows traversal
    assert!(result.is_err(), "Path traversal should be rejected");
    assert!(result.unwrap_err().to_string().contains("escapes package root"));
}

fn calculate_traversal_path(from: &Path, to: &Path) -> String {
    // Calculate number of ../ needed to escape from 'from' to 'to'
    // Implementation details omitted for brevity
    // Returns something like "../../../tmp/target"
    unimplemented!()
}
```

## Notes

**Critical Context:**
This vulnerability exists in the **Move package build tooling**, not the blockchain runtime. While it represents a legitimate security issue for developers and CI/CD systems, it does not directly impact:
- Blockchain consensus safety
- On-chain Move VM execution
- Transaction validation or state management
- Validator node operation (unless they build untrusted packages)

The inconsistency in security controls—where Git dependencies have path traversal protection but local dependencies don't—indicates this was an oversight rather than an intentional design decision. The developers clearly understood the attack vector but failed to apply the same protection uniformly across all dependency types.

### Citations

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L258-317)
```rust
impl<'de> Deserialize<'de> for Dependency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawDependency::deserialize(deserializer)?;

        macro_rules! error_on_unneeded_fields {
            ($field_name:ident, $tag_name:ident) => {
                if (raw.$field_name.is_some() && raw.$tag_name.is_none()) {
                    return Err(serde::de::Error::custom(format!(
                        "redundant field \"{}\" -- only needed for \"{}\" dependencies",
                        stringify!($field_name),
                        stringify!($tag_name),
                    )));
                }
            };
        }

        error_on_unneeded_fields!(rev, git);
        error_on_unneeded_fields!(subdir, git);

        error_on_unneeded_fields!(address, aptos);

        let location = match (raw.local, raw.git, raw.aptos) {
            (Some(path), None, None) => PackageLocation::Local { path },
            (None, Some(url), None) => PackageLocation::Git {
                url,
                rev: raw.rev,
                subdir: raw.subdir,
            },
            (None, None, Some(node_url)) => match raw.address {
                Some(package_addr) => PackageLocation::Aptos {
                    node_url,
                    package_addr,
                },
                None => {
                    return Err(serde::de::Error::custom(
                        "missing field \"address\" for aptos dependency",
                    ))
                },
            },
            (None, None, None) => {
                return Err(serde::de::Error::custom(
                    "no package location specified for dependency",
                ));
            },
            _ => {
                return Err(serde::de::Error::custom(
                    "dependency cannot have have multiple locations",
                ));
            },
        };

        Ok(Dependency {
            version: raw.version,
            location,
        })
    }
}
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L325-349)
```rust
        PackageLocation::Local { path: local_path } => match &parent_identity.location {
            SourceLocation::Local { path: parent_path } => {
                // Both parent and child are local, so if the child's path is relative,
                // it is relative to the parent's path.
                let dep_manitest_path = if local_path.is_absolute() {
                    local_path
                } else {
                    parent_path.join(local_path)
                };
                let canonical_path = CanonicalPath::new(&dep_manitest_path).map_err(|err| {
                    anyhow!(
                        "failed to find package at {}: {}",
                        dep_manitest_path.display(),
                        err
                    )
                })?;

                let identity = PackageIdentity {
                    name: dep_name.to_string(),
                    location: SourceLocation::Local {
                        path: canonical_path,
                    },
                };

                (identity, None)
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L351-372)
```rust
            SourceLocation::Git {
                repo,
                commit_id,
                subdir,
            } => {
                // Parent is a git dependency while child is local.
                // This makes the child also a git dependency, with path relative to that of the
                // parent's in the same git repo.
                if local_path.is_absolute() {
                    bail!(
                        "local dependency in a git repo cannot be an absolute path: {}",
                        local_path.display()
                    );
                }

                let new_subdir = subdir.join(local_path);
                let normalized_new_subdir = NormalizedPath::new(&new_subdir);
                if let Some(std::path::Component::ParentDir) =
                    normalized_new_subdir.components().next()
                {
                    bail!("subdir outside of repo root: {}", new_subdir.display());
                }
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L387-399)
```rust
        PackageLocation::Git { url, rev, subdir } => {
            let commit_id = package_lock
                .resolve_git_revision(package_cache, &url, &rev.unwrap())
                .await?;

            let subdir = PathBuf::from_str(&subdir.unwrap_or(String::new()))?;
            if subdir.is_absolute() {
                bail!("subdir cannot be an absolute path: {}", subdir.display());
            }
            let normalized_subdir = NormalizedPath::new(&subdir);
            if let Some(std::path::Component::ParentDir) = normalized_subdir.components().next() {
                bail!("subdir outside of repo root: {}", subdir.display());
            }
```

**File:** third_party/move/tools/move-package-resolver/src/path.rs (L29-34)
```rust
impl CanonicalPath {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().canonicalize()?;
        Ok(Self(path))
    }
}
```

**File:** third_party/move/move-command-line-common/src/files.rs (L80-94)
```rust
        for entry in walkdir::WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let entry_path = entry.path();
            if !entry.file_type().is_file() || !is_file_desired(entry_path) {
                continue;
            }

            result.push(path_to_string(entry_path)?);
        }
    }
    Ok(result)
}
```
