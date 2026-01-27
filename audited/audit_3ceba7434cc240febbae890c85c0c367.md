# Audit Report

## Title
Absolute Path Injection in Move Package Resolver Allowing Filesystem Access During Package Compilation

## Summary
The Move package resolver accepts absolute paths in local dependency declarations without validation, allowing an attacker to craft a malicious `Move.toml` that causes the compiler to attempt reading arbitrary filesystem locations when the package is compiled.

## Finding Description

The vulnerability exists in both the prototype `move-package-resolver` and the production `move-package` systems. When parsing local dependencies from `Move.toml`, the code accepts absolute paths without any security validation. [1](#0-0) 

The `local_str` from the manifest is directly converted to a `PathBuf` without checking if it's an absolute path. This path is then used in the resolution process: [2](#0-1) 

When `root_path.push(&dep.local)` is called with an absolute path, Rust's `PathBuf::push()` replaces the entire path rather than appending. This allows an attacker to specify any absolute filesystem path.

In contrast, the code properly validates absolute paths for git repository subdirectories: [3](#0-2) 

But fails to apply the same validation to local-to-local dependencies: [4](#0-3) 

**Attack Vector:**
1. Attacker creates a Move package with malicious `Move.toml`:
   ```toml
   [dependencies]
   MaliciousDep = { local = "/etc" }
   ```
2. Victim compiles the package via `aptos move compile`
3. Compiler attempts to read `/etc/Move.toml` or other sensitive paths
4. Error messages may leak filesystem information

## Impact Explanation

This vulnerability is assessed as **Medium severity** per Aptos bug bounty criteria, NOT Critical as initially labeled. While it represents a path traversal vulnerability, it has significant limitations:

**Why NOT Critical:**
- Does not achieve remote code execution on validator nodes
- Does not compromise consensus or cause fund loss
- Validators do not compile untrusted Move packages during normal operations
- Move package compilation occurs at development/build time, not at blockchain runtime

**Medium Severity Justification:**
- Information disclosure vulnerability that could expose filesystem structure
- Could leak sensitive configuration if developers/operators compile malicious packages on systems with elevated privileges
- Violates security boundaries and principle of least privilege
- Could be part of supply chain attacks targeting development infrastructure

The compilation process is used by the CLI tool invoked by developers: [5](#0-4) 

## Likelihood Explanation

**Moderate Likelihood:**
- Requires social engineering to trick a developer/operator into compiling malicious package
- Limited to build-time exploitation, not runtime validator operations
- Files must parse as valid Move.toml manifests to proceed beyond initial read
- Most restrictive: validators don't compile arbitrary packages during normal blockchain operations

The primary risk targets are development machines, CI/CD systems, or scenarios where validator operators might compile packages on infrastructure with access to sensitive files.

## Recommendation

Add validation to reject absolute paths in local dependencies, consistent with the existing protection for git repository subdirectories:

```rust
// In manifest_parser.rs, after line 346:
let local_path = PathBuf::from(local_str);
if local_path.is_absolute() {
    bail!("Local dependency paths cannot be absolute: {}", local_path.display());
}

// In resolver.rs, after line 329:
let dep_manifest_path = if local_path.is_absolute() {
    bail!("local dependency cannot be an absolute path: {}", local_path.display());
} else {
    parent_path.join(local_path)
};
```

Additionally, validate that relative paths don't escape the package root using normalized path checks similar to the git subdir validation.

## Proof of Concept

```rust
// Create a malicious Move.toml file:
// File: /tmp/malicious_package/Move.toml
[package]
name = "MaliciousPackage"
version = "0.0.0"

[dependencies]
EvilDep = { local = "/etc" }

// Compile the package:
// $ cd /tmp/malicious_package
// $ aptos move compile

// Expected behavior: Compilation should fail with absolute path rejection
// Actual behavior: Compiler attempts to read /etc/Move.toml and may leak
// filesystem information through error messages
```

## Notes

**Critical Limitation:** While this vulnerability exists in the codebase, it does NOT directly compromise validator node security during blockchain operations. The `move-package-resolver` code in question is prototype code that isn't actually used in production (only `move-package` is used, which has the same bug). More importantly, Move package compilation is a **build-time** operation performed by developers, not a **runtime** operation performed by validator nodes during consensus or transaction execution.

This finding fails the validation criterion: "Clear security harm demonstrated (funds, consensus, availability)" as it does not affect the running blockchain infrastructure, only development tooling. Therefore, despite the path traversal vulnerability existing in the code, it does not meet the threshold for a Critical or High severity validator node security issue as framed by the security question.

### Citations

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L342-354)
```rust
                (Some(local), None, None) => {
                    let local_str = local
                        .as_str()
                        .ok_or_else(|| format_err!("Local source path not a string"))?;
                    let local_path = PathBuf::from(local_str);
                    Ok(PM::Dependency {
                        subst,
                        version,
                        digest,
                        local: local_path,
                        git_info,
                        node_info,
                    })
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L504-516)
```rust
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

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L329-340)
```rust
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
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L359-363)
```rust
                if local_path.is_absolute() {
                    bail!(
                        "local dependency in a git repo cannot be an absolute path: {}",
                        local_path.display()
                    );
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
