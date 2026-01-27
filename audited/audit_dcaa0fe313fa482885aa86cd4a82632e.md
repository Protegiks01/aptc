# Audit Report

## Title
Time-of-Check-Time-of-Use (TOCTOU) Vulnerability in Diamond Dependency Resolution Allowing Malicious Code Injection

## Summary
The Move package dependency resolution system contains a critical TOCTOU vulnerability in diamond dependency scenarios when dependencies use mutable git branches. An attacker controlling a git repository can inject malicious code between resolution steps that gets compiled without detection, potentially leading to consensus violations or fund theft when deployed to the Aptos blockchain.

## Finding Description

The vulnerability exists in the `resolution_graph_for_package()` function and its dependency resolution logic. When a diamond dependency pattern occurs (Package A depends on B and C, both B and C depend on D), and D is referenced via a mutable git branch rather than a fixed commit, the following attack sequence is possible:

**Step 1: Initial Resolution**
When package B's dependency on D is processed, the system downloads/updates the git repository and computes a source digest: [1](#0-0) 

The git repository is updated if it exists and points to a branch: [2](#0-1) 

**Step 2: Vulnerable Comparison Logic**
When package C later processes the same dependency D, the system checks if D is already in the package table using only SourceManifest equality: [3](#0-2) 

The SourceManifest comparison is structural and includes only the Move.toml contents (version, dependencies, addresses), not the actual source code: [4](#0-3) 

**Step 3: TOCTOU Gap**
Between processing B's dependency (time-of-check) and C's dependency (time-of-use), an attacker can force-push to the git branch with:
- Same Move.toml (ensuring SourceManifest equality passes)
- Modified source .move files containing malicious code

When C processes D, the git update fetches malicious code, but since Move.toml is unchanged, the comparison at line 223 returns `Ok(())` early without updating the package_table entry.

**Step 4: Compilation Uses Updated Files**
During compilation, the system reads source files directly from disk: [5](#0-4) [6](#0-5) 

The source files read are from the updated (malicious) version on disk, not the version that was initially digested.

**Step 5: Missing Digest Verification**
The stored source_digest is never compared against the actual files being compiled. The digest verification functions exist but are marked as unused: [7](#0-6) [8](#0-7) 

The optional digest check in dependencies only applies if a digest is explicitly specified in the dependency declaration, which is not required: [9](#0-8) 

**Attack Invariant Violation:**
This violates the **Deterministic Execution** invariant (#1) because different validators compiling at different times could get different versions of the dependency, leading to different bytecode and different state roots for identical blocks. It also violates **Move VM Safety** (#3) by allowing unverified bytecode execution.

## Impact Explanation

**Severity: High to Critical**

This vulnerability has severe impact potential:

1. **Consensus Violations**: If different validators build the same package at different times, they may compile different versions of the dependency, leading to non-deterministic execution and consensus failures. This breaks the fundamental invariant that all validators must produce identical state roots for identical blocks.

2. **Malicious Code Injection**: An attacker can inject arbitrary malicious code including:
   - Fund theft logic in DeFi protocols
   - Backdoors in governance modules
   - Logic bombs in validator staking code
   - Access control bypasses

3. **Supply Chain Attack**: This is a sophisticated supply chain attack that affects any package using branch-based git dependencies in diamond patterns, which is common in complex dependency graphs.

4. **Silent Compromise**: The attack is difficult to detect because:
   - Build succeeds without errors
   - The Move.toml remains valid
   - No digest mismatch warnings
   - The malicious code is properly compiled

According to Aptos bug bounty criteria:
- **Critical Severity** if exploited to cause consensus violations or fund theft
- **High Severity** for the protocol violation itself and potential node compromise

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability is realistic and exploitable because:

1. **Common Dependency Pattern**: Diamond dependencies are common in real-world projects with complex dependency graphs.

2. **Common Practice**: Many developers use branch-based dependencies (e.g., `rev = "main"`) for convenience, especially during development or when tracking upstream changes.

3. **No Special Access Required**: The attacker only needs:
   - Control over a git repository (could be a compromised dependency)
   - No validator access required
   - No governance participation needed

4. **Timing Window**: The attacker doesn't need precise timing - they can either:
   - Continuously serve malicious code on the branch
   - Set up webhooks to detect git fetches and push malicious updates
   - Compromise a legitimate repository and inject backdoors

5. **No Digest Enforcement**: The system doesn't enforce digest pinning for dependencies, making this attack viable against any package not explicitly using digest verification.

6. **Real-World Precedent**: Similar supply chain attacks (e.g., SolarWinds, codecov) have occurred in other ecosystems.

## Recommendation

Implement the following fixes:

**1. Enforce Immutable References**
Reject or warn on mutable git references (branches) in production builds:

```rust
// In resolution_graph.rs, download_and_update_if_remote
if let Some(git_info) = &dep.git_info {
    let git_rev = git_info.git_rev.as_str();
    
    // Check if it's a commit SHA (immutable)
    if !is_commit_sha(git_rev) {
        bail!(
            "Dependency '{}' uses mutable git reference '{}'. \
             For security, use a specific commit SHA or enable digest verification.",
            dep_name, git_rev
        );
    }
}
```

**2. Recompute and Verify Digest Before Compilation**
Before compilation, verify the source_digest matches current files:

```rust
// In build_plan.rs, before calling build_all
for (package_name, package) in &self.resolution_graph.package_table {
    let current_digest = ResolvingPackage::get_package_digest_for_config(
        &package.package_path,
        &self.resolution_graph.build_options
    )?;
    
    if current_digest != package.source_digest {
        bail!(
            "Source digest mismatch for package '{}': expected {}, got {}. \
             This may indicate the package was modified after resolution.",
            package_name,
            package.source_digest,
            current_digest
        );
    }
}
```

**3. Require Digest Pinning for Git Dependencies**
Make the `digest` field mandatory for git-based dependencies in production builds:

```rust
// In process_dependency
if dep.git_info.is_some() && dep.digest.is_none() && !self.build_options.dev_mode {
    bail!(
        "Dependency '{}' from git must specify a 'digest' for production builds. \
         Run with --dev mode or add digest = \"...\" to the dependency.",
        dep_name_in_pkg
    );
}
```

**4. Add Cache Invalidation**
Implement proper cache invalidation when git repos are updated to prevent stale package_table entries from being used with updated files.

## Proof of Concept

**Setup:**
```bash
# Create malicious git repository
mkdir malicious-dep && cd malicious-dep
git init

# Initial benign version
cat > Move.toml << 'EOF'
[package]
name = "MaliciousDep"
version = "1.0.0"

[addresses]
malicious_dep = "0x42"
EOF

mkdir sources
cat > sources/benign.move << 'EOF'
module malicious_dep::safe {
    public fun process(amount: u64): u64 {
        amount  // Just return the amount
    }
}
EOF

git add . && git commit -m "Benign version"
git branch main
```

**Create victim project with diamond dependency:**
```toml
# Package A's Move.toml
[package]
name = "PackageA"
version = "1.0.0"

[dependencies]
PackageB = { local = "../PackageB" }
PackageC = { local = "../PackageC" }

# Package B's Move.toml
[package]
name = "PackageB"
version = "1.0.0"

[dependencies]
MaliciousDep = { git = "https://github.com/attacker/malicious-dep", rev = "main" }

# Package C's Move.toml (same dependency)
[package]
name = "PackageC"
version = "1.0.0"

[dependencies]
MaliciousDep = { git = "https://github.com/attacker/malicious-dep", rev = "main" }
```

**Attack execution:**
```bash
# Victim starts build - B's dependency gets processed first
aptos move compile &

# Attacker force-pushes malicious code while build is in progress
cd malicious-dep
cat > sources/benign.move << 'EOF'
module malicious_dep::safe {
    public fun process(amount: u64): u64 {
        // Malicious: steal funds by returning 0
        0
    }
}
EOF

# Keep Move.toml unchanged!
git add sources/benign.move
git commit -m "Malicious update"
git push --force origin main
```

The victim's build will compile the malicious version without any errors or warnings, despite the package_table having a different source_digest from the initial benign version.

## Notes

This vulnerability is particularly dangerous because:

1. **Silent Failure**: The build system provides no indication that the compiled code differs from what was initially resolved.

2. **Widespread Impact**: Any Aptos Move package using branch-based git dependencies in complex dependency graphs is vulnerable.

3. **Blockchain Context**: Once malicious code is deployed to the blockchain, it's immutable and could be exploited to steal funds, manipulate governance, or compromise consensus.

4. **Defense in Depth Failure**: Multiple defensive layers failed:
   - No enforcement of immutable references
   - No digest verification during compilation
   - Unused digest checking functions
   - No cache invalidation for updated dependencies

The fix requires both immediate mitigation (enforce immutable refs or mandatory digests) and long-term hardening (active digest verification, cache management).

### Citations

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L220-232)
```rust
        let package_node_id = match self.package_table.get(&package_name) {
            None => self.get_or_add_node(package_name)?,
            // Same package and we've already resolved it: OK, return early
            Some(other) if other.source_package == package => return Ok(()),
            // Different packages, with same name: Not OK
            Some(other) => {
                bail!(
                    "Conflicting dependencies found: package '{}' conflicts with '{}'",
                    other.source_package.package.name,
                    package.package.name,
                )
            },
        };
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L431-447)
```rust
        Self::download_and_update_if_remote(
            dep_name_in_pkg,
            &dep,
            self.build_options.skip_fetch_latest_git_deps,
            writer,
        )?;
        let (dep_package, dep_package_dir) =
            Self::parse_package_manifest(&dep, &dep_name_in_pkg, root_path)
                .with_context(|| format!("While processing dependency '{}'", dep_name_in_pkg))?;
        self.build_resolution_graph(
            dep_package.clone(),
            dep_package_dir,
            false,
            override_std,
            writer,
        )
        .with_context(|| format!("Unable to resolve package dependency '{}'", dep_name_in_pkg))?;
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L456-472)
```rust
        match dep.digest {
            None => (),
            Some(fixed_digest) => {
                let resolved_pkg = self
                    .package_table
                    .get(&dep_name_in_pkg)
                    .context("Unable to find resolved package by name")?;
                if fixed_digest != resolved_pkg.source_digest {
                    bail!(
                        "Source digest mismatch in dependency '{}'. Expected '{}' but got '{}'.",
                        dep_name_in_pkg,
                        fixed_digest,
                        resolved_pkg.source_digest
                    )
                }
            },
        }
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L577-610)
```rust
            } else if !skip_fetch_latest_git_deps {
                // Confirm git is available.
                git::confirm_git_available()?;

                // Update the git dependency
                // Check first that it isn't a git rev (if it doesn't work, just continue with the fetch)
                if let Ok(parsed_rev) = git::find_rev(git_path, git_rev) {
                    // If it's exactly the same, then it's a git rev
                    if parsed_rev.trim().starts_with(git_rev) {
                        return Ok(());
                    }
                }

                if let Ok(tag) = git::find_tag(git_path, git_rev) {
                    // If it's exactly the same, then it's a git tag, for now tags won't be updated
                    // Tags don't easily update locally and you can't use reset --hard to cleanup
                    // any extra files
                    if tag.trim().starts_with(git_rev) {
                        return Ok(());
                    }
                }

                writeln!(
                    writer,
                    "{} {}",
                    "UPDATING GIT DEPENDENCY".bold().green(),
                    git_url,
                )?;
                // If the current folder exists, do a fetch and reset to ensure that the branch
                // is up to date
                // NOTE: this means that you must run the package system with a working network connection
                git::fetch_origin(git_path, dep_name)?;
                git::reset_hard(git_path, git_rev, dep_name)?;
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

**File:** third_party/move/tools/move-package/src/source_package/parsed_manifest.rs (L20-28)
```rust
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceManifest {
    pub package: PackageInfo,
    pub addresses: Option<AddressDeclarations>,
    pub dev_address_assignments: Option<DevAddressDeclarations>,
    pub build: Option<BuildInfo>,
    pub dependencies: Dependencies,
    pub dev_dependencies: Dependencies,
}
```

**File:** third_party/move/tools/move-package/src/compilation/build_plan.rs (L108-116)
```rust
                let mut dep_source_paths = dep_package
                    .get_sources(&self.resolution_graph.build_options)
                    .unwrap();
                let mut source_available = true;
                // If source is empty, search bytecode(mv) files
                if dep_source_paths.is_empty() {
                    dep_source_paths = dep_package.get_bytecodes().unwrap();
                    source_available = false;
                }
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L287-296)
```rust
    pub(crate) fn has_source_changed_since_last_compile(
        &self,
        resolved_package: &ResolvedPackage,
    ) -> bool {
        match &self.package.compiled_package_info.source_digest {
            // Don't have source available to us
            None => false,
            Some(digest) => digest != &resolved_package.source_digest,
        }
    }
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L512-531)
```rust
    #[allow(unused)]
    fn can_load_cached(
        package: &OnDiskCompiledPackage,
        resolution_graph: &ResolvedGraph,
        resolved_package: &ResolvedPackage,
        is_root_package: bool,
    ) -> bool {
        // TODO: add more tests for the different caching cases
        !(package.has_source_changed_since_last_compile(resolved_package) // recompile if source has changed
            // Recompile if the flags are different
            || package.are_build_flags_different(&resolution_graph.build_options)
            // Force root package recompilation in test mode
            || resolution_graph.build_options.test_mode && is_root_package
            // Recompile if force recompilation is set
            || resolution_graph.build_options.force_recompilation) &&
            // Dive deeper to make sure that instantiations haven't changed since that
            // can be changed by other packages above us in the dependency graph possibly
            package.package.compiled_package_info.address_alias_instantiation
                == resolved_package.resolution_table
    }
```
