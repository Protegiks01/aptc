# Audit Report

## Title
Circular Git Dependency DoS via Infinite Recursion in Move Package Resolution

## Summary
The `download_dependency_repos` function in the Move package system lacks circular dependency detection, allowing malicious packages with circular git dependencies to trigger infinite recursion and stack overflow, causing a complete denial of service of the Move build tools.

## Finding Description

The Move package system's dependency download mechanism contains a critical flaw in the `download_dependency_repos` function that processes git dependencies recursively without any cycle detection or visited package tracking. [1](#0-0) 

This function iterates through a package's dependencies, downloads each git repository, parses its manifest, and then recursively processes that dependency's own dependencies. However, it maintains no state tracking which packages have already been visited, leading to infinite recursion when circular dependencies exist.

The vulnerability is exposed through the public API: [2](#0-1) 

This is directly callable via the Move CLI: [3](#0-2) 

**Attack Scenario:**

1. Attacker creates Package A with a git dependency on Package B
2. Attacker creates Package B with a git dependency on Package A  
3. Both packages are published to accessible git repositories
4. When a user runs `move build --fetch-deps-only` on either package:
   - `download_dependency_repos(A)` is called
   - For dependency B: `download_and_update_if_remote(B)` clones B, then `download_dependency_repos(B)` is called
   - For dependency A: `download_and_update_if_remote(A)` clones A, then `download_dependency_repos(A)` is called
   - This continues infinitely: A → B → A → B → A...
   - Eventually causes stack overflow and crashes

While the git clone operation checks if repositories are already downloaded to prevent re-cloning: [4](#0-3) 

This only prevents duplicate git operations, not the recursive function calls. The recursion continues processing the same manifests repeatedly until stack exhaustion occurs.

**Key Difference from Normal Build Path:**

The normal build resolution path has cycle detection: [5](#0-4) 

However, `download_dependency_repos` is a separate code path that bypasses this protection entirely.

## Impact Explanation

**Severity: HIGH** (per Aptos bug bounty categories)

This vulnerability enables:

1. **Validator Node Slowdowns**: If validator operators use `move build --fetch-deps-only` on malicious packages during deployment or updates, the infinite recursion will crash their build tools, delaying node operations.

2. **API/Tool Crashes**: Any automated system or CI/CD pipeline that builds Move packages is vulnerable to crash attacks.

3. **Developer Disruption**: Developers attempting to build packages that transitively depend on malicious circular dependency packages will experience immediate crashes.

4. **Resource Exhaustion**: The stack overflow crash is deterministic and requires no special timing or race conditions.

The attack requires no privileged access and can be triggered by any user attempting to build or fetch dependencies for a package that includes the malicious circular dependency anywhere in its dependency tree.

## Likelihood Explanation

**Likelihood: HIGH**

- **Ease of Exploitation**: Trivial - attacker only needs to create two git repositories with circular dependencies
- **Attack Surface**: All Move package users and tooling exposed via `--fetch-deps-only` flag
- **No Prerequisites**: Requires no special permissions, just ability to publish git repositories
- **Detection Difficulty**: Users won't know packages contain circular dependencies until crash occurs
- **Reliability**: 100% reliable - infinite recursion always causes stack overflow

The vulnerability is particularly dangerous because:
- It's not caught during manifest validation
- Git repositories are commonly used for Move package dependencies
- Transitive dependencies can hide the malicious packages deep in dependency trees
- Automated build systems are highly vulnerable

## Recommendation

Add visited package tracking to `download_dependency_repos` to prevent reprocessing packages and detect circular dependencies:

```rust
pub fn download_dependency_repos<W: Write>(
    manifest: &SourceManifest,
    build_options: &BuildConfig,
    root_path: &Path,
    writer: &mut W,
) -> Result<()> {
    let mut visited = BTreeSet::new();
    Self::download_dependency_repos_impl(
        manifest,
        build_options,
        root_path,
        writer,
        &mut visited,
    )
}

fn download_dependency_repos_impl<W: Write>(
    manifest: &SourceManifest,
    build_options: &BuildConfig,
    root_path: &Path,
    writer: &mut W,
    visited: &mut BTreeSet<PackageName>,
) -> Result<()> {
    let empty_deps;
    let additional_deps = if build_options.dev_mode {
        &manifest.dev_dependencies
    } else {
        empty_deps = Dependencies::new();
        &empty_deps
    };

    for (dep_name, dep) in manifest.dependencies.iter().chain(additional_deps.iter()) {
        // Check if already processed to detect cycles
        if visited.contains(dep_name) {
            continue; // Skip already-processed packages
        }
        visited.insert(*dep_name);

        Self::download_and_update_if_remote(
            *dep_name,
            dep,
            build_options.skip_fetch_latest_git_deps,
            writer,
        )?;

        let (dep_manifest, _) =
            Self::parse_package_manifest(dep, dep_name, root_path.to_path_buf())
                .with_context(|| format!("While processing dependency '{}'", *dep_name))?;
        
        Self::download_dependency_repos_impl(
            &dep_manifest,
            build_options,
            root_path,
            writer,
            visited,
        )?;
    }
    Ok(())
}
```

Alternatively, reuse the existing cycle detection from `get_or_add_node` by building a dependency graph before downloading.

## Proof of Concept

**Setup:**

1. Create Package A (`/tmp/pkgA/Move.toml`):
```toml
[package]
name = "PackageA"
version = "1.0.0"

[dependencies]
PackageB = { git = "https://github.com/attacker/PackageB.git", rev = "main", subdir = "" }

[addresses]
PackageA = "0x1"
```

2. Create Package B (`/tmp/pkgB/Move.toml`):
```toml
[package]
name = "PackageB"
version = "1.0.0"

[dependencies]
PackageA = { git = "https://github.com/attacker/PackageA.git", rev = "main", subdir = "" }

[addresses]
PackageB = "0x2"
```

3. Publish both packages to git repositories

4. Execute:
```bash
cd /tmp/pkgA
move build --fetch-deps-only
```

**Expected Result:** Stack overflow crash:
```
thread 'main' has overflowed its stack
fatal runtime error: stack overflow
```

The recursion depth before crash depends on stack size but typically occurs within seconds.

## Notes

This vulnerability is distinct from the cycle detection in the normal build path. While `build_resolution_graph` properly detects cycles using petgraph algorithms, the `download_dependency_repos` function provides a separate entry point specifically for downloading dependencies that completely bypasses this protection. This creates a significant security gap where malicious packages can cause immediate DoS through a simple and reliable attack vector.

### Citations

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L480-497)
```rust
    fn get_or_add_node(&mut self, package_name: PackageName) -> Result<GraphIndex> {
        if self.graph.contains_node(package_name) {
            // If we encounter a node that we've already added we should check for cycles
            if algo::is_cyclic_directed(&self.graph) {
                // get the first cycle. Exists because we found a cycle above.
                let mut cycle = algo::kosaraju_scc(&self.graph)[0]
                    .iter()
                    .map(|node| node.as_str().to_string())
                    .collect::<Vec<_>>();
                // Add offending node at end to complete the cycle for display
                cycle.push(package_name.as_str().to_string());
                bail!("Found cycle between packages: {}", cycle.join(" -> "));
            }
            Ok(package_name)
        } else {
            Ok(self.graph.add_node(package_name))
        }
    }
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L519-549)
```rust
    pub fn download_dependency_repos<W: Write>(
        manifest: &SourceManifest,
        build_options: &BuildConfig,
        root_path: &Path,
        writer: &mut W,
    ) -> Result<()> {
        // include dev dependencies if in dev mode
        let empty_deps;
        let additional_deps = if build_options.dev_mode {
            &manifest.dev_dependencies
        } else {
            empty_deps = Dependencies::new();
            &empty_deps
        };

        for (dep_name, dep) in manifest.dependencies.iter().chain(additional_deps.iter()) {
            Self::download_and_update_if_remote(
                *dep_name,
                dep,
                build_options.skip_fetch_latest_git_deps,
                writer,
            )?;

            let (dep_manifest, _) =
                Self::parse_package_manifest(dep, dep_name, root_path.to_path_buf())
                    .with_context(|| format!("While processing dependency '{}'", *dep_name))?;
            // download dependencies of dependencies
            Self::download_dependency_repos(&dep_manifest, build_options, root_path, writer)?;
        }
        Ok(())
    }
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L551-616)
```rust
    fn download_and_update_if_remote<W: Write>(
        dep_name: PackageName,
        dep: &Dependency,
        skip_fetch_latest_git_deps: bool,
        writer: &mut W,
    ) -> Result<()> {
        if let Some(git_info) = &dep.git_info {
            let git_url = git_info.git_url.as_str();
            let git_rev = git_info.git_rev.as_str();
            let git_path = &git_info.download_to.display().to_string();

            // If there is no cached dependency, download it
            if !git_info.download_to.exists() {
                writeln!(
                    writer,
                    "{} {}",
                    "FETCHING GIT DEPENDENCY".bold().green(),
                    git_url,
                )?;

                // Confirm git is available.
                git::confirm_git_available()?;

                // If the cached folder does not exist, download and clone accordingly
                git::clone(git_url, git_path, dep_name)?;
                git::checkout(git_path, git_rev, dep_name)?;
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
        }
        if let Some(node_info) = &dep.node_info {
            package_hooks::resolve_custom_dependency(dep_name, node_info)?
        }
        Ok(())
    }
```

**File:** third_party/move/tools/move-package/src/lib.rs (L190-201)
```rust
    pub fn download_deps_for_package<W: Write>(&self, path: &Path, writer: &mut W) -> Result<()> {
        let path = SourcePackageLayout::try_find_root(path)?;
        let toml_manifest =
            self.parse_toml_manifest(path.join(SourcePackageLayout::Manifest.path()))?;
        let mutx = PackageLock::strict_lock();
        // This should be locked as it inspects the environment for `MOVE_HOME` which could
        // possibly be set by a different process in parallel.
        let manifest = manifest_parser::parse_source_manifest(toml_manifest)?;
        ResolutionGraph::download_dependency_repos(&manifest, self, &path, writer)?;
        mutx.unlock();
        Ok(())
    }
```

**File:** third_party/move/tools/move-cli/src/base/build.rs (L15-27)
```rust
    pub fn execute(self, path: Option<PathBuf>, config: BuildConfig) -> anyhow::Result<()> {
        let rerooted_path = reroot_path(path)?;
        if config.fetch_deps_only {
            let mut config = config;
            if config.test_mode {
                config.dev_mode = true;
            }
            config.download_deps_for_package(&rerooted_path, &mut std::io::stdout())?;
            return Ok(());
        }
        config.compile_package(&rerooted_path, &mut std::io::stdout())?;
        Ok(())
    }
```
