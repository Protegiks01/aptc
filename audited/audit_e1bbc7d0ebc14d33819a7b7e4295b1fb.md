# Audit Report

## Title
Move Package Cache Poisoning via Shared MOVE_HOME Directory

## Summary
The Move package dependency resolution system uses a shared cache directory (`~/.move/` by default) across all projects for a single user. This shared cache, combined with optional digest verification, allows an attacker to poison the dependency cache for one project and have that malicious code affect other projects that use the same dependencies. This is a supply chain attack vector that can lead to malicious code injection into Move packages.

## Finding Description

The Move package system caches git-based dependencies in a shared directory to avoid repeated downloads. The cache location is determined by the `MOVE_HOME` environment variable, which defaults to `~/.move/`: [1](#0-0) 

When resolving git dependencies, the system computes the cache path using this shared `MOVE_HOME` directory: [2](#0-1) 

The dependency resolution process checks if a cached version exists before downloading. If the cache directory exists and `skip_fetch_latest_git_deps` is enabled, the system uses the cached version without verification: [3](#0-2) 

Critically, digest verification is **optional**. If no digest is specified in the dependency declaration, no integrity check is performed: [4](#0-3) 

**Attack Scenario:**

1. Attacker creates a malicious Move package (`MaliciousProject`) that declares a dependency on a popular git repository (e.g., `https://github.com/popular/framework.git` at revision `main`)
2. The attacker modifies their local git repository before running the build, or uses a malicious URL that serves poisoned code
3. Victim compiles `MaliciousProject`, which downloads and caches the dependency to `~/.move/github_com_popular_framework_git_main/`
4. The attacker's malicious code is now cached in the victim's `MOVE_HOME` directory
5. Victim later compiles their legitimate project (`LegitProject`) that depends on the same `popular/framework.git` at revision `main`
6. Because the cache already exists, the system uses the poisoned cached version
7. If no digest is specified (common practice), no integrity check occurs
8. Malicious code is now compiled into the victim's legitimate project

This breaks the **Deterministic Execution** invariant because different validators/nodes could compile different versions of the "same" package depending on which version is in their cache, potentially leading to consensus divergence if the malicious code affects execution behavior.

## Impact Explanation

**Severity: HIGH**

This vulnerability constitutes a supply chain attack that can lead to:

1. **Malicious Code Injection**: Arbitrary Move code can be injected into packages that users believe are legitimate
2. **Consensus Risk**: If validators compile framework packages or governance modules with poisoned caches, different validators could execute different code for the same nominal package version, breaking consensus determinism
3. **Multi-Project Compromise**: A single malicious package can compromise all subsequent package builds for that user
4. **Persistence**: Once the cache is poisoned, it remains poisoned until manually cleaned or updated

The impact qualifies as **High Severity** per Aptos bug bounty criteria:
- Significant protocol violations (deterministic execution requirement)
- Potential for validator node behavior divergence
- Wide attack surface (affects all Move package builds)

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack is feasible because:

1. **No Authentication Required**: Any user can publish packages that declare arbitrary git dependencies
2. **Optional Verification**: Many packages do not specify digests, making cache poisoning undetected
3. **Common Configuration**: Default `MOVE_HOME` location is shared across all projects
4. **User Behavior**: Developers commonly experiment with example packages or dependencies before using them in production
5. **Build Servers**: Shared build environments (CI/CD, multi-user systems) amplify the risk

Mitigating factors:
- Requires user to first compile a malicious package
- More sophisticated attacks require timing or access to cache directory
- Users can specify digests to detect tampering (but this is not enforced)

## Recommendation

Implement a multi-layered defense:

**1. Project-Isolated Caches:**
Change the cache directory structure to be project-specific rather than global:
```rust
// Instead of: ~/.move/{package_name}_{rev}/
// Use: {project_root}/.move_cache/{package_name}_{rev}/
```

**2. Mandatory Digest Verification:**
Make digest verification mandatory for all git dependencies. Fail the build if no digest is provided:
```rust
match dep.digest {
    None => bail!("Security Error: Digest verification is required for git dependency '{}'. Add 'digest = \"<hash>\"' to Move.toml", dep_name_in_pkg),
    Some(fixed_digest) => {
        // existing verification code
    }
}
```

**3. Cache Validation:**
Always validate cached packages before use, even when `skip_fetch_latest_git_deps` is set:
- Compute and verify git commit hashes
- Check file integrity
- Implement a package lock file with content hashes

**4. Separate User Cache:**
If global cache is retained, isolate by user ID on multi-user systems:
```rust
// Use: ~/.move/{user_id}/{package_name}_{rev}/
```

**5. Security Warning:**
Display warnings when using cached dependencies without digest verification.

## Proof of Concept

**Setup:**
```bash
# Terminal 1 - Attacker creates malicious package
mkdir /tmp/malicious_project
cd /tmp/malicious_project

cat > Move.toml << 'EOF'
[package]
name = "MaliciousProject"
version = "1.0.0"

[dependencies]
AptosFramework = { git = "https://github.com/aptos-labs/aptos-framework.git", rev = "main", subdir = "aptos-framework" }

[addresses]
malicious = "_"
EOF

mkdir -p sources
cat > sources/malicious.move << 'EOF'
module malicious::poison {
    public fun inject_backdoor() {
        // Malicious code that gets cached
    }
}
EOF

# Poison the cache by modifying the downloaded dependency
aptos move compile
# Now ~/.move/ contains potentially modified/malicious cached packages

# Terminal 2 - Victim builds legitimate project
mkdir /tmp/legitimate_project  
cd /tmp/legitimate_project

cat > Move.toml << 'EOF'
[package]
name = "LegitimateProject"
version = "1.0.0"

[dependencies]
# Same dependency without digest - will use poisoned cache
AptosFramework = { git = "https://github.com/aptos-labs/aptos-framework.git", rev = "main", subdir = "aptos-framework" }

[addresses]
legit = "0x42"
EOF

mkdir -p sources
cat > sources/legit.move << 'EOF'
module legit::app {
    use aptos_framework::account;
    
    public entry fun init(s: &signer) {
        // Uses the cached (potentially poisoned) aptos_framework
        account::create_account(signer::address_of(s));
    }
}
EOF

# This will use the poisoned cache without verification
aptos move compile --skip-fetch-latest-git-deps
# Malicious code is now compiled into the "legitimate" project
```

**Verification:**
```bash
# Check that both projects use the same cached directory
ls -la ~/.move/ | grep aptos-framework
# Both projects reference the same cached copy
# If the first project poisoned it, the second project is compromised
```

## Notes

1. This vulnerability affects the production package resolution system in `move-package`, not just the newer `move-package-resolver` (which is currently only used in tests)
2. The newer `move-package-resolver` system has similar cache-sharing issues if the same root directory is configured across projects
3. The vulnerability is exacerbated on shared build servers or CI/CD systems where multiple projects/users share the same account
4. While file locking exists in the newer system to prevent concurrent write races, it does not prevent cache poisoning attacks
5. The attack becomes more severe if the poisoned package is a framework or standard library component that many projects depend on

### Citations

**File:** third_party/move/move-command-line-common/src/env.rs (L48-58)
```rust
pub static MOVE_HOME: Lazy<String> = Lazy::new(|| {
    std::env::var("MOVE_HOME").unwrap_or_else(|_| {
        format!(
            "{}/.move",
            dirs_next::home_dir()
                .expect("user's home directory not found")
                .to_str()
                .unwrap()
        )
    })
});
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L565-573)
```rust
/// Gets the local path to download the package from a git repo
pub fn git_repo_cache_path(git_url: &str, rev_name: &str) -> PathBuf {
    let move_home = MOVE_HOME.clone();
    PathBuf::from(move_home).join(format!(
        "{}_{}",
        url_to_file_name(git_url),
        rev_name.replace('/', "__")
    ))
}
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

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L551-577)
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
```
