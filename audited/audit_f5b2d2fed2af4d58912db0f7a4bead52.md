# Audit Report

## Title
Symbolic Link Following in Git Dependency Resolution Enables Resource Exhaustion via Device File Exploitation

## Summary
The Move package dependency resolution system follows symbolic links when computing package digests and discovering source files from cloned git repositories. An attacker can create a malicious git repository containing symbolic links to device files (e.g., `/dev/random`, `/dev/urandom`, `/dev/zero`) that, when cloned as a package dependency, cause denial of service through infinite reads and memory exhaustion during the build process.

## Finding Description

The vulnerability exists in the package digest computation and file discovery mechanisms used during git dependency resolution. When a Move package declares a git dependency in its `Move.toml`, the build system clones the repository and computes a digest of its contents to verify package integrity. [1](#0-0) 

After cloning, the system computes a package digest by traversing all source files: [2](#0-1) 

The critical vulnerability is at line 31 where `walkdir::WalkDir` is configured with `.follow_links(true)`, causing the traversal to follow symbolic links. When a discovered file is read at line 14, if it's a symlink pointing to a device file like `/dev/random`, the system attempts to read infinite data: [3](#0-2) 

The same vulnerability exists in the file discovery mechanism: [4](#0-3) 

**Attack Scenario:**

1. Attacker creates a malicious git repository with a symbolic link: `exploit.move -> /dev/random`
2. Attacker publishes this repository (e.g., on GitHub)
3. Victim declares the malicious package as a dependency in their `Move.toml`:
   ```toml
   [dependencies]
   MaliciousPackage = { git = "https://github.com/attacker/malicious", rev = "main" }
   ```
4. Victim runs `aptos move compile` or `aptos move build`
5. The resolution process executes: [5](#0-4) 
6. The digest computation attempts to read from `/dev/random` via the symlink
7. Result: Build process hangs indefinitely, memory exhaustion, or system resource exhaustion

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." Build operations should have bounded resource consumption.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** based on the following considerations:

**Direct Impact:**
- Denial of Service on developer machines and CI/CD build systems
- Supply chain attack vector affecting any project that transitively depends on a malicious package
- Potential to disrupt production build pipelines and automated deployments

**Scope Limitations:**
- Does not directly affect validator nodes or consensus protocol
- Does not compromise funds, state integrity, or network availability
- Requires victim interaction (adding malicious dependency and building)
- Primarily affects development/build-time operations, not runtime execution

While this doesn't meet the High Severity criteria of "Validator node slowdowns" or "API crashes," it represents a significant security risk to the Move ecosystem's development infrastructure. If build servers or validator operators' development environments are affected, it could indirectly impact network operations.

## Likelihood Explanation

**High Likelihood:**
- Attack is trivial to execute (creating a symlink in a git repository is straightforward)
- No special privileges or complex setup required
- Git naturally preserves symbolic links during clone operations
- Attackers can create seemingly legitimate packages with hidden malicious symlinks
- Transitive dependencies amplify the attack surface (victim may not directly declare malicious package)

**Mitigation Factors:**
- Requires victim to add dependency and trigger a build
- Some systems may have protections against following symlinks
- Code review might catch obvious malicious symlinks (but sophisticated attacks could obfuscate them)

The combination of easy exploitation and broad attack surface makes this vulnerability highly likely to be exploited in practice.

## Recommendation

Disable symbolic link following in directory traversal operations during package resolution:

**For `digest.rs`:**
```rust
for entry in walkdir::WalkDir::new(path)
    .follow_links(false)  // Changed from true to false
    .into_iter()
    .filter_map(|e| e.ok())
{
    if entry.file_type().is_file() {
        maybe_hash_file(entry.path())?
    }
}
```

**For `files.rs`:**
```rust
for entry in walkdir::WalkDir::new(path)
    .follow_links(false)  // Changed from true to false
    .into_iter()
    .filter_map(|e| e.ok())
{
    // ... rest of logic
}
```

Additionally, implement explicit validation to reject symbolic links:
```rust
if entry.path().is_symlink() {
    bail!("Symbolic links are not allowed in Move packages: {:?}", entry.path());
}
```

**Defense in Depth:**
- Add resource limits (timeout, maximum bytes read) to all file read operations
- Implement allowlist for file extensions (only `.move`, `.toml`)
- Add security warnings in documentation about untrusted git dependencies
- Consider sandboxing the build process

## Proof of Concept

**Step 1: Create malicious repository**
```bash
#!/bin/bash
# Create malicious package
mkdir malicious-package
cd malicious-package

# Create basic Move.toml
cat > Move.toml << 'EOF'
[package]
name = "MaliciousPackage"
version = "1.0.0"

[addresses]
malicious = "_"

[dependencies]
EOF

# Create sources directory with malicious symlink
mkdir sources
cd sources
ln -s /dev/random exploit.move
cd ..

# Initialize git and commit
git init
git add .
git commit -m "Initial commit"

# Push to a git hosting service (GitHub, GitLab, etc.)
```

**Step 2: Victim's Move.toml**
```toml
[package]
name = "VictimPackage"
version = "1.0.0"

[dependencies]
MaliciousPackage = { git = "https://github.com/attacker/malicious-package", rev = "main" }
```

**Step 3: Trigger exploitation**
```bash
# This will hang or exhaust memory
aptos move compile
# or
aptos move build
```

**Expected Result:** The build process will hang indefinitely as it attempts to read infinite data from `/dev/random`, or will crash with an out-of-memory error as it buffers the random data.

**Alternative PoC using `/dev/zero`:**
Using `/dev/zero` instead of `/dev/random` will more reliably demonstrate the memory exhaustion, as it produces zeros faster than `/dev/random` produces random bytes.

## Notes

This vulnerability affects the Move package manager's supply chain security. While it doesn't directly compromise validator nodes or consensus, it represents a significant risk to development infrastructure and could be used in sophisticated supply chain attacks. The fix is straightforward and should be implemented with high priority to protect the Move developer ecosystem.

### Citations

**File:** third_party/move/tools/move-package/src/resolution/git.rs (L27-44)
```rust
pub(crate) fn clone(url: &str, target_path: &str, dep_name: PackageName) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args(["clone", url, target_path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| {
            anyhow::anyhow!("Failed to clone Git repository for package '{}'", dep_name)
        })?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "Failed to clone Git repository for package '{}' | Exit status: {}",
            dep_name,
            status
        ));
    }
    Ok(())
}
```

**File:** third_party/move/tools/move-package/src/resolution/digest.rs (L11-17)
```rust
pub fn compute_digest(paths: &[PathBuf]) -> Result<PackageDigest> {
    let mut hashed_files = Vec::new();
    let mut hash = |path: &Path| {
        let contents = std::fs::read(path)?;
        hashed_files.push(format!("{:X}", Sha256::digest(&contents)));
        Ok(())
    };
```

**File:** third_party/move/tools/move-package/src/resolution/digest.rs (L30-39)
```rust
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
```

**File:** third_party/move/move-command-line-common/src/files.rs (L80-84)
```rust
        for entry in walkdir::WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L551-576)
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
```
