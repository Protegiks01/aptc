# Audit Report

## Title
Symlink Path Traversal and Git Clone Security Gaps in Move Package Dependency Resolution

## Summary
The Move package system's git dependency handling lacks critical security protections, allowing malicious git repositories to exploit symlink following during file discovery, use unvalidated git URLs without protocol restrictions, and clone repositories without submodule or git client vulnerability protections.

## Finding Description

The GitInfo struct and its associated git cloning operations contain multiple security vulnerabilities:

**1. Symlink Path Traversal Vulnerability**

The git clone operation creates symlinks from malicious repositories on the local filesystem. When scanning for Move source files, the code explicitly follows symlinks without validation: [1](#0-0) 

This allows attackers to:
- Create symlinks in their git repository pointing to arbitrary filesystem paths
- When the repository is cloned using the command-line git client, these symlinks are created on the victim's filesystem
- During Move file discovery, these symlinks are followed, potentially reading sensitive files

The git clone operation uses basic command-line git without security flags: [2](#0-1) 

**2. No Git URL or Protocol Validation**

Git URLs are parsed and used directly without any validation: [3](#0-2) 

The system accepts any git URL protocol (git://, file://, http://, https://) without restrictions.

**3. Unprotected Submodule References**

While submodules aren't automatically initialized, .gitmodules files are cloned without validation. If developers later run git commands in the cloned directory, submodules pointing to attacker-controlled servers could be initialized.

**4. No Git Client Security Configuration**

The system uses the system git client without:
- Version checks to prevent known CVE exploitation
- Security configuration flags like `--config protocol.allow=user`
- Validation of git objects or repository integrity

**Attack Scenario:**

1. Attacker creates a malicious Move package repository on GitHub
2. Repository contains a symlink: `sources/malicious.move -> ../../../../.ssh/id_rsa.move` (or points to another Move package)
3. Developer adds this as a dependency in Move.toml:
   ```toml
   [dependencies]
   MaliciousPackage = { git = "https://github.com/attacker/malicious-package", rev = "main" }
   ```
4. During `aptos move compile`, the system:
   - Clones the repository via `git::clone()`
   - Creates the symlink on the filesystem
   - Calls `find_move_filenames()` which follows the symlink
   - Reads the target file (if it has .move extension or attacker controls it)

**Digest Computation Also Vulnerable:**

The package digest computation similarly follows symlinks: [4](#0-3) 

This allows attackers to:
- Make digest computations depend on files outside the repository
- Cause different digests on different systems
- Potentially leak information through digest-based side channels

## Impact Explanation

**Severity: Medium to High**

This vulnerability affects the supply chain security of Move package development and could potentially impact consensus if malicious packages are included in the Aptos Framework or validator infrastructure.

**Direct Impacts:**
1. **Information Disclosure**: Symlinks can read sensitive files from developer machines (SSH keys, credentials, other Move packages)
2. **Build Determinism Violation**: Breaks the deterministic execution invariant if different validators have different filesystem contents at symlink targets
3. **Code Injection**: Attackers can inject malicious Move code by pointing symlinks to attacker-controlled files
4. **Supply Chain Attack**: Malicious dependencies can compromise the development and build process

**Potential Consensus Impact:**
If a malicious dependency is included in:
- Aptos Framework updates
- Validator node software builds
- Core infrastructure packages

Then different validators could compile different bytecode if symlinks resolve to different files on their systems, violating the **Deterministic Execution** invariant.

## Likelihood Explanation

**Likelihood: Medium**

**Factors increasing likelihood:**
- Move package ecosystem encourages dependency usage
- Developers trust packages from seemingly legitimate sources
- Social engineering can convince developers to add malicious dependencies
- No warnings or validation when adding git dependencies
- Symlink creation is automatic and silent

**Factors decreasing likelihood:**
- Requires developer to explicitly add malicious dependency
- Target files must have .move extension (though attackers can control this)
- Currently limited Move package ecosystem reduces attack surface
- Most developers use official Aptos packages

**Realistic Attack Vector:**
An attacker could create a useful-looking Move package (e.g., "aptos-token-extensions"), publish it, and through social media/documentation, encourage developers to use it. Once added as a dependency, the symlink exploitation occurs automatically.

## Recommendation

**1. Disable Symlink Following**

Modify file discovery to not follow symlinks:

```rust
// In third_party/move/move-command-line-common/src/files.rs
for entry in walkdir::WalkDir::new(path)
    .follow_links(false)  // Changed from true
    .into_iter()
    .filter_map(|e| e.ok())
{
    // Reject symlinks explicitly
    if entry.file_type().is_symlink() {
        bail!("Symlinks are not allowed in Move packages for security reasons: {:?}", entry.path());
    }
    // ... rest of code
}
```

**2. Add Git URL Validation**

```rust
// In manifest_parser.rs
fn validate_git_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url)?;
    
    // Only allow https for security
    if parsed.scheme() != "https" {
        bail!("Only HTTPS git URLs are allowed for security. Found: {}", parsed.scheme());
    }
    
    // Optional: Allowlist trusted git hosting providers
    let allowed_hosts = ["github.com", "gitlab.com"];
    if let Some(host) = parsed.host_str() {
        if !allowed_hosts.contains(&host) {
            bail!("Git host not in allowlist: {}", host);
        }
    }
    
    Ok(())
}
```

**3. Add Git Security Configuration**

```rust
// In git.rs
pub(crate) fn clone(url: &str, target_path: &str, dep_name: PackageName) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args([
            "-c", "protocol.allow=user",  // Only allow user-approved protocols
            "-c", "core.symlinks=false",   // Disable symlink support
            "clone",
            "--no-checkout",               // Don't checkout initially
            url,
            target_path
        ])
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
    
    // Verify no submodules
    let gitmodules_path = Path::new(target_path).join(".gitmodules");
    if gitmodules_path.exists() {
        bail!("Git submodules are not allowed in dependencies for security reasons");
    }
    
    Ok(())
}
```

**4. Use git2 Library Exclusively**

Migrate away from command-line git to the git2 library which provides better control and doesn't create symlinks by default (as seen in package_cache.rs).

## Proof of Concept

```bash
# Create malicious repository
mkdir malicious-move-package
cd malicious-move-package

# Initialize git repo
git init

# Create Move.toml
cat > Move.toml << 'EOF'
[package]
name = "MaliciousPackage"
version = "0.0.1"
EOF

# Create sources directory
mkdir sources

# Create a symlink to a sensitive file
# This will be followed when the package is cloned and compiled
ln -s /etc/passwd sources/passwd.move
# Or point to another location where attacker controls a .move file
ln -s /tmp/attacker_controlled.move sources/exploit.move

# Commit
git add Move.toml sources
git commit -m "Initial commit"

# Push to GitHub (attacker's repo)
# ... git remote add origin ... git push ...

# Victim adds this to their Move.toml:
# [dependencies]
# MaliciousPackage = { git = "https://github.com/attacker/malicious-move-package", rev = "main" }

# When victim runs: aptos move compile
# The system will:
# 1. Clone the repo (creating the symlink)
# 2. Call find_move_filenames() which follows the symlink
# 3. Read /etc/passwd or /tmp/attacker_controlled.move
# 4. Attempt to compile it as Move code
```

**Rust Test to Demonstrate Symlink Following:**

```rust
#[test]
fn test_symlink_following_vulnerability() {
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;
    
    // Create temporary directory structure
    let temp = TempDir::new().unwrap();
    let package_dir = temp.path().join("package");
    let sources_dir = package_dir.join("sources");
    fs::create_dir_all(&sources_dir).unwrap();
    
    // Create a sensitive file outside the package
    let sensitive_file = temp.path().join("sensitive.move");
    fs::write(&sensitive_file, "module Sensitive { }").unwrap();
    
    // Create a symlink inside the package pointing to the sensitive file
    let symlink_path = sources_dir.join("exploit.move");
    symlink(&sensitive_file, &symlink_path).unwrap();
    
    // Call find_move_filenames - it will follow the symlink
    let sources = vec![sources_dir.to_str().unwrap().to_string()];
    let files = move_command_line_common::files::find_move_filenames(&sources, false).unwrap();
    
    // Verify the symlink target was included
    assert!(files.iter().any(|f| f.contains("exploit.move")));
    
    // Verify we can read the sensitive file through the symlink
    let content = fs::read_to_string(&files[0]).unwrap();
    assert_eq!(content, "module Sensitive { }");
    
    println!("VULNERABILITY CONFIRMED: Symlink to sensitive file was followed!");
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Breaks Deterministic Execution**: If different validators have different files at symlink targets, they could compile different bytecode
2. **Supply Chain Attack Vector**: Common pattern in modern software supply chains
3. **Silent Exploitation**: Symlinks are created and followed without user awareness
4. **No Current Mitigations**: The codebase has no protections against this attack vector

The git2 library implementation in `package_cache.rs` is safer as it doesn't create symlinks by default, but the command-line git path in `git.rs` remains vulnerable and is actively used in the resolution graph.

### Citations

**File:** third_party/move/move-command-line-common/src/files.rs (L80-84)
```rust
        for entry in walkdir::WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
```

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

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L365-381)
```rust
                    let git_url = git
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Git URL not a string"))?;
                    let local_path = git_repo_cache_path(git_url, rev_name.as_str());
                    let subdir = PathBuf::from(match table.remove("subdir") {
                        None => "".to_string(),
                        Some(path) => path
                            .as_str()
                            .ok_or_else(|| format_err!("'subdir' not a string"))?
                            .to_string(),
                    });
                    git_info = Some(PM::GitInfo {
                        git_url: Symbol::from(git_url),
                        git_rev: rev_name,
                        subdir: subdir.clone(),
                        download_to: local_path.clone(),
                    });
```

**File:** third_party/move/tools/move-package/src/resolution/digest.rs (L30-38)
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
```
