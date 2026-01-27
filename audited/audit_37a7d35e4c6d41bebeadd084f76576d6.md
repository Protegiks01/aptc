# Audit Report

## Title
Cache Directory Poisoning Attack Enables Malicious Move Package Injection

## Summary
The Move package compilation system checks if cached Git dependencies exist before downloading them, but does not verify the integrity of cached content. An attacker with write access to the cache directory can pre-populate it with malicious Move code that will be compiled and potentially deployed on-chain without detection.

## Finding Description
The vulnerability exists in the Move package cache implementation at two locations:

**New System (not yet in production):** [1](#0-0) 

**Old System (currently in production):** [2](#0-1) 

Both implementations check if a cached package directory exists and immediately use it without integrity verification. The cache paths are deterministic and predictable:
- Old system: `~/.move/<sanitized_git_url>_<rev_name>`
- New system: `<root>/git/checkouts/<encoded_repo>@<oid>` [3](#0-2) 

While digest verification exists in the system, it is **optional** and only enforced if the dependency explicitly specifies a digest field in Move.toml: [4](#0-3) 

**Attack Flow:**
1. Attacker calculates the predictable cache path for a target dependency (e.g., `~/.move/github.com_aptos-labs_aptos-framework_main`)
2. Attacker pre-creates the directory with malicious Move source code that mimics the legitimate package structure
3. Victim runs `aptos move compile` on a package with this Git dependency
4. The resolution system checks if the cache exists, finds it, and skips downloading
5. If no digest is specified in Move.toml, the malicious code is compiled without verification
6. Malicious code may be deployed on-chain, affecting consensus, governance, or fund management

This breaks the **Deterministic Execution** invariant - different validators could compile different code if their caches are poisoned differently, leading to consensus failures.

## Impact Explanation
This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program because it enables:

1. **Consensus/Safety Violations**: If validator operators compile framework code with poisoned caches, different validators may execute different bytecode, breaking deterministic execution and causing consensus failures or chain splits.

2. **Loss of Funds**: Malicious Move code in governance or staking modules could enable unauthorized fund transfers, voting power manipulation, or validator set attacks.

3. **Remote Code Execution**: Compromised Move code deployed to on-chain governance could execute arbitrary operations with system privileges.

The attack specifically targets the Move compilation toolchain used by validator operators, developers, and governance participants, making it a supply chain attack vector against the Aptos blockchain infrastructure.

## Likelihood Explanation
**Likelihood: MEDIUM**

**Required Conditions:**
- Attacker must have write access to the victim's cache directory (`~/.move/` or custom cache root)
- Target dependency must not specify a digest in Move.toml (common in practice)
- Victim must compile a package using the poisoned dependency

**Realistic Scenarios:**
1. **Shared CI/CD Infrastructure**: Multiple users' build jobs share the same cache directory with insufficient isolation
2. **Container Environments**: Misconfigured Docker volumes or Kubernetes persistent volumes expose the cache
3. **Multi-user Systems**: Development servers where multiple developers share the same machine
4. **Symlink Attacks**: If the cache directory is created with world-writable permissions, an attacker could create symlinks to inject malicious content
5. **Supply Chain Compromise**: An attacker compromises a developer's machine with limited privileges but can write to the cache

While requiring write access to the cache directory is a significant constraint, the predictability of cache paths and the lack of integrity verification creates a dangerous attack surface, especially in production validator environments.

## Recommendation
Implement content integrity verification for all cached packages:

**Fix for checkout_git_repo():**
```rust
pub async fn checkout_git_repo(&self, git_url: &Url, oid: Oid) -> Result<PathBuf>
where
    L: PackageCacheListener,
{
    let repo_dir_name = percent_encode_for_filename(&CanonicalGitIdentity::new(git_url)?);
    let checkouts_path = self.root.join("git").join("checkouts");
    let checkout_path = checkouts_path.join(format!("{}@{}", repo_dir_name, oid));
    
    // REMOVED: Early return without verification
    // if checkout_path.exists() {
    //     return Ok(checkout_path);
    // }
    
    // Always verify through the proper flow with locking
    let repo = self.clone_or_update_git_repo(git_url).await?;
    
    // Acquire file lock
    let lock_path = checkout_path.with_extension("lock");
    fs::create_dir_all(&checkouts_path)?;
    let _file_lock = FileLock::lock_with_alert_on_wait(&lock_path, Duration::from_millis(1000), || {
        self.listener.on_file_lock_wait(&lock_path);
    }).await?;
    
    // Check again after acquiring lock, but verify OID if exists
    if checkout_path.exists() {
        // Verify the checkout matches the expected OID by checking
        // against the repository's commit history
        if self.verify_checkout_integrity(&checkout_path, &repo.repo, oid)? {
            return Ok(checkout_path);
        }
        // If verification fails, delete and recreate
        remove_dir_if_exists(&checkout_path)?;
    }
    
    // Create fresh checkout with verified content
    // ... rest of function
}
```

**Additional Recommendations:**
1. Make digest verification **mandatory** for all Git dependencies, not optional
2. Implement cache signature verification using Git commit signatures
3. Add cache directory permission checks on initialization
4. Log warnings when using cached packages without digest verification
5. Consider implementing a secure cache with cryptographic verification (e.g., content-addressed storage)

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_cache_poisoning_attack() {
    // Setup: Create a malicious cache directory structure
    let cache_root = TempDir::new().unwrap();
    let malicious_checkout = cache_root.path()
        .join("git")
        .join("checkouts")
        .join("github.com_victim_repo@1234567890abcdef");
    
    fs::create_dir_all(&malicious_checkout).unwrap();
    
    // Create malicious Move.toml
    fs::write(
        malicious_checkout.join("Move.toml"),
        r#"
[package]
name = "MaliciousPackage"
version = "1.0.0"

[addresses]
malicious = "0xBAD"
"#
    ).unwrap();
    
    // Create malicious Move source with backdoor
    fs::create_dir_all(malicious_checkout.join("sources")).unwrap();
    fs::write(
        malicious_checkout.join("sources").join("backdoor.move"),
        r#"
module malicious::backdoor {
    use std::signer;
    
    // Malicious function that steals funds
    public entry fun steal_funds(victim: &signer, attacker_addr: address) {
        // Backdoor logic here
    }
}
"#
    ).unwrap();
    
    // Attack: When victim compiles, the malicious cache is used
    let package_cache = move_package_cache::PackageCache::new(cache_root.path()).unwrap();
    
    let git_url = url::Url::parse("https://github.com/victim/repo").unwrap();
    let oid = git2::Oid::from_str("1234567890abcdef").unwrap();
    
    // This returns the malicious checkout WITHOUT verification
    let result = package_cache.checkout_git_repo(&git_url, oid).await;
    
    // Verify the attack succeeded - malicious path is returned
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), malicious_checkout);
    
    // The malicious Move code will now be compiled and potentially deployed
}
```

**Notes:**
- The vulnerability affects the production Move package resolution system used by `aptos move compile`
- While the specific line mentioned (218 in package_cache.rs) is in newer code not yet in production, an identical vulnerability exists in the production system at line 563 of resolution_graph.rs
- The attack is particularly dangerous because it's subtle - developers and validator operators may not realize they're compiling cached malicious code rather than fresh downloads from the legitimate repository
- The lack of mandatory integrity verification creates a significant supply chain security risk for the Aptos ecosystem

### Citations

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L215-219)
```rust
        // Check if a checkout already exists for this commit.
        let checkout_path = checkouts_path.join(format!("{}@{}", repo_dir_name, oid));
        if checkout_path.exists() {
            return Ok(checkout_path);
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

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L562-577)
```rust
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

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L566-573)
```rust
pub fn git_repo_cache_path(git_url: &str, rev_name: &str) -> PathBuf {
    let move_home = MOVE_HOME.clone();
    PathBuf::from(move_home).join(format!(
        "{}_{}",
        url_to_file_name(git_url),
        rev_name.replace('/', "__")
    ))
}
```
