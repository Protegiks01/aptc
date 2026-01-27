# Audit Report

## Title
Cache Poisoning via Lack of Integrity Verification in Move Package Cache

## Summary
The `checkout_git_repo()` function in the Move package cache returns cached git checkouts without verifying file integrity, allowing an attacker with filesystem access to poison the cache with malicious Move code that will be used in subsequent builds.

## Finding Description

The Move package cache system is designed to cache git repository checkouts for Move package dependencies. However, the implementation fails to verify the integrity of cached checkouts on subsequent uses. [1](#0-0) 

When `checkout_git_repo()` is called, it first checks if a checkout directory already exists. If the directory exists, it immediately returns the path without verifying that the files actually match the git commit they claim to represent. There is no integrity checking mechanism such as:
- Hash verification of file contents against git objects
- Filesystem permissions to make checkouts truly immutable
- Checksums or digital signatures on cached files

The cached checkout directory is created at a predictable path: `./data/git/checkouts/{repo}@{oid}`. An attacker with filesystem write access could:

1. Wait for a legitimate checkout to be created by the package cache
2. Modify Move source files (`.move` files) or the `Move.toml` manifest in the checkout directory
3. On the next invocation of the build/compile process, `checkout_git_repo()` returns the existing (now poisoned) path
4. The build system reads and compiles the malicious Move code from the poisoned cache [2](#0-1) 

The poisoned checkout is then used during dependency resolution, where the `Move.toml` manifest and source files are read for compilation. The code even acknowledges this gap exists for on-chain packages: [3](#0-2) 

## Impact Explanation

**Impact Assessment: Does NOT meet bug bounty severity criteria**

While this is a valid security concern for development tooling, it **does not qualify** as a blockchain protocol vulnerability under the Aptos bug bounty program for the following reasons:

1. **Not a Runtime/Protocol Issue**: The move-package-cache is a development-time tool used for building Move contracts, not a component of the running blockchain network, consensus mechanism, or validator operations.

2. **Requires Pre-Existing Compromise**: The attack requires filesystem write access to the cache directory, which means the attacker has already compromised the developer's machine or the build environment.

3. **No Direct Blockchain Impact**: The poisoned cache affects what code a developer *compiles*, but to actually affect the blockchain, the developer would need to sign and deploy a transaction containing the malicious bytecode. The blockchain itself would execute that bytecode correctly according to the Move VM specification.

4. **Supply Chain vs Protocol**: This is a supply chain security issue affecting developer workflows, not a vulnerability in the Aptos protocol, consensus, state management, or execution engine.

The Aptos bug bounty program focuses on vulnerabilities that directly affect:
- Loss of funds
- Consensus safety violations  
- Network partitions
- Validator operations
- Smart contract execution bugs

This vulnerability does not impact any of these categories directly.

## Likelihood Explanation

**Likelihood: Low for blockchain impact, but noteworthy for development security**

The likelihood of this affecting the Aptos blockchain itself is low because:
- It requires local machine compromise
- Developers typically review code before deploying to mainnet
- The blockchain's security model does not trust client-side build environments
- Move bytecode verification still occurs at deployment time

However, in shared CI/CD environments or multi-tenant build systems, this could be exploited to inject malicious code into multiple developers' builds.

## Recommendation

While this issue does not meet the bug bounty criteria for a protocol vulnerability, it should still be addressed as a security hardening measure for the development tooling:

1. **Implement Integrity Verification**: Before returning a cached checkout, verify that files match the git commit:
   - Calculate and cache SHA256 hashes of all files during initial checkout
   - On subsequent uses, verify hashes match before returning the path
   - Alternatively, regenerate files from git objects and compare

2. **Set Read-Only Permissions**: After creating a checkout, set filesystem permissions to read-only to prevent accidental or malicious modifications

3. **Periodic Integrity Checks**: Add an option to periodically verify all cached checkouts against their git repositories

4. **Cache Validation Command**: Provide a CLI command to validate cache integrity on demand

## Proof of Concept

This demonstrates the vulnerability in a development environment context:

```rust
// File: poison_cache_poc.rs
use std::fs;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Step 1: Create legitimate cache using PackageCache
    let cache = move_package_cache::PackageCache::new("./data")?;
    let url = url::Url::parse("https://github.com/aptos-labs/aptos-framework")?;
    let oid = cache.resolve_git_revision(&url, "main").await?;
    let checkout_path = cache.checkout_git_repo(&url, oid).await?;
    
    println!("Legitimate checkout at: {}", checkout_path.display());
    
    // Step 2: Attacker modifies cached files
    let malicious_move_code = r#"
        module 0x1::backdoor {
            public fun steal_funds() {
                // Malicious code here
            }
        }
    "#;
    
    let sources_dir = checkout_path.join("sources");
    fs::create_dir_all(&sources_dir)?;
    fs::write(sources_dir.join("backdoor.move"), malicious_move_code)?;
    
    println!("Cache poisoned with malicious Move code");
    
    // Step 3: Next use returns poisoned cache
    let cache2 = move_package_cache::PackageCache::new("./data")?;
    let cached_path = cache2.checkout_git_repo(&url, oid).await?;
    
    // Verify poisoned file exists
    assert!(cached_path.join("sources/backdoor.move").exists());
    println!("Subsequent checkout returned poisoned cache!");
    
    Ok(())
}
```

**Note**: This PoC demonstrates the technical vulnerability in the caching mechanism but does not constitute a blockchain protocol vulnerability since it affects only the development tooling.

---

## Notes

After thorough analysis and strict validation against the bug bounty criteria, **this issue does not qualify as a valid blockchain vulnerability** for the Aptos bug bounty program. While the cache poisoning vulnerability technically exists in the development tooling, it:

- Does not affect the running Aptos blockchain network
- Does not compromise consensus, state management, or execution
- Requires pre-existing machine compromise 
- Affects only development/build workflows, not production blockchain operations

The move-package-cache is explicitly a development tool [4](#0-3)  used for building Move packages, not a runtime component of validator nodes or the blockchain protocol.

**Final Assessment**: While this represents good security hygiene for development tooling, it does not meet the threshold for a blockchain protocol vulnerability under the strict validation criteria provided.

### Citations

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L215-219)
```rust
        // Check if a checkout already exists for this commit.
        let checkout_path = checkouts_path.join(format!("{}@{}", repo_dir_name, oid));
        if checkout_path.exists() {
            return Ok(checkout_path);
        }
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L300-305)
```rust
        // If the package directory already exists, assume it has been cached.
        if cached_package_path.exists() {
            // TODO: In the future, consider verifying data integrity,
            //       e.g. hash of metadata or full contents.
            return Ok(cached_package_path);
        }
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L205-214)
```rust
        SourceLocation::Git {
            repo: _,
            commit_id,
            subdir,
        } => {
            let git_url = user_provided_url.expect("must be specified for on-chain dep");

            let checkout_path = package_cache.checkout_git_repo(git_url, *commit_id).await?;
            checkout_path.join(subdir)
        },
```

**File:** third_party/move/tools/move-package-cache/src/main.rs (L10-12)
```rust
// Note: this is just sample workflow demonstrating how the package cache can be used as a library.
// It will likely be removed later as the package cache is intended to be integrated into
// other tools rather than used as a standalone executable.
```
