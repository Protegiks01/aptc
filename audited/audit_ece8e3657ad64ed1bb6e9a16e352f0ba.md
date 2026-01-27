# Audit Report

## Title
Unbounded Disk Space Consumption in Move Package Resolver Cache

## Summary
The Move package resolver lacks disk space limits when fetching and caching dependencies, allowing an attacker to cause disk exhaustion on victim machines by creating packages with numerous large Git repository or on-chain package dependencies.

## Finding Description

The `move-package-resolver` fetches and caches all transitive dependencies without any size limits or eviction policies, breaking the **Resource Limits** invariant that "all operations must respect gas, storage, and computational limits." [1](#0-0) 

When resolving dependencies, the resolver clones entire Git repositories (including full history) using libgit2's `bare` clone mode. Each unique repository URL is stored separately, and each commit creates a separate checkout directory. [2](#0-1) 

For on-chain packages, all module bytecode files are downloaded concurrently without size validation: [3](#0-2) 

The package resolution process recursively fetches all dependencies declared in `Move.toml` manifests: [4](#0-3) [5](#0-4) 

An attacker can craft a malicious `Move.toml` declaring hundreds of dependencies pointing to large Git repositories or on-chain packages. When a victim attempts to build this package, the resolver will:

1. Clone all Git repositories with full history (potentially gigabytes each)
2. Create separate checkouts for each commit
3. Download all on-chain package modules
4. Store everything in the local cache with no limits
5. Continue until disk space is exhausted

The cache has no automatic cleanup mechanism beyond the manual `CleanPackage` command, and no warnings about disk usage.

## Impact Explanation

This is classified as **Medium severity** because:
- It causes resource exhaustion affecting developer tooling availability
- While it doesn't directly compromise blockchain consensus or funds, it can disrupt development workflows
- It could be weaponized in supply chain attacks where malicious dependencies are added to legitimate projects
- Developers building packages from untrusted sources would have their systems incapacitated

However, this falls short of High/Critical severity as it:
- Does not affect running validator nodes or the blockchain network
- Only impacts local development environments
- Requires victim interaction (building a malicious package)

## Likelihood Explanation

**High Likelihood:**
- Extremely simple to exploit - just create a `Move.toml` with many large dependencies
- No authentication or authorization required
- No cryptographic operations needed
- Attack surface includes any developer building Move packages
- Could be hidden in transitive dependencies (dependency-of-dependency)

The attack requires only:
1. Attacker creates malicious package with large dependencies
2. Attacker publishes or shares the package
3. Victim attempts to build/compile the package

## Recommendation

Implement disk space limits and cache management:

```rust
pub struct PackageCacheConfig {
    pub max_cache_size_bytes: u64,
    pub max_single_repo_size_bytes: u64,
    pub max_dependencies_per_package: usize,
}

impl<L> PackageCache<L> {
    pub fn new_with_config(
        root: impl AsRef<Path>, 
        listener: L,
        config: PackageCacheConfig
    ) -> Result<Self> {
        // Initialize with config
    }
    
    fn check_cache_size_limit(&self) -> Result<()> {
        let total_size = calculate_directory_size(&self.root)?;
        if total_size > self.config.max_cache_size_bytes {
            self.evict_old_entries()?;
        }
        Ok(())
    }
}
```

Additional mitigations:
1. Add `--max-cache-size` CLI flag with default limits (e.g., 10GB)
2. Warn users when cache exceeds thresholds
3. Implement LRU eviction for old/unused packages
4. Validate repository size before cloning (using `git ls-remote`)
5. Limit maximum number of dependencies per package (e.g., 100)

## Proof of Concept

Create a malicious `Move.toml`:

```toml
[package]
name = "MaliciousPackage"
version = "1.0.0"

[dependencies]
# Point to 50 large repositories (e.g., Linux kernel, large monorepos)
LargeRepo1 = { git = "https://github.com/torvalds/linux.git", rev = "master" }
LargeRepo2 = { git = "https://github.com/torvalds/linux.git", rev = "v6.0" }
# ... repeat with different commits for 50+ entries
# Each clone will be ~3GB, total 150GB+
```

When a victim runs:
```bash
aptos move compile --package-dir ./MaliciousPackage
```

The resolver will:
1. Clone linux repo 50 times (once per unique commit)
2. Create 50 separate checkouts
3. Consume 150GB+ disk space
4. Continue until disk is full or process crashes

**Notes**

- The runtime dependency limits enforced by the Move VM (`max_num_dependencies`, `max_total_dependency_size`) apply only during transaction execution, not during package resolution at build time. [6](#0-5) 

- While there's a `MAX_PUBLISH_PACKAGE_SIZE` limit (60,000 bytes) for publishing packages on-chain, this doesn't limit what can be fetched during dependency resolution. The limit only applies to the final compiled package being published.

- This vulnerability is distinct from consensus or state management issues, as it affects the developer tooling layer rather than the blockchain runtime itself.

### Citations

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L89-178)
```rust
    /// Clones or updates a Git repository, ensuring it is available locally with up-to-date data.
    ///
    /// Returns an `ActiveRepository` object. This can be used to access the contents of the repo, and while
    /// is still alive, a lock is held to prevent other package cache instances to access the repo.
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

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L204-273)
```rust
    /// Checks out a commit of a Git repository and returns the path to the checkout.
    ///
    /// A checkout is an immutable snapshot of a repository at a specific commit.
    /// If a checkout already exists, the existing path is returned.
    pub async fn checkout_git_repo(&self, git_url: &Url, oid: Oid) -> Result<PathBuf>
    where
        L: PackageCacheListener,
    {
        let repo_dir_name = percent_encode_for_filename(&CanonicalGitIdentity::new(git_url)?);
        let checkouts_path = self.root.join("git").join("checkouts");

        // Check if a checkout already exists for this commit.
        let checkout_path = checkouts_path.join(format!("{}@{}", repo_dir_name, oid));
        if checkout_path.exists() {
            return Ok(checkout_path);
        }

        // Checkout does not exist -- need to create one.
        //
        // However before we do that, we need to make sure the repo is cloned to the local
        // file system and updated.
        let repo = self.clone_or_update_git_repo(git_url).await?;

        // Acquire a file lock to ensure exclusive write access to the checkout.
        let lock_path = checkout_path.with_extension("lock");

        fs::create_dir_all(&checkouts_path)?;
        let _file_lock =
            FileLock::lock_with_alert_on_wait(&lock_path, Duration::from_millis(1000), || {
                self.listener.on_file_lock_wait(&lock_path);
            })
            .await?;

        self.listener
            .on_repo_checkout(git_url.as_str(), oid.as_bytes());

        // Create the files from the commit.
        //
        // The files stored into a temporary directory, and then the temporary directory
        // is atomically renamed/moved to the destination.
        //
        // This is to ensure we only expose complete checkouts.
        let temp = tempfile::tempdir_in(&checkouts_path)?;

        let commit = repo.repo.find_commit(oid)?;
        let tree = commit.tree()?;

        tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
            let name = entry.name().unwrap_or("");
            let full_path = temp.path().join(format!("{}{}", root, name));

            match entry.kind() {
                Some(ObjectType::Blob) => {
                    let blob = repo.repo.find_blob(entry.id()).unwrap();
                    fs::create_dir_all(full_path.parent().unwrap()).unwrap();
                    let mut file = File::create(&full_path).unwrap();
                    file.write_all(blob.content()).unwrap();
                },
                Some(ObjectType::Tree) => (),
                _ => {},
            }

            TreeWalkResult::Ok
        })?;

        remove_dir_if_exists(&checkout_path)?;
        fs::rename(temp.into_path(), &checkout_path)?;

        Ok(checkout_path)
    }
```

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L275-408)
```rust
    /// Fetches an on-chain package from the specified network and version and stores it locally.
    /// Returns the path to the cached package.
    ///
    /// The cached package currently only contains the bytecode modules, but may be extended with
    /// additional metadata in the future.
    pub async fn fetch_on_chain_package(
        &self,
        fullnode_url: &Url,
        network_version: u64,
        address: AccountAddress,
        package_name: &str,
    ) -> Result<PathBuf>
    where
        L: PackageCacheListener,
    {
        let on_chain_packages_path = self.root.join("on-chain");

        let canonical_node_identity = CanonicalNodeIdentity::new(fullnode_url)?;
        let canonical_name = format!(
            "{}+{}+{}+{}",
            &*canonical_node_identity, network_version, address, package_name
        );

        let cached_package_path = on_chain_packages_path.join(&canonical_name);

        // If the package directory already exists, assume it has been cached.
        if cached_package_path.exists() {
            // TODO: In the future, consider verifying data integrity,
            //       e.g. hash of metadata or full contents.
            return Ok(cached_package_path);
        }

        // Package directory does not exist -- need to download the package and cache it.
        //
        // First, acquire a lock to ensure exclusive write access to this package.
        let lock_path = cached_package_path.with_extension("lock");

        fs::create_dir_all(&on_chain_packages_path)?;
        let _file_lock =
            FileLock::lock_with_alert_on_wait(&lock_path, Duration::from_millis(1000), || {
                self.listener.on_file_lock_wait(&lock_path);
            })
            .await?;

        self.listener.on_file_lock_acquired(&lock_path);

        // After acquiring the lock, re-check if the package was already cached by another process.
        if cached_package_path.exists() {
            return Ok(cached_package_path);
        }

        // Fetch the on-chain package registry at the specified ledger version and look-up the
        // package by name.
        self.listener
            .on_bytecode_package_download_start(address, package_name);

        let client = aptos_rest_client::Client::new(fullnode_url.clone());

        let package_registry = client
            .get_account_resource_at_version_bcs::<PackageRegistry>(
                address,
                "0x1::code::PackageRegistry",
                network_version,
            )
            .await?
            .into_inner();

        let package = match package_registry
            .packages
            .iter()
            .find(|package_metadata| package_metadata.name == package_name)
        {
            Some(package) => package,
            None => bail!(
                "package not found: {}//{}::{}",
                fullnode_url,
                address,
                package_name
            ),
        };

        self.listener
            .on_bytecode_package_receive_metadata(address, package);

        // Download all modules of the package concurrently.
        //
        // The downloaded files are first saved into a temporary directory, and then
        // the temporary directory is atomically renamed/moved to the destination.
        // This is to ensure we only expose complete downloads.
        let temp = tempfile::tempdir_in(&on_chain_packages_path)?;

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

        future::try_join_all(fetch_futures).await?;

        remove_dir_if_exists(&cached_package_path)?;
        fs::rename(temp.into_path(), &cached_package_path)?;

        self.listener
            .on_bytecode_package_download_complete(address, package_name);

        Ok(cached_package_path)
    }
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L129-175)
```rust
/// Resolves all transitive dependencies for the given root package.
/// The results are returned as a [`ResolutionGraph`].
///
/// During resolution, remote dependencies are fetched and cached.
///
/// As of now, if dev_mode is set to true, dev dependencies are appended to the list of
/// dependencies, after the regular ones.
pub async fn resolve(
    package_cache: &PackageCache<impl PackageCacheListener>,
    package_lock: &mut PackageLock,
    root_package_path: impl AsRef<Path>,
    dev_mode: bool,
) -> Result<ResolutionGraph> {
    let mut graph = ResolutionGraph::new();
    let mut resolved = BTreeMap::new();

    let root_package_path = root_package_path.as_ref();

    // TODO: Is there a way to avoid reading the manifest twice?
    let root_package_manifest = move_package_manifest::parse_package_manifest(
        &fs::read_to_string(root_package_path.join("Move.toml"))?,
    )?;

    let root_package_identity = PackageIdentity {
        name: root_package_manifest.package.name.to_string(),
        location: SourceLocation::Local {
            path: CanonicalPath::new(root_package_path)?,
        },
    };

    resolve_package(
        package_cache,
        package_lock,
        &mut graph,
        &mut resolved,
        root_package_identity,
        None,
        dev_mode,
    )
    .await?;

    check_for_name_conflicts(&graph)?;
    check_for_self_dependencies(&graph)?;
    check_for_cyclic_dependencies(&graph)?;

    Ok(graph)
}
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L218-304)
```rust
/// Resolves a package identified by the given identity and adds it to the resolution graph.
async fn resolve_package(
    package_cache: &PackageCache<impl PackageCacheListener>,
    package_lock: &mut PackageLock,
    graph: &mut ResolutionGraph,
    resolved: &mut BTreeMap<PackageIdentity, NodeIndex>,
    identity: PackageIdentity,
    user_provided_url: Option<&Url>,
    dev_mode: bool,
) -> Result<NodeIndex> {
    if let Some(idx) = resolved.get(&identity) {
        return Ok(*idx);
    }

    let local_path =
        get_package_local_path(package_cache, package_lock, &identity, user_provided_url).await?;

    match &identity.location {
        SourceLocation::OnChain { .. } => {
            let node_idx = graph.add_node(Package {
                identity: identity.clone(),
                local_path,
            });
            resolved.insert(identity, node_idx);

            // TODO: fetch transitive deps

            Ok(node_idx)
        },
        SourceLocation::Local { .. } | SourceLocation::Git { .. } => {
            // Read the package manifest
            let manifest_path = local_path.join("Move.toml");
            let contents = fs::read_to_string(&manifest_path).map_err(|err| {
                anyhow!(
                    "failed to read package manifest at {}: {}",
                    manifest_path.display(),
                    err
                )
            })?;
            let package_manifest = move_package_manifest::parse_package_manifest(&contents)?;
            if *package_manifest.package.name != identity.name {
                bail!(
                    "Package name mismatch -- expected {}, got {}",
                    identity.name,
                    package_manifest.package.name
                );
            }

            // Add the package to the graph
            let node_idx = graph.add_node(Package {
                identity: identity.clone(),
                local_path,
            });
            resolved.insert(identity.clone(), node_idx);

            // Resolve all dependencies
            let all_deps = if dev_mode {
                Either::Left(
                    package_manifest
                        .dependencies
                        .into_iter()
                        .chain(package_manifest.dev_dependencies.into_iter()),
                )
            } else {
                Either::Right(package_manifest.dependencies.into_iter())
            };

            for (dep_name, dep) in all_deps {
                let dep_idx = Box::pin(resolve_dependency(
                    package_cache,
                    package_lock,
                    graph,
                    resolved,
                    &identity,
                    user_provided_url,
                    &dep_name,
                    dep,
                    dev_mode,
                ))
                .await?;
                graph.add_edge(node_idx, dep_idx, Dependency {});
            }

            Ok(node_idx)
        },
    }
}
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L300-313)
```rust
    fn count_dependency(&mut self, size: NumBytes) -> PartialVMResult<()> {
        if self.feature_version >= 15 {
            self.num_dependencies += 1.into();
            self.total_dependency_size += size;

            if self.num_dependencies > self.vm_gas_params.txn.max_num_dependencies {
                return Err(PartialVMError::new(StatusCode::DEPENDENCY_LIMIT_REACHED));
            }
            if self.total_dependency_size > self.vm_gas_params.txn.max_total_dependency_size {
                return Err(PartialVMError::new(StatusCode::DEPENDENCY_LIMIT_REACHED));
            }
        }
        Ok(())
    }
```
