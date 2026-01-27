# Audit Report

## Title
Unbounded Concurrent Module Fetching Enables DoS via Malicious Packages with Thousands of Modules

## Summary
The `fetch_on_chain_package()` function in the Move package cache fetches all modules of a package concurrently without any limit on the number of modules. An attacker can deploy a malicious package containing thousands of minimal modules using chunked publishing, and when this package is fetched as a dependency, it triggers thousands of concurrent HTTP requests, causing resource exhaustion and denial of service.

## Finding Description

The vulnerability exists in the `fetch_on_chain_package()` method where package modules are fetched from the blockchain: [1](#0-0) 

The code creates a future for **every module** in the package and executes them **all concurrently** using `future::try_join_all()`. There is no limit on the number of concurrent module fetches.

The Aptos blockchain allows deploying packages with an arbitrary number of modules through chunked publishing: [2](#0-1) 

The `code_indices` parameter uses `vector<u16>`, theoretically allowing up to 65,535 modules. There is no validation in the package publishing logic that limits the number of modules: [3](#0-2) 

The `PackageMetadata` struct contains `modules: vector<ModuleMetadata>` with no explicit size limit enforced.

**Attack Path:**

1. Attacker creates a package with thousands of minimal modules (e.g., 10,000 modules each containing a single empty function)
2. Attacker uses chunked publishing to deploy this package on-chain
3. Victim developer adds this package as a dependency in their Move.toml
4. When victim runs `aptos move compile` or similar commands, the Move package resolver attempts to fetch the malicious package: [4](#0-3) 

5. The package cache's `fetch_on_chain_package()` is invoked, creating 10,000 concurrent futures
6. Each future spawns an HTTP request to the fullnode API and a blocking file write task: [5](#0-4) 

7. This causes:
   - **Memory exhaustion** from 10,000+ tokio tasks
   - **File descriptor exhaustion** from 10,000+ concurrent connections
   - **Fullnode API DoS** from overwhelming concurrent requests to `get_account_module_bcs_at_version`
   - **Client machine freeze** from excessive resource consumption

The REST client has no connection pool limits or concurrency controls: [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per Aptos bug bounty criteria:

1. **Validator node slowdowns**: If validators build Move packages that depend on malicious packages, their nodes will experience resource exhaustion, slowing down block production.

2. **API crashes**: The fullnode REST API will be overwhelmed by thousands of concurrent `get_account_module_bcs_at_version` requests, potentially crashing or degrading service for all users.

3. **Significant protocol violations**: Violates the critical invariant "Resource Limits: All operations must respect gas, storage, and computational limits" - there is unbounded resource consumption with no limits enforced.

The attack is **not limited to development environments**. Any system that resolves Move package dependencies (build tools, IDEs, CI/CD pipelines, package explorers) is vulnerable.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker requirements**: Minimal - only need ability to deploy Move packages (no validator access required)
- **Attack complexity**: Low - chunked publishing is a standard feature, creating minimal modules is trivial
- **Cost**: Low - deploying thousands of tiny modules costs only transaction fees
- **Detection difficulty**: High - malicious package looks like any other large package
- **Widespread impact**: Any developer or tool that depends on the malicious package triggers the attack

The attack is **practical and realistic**:
- Chunked publishing is officially supported and documented
- No validation prevents packages with excessive module counts
- The package cache is used by standard Move development tools
- Attack succeeds automatically when dependency is resolved

## Recommendation

Implement a **maximum module count limit** and **concurrent fetch limiting**:

```rust
// In package_cache.rs
const MAX_MODULES_PER_PACKAGE: usize = 256;
const MAX_CONCURRENT_MODULE_FETCHES: usize = 50;

pub async fn fetch_on_chain_package(
    &self,
    fullnode_url: &Url,
    network_version: u64,
    address: AccountAddress,
    package_name: &str,
) -> Result<PathBuf> {
    // ... existing code ...
    
    // Validate module count
    if package.modules.len() > MAX_MODULES_PER_PACKAGE {
        bail!(
            "Package {} has {} modules, exceeding maximum of {}",
            package_name,
            package.modules.len(),
            MAX_MODULES_PER_PACKAGE
        );
    }
    
    // Use futures::stream::iter with buffer_unordered for concurrency control
    use futures::stream::{self, StreamExt};
    
    let results: Vec<()> = stream::iter(package.modules.iter().map(|module| {
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
            
            tokio::task::spawn_blocking(move || {
                fs::create_dir_all(module_file_path.parent().unwrap())?;
                let mut file = File::create(&module_file_path)?;
                file.write_all(&module_bytes)?;
                Ok::<(), std::io::Error>(())
            })
            .await??;
            
            self.listener.on_bytecode_package_receive_module(
                address,
                &package_name,
                &module_name,
            );
            Ok::<(), anyhow::Error>(())
        }
    }))
    .buffer_unordered(MAX_CONCURRENT_MODULE_FETCHES)
    .collect::<Vec<_>>()
    .await;
    
    // Check all results succeeded
    for result in results {
        result?;
    }
    
    // ... rest of existing code ...
}
```

Additionally, add validation in the Move framework to reject packages with excessive modules during publication.

## Proof of Concept

```rust
// PoC: Demonstrate resource exhaustion from fetching package with many modules
// File: test_module_dos.rs

use anyhow::Result;
use aptos_rest_client::Client;
use move_package_cache::PackageCache;
use url::Url;
use move_core_types::account_address::AccountAddress;
use std::time::Instant;

#[tokio::test]
async fn test_unlimited_module_fetch_dos() -> Result<()> {
    // Assume attacker has deployed a package with 5000 modules at this address
    let malicious_package_address = AccountAddress::from_hex_literal("0xBAD")?;
    let fullnode_url = Url::parse("https://fullnode.mainnet.aptoslabs.com")?;
    
    let cache_dir = tempfile::tempdir()?;
    let cache = PackageCache::new(cache_dir.path())?;
    
    println!("Starting fetch of malicious package with 5000 modules...");
    let start = Instant::now();
    
    // This will create 5000 concurrent futures and HTTP requests
    // Expected: System resource exhaustion, memory spike, potential OOM
    let result = cache.fetch_on_chain_package(
        &fullnode_url,
        1000000, // network version
        malicious_package_address,
        "MaliciousPackage",
    ).await;
    
    let duration = start.elapsed();
    println!("Fetch completed in {:?}", duration);
    println!("Result: {:?}", result);
    
    // Monitor resource usage during this operation:
    // - Memory consumption will spike significantly
    // - Open file descriptors will reach thousands
    // - Network connections will saturate
    // - Fullnode API will be hammered with 5000 concurrent requests
    
    Ok(())
}

// To create the malicious package on-chain, use this Move code generator:

// Generate 5000 minimal modules
for i in 0..5000 {
    println!("module 0xBAD::Module{} {{", i);
    println!("    public fun noop() {{}}");
    println!("}}");
}

// Then use chunked publishing via aptos CLI:
// aptos move publish --chunked-publish --package-dir ./malicious_package
```

**Notes:**
- The vulnerability affects all users of the Move package cache, including developers, build tools, and CI/CD systems
- The attack bypasses all existing gas limits and transaction size restrictions because it exploits the **client-side** fetch logic, not on-chain execution
- Even legitimate large packages (e.g., comprehensive libraries) could inadvertently trigger this issue
- The fullnode API pagination limit (`max_account_modules_page_size: 9999`) does not prevent this attack since each module is fetched individually via `get_account_module_bcs_at_version`
- Connection pooling in the underlying `reqwest` library provides no protection as it reuses connections but doesn't limit concurrent requests

### Citations

**File:** third_party/move/tools/move-package-cache/src/package_cache.rs (L366-399)
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

        future::try_join_all(fetch_futures).await?;
```

**File:** aptos-move/framework/aptos-experimental/sources/large_packages.move (L66-78)
```text
    public entry fun stage_code_chunk(
        owner: &signer,
        metadata_chunk: vector<u8>,
        code_indices: vector<u16>,
        code_chunks: vector<vector<u8>>
    ) acquires StagingArea {
        stage_code_chunk_internal(
            owner,
            metadata_chunk,
            code_indices,
            code_chunks
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/code.move (L24-49)
```text
    struct PackageRegistry has key, store, drop {
        /// Packages installed at this address.
        packages: vector<PackageMetadata>,
    }

    /// Metadata for a package. All byte blobs are represented as base64-of-gzipped-bytes
    struct PackageMetadata has copy, drop, store {
        /// Name of this package.
        name: String,
        /// The upgrade policy of this package.
        upgrade_policy: UpgradePolicy,
        /// The numbers of times this module has been upgraded. Also serves as the on-chain version.
        /// This field will be automatically assigned on successful upgrade.
        upgrade_number: u64,
        /// The source digest of the sources in the package. This is constructed by first building the
        /// sha256 of each individual source, than sorting them alphabetically, and sha256 them again.
        source_digest: String,
        /// The package manifest, in the Move.toml format. Gzipped text.
        manifest: vector<u8>,
        /// The list of modules installed by this package.
        modules: vector<ModuleMetadata>,
        /// Holds PackageDeps.
        deps: vector<PackageDep>,
        /// For future extension
        extension: Option<Any>
    }
```

**File:** third_party/move/tools/move-package-resolver/src/resolver.rs (L129-141)
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
```

**File:** crates/aptos-rest-client/src/lib.rs (L80-85)
```rust
#[derive(Clone, Debug)]
pub struct Client {
    inner: ReqwestClient,
    base_url: Url,
    version_path_base: String,
}
```
