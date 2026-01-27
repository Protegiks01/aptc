# Audit Report

## Title
Insufficient Path Validation in IndexerGrpcCacheWorker File Store Configuration

## Summary
The `IndexerGrpcCacheWorkerConfig::new()` function does not validate the `file_store_config` parameter to prevent arbitrary file system access. When configured with a `LocalFileStore`, an attacker who controls the configuration file or environment variables can specify any directory path, leading to unauthorized file system access.

## Finding Description

The indexer-grpc-cache-worker loads its configuration from a YAML file without validating the `local_file_store_path` parameter. [1](#0-0) 

The configuration is loaded via the server framework which uses Figment to parse YAML and environment variables, with no path validation. [2](#0-1) 

The `RunnableConfig` trait provides a default `validate()` method that returns `Ok(())`, and `IndexerGrpcCacheWorkerConfig` does not override it. [3](#0-2) 

When the worker creates a file store operator, it uses the unvalidated path. [4](#0-3) 

The `LocalFileStoreOperator::new()` only verifies the path exists, not whether it's a safe location. [5](#0-4) 

File operations then use this path directly for reading and writing. [6](#0-5) 

**Attack Path:**
1. Attacker gains access to modify the cache-worker-config.yaml file (e.g., through compromised CI/CD, misconfigured deployment, or insider access)
2. Sets `local_file_store_path` to a sensitive directory (e.g., `/etc`, `/var/log`, or application directories)
3. The worker reads/writes files from the malicious path, exposing or corrupting data

## Impact Explanation

This vulnerability does NOT meet the severity criteria for the Aptos bug bounty program because:

1. **No Impact on Core Blockchain**: The indexer-grpc-cache-worker is an auxiliary service in the `ecosystem/` directory, not part of the core consensus, execution, or storage layers. Compromising it does not affect blockchain safety, liveness, or funds.

2. **Requires Privileged Access**: Exploitation requires the attacker to already have privileged access to modify deployment configurations or environment variables. This is not exploitable by an unprivileged external attacker.

3. **No Critical Invariant Violation**: This does not break any of the documented critical invariants (deterministic execution, consensus safety, state consistency, etc.).

4. **Limited to Data Service**: The impact is limited to the indexer data service, which provides read-only blockchain data access to external consumers, not to validators or core blockchain operations.

## Likelihood Explanation

The likelihood of exploitation is **LOW** because:
- Requires privileged access to deployment configuration
- Configuration files are typically protected in production environments
- Docker deployments mount configs as read-only volumes from the host
- This is essentially an insider threat or post-compromise scenario

## Recommendation

While this doesn't meet the bug bounty criteria, defense-in-depth improvements would include:

1. Implement path validation in `IndexerGrpcCacheWorkerConfig::validate()`:
   - Verify paths are within expected directories
   - Canonicalize paths and check for directory traversal
   - Reject absolute paths to sensitive system directories

2. Use path allowlisting in the configuration schema

3. Run the indexer with minimal file system permissions

4. Add runtime monitoring for unexpected file access patterns

## Proof of Concept

```rust
// This demonstrates the lack of validation, not a full exploit
use std::path::PathBuf;
use aptos_indexer_grpc_utils::config::{IndexerGrpcFileStoreConfig, LocalFileStore};

#[test]
fn test_no_path_validation() {
    // Configuration accepts any path that exists
    let malicious_config = IndexerGrpcFileStoreConfig::LocalFileStore(
        LocalFileStore {
            local_file_store_path: PathBuf::from("/etc"), // Sensitive directory
            enable_compression: false,
        }
    );
    
    // No validation error occurs
    let file_store = malicious_config.create();
    // File store would now operate on /etc directory
}
```

**However, this does not constitute an exploitable vulnerability per the Aptos bug bounty requirements.**

---

## Notes

After thorough analysis, this issue does **NOT** meet the EXTREMELY high validation bar required:

- ❌ **Not exploitable by unprivileged attacker** - requires config/environment access
- ❌ **Does not break critical invariants** - indexer is auxiliary, not core blockchain
- ❌ **No impact on funds/consensus/availability** - limited to data service
- ❌ **Not a protocol vulnerability** - this is a deployment security concern

**The indexer-grpc-cache-worker is an ecosystem tool for blockchain data access, not part of the consensus-critical validator infrastructure.** While the lack of path validation is a security hardening opportunity, it does not represent an exploitable vulnerability in the context of the Aptos bug bounty program's scope.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/lib.rs (L29-41)
```rust
    pub fn new(
        fullnode_grpc_address: Url,
        file_store_config: IndexerGrpcFileStoreConfig,
        redis_main_instance_address: RedisUrl,
        enable_cache_compression: bool,
    ) -> Self {
        Self {
            fullnode_grpc_address,
            file_store_config,
            redis_main_instance_address,
            enable_cache_compression,
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L113-116)
```rust
    // Validate the config.
    fn validate(&self) -> Result<()> {
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L130-136)
```rust
pub fn load<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T> {
    Figment::new()
        .merge(Yaml::file(path))
        .merge(Env::raw().split("__"))
        .extract()
        .map_err(anyhow::Error::msg)
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L119-120)
```rust
            // 1. Fetch metadata.
            let file_store_operator: Box<dyn FileStoreOperator> = self.file_store.create();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L23-36)
```rust
impl LocalFileStoreOperator {
    pub fn new(path: PathBuf, enable_compression: bool) -> Self {
        let storage_format = if enable_compression {
            StorageFormat::Lz4CompressedProto
        } else {
            StorageFormat::JsonBase64UncompressedProto
        };
        Self {
            path,
            latest_metadata_update_timestamp: None,
            storage_format,
        }
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator/local.rs (L58-74)
```rust
    async fn get_raw_file(&self, version: u64) -> anyhow::Result<Vec<u8>> {
        let file_entry_key = FileEntry::build_key(version, self.storage_format).to_string();
        let file_path = self.path.join(file_entry_key);
        match tokio::fs::read(file_path).await {
            Ok(file) => Ok(file),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    anyhow::bail!("[Indexer File] Transactions file not found. Gap might happen between cache and file store. {}", err)
                } else {
                    anyhow::bail!(
                        "[Indexer File] Error happens when transaction file. {}",
                        err
                    );
                }
            },
        }
    }
```
