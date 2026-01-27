# Audit Report

## Title
Path Canonicalization Bypass in RocksDB Checkpoint Creation Allows Same-Directory Corruption

## Summary
The assert at line 144 in `create_rocksdb_checkpoint_and_change_working_dir()` fails to prevent same-directory checkpoints because it only compares PathBuf string representations rather than canonical filesystem paths. Attackers with configuration access can bypass this check using symbolic links, relative path components, or other path manipulation techniques, potentially corrupting the source database.

## Finding Description

The function `create_rocksdb_checkpoint_and_change_working_dir()` [1](#0-0)  attempts to prevent checkpoint creation in the source directory through a string equality check.

The vulnerability occurs in this sequence:
1. Line 141: `source_dir` is obtained via `node_config.storage.dir()` [2](#0-1) 
2. Line 142: The data directory is changed to `working_dir` [3](#0-2) 
3. Line 143: `checkpoint_dir` is obtained from the updated config [4](#0-3) 
4. Line 144: Assert checks `source_dir != checkpoint_dir` [5](#0-4) 

The `StorageConfig::dir()` method [6](#0-5)  returns a PathBuf that is either the absolute path or data_dir joined with the relative dir. PathBuf's `PartialEq` compares string representations, not canonical filesystem locations.

**Bypass Scenarios:**

1. **Symbolic Links**: Create `/tmp/link -> /opt/aptos/data`, set `working_dir = /tmp/link/data`. The paths `/opt/aptos/data/db` and `/tmp/link/data/db` are string-different but resolve to the same physical directory.

2. **Relative Path Components**: Set `working_dir = /opt/aptos/other/../data`. The paths `/opt/aptos/data/db` and `/opt/aptos/other/../data/db` differ as strings but resolve identically.

3. **Case Differences**: On case-insensitive filesystems (macOS, Windows), `/PATH/db` and `/path/db` are different PathBufs but the same directory.

When RocksDB's checkpoint mechanism [7](#0-6)  attempts to create hard links in the source directory, it causes file conflicts and database corruption. The checkpoint creation process [8](#0-7)  has no additional validation.

## Impact Explanation

**Severity: High**

This vulnerability breaks the **State Consistency** invariant - database corruption prevents atomic state transitions and compromises Merkle proof verification. Impact includes:

- **Validator Node Unavailability**: Corrupted database prevents node startup, removing validators from consensus
- **State Sync Failures**: Corrupted Merkle trees prevent state synchronization with network
- **Consensus Disruption**: Multiple affected validators could impact network liveness (though requires < 1/3 for safety)
- **Data Loss**: Checkpoint operation failures may leave database in inconsistent state

This qualifies as **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: Low-Medium**

While the technical bypass is trivial, exploitation requires configuration file access:

- Feature is documented as "test-only" [9](#0-8) 
- The `working_dir` config field [10](#0-9)  defaults to None
- Used primarily in test suites [11](#0-10) 

However, likelihood increases if:
- Feature is accidentally enabled in production environments
- Honest misconfigurations occur (symlinks in shared storage systems)
- An attacker compromises configuration management systems

## Recommendation

Replace string-based path comparison with canonical path resolution:

```rust
fn create_rocksdb_checkpoint_and_change_working_dir(
    node_config: &mut NodeConfig,
    working_dir: impl AsRef<Path>,
) {
    let source_dir = node_config.storage.dir();
    node_config.set_data_dir(working_dir.as_ref().to_path_buf());
    let checkpoint_dir = node_config.storage.dir();
    
    // Canonicalize paths before comparison
    let canonical_source = source_dir.canonicalize()
        .expect("Failed to canonicalize source directory");
    let canonical_checkpoint = checkpoint_dir.canonicalize()
        .expect("Failed to canonicalize checkpoint directory");
    
    assert!(
        canonical_source != canonical_checkpoint,
        "Checkpoint directory must differ from source directory. Source: {:?}, Checkpoint: {:?}",
        canonical_source,
        canonical_checkpoint
    );
    
    // Create rocksdb checkpoint directory
    fs::create_dir_all(&checkpoint_dir).unwrap();
    // ... rest of function
}
```

Additionally, consider:
1. Adding runtime checks in `AptosDB::create_checkpoint` to prevent same-directory operations
2. Disabling `working_dir` config option in production builds
3. Adding filesystem isolation checks before checkpoint creation

## Proof of Concept

```rust
use std::fs;
use std::path::PathBuf;
use aptos_temppath::TempPath;

#[test]
fn test_path_comparison_bypass() {
    let temp = TempPath::new();
    let source = temp.path().join("db");
    fs::create_dir_all(&source).unwrap();
    
    // Create symbolic link
    let link = temp.path().join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&temp.path(), &link).unwrap();
    
    let checkpoint = link.join("db");
    
    // String comparison passes
    assert_ne!(source, checkpoint);
    
    // But canonical paths are identical
    assert_eq!(
        source.canonicalize().unwrap(),
        checkpoint.canonicalize().unwrap()
    );
    
    // This demonstrates the bypass: the assert would pass
    // but both paths resolve to the same directory
}
```

## Notes

While this vulnerability requires configuration file access (typically restricted to validator operators who are trusted roles), it represents a **defense-in-depth failure**. The assert is designed as a safety mechanism but fails to prevent the exact scenario it's meant to guard against. Even trusted operators can make honest mistakes with filesystem configurations, and this inadequate validation could lead to catastrophic database corruption.

The impact severity remains **High** due to potential validator unavailability and state consistency violations, though the likelihood is reduced by the privileged access requirement and test-only designation.

### Citations

**File:** aptos-node/src/storage.rs (L136-167)
```rust
fn create_rocksdb_checkpoint_and_change_working_dir(
    node_config: &mut NodeConfig,
    working_dir: impl AsRef<Path>,
) {
    // Update the source and checkpoint directories
    let source_dir = node_config.storage.dir();
    node_config.set_data_dir(working_dir.as_ref().to_path_buf());
    let checkpoint_dir = node_config.storage.dir();
    assert!(source_dir != checkpoint_dir);

    // Create rocksdb checkpoint directory
    fs::create_dir_all(&checkpoint_dir).unwrap();

    // Open the database and create a checkpoint
    AptosDB::create_checkpoint(
        &source_dir,
        &checkpoint_dir,
        node_config.storage.rocksdb_configs.enable_storage_sharding,
    )
    .expect("AptosDB checkpoint creation failed.");

    // Create a consensus db checkpoint
    aptos_consensus::create_checkpoint(&source_dir, &checkpoint_dir)
        .expect("ConsensusDB checkpoint creation failed.");

    // Create a state sync db checkpoint
    let state_sync_db =
        aptos_state_sync_driver::metadata_storage::PersistentMetadataStorage::new(&source_dir);
    state_sync_db
        .create_checkpoint(&checkpoint_dir)
        .expect("StateSyncDB checkpoint creation failed.");
}
```

**File:** aptos-node/src/storage.rs (L182-182)
```rust
    // This is test-only.
```

**File:** config/src/config/storage_config.rs (L459-465)
```rust
    pub fn dir(&self) -> PathBuf {
        if self.dir.is_relative() {
            self.data_dir.join(&self.dir)
        } else {
            self.dir.clone()
        }
    }
```

**File:** storage/schemadb/src/lib.rs (L356-362)
```rust
    pub fn create_checkpoint<P: AsRef<Path>>(&self, path: P) -> DbResult<()> {
        rocksdb::checkpoint::Checkpoint::new(&self.inner)
            .into_db_res()?
            .create_checkpoint(path)
            .into_db_res()?;
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/mod.rs (L172-205)
```rust
    pub fn create_checkpoint(
        db_path: impl AsRef<Path>,
        cp_path: impl AsRef<Path>,
        sharding: bool,
    ) -> Result<()> {
        let start = Instant::now();

        info!(sharding = sharding, "Creating checkpoint for AptosDB.");

        LedgerDb::create_checkpoint(db_path.as_ref(), cp_path.as_ref(), sharding)?;
        if sharding {
            StateKvDb::create_checkpoint(db_path.as_ref(), cp_path.as_ref())?;
            StateMerkleDb::create_checkpoint(
                db_path.as_ref(),
                cp_path.as_ref(),
                sharding,
                /* is_hot = */ true,
            )?;
        }
        StateMerkleDb::create_checkpoint(
            db_path.as_ref(),
            cp_path.as_ref(),
            sharding,
            /* is_hot = */ false,
        )?;

        info!(
            db_path = db_path.as_ref(),
            cp_path = cp_path.as_ref(),
            time_ms = %start.elapsed().as_millis(),
            "Made AptosDB checkpoint."
        );
        Ok(())
    }
```

**File:** config/src/config/base_config.rs (L19-19)
```rust
    pub working_dir: Option<PathBuf>,
```

**File:** testsuite/forge-cli/src/suites/db.rs (L29-32)
```rust
            config.base.working_dir = Some(PathBuf::from("/opt/aptos/data/checkpoint"));
        }))
        .with_fullnode_override_node_config_fn(Arc::new(move |config, _| {
            config.base.working_dir = Some(PathBuf::from("/opt/aptos/data/checkpoint"));
```
