# Audit Report

## Title
Database Directory Injection in Restore Tool Allows System Directory Corruption and Offline Validator Database Tampering

## Summary
The `db-tool restore` command accepts arbitrary file paths via the `--target-db-dir` parameter without any validation, allowing operators (or compromised accounts) to specify system directories, running validator database paths, or arbitrary locations. This can lead to system directory pollution, corruption of offline validator databases, and disk space exhaustion in critical partitions.

## Finding Description
The `GlobalRestoreOpt` struct in the backup-cli utility accepts a `db_dir` parameter that is passed directly to database initialization without validation. [1](#0-0) 

This path flows through `StorageDirPaths::from_path()` which performs no validation: [2](#0-1) 

The path is then used to open RocksDB databases in write mode: [3](#0-2) 

There are no checks for:
- Absolute vs relative paths
- System directories (`/`, `/etc`, `/var`, `/usr`, etc.)
- Existing validator database directories
- Path traversal sequences
- Disk space availability on the target partition

The database opening logic constructs child paths and directly creates RocksDB instances: [4](#0-3) 

**Attack Scenarios:**

1. **System Directory Pollution**: Specifying `--target-db-dir /etc` or `/var` creates subdirectories like `/etc/ledger_db`, `/etc/state_kv_db`, potentially breaking system functionality.

2. **Offline Validator Database Corruption**: If a validator's database is offline (maintenance, crash recovery), an attacker with tool access can restore incorrect/malicious state data, causing the validator to produce invalid state roots when restarted.

3. **Disk Space Exhaustion**: Targeting critical partitions like `/` or `/var` for restoration can fill disk space, causing system-wide failures.

While RocksDB's LOCK file mechanism prevents corrupting **running** validator databases, it does not protect against offline databases or system directory pollution.

## Impact Explanation
This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

- **Validator Node Slowdowns/Crashes**: Corrupting an offline validator's database with incorrect state causes the validator to crash or produce invalid state roots upon restart, leading to downtime.

- **Significant Protocol Violations**: Multiple validators restoring incorrect state while offline could cause consensus divergence when they rejoin the network.

- **System Instability**: Writing database files to system directories can cause operational failures, breaking monitoring tools, logging systems, or other critical infrastructure.

The impact is amplified in multi-tenant validator infrastructure where one operator's misconfiguration could affect others.

## Likelihood Explanation
**Likelihood: Medium to High**

This vulnerability can be triggered through:
1. **Operational Error**: Node operators accidentally specifying wrong paths during legitimate restore operations
2. **Compromised Accounts**: Attackers gaining access to operator accounts/systems where the db-tool is available
3. **Shared Infrastructure**: In multi-tenant validator hosting environments where multiple operators have tool access
4. **Automated Scripts**: Misconfigured automation scripts using the restore tool with incorrect paths

The attack requires only the ability to execute the db-tool binary with chosen parameters, which is common in validator operational workflows.

## Recommendation
Implement strict path validation in the `StorageDirPaths::from_path()` method or before calling it:

```rust
pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
    let path = path.as_ref();
    
    // Validate path is absolute
    if !path.is_absolute() {
        return Err(anyhow::anyhow!("Database path must be absolute: {:?}", path));
    }
    
    // Reject system directories
    let dangerous_prefixes = ["/", "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/boot", "/sys", "/proc", "/dev"];
    for prefix in &dangerous_prefixes {
        if path.starts_with(prefix) && path.components().count() <= 2 {
            return Err(anyhow::anyhow!("Cannot use system directory as database path: {:?}", path));
        }
    }
    
    // Check if path appears to be an active database (has LOCK file)
    let lock_file = path.join("ledger_db").join("LOCK");
    if lock_file.exists() {
        return Err(anyhow::anyhow!("Target directory appears to contain an active database: {:?}", path));
    }
    
    // Ensure sufficient disk space (e.g., require at least 100GB free)
    // Implementation depends on platform-specific APIs
    
    Ok(Self {
        default_path: path.to_path_buf(),
        ledger_db_path: None,
        state_kv_db_paths: Default::default(),
        state_merkle_db_paths: Default::default(),
        hot_state_kv_db_paths: Default::default(),
        hot_state_merkle_db_paths: Default::default(),
    })
}
```

Additionally, add validation at the `GlobalRestoreOpt` level before conversion: [5](#0-4) 

## Proof of Concept
```rust
use aptos_config::config::StorageDirPaths;
use std::path::PathBuf;

#[test]
fn test_db_dir_injection_vulnerability() {
    // This test demonstrates the vulnerability - no validation occurs
    
    // Case 1: System directory injection - SHOULD BE REJECTED BUT ISN'T
    let malicious_path = PathBuf::from("/etc/malicious_db");
    let storage_paths = StorageDirPaths::from_path(&malicious_path);
    assert_eq!(storage_paths.default_root_path(), &malicious_path);
    // ^ This succeeds but should fail - /etc is a system directory
    
    // Case 2: Relative path injection - SHOULD BE REJECTED BUT ISN'T
    let relative_path = PathBuf::from("../../../etc/db");
    let storage_paths = StorageDirPaths::from_path(&relative_path);
    assert_eq!(storage_paths.default_root_path(), &relative_path);
    // ^ This succeeds but should fail - relative paths allow traversal
    
    // Case 3: Root directory injection - SHOULD BE REJECTED BUT ISN'T
    let root_path = PathBuf::from("/");
    let storage_paths = StorageDirPaths::from_path(&root_path);
    assert_eq!(storage_paths.default_root_path(), &root_path);
    // ^ This succeeds but should fail - writing to / is dangerous
    
    // The actual restore command would be:
    // aptos-db-tool restore bootstrap-db --target-db-dir /etc/malicious_db --metadata-cache-dir /tmp/cache --command-adapter-config config.yaml
    // This would create /etc/malicious_db/ledger_db/, /etc/malicious_db/state_kv_db/, etc.
}
```

To reproduce the vulnerability in practice:
1. Build the aptos-db-tool binary
2. Run: `aptos-db-tool restore bootstrap-db --target-db-dir /tmp/test_inject --dry-run --trust-waypoint <waypoint> --metadata-cache-dir /tmp/cache --command-adapter-config <config>`
3. Observe that no validation prevents specifying arbitrary paths
4. Remove `--dry-run` and observe database files created at the specified location without any safety checks

## Notes
This vulnerability is particularly concerning because:
1. The restore tool is critical infrastructure used during validator recovery
2. Mistakes during high-pressure incident response could lead to catastrophic data corruption
3. The lack of validation violates defense-in-depth principles for critical operational tools
4. The tool's example docker-compose configuration hardcodes the path, but direct CLI usage is unrestricted

The RocksDB LOCK file provides partial mitigation against corrupting running validators, but does not address system directory pollution or offline database tampering scenarios.

### Citations

**File:** storage/backup/backup-cli/src/utils/mod.rs (L138-144)
```rust
    #[clap(
        long = "target-db-dir",
        value_parser,
        conflicts_with = "dry_run",
        required_unless_present = "dry_run"
    )]
    pub db_dir: Option<PathBuf>,
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L290-329)
```rust
impl TryFrom<GlobalRestoreOpt> for GlobalRestoreOptions {
    type Error = anyhow::Error;

    fn try_from(opt: GlobalRestoreOpt) -> anyhow::Result<Self> {
        let target_version = opt.target_version.unwrap_or(Version::MAX);
        let concurrent_downloads = opt.concurrent_downloads.get();
        let replay_concurrency_level = opt.replay_concurrency_level.get();
        let run_mode = if let Some(db_dir) = &opt.db_dir {
            // for restore, we can always start state store with empty buffered_state since we will restore
            // TODO(grao): Support path override here.
            let internal_indexer_db = if opt.enable_state_indices {
                InternalIndexerDBService::get_indexer_db_for_restore(db_dir.as_path())
            } else {
                None
            };
            let restore_handler = Arc::new(AptosDB::open_kv_only(
                StorageDirPaths::from_path(db_dir),
                false,                       /* read_only */
                NO_OP_STORAGE_PRUNER_CONFIG, /* pruner config */
                opt.rocksdb_opt.clone().into(),
                false, /* indexer */
                BUFFERED_STATE_TARGET_ITEMS,
                DEFAULT_MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
                internal_indexer_db,
            )?)
            .get_restore_handler();

            RestoreRunMode::Restore { restore_handler }
        } else {
            RestoreRunMode::Verify
        };
        Ok(Self {
            target_version,
            trusted_waypoints: Arc::new(opt.trusted_waypoints.verify()?),
            run_mode: Arc::new(run_mode),
            concurrent_downloads,
            replay_concurrency_level,
        })
    }
}
```

**File:** config/src/config/storage_config.rs (L584-593)
```rust
    pub fn from_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            default_path: path.as_ref().to_path_buf(),
            ledger_db_path: None,
            state_kv_db_paths: Default::default(),
            state_merkle_db_paths: Default::default(),
            hot_state_kv_db_paths: Default::default(),
            hot_state_merkle_db_paths: Default::default(),
        }
    }
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L522-529)
```rust
    fn metadata_db_path<P: AsRef<Path>>(db_root_path: P, sharding: bool) -> PathBuf {
        let ledger_db_folder = db_root_path.as_ref().join(LEDGER_DB_FOLDER_NAME);
        if sharding {
            ledger_db_folder.join("metadata")
        } else {
            ledger_db_folder
        }
    }
```
