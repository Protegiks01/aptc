# Audit Report

## Title
Database Handle Confusion in Validation Tool Causes Validation of Wrong Database Instance

## Summary
The `validate_db_data()` function in the validation tool uses `AptosDB::new_for_test_with_sharding()` which opens databases using `StorageDirPaths::from_path()`, ignoring any custom shard paths configured via `db_path_overrides` in production nodes. This causes the validation tool to open and validate databases at default paths instead of the actual production database locations, potentially creating empty databases at wrong locations and validating incorrect data.

## Finding Description

The vulnerability exists in how the validation tool opens database handles compared to production nodes:

**Production Database Opening:**
Production nodes use `config.storage.get_dir_paths()` which respects custom shard paths configured via `db_path_overrides` [1](#0-0) 

This allows production nodes to store database shards on different physical paths (e.g., `/ssd1/state_kv_shard_0`, `/ssd2/state_kv_shard_1`) for performance optimization.

**Validation Tool Database Opening:**
The validation tool uses `new_for_test_with_sharding()` which internally uses `StorageDirPaths::from_path(db_root_path)` [2](#0-1) 

This creates a `StorageDirPaths` with all shard paths set to default (None) [3](#0-2) 

**Path Resolution:**
When accessing shard paths, the code falls back to the default path using `unwrap_or(&self.default_path)` [4](#0-3) 

**Database Creation:**
Since validation opens databases in read-write mode (readonly=false), RocksDB automatically creates new databases if they don't exist due to `create_if_missing(true)` [5](#0-4) 

**Exploitation Scenario:**
1. Production node configured with custom shard paths: `/disk1/state_kv_shard_0`, `/disk2/state_kv_shard_1`, etc.
2. Operator runs validation: `validate_db_data("/data/db", ...)`
3. Validation tool looks at default paths: `/data/db/state_kv_db/shard_0`, `/data/db/state_kv_db/shard_1`, etc.
4. These paths either don't exist or contain different/old data
5. Tool creates NEW empty databases at these default locations
6. Validation succeeds on wrong/empty databases
7. Operator receives false confidence that production database is valid

The same issue exists in `verify_state_kvs()` which also uses `StorageDirPaths::from_path()` [6](#0-5) 

## Impact Explanation

This qualifies as **Medium Severity** (up to $10,000) because it can lead to **state inconsistencies requiring intervention**. 

While this bug doesn't directly cause consensus violations or fund loss, it undermines database integrity verification in production environments. Operators relying on validation results may:
- Continue operating nodes with corrupted databases believing them to be valid
- Make incorrect decisions about database recovery or replacement
- Experience unexpected state inconsistencies during critical operations

The bug affects any production node using `db_path_overrides` for custom shard configurations, which is a supported and documented feature for performance optimization in production deployments.

## Likelihood Explanation

**High likelihood** of occurrence because:
1. Custom shard paths (`db_path_overrides`) are a documented feature for production deployments
2. Mainnet nodes are required to have `enable_storage_sharding` set to true [7](#0-6) 
3. The validation tool is explicitly designed for production database validation
4. No attacker action required - happens during normal validation operations
5. Developers are aware of similar issues in other tools (TODOs exist) [8](#0-7) 

## Recommendation

Fix the `validate_db_data()` function to accept and use a `StorageConfig` or `StorageDirPaths` parameter that properly respects custom shard paths:

```rust
pub fn validate_db_data(
    storage_dir_paths: StorageDirPaths,  // Changed from db_root_path: &Path
    internal_indexer_db_path: &Path,
    mut target_ledger_version: u64,
) -> Result<()> {
    // ... existing code ...
    
    // Use the provided storage_dir_paths instead of creating new one from path
    verify_state_kvs(&storage_dir_paths, &internal_db, target_ledger_version)?;
    
    // Open AptosDB using proper configuration
    let aptos_db = AptosDB::open(
        storage_dir_paths,
        false,  // readonly
        NO_OP_STORAGE_PRUNER_CONFIG,
        RocksdbConfigs {
            enable_storage_sharding: true,
            ..Default::default()
        },
        false,  // enable_indexer
        BUFFERED_STATE_TARGET_ITEMS_FOR_TEST,
        1000000,  // max_num_nodes_per_lru_cache_shard
        None,  // internal_indexer_db
        HotStateConfig::default(),
    )?;
    
    // ... rest of existing code ...
}
```

Update the CLI command to accept storage configuration from a config file or allow explicit shard path specification.

## Proof of Concept

```rust
// Setup: Create a config with custom shard paths
use std::path::PathBuf;
use aptos_config::config::{StorageConfig, DbPathConfig, ShardedDbPathConfig, ShardPathConfig};

// Simulate production config with custom shard paths
let mut prod_config = StorageConfig::default();
prod_config.db_path_overrides = Some(DbPathConfig {
    state_kv_db_path: Some(ShardedDbPathConfig {
        metadata_path: Some(PathBuf::from("/disk0/metadata")),
        shard_paths: vec![
            ShardPathConfig { shards: "0-7".to_string(), path: PathBuf::from("/disk1") },
            ShardPathConfig { shards: "8-15".to_string(), path: PathBuf::from("/disk2") },
        ],
    }),
    ..Default::default()
});

// Production node opens database correctly
let prod_paths = prod_config.get_dir_paths();
assert_eq!(prod_paths.state_kv_db_shard_root_path(0), &PathBuf::from("/disk1"));
assert_eq!(prod_paths.state_kv_db_shard_root_path(8), &PathBuf::from("/disk2"));

// Validation tool uses from_path(), ignoring custom paths
let validation_paths = StorageDirPaths::from_path("/data/db");
assert_eq!(validation_paths.state_kv_db_shard_root_path(0), &PathBuf::from("/data/db"));
assert_eq!(validation_paths.state_kv_db_shard_root_path(8), &PathBuf::from("/data/db"));

// Result: Validation tool opens databases at WRONG locations!
// Production data at /disk1, /disk2 is NOT validated
// Validation tool creates/checks databases at /data/db instead
```

## Notes

This vulnerability is a configuration mismatch between production database initialization and the validation tool. The issue stems from using a test helper function (`new_for_test_with_sharding`) in production validation code, which was designed for simple test scenarios without custom path configurations.

The bug is compounded by RocksDB's `create_if_missing` behavior, which silently creates new empty databases at the wrong locations instead of failing, making the issue difficult to detect during normal operations.

Similar limitations exist in other debugging tools (checkpoint creation, truncation), suggesting a systematic issue with how these tools handle production configurations.

### Citations

**File:** config/src/config/storage_config.rs (L467-507)
```rust
    pub fn get_dir_paths(&self) -> StorageDirPaths {
        let default_dir = self.dir();
        let mut ledger_db_path = None;
        let mut state_kv_db_paths = ShardedDbPaths::default();
        let mut state_merkle_db_paths = ShardedDbPaths::default();
        let mut hot_state_kv_db_paths = ShardedDbPaths::default();
        let mut hot_state_merkle_db_paths = ShardedDbPaths::default();

        if let Some(db_path_overrides) = self.db_path_overrides.as_ref() {
            db_path_overrides
                .ledger_db_path
                .clone_into(&mut ledger_db_path);

            if let Some(state_kv_db_path) = db_path_overrides.state_kv_db_path.as_ref() {
                state_kv_db_paths = ShardedDbPaths::new(state_kv_db_path);
            }

            if let Some(state_merkle_db_path) = db_path_overrides.state_merkle_db_path.as_ref() {
                state_merkle_db_paths = ShardedDbPaths::new(state_merkle_db_path);
            }

            if let Some(hot_state_kv_db_path) = db_path_overrides.hot_state_kv_db_path.as_ref() {
                hot_state_kv_db_paths = ShardedDbPaths::new(hot_state_kv_db_path);
            }

            if let Some(hot_state_merkle_db_path) =
                db_path_overrides.hot_state_merkle_db_path.as_ref()
            {
                hot_state_merkle_db_paths = ShardedDbPaths::new(hot_state_merkle_db_path);
            }
        }

        StorageDirPaths::new(
            default_dir,
            ledger_db_path,
            state_kv_db_paths,
            state_merkle_db_paths,
            hot_state_kv_db_paths,
            hot_state_merkle_db_paths,
        )
    }
```

**File:** config/src/config/storage_config.rs (L548-552)
```rust
    pub fn state_kv_db_shard_root_path(&self, shard_id: usize) -> &PathBuf {
        self.state_kv_db_paths
            .shard_path(shard_id)
            .unwrap_or(&self.default_path)
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

**File:** config/src/config/storage_config.rs (L664-668)
```rust
            if (chain_id.is_testnet() || chain_id.is_mainnet())
                && config_yaml["rocksdb_configs"]["enable_storage_sharding"].as_bool() != Some(true)
            {
                panic!("Storage sharding (AIP-97) is not enabled in node config. Please follow the guide to migration your node, and set storage.rocksdb_configs.enable_storage_sharding to true explicitly in your node config. https://aptoslabs.notion.site/DB-Sharding-Migration-Public-Full-Nodes-1978b846eb7280b29f17ceee7d480730");
            }
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L72-72)
```rust
    let aptos_db = AptosDB::new_for_test_with_sharding(db_root_path, 1000000);
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L120-122)
```rust
    let storage_dir = StorageDirPaths::from_path(db_root_path);
    let state_kv_db =
        StateKvDb::open_sharded(&storage_dir, RocksdbConfig::default(), None, None, false)?;
```

**File:** storage/rocksdb-options/src/lib.rs (L38-41)
```rust
    if !readonly {
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
    }
```

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L27-27)
```rust
    // TODO(grao): Support db_path_overrides here.
```
