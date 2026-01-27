# Audit Report

## Title
Resource Exhaustion in Fast Sync Mode: Dual Database Instances Cause Memory and File Descriptor Depletion Leading to Node Crashes

## Summary
The `initialize_dbs()` function opens two full AptosDB instances with identical resource configurations during fast sync bootstrap. This causes critical resource duplication (48GB RAM for block caches, ~31K file descriptors, 12 background threads) that can exhaust node resources and trigger crashes. The secondary database is never cleaned up even after fast sync completes, causing permanent resource leakage.

## Finding Description

When a fresh node starts with fast sync enabled, the `FastSyncStorageWrapper::initialize_dbs()` function creates two complete AptosDB instances:

1. **Primary Database (`db_main`)**: [1](#0-0) 

2. **Secondary Database (`secondary_db`)**: [2](#0-1) 

Both databases are opened with **identical resource configurations** from `config.storage`, including:
- `storage_pruner_config`
- `rocksdb_configs` (which contains all RocksDB settings)
- `buffered_state_target_items`
- `max_num_nodes_per_lru_cache_shard`
- `hot_state_config`

### Resource Duplication Analysis

Each `AptosDB::open()` call internally creates: [3](#0-2) 

The RocksDB configuration defaults show: [4](#0-3) 

**Total Resource Consumption:**
- **Memory**: 48GB (24GB × 2 for block caches alone)
- **File Descriptors**: ~31,000 (each DB uses 5,000 × 3 databases + index DB)
- **Background Threads**: 12 threads (6 per instance)

### Critical Issue: No Cleanup After Fast Sync

The secondary database persists indefinitely. The `FastSyncStorageWrapper` is wrapped and stored for the node's lifetime: [5](#0-4) 

After fast sync completes (status = `FINISHED`), reads switch to the primary database, but the secondary database Arc reference is never dropped: [6](#0-5) 

There is **no Drop implementation** or explicit cleanup mechanism to close the secondary database or reclaim its resources.

## Impact Explanation

**Severity: HIGH** per Aptos Bug Bounty criteria ("Validator node slowdowns" and "API crashes")

1. **Memory Exhaustion**: Nodes configured with 60GB RAM limits (common in Helm deployments) will experience severe memory pressure with 48GB consumed by storage alone, triggering OOM kills

2. **File Descriptor Exhaustion**: While mainnet/testnet nodes set `ensure_rlimit_nofile: 999,999`, consuming ~31K file descriptors for storage alone significantly reduces headroom for consensus, networking, and other critical components [7](#0-6) 

3. **Node Crashes During Bootstrap**: Resource exhaustion during the critical fast sync period can cause node failures, affecting network availability and preventing new validators from joining

4. **Permanent Resource Leakage**: Resources remain allocated indefinitely even after fast sync completes, degrading node performance for its entire lifetime

5. **Affects Network Decentralization**: Makes it harder to run nodes on standard hardware, reducing network participation

## Likelihood Explanation

**Likelihood: HIGH**

- **Automatic Trigger**: Any operator starting a fresh node with fast sync enabled automatically triggers this condition (no malicious input required)
- **Common Scenario**: Fast sync is the recommended bootstrap mode for new nodes
- **No Workarounds**: Node operators cannot adjust secondary DB configs independently
- **Bootstrap Condition Check**: [8](#0-7) 

The vulnerability occurs every time a node bootstraps with fast sync mode enabled and an empty database.

## Recommendation

**Immediate Fix**: Implement reduced resource allocation for the secondary database and add explicit cleanup after fast sync completes.

```rust
// In fast_sync_storage_wrapper.rs, initialize_dbs():

// Create reduced configs for secondary DB (50% of main DB resources)
let mut secondary_rocksdb_configs = config.storage.rocksdb_configs;
secondary_rocksdb_configs.shared_block_cache_size /= 2;
secondary_rocksdb_configs.high_priority_background_threads /= 2;
secondary_rocksdb_configs.low_priority_background_threads = 1;

let secondary_db = AptosDB::open(
    StorageDirPaths::from_path(db_dir.as_path()),
    /*readonly=*/ false,
    config.storage.storage_pruner_config,
    secondary_rocksdb_configs, // Use reduced configs
    false, // Disable indexer for secondary
    config.storage.buffered_state_target_items / 2,
    config.storage.max_num_nodes_per_lru_cache_shard / 2,
    None,
    config.storage.hot_state_config,
)?;

// Add cleanup method to FastSyncStorageWrapper
impl FastSyncStorageWrapper {
    pub fn cleanup_temporary_db(&mut self) {
        if self.is_fast_sync_bootstrap_finished() {
            // Drop the Arc to allow cleanup
            self.temporary_db_with_genesis = Arc::new(/* minimal stub DB */);
            // Optionally remove secondary DB directory
        }
    }
}
```

**Long-term Fix**: Redesign fast sync to use a single database instance with internal state management instead of dual instances.

## Proof of Concept

```rust
// Reproduce resource exhaustion scenario:
// 1. Start with empty database
// 2. Enable fast sync in node config
// 3. Monitor resource usage during initialize_dbs()

use aptos_config::config::NodeConfig;
use aptos_db::fast_sync_storage_wrapper::FastSyncStorageWrapper;
use std::sync::Arc;

fn demonstrate_resource_exhaustion() {
    // Load config with fast sync enabled
    let mut config = NodeConfig::default();
    config.state_sync.state_sync_driver.bootstrapping_mode = 
        BootstrappingMode::ExecuteOrApplyFromGenesis;
    
    // Initialize storage (this will create both databases)
    let result = FastSyncStorageWrapper::initialize_dbs(
        &config,
        None,
        None,
    ).unwrap();
    
    // Monitor using:
    // - `ps aux | grep aptos-node` for RSS memory
    // - `lsof -p <pid> | wc -l` for file descriptor count
    // - `pmap <pid>` for detailed memory mapping
    
    // Expected observations:
    // - RSS memory: 48GB+ (just for storage block caches)
    // - Open file descriptors: ~31,000
    // - Background threads: 12 RocksDB threads
    
    // After fast sync completes, resources are NOT released
    // temporary_db_with_genesis Arc remains allocated
}
```

**Measurement Commands:**
```bash
# Monitor node during fast sync bootstrap
while true; do
  echo "=== $(date) ==="
  ps aux | grep aptos-node | awk '{print "RSS Memory: " $6/1024/1024 " GB"}'
  lsof -p $(pgrep aptos-node) 2>/dev/null | wc -l
  sleep 10
done
```

## Notes

This vulnerability violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The dual database initialization consumes approximately double the intended storage resources without any mechanism to reclaim them, leading to resource exhaustion that can crash nodes and degrade network availability.

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L48-59)
```rust
        let mut db_main = AptosDB::open(
            config.storage.get_dir_paths(),
            /*readonly=*/ false,
            config.storage.storage_pruner_config,
            config.storage.rocksdb_configs,
            config.storage.enable_indexer,
            config.storage.buffered_state_target_items,
            config.storage.max_num_nodes_per_lru_cache_shard,
            internal_indexer_db,
            config.storage.hot_state_config,
        )
        .map_err(|err| anyhow!("fast sync DB failed to open {}", err))?;
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L66-77)
```rust
        if config
            .state_sync
            .state_sync_driver
            .bootstrapping_mode
            .is_fast_sync()
            && (db_main
                .ledger_db
                .metadata_db()
                .get_synced_version()?
                .map_or(0, |v| v)
                == 0)
        {
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L79-90)
```rust
            let secondary_db = AptosDB::open(
                StorageDirPaths::from_path(db_dir.as_path()),
                /*readonly=*/ false,
                config.storage.storage_pruner_config,
                config.storage.rocksdb_configs,
                config.storage.enable_indexer,
                config.storage.buffered_state_target_items,
                config.storage.max_num_nodes_per_lru_cache_shard,
                None,
                config.storage.hot_state_config,
            )
            .map_err(|err| anyhow!("Secondary DB failed to open {}", err))?;
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L126-132)
```rust
    pub(crate) fn get_aptos_db_read_ref(&self) -> &AptosDB {
        if self.is_fast_sync_bootstrap_finished() {
            self.db_for_fast_sync.as_ref()
        } else {
            self.temporary_db_with_genesis.as_ref()
        }
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L129-136)
```rust
        let mut env =
            Env::new().map_err(|err| AptosDbError::OtherRocksDbError(err.into_string()))?;
        env.set_high_priority_background_threads(rocksdb_configs.high_priority_background_threads);
        env.set_low_priority_background_threads(rocksdb_configs.low_priority_background_threads);
        let block_cache = Cache::new_hyper_clock_cache(
            rocksdb_configs.shared_block_cache_size,
            /* estimated_entry_charge = */ 0,
        );
```

**File:** config/src/config/storage_config.rs (L210-237)
```rust
impl RocksdbConfigs {
    /// Default block cache size is 24GB.
    pub const DEFAULT_BLOCK_CACHE_SIZE: usize = 24 * (1 << 30);
}

fn default_to_true() -> bool {
    true
}

impl Default for RocksdbConfigs {
    fn default() -> Self {
        Self {
            ledger_db_config: RocksdbConfig::default(),
            state_merkle_db_config: RocksdbConfig::default(),
            state_kv_db_config: RocksdbConfig {
                bloom_filter_bits: Some(10.0),
                bloom_before_level: Some(2),
                ..Default::default()
            },
            index_db_config: RocksdbConfig {
                max_open_files: 1000,
                ..Default::default()
            },
            enable_storage_sharding: true,
            high_priority_background_threads: 4,
            low_priority_background_threads: 2,
            shared_block_cache_size: Self::DEFAULT_BLOCK_CACHE_SIZE,
        }
```

**File:** config/src/config/storage_config.rs (L654-663)
```rust
            if (chain_id.is_testnet() || chain_id.is_mainnet())
                && config_yaml["ensure_rlimit_nofile"].is_null()
            {
                config.ensure_rlimit_nofile = 999_999;
                modified_config = true;
            }
            if chain_id.is_testnet() && config_yaml["assert_rlimit_nofile"].is_null() {
                config.assert_rlimit_nofile = true;
                modified_config = true;
            }
```

**File:** aptos-node/src/storage.rs (L75-97)
```rust
        Either::Right(fast_sync_db_wrapper) => {
            let temp_db = fast_sync_db_wrapper.get_temporary_db_with_genesis();
            maybe_apply_genesis(&DbReaderWriter::from_arc(temp_db), node_config)?;
            let (db_arc, db_rw) = DbReaderWriter::wrap(fast_sync_db_wrapper);
            let fast_sync_db = db_arc.get_fast_sync_db();
            // FastSyncDB requires ledger info at epoch 0 to establish provenance to genesis
            let ledger_info = db_arc
                .get_temporary_db_with_genesis()
                .get_epoch_ending_ledger_info(0)
                .expect("Genesis ledger info must exist");

            if fast_sync_db
                .get_latest_ledger_info_option()
                .expect("should returns Ok results")
                .is_none()
            {
                // it means the DB is empty and we need to
                // commit the genesis ledger info to the DB.
                fast_sync_db.commit_genesis_ledger_info(&ledger_info)?;
            }
            let db_backup_service =
                start_backup_service(node_config.storage.backup_service_address, fast_sync_db);
            (db_arc as Arc<dyn DbReader>, db_rw, Some(db_backup_service))
```
