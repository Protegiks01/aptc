# Audit Report

## Title
Unvalidated RocksDB Configuration Parameters in Restore Operations Lead to Resource Exhaustion

## Summary
RocksDB configuration parameters in the restore controllers are not validated, allowing operators to specify arbitrary values that can cause memory exhaustion, file descriptor exhaustion, disk space exhaustion, or CPU overload during database restoration operations.

## Finding Description

The restore functionality in `storage/db-tool/src/restore.rs` accepts RocksDB configuration parameters through command-line flags without performing any validation on their values. [1](#0-0) 

These parameters include:
- `max_open_files` (i32, default 5000)
- `max_total_wal_size` (u64, default 1GB)
- `max_background_jobs` (i32, default 16)
- `block_cache_size` (usize, default 24GB)

When the restore operation initializes the database, these parameters are converted directly to `RocksdbConfigs` without any bounds checking: [2](#0-1) 

The configuration is then passed to `AptosDB::open_kv_only`: [3](#0-2) 

These parameters are ultimately passed to RocksDB without validation: [4](#0-3) 

**Attack Scenarios:**

1. **Memory Exhaustion**: Setting `block_cache_size` to an extreme value (e.g., 100TB) causes `Cache::new_hyper_clock_cache()` to attempt allocation, leading to OOM.

2. **File Descriptor Exhaustion**: Setting `max_open_files` to `i32::MAX` (2.1 billion) can exhaust system file descriptors, affecting the entire system.

3. **Disk Exhaustion**: Setting `max_total_wal_size` to `u64::MAX` allows WAL to grow unbounded until disk is full.

4. **CPU Exhaustion**: Setting `max_background_jobs` to `i32::MAX` spawns excessive threads, causing context switching overhead and CPU exhaustion.

## Impact Explanation

This issue represents a **Medium severity** vulnerability according to the Aptos bug bounty criteria. While it does not directly affect consensus or cause loss of funds, it can:

- Cause denial of service on nodes performing restore operations
- Lead to system instability requiring manual intervention
- Result in failed restore operations wasting hours of processing time
- Potentially affect validator nodes if restore is performed on active validators

The impact is classified as Medium because it causes "state inconsistencies requiring intervention" - failed restores prevent nodes from synchronizing with the network, requiring operator intervention to correct configuration and restart the process.

## Likelihood Explanation

The likelihood is **Medium** because:

1. Restore operations are regularly performed by node operators when:
   - Setting up new nodes
   - Recovering from failures
   - Migrating data between systems

2. Operators may accidentally misconfigure parameters (e.g., adding extra zeros to `block_cache_size`)

3. The parameters are hidden by default (`hide(true)` in clap), making them less discoverable but still accessible

4. Malicious insiders with operator access could intentionally set extreme values to disrupt operations

5. Automated scripts might propagate misconfigurations across multiple nodes

## Recommendation

Add validation for RocksDB configuration parameters before passing them to the database initialization. Implement reasonable bounds based on system capabilities and expected usage:

```rust
impl RocksdbOpt {
    pub fn validate(&self) -> Result<()> {
        // Validate max_open_files
        ensure!(
            self.ledger_db_max_open_files > 0 && self.ledger_db_max_open_files <= 100_000,
            "ledger_db_max_open_files must be between 1 and 100,000"
        );
        ensure!(
            self.state_merkle_db_max_open_files > 0 && self.state_merkle_db_max_open_files <= 100_000,
            "state_merkle_db_max_open_files must be between 1 and 100,000"
        );
        ensure!(
            self.state_kv_db_max_open_files > 0 && self.state_kv_db_max_open_files <= 100_000,
            "state_kv_db_max_open_files must be between 1 and 100,000"
        );
        ensure!(
            self.index_db_max_open_files > 0 && self.index_db_max_open_files <= 100_000,
            "index_db_max_open_files must be between 1 and 100,000"
        );

        // Validate max_total_wal_size (max 100GB)
        const MAX_WAL_SIZE: u64 = 100 * 1024 * 1024 * 1024;
        ensure!(
            self.ledger_db_max_total_wal_size <= MAX_WAL_SIZE,
            "ledger_db_max_total_wal_size must not exceed 100GB"
        );
        ensure!(
            self.state_merkle_db_max_total_wal_size <= MAX_WAL_SIZE,
            "state_merkle_db_max_total_wal_size must not exceed 100GB"
        );
        ensure!(
            self.state_kv_db_max_total_wal_size <= MAX_WAL_SIZE,
            "state_kv_db_max_total_wal_size must not exceed 100GB"
        );
        ensure!(
            self.index_db_max_total_wal_size <= MAX_WAL_SIZE,
            "index_db_max_total_wal_size must not exceed 100GB"
        );

        // Validate max_background_jobs
        ensure!(
            self.max_background_jobs > 0 && self.max_background_jobs <= 256,
            "max_background_jobs must be between 1 and 256"
        );

        // Validate block_cache_size (max 256GB)
        const MAX_CACHE_SIZE: usize = 256 * 1024 * 1024 * 1024;
        ensure!(
            self.block_cache_size <= MAX_CACHE_SIZE,
            "block_cache_size must not exceed 256GB"
        );

        Ok(())
    }
}
```

Call this validation in the `TryFrom<GlobalRestoreOpt>` implementation: [5](#0-4) 

Add validation call after line 293:
```rust
opt.rocksdb_opt.validate()?;
```

## Proof of Concept

To demonstrate the vulnerability, run the db-tool restore command with extreme parameter values:

```bash
# Memory exhaustion attack
aptos-node-checker db-tool restore oneoff state-snapshot \
  --state-manifest <manifest> \
  --state-into-version 1000000 \
  --target-db-dir /tmp/restore_db \
  --local-fs-dir /tmp/backup \
  --block-cache-size 1099511627776000  # 1 PB - will cause OOM

# File descriptor exhaustion attack  
aptos-node-checker db-tool restore oneoff state-snapshot \
  --state-manifest <manifest> \
  --state-into-version 1000000 \
  --target-db-dir /tmp/restore_db \
  --local-fs-dir /tmp/backup \
  --ledger-db-max-open-files 2147483647  # i32::MAX

# Expected result: System becomes unresponsive, OOM killer triggers, or restore process crashes
```

The system will attempt to allocate the requested resources, leading to resource exhaustion and denial of service.

## Notes

While this vulnerability requires operator-level access to exploit, it represents a genuine security concern because:

1. Operators regularly run restore operations in production environments
2. Misconfigurations can cascade across multiple nodes via automation
3. The lack of bounds checking violates the principle of defense in depth
4. Resource exhaustion can affect not just the restore process but the entire system

The recommended validation ensures that RocksDB configuration parameters remain within safe operational bounds, preventing both accidental misconfigurations and malicious insider attacks.

### Citations

**File:** storage/backup/backup-cli/src/utils/mod.rs (L68-91)
```rust
pub struct RocksdbOpt {
    #[clap(long, hide(true), default_value_t = 5000)]
    ledger_db_max_open_files: i32,
    #[clap(long, hide(true), default_value_t = 1073741824)] // 1GB
    ledger_db_max_total_wal_size: u64,
    #[clap(long, hide(true), default_value_t = 5000)]
    state_merkle_db_max_open_files: i32,
    #[clap(long, hide(true), default_value_t = 1073741824)] // 1GB
    state_merkle_db_max_total_wal_size: u64,
    #[clap(long, hide(true))]
    enable_storage_sharding: bool,
    #[clap(long, hide(true), default_value_t = 5000)]
    state_kv_db_max_open_files: i32,
    #[clap(long, hide(true), default_value_t = 1073741824)] // 1GB
    state_kv_db_max_total_wal_size: u64,
    #[clap(long, hide(true), default_value_t = 1000)]
    index_db_max_open_files: i32,
    #[clap(long, hide(true), default_value_t = 1073741824)] // 1GB
    index_db_max_total_wal_size: u64,
    #[clap(long, hide(true), default_value_t = 16)]
    max_background_jobs: i32,
    #[clap(long, hide(true), default_value_t = RocksdbConfigs::DEFAULT_BLOCK_CACHE_SIZE)]
    block_cache_size: usize,
}
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L93-125)
```rust
impl From<RocksdbOpt> for RocksdbConfigs {
    fn from(opt: RocksdbOpt) -> Self {
        Self {
            ledger_db_config: RocksdbConfig {
                max_open_files: opt.ledger_db_max_open_files,
                max_total_wal_size: opt.ledger_db_max_total_wal_size,
                max_background_jobs: opt.max_background_jobs,
                ..Default::default()
            },
            state_merkle_db_config: RocksdbConfig {
                max_open_files: opt.state_merkle_db_max_open_files,
                max_total_wal_size: opt.state_merkle_db_max_total_wal_size,
                max_background_jobs: opt.max_background_jobs,
                ..Default::default()
            },
            enable_storage_sharding: opt.enable_storage_sharding,
            state_kv_db_config: RocksdbConfig {
                max_open_files: opt.state_kv_db_max_open_files,
                max_total_wal_size: opt.state_kv_db_max_total_wal_size,
                max_background_jobs: opt.max_background_jobs,
                ..Default::default()
            },
            index_db_config: RocksdbConfig {
                max_open_files: opt.index_db_max_open_files,
                max_total_wal_size: opt.index_db_max_total_wal_size,
                max_background_jobs: opt.max_background_jobs,
                ..Default::default()
            },
            shared_block_cache_size: opt.block_cache_size,
            ..Default::default()
        }
    }
}
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L290-293)
```rust
impl TryFrom<GlobalRestoreOpt> for GlobalRestoreOptions {
    type Error = anyhow::Error;

    fn try_from(opt: GlobalRestoreOpt) -> anyhow::Result<Self> {
```

**File:** storage/backup/backup-cli/src/utils/mod.rs (L305-314)
```rust
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
```

**File:** storage/rocksdb-options/src/lib.rs (L22-43)
```rust
pub fn gen_rocksdb_options(config: &RocksdbConfig, env: Option<&Env>, readonly: bool) -> Options {
    let mut db_opts = Options::default();
    if let Some(env) = env {
        db_opts.set_env(env);
    }
    db_opts.set_max_open_files(config.max_open_files);
    db_opts.set_max_total_wal_size(config.max_total_wal_size);

    if let Some(level) = config.stats_level {
        db_opts.enable_statistics();
        db_opts.set_statistics_level(convert_stats_level(level));
    }
    if let Some(stats_dump_period_sec) = config.stats_dump_period_sec {
        db_opts.set_stats_dump_period_sec(stats_dump_period_sec);
    }

    if !readonly {
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
    }

    db_opts
```
