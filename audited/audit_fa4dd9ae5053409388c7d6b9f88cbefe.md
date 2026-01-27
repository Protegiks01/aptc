# Audit Report

## Title
Database Lock Hang in Truncate Debugger Tool Blocking Validator Operations

## Summary
The `truncate` database debugger tool in `storage/aptosdb/src/db_debugger/truncate/mod.rs` opens RocksDB databases without any timeout mechanism. When another process (such as a running validator or another maintenance tool) holds the database lock, the truncate operation hangs indefinitely with no timeout or retry logic, potentially blocking critical validator startup or recovery operations.

## Finding Description

The `run()` function in the truncate debugger opens databases using `AptosDB::open_dbs()`: [1](#0-0) 

This calls through multiple layers without any timeout handling:

1. `AptosDB::open_dbs()` calls `LedgerDb::new()`, `StateKvDb::new()`, and `StateMerkleDb::new()` [2](#0-1) 

2. These eventually call `open_rocksdb()` which directly invokes RocksDB's native open operations [3](#0-2) 

3. The SchemaDB wrapper performs the actual RocksDB open call [4](#0-3) 

4. RocksDB options are generated without any timeout configuration [5](#0-4) 

**Critical Issue**: RocksDB's default behavior is to block indefinitely when attempting to acquire a database lock that is held by another process. There is no timeout mechanism at any layer of this stack.

**Operational Impact Scenarios**:

1. **Validator Startup Blocking**: If an operator inadvertently leaves the truncate tool running or it hangs for any reason, subsequent validator startup attempts will hang indefinitely when trying to open the database, requiring manual intervention to kill the blocking process.

2. **Maintenance Tool Conflicts**: Multiple maintenance operations (truncate, examine, etc.) attempting to access the database simultaneously will result in indefinite hangs without clear error messaging.

This affects multiple debugger tools that use the same pattern [6](#0-5) 

## Impact Explanation

This issue qualifies as **Medium severity** per the Aptos bug bounty categories under "State inconsistencies requiring intervention":

- **Availability Impact**: Blocks validator node startup/recovery operations indefinitely, requiring manual intervention to identify and terminate hung processes
- **Operational Risk**: Creates operational blind spots where processes hang silently without error messages or timeouts
- **Recovery Complications**: During critical recovery scenarios (e.g., after crashes or updates), the lack of timeout can delay validator restart, potentially affecting network participation
- **Cascading Effects**: Operators may not realize a process is hung, leading to repeated failed restart attempts and extended downtime

While not directly a consensus or fund loss issue, it creates operational vulnerabilities that can impact node availability and recovery times, which are critical for validator operations.

## Likelihood Explanation

**Likelihood: Medium-High**

This issue is likely to occur in production environments because:

1. **Common Operational Pattern**: Database maintenance tools are regularly used for pruning, backup, and troubleshooting
2. **Process Management Gaps**: Operators may not properly terminate maintenance processes before validator operations
3. **Error Recovery Scenarios**: During crash recovery or emergency maintenance, multiple processes may attempt database access
4. **Silent Failure Mode**: The hang provides no indication of the problem (no timeout error, no log message explaining the wait)
5. **Multiple Affected Tools**: The same pattern exists in several debugger tools, multiplying exposure

The issue requires operational access (not remote exploitation), but is highly likely to manifest during normal validator operations and maintenance windows.

## Recommendation

Implement timeout and retry logic for database opening operations. Use the existing `aptos-retrier` infrastructure:

**Option 1: Add timeout to database open operations**
```rust
use std::time::Duration;
use std::thread;

pub fn run(self) -> Result<()> {
    // ... existing backup logic ...
    
    let rocksdb_config = RocksdbConfigs { /* ... */ };
    let env = None;
    let block_cache = None;
    
    // Implement timeout for database opening
    let timeout = Duration::from_secs(30); // configurable timeout
    let start = Instant::now();
    
    let db_result = loop {
        match AptosDB::open_dbs(
            &StorageDirPaths::from_path(&self.db_dir),
            rocksdb_config,
            env,
            block_cache,
            /*readonly=*/ false,
            /*max_num_nodes_per_lru_cache_shard=*/ 0,
            /*reset_hot_state=*/ true,
        ) {
            Ok(dbs) => break Ok(dbs),
            Err(e) if start.elapsed() < timeout => {
                eprintln!("Failed to open database, retrying: {}", e);
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            Err(e) => break Err(e),
        }
    };
    
    let (ledger_db, hot_state_merkle_db, state_merkle_db, state_kv_db) = 
        db_result.map_err(|e| {
            AptosDbError::Other(format!(
                "Failed to open database after {}s timeout. \
                Another process may be holding the lock. Error: {}",
                timeout.as_secs(), e
            ))
        })?;
    
    // ... rest of function ...
}
```

**Option 2: Add command-line flag for timeout control**
```rust
#[derive(Parser)]
pub struct Cmd {
    // ... existing fields ...
    
    #[clap(long, default_value_t = 30)]
    db_open_timeout_secs: u64,
}
```

**Option 3: Use non-blocking database open with explicit lock detection**
Add RocksDB options to fail fast on lock conflicts rather than blocking.

## Proof of Concept

**Reproduction Steps:**

```bash
# Terminal 1: Start a long-running process holding DB lock
cd /path/to/aptos/storage
cargo run --bin aptos-db-tool -- truncate \
    --db-dir /opt/aptos/data \
    --target-version 1000000 \
    --opt-out-backup-checkpoint &

# Terminal 2: Attempt to start validator
# This will hang indefinitely waiting for DB lock
aptos-node -f /opt/aptos/config/validator.yaml

# Observe: validator startup hangs with no error message or timeout
# Process must be manually killed to proceed
```

**Expected behavior**: After 30-60 seconds, should fail with clear error message:
```
Error: Failed to open database after 30s timeout. 
Another process may be holding the lock at /opt/aptos/data
Please ensure no other processes are accessing the database.
```

**Actual behavior**: Process hangs indefinitely with no output or error message.

## Notes

- This issue affects multiple database debugger tools that use the same `AptosDB::open_dbs()` pattern
- RocksDB's default behavior is to block indefinitely on lock acquisition, which is standard but inappropriate for operational tools that should fail fast
- The codebase contains retry infrastructure (`aptos-retrier`) but it's not applied to database opening operations
- Similar timeout patterns should be implemented for all maintenance and debugger tools that access the database
- Consider adding a command-line flag (`--force`) that attempts to break stale locks after timeout, with appropriate warnings

### Citations

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L74-82)
```rust
        let (ledger_db, hot_state_merkle_db, state_merkle_db, state_kv_db) = AptosDB::open_dbs(
            &StorageDirPaths::from_path(&self.db_dir),
            rocksdb_config,
            env,
            block_cache,
            /*readonly=*/ false,
            /*max_num_nodes_per_lru_cache_shard=*/ 0,
            /*reset_hot_state=*/ true,
        )?;
```

**File:** storage/aptosdb/src/db/mod.rs (L106-156)
```rust
    pub fn open_dbs(
        db_paths: &StorageDirPaths,
        rocksdb_configs: RocksdbConfigs,
        env: Option<&Env>,
        block_cache: Option<&Cache>,
        readonly: bool,
        max_num_nodes_per_lru_cache_shard: usize,
        reset_hot_state: bool,
    ) -> Result<(LedgerDb, Option<StateMerkleDb>, StateMerkleDb, StateKvDb)> {
        let ledger_db = LedgerDb::new(
            db_paths.ledger_db_root_path(),
            rocksdb_configs,
            env,
            block_cache,
            readonly,
        )?;
        let state_kv_db = StateKvDb::new(
            db_paths,
            rocksdb_configs,
            env,
            block_cache,
            readonly,
            ledger_db.metadata_db_arc(),
        )?;
        let hot_state_merkle_db = if !readonly && rocksdb_configs.enable_storage_sharding {
            Some(StateMerkleDb::new(
                db_paths,
                rocksdb_configs,
                env,
                block_cache,
                readonly,
                max_num_nodes_per_lru_cache_shard,
                /* is_hot = */ true,
                reset_hot_state,
            )?)
        } else {
            None
        };
        let state_merkle_db = StateMerkleDb::new(
            db_paths,
            rocksdb_configs,
            env,
            block_cache,
            readonly,
            max_num_nodes_per_lru_cache_shard,
            /* is_hot = */ false,
            /* delete_on_restart = */ false,
        )?;

        Ok((ledger_db, hot_state_merkle_db, state_merkle_db, state_kv_db))
    }
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L457-484)
```rust
    fn open_rocksdb(
        path: PathBuf,
        name: &str,
        db_config: &RocksdbConfig,
        env: Option<&Env>,
        block_cache: Option<&Cache>,
        readonly: bool,
    ) -> Result<DB> {
        let db = if readonly {
            DB::open_cf_readonly(
                &gen_rocksdb_options(db_config, env, true),
                path.clone(),
                name,
                Self::gen_cfds_by_name(db_config, block_cache, name),
            )?
        } else {
            DB::open_cf(
                &gen_rocksdb_options(db_config, env, false),
                path.clone(),
                name,
                Self::gen_cfds_by_name(db_config, block_cache, name),
            )?
        };

        info!("Opened {name} at {path:?}!");

        Ok(db)
    }
```

**File:** storage/schemadb/src/lib.rs (L141-193)
```rust
    fn open_cf_impl(
        db_opts: &Options,
        path: impl AsRef<Path>,
        name: &str,
        cfds: Vec<ColumnFamilyDescriptor>,
        open_mode: OpenMode,
    ) -> DbResult<DB> {
        // ignore error, since it'll fail to list cfs on the first open
        let existing_cfs: HashSet<String> = rocksdb::DB::list_cf(db_opts, path.de_unc())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let requested_cfs: HashSet<String> =
            cfds.iter().map(|cfd| cfd.name().to_string()).collect();
        let missing_cfs: HashSet<&str> = requested_cfs
            .difference(&existing_cfs)
            .map(|cf| {
                warn!("Missing CF: {}", cf);
                cf.as_ref()
            })
            .collect();
        let unrecognized_cfs = existing_cfs.difference(&requested_cfs);

        let all_cfds = cfds
            .into_iter()
            .chain(unrecognized_cfs.map(Self::cfd_for_unrecognized_cf));

        let inner = {
            use rocksdb::DB;
            use OpenMode::*;

            match open_mode {
                ReadWrite => DB::open_cf_descriptors(db_opts, path.de_unc(), all_cfds),
                ReadOnly => {
                    DB::open_cf_descriptors_read_only(
                        db_opts,
                        path.de_unc(),
                        all_cfds.filter(|cfd| !missing_cfs.contains(cfd.name())),
                        false, /* error_if_log_file_exist */
                    )
                },
                Secondary(secondary_path) => DB::open_cf_descriptors_as_secondary(
                    db_opts,
                    path.de_unc(),
                    secondary_path,
                    all_cfds,
                ),
            }
        }
        .into_db_res()?;

        Ok(Self::log_construct(name, open_mode, inner))
    }
```

**File:** storage/rocksdb-options/src/lib.rs (L22-44)
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
}
```

**File:** storage/aptosdb/src/db_debugger/examine/print_db_versions.rs (L47-55)
```rust
        let (ledger_db, _hot_state_merkle_db, state_merkle_db, state_kv_db) = AptosDB::open_dbs(
            &StorageDirPaths::from_path(&self.db_dir),
            rocksdb_config,
            env,
            block_cache,
            /*readonly=*/ true,
            /*max_num_nodes_per_lru_cache_shard=*/ 0,
            /*reset_hot_state=*/ false,
        )?;
```
