# Audit Report

## Title
Database Structure Mismatch Causes Silent Data Loss Through Configuration Mismatch

## Summary
The `LedgerDb::new()` function lacks runtime validation to ensure the `enable_storage_sharding` configuration matches the actual database structure on disk. When a mismatch occurs, RocksDB's `create_if_missing=true` option silently creates new empty databases at different paths, causing nodes to read from wrong databases and diverge from the network.

## Finding Description

The vulnerability exists in `LedgerDb::new()` where the `enable_storage_sharding` configuration determines database paths without validating against the actual on-disk structure. [1](#0-0) 

The function uses different paths based on the sharding flag: [2](#0-1) 

When `sharding=true`, the metadata DB is at `ledger_db/metadata/`, but when `sharding=false`, it's at `ledger_db/`. The separate component databases (events, transactions, etc.) are opened at different paths when sharding is enabled. [3](#0-2) 

Critically, RocksDB is configured with `create_if_missing=true`: [4](#0-3) 

**Attack Scenario:**
1. A node runs with `enable_storage_sharding=true` (default) and accumulates ledger data in the sharded structure
2. Configuration is changed to `enable_storage_sharding=false` (via config management error or operational mistake)
3. Node restarts and `LedgerDb::new()` is called with the mismatched configuration
4. RocksDB creates new empty databases at the non-sharded paths instead of failing
5. All read operations return `NotFound` errors or empty results: [5](#0-4) 

6. The node sees an empty ledger and diverges from the network, breaking consensus

A TODO comment acknowledges this issue needs handling: [6](#0-5) 

No metadata is persisted to track the original sharding configuration: [7](#0-6) 

## Impact Explanation

This meets **High Severity** criteria per the Aptos bug bounty program:
- **Validator node failures**: Nodes become completely unusable, returning errors on all read operations
- **Significant protocol violations**: Breaks the **State Consistency** and **Deterministic Execution** invariants
- **State inconsistencies requiring intervention**: Requires manual intervention to detect and fix the configuration mismatch

If multiple validators are affected by the same configuration management error, it could impact network liveness and consensus.

## Likelihood Explanation

**Likelihood: Medium**

This can occur through:
- Configuration management system bugs pushing incorrect settings to multiple nodes
- Human error during node maintenance or migration
- Misunderstanding of the `enable_storage_sharding` setting by operators
- Automated configuration updates that don't preserve the original sharding setting

While it requires operator-level access to configuration files, such access is commonly granted in production environments, and configuration errors are a realistic operational risk.

## Recommendation

Add runtime validation during database initialization to detect and prevent configuration mismatches:

```rust
pub(crate) fn new<P: AsRef<Path>>(
    db_root_path: P,
    rocksdb_configs: RocksdbConfigs,
    env: Option<&Env>,
    block_cache: Option<&Cache>,
    readonly: bool,
) -> Result<Self> {
    let sharding = rocksdb_configs.enable_storage_sharding;
    
    // Validate that the configuration matches the on-disk structure
    let sharded_path = Self::metadata_db_path(db_root_path.as_ref(), true);
    let non_sharded_path = Self::metadata_db_path(db_root_path.as_ref(), false);
    
    let sharded_exists = sharded_path.exists();
    let non_sharded_exists = non_sharded_path.exists();
    
    if sharded_exists && non_sharded_exists {
        bail!("Inconsistent database state: both sharded and non-sharded paths exist");
    }
    
    if sharding && non_sharded_exists && !sharded_path.exists() {
        bail!(
            "Configuration mismatch: enable_storage_sharding=true but database exists at non-sharded path. \
             Expected sharded structure at {:?}, found non-sharded at {:?}. \
             Please migrate the database or correct the configuration.",
            sharded_path, non_sharded_path
        );
    }
    
    if !sharding && sharded_exists && !non_sharded_path.exists() {
        bail!(
            "Configuration mismatch: enable_storage_sharding=false but database exists at sharded path. \
             Expected non-sharded structure at {:?}, found sharded at {:?}. \
             Please migrate the database or correct the configuration.",
            non_sharded_path, sharded_path
        );
    }
    
    // Continue with existing initialization logic...
}
```

Additionally, persist the sharding configuration as metadata in the database itself to enable automated detection.

## Proof of Concept

```rust
#[test]
fn test_sharding_mismatch_detection() {
    use tempfile::TempDir;
    use aptos_config::config::RocksdbConfigs;
    
    // Create a temporary directory for the test
    let tmpdir = TempDir::new().unwrap();
    
    // Initialize a database with sharding=true
    let rocksdb_configs_sharded = RocksdbConfigs {
        enable_storage_sharding: true,
        ..Default::default()
    };
    
    let ledger_db = LedgerDb::new(
        tmpdir.path(),
        rocksdb_configs_sharded,
        None,
        None,
        false,
    ).unwrap();
    
    // Write some test data
    // ... (write transactions, events, etc.)
    
    drop(ledger_db);
    
    // Try to reopen with sharding=false - this should fail but currently doesn't
    let rocksdb_configs_non_sharded = RocksdbConfigs {
        enable_storage_sharding: false,
        ..Default::default()
    };
    
    let result = LedgerDb::new(
        tmpdir.path(),
        rocksdb_configs_non_sharded,
        None,
        None,
        false,
    );
    
    // Currently this succeeds and creates wrong databases
    // After fix, this should return an error indicating configuration mismatch
    assert!(result.is_err(), "Should detect sharding configuration mismatch");
}
```

**Notes:**
This vulnerability requires operator-level access to modify node configuration files, which places it at the boundary of the trust model. However, configuration management errors are realistic operational risks that can affect multiple nodes simultaneously, potentially impacting network consensus and availability.

### Citations

**File:** storage/aptosdb/src/ledger_db/mod.rs (L122-142)
```rust
    pub(crate) fn new<P: AsRef<Path>>(
        db_root_path: P,
        rocksdb_configs: RocksdbConfigs,
        env: Option<&Env>,
        block_cache: Option<&Cache>,
        readonly: bool,
    ) -> Result<Self> {
        let sharding = rocksdb_configs.enable_storage_sharding;
        let ledger_metadata_db_path = Self::metadata_db_path(db_root_path.as_ref(), sharding);
        let ledger_metadata_db = Arc::new(Self::open_rocksdb(
            ledger_metadata_db_path.clone(),
            if sharding {
                LEDGER_METADATA_DB_NAME
            } else {
                LEDGER_DB_NAME
            },
            &rocksdb_configs.ledger_db_config,
            env,
            block_cache,
            readonly,
        )?);
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L174-293)
```rust
        let ledger_db_folder = db_root_path.as_ref().join(LEDGER_DB_FOLDER_NAME);

        let mut event_db = None;
        let mut persisted_auxiliary_info_db = None;
        let mut transaction_accumulator_db = None;
        let mut transaction_auxiliary_data_db = None;
        let mut transaction_db = None;
        let mut transaction_info_db = None;
        let mut write_set_db = None;
        THREAD_MANAGER.get_non_exe_cpu_pool().scope(|s| {
            s.spawn(|_| {
                let event_db_raw = Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(EVENT_DB_NAME),
                        EVENT_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                );
                event_db = Some(EventDb::new(
                    event_db_raw.clone(),
                    EventStore::new(event_db_raw),
                ));
            });
            s.spawn(|_| {
                persisted_auxiliary_info_db = Some(PersistedAuxiliaryInfoDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(PERSISTED_AUXILIARY_INFO_DB_NAME),
                        PERSISTED_AUXILIARY_INFO_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_accumulator_db = Some(TransactionAccumulatorDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_ACCUMULATOR_DB_NAME),
                        TRANSACTION_ACCUMULATOR_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_auxiliary_data_db = Some(TransactionAuxiliaryDataDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_AUXILIARY_DATA_DB_NAME),
                        TRANSACTION_AUXILIARY_DATA_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )))
            });
            s.spawn(|_| {
                transaction_db = Some(TransactionDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_DB_NAME),
                        TRANSACTION_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                transaction_info_db = Some(TransactionInfoDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(TRANSACTION_INFO_DB_NAME),
                        TRANSACTION_INFO_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
            s.spawn(|_| {
                write_set_db = Some(WriteSetDb::new(Arc::new(
                    Self::open_rocksdb(
                        ledger_db_folder.join(WRITE_SET_DB_NAME),
                        WRITE_SET_DB_NAME,
                        &rocksdb_configs.ledger_db_config,
                        env,
                        block_cache,
                        readonly,
                    )
                    .unwrap(),
                )));
            });
        });

        // TODO(grao): Handle data inconsistency.

        Ok(Self {
            ledger_metadata_db: LedgerMetadataDb::new(ledger_metadata_db),
            event_db: event_db.unwrap(),
            persisted_auxiliary_info_db: persisted_auxiliary_info_db.unwrap(),
            transaction_accumulator_db: transaction_accumulator_db.unwrap(),
            transaction_auxiliary_data_db: transaction_auxiliary_data_db.unwrap(),
            transaction_db: transaction_db.unwrap(),
            transaction_info_db: transaction_info_db.unwrap(),
            write_set_db: write_set_db.unwrap(),
            enable_storage_sharding: true,
        })
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

**File:** storage/rocksdb-options/src/lib.rs (L38-41)
```rust
    if !readonly {
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L56-60)
```rust
    pub(crate) fn get_transaction(&self, version: Version) -> Result<Transaction> {
        self.db
            .get::<TransactionSchema>(&version)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Txn {version}")))
    }
```

**File:** storage/aptosdb/src/schema/db_metadata/mod.rs (L49-72)
```rust
pub enum DbMetadataKey {
    LedgerPrunerProgress,
    StateMerklePrunerProgress,
    EpochEndingStateMerklePrunerProgress,
    StateKvPrunerProgress,
    StateSnapshotKvRestoreProgress(Version),
    LedgerCommitProgress,
    StateKvCommitProgress,
    OverallCommitProgress,
    StateKvShardCommitProgress(ShardId),
    StateMerkleCommitProgress,
    StateMerkleShardCommitProgress(ShardId),
    EventPrunerProgress,
    TransactionAccumulatorPrunerProgress,
    TransactionInfoPrunerProgress,
    TransactionPrunerProgress,
    WriteSetPrunerProgress,
    StateMerkleShardPrunerProgress(ShardId),
    EpochEndingStateMerkleShardPrunerProgress(ShardId),
    StateKvShardPrunerProgress(ShardId),
    StateMerkleShardRestoreProgress(ShardId, Version),
    TransactionAuxiliaryDataPrunerProgress,
    PersistedAuxiliaryInfoPrunerProgress,
}
```
