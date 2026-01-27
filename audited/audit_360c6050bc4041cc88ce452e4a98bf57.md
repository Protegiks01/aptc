# Audit Report

## Title
Internal Indexer State Corruption via db_debugger Pruning Without Indexer Database

## Summary
The `db_debugger watch opened` command opens AptosDB with `readonly=false` and `internal_indexer_db=None`, allowing automatic background pruning to delete events and transactions from the main database while leaving stale indices in the internal indexer database. This causes API query failures when the validator later runs with the internal indexer enabled, requiring manual reindexing to recover.

## Finding Description

When a validator database is configured with `enable_storage_sharding=true` and internal indexer enabled, event and transaction indices are stored exclusively in the internal indexer database, not in the main database. [1](#0-0) 

The `db_debugger watch opened` command opens the database with critical configuration mismatches: [2](#0-1) 

This creates a dangerous scenario:

1. The database opens with `readonly=false` and default pruner configuration (pruning enabled)
2. The `skip_index_and_usage` flag is set based on `enable_storage_sharding` 
3. Background pruner workers are spawned and automatically begin pruning when thresholds are met [3](#0-2) 

The pruning trigger logic activates automatically during database initialization: [4](#0-3) 

The background pruner runs continuously in a separate thread: [5](#0-4) 

When `EventStorePruner::prune` executes without the internal indexer database, it attempts to delete indices from the main database (where they don't exist) instead of the internal indexer database (where they do exist): [6](#0-5) 

The critical issue: when `internal_indexer_db` is `None`, the `indices_batch` points to the main batch, not the indexer batch. Event indices are deleted from the main database (non-existent deletes succeed silently), but the internal indexer database is never updated and retains stale indices.

When the validator later restarts with internal indexer enabled, API queries use the stale indices to look up events that were already pruned: [7](#0-6) 

The `get_event_by_version_and_index` call fails because the event was pruned from the main database: [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: The internal indexer database becomes permanently out of sync with the main database, containing indices pointing to pruned data
- **API crashes**: Event and transaction API queries fail with `NotFound` errors for any version between the old pruner progress and new pruner progress
- Requires manual intervention (full reindexing or manual pruner progress reset) to recover
- Does not affect consensus or blockchain progression, only external API availability

The inconsistency persists indefinitely because during validator restart, the pruner reads progress from the main database only and finds no catchup work needed: [9](#0-8) 

## Likelihood Explanation

**High likelihood** of occurrence in production:
- The db_debugger is a legitimate operational tool that operators may use for database inspection
- Pruning triggers automatically based on database version thresholds (default 90M prune window)
- No warnings or validation checks prevent opening a database with mismatched indexer configuration
- The default `StorageConfig` has pruning enabled [10](#0-9) 

## Recommendation

Add validation to prevent opening databases with incompatible internal indexer configurations. The database should detect if it was previously configured with internal indexer enabled and enforce that it must be provided:

**Option 1**: Store internal indexer enablement flag in main database metadata and validate on open
**Option 2**: Make db_debugger tools open databases in readonly mode by default
**Option 3**: Add a check in `EventStorePruner::new` and `TransactionPruner::new` to validate that if the database has internal indexer metadata, the `internal_indexer_db` parameter must be provided

**Recommended fix for db_debugger**:

```rust
// storage/aptosdb/src/db_debugger/watch/opened.rs
pub fn run(self) -> Result<()> {
    let mut config = StorageConfig::default();
    config.set_data_dir(self.db_dir);
    config.rocksdb_configs.enable_storage_sharding =
        self.sharding_config.enable_storage_sharding;
    config.hot_state_config.delete_on_restart = false;

    let _db = AptosDB::open(
        config.get_dir_paths(),
        true, // CHANGE: Open in readonly mode to prevent pruning
        NO_OP_STORAGE_PRUNER_CONFIG, // CHANGE: Disable all pruning
        config.rocksdb_configs,
        config.enable_indexer,
        config.buffered_state_target_items,
        config.max_num_nodes_per_lru_cache_shard,
        None,
        config.hot_state_config,
    )
    .expect("Failed to open AptosDB");
    // ...
}
```

## Proof of Concept

```rust
// Reproduction steps (Rust pseudo-code for clarity):

// Step 1: Setup - Create validator database with internal indexer
let node_config = NodeConfig {
    storage: StorageConfig {
        rocksdb_configs: RocksdbConfigs { 
            enable_storage_sharding: true, 
            ..Default::default() 
        },
        storage_pruner_config: PrunerConfig::default(), // Pruning enabled
        ..Default::default()
    },
    indexer_db_config: InternalIndexerDBConfig {
        enable_transaction: true,
        enable_event: true,
        enable_statekeys: true,
        ..Default::default()
    },
    ..Default::default()
};

// Create internal indexer DB
let internal_indexer_db = InternalIndexerDBService::get_indexer_db(&node_config);

// Open database with internal indexer
let db = AptosDB::open(
    node_config.storage.get_dir_paths(),
    false,
    node_config.storage.storage_pruner_config,
    node_config.storage.rocksdb_configs,
    false,
    node_config.storage.buffered_state_target_items,
    node_config.storage.max_num_nodes_per_lru_cache_shard,
    internal_indexer_db,
    node_config.storage.hot_state_config,
).unwrap();

// Commit 100M versions with events
// ... (commit transactions)
// db now has: main db events 0-100M, indexer db indices 0-100M

// Step 2: Attack - Run db_debugger without internal indexer
// This simulates: db-tool db-debugger watch opened --db-dir /path/to/db --enable-storage-sharding
let mut debug_config = StorageConfig::default();
debug_config.set_data_dir(node_config.storage.dir());
debug_config.rocksdb_configs.enable_storage_sharding = true;

let debug_db = AptosDB::open(
    debug_config.get_dir_paths(),
    false, // readonly=false - DANGEROUS!
    debug_config.storage_pruner_config, // Pruning enabled - DANGEROUS!
    debug_config.rocksdb_configs,
    debug_config.enable_indexer,
    debug_config.buffered_state_target_items,
    debug_config.max_num_nodes_per_lru_cache_shard,
    None, // internal_indexer_db=None - THE BUG!
    debug_config.hot_state_config,
).unwrap();

// Background pruner automatically triggers and prunes versions 0-10M
// Main db EventPrunerProgress: 0 -> 10M
// Internal indexer db EventPrunerProgress: stays at 0
// Main db: events 0-10M deleted
// Internal indexer db: indices 0-10M still exist (STALE!)

std::thread::sleep(Duration::from_secs(10)); // Let pruner work
drop(debug_db);

// Step 3: Demonstrate failure - Reopen with internal indexer
let internal_indexer_db = InternalIndexerDBService::get_indexer_db(&node_config);
let db = AptosDB::open(
    node_config.storage.get_dir_paths(),
    false,
    node_config.storage.storage_pruner_config,
    node_config.storage.rocksdb_configs,
    false,
    node_config.storage.buffered_state_target_items,
    node_config.storage.max_num_nodes_per_lru_cache_shard,
    internal_indexer_db,
    node_config.storage.hot_state_config,
).unwrap();

// Try to query event at version 5M (was pruned, but indexer still has index)
let event_key = EventKey::new_from_address(&AccountAddress::random(), 0);
let db_indexer = DBIndexer::new(internal_indexer_db, db_reader);
let result = db_indexer.get_events_by_event_key(
    &event_key,
    0,
    Order::Ascending,
    10,
    100_000_000,
);

// Result: ERROR! 
// "Event at version 5000000 is pruned, min available version is 10000000"
// But the query should have returned empty results, not an error
assert!(result.is_err()); // Query fails due to stale indices
```

**Notes**

The vulnerability stems from the architectural assumption that databases are always opened with consistent internal indexer configuration. The db_debugger tool violates this assumption by opening production databases with `internal_indexer_db=None` while allowing write operations (pruning). This creates permanent state inconsistencies between the main database and internal indexer database that persist across restarts and require manual intervention to resolve.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L148-160)
```rust
        let mut myself = Self::new_with_dbs(
            ledger_db,
            hot_state_merkle_db,
            state_merkle_db,
            state_kv_db,
            pruner_config,
            buffered_state_target_items,
            readonly,
            empty_buffered_state_for_restore,
            rocksdb_configs.enable_storage_sharding,
            internal_indexer_db,
            hot_state_config,
        );
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L162-171)
```rust
        if !readonly {
            if let Some(version) = myself.get_synced_version()? {
                myself
                    .ledger_pruner
                    .maybe_set_pruner_target_db_version(version);
                myself
                    .state_store
                    .state_kv_pruner
                    .maybe_set_pruner_target_db_version(version);
            }
```

**File:** storage/aptosdb/src/db_debugger/watch/opened.rs (L28-39)
```rust
        let _db = AptosDB::open(
            config.get_dir_paths(),
            false, /* readonly */
            config.storage_pruner_config,
            config.rocksdb_configs,
            config.enable_indexer,
            config.buffered_state_target_items,
            config.max_num_nodes_per_lru_cache_shard,
            None,
            config.hot_state_config,
        )
        .expect("Failed to open AptosDB");
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L66-77)
```rust
    fn maybe_set_pruner_target_db_version(&self, latest_version: Version) {
        *self.latest_version.lock() = latest_version;

        let min_readable_version = self.get_min_readable_version();
        // Only wake up the ledger pruner if there are `ledger_pruner_pruning_batch_size` pending
        // versions.
        if self.is_pruner_enabled()
            && latest_version
                >= min_readable_version + self.pruning_batch_size as u64 + self.prune_window
        {
            self.set_pruner_target_db_version(latest_version);
        }
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L52-68)
```rust
    // Loop that does the real pruning job.
    fn work(&self) {
        while !self.quit_worker.load(Ordering::SeqCst) {
            let pruner_result = self.pruner.prune(self.batch_size);
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
            if !self.pruner.is_pruning_pending() {
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            }
        }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L43-81)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        let mut indexer_batch = None;

        let indices_batch = if let Some(indexer_db) = self.indexer_db() {
            if indexer_db.event_enabled() {
                indexer_batch = Some(SchemaBatch::new());
            }
            indexer_batch.as_mut()
        } else {
            Some(&mut batch)
        };
        let num_events_per_version = self.ledger_db.event_db().prune_event_indices(
            current_progress,
            target_version,
            indices_batch,
        )?;
        self.ledger_db.event_db().prune_events(
            num_events_per_version,
            current_progress,
            target_version,
            &mut batch,
        )?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::EventPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        if let Some(mut indexer_batch) = indexer_batch {
            indexer_batch.put::<InternalIndexerMetadataSchema>(
                &IndexerMetadataKey::EventPrunerProgress,
                &IndexerMetadataValue::Version(target_version),
            )?;
            self.expect_indexer_db()
                .get_inner_db_ref()
                .write_schemas(indexer_batch)?;
        }
        self.ledger_db.event_db().write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L85-109)
```rust
    pub(in crate::pruner) fn new(
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
        internal_indexer_db: Option<InternalIndexerDB>,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.event_db_raw(),
            &DbMetadataKey::EventPrunerProgress,
            metadata_progress,
        )?;

        let myself = EventStorePruner {
            ledger_db,
            internal_indexer_db,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up EventStorePruner."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L691-718)
```rust

        let mut events_with_version = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let event = match self
                    .main_db_reader
                    .get_event_by_version_and_index(ver, idx)?
                {
                    event @ ContractEvent::V1(_) => event,
                    ContractEvent::V2(_) => ContractEvent::V1(
                        self.indexer_db
                            .get_translated_v1_event_by_version_and_index(ver, idx)?,
                    ),
                };
                let v0 = match &event {
                    ContractEvent::V1(event) => event,
                    ContractEvent::V2(_) => bail!("Unexpected module event"),
                };
                ensure!(
                    seq == v0.sequence_number(),
                    "Index broken, expected seq:{}, actual:{}",
                    seq,
                    v0.sequence_number()
                );

                Ok(EventWithVersion::new(ver, event))
            })
            .collect::<Result<Vec<_>>>()?;
```

**File:** storage/aptosdb/src/event_store/mod.rs (L42-50)
```rust
    pub fn get_event_by_version_and_index(
        &self,
        version: Version,
        index: u64,
    ) -> Result<ContractEvent> {
        self.event_db
            .get::<EventSchema>(&(version, index))?
            .ok_or_else(|| AptosDbError::NotFound(format!("Event {} of Txn {}", index, version)))
    }
```

**File:** config/src/config/storage_config.rs (L387-430)
```rust
impl Default for LedgerPrunerConfig {
    fn default() -> Self {
        LedgerPrunerConfig {
            enable: true,
            prune_window: 90_000_000,
            batch_size: 5_000,
            user_pruning_window_offset: 200_000,
        }
    }
}

impl Default for StateMerklePrunerConfig {
    fn default() -> Self {
        StateMerklePrunerConfig {
            enable: true,
            // This allows a block / chunk being executed to have access to a non-latest state tree.
            // It needs to be greater than the number of versions the state committing thread is
            // able to commit during the execution of the block / chunk. If the bad case indeed
            // happens due to this being too small, a node restart should recover it.
            // Still, defaulting to 1M to be super safe.
            prune_window: 1_000_000,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
        }
    }
}

impl Default for EpochSnapshotPrunerConfig {
    fn default() -> Self {
        Self {
            enable: true,
            // This is based on ~5K TPS * 2h/epoch * 2 epochs. -- epoch ending snapshots are used
            // by state sync in fast sync mode.
            // The setting is in versions, not epochs, because this makes it behave more like other
            // pruners: a slower network will have longer history in db with the same pruner
            // settings, but the disk space take will be similar.
            // settings.
            prune_window: 80_000_000,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
        }
    }
```
