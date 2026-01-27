# Audit Report

## Title
Partial Backup Restoration Creates Inconsistent Database State Without Validation

## Summary
The db-tool's oneoff restore functionality allows restoring transactions without corresponding state or vice versa, creating an inconsistent database that violates the State Consistency invariant. The database is opened with `empty_buffered_state_for_restore=true`, which bypasses critical consistency checks in `StateStore::sync_commit_progress()`, allowing transactions to exist without their corresponding state values.

## Finding Description

The `Command::run()` function in `restore.rs` provides separate oneoff restore modes for transactions, state snapshots, and epoch endings that can be executed independently. [1](#0-0) 

When restoring transactions in oneoff mode, the `TransactionRestoreController` is initialized with `VerifyExecutionMode::NoVerify` and no epoch history: [2](#0-1) 

The transaction restoration process determines whether to save transactions directly or replay them based on the `replay_from_version` parameter. When `replay_from_version` is not set, `first_to_replay` defaults to `Version::MAX`, causing all transactions to be saved directly without replay: [3](#0-2) 

Transactions saved directly bypass state KV updates. The `save_transactions` function only updates state KV when `kv_replay=true` AND state usage can be retrieved: [4](#0-3) 

**Critical Vulnerability**: The database for restore operations is opened using `open_kv_only()`, which sets `empty_buffered_state_for_restore=true`: [5](#0-4) 

This flag causes `StateStore::new()` to skip the `sync_commit_progress()` consistency check: [6](#0-5) 

The skipped `sync_commit_progress()` function contains critical assertions ensuring database component consistency: [7](#0-6) 

**Attack Scenario:**
1. Attacker runs: `db-tool restore oneoff transaction --transaction-manifest <manifest> --db-dir <db> --target-version 1000`
2. Transactions 0-1000 are saved to ledger DB (transaction accumulator, transaction infos, events, write sets)
3. NO corresponding state KV entries are created
4. Database has `ledger_db_version=1000` but `state_kv_db_version=0`
5. State queries at versions 1-1000 fail or return incorrect data
6. Transaction execution requiring state access crashes
7. State sync cannot serve state chunks
8. Node experiences liveness failure

**Alternative Attack:**
1. Restore state snapshot at version 100
2. Restore transactions starting at version 500
3. Creates database with state at version 100, transactions 500+, missing transactions 101-499
4. Node cannot synchronize properly

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **Validator node slowdowns/failures** (High Severity): Nodes with inconsistent databases will fail when attempting to execute transactions or serve state queries, causing operational failures.

- **State inconsistencies requiring intervention** (Medium Severity): The database requires manual recovery, potentially necessitating complete database rebuilding from correct backups.

- **Violates State Consistency Invariant (#4)**: "State transitions must be atomic and verifiable via Merkle proofs" - transactions exist without their corresponding state values.

The impact extends to:
- Node crash when querying non-existent state
- Inability to serve state sync requests
- Transaction execution failures
- Potential consensus participation degradation
- Network liveness issues if multiple nodes are affected

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability can be triggered by:
1. **Malicious node operator**: Someone with legitimate db-tool access deliberately creating inconsistent state
2. **Compromised backup system**: Attacker gains access to backup restoration tools
3. **Operator error**: Accidental restoration of partial backups in incorrect order
4. **Automated attack**: Compromised automation scripts performing incorrect restoration

The attack requires:
- Access to db-tool binary (available to node operators)
- Backup manifest files
- Ability to execute restore commands

No special privileges beyond node operator access are required. The lack of validation makes the attack straightforward to execute.

## Recommendation

Implement multi-layered consistency validation:

**1. Add pre-restore validation in `Command::run()`:**
```rust
// Before oneoff restore, validate consistency with existing DB
if let RestoreRunMode::Restore { restore_handler } = global_opt.run_mode.as_ref() {
    let synced_version = restore_handler.get_next_expected_transaction_version()?;
    let state_version = restore_handler.get_state_snapshot_before(Version::MAX)?
        .map(|(v, _)| v);
    
    ensure!(
        synced_version == 0 || state_version.is_some(),
        "Database has transactions without state. Use BootstrapDB for coordinated restore."
    );
}
```

**2. Enable consistency checks even during restore:**

Modify `StateStore::new()` to always perform basic consistency validation: [6](#0-5) 

Change to:
```rust
// Always perform basic consistency check with larger tolerance for restore
Self::sync_commit_progress(
    Arc::clone(&ledger_db),
    Arc::clone(&state_kv_db),
    Arc::clone(&state_merkle_db),
    /*crash_if_difference_is_too_large=*/ !empty_buffered_state_for_restore,
);
```

**3. Add version range validation in oneoff restore:**

Validate that restored data doesn't create gaps:
```rust
// In TransactionRestoreController::run()
if let Some(first_chunk_version) = manifest.chunks.first().map(|c| c.first_version) {
    let db_version = restore_handler.get_next_expected_transaction_version()?;
    ensure!(
        first_chunk_version == db_version,
        "Gap detected: DB at version {}, restoring from version {}. Use coordinated restore.",
        db_version, first_chunk_version
    );
}
```

**4. Document and enforce proper restore workflow:**
- Oneoff restores should only be used for debugging/analysis
- Production restore must use BootstrapDB coordinated mode
- Add warnings in CLI help text about consistency risks

## Proof of Concept

```bash
#!/bin/bash
# PoC: Create inconsistent database via partial restore

# Step 1: Create initial database and backup
aptos node run-local-testnet --test-dir ./testnet1
# Generate transactions and create backup
db-tool backup --db-dir ./testnet1/data/db --backup-dir ./backup1 --target-version 1000

# Step 2: Initialize empty database
mkdir -p ./testnet2/data/db

# Step 3: Restore ONLY transactions (no state snapshot)
db-tool restore oneoff transaction \
  --transaction-manifest ./backup1/transaction_manifest.json \
  --db-dir ./testnet2/data/db \
  --target-version 1000

# Step 4: Attempt to query state (will fail)
# Start node with restored DB
aptos node run-local-testnet --test-dir ./testnet2

# Expected: Node crashes or fails to start because:
# - Transactions exist at versions 0-1000
# - State KV DB is empty (no state for those versions)
# - State queries return NotFound errors
# - Transaction execution fails due to missing state
```

**Verification script:**
```rust
// Check database consistency
let db = AptosDB::open(/* restored db path */)?;
let synced_version = db.get_synced_version()?.expect("should have version");
let state_checkpoint = db.get_latest_state_checkpoint_version()?;

println!("Synced version: {}", synced_version);
println!("State checkpoint: {:?}", state_checkpoint);

// Try to read state at version 500
let state_key = StateKey::access_path(/* some key */);
match db.get_state_value_by_version(&state_key, 500) {
    Ok(Some(value)) => println!("State found: {:?}", value),
    Ok(None) => println!("INCONSISTENCY: State missing at version 500!"),
    Err(e) => println!("INCONSISTENCY: Error reading state: {:?}", e),
}
```

**Notes**

The vulnerability exists because restore operations intentionally bypass normal consistency checks to allow flexible recovery scenarios. However, the lack of ANY validation enables dangerous partial restores. The coordinated `BootstrapDB` mode implements proper restore ordering, but the oneoff modes trust the operator to maintain consistency manually without providing safeguards against mistakes or malicious actions.

### Citations

**File:** storage/db-tool/src/restore.rs (L65-127)
```rust
impl Command {
    pub async fn run(self) -> Result<()> {
        match self {
            Command::Oneoff(oneoff) => {
                match oneoff {
                    Oneoff::EpochEnding {
                        storage,
                        opt,
                        global,
                    } => {
                        EpochEndingRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                        )
                        .run(None)
                        .await?;
                    },
                    Oneoff::StateSnapshot {
                        storage,
                        opt,
                        global,
                    } => {
                        StateSnapshotRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                        )
                        .run()
                        .await?;
                    },
                    Oneoff::Transaction {
                        storage,
                        opt,
                        global,
                    } => {
                        TransactionRestoreController::new(
                            opt,
                            global.try_into()?,
                            storage.init_storage().await?,
                            None, /* epoch_history */
                            VerifyExecutionMode::NoVerify,
                        )
                        .run()
                        .await?;
                    },
                }
            },
            Command::BootstrapDB(bootstrap) => {
                RestoreCoordinator::new(
                    bootstrap.opt,
                    bootstrap.global.try_into()?,
                    bootstrap.storage.init_storage().await?,
                )
                .run()
                .await?;
            },
        }

        Ok(())
    }
}
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L453-457)
```rust
        let first_to_replay = max(
            self.replay_from_version
                .map_or(Version::MAX, |(version, _)| version),
            next_expected_version,
        );
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L269-277)
```rust
    if kv_replay && first_version > 0 && state_store.get_usage(Some(first_version - 1)).is_ok() {
        let (ledger_state, _hot_state_updates) = state_store.calculate_state_and_put_updates(
            &StateUpdateRefs::index_write_sets(first_version, write_sets, write_sets.len(), vec![]),
            &mut ledger_db_batch.ledger_metadata_db_batches, // used for storing the storage usage
            state_kv_batches,
        )?;
        // n.b. ideally this is set after the batches are committed
        state_store.set_state_ignoring_summary(ledger_state);
    }
```

**File:** storage/aptosdb/src/db/mod.rs (L82-104)
```rust
    pub fn open_kv_only(
        db_paths: StorageDirPaths,
        readonly: bool,
        pruner_config: PrunerConfig,
        rocksdb_configs: RocksdbConfigs,
        enable_indexer: bool,
        buffered_state_target_items: usize,
        max_num_nodes_per_lru_cache_shard: usize,
        internal_indexer_db: Option<InternalIndexerDB>,
    ) -> Result<Self> {
        Self::open_internal(
            &db_paths,
            readonly,
            pruner_config,
            rocksdb_configs,
            enable_indexer,
            buffered_state_target_items,
            max_num_nodes_per_lru_cache_shard,
            true,
            internal_indexer_db,
            HotStateConfig::default(),
        )
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L353-359)
```rust
        if !hack_for_tests && !empty_buffered_state_for_restore {
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
```

**File:** storage/aptosdb/src/state_store/mod.rs (L428-436)
```rust
            assert_ge!(ledger_commit_progress, overall_commit_progress);

            let state_kv_commit_progress = state_kv_db
                .metadata_db()
                .get::<DbMetadataSchema>(&DbMetadataKey::StateKvCommitProgress)
                .expect("Failed to read state K/V commit progress.")
                .expect("State K/V commit progress cannot be None.")
                .expect_version();
            assert_ge!(state_kv_commit_progress, overall_commit_progress);
```
