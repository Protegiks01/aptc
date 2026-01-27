# Audit Report

## Title
Database Version Skew Causes Deserialization Panic in DB Debugger Tool

## Summary
The `db_debugger/watch/opened.rs` tool lacks database schema version checking and contains multiple `.expect()` calls that will panic when an older version of the tool attempts to open a database from a newer Aptos version with incompatible schema changes.

## Finding Description

The debugging tool opens an AptosDB database without any version validation mechanism. During the database opening process, critical deserialization operations use `.expect()` calls that will panic on failure.

**Critical Code Path:** [1](#0-0) 

This calls into the database opening code: [2](#0-1) 

Which creates a `LedgerMetadataDb` that immediately reads database content: [3](#0-2) 

The `get_latest_ledger_info_in_db_impl` function deserializes ledger info: [4](#0-3) 

This deserialization uses BCS which strictly validates schema compatibility: [5](#0-4) 

**The Vulnerability:**

`LedgerInfoWithSignatures` is an enum designed for schema evolution: [6](#0-5) 

When a newer Aptos version adds a new enum variant (e.g., `V1`), and an older debugging tool tries to open that database, BCS deserialization will fail because the old code only knows about `V0`. This failure propagates through multiple `.expect()` calls, causing a panic.

**No Schema Version Checking:**

The codebase has no database schema version validation: [7](#0-6) 

Notice that `DbMetadataKey` only tracks operational progress (pruner, commit), not schema versions.

## Impact Explanation

**Severity: Low to Medium** (depending on operational context)

This issue does not meet Critical or High severity criteria because:
- No funds are at risk
- No consensus safety violations occur
- No network partition results
- This only affects diagnostic/debugging tools

However, it represents a **High operational risk**:
- Operators cannot inspect databases during version transitions
- Debugging becomes impossible during schema migrations
- Could delay incident response if old tools are used

## Likelihood Explanation

**Likelihood: Medium**

This will occur whenever:
1. Aptos releases a schema-breaking change (e.g., adding `LedgerInfoWithSignatures::V1`)
2. An operator attempts to use an older debugging tool on a newer database
3. Common during:
   - Partial rollouts across validator fleet
   - Testing new versions
   - Forensic analysis of production databases with old tools

## Recommendation

Implement database schema versioning and validation:

**1. Add schema version metadata:**
```rust
// In storage/aptosdb/src/schema/db_metadata/mod.rs
pub enum DbMetadataKey {
    // ... existing keys ...
    SchemaVersion, // NEW
}
```

**2. Add version checking in database opening:**
```rust
// In storage/aptosdb/src/db/mod.rs
const CURRENT_SCHEMA_VERSION: u64 = 1;

pub fn open(...) -> Result<Self> {
    let db = Self::open_internal(...)?;
    
    // Check schema version
    if let Some(db_version) = db.get_schema_version()? {
        if db_version > CURRENT_SCHEMA_VERSION {
            return Err(AptosDbError::Other(format!(
                "Database schema version {} is newer than supported version {}. Please upgrade the tool.",
                db_version, CURRENT_SCHEMA_VERSION
            )));
        }
    }
    
    Ok(db)
}
```

**3. Remove panic-causing `.expect()` calls:**
```rust
// In storage/aptosdb/src/ledger_db/ledger_metadata_db.rs
pub(super) fn new(db: Arc<DB>) -> Result<Self> {
    let latest_ledger_info = get_latest_ledger_info_in_db_impl(&db)?; // Use ? instead of expect()
    // ...
}
```

## Proof of Concept

While I cannot provide a runnable PoC without modifying the enum definitions, the exploitation path is straightforward:

**Step 1:** Modify `LedgerInfoWithSignatures` to add V1 variant (simulating newer version):
```rust
pub enum LedgerInfoWithSignatures {
    V0(LedgerInfoWithV0),
    V1(LedgerInfoWithV1), // New variant
}
```

**Step 2:** Create and populate a database with V1 ledger info

**Step 3:** Revert the enum to only V0 (simulating older tool)

**Step 4:** Run the debugging tool:
```bash
cargo run --bin aptos-debugger -- watch --db-dir /path/to/newer/db
```

**Expected Result:** Panic with "DB read failed." message due to unrecognized enum variant during BCS deserialization.

---

**Notes:**

While this issue primarily affects debugging tools rather than production validators, it represents a gap in the database layer's defensive programming. The lack of schema versioning means any schema-breaking change will cause panics rather than graceful errors. This becomes more critical as the codebase evolves and schema migrations become necessary.

### Citations

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

**File:** storage/aptosdb/src/db/mod.rs (L115-121)
```rust
        let ledger_db = LedgerDb::new(
            db_paths.ledger_db_root_path(),
            rocksdb_configs,
            env,
            block_cache,
            readonly,
        )?;
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L26-30)
```rust
fn get_latest_ledger_info_in_db_impl(db: &DB) -> Result<Option<LedgerInfoWithSignatures>> {
    let mut iter = db.iter::<LedgerInfoSchema>()?;
    iter.seek_to_last();
    Ok(iter.next().transpose()?.map(|(_, v)| v))
}
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L43-50)
```rust
    pub(super) fn new(db: Arc<DB>) -> Self {
        let latest_ledger_info = get_latest_ledger_info_in_db_impl(&db).expect("DB read failed.");
        let latest_ledger_info = ArcSwap::from(Arc::new(latest_ledger_info));

        Self {
            db,
            latest_ledger_info,
        }
```

**File:** storage/aptosdb/src/schema/ledger_info/mod.rs (L49-51)
```rust
    fn decode_value(data: &[u8]) -> Result<Self> {
        bcs::from_bytes(data).map_err(Into::into)
    }
```

**File:** types/src/ledger_info.rs (L164-168)
```rust
/// Wrapper around LedgerInfoWithScheme to support future upgrades, this is the data being persisted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LedgerInfoWithSignatures {
    V0(LedgerInfoWithV0),
}
```

**File:** storage/aptosdb/src/schema/db_metadata/mod.rs (L47-72)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
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
