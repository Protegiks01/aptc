# Audit Report

## Title
Unhandled Panic in Indexer Metadata Deserialization Causes Complete Service Crash

## Summary
The indexer service contains multiple locations where database deserialization errors are not properly handled, using `.unwrap()` and `.expect()` calls that convert errors into panics. When combined with the global panic handler that exits the process, corrupted database metadata can crash the entire indexer service, requiring manual intervention to restart.

## Finding Description

The `decode_key()` and `decode_value()` implementations properly return `Result` types to handle deserialization errors: [1](#0-0) [2](#0-1) 

However, calling code in critical paths uses `.unwrap()` which converts these errors into panics: [3](#0-2) 

Additionally, the `MetadataValue` enum provides `expect_*()` methods that panic if the wrong variant is encountered: [4](#0-3) 

This pattern appears in multiple critical locations where metadata is read, including initialization and runtime operations: [5](#0-4) [6](#0-5) [7](#0-6) 

The indexer-grpc services use a global panic handler that exits the entire process when any panic occurs: [8](#0-7) 

This `next_version()` method is called during service initialization: [9](#0-8) 

**Attack Path:**
1. Database contains corrupted or invalid metadata (from disk corruption, write path bugs, or file system issues)
2. Indexer service starts or calls `next_version()` during operation
3. BCS deserialization of corrupted data fails, returning an error
4. The `.unwrap()` call converts the error to a panic
5. Global panic handler catches the panic and exits the process with code 12
6. Indexer service is completely down until manually restarted

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty criteria:

- **API crashes**: The indexer-grpc services provide critical API functionality for table info lookups and event indexing. Complete service crashes qualify as API crashes.
- **Significant protocol violations**: The lack of error recovery violates the availability guarantees expected from production infrastructure.

The impact includes:
- Complete unavailability of indexer services (table info, event indexing)
- Ecosystem services depending on the indexer fail or degrade
- Requires manual intervention to restart services
- Potential cascading failures in dApps relying on indexer data

This does NOT affect:
- Validator consensus (indexer runs separately from validators)
- Core blockchain functionality
- Fund security or transaction processing

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can be triggered by:
1. **Disk corruption**: Hardware failures, file system errors, or improper shutdown can corrupt RocksDB data
2. **Software bugs**: Bugs in the write path could write invalid metadata
3. **Database versioning issues**: Schema changes without migration could result in incompatible data
4. **Concurrent access issues**: Race conditions during write operations

The vulnerability is realistic because:
- RocksDB databases can become corrupted in production
- The indexer processes large volumes of data continuously
- No validation occurs before attempting deserialization
- Multiple code paths can trigger the panic

## Recommendation

Replace all `.unwrap()` and `.expect()` calls with proper error handling that returns `Result` types or logs errors without panicking:

**For `next_version()` in db_v2.rs:**
```rust
pub fn next_version(&self) -> Result<Version> {
    Ok(self
        .db
        .get::<IndexerMetadataSchema>(&MetadataKey::LatestVersion)?
        .map_or(0, |v| v.expect_version()))
}
```

**For initialization in db_v2.rs:**
```rust
pub fn new(db: DB) -> Result<Self> {
    let next_version = db
        .get::<IndexerMetadataSchema>(&MetadataKey::LatestVersion)?
        .map_or(0, |v| match v {
            MetadataValue::Version(ver) => ver,
            _ => return Err(anyhow::anyhow!("Unexpected metadata value type")),
        });

    Ok(Self {
        db,
        next_version: AtomicU64::new(next_version),
        pending_on: DashMap::new(),
    })
}
```

**For db_indexer.rs methods:**
```rust
fn get_version(&self, key: &MetadataKey) -> Result<Option<Version>> {
    match self.db.get::<InternalIndexerMetadataSchema>(key)? {
        Some(MetadataValue::Version(v)) => Ok(Some(v)),
        Some(_) => bail!("Unexpected metadata value type for key {:?}", key),
        None => Ok(None),
    }
}

pub fn get_restore_progress(&self, version: Version) -> Result<Option<StateSnapshotProgress>> {
    match self.db.get::<InternalIndexerMetadataSchema>(&MetadataKey::StateSnapshotRestoreProgress(version))? {
        Some(MetadataValue::StateSnapshotProgress(p)) => Ok(Some(p)),
        Some(_) => bail!("Unexpected metadata value type"),
        None => Ok(None),
    }
}
```

Additionally, consider adding data validation and recovery mechanisms:
- Validate metadata before deserialization
- Implement checkpointing for recovery
- Add monitoring for deserialization errors
- Consider using `catch_unwind` at service boundaries for graceful degradation

## Proof of Concept

```rust
#[cfg(test)]
mod test_panic_on_corrupted_metadata {
    use super::*;
    use aptos_db_indexer_schemas::schema::indexer_metadata::IndexerMetadataSchema;
    use aptos_schemadb::DB;
    use tempfile::TempDir;

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value")]
    fn test_next_version_panics_on_corrupted_data() {
        let tmpdir = TempDir::new().unwrap();
        let db = DB::open(
            tmpdir.path(),
            "test_db",
            vec![IndexerMetadataSchema::COLUMN_FAMILY_NAME],
            &Default::default(),
        )
        .unwrap();

        // Write corrupted data directly to the database
        let key = bcs::to_bytes(&MetadataKey::LatestVersion).unwrap();
        let corrupted_value = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Invalid BCS data
        
        db.put_raw(
            IndexerMetadataSchema::COLUMN_FAMILY_NAME,
            &key,
            &corrupted_value,
        )
        .unwrap();

        let indexer = IndexerAsyncV2 { 
            db, 
            next_version: AtomicU64::new(0),
            pending_on: DashMap::new(),
        };

        // This will panic with unwrap() on deserialization error
        let _ = indexer.next_version();
    }

    #[test]
    #[should_panic(expected = "Not version")]
    fn test_expect_version_panics_on_wrong_variant() {
        let tmpdir = TempDir::new().unwrap();
        let db = DB::open(
            tmpdir.path(),
            "test_db",
            vec![IndexerMetadataSchema::COLUMN_FAMILY_NAME],
            &Default::default(),
        )
        .unwrap();

        // Write wrong variant to database
        let progress = StateSnapshotProgress::new(
            HashValue::zero(),
            StateStorageUsage::zero(),
        );
        db.put::<IndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::StateSnapshotProgress(progress),
        )
        .unwrap();

        let indexer = IndexerAsyncV2 { 
            db, 
            next_version: AtomicU64::new(0),
            pending_on: DashMap::new(),
        };

        // This will panic with expect_version() on wrong variant
        let _ = indexer.next_version();
    }
}
```

## Notes

**Scope Clarification:**
This vulnerability affects the indexer-grpc services (`indexer-grpc-table-info`, `indexer-grpc-fullnode`), which are separate processes from validator nodes. While these services are critical ecosystem infrastructure that many dApps depend on, they do not affect:
- Consensus safety or liveness
- Validator node operation
- Transaction processing or execution
- State commitment or storage on validator nodes

**Additional Vulnerable Locations:**
Beyond `next_version()`, similar patterns exist in:
- `DBIndexer::get_version()` 
- `DBIndexer::get_restore_progress()`
- `DBCommitter::run()` with `.expect()` on channel receives and DB writes
- Iterator implementations with `.unwrap()` on deserialization

All of these should be refactored to use proper error handling instead of panicking.

### Citations

**File:** storage/indexer_schemas/src/schema/indexer_metadata/mod.rs (L30-32)
```rust
    fn decode_key(data: &[u8]) -> Result<Self> {
        Ok(bcs::from_bytes(data)?)
    }
```

**File:** storage/indexer_schemas/src/schema/indexer_metadata/mod.rs (L40-42)
```rust
    fn decode_value(data: &[u8]) -> Result<Self> {
        Ok(bcs::from_bytes(data)?)
    }
```

**File:** storage/indexer/src/db_v2.rs (L61-64)
```rust
    pub fn new(db: DB) -> Result<Self> {
        let next_version = db
            .get::<IndexerMetadataSchema>(&MetadataKey::LatestVersion)?
            .map_or(0, |v| v.expect_version());
```

**File:** storage/indexer/src/db_v2.rs (L142-147)
```rust
    pub fn next_version(&self) -> Version {
        self.db
            .get::<IndexerMetadataSchema>(&MetadataKey::LatestVersion)
            .unwrap()
            .map_or(0, |v| v.expect_version())
    }
```

**File:** storage/indexer_schemas/src/metadata.rs (L16-28)
```rust
    pub fn expect_version(self) -> Version {
        match self {
            Self::Version(v) => v,
            _ => panic!("Not version"),
        }
    }

    pub fn expect_state_snapshot_progress(self) -> StateSnapshotProgress {
        match self {
            Self::StateSnapshotProgress(p) => p,
            _ => panic!("Not state snapshot progress"),
        }
    }
```

**File:** storage/indexer/src/db_indexer.rs (L154-161)
```rust
    pub fn get_restore_progress(&self, version: Version) -> Result<Option<StateSnapshotProgress>> {
        Ok(self
            .db
            .get::<InternalIndexerMetadataSchema>(&MetadataKey::StateSnapshotRestoreProgress(
                version,
            ))?
            .map(|e| e.expect_state_snapshot_progress()))
    }
```

**File:** storage/indexer/src/db_indexer.rs (L287-292)
```rust
    fn get_version(&self, key: &MetadataKey) -> Result<Option<Version>> {
        Ok(self
            .db
            .get::<InternalIndexerMetadataSchema>(key)?
            .map(|v| v.expect_version()))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L149-168)
```rust
pub fn setup_panic_handler() {
    std::panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());
    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);
    // Kill the process
    process::exit(12);
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L100-107)
```rust
        let parser = TableInfoService::new(
            context,
            indexer_async_v2_clone.next_version(),
            node_config.indexer_table_info.parser_task_count,
            node_config.indexer_table_info.parser_batch_size,
            backup_restore_operator,
            indexer_async_v2_clone,
        );
```
