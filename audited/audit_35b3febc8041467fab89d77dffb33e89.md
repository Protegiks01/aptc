# Audit Report

## Title
Disk Corruption in Internal Indexer Event Index Causes Unrecoverable Node Crash via Panic Handler

## Summary
A panic in the internal indexer DB service caused by version mismatch between the persisted version and event-specific version triggers the global panic handler, causing immediate process termination (exit code 12) and preventing node restart until manual database repair.

## Finding Description
The `get_start_version()` function performs version consistency checks across different indexer components. When event indexing is enabled, it verifies that the general persisted version matches the event-specific version. [1](#0-0) 

During node startup, the internal indexer DB service is spawned as an async task that immediately calls `run()`, which in turn calls `get_start_version()`: [2](#0-1) 

The critical issue is that Aptos nodes install a global panic handler that intercepts ALL panics (including those in Tokio async tasks) and terminates the process: [3](#0-2) [4](#0-3) 

This panic handler is installed during node startup: [5](#0-4) 

The version metadata is stored in the InternalIndexerDB using separate keys for different index types (LatestVersion, EventVersion, StateVersion, TransactionVersion): [6](#0-5) 

These versions are updated together in a batch during indexing: [7](#0-6) 

**Attack Path:**
1. Node is running with event indexing enabled (`enable_event = true`)
2. Disk corruption, unclean shutdown, or partial write during batch commit causes version metadata to become inconsistent (e.g., LatestVersion = 1000 but EventVersion = 999)
3. Node crashes or is restarted
4. During startup, `bootstrap_internal_indexer_db()` spawns the indexer service task
5. The task calls `get_start_version()` which detects `start_version != event_start_version`
6. Panic is triggered at line 137
7. Global panic handler catches it and calls `process::exit(12)`
8. Node terminates before completing startup
9. Every subsequent restart attempt hits the same panic, making the node unrecoverable without manual intervention

## Impact Explanation
This is a **High Severity** vulnerability per the Aptos bug bounty criteria:

- **Validator node slowdowns/unavailability**: The affected node cannot start and remains offline until manual database repair
- **Significant protocol violation**: A component designed to be auxiliary (indexer) can prevent core node functionality from starting
- **Service degradation**: Operators must manually intervene to repair or rebuild the indexer database

While this doesn't cause network-wide liveness loss (other nodes continue functioning) or consensus safety violations, it does cause individual node unavailability requiring manual intervention. The vulnerability affects node availability without requiring privileged access—disk corruption is a realistic operational failure mode.

## Likelihood Explanation
The likelihood is **Medium to High** because:

**Triggering Conditions (Realistic):**
- Disk corruption from hardware failures (bad sectors, controller errors)
- Unclean shutdowns during power loss or OOM kills
- Filesystem bugs causing inconsistent writes
- RocksDB batch commit failures or crashes mid-write

**Mitigating Factors:**
- Requires event indexing to be enabled (`enable_event = true`)
- Modern filesystems and hardware have corruption protection
- Proper shutdown procedures minimize partial writes

However, production infrastructure regularly experiences these issues, making this a realistic operational concern rather than a theoretical attack vector.

## Recommendation
Implement graceful degradation instead of crashing on indexer version mismatches:

```rust
pub async fn get_start_version(&self, node_config: &NodeConfig) -> Result<Version> {
    // ... existing code ...
    
    if node_config.indexer_db_config.enable_event() {
        let event_start_version = self
            .db_indexer
            .indexer_db
            .get_event_version()?
            .map_or(0, |v| v + 1);
        if start_version != event_start_version {
            // Log error and attempt recovery instead of panicking
            error!(
                "Event indexer version mismatch detected: start_version={}, event_start_version={}. \
                Attempting to recover by resetting event indexer progress.",
                start_version, event_start_version
            );
            
            // Option 1: Reset event indexer to match persisted version
            // This allows the node to start and re-index events
            return Ok(start_version);
            
            // Option 2: Reset all indexer versions to the minimum
            // let min_version = start_version.min(event_start_version);
            // return Ok(min_version);
        }
    }
    
    Ok(start_version)
}
```

Additional hardening:
1. Add database consistency checks on shutdown
2. Implement atomic metadata updates using RocksDB transactions
3. Add recovery mode that rebuilds indexer from main database
4. Make the panic conditional on a config flag for strict mode vs. recovery mode
5. Log detailed diagnostics before recovery attempts

## Proof of Concept
The following steps reproduce the vulnerability:

```rust
// Rust reproduction steps:
// 1. Start a node with event indexing enabled (enable_event = true)
// 2. Wait for it to index some transactions
// 3. Manually corrupt the indexer database metadata:

use aptos_db_indexer_schemas::schema::indexer_metadata::InternalIndexerMetadataSchema;
use aptos_db_indexer_schemas::metadata::{MetadataKey, MetadataValue};
use aptos_schemadb::SchemaBatch;

fn corrupt_indexer_metadata(indexer_db_path: &Path) {
    let db = open_internal_indexer_db(indexer_db_path, &default_config()).unwrap();
    
    // Read current LatestVersion
    let latest = db.get::<InternalIndexerMetadataSchema>(&MetadataKey::LatestVersion)
        .unwrap()
        .unwrap()
        .expect_version();
    
    // Write mismatched EventVersion (off by 1)
    let mut batch = SchemaBatch::new();
    batch.put::<InternalIndexerMetadataSchema>(
        &MetadataKey::EventVersion,
        &MetadataValue::Version(latest - 1)
    ).unwrap();
    db.write_schemas(batch).unwrap();
}

// 4. Restart the node
// Expected: Node crashes with exit code 12 and cannot restart
// Actual: Panic handler terminates process, node is unrecoverable without DB repair
```

**Verification:**
1. Enable event indexing in node config
2. Run node and let it index transactions
3. Kill node process
4. Use `rocksdb-admin` or similar tool to modify EventVersion metadata to differ from LatestVersion
5. Attempt to restart node
6. Observe: Node panics during startup with "Cannot start event indexer because the progress doesn't match" and exits with code 12
7. Observe: All subsequent restart attempts fail identically until database is manually repaired

## Notes
- This vulnerability also affects the transaction indexer (line 126) and state keys indexer (line 115) with identical panic conditions
- The event v2 translation indexer has a similar check (lines 147-158) with slightly different conditions
- The InternalIndexerDB is optional but commonly enabled on fullnodes and archive nodes for API functionality
- The vulnerability only affects nodes with indexing enabled; nodes without indexing are unaffected

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L130-139)
```rust
        if node_config.indexer_db_config.enable_event() {
            let event_start_version = self
                .db_indexer
                .indexer_db
                .get_event_version()?
                .map_or(0, |v| v + 1);
            if start_version != event_start_version {
                panic!("Cannot start event indexer because the progress doesn't match.");
            }
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L42-44)
```rust
    runtime.spawn(async move {
        indexer_service.run(&config_clone).await.unwrap();
    });
```

**File:** crates/crash-handler/src/lib.rs (L21-30)
```rust
/// Invoke to ensure process exits on a thread panic.
///
/// Tokio's default behavior is to catch panics and ignore them.  Invoking this function will
/// ensure that all subsequent thread panics (even Tokio threads) will report the
/// details/backtrace and then exit.
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}
```

**File:** crates/crash-handler/src/lib.rs (L56-57)
```rust
    // Kill the process
    process::exit(12);
```

**File:** aptos-node/src/lib.rs (L233-234)
```rust
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();
```

**File:** storage/indexer/src/db_indexer.rs (L110-116)
```rust
    pub fn get_persisted_version(&self) -> Result<Option<Version>> {
        self.get_version(&MetadataKey::LatestVersion)
    }

    pub fn get_event_version(&self) -> Result<Option<Version>> {
        self.get_version(&MetadataKey::EventVersion)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L530-545)
```rust
        if self.indexer_db.event_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::EventVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        if self.indexer_db.statekeys_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::StateVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
        batch.put::<InternalIndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::Version(version - 1),
        )?;
```
