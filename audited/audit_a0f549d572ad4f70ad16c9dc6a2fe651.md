# Audit Report

## Title
Internal Indexer DB Configuration Mismatch Causes Node Startup Failure After Restore or Corruption Recovery

## Summary
The Internal Indexer DB lacks a safe mechanism to reset or rebuild individual indexer components, forcing operators to manually delete the entire indexer database when recovering from corruption or changing feature flags. This creates operational risk and potential node unavailability.

## Finding Description

The vulnerability exists in the interaction between the restore process and normal node startup configuration for the Internal Indexer DB. The system maintains separate version metadata for each indexer component (transactions, events, state keys, event v2 translation), and strictly enforces that all enabled components must have matching progress.

During backup restoration, the system uses a hardcoded configuration that enables all indexer features: [1](#0-0) 

However, during normal startup, the node uses the operator-specified configuration: [2](#0-1) 

The startup validation strictly enforces version consistency across all enabled features and panics if mismatches are detected: [3](#0-2) 

**Exploitation Path:**

1. Operator performs backup restoration using `get_indexer_db_for_restore()`, which populates all indexer features (transaction, event, statekeys, event_v2_translation) with data up to version N
2. Operator starts node with configuration having only some features enabled (e.g., `enable_event=false`)
3. Node advances to version M >> N while event indexing remains at version N
4. Operator later enables events in configuration (`enable_event=true`)
5. Node startup checks reveal: `LatestVersion=M` but `EventVersion=N`
6. System panics: "Cannot start event indexer because the progress doesn't match"

**Alternative Corruption Scenario:**

1. Node running with all features enabled experiences corruption in one component (e.g., event indexing)
2. Operator wants to rebuild only the corrupted component
3. No documented mechanism exists to reset individual component metadata
4. Only option: Delete entire internal_indexer_db directory, losing all indexing data

Each indexer component tracks its version independently: [4](#0-3) 

## Impact Explanation

This qualifies as **Medium severity** under Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: The internal indexer DB state becomes inconsistent with the runtime configuration, requiring manual operator intervention
- **Node availability impact**: Nodes cannot start when configuration changes conflict with existing DB state
- **Operational disruption**: Forces complete indexer rebuild (hours/days of processing) instead of targeted component recovery

This does NOT qualify as High/Critical because:
- Does not affect consensus or main ledger
- Does not cause fund loss
- Main DB remains intact and consistent
- Network continues operating (only affects individual operator's node)

## Likelihood Explanation

**High likelihood** in production environments:
- Operators routinely perform backup/restore operations
- Configuration changes are common operational tasks
- Partial corruption requiring component-level recovery is a realistic scenario
- No documentation warns operators about this limitation

**Affected scenarios:**
- Any restore operation followed by configuration changes
- Recovery from partial indexer corruption
- Feature flag adjustments during upgrades or optimization

## Recommendation

Implement a safe reset mechanism for individual indexer components:

1. **Add metadata management commands** to db-tool:
   - `reset-indexer-component --component=events` to clear specific component metadata and data
   - `rebuild-indexer-component --component=events --from-version=N` to rebuild from main DB

2. **Add validation warnings** instead of panics:
   - Check if disabled features have stale data and warn operator
   - Provide clear remediation steps in error messages

3. **Document recovery procedures**:
   - Explicitly document that `get_indexer_db_for_restore()` enables all features
   - Provide step-by-step recovery procedures for corruption scenarios
   - Warn about configuration change impacts

4. **Improve config validation**:
   - Detect config-DB mismatches on startup
   - Offer automatic reconciliation options (with confirmation)
   - Add `--force-rebuild-component` flag for controlled rebuilds

## Proof of Concept

```rust
// Reproduction steps (operational scenario, not malicious attack):

// Step 1: Restore with all features enabled (hardcoded in restore function)
// This populates all indexer components to version 10000

// Step 2: Start node with partial features enabled
let config = InternalIndexerDBConfig {
    enable_transaction: true,
    enable_event: false,  // Disabled
    enable_event_v2_translation: false,
    event_v2_translation_ignores_below_version: 0,
    enable_statekeys: true,
    batch_size: 10_000,
};

// Step 3: Node runs and advances to version 50000
// EventVersion remains at 10000 (not updated when disabled)

// Step 4: Operator enables events
let new_config = InternalIndexerDBConfig {
    enable_transaction: true,
    enable_event: true,  // Now enabled
    enable_event_v2_translation: false,
    event_v2_translation_ignores_below_version: 0,
    enable_statekeys: true,
    batch_size: 10_000,
};

// Step 5: Node startup calls get_start_version()
// LatestVersion = 50000
// EventVersion = 10000
// Mismatch detected → PANIC

// Expected: "Cannot start event indexer because the progress doesn't match."
// Actual operator options:
// 1. Delete entire internal_indexer_db directory (loses all indexing data)
// 2. Manually manipulate RocksDB (unsafe, undocumented)
// No safe, documented recovery path exists.
```

## Notes

While this is a real operational limitation that affects node availability and operator workflows, it does **not** meet all validation criteria for a traditional security vulnerability:

- Not exploitable by unprivileged external attackers
- Requires operator access and legitimate operational actions  
- Affects availability but not consensus, funds, or data integrity
- Main ledger DB remains unaffected

This represents a **design limitation** in the indexer recovery mechanism rather than a security vulnerability that malicious actors can exploit. The security impact is primarily operational risk and reduced resilience to corruption scenarios.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L43-57)
```rust
    pub fn get_indexer_db_for_restore(db_dir: &Path) -> Option<InternalIndexerDB> {
        let db_path_buf = PathBuf::from(db_dir).join(INTERNAL_INDEXER_DB);
        let rocksdb_config = NodeConfig::default()
            .storage
            .rocksdb_configs
            .index_db_config;
        let arc_db = Arc::new(
            open_internal_indexer_db(db_path_buf.as_path(), &rocksdb_config)
                .expect("Failed to open internal indexer db"),
        );

        let internal_indexer_db_config =
            InternalIndexerDBConfig::new(true, true, true, 0, true, 10_000);
        Some(InternalIndexerDB::new(arc_db, internal_indexer_db_config))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L59-82)
```rust
    pub fn get_indexer_db(node_config: &NodeConfig) -> Option<InternalIndexerDB> {
        if !node_config
            .indexer_db_config
            .is_internal_indexer_db_enabled()
        {
            return None;
        }
        let db_path_buf = node_config
            .storage
            .get_dir_paths()
            .default_root_path()
            .join(INTERNAL_INDEXER_DB);
        let rocksdb_config = node_config.storage.rocksdb_configs.index_db_config;
        let db_path = db_path_buf.as_path();

        let arc_db = Arc::new(
            open_internal_indexer_db(db_path, &rocksdb_config)
                .expect("Failed to open internal indexer db"),
        );
        Some(InternalIndexerDB::new(
            arc_db,
            node_config.indexer_db_config,
        ))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L108-139)
```rust
        if node_config.indexer_db_config.enable_statekeys() {
            let state_start_version = self
                .db_indexer
                .indexer_db
                .get_state_version()?
                .map_or(0, |v| v + 1);
            if start_version != state_start_version {
                panic!("Cannot start state indexer because the progress doesn't match.");
            }
        }

        if node_config.indexer_db_config.enable_transaction() {
            let transaction_start_version = self
                .db_indexer
                .indexer_db
                .get_transaction_version()?
                .map_or(0, |v| v + 1);
            if start_version != transaction_start_version {
                panic!("Cannot start transaction indexer because the progress doesn't match.");
            }
        }

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

**File:** storage/indexer/src/db_indexer.rs (L524-541)
```rust
        if self.indexer_db.transaction_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::TransactionVersion,
                &MetadataValue::Version(version - 1),
            )?;
        }
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
```
