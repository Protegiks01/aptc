# Audit Report

## Title
Indexer Version Desynchronization Vulnerability in State Snapshot Restoration Path

## Summary
The state snapshot restoration code path (`kv_finish` in `state_store/mod.rs`) fails to update the `EventV2TranslationVersion` metadata field while updating all other indexer version fields. This creates a permanent version mismatch that causes validator nodes to panic on restart when the Event V2 translation indexer is enabled, resulting in a denial of service.

## Finding Description

The internal indexer database maintains five separate version metadata fields to track indexing progress: `LatestVersion`, `StateVersion`, `TransactionVersion`, `EventVersion`, and `EventV2TranslationVersion`. The codebase has two distinct code paths that update these metadata fields:

**Path 1: Normal Indexing** - Updates all 5 version fields atomically in a single batch: [1](#0-0) 

**Path 2: State Snapshot Restoration** - Only updates 4 of the 5 version fields, omitting `EventV2TranslationVersion`: [2](#0-1) 

During node startup, the `get_start_version()` function enforces strict equality checks between all enabled indexer version fields: [3](#0-2) 

The vulnerability manifests when:
1. A node with Event V2 translation enabled undergoes state snapshot restoration (triggered during bootstrap, fast-sync, or backup restore operations)
2. The `kv_finish()` function updates `LatestVersion` to the restored version (e.g., 5000) but leaves `EventV2TranslationVersion` at its previous value (e.g., 1000)
3. On next restart, `get_start_version()` detects the version mismatch and panics with: "Cannot start event v2 translation indexer because the progress doesn't match"
4. The node cannot restart, causing a permanent liveness failure

This breaks the critical invariant that **all indexer types must remain synchronized at all times**.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty categories)

This vulnerability causes **validator node liveness failures** that meet the High severity criteria:
- Affected nodes cannot restart after state restoration, causing extended downtime
- Requires manual database intervention to recover
- No funds are lost, but network participation is disrupted
- Applies to any validator node with Event V2 translation indexer enabled that undergoes state restoration

The impact is limited to individual nodes (not network-wide consensus failure), placing it in the High rather than Critical category.

## Likelihood Explanation

**Likelihood: High**

State snapshot restoration is a common operation that occurs in multiple scenarios:
1. **Bootstrap from snapshot** - New validators joining the network
2. **Fast-sync catch-up** - Nodes that fall behind synchronizing state
3. **Backup restoration** - Disaster recovery scenarios

The Event V2 translation indexer is enabled by default in many node configurations. Any node that undergoes state restoration while having this feature enabled will experience the version desynchronization, making this a high-probability operational issue rather than a theoretical vulnerability.

No attacker action is required - the bug triggers during normal node operations.

## Recommendation

Update the `kv_finish()` function in `state_store/mod.rs` to include the `EventV2TranslationVersion` metadata update, ensuring consistency with the normal indexing path:

```rust
fn kv_finish(&self, version: Version, usage: StateStorageUsage) -> Result<()> {
    self.ledger_db.metadata_db().put_usage(version, usage)?;
    if let Some(internal_indexer_db) = self.internal_indexer_db.as_ref() {
        if version > 0 {
            let mut batch = SchemaBatch::new();
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::LatestVersion,
                &MetadataValue::Version(version - 1),
            )?;
            if internal_indexer_db.statekeys_enabled() {
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::StateVersion,
                    &MetadataValue::Version(version - 1),
                )?;
            }
            if internal_indexer_db.transaction_enabled() {
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::TransactionVersion,
                    &MetadataValue::Version(version - 1),
                )?;
            }
            if internal_indexer_db.event_enabled() {
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::EventVersion,
                    &MetadataValue::Version(version - 1),
                )?;
            }
            // ADD THIS BLOCK:
            if internal_indexer_db.event_v2_translation_enabled() {
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::EventV2TranslationVersion,
                    &MetadataValue::Version(version - 1),
                )?;
            }
            internal_indexer_db
                .get_inner_db_ref()
                .write_schemas(batch)?;
        }
    }
    Ok(())
}
```

Additionally, consider adding a defensive check in `get_start_version()` that allows automatic recovery by resetting lagging version fields rather than panicking, or at least providing clearer error messages with recovery instructions.

## Proof of Concept

**Reproduction Steps:**

1. **Setup**: Start a validator node with Event V2 translation indexer enabled:
   ```toml
   [indexer_db_config]
   enable_event_v2_translation = true
   enable_event = true
   enable_transaction = true
   enable_statekeys = true
   ```

2. **Initial Operation**: Let the node process transactions normally up to version 1000. All version fields will be synchronized at 1000.

3. **Trigger State Restoration**: Initiate a state snapshot restore to version 5000 using the backup-cli tool:
   ```bash
   cargo run -p aptos-db-tool -- bootstrap-db \
     --target-db-dir /path/to/db \
     --metadata-cache-dir /path/to/metadata \
     --command restore-from-backup \
     --backup-uri file:///path/to/backup
   ```

4. **Verify Desynchronization**: After restoration completes, query the internal indexer metadata:
   ```rust
   // LatestVersion = 5000
   // StateVersion = 5000
   // TransactionVersion = 5000
   // EventVersion = 5000
   // EventV2TranslationVersion = 1000  // <- DESYNCHRONIZED
   ```

5. **Trigger Failure**: Restart the node with the same configuration:
   ```bash
   cargo run -p aptos-node -- -f /path/to/config.yaml
   ```

6. **Observe Panic**: The node will panic during startup with:
   ```
   thread 'main' panicked at 'Cannot start event v2 translation indexer because the progress doesn't match. start_version: 5001, event_v2_translation_start_version: 1001'
   ```

The node cannot restart without manual database intervention or configuration changes.

## Notes

This vulnerability is particularly insidious because:
1. It only manifests after a restart following state restoration
2. The desynchronization is permanent and persisted to disk
3. Regular operation appears normal until the restart
4. Recovery requires expert knowledge of the internal indexer database structure

The root cause is the incomplete port of version tracking logic from the normal indexing path to the state restoration path when Event V2 translation support was added to the indexer system.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L505-545)
```rust
        if self.indexer_db.event_v2_translation_enabled() {
            batch.put::<InternalIndexerMetadataSchema>(
                &MetadataKey::EventV2TranslationVersion,
                &MetadataValue::Version(version - 1),
            )?;

            for event_key in event_keys {
                batch
                    .put::<EventSequenceNumberSchema>(
                        &event_key,
                        &self
                            .event_v2_translation_engine
                            .get_cached_sequence_number(&event_key)
                            .unwrap_or(0),
                    )
                    .expect("Failed to put events by key to a batch");
            }
        }

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
        batch.put::<InternalIndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::Version(version - 1),
        )?;
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1281-1315)
```rust
    fn kv_finish(&self, version: Version, usage: StateStorageUsage) -> Result<()> {
        self.ledger_db.metadata_db().put_usage(version, usage)?;
        if let Some(internal_indexer_db) = self.internal_indexer_db.as_ref() {
            if version > 0 {
                let mut batch = SchemaBatch::new();
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::LatestVersion,
                    &MetadataValue::Version(version - 1),
                )?;
                if internal_indexer_db.statekeys_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::StateVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                if internal_indexer_db.transaction_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::TransactionVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                if internal_indexer_db.event_enabled() {
                    batch.put::<InternalIndexerMetadataSchema>(
                        &MetadataKey::EventVersion,
                        &MetadataValue::Version(version - 1),
                    )?;
                }
                internal_indexer_db
                    .get_inner_db_ref()
                    .write_schemas(batch)?;
            }
        }

        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L88-165)
```rust
    pub async fn get_start_version(&self, node_config: &NodeConfig) -> Result<Version> {
        let fast_sync_enabled = node_config
            .state_sync
            .state_sync_driver
            .bootstrapping_mode
            .is_fast_sync();
        let mut main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;

        // Wait till fast sync is done
        while fast_sync_enabled && main_db_synced_version == 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
        }

        let start_version = self
            .db_indexer
            .indexer_db
            .get_persisted_version()?
            .map_or(0, |v| v + 1);

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

        if node_config.indexer_db_config.enable_event_v2_translation() {
            let event_v2_translation_start_version = self
                .db_indexer
                .indexer_db
                .get_event_v2_translation_version()?
                .map_or(0, |v| v + 1);
            if node_config
                .indexer_db_config
                .event_v2_translation_ignores_below_version()
                < start_version
                && start_version != event_v2_translation_start_version
            {
                panic!(
                    "Cannot start event v2 translation indexer because the progress doesn't match. \
                    start_version: {}, event_v2_translation_start_version: {}",
                    start_version, event_v2_translation_start_version
                );
            }
            if !node_config.indexer_db_config.enable_event() {
                panic!("Cannot start event v2 translation indexer because event indexer is not enabled.");
            }
        }

        Ok(start_version)
    }
```
