# Audit Report

## Title
Indexer Metadata Inconsistency After Fast Sync Causes Silent Data Loss in Historical Queries

## Summary
During fast sync state snapshot restoration, the `StateStore::kv_finish()` method incorrectly sets internal indexer metadata (`TransactionVersion` and `EventVersion`) to `snapshot_version - 1`, falsely claiming that transactions and events have been indexed. However, fast sync intentionally skips historical transaction/event data, leaving these indices empty. This causes API queries to pass metadata validation but return empty results, resulting in silent data loss.

## Finding Description

The vulnerability exists in the interaction between fast sync state snapshot restoration and internal indexer metadata management.

**Root Cause:**

During fast sync, `StateStore::kv_finish()` unconditionally sets indexer metadata for all data types, including transactions and events that were never actually indexed. [1](#0-0) 

The method sets `TransactionVersion` and `EventVersion` to `version - 1` whenever the internal indexer is enabled, regardless of whether any transactions or events were actually indexed during the fast sync process.

**Why This Is Wrong:**

Fast sync only saves ONE checkpoint transaction at the snapshot version, not the historical transactions. [2](#0-1) 

The code explicitly enforces that only one transaction is saved during `finalize_state_snapshot`.

**State Keys vs Transactions/Events:**

While state keys ARE correctly indexed during fast sync via `write_kv_batch`. [3](#0-2) 

Transactions and events are indexed separately by `DBIndexer.process_a_batch()` which reads from the main database. [4](#0-3) 

**The Consequence:**

When the `DBIndexer` starts after fast sync, it reads the incorrect metadata and believes it has already indexed all historical data. [5](#0-4) 

The indexer starts from `persisted_version + 1`, skipping all historical versions that were never actually indexed.

**API Query Failure:**

When queries route through the internal indexer (default behavior with `db_sharding_enabled` set to true). [6](#0-5) [7](#0-6) 

The query path calls `ensure_cover_ledger_version()` which checks the incorrect metadata. [8](#0-7) 

This check passes because the metadata falsely claims coverage. Then `lookup_events_by_key()` is called. [9](#0-8) 

The iterator finds no entries (because nothing was indexed) and returns an empty vector, causing silent data loss instead of a proper error.

**Fast Sync Call Path:**

The `kv_finish()` method is called during fast sync completion. [10](#0-9) [11](#0-10) [12](#0-11) 

## Impact Explanation

This vulnerability qualifies as **MEDIUM severity** under the Aptos bug bounty program's "Limited Protocol Violations" category:

1. **API Misbehavior**: API nodes using fast sync serve incorrect (empty) results for all historical transaction and event queries in the range [0, snapshot_version-1]. Applications depending on this data will malfunction.

2. **Silent Data Loss**: The system returns empty results instead of proper "data not available" errors, making the issue extremely difficult to detect and debug.

3. **Widespread Impact**: Affects all nodes that:
   - Use fast sync for bootstrapping (standard practice for new API nodes)
   - Have internal indexer enabled (default configuration)
   - Have `enable_storage_sharding` set to true (default per configuration) [13](#0-12) 
   - Serve historical query requests

4. **Protocol Violation**: The indexer metadata provides false guarantees about data availability, violating the fundamental contract between storage and query layers.

5. **Limited Scope**: This does not affect consensus, validator operation, or fund security. It only impacts data availability for historical queries on nodes bootstrapped via fast sync.

## Likelihood Explanation

**Likelihood: HIGH**

This bug triggers deterministically whenever:
- A node uses fast sync mode (standard for new node deployments)
- The internal indexer is enabled (default configuration)
- Storage sharding is enabled (default value is `true`)
- Any historical queries are made through the API

No malicious actor is required - this is a systematic integration bug between fast sync and the internal indexer. The conditions for this bug are the default configuration for production deployments, making it highly likely to affect new node operators.

## Recommendation

The `kv_finish()` method should only set metadata for data types that were actually indexed during the fast sync process. Since fast sync only indexes state keys, it should only set `StateVersion` metadata, not `TransactionVersion` or `EventVersion`.

Recommended fix:
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
            // Only set StateVersion metadata during fast sync
            // TransactionVersion and EventVersion should only be set by DBIndexer
            if internal_indexer_db.statekeys_enabled() {
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::StateVersion,
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

## Proof of Concept

This vulnerability can be verified by:
1. Starting a new node with fast sync enabled and default configuration (enable_storage_sharding=true, internal indexer enabled)
2. Allowing fast sync to complete to a snapshot version (e.g., version 1,000,000)
3. Querying for historical events at version 100,000 via the API
4. Observing that the query returns an empty array instead of an error or actual data
5. Verifying that `get_event_version()` returns 999,999 (snapshot_version - 1) even though no events were indexed

The issue manifests as silent data unavailability - queries succeed but return empty results for all historical data before the fast sync snapshot version.

## Notes

This is a data availability issue specific to nodes bootstrapped via fast sync. It does not affect:
- Consensus correctness
- Validator operation
- Fund security
- Nodes that bootstrap via normal state sync (which indexes all historical data)

The vulnerability represents a protocol violation where the storage layer makes false claims about data availability, causing API queries to silently return empty results instead of proper errors.

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L1259-1271)
```rust
        if self.internal_indexer_db.is_some()
            && self
                .internal_indexer_db
                .as_ref()
                .unwrap()
                .statekeys_enabled()
        {
            let keys = node_batch.keys().map(|key| key.0.clone()).collect();
            self.internal_indexer_db
                .as_ref()
                .unwrap()
                .write_keys_to_indexer_db(&keys, version, progress)?;
        }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1296-1307)
```rust
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
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L134-145)
```rust
            let num_transaction_outputs = output_with_proof.get_num_outputs();
            let num_transaction_infos = output_with_proof.proof.transaction_infos.len();
            ensure!(
                num_transaction_outputs == 1,
                "Number of transaction outputs should == 1, but got: {}",
                num_transaction_outputs
            );
            ensure!(
                num_transaction_infos == 1,
                "Number of transaction infos should == 1, but got: {}",
                num_transaction_infos
            );
```

**File:** storage/indexer/src/db_indexer.rs (L163-172)
```rust
    pub fn ensure_cover_ledger_version(&self, ledger_version: Version) -> Result<()> {
        let indexer_latest_version = self.get_persisted_version()?;
        if let Some(indexer_latest_version) = indexer_latest_version {
            if indexer_latest_version >= ledger_version {
                return Ok(());
            }
        }

        bail!("ledger version too new")
    }
```

**File:** storage/indexer/src/db_indexer.rs (L209-244)
```rust
    pub fn lookup_events_by_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        limit: u64,
        ledger_version: u64,
    ) -> Result<
        Vec<(
            u64,     // sequence number
            Version, // transaction version it belongs to
            u64,     // index among events for the same transaction
        )>,
    > {
        let mut iter = self.db.iter::<EventByKeySchema>()?;
        iter.seek(&(*event_key, start_seq_num))?;

        let mut result = Vec::new();
        let mut cur_seq = start_seq_num;
        for res in iter.take(limit as usize) {
            let ((path, seq), (ver, idx)) = res?;
            if path != *event_key || ver > ledger_version {
                break;
            }
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
            result.push((seq, ver, idx));
            cur_seq += 1;
        }

        Ok(result)
```

**File:** storage/indexer/src/db_indexer.rs (L410-500)
```rust
    pub fn process_a_batch(&self, start_version: Version, end_version: Version) -> Result<Version> {
        let _timer: aptos_metrics_core::HistogramTimer = TIMER.timer_with(&["process_a_batch"]);
        let mut version = start_version;
        let num_transactions = self.get_num_of_transactions(version, end_version)?;
        // This promises num_transactions should be readable from main db
        let mut db_iter = self.get_main_db_iter(version, num_transactions)?;
        let mut batch = SchemaBatch::new();
        let mut event_keys: HashSet<EventKey> = HashSet::new();
        db_iter.try_for_each(|res| {
            let (txn, events, writeset) = res?;
            if let Some(signed_txn) = txn.try_as_signed_user_txn() {
                if self.indexer_db.transaction_enabled() {
                    if let ReplayProtector::SequenceNumber(seq_num) = signed_txn.replay_protector()
                    {
                        batch.put::<OrderedTransactionByAccountSchema>(
                            &(signed_txn.sender(), seq_num),
                            &version,
                        )?;
                    }
                }
            }

            if self.indexer_db.event_enabled() {
                events.iter().enumerate().try_for_each(|(idx, event)| {
                    if let ContractEvent::V1(v1) = event {
                        batch
                            .put::<EventByKeySchema>(
                                &(*v1.key(), v1.sequence_number()),
                                &(version, idx as u64),
                            )
                            .expect("Failed to put events by key to a batch");
                        batch
                            .put::<EventByVersionSchema>(
                                &(*v1.key(), version, v1.sequence_number()),
                                &(idx as u64),
                            )
                            .expect("Failed to put events by version to a batch");
                    }
                    if self.indexer_db.event_v2_translation_enabled() {
                        if let ContractEvent::V2(v2) = event {
                            if let Some(translated_v1_event) =
                                self.translate_event_v2_to_v1(v2).map_err(|e| {
                                    anyhow::anyhow!(
                                        "Failed to translate event: {:?}. Error: {}",
                                        v2,
                                        e
                                    )
                                })?
                            {
                                let key = *translated_v1_event.key();
                                let sequence_number = translated_v1_event.sequence_number();
                                self.event_v2_translation_engine
                                    .cache_sequence_number(&key, sequence_number);
                                event_keys.insert(key);
                                batch
                                    .put::<EventByKeySchema>(
                                        &(key, sequence_number),
                                        &(version, idx as u64),
                                    )
                                    .expect("Failed to put events by key to a batch");
                                batch
                                    .put::<EventByVersionSchema>(
                                        &(key, version, sequence_number),
                                        &(idx as u64),
                                    )
                                    .expect("Failed to put events by version to a batch");
                                batch
                                    .put::<TranslatedV1EventSchema>(
                                        &(version, idx as u64),
                                        &translated_v1_event,
                                    )
                                    .expect("Failed to put translated v1 events to a batch");
                            }
                        }
                    }
                    Ok::<(), AptosDbError>(())
                })?;
            }

            if self.indexer_db.statekeys_enabled() {
                writeset.write_op_iter().for_each(|(state_key, write_op)| {
                    if write_op.is_creation() || write_op.is_modification() {
                        batch
                            .put::<StateKeysSchema>(state_key, &())
                            .expect("Failed to put state keys to a batch");
                    }
                });
            }
            version += 1;
            Ok::<(), AptosDbError>(())
        })?;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L102-106)
```rust
        let start_version = self
            .db_indexer
            .indexer_db
            .get_persisted_version()?
            .map_or(0, |v| v + 1);
```

**File:** api/src/context.rs (L1096-1104)
```rust
        let mut res = if !db_sharding_enabled(&self.node_config) {
            self.db
                .get_events(event_key, start, order, limit as u64, ledger_version)?
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| anyhow!("Internal indexer reader doesn't exist"))?
                .get_events(event_key, start, order, limit as u64, ledger_version)?
        };
```

**File:** api/src/context.rs (L1771-1772)
```rust
fn db_sharding_enabled(node_config: &NodeConfig) -> bool {
    node_config.storage.rocksdb_configs.enable_storage_sharding
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L129-135)
```rust
    pub fn finish(self) -> Result<()> {
        let progress = self.db.get_progress(self.version)?;
        self.db.kv_finish(
            self.version,
            progress.map_or(StateStorageUsage::zero(), |p| p.usage),
        )
    }
```

**File:** storage/aptosdb/src/state_restore/mod.rs (L260-273)
```rust
    fn finish(self) -> Result<()> {
        match self.restore_mode {
            StateSnapshotRestoreMode::KvOnly => self.kv_restore.lock().take().unwrap().finish()?,
            StateSnapshotRestoreMode::TreeOnly => {
                self.tree_restore.lock().take().unwrap().finish_impl()?
            },
            StateSnapshotRestoreMode::Default => {
                // for tree only mode, we also need to write the usage to DB
                self.kv_restore.lock().take().unwrap().finish()?;
                self.tree_restore.lock().take().unwrap().finish_impl()?
            },
        }
        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L1123-1128)
```rust
    state_snapshot_receiver.finish_box().map_err(|error| {
        format!(
            "Failed to finish the state value synchronization! Error: {:?}",
            error
        )
    })?;
```

**File:** config/src/config/storage_config.rs (L233-233)
```rust
            enable_storage_sharding: true,
```
