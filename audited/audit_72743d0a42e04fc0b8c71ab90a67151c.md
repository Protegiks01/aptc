# Audit Report

## Title
Indexer Metadata Inconsistency After Fast Sync Causes Silent Data Loss in Historical Queries

## Summary
During fast sync state snapshot restoration, the `StateStore::kv_finish()` method incorrectly sets internal indexer metadata (`TransactionVersion` and `EventVersion`) to `snapshot_version - 1`, falsely claiming that transactions and events have been indexed. However, fast sync intentionally skips historical transaction/event data, leaving these indices empty. This causes API queries to pass metadata validation but return empty results, resulting in silent data loss.

## Finding Description

The vulnerability exists in the interaction between fast sync state snapshot restoration and internal indexer metadata management.

**Root Cause:**

During fast sync, `StateStore::kv_finish()` unconditionally sets indexer metadata for all data types, including transactions and events that were never actually indexed: [1](#0-0) 

The method sets `TransactionVersion` and `EventVersion` to `version - 1` whenever the internal indexer is enabled, regardless of whether any transactions or events were actually indexed during the fast sync process.

**Why This Is Wrong:**

Fast sync only saves ONE checkpoint transaction at the snapshot version, not the historical transactions: [2](#0-1) 

The code explicitly enforces that only one transaction is saved during `finalize_state_snapshot`.

**State Keys vs Transactions/Events:**

While state keys ARE correctly indexed during fast sync via `write_kv_batch`: [3](#0-2) 

Transactions and events are indexed separately by `DBIndexer.process_a_batch()` which reads from the main database: [4](#0-3) 

**The Consequence:**

When the `DBIndexer` starts after fast sync, it reads the incorrect metadata and believes it has already indexed all historical data: [5](#0-4) 

The indexer starts from `persisted_version + 1`, skipping all historical versions that were never actually indexed.

**API Query Failure:**

When queries route through the internal indexer (default behavior with `db_sharding_enabled` set to true): [6](#0-5) 

The query path calls `ensure_cover_ledger_version()` which checks the incorrect metadata: [7](#0-6) 

This check passes because the metadata falsely claims coverage. Then `lookup_events_by_key()` is called: [8](#0-7) 

The iterator finds no entries (because nothing was indexed) and returns an empty vector, causing silent data loss instead of a proper error.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program's "API Crashes" / "Significant protocol violations" category:

1. **API Misbehavior**: API nodes using fast sync serve incorrect (empty) results for all historical transaction and event queries in the range [0, snapshot_version-1]. Applications depending on this data will malfunction.

2. **Silent Data Loss**: The system returns empty results instead of proper "data not available" errors, making the issue extremely difficult to detect and debug.

3. **Widespread Impact**: Affects all nodes that:
   - Use fast sync for bootstrapping (standard practice for new validators and API nodes)
   - Have internal indexer enabled (default configuration)
   - Have `enable_storage_sharding` set to true (default per configuration)
   - Serve historical query requests

4. **Protocol Violation**: The indexer metadata provides false guarantees about data availability, violating the fundamental contract between storage and query layers.

5. **Permanent Inconsistency**: Once fast sync completes, there's no automatic recovery mechanism. The metadata inconsistency persists indefinitely.

## Likelihood Explanation

**Likelihood: HIGH**

This bug triggers deterministically whenever:
- A node uses fast sync mode (standard for new node deployments)
- The internal indexer is enabled (default configuration)
- Storage sharding is enabled (default value is `true`)
- Any historical queries are made through the API

No malicious actor is required - this is a systematic integration bug between fast sync and the internal indexer. The conditions for this bug are the default configuration for production deployments, making it highly likely to affect new node operators.

## Recommendation

**Fix the `kv_finish` method to only set metadata for data types that were actually indexed during fast sync:**

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
            // Only set StateVersion - state keys ARE indexed during fast sync
            if internal_indexer_db.statekeys_enabled() {
                batch.put::<InternalIndexerMetadataSchema>(
                    &MetadataKey::StateVersion,
                    &MetadataValue::Version(version - 1),
                )?;
            }
            // DO NOT set TransactionVersion or EventVersion here
            // They should only be set by DBIndexer.process_a_batch()
            internal_indexer_db
                .get_inner_db_ref()
                .write_schemas(batch)?;
        }
    }
    Ok(())
}
```

Alternatively, introduce a parameter to distinguish between full indexing and fast sync scenarios.

## Proof of Concept

This vulnerability can be demonstrated by:

1. Setting up a node with fast sync enabled, internal indexer enabled, and `enable_storage_sharding: true`
2. Performing fast sync to a recent epoch (e.g., version 1,000,000)
3. Querying the indexer metadata - it will show `TransactionVersion: 999,999` and `EventVersion: 999,999`
4. Attempting to query events at a historical version (e.g., 500,000) via the API
5. Observing that the query returns an empty result instead of an error, despite the metadata claiming the data is indexed
6. Verifying that the `EventByKeySchema` table in the internal indexer DB is empty for versions [0, 999,999]

This demonstrates the metadata inconsistency and resulting silent data loss in production scenarios.

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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L125-145)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
    ) -> Result<()> {
        let (output_with_proof, persisted_aux_info) = output_with_proof.into_parts();
        gauged_api("finalize_state_snapshot", || {
            // Ensure the output with proof only contains a single transaction output and info
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

**File:** storage/indexer/src/db_indexer.rs (L209-245)
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
    }
```

**File:** storage/indexer/src/db_indexer.rs (L410-530)
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
        assert!(version > 0, "batch number should be greater than 0");

        assert_eq!(num_transactions, version - start_version);

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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L88-164)
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
