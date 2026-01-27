# Audit Report

## Title
Missing Event Index Check in `get_last_version_before_timestamp` Causes API Failure with Storage Sharding Enabled

## Summary
When `skip_index_and_usage=true` (enabled by default via `enable_storage_sharding=true`), event indices are not created during transaction commits. However, the `get_last_version_before_timestamp` API unconditionally depends on these indices, causing it to fail with NotFound errors on all sharded nodes. [1](#0-0) 

## Finding Description

The `skip_index_and_usage` flag is set based on `rocksdb_configs.enable_storage_sharding`, which defaults to `true`: [2](#0-1) [3](#0-2) 

When this flag is enabled, the system skips creating event indices (`EventByKeySchema`, `EventByVersionSchema`, `EventAccumulatorSchema`) during event commits: [4](#0-3) 

Block info queries were correctly updated with a fallback mechanism that checks the flag and uses alternative storage paths: [5](#0-4) 

However, `get_last_version_before_timestamp` has **no such fallback** and always attempts to use the event store indices: [6](#0-5) 

The underlying implementation depends on event indices that don't exist when sharding is enabled: [7](#0-6) 

This causes the API to fail because:
1. `get_latest_sequence_number` cannot find event sequences in `EventByVersionSchema`
2. `lookup_event_by_key` cannot find events in `EventByKeySchema`
3. The method returns `AptosDbError::NotFound` instead of the expected version

## Impact Explanation

**High Severity** per Aptos bug bounty criteria - "API crashes":

1. **Deterministic API Failure**: Any call to `get_last_version_before_timestamp` on nodes with storage sharding (default configuration) will fail with NotFound errors
2. **Public Interface Contract Violation**: The `DbReader` trait is a public interface exposed to external consumers
3. **Operational Impact**: External tools, monitoring systems, or future features depending on timestamp-based version lookups will be completely broken
4. **No Consensus Impact**: While this doesn't affect consensus safety or validator operations directly, it breaks the storage interface guarantees

This does not reach Critical severity because:
- No loss of funds or consensus safety violations
- Not currently used in critical state sync or consensus paths
- Node operation continues normally for other APIs

## Likelihood Explanation

**HIGH** - This occurs with 100% probability under the following conditions:
1. Node is configured with `enable_storage_sharding=true` (the **default** setting)
2. Any external caller invokes `get_last_version_before_timestamp` through the `DbReader` interface
3. No workaround exists as the indices simply don't exist in the database

The vulnerability is deterministic and affects all production nodes using the default configuration.

## Recommendation

Add a flag check and implement a fallback mechanism similar to block info queries. The fix should:

1. Check `self.skip_index_and_usage` before calling event store methods
2. Implement an alternative timestamp lookup using `BlockInfoSchema` and `BlockByVersionSchema` when indices are skipped
3. Leverage the direct block metadata that is written when `skip_index_and_usage=true`: [8](#0-7) 

**Proposed Fix Pattern** (similar to existing block info fallback):
```rust
fn get_last_version_before_timestamp(
    &self,
    timestamp: u64,
    ledger_version: Version,
) -> Result<Version> {
    gauged_api("get_last_version_before_timestamp", || {
        if !self.skip_index_and_usage {
            // Original path using event store
            self.event_store.get_last_version_before_timestamp(timestamp, ledger_version)
        } else {
            // Fallback path using block info metadata
            self.get_version_by_timestamp_from_block_metadata(timestamp, ledger_version)
        }
    })
}
```

## Proof of Concept

```rust
// Reproduction steps:
// 1. Initialize AptosDB with storage sharding enabled (default)
let db = AptosDB::open(
    db_paths,
    false, // readonly
    PrunerConfig::default(),
    RocksdbConfigs {
        enable_storage_sharding: true,  // This is the default
        ..Default::default()
    },
    false, // enable_indexer
    1000,  // buffered_state_target_items
    1000,  // max_num_nodes_per_lru_cache_shard
    None,  // internal_indexer_db
    HotStateConfig::default(),
)?;

// 2. Commit some transactions with timestamps
// (transactions committed normally)

// 3. Attempt to query by timestamp
let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
let ledger_version = db.get_latest_version()?;

// This will FAIL with NotFound error because event indices don't exist
let result = db.get_last_version_before_timestamp(current_time, ledger_version);
assert!(result.is_err());
assert!(matches!(result.unwrap_err(), AptosDbError::NotFound(_)));
```

The vulnerability is confirmed through code analysis showing that event indices are never created when `skip_index_and_usage=true`, while `get_last_version_before_timestamp` unconditionally requires them.

## Notes

While this API is currently only used in test mocks and not in critical production paths, it represents a significant contract violation in the public `DbReader` interface. The default configuration breaks a documented API, which could cause failures in external integrations, monitoring tools, or future features that rely on timestamp-based queries. The issue should be addressed to maintain API contract guarantees even if current usage is limited.

### Citations

**File:** storage/aptosdb/src/db/mod.rs (L39-39)
```rust
    skip_index_and_usage: bool,
```

**File:** config/src/config/storage_config.rs (L202-203)
```rust
    #[serde(default = "default_to_true")]
    pub enable_storage_sharding: bool,
```

**File:** config/src/config/storage_config.rs (L233-233)
```rust
            enable_storage_sharding: true,
```

**File:** storage/aptosdb/src/ledger_db/event_db.rs (L145-188)
```rust
    pub(crate) fn put_events(
        &self,
        version: u64,
        events: &[ContractEvent],
        skip_index: bool,
        batch: &mut impl WriteBatch,
    ) -> Result<()> {
        // Event table and indices updates
        events
            .iter()
            .enumerate()
            .try_for_each::<_, Result<_>>(|(idx, event)| {
                if let ContractEvent::V1(v1) = event {
                    if !skip_index {
                        batch.put::<EventByKeySchema>(
                            &(*v1.key(), v1.sequence_number()),
                            &(version, idx as u64),
                        )?;
                        batch.put::<EventByVersionSchema>(
                            &(*v1.key(), version, v1.sequence_number()),
                            &(idx as u64),
                        )?;
                    }
                }
                batch.put::<EventSchema>(&(version, idx as u64), event)
            })?;

        if !skip_index {
            // EventAccumulatorSchema updates
            let event_hashes: Vec<HashValue> = events.iter().map(ContractEvent::hash).collect();
            let (_root_hash, writes) =
                MerkleAccumulator::<EmptyReader, EventAccumulatorHasher>::append(
                    &EmptyReader,
                    0,
                    &event_hashes,
                )?;

            writes.into_iter().try_for_each(|(pos, hash)| {
                batch.put::<EventAccumulatorSchema>(&(version, pos), &hash)
            })?;
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L317-337)
```rust
    pub(super) fn get_raw_block_info_by_height(&self, block_height: u64) -> Result<BlockInfo> {
        if !self.skip_index_and_usage {
            let (first_version, new_block_event) = self.event_store.get_event_by_key(
                &new_block_event_key(),
                block_height,
                self.ensure_synced_version()?,
            )?;
            let new_block_event = bcs::from_bytes(new_block_event.event_data())?;
            Ok(BlockInfo::from_new_block_event(
                first_version,
                &new_block_event,
            ))
        } else {
            Ok(self
                .ledger_db
                .metadata_db()
                .get_block_info(block_height)?
                .ok_or_else(|| {
                    AptosDbError::NotFound(format!("BlockInfo not found at height {block_height}"))
                })?)
        }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L801-810)
```rust
    fn get_last_version_before_timestamp(
        &self,
        timestamp: u64,
        ledger_version: Version,
    ) -> Result<Version> {
        gauged_api("get_last_version_before_timestamp", || {
            self.event_store
                .get_last_version_before_timestamp(timestamp, ledger_version)
        })
    }
```

**File:** storage/aptosdb/src/event_store/mod.rs (L287-317)
```rust
    pub(crate) fn get_last_version_before_timestamp(
        &self,
        timestamp: u64,
        ledger_version: Version,
    ) -> Result<Version> {
        let event_key = new_block_event_key();
        let seq_at_or_after_ts = self.search_for_event_lower_bound(
            &event_key,
            |event| {
                let new_block_event: NewBlockEvent = event.try_into()?;
                Ok(new_block_event.proposed_time() < timestamp)
            },
            ledger_version,
        )?.ok_or_else(|| AptosDbError::NotFound(
            format!("No new block found beyond timestamp {}, so can't determine the last version before it.",
            timestamp,
        )))?;

        ensure!(
            seq_at_or_after_ts > 0,
            "First block started at or after timestamp {}.",
            timestamp,
        );

        let (version, _idx) =
            self.lookup_event_by_key(&event_key, seq_at_or_after_ts, ledger_version)?;

        version.checked_sub(1).ok_or_else(|| {
            AptosDbError::Other("A block with non-zero seq num started at version 0.".to_string())
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L342-358)
```rust
        // Write block index if event index is skipped.
        if skip_index_and_usage {
            for (i, txn_out) in chunk.transaction_outputs.iter().enumerate() {
                for event in txn_out.events() {
                    if let Some(event_key) = event.event_key() {
                        if *event_key == new_block_event_key() {
                            let version = chunk.first_version + i as Version;
                            LedgerMetadataDb::put_block_info(
                                version,
                                event,
                                &mut ledger_metadata_batch,
                            )?;
                        }
                    }
                }
            }
        }
```
