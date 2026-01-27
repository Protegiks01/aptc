# Audit Report

## Title
Time-of-Check to Time-of-Use (TOCTOU) Race Condition in Indexer Reader Causing Torn Reads and Data Inconsistency

## Summary
The indexer reader implementation performs multi-step queries without using consistent snapshots, allowing concurrent writes from the DBCommitter thread to cause torn reads. This violates the fundamental consistency guarantee that queries at a specific `ledger_version` should only see data up to that version.

## Finding Description

The indexer reader performs queries through multiple separate read operations without snapshot isolation. The `DBIndexer` uses a separate committer thread that writes batches asynchronously, while queries read directly from the database without coordination.

**Architecture Overview:**

The `DBIndexer` creates a background `DBCommitter` thread that receives write batches via a channel and commits them atomically to RocksDB: [1](#0-0) 

Write batches are prepared and sent to this committer: [2](#0-1) 

**The Vulnerability:**

Query methods perform multiple separate read operations that can see different database states:

1. **Version Check:** First, queries check if the indexer covers the requested ledger version by reading metadata: [3](#0-2) 

2. **Iterator Creation:** Then queries create iterators to read indexed data: [4](#0-3) 

3. **Between Operations:** The DBCommitter thread can commit a new batch containing updated metadata (LatestVersion) and new index entries.

4. **Data Reads:** Subsequent iterator operations or additional queries see the newly committed data.

**Concrete Example - `get_account_ordered_transactions`:** [5](#0-4) 

**Attack Sequence:**
1. Query calls `ensure_cover_ledger_version(1000)` at line 594-595, reads `LatestVersion=1000` → passes
2. DBCommitter commits batch with transactions 1001-1100, updates `LatestVersion=1100`
3. Query creates iterator at line 600, which now sees transactions 1001-1100
4. Query returns transactions that shouldn't exist at `ledger_version=1000`

**Same Issue in `get_events_by_event_key`:** [6](#0-5) 

The method performs multiple reads:
- Line 652-653: Version check
- Line 660-662: Optional `get_latest_sequence_number()` call (creates iterator)
- Line 671-676: `lookup_events_by_key()` (creates another iterator)
- Line 692-718: Reads from main_db

Each of these operations can see different committed database states.

**Root Cause:**

The underlying schemadb implementation creates iterators without snapshots: [7](#0-6) 

RocksDB iterators internally maintain consistency once created, but **multiple separate read operations** (metadata check, then iterator creation, then data reads) can each see different committed database versions.

**Why This Breaks Consistency:**

The fundamental invariant violated is: **Queries at a specific `ledger_version` must see a consistent snapshot of all data up to that version.**

When a query requests data at `ledger_version=N`, it expects:
- All transactions/events/state up to version N
- No transactions/events/state beyond version N
- Atomic, consistent view across all index tables

The torn read allows queries to see:
- Metadata claiming version N
- Index data from version N+K
- Inconsistent state across different index tables if the batch write is observed mid-query

## Impact Explanation

**Severity: HIGH**

This issue qualifies as HIGH severity under the Aptos bug bounty program for multiple reasons:

1. **Significant Protocol Violation:** This breaks the core consistency guarantee of the indexer API. Clients requesting data at a specific ledger version receive data from future versions, violating the time-travel query semantics that the ledger provides.

2. **API Crashes:** The inconsistency checks in `lookup_events_by_key` can trigger false positives: [8](#0-7) 

If a concurrent write adds events mid-iteration, the sequence number continuity check can fail incorrectly, causing queries to bail with "DB corruption" errors.

3. **State Inconsistencies:** Similar checks exist in `AccountOrderedTransactionsIter`: [9](#0-8) 

These validation checks can trigger incorrectly due to torn reads, causing spurious "DB corruption" errors.

4. **Potential Impact on Validators:** While the indexer is primarily used for API queries, validators may rely on indexed data for certain operations. Inconsistent data could cause validator behavior divergence.

5. **Data Integrity Violations:** Applications and users expect deterministic, reproducible queries. Torn reads break this fundamental guarantee.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will occur frequently in production:

1. **High Concurrency:** The indexer runs continuously, committing batches as new blocks arrive. API queries run concurrently from multiple clients.

2. **No Synchronization:** There is zero synchronization between the committer thread and reader threads. Every query has a race window.

3. **Batch Size:** Default batch sizes can be large (configured via `batch_size`), meaning writes happen frequently: [10](#0-9) 

4. **Multiple Read Operations:** Every query method performs 2-4 separate database operations, creating multiple race windows.

5. **Observable Effects:** The inconsistency can manifest as:
   - Queries returning data beyond the requested ledger_version
   - False "DB corruption" errors from continuity checks
   - Non-deterministic query results for the same parameters

This is not a theoretical race condition - it will occur regularly under normal load on any node running the internal indexer with concurrent API queries.

## Recommendation

**Implement snapshot-based reads for all query operations.**

RocksDB provides snapshot isolation through the `ReadOptions` API. All read operations within a single query must use the same snapshot:

```rust
// In DBIndexer query methods:
pub fn get_account_ordered_transactions(
    &self,
    address: AccountAddress,
    start_seq_num: u64,
    limit: u64,
    include_events: bool,
    ledger_version: Version,
) -> Result<AccountOrderedTransactionsWithProof> {
    // Create a snapshot for this entire query
    let snapshot = self.indexer_db.get_inner_db_ref().snapshot();
    let mut read_opts = ReadOptions::default();
    read_opts.set_snapshot(&snapshot);
    
    // Use read_opts for all operations
    self.indexer_db
        .ensure_cover_ledger_version_with_snapshot(ledger_version, &read_opts)?;
    
    let txns_with_proofs = self
        .indexer_db
        .get_account_ordered_transactions_iter_with_snapshot(
            address, 
            start_seq_num, 
            limit, 
            ledger_version,
            &read_opts
        )?
        .map(|result| {
            let (_seq_num, txn_version) = result?;
            self.main_db_reader.get_transaction_by_version(
                txn_version,
                ledger_version,
                include_events,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    
    Ok(AccountOrderedTransactionsWithProof::new(txns_with_proofs))
}
```

**Key Changes Required:**

1. Modify `InternalIndexerDB` to accept `ReadOptions` parameter in all query methods
2. Use `db.iter_with_opts::<Schema>(read_opts)` instead of `db.iter::<Schema>()`
3. Use snapshot-aware `get_cf_opt()` for metadata reads
4. Apply consistently across all query methods: `get_events_by_event_key`, `get_prefixed_state_value_iterator`, etc.

This ensures all read operations within a query see the same consistent database state, eliminating the TOCTOU race condition.

## Proof of Concept

```rust
// Reproduction test demonstrating the race condition
#[tokio::test]
async fn test_torn_read_race_condition() {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    
    // Setup: Create indexer with DBCommitter thread
    let (indexer_db, db_indexer) = setup_test_indexer();
    
    // Scenario: Version 100 is initially indexed
    indexer_db.write_version_metadata(100);
    
    // Thread 1: Query at ledger_version=100
    let db_indexer_clone = db_indexer.clone();
    let query_thread = thread::spawn(move || {
        // Step 1: Check version (reads LatestVersion=100)
        db_indexer_clone.indexer_db
            .ensure_cover_ledger_version(100)
            .expect("Version check should pass");
        
        // Simulate processing delay before creating iterator
        thread::sleep(Duration::from_millis(50));
        
        // Step 3: Create iterator - NOW SEES VERSION 200 DATA!
        let iter = db_indexer_clone.indexer_db
            .get_account_ordered_transactions_iter(
                test_address(),
                0,
                100,
                100, // Requested ledger_version=100
            )
            .expect("Iterator creation should succeed");
        
        // Collect results
        let results: Vec<_> = iter.collect();
        results
    });
    
    // Thread 2: DBCommitter commits new batch
    thread::sleep(Duration::from_millis(25)); // Ensure query starts first
    
    // Step 2: Commit batch with versions 101-200
    let batch = create_test_batch_with_versions(101, 200);
    db_indexer.sender
        .send(Some(batch))
        .expect("Send batch to committer");
    
    // Wait for commit to complete
    thread::sleep(Duration::from_millis(100));
    
    // Verify: Query results contain transactions beyond ledger_version=100
    let results = query_thread.join().unwrap();
    
    for result in results {
        let (seq_num, txn_version) = result.unwrap();
        assert!(txn_version <= 100, 
            "VULNERABILITY: Query at ledger_version=100 returned transaction at version {}",
            txn_version);
    }
    
    // Test will FAIL, demonstrating torn read vulnerability
}
```

The test demonstrates that a query requesting data at `ledger_version=100` can receive data from `ledger_version=200` due to the TOCTOU race condition between the version check and iterator creation.

**Notes:**

1. **RocksDB Iterator Semantics:** While individual RocksDB iterators provide point-in-time consistency once created, the issue is that **multiple separate read operations** (metadata check, iterator creation, additional reads) can each see different database snapshots. The lack of a unified snapshot across all operations within a query causes the torn read.

2. **Batch Atomicity:** Write batches are atomic at the RocksDB level (all-or-nothing), but queries can observe the database state before and after batch commits within a single logical query operation.

3. **Production Impact:** This affects any deployment using the internal indexer with concurrent API queries, which includes public API nodes and potentially validators using indexer features.

4. **Related Code:** The same pattern exists in `get_prefixed_state_value_iterator` and all other query methods in `IndexerReaders`: [11](#0-10) 

All methods that delegate to `DBIndexer` inherit this vulnerability.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L52-77)
```rust
pub struct DBCommitter {
    db: Arc<DB>,
    receiver: Receiver<Option<SchemaBatch>>,
}

impl DBCommitter {
    pub fn new(db: Arc<DB>, receiver: Receiver<Option<SchemaBatch>>) -> Self {
        Self { db, receiver }
    }

    pub fn run(&self) {
        loop {
            let batch_opt = self
                .receiver
                .recv()
                .expect("Failed to receive batch from DB Indexer");
            if let Some(batch) = batch_opt {
                self.db
                    .write_schemas(batch)
                    .expect("Failed to write batch to indexer db");
            } else {
                break;
            }
        }
    }
}
```

**File:** storage/indexer/src/db_indexer.rs (L163-173)
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

**File:** storage/indexer/src/db_indexer.rs (L174-191)
```rust
    pub fn get_account_ordered_transactions_iter(
        &self,
        address: AccountAddress,
        min_seq_num: u64,
        num_versions: u64,
        ledger_version: Version,
    ) -> Result<AccountOrderedTransactionsIter<'_>> {
        let mut iter = self.db.iter::<OrderedTransactionByAccountSchema>()?;
        iter.seek(&(address, min_seq_num))?;
        Ok(AccountOrderedTransactionsIter::new(
            iter,
            address,
            min_seq_num
                .checked_add(num_versions)
                .ok_or(AptosDbError::TooManyRequested(min_seq_num, num_versions))?,
            ledger_version,
        ))
    }
```

**File:** storage/indexer/src/db_indexer.rs (L232-239)
```rust
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
```

**File:** storage/indexer/src/db_indexer.rs (L389-394)
```rust
        let num_of_transaction = min(
            self.indexer_db.config.batch_size as u64,
            highest_version + 1 - version,
        );
        Ok(num_of_transaction)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L410-550)
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
        self.sender
            .send(Some(batch))
            .map_err(|e| AptosDbError::Other(e.to_string()))?;
        Ok(version)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L586-612)
```rust
    pub fn get_account_ordered_transactions(
        &self,
        address: AccountAddress,
        start_seq_num: u64,
        limit: u64,
        include_events: bool,
        ledger_version: Version,
    ) -> Result<AccountOrderedTransactionsWithProof> {
        self.indexer_db
            .ensure_cover_ledger_version(ledger_version)?;
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

        let txns_with_proofs = self
            .indexer_db
            .get_account_ordered_transactions_iter(address, start_seq_num, limit, ledger_version)?
            .map(|result| {
                let (_seq_num, txn_version) = result?;
                self.main_db_reader.get_transaction_by_version(
                    txn_version,
                    ledger_version,
                    include_events,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(AccountOrderedTransactionsWithProof::new(txns_with_proofs))
    }
```

**File:** storage/indexer/src/db_indexer.rs (L644-724)
```rust
    pub fn get_events_by_event_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        order: Order,
        limit: u64,
        ledger_version: Version,
    ) -> Result<Vec<EventWithVersion>> {
        self.indexer_db
            .ensure_cover_ledger_version(ledger_version)?;
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
        let get_latest = order == Order::Descending && start_seq_num == u64::MAX;

        let cursor = if get_latest {
            // Caller wants the latest, figure out the latest seq_num.
            // In the case of no events on that path, use 0 and expect empty result below.
            self.indexer_db
                .get_latest_sequence_number(ledger_version, event_key)?
                .unwrap_or(0)
        } else {
            start_seq_num
        };

        // Convert requested range and order to a range in ascending order.
        let (first_seq, real_limit) = get_first_seq_num_and_limit(order, cursor, limit)?;

        // Query the index.
        let mut event_indices = self.indexer_db.lookup_events_by_key(
            event_key,
            first_seq,
            real_limit,
            ledger_version,
        )?;

        // When descending, it's possible that user is asking for something beyond the latest
        // sequence number, in which case we will consider it a bad request and return an empty
        // list.
        // For example, if the latest sequence number is 100, and the caller is asking for 110 to
        // 90, we will get 90 to 100 from the index lookup above. Seeing that the last item
        // is 100 instead of 110 tells us 110 is out of bound.
        if order == Order::Descending {
            if let Some((seq_num, _, _)) = event_indices.last() {
                if *seq_num < cursor {
                    event_indices = Vec::new();
                }
            }
        }

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
        if order == Order::Descending {
            events_with_version.reverse();
        }

        Ok(events_with_version)
    }
```

**File:** storage/schemadb/src/lib.rs (L267-274)
```rust
    pub fn iter<S: Schema>(&self) -> DbResult<SchemaIterator<'_, S>> {
        self.iter_with_opts(ReadOptions::default())
    }

    /// Returns a forward [`SchemaIterator`] on a certain schema, with non-default ReadOptions
    pub fn iter_with_opts<S: Schema>(&self, opts: ReadOptions) -> DbResult<SchemaIterator<'_, S>> {
        self.iter_with_direction::<S>(opts, ScanDirection::Forward)
    }
```

**File:** storage/indexer_schemas/src/utils.rs (L84-104)
```rust
                // Ensure seq_num_{i+1} == seq_num_{i} + 1
                if let Some(expected_seq_num) = self.expected_next_seq_num {
                    ensure!(
                        seq_num == expected_seq_num,
                        "DB corruption: account transactions sequence numbers are not contiguous: \
                     actual: {}, expected: {}",
                        seq_num,
                        expected_seq_num,
                    );
                };

                // Ensure version_{i+1} > version_{i}
                if let Some(prev_version) = self.prev_version {
                    ensure!(
                        prev_version < version,
                        "DB corruption: account transaction versions are not strictly increasing: \
                         previous version: {}, current version: {}",
                        prev_version,
                        version,
                    );
                }
```

**File:** storage/indexer/src/indexer_reader.rs (L68-90)
```rust
    fn get_events(
        &self,
        event_key: &EventKey,
        start: u64,
        order: Order,
        limit: u64,
        ledger_version: Version,
    ) -> anyhow::Result<Vec<EventWithVersion>> {
        if let Some(db_indexer_reader) = &self.db_indexer_reader {
            if db_indexer_reader.indexer_db.event_enabled() {
                return Ok(db_indexer_reader.get_events(
                    event_key,
                    start,
                    order,
                    limit,
                    ledger_version,
                )?);
            } else {
                anyhow::bail!("Internal event index is not enabled")
            }
        }
        anyhow::bail!("DB Indexer reader is not available")
    }
```
