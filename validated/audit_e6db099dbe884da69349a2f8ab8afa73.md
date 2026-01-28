# Audit Report

## Title
Indexer Permanent Desynchronization After Partial Commit Failure

## Summary
The storage layer commits ledger metadata to disk before updating the indexer, creating a non-atomic operation. If the indexer write fails after the ledger commit succeeds, the system enters an unrecoverable desynchronized state where the indexer permanently lags behind the ledger. This causes version mismatch errors preventing further commits and may result in node liveness failure if the underlying storage issue persists across restarts.

## Finding Description
The vulnerability exists in the commit sequence where ledger and indexer updates are not atomic. The `commit_ledger` function first writes `OverallCommitProgress` to the ledger database and flushes it to disk [1](#0-0) , then calls `post_commit` to update the indexer [2](#0-1) .

Within `post_commit`, the indexer is conditionally invoked only if the version has advanced [3](#0-2) . The indexer performs its database write [4](#0-3) , and only upon success updates its in-memory `next_version` [5](#0-4) .

If the indexer write fails at line 144, the ledger database has already committed version N, but the indexer database remains at version N-1. This creates three unrecoverable scenarios:

**Recovery Scenario 1 - Retry same version N**: The `old_committed_version` returns N since it's already committed [6](#0-5) . The condition `N > N` evaluates to FALSE, causing the entire indexer update block (lines 612-658) to be skipped. The indexer remains stuck at version N-1.

**Recovery Scenario 2 - Commit next version N+1**: When attempting to commit N+1, `first_version` is set to N+1 [7](#0-6) . The indexer's `next_version` is still N, so the continuity check fails [8](#0-7)  with error "Indexer expects to see continuous transaction versions."

**Recovery Scenario 3 - Node restart**: On restart, the catch-up mechanism attempts to reindex missing versions [9](#0-8) . If the underlying failure is persistent (disk space exhaustion, database corruption), the indexer write fails again at line 224, preventing the node from starting.

This breaks the storage invariant that all database components (ledger DB, indexer DB, in-memory state) maintain synchronization. The indexer is an optional but important component for API functionality when enabled [10](#0-9) .

## Impact Explanation
This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program based on:

1. **State inconsistencies requiring manual intervention**: The indexer database becomes permanently desynchronized from the ledger database, requiring manual database repair or selective restoration to recover. This aligns with the Medium Severity category of "State inconsistencies requiring manual intervention."

2. **Potential liveness failure**: If the underlying cause persists (permanent disk corruption, insufficient space), the node cannot restart successfully, removing it from network participation until operator intervention. This represents a "Temporary liveness issue" as categorized under Medium Severity.

3. **No automatic recovery mechanism**: The system lacks self-healing capabilities for this failure mode. Neither transaction retry nor node restart resolves the desynchronization without manual intervention.

The vulnerability only affects nodes with `enable_indexer` enabled, but for those nodes, it creates operational disruption requiring manual database recovery procedures.

## Likelihood Explanation
**Moderate likelihood** - This vulnerability can be triggered through realistic operational scenarios:

1. **Disk space exhaustion**: The indexer database may fill remaining space while the ledger database write succeeds (different RocksDB instances with separate space tracking)

2. **Selective database corruption**: RocksDB corruption affecting only the indexer database instance while the ledger database remains healthy

3. **I/O errors**: Storage subsystem errors that manifest during the indexer write phase but not during the ledger commit phase

4. **File system permission changes**: Runtime permission modifications that prevent indexer writes after ledger writes complete

5. **Hardware failures**: Partial disk failures affecting specific data partitions

These scenarios do not require attacker action and can occur during normal continuous node operation. The high write volume characteristic of blockchain nodes increases the probability of encountering storage-related failures over time. The vulnerability's triggering is deterministic once a storage failure occurs at the specific timing window between ledger commit and indexer update.

## Recommendation
Implement one of the following solutions:

**Option 1 - Atomic Transaction**: Wrap both ledger and indexer updates in a single atomic transaction using a transaction-capable storage backend, ensuring both succeed or both fail together.

**Option 2 - Write-Ahead Log**: Implement a write-ahead log for indexer operations that can be replayed on recovery, similar to database transaction logs.

**Option 3 - Best-Effort Indexer**: Make indexer failures non-fatal by catching errors at the post_commit level and logging them for later reconciliation, preventing commit failures due to indexer issues:

```rust
// In post_commit function, around line 636
if let Some(indexer) = &self.indexer {
    if let Err(e) = indexer.index(...) {
        warn!("Indexer update failed: {:?}. Will attempt recovery on next commit.", e);
        // Log failed version for later recovery
        self.log_indexer_failure(version);
        // Don't propagate error - allow commit to succeed
    }
}
```

**Option 4 - Retry with Recovery**: Add automatic retry logic with exponential backoff and a recovery mechanism that can detect and repair version gaps during normal operation.

## Proof of Concept
While a complete PoC would require simulating storage failures in a test environment, the vulnerability can be demonstrated by:

1. Instrumenting the indexer's `write_schemas` call to inject a failure after the ledger commit succeeds
2. Observing that retry attempts skip the indexer update
3. Observing that subsequent commits fail with version mismatch errors
4. Verifying that node restart with persistent failure prevents startup

A minimal reproduction would involve modifying the test suite to inject controlled failures at line 144 of `storage/indexer/src/lib.rs` and verifying the described recovery scenarios fail as predicted.

## Notes

**Critical Observation**: This vulnerability demonstrates a fundamental atomicity issue in the storage layer's commit protocol. The ledger metadata is durably committed before dependent updates complete, violating the all-or-nothing principle for distributed database updates.

**Additional Finding**: The indexer initialization code has a related bug where `next_version` is loaded directly from `LatestVersion` [11](#0-10)  without adding 1, which should load as `LatestVersion + 1` to represent the next version to index. This exacerbates recovery complexity during restart scenarios.

**Scope Note**: This vulnerability only affects nodes with the indexer enabled (`storage.enable_indexer = true`). Nodes running without the indexer are not affected. However, nodes that enable the indexer for API support become vulnerable to this desynchronization issue.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L103-107)
```rust
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
            self.ledger_db.metadata_db().write_schemas(ledger_batch)?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L110-110)
```rust
            self.post_commit(old_committed_ver, version, ledger_info_with_sigs, chunk_opt)
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L612-658)
```rust
        if old_committed_version.is_none() || version > old_committed_version.unwrap() {
            let first_version = old_committed_version.map_or(0, |v| v + 1);
            let num_txns = version + 1 - first_version;

            COMMITTED_TXNS.inc_by(num_txns);
            LATEST_TXN_VERSION.set(version as i64);
            if let Some(update_sender) = &self.update_subscriber {
                update_sender
                    .send((Instant::now(), version))
                    .map_err(|err| {
                        AptosDbError::Other(format!("Failed to send update to subscriber: {}", err))
                    })?;
            }
            // Activate the ledger pruner and state kv pruner.
            // Note the state merkle pruner is activated when state snapshots are persisted
            // in their async thread.
            self.ledger_pruner
                .maybe_set_pruner_target_db_version(version);
            self.state_store
                .state_kv_pruner
                .maybe_set_pruner_target_db_version(version);

            // Note: this must happen after txns have been saved to db because types can be newly
            // created in this same chunk of transactions.
            if let Some(indexer) = &self.indexer {
                let _timer = OTHER_TIMERS_SECONDS.timer_with(&["indexer_index"]);
                // n.b. txns_to_commit can be partial, when the control was handed over from consensus to state sync
                // where state sync won't send the pre-committed part to the DB again.
                if let Some(chunk) = chunk_opt
                    && chunk.len() == num_txns as usize
                {
                    let write_sets = chunk
                        .transaction_outputs
                        .iter()
                        .map(|t| t.write_set())
                        .collect_vec();
                    indexer.index(self.state_store.clone(), first_version, &write_sets)?;
                } else {
                    let write_sets: Vec<_> = self
                        .ledger_db
                        .write_set_db()
                        .get_write_set_iter(first_version, num_txns as usize)?
                        .try_collect()?;
                    let write_set_refs = write_sets.iter().collect_vec();
                    indexer.index(self.state_store.clone(), first_version, &write_set_refs)?;
                };
            }
```

**File:** storage/indexer/src/lib.rs (L73-75)
```rust
        let next_version = db
            .get::<IndexerMetadataSchema>(&MetadataKey::LatestVersion)?
            .map_or(0, |v| v.expect_version());
```

**File:** storage/indexer/src/lib.rs (L102-107)
```rust
        db_ensure!(
            first_version <= next_version,
            "Indexer expects to see continuous transaction versions. Expecting: {}, got: {}",
            next_version,
            first_version,
        );
```

**File:** storage/indexer/src/lib.rs (L144-144)
```rust
        self.db.write_schemas(batch)?;
```

**File:** storage/indexer/src/lib.rs (L145-145)
```rust
        self.next_version.store(end_version, Ordering::Relaxed);
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L207-227)
```rust
        if indexer.next_version() < ledger_next_version {
            use aptos_storage_interface::state_store::state_view::db_state_view::DbStateViewAtVersion;
            let db: Arc<dyn DbReader> = self.state_store.clone();

            let state_view = db.state_view_at_version(Some(ledger_next_version - 1))?;
            let annotator = AptosValueAnnotator::new(&state_view);

            const BATCH_SIZE: Version = 10000;
            let mut next_version = indexer.next_version();
            while next_version < ledger_next_version {
                info!(next_version = next_version, "AptosDB Indexer catching up. ",);
                let end_version = std::cmp::min(ledger_next_version, next_version + BATCH_SIZE);
                let write_sets = self
                    .ledger_db
                    .write_set_db()
                    .get_write_sets(next_version, end_version)?;
                let write_sets_ref: Vec<_> = write_sets.iter().collect();
                indexer.index_with_annotator(&annotator, next_version, &write_sets_ref)?;

                next_version = end_version;
            }
```
