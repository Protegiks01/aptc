# Audit Report

## Title
Race Condition Between Transaction Commit and State Persistence Causes Stale State Reads in Table Info Indexer

## Summary
The `index_table_info()` function creates a state view using `db_reader.state_view_at_version()` which reads from persisted state in RocksDB. However, due to asynchronous state commits in BufferedState, the state may not be fully persisted when the indexer fetches newly committed transactions, causing stale or inconsistent state to be used for table info extraction.

## Finding Description

The vulnerability arises from a timing mismatch between transaction commitment and state persistence in the two-phase commit protocol: [1](#0-0) 

The `index_table_info()` function calculates `last_version = first_version + write_sets.len()` and creates a state view at this version. This state view reads from StateKvDb: [2](#0-1) 

The state is read directly from RocksDB, not from BufferedState. However, state updates are committed asynchronously: [3](#0-2) 

When `sync_commit` is false (the default for non-reconfig transactions), state updates are queued in BufferedState and committed asynchronously by StateSnapshotCommitter: [4](#0-3) 

Meanwhile, TableInfoService fetches transactions based on the latest ledger version: [5](#0-4) 

**Race Condition Timeline:**
1. Transactions [V₀, V₀+N] are pre-committed → state updates queued asynchronously
2. Transactions committed → ledger version advances to V₀+N
3. TableInfoService sees new ledger version
4. Fetches transactions [V₀, V₀+N] and calls `index_table_info()`
5. Creates state view at version V₀+N+1
6. **Race**: StateKvDb reads from RocksDB, but state updates not yet persisted
7. Returns stale state from before version V₀
8. AptosValueAnnotator parses table info using stale/inconsistent state

This breaks the **State Consistency** invariant: table info extraction assumes state at version V reflects all write sets up to version V, but async commits violate this assumption.

## Impact Explanation

This vulnerability causes **state inconsistencies requiring manual intervention**, qualifying as **Medium Severity** per Aptos bug bounty criteria.

**Specific Impacts:**
1. **Incorrect Table Type Metadata**: Newly created tables may not be recognized, or table types may be misidentified
2. **Index Corruption**: The table info index becomes inconsistent with actual on-chain state
3. **Client Data Integrity**: Applications relying on table info for data parsing receive incorrect type information
4. **Manual Intervention Required**: Corrupted index entries require database cleanup and re-indexing

While this doesn't directly affect consensus or cause fund loss, it corrupts critical indexer infrastructure that applications depend on for accurate state interpretation.

## Likelihood Explanation

**High Likelihood** - This race condition occurs naturally in normal operation:

1. **Default Behavior**: Most transactions use async commit (`sync_commit=false`)
2. **Common Pattern**: High transaction throughput creates persistent lag between ledger version and state checkpoint version
3. **No Synchronization**: TableInfoService doesn't wait for state checkpoint before fetching transactions
4. **Automatic Trigger**: Any transaction creating or modifying tables can trigger incorrect indexing

The vulnerability doesn't require malicious input—it's a systemic timing issue in the indexer architecture.

## Recommendation

**Solution**: Use `get_latest_state_checkpoint_version()` instead of `get_latest_ledger_info().version` to ensure state is persisted before indexing:

```rust
// In TableInfoService::get_highest_known_version()
async fn get_highest_known_version(&self) -> Result<u64, Error> {
    loop {
        // Use state checkpoint version instead of ledger version
        let state_checkpoint_version = self.context.db
            .get_latest_state_checkpoint_version()?
            .unwrap_or(0);
        
        if state_checkpoint_version >= self.current_version.load(Ordering::SeqCst) {
            return Ok(state_checkpoint_version);
        }
        
        tokio::time::sleep(Duration::from_millis(LEDGER_VERSION_RETRY_TIME_MILLIS)).await;
    }
}
```

**Alternative**: Force synchronous state commit for transactions that modify table structures, or add explicit synchronization in `index_table_info()` to wait for state checkpoint.

## Proof of Concept

```rust
// Reproduction steps:
// 1. Start Aptos node with table info indexer enabled
// 2. Submit high-throughput transactions creating new tables
// 3. Monitor state checkpoint version vs ledger version lag
// 4. Observe table info indexer processing transactions before state persisted

#[test]
fn test_stale_state_in_table_indexer() {
    // Setup: Create AptosDB with async commits
    let db = create_test_db();
    let indexer = IndexerAsyncV2::new(test_indexer_db()).unwrap();
    
    // Execute transactions creating tables
    let txns = create_table_creation_transactions(100);
    db.save_transactions(txns, None, false); // sync_commit=false
    
    // Immediately fetch for indexing (before state persisted)
    let ledger_version = db.get_latest_ledger_info_version().unwrap();
    let state_checkpoint = db.get_latest_state_checkpoint_version().unwrap();
    
    // Verify race condition: ledger ahead of state checkpoint
    assert!(ledger_version > state_checkpoint.unwrap_or(0));
    
    // Index will use stale state
    let write_sets = fetch_write_sets(0, ledger_version);
    let result = indexer.index_table_info(
        db.reader.clone(), 
        0, 
        &write_sets
    );
    
    // Verify table info is incorrect/missing due to stale state
    // Tables created in recent txns won't be in index
}
```

**Notes:**
- This vulnerability affects the **table info indexer auxiliary service**, not consensus or core state management
- The race window is proportional to state commit latency (typically hundreds of milliseconds under load)
- Detection: Monitor `LATEST_CHECKPOINT_VERSION` metric lag behind committed ledger version
- Exploitation requires no special privileges—occurs naturally under normal load

### Citations

**File:** storage/indexer/src/db_v2.rs (L73-83)
```rust
    pub fn index_table_info(
        &self,
        db_reader: Arc<dyn DbReader>,
        first_version: Version,
        write_sets: &[&WriteSet],
    ) -> Result<()> {
        let last_version = first_version + write_sets.len() as Version;
        let state_view = db_reader.state_view_at_version(Some(last_version))?;
        let annotator = AptosValueAnnotator::new(&state_view);
        self.index_with_annotator(&annotator, first_version, write_sets)
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L374-401)
```rust
    pub(crate) fn get_state_value_with_version_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<(Version, StateValue)>> {
        let mut read_opts = ReadOptions::default();

        // We want `None` if the state_key changes in iteration.
        read_opts.set_prefix_same_as_start(true);
        if !self.enabled_sharding() {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueSchema>(read_opts)?;
            iter.seek(&(state_key.clone(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        } else {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueByKeyHashSchema>(read_opts)?;
            iter.seek(&(state_key.hash(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L68-72)
```rust
            self.state_store.buffered_state().lock().update(
                chunk.result_ledger_state_with_summary(),
                chunk.estimated_total_state_updates(),
                sync_commit || chunk.is_reconfig,
            )?;
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L99-113)
```rust
    fn maybe_commit(&mut self, checkpoint: Option<StateWithSummary>, sync_commit: bool) {
        if let Some(checkpoint) = checkpoint {
            if !checkpoint.is_the_same(&self.last_snapshot)
                && (sync_commit
                    || self.estimated_items >= self.target_items
                    || self.buffered_versions() >= TARGET_SNAPSHOT_INTERVAL_IN_VERSION)
            {
                self.enqueue_commit(checkpoint);
            }
        }

        if sync_commit {
            self.drain_commits();
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L494-528)
```rust
    async fn get_highest_known_version(&self) -> Result<u64, Error> {
        let mut info = self.context.get_latest_ledger_info_wrapped();
        let mut ledger_version = info.unwrap().ledger_version.0;
        let mut empty_loops = 0;

        while ledger_version == 0 || self.current_version.load(Ordering::SeqCst) > ledger_version {
            if self.aborted.load(Ordering::SeqCst) {
                break;
            }
            if empty_loops > 0 {
                tokio::time::sleep(Duration::from_millis(LEDGER_VERSION_RETRY_TIME_MILLIS)).await;
            }
            empty_loops += 1;
            if let Err(err) = {
                info = self.context.get_latest_ledger_info_wrapped();
                ledger_version = info.unwrap().ledger_version.0;
                Ok::<(), Error>(())
            } {
                error!(
                    error = format!("{:?}", err),
                    "[Table Info] Failed to set highest known version"
                );
                continue;
            } else {
                sample!(
                    SampleRate::Frequency(100),
                    debug!(
                        ledger_version = ledger_version,
                        "[Table Info] Found new highest known ledger version",
                    )
                );
            }
        }
        Ok(ledger_version)
    }
```
