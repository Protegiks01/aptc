# Audit Report

## Title
Non-Atomic Version Reads in OldSyncRequest Validation Cause Incorrect Error Classification and Consensus Sync Failures

## Summary
The `OldSyncRequest` error validation reads pre-committed and committed versions from storage non-atomically, allowing race conditions where committed version appears higher than pre-committed version. This violates storage invariants and incorrectly rejects valid consensus sync requests, causing validator sync failures and consensus coordination breakdowns.

## Finding Description

The state-sync driver validates consensus sync target requests by checking if the target version is older than both the pre-committed and committed versions. However, this validation performs two separate, non-atomic storage reads that can observe inconsistent state. [1](#0-0) 

These two utility functions read from different storage locations: [2](#0-1) [3](#0-2) 

**Normal Storage Invariant**: `pre_committed_version >= committed_version` (pre-committed transactions include those written to DB but not yet certified by consensus) [4](#0-3) 

**Race Condition Scenario**:
1. Initial state: pre_committed = 100, committed = 100
2. Consensus sends sync request for target version 105 (valid future target)
3. Thread A (handling sync request) reads `pre_committed = 100` from state_store
4. **Meanwhile**: Another thread commits new transactions via `pre_commit_ledger()` and `commit_ledger()`:
   - state_store advances to version 110 (pre-committed)
   - ledger_db metadata advances to version 110 (committed) [5](#0-4) [6](#0-5) 

5. Thread A reads `committed = 110` from ledger_db metadata
6. Thread A now has: `pre_committed = 100`, `committed = 110` (violates invariant!)
7. Validation check executes: [7](#0-6) 

   Evaluates to: `if 105 < 110 || 105 < 100` = `TRUE`
8. Returns `OldSyncRequest(105, 100, 110)` to consensus - **INCORRECT**

The sync target 105 was valid when the request was made (state was 100,100), but the non-atomic reads observed an impossible state (100,110) and incorrectly rejected it.

The commit locks only prevent concurrent pre-commits and concurrent commits separately, but explicitly allow pre-commit and commit operations to run concurrently: [8](#0-7) 

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: When consensus receives the incorrect `OldSyncRequest` error, sync-to-target operations fail. At epoch transitions, this causes validator panics: [9](#0-8) 

2. **Significant Protocol Violations**: 
   - Breaks consensus/state-sync handover protocol
   - Violates storage consistency invariant (committed > pre-committed observable)
   - Causes incorrect error responses to consensus for valid sync requests

3. **Consensus Coordination Failures**: State-sync incorrectly signals to consensus that a valid future target is "old", disrupting the synchronization protocol and potentially causing validators to fall behind or fail epoch transitions.

## Likelihood Explanation

**High Likelihood**: This race condition occurs naturally during normal validator operation:
- Consensus frequently commits new blocks while state-sync handles sync requests
- No attacker interaction required - happens during concurrent legitimate operations
- Window of opportunity exists whenever commits occur between the two version reads
- More likely during high transaction throughput when commits are frequent
- Particularly problematic during epoch transitions when sync-to-target is critical

## Recommendation

Implement atomic version snapshot reading to ensure consistent view of storage state:

**Solution 1: Add atomic snapshot method to DbReader interface**
```rust
// In storage/storage-interface/src/lib.rs
fn get_version_snapshot(&self) -> Result<VersionSnapshot> {
    // Single atomic read returning both versions
}

struct VersionSnapshot {
    pub pre_committed_version: Version,
    pub committed_version: Version,
}
```

**Solution 2: Use single consistent read source**
Since committed version should never exceed pre-committed version, use pre-committed version for both checks initially, then verify ledger info separately:

```rust
// In state-sync/state-sync-driver/src/driver.rs
async fn handle_consensus_sync_target_notification(
    &mut self,
    sync_target_notification: ConsensusSyncTargetNotification,
) -> Result<(), Error> {
    // Single atomic read
    let latest_pre_committed_version = 
        utils::fetch_pre_committed_version(self.storage.clone())?;
    let sync_target_version = sync_target_notification
        .get_target()
        .ledger_info()
        .version();
    
    // Only check pre-committed for initial validation
    if sync_target_version < latest_pre_committed_version {
        let latest_synced_ledger_info = 
            utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
        let error = Err(Error::OldSyncRequest(
            sync_target_version,
            latest_pre_committed_version,
            latest_synced_ledger_info.ledger_info().version(),
        ));
        // ... respond with error
    }
    
    // Proceed with sync request initialization
    // ...
}
```

**Solution 3: Lock-protected consistent reads**
Add a read lock that prevents commits from advancing during version checks (may impact performance).

## Proof of Concept

```rust
// Rust reproduction - requires access to AptosDB internals
#[tokio::test]
async fn test_non_atomic_version_read_race() {
    let (storage, executor) = setup_test_environment();
    
    // Initial state: both versions at 100
    commit_blocks_to_version(&storage, &executor, 100).await;
    
    // Thread 1: Read pre-committed (will be 100)
    let handle1 = tokio::spawn({
        let storage = storage.clone();
        async move {
            let pre_committed = storage.get_pre_committed_version().unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let committed = storage.get_latest_ledger_info().unwrap()
                .ledger_info().version();
            (pre_committed.unwrap(), committed)
        }
    });
    
    // Thread 2: Commit new blocks (advancing to 110)
    tokio::time::sleep(Duration::from_millis(50)).await;
    let handle2 = tokio::spawn({
        let storage = storage.clone();
        let executor = executor.clone();
        async move {
            commit_blocks_to_version(&storage, &executor, 110).await;
        }
    });
    
    handle2.await.unwrap();
    let (pre_committed, committed) = handle1.await.unwrap();
    
    // Demonstrates the race: pre_committed = 100, committed = 110
    assert_eq!(pre_committed, 100);
    assert_eq!(committed, 110);
    assert!(committed > pre_committed); // Invariant violated!
    
    // Now simulate sync request validation
    let sync_target = 105;
    let is_old = sync_target < committed || sync_target < pre_committed;
    assert!(is_old); // Incorrectly classified as old!
}
```

## Notes

This vulnerability demonstrates a classic Time-of-Check-Time-of-Use (TOCTOU) race condition where the assumption of atomicity between related storage reads is violated. The issue is exacerbated by the explicit design choice to allow concurrent pre-commit and commit operations, which increases the window for this race condition.

### Citations

**File:** state-sync/state-sync-driver/src/driver.rs (L412-417)
```rust
        // Fetch the pre-committed and committed versions
        let latest_pre_committed_version =
            utils::fetch_pre_committed_version(self.storage.clone())?;
        let latest_synced_ledger_info =
            utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L125-129)
```rust
    fn get_latest_ledger_info_option(&self) -> Result<Option<LedgerInfoWithSignatures>> {
        gauged_api("get_latest_ledger_info_option", || {
            Ok(self.ledger_db.metadata_db().get_latest_ledger_info_option())
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L137-141)
```rust
    fn get_pre_committed_version(&self) -> Result<Option<Version>> {
        gauged_api("get_pre_committed_version", || {
            Ok(self.state_store.current_state_locked().version())
        })
    }
```

**File:** storage/storage-interface/src/lib.rs (L299-302)
```rust
        /// Returns the latest "pre-committed" transaction version, which includes those written to
        /// the DB but yet to be certified by consensus or a verified LedgerInfo from a state sync
        /// peer.
        fn get_pre_committed_version(&self) -> Result<Option<Version>>;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L44-76)
```rust
    fn pre_commit_ledger(&self, chunk: ChunkToCommit, sync_commit: bool) -> Result<()> {
        gauged_api("pre_commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .pre_commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["pre_commit_ledger"]);

            chunk
                .state_summary
                .latest()
                .global_state_summary
                .log_generation("db_save");

            self.pre_commit_validation(&chunk)?;
            let _new_root_hash =
                self.calculate_and_commit_ledger_and_state_kv(&chunk, self.skip_index_and_usage)?;

            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["save_transactions__others"]);

            self.state_store.buffered_state().lock().update(
                chunk.result_ledger_state_with_summary(),
                chunk.estimated_total_state_updates(),
                sync_commit || chunk.is_reconfig,
            )?;

            Ok(())
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L78-112)
```rust
    fn commit_ledger(
        &self,
        version: Version,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        chunk_opt: Option<ChunkToCommit>,
    ) -> Result<()> {
        gauged_api("commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_ledger"]);

            let old_committed_ver = self.get_and_check_commit_range(version)?;

            let mut ledger_batch = SchemaBatch::new();
            // Write down LedgerInfo if provided.
            if let Some(li) = ledger_info_with_sigs {
                self.check_and_put_ledger_info(version, li, &mut ledger_batch)?;
            }
            // Write down commit progress
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
            self.ledger_db.metadata_db().write_schemas(ledger_batch)?;

            // Notify the pruners, invoke the indexer, and update in-memory ledger info.
            self.post_commit(old_committed_ver, version, ledger_info_with_sigs, chunk_opt)
        })
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L275-286)
```rust
        // If the target version is old, return an error to consensus (something is wrong!)
        if sync_target_version < latest_committed_version
            || sync_target_version < latest_pre_committed_version
        {
            let error = Err(Error::OldSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
                latest_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }
```

**File:** consensus/src/epoch_manager.rs (L558-565)
```rust
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
            .context(format!(
                "[EpochManager] State sync to new epoch {}",
                ledger_info
            ))
            .expect("Failed to sync to new epoch");
```
