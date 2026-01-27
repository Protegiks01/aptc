# Audit Report

## Title
Race Condition in FastSyncStorageWrapper Causes Database Mismatch Between Pre-Commit and Commit Operations

## Summary
The `FastSyncStorageWrapper` contains a critical race condition where `pre_commit_ledger()` and `commit_ledger()` can target different underlying databases when the fast sync status changes between these operations, leading to commit validation failures and potential node crashes.

## Finding Description

The `FastSyncStorageWrapper` wraps two separate `AptosDB` instances and delegates write operations based on the `fast_sync_status` state [1](#0-0) . 

The `get_aptos_db_write_ref()` method returns different databases depending on the status [2](#0-1) :
- When status is `UNKNOWN`: returns `temporary_db_with_genesis`
- When status is `STARTED` or `FINISHED`: returns `db_for_fast_sync`

Both `pre_commit_ledger()` and `commit_ledger()` in the `DbWriter` trait implementation delegate to `get_aptos_db_write_ref()` [3](#0-2) .

The vulnerability occurs because consensus calls `pre_commit_block()` and `commit_ledger()` as **separate operations** [4](#0-3) . Between these calls, state sync can invoke `get_state_snapshot_receiver()` which changes the status from `UNKNOWN` to `STARTED` [5](#0-4) .

**Attack Scenario:**
1. Node starts with `fast_sync_status = UNKNOWN`
2. Consensus calls `pre_commit_block()` → `pre_commit_ledger()` on `temporary_db_with_genesis`
3. State sync calls `get_state_snapshot_receiver()` → status changes to `STARTED`
4. Consensus calls `commit_ledger()` on `db_for_fast_sync` (different database)
5. Commit validation fails because `db_for_fast_sync` has no pre-committed data

The `commit_ledger()` implementation validates that the version being committed was previously pre-committed [6](#0-5) . This check reads from the database's internal `state_store`, which differs between the two `AptosDB` instances, causing the validation to fail with "Version too new to commit" error.

## Impact Explanation

**Critical Severity** - This breaks the **Consensus Safety** and **State Consistency** invariants:

1. **Node Crash**: When commit validation fails, the node panics because it has pending pre-committed data in the wrong database [7](#0-6) 
   
2. **Data Loss**: Pre-committed transactions in `temporary_db_with_genesis` become orphaned and unrecoverable

3. **Liveness Failure**: Affected validator nodes cannot progress consensus, potentially causing network-wide liveness issues if enough validators are affected

4. **State Divergence**: Different validators might apply the status transition at different times, causing non-deterministic behavior

This qualifies as **Critical** per Aptos bug bounty criteria as it can cause "Total loss of liveness/network availability" and "Consensus/Safety violations."

## Likelihood Explanation

**Medium-High Likelihood** during fast sync operations:

- The race window exists whenever a node bootstraps using fast sync mode
- The timing depends on when genesis completes and when state snapshot receiver initializes
- No synchronization mechanism prevents concurrent status changes
- Nodes restarting or joining the network in fast sync mode are vulnerable
- The vulnerability is deterministic once the race condition occurs

While requiring specific timing, this occurs naturally during node initialization without requiring attacker manipulation.

## Recommendation

Add atomic locking to prevent status changes during write operations:

**Option 1 - Status Change Lock:**
```rust
pub struct FastSyncStorageWrapper {
    temporary_db_with_genesis: Arc<AptosDB>,
    db_for_fast_sync: Arc<AptosDB>,
    fast_sync_status: Arc<RwLock<FastSyncStatus>>,
    write_operation_lock: Arc<Mutex<()>>, // New field
}

impl DbWriter for FastSyncStorageWrapper {
    fn pre_commit_ledger(&self, chunk: ChunkToCommit, sync_commit: bool) -> Result<()> {
        let _guard = self.write_operation_lock.lock();
        self.get_aptos_db_write_ref().pre_commit_ledger(chunk, sync_commit)
    }

    fn commit_ledger(
        &self,
        version: Version,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        chunk_opt: Option<ChunkToCommit>,
    ) -> Result<()> {
        let _guard = self.write_operation_lock.lock();
        self.get_aptos_db_write_ref().commit_ledger(version, ledger_info_with_sigs, chunk_opt)
    }
    
    fn get_state_snapshot_receiver(&self, ...) -> Result<...> {
        let _guard = self.write_operation_lock.lock();
        *self.fast_sync_status.write() = FastSyncStatus::STARTED;
        // ... rest of implementation
    }
}
```

**Option 2 - Capture DB Reference:**
Store the database reference in the block/chunk metadata to ensure pre-commit and commit use the same instance.

## Proof of Concept

```rust
// Reproduction scenario (conceptual - would require integration test)
#[test]
fn test_fast_sync_race_condition() {
    let node_config = create_fast_sync_config();
    let wrapper = FastSyncStorageWrapper::initialize_dbs(&node_config, None, None)
        .unwrap()
        .right()
        .unwrap();
    
    // Apply genesis - status is UNKNOWN
    let genesis_chunk = create_genesis_chunk();
    
    // Simulate race: Start pre-commit
    let chunk = create_test_chunk(version: 1);
    std::thread::spawn(move || {
        wrapper.pre_commit_ledger(chunk.clone(), false).unwrap();
        // Status is still UNKNOWN here, writes to temporary_db_with_genesis
    });
    
    // Change status before commit completes
    std::thread::sleep(Duration::from_millis(10));
    wrapper.get_state_snapshot_receiver(version: 100, expected_hash).unwrap();
    // Status is now STARTED
    
    // Attempt commit - will fail!
    let result = wrapper.commit_ledger(version: 1, None, Some(chunk));
    // ERROR: "Version too new to commit" because pre-commit was on different DB
    assert!(result.is_err());
}
```

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L31-38)
```rust
pub struct FastSyncStorageWrapper {
    // Used for storing genesis data during fast sync
    temporary_db_with_genesis: Arc<AptosDB>,
    // Used for restoring fast sync snapshot and all the read/writes afterwards
    db_for_fast_sync: Arc<AptosDB>,
    // This is for reading the fast_sync status to determine which db to use
    fast_sync_status: Arc<RwLock<FastSyncStatus>>,
}
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L134-140)
```rust
    pub(crate) fn get_aptos_db_write_ref(&self) -> &AptosDB {
        if self.is_fast_sync_bootstrap_started() || self.is_fast_sync_bootstrap_finished() {
            self.db_for_fast_sync.as_ref()
        } else {
            self.temporary_db_with_genesis.as_ref()
        }
    }
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L144-152)
```rust
    fn get_state_snapshot_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
    ) -> Result<Box<dyn StateSnapshotReceiver<StateKey, StateValue>>> {
        *self.fast_sync_status.write() = FastSyncStatus::STARTED;
        self.get_aptos_db_write_ref()
            .get_state_snapshot_receiver(version, expected_root_hash)
    }
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L172-185)
```rust
    fn pre_commit_ledger(&self, chunk: ChunkToCommit, sync_commit: bool) -> Result<()> {
        self.get_aptos_db_write_ref()
            .pre_commit_ledger(chunk, sync_commit)
    }

    fn commit_ledger(
        &self,
        version: Version,
        ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
        chunk_opt: Option<ChunkToCommit>,
    ) -> Result<()> {
        self.get_aptos_db_write_ref()
            .commit_ledger(version, ledger_info_with_sigs, chunk_opt)
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L336-395)
```rust
    fn pre_commit_block(&self, block_id: HashValue) -> ExecutorResult<()> {
        let _timer = COMMIT_BLOCKS.start_timer();
        info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
            "pre_commit_block",
        );

        let block = self.block_tree.get_block(block_id)?;

        fail_point!("executor::pre_commit_block", |_| {
            Err(anyhow::anyhow!("Injected error in pre_commit_block.").into())
        });

        let output = block.output.expect_complete_result();
        let num_txns = output.num_transactions_to_commit();
        if num_txns != 0 {
            let _timer = SAVE_TRANSACTIONS.start_timer();
            self.db
                .writer
                .pre_commit_ledger(output.as_chunk_to_commit(), false)?;
            TRANSACTIONS_SAVED.observe(num_txns as f64);
        }

        Ok(())
    }

    fn commit_ledger(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) -> ExecutorResult<()> {
        let _timer = OTHER_TIMERS.timer_with(&["commit_ledger"]);

        let block_id = ledger_info_with_sigs.ledger_info().consensus_block_id();
        info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
            "commit_ledger"
        );

        // Check for any potential retries
        // TODO: do we still have such retries?
        let committed_block = self.block_tree.root_block();
        if committed_block.num_persisted_transactions()?
            == ledger_info_with_sigs.ledger_info().version() + 1
        {
            return Ok(());
        }

        // Confirm the block to be committed is tracked in the tree.
        self.block_tree.get_block(block_id)?;

        fail_point!("executor::commit_blocks", |_| {
            Err(anyhow::anyhow!("Injected error in commit_blocks.").into())
        });

        let target_version = ledger_info_with_sigs.ledger_info().version();
        self.db
            .writer
            .commit_ledger(target_version, Some(&ledger_info_with_sigs), None)?;

        self.block_tree.prune(ledger_info_with_sigs.ledger_info())?;

        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L522-538)
```rust
    fn get_and_check_commit_range(&self, version_to_commit: Version) -> Result<Option<Version>> {
        let old_committed_ver = self.ledger_db.metadata_db().get_synced_version()?;
        let pre_committed_ver = self.state_store.current_state_locked().version();
        ensure!(
            old_committed_ver.is_none() || version_to_commit >= old_committed_ver.unwrap(),
            "Version too old to commit. Committed: {:?}; Trying to commit with LI: {}",
            old_committed_ver,
            version_to_commit,
        );
        ensure!(
            pre_committed_ver.is_some() && version_to_commit <= pre_committed_ver.unwrap(),
            "Version too new to commit. Pre-committed: {:?}, Trying to commit with LI: {}",
            pre_committed_ver,
            version_to_commit,
        );
        Ok(old_committed_ver)
    }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L96-105)
```rust
        let has_pending_pre_commit = inner.has_pending_pre_commit.load(Ordering::Acquire);
        f(inner).map_err(|error| {
            if has_pending_pre_commit {
                panic!(
                    "Hit error with pending pre-committed ledger, panicking. {:?}",
                    error,
                );
            }
            error
        })
```
