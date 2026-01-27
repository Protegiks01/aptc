# Audit Report

## Title
Transaction Accumulator Frozen Subtree Gap in Replay-Verify Snapshot Restoration

## Summary

The `replay_verify.rs` coordinator captures `save_start_version` before updating `next_txn_version` based on snapshot version, causing `TransactionRestoreBatchController` to skip frozen subtree initialization when restoring a snapshot that's newer than existing database transactions. This leads to transaction accumulator failures when the database has partial transaction history.

## Finding Description

The vulnerability exists in the timing of when `save_start_version` is set relative to when `next_txn_version` is updated for snapshot-based restoration. [1](#0-0) 

The problematic sequence occurs when:

1. **Database has partial history**: Database contains transactions 0-500, so `get_next_expected_transaction_version()` returns 501
2. **Snapshot available**: A state snapshot exists at version 1000
3. **Line 155 captures old value**: `save_start_version = Some(501)` using the original `next_txn_version`
4. **Line 157 updates version**: `next_txn_version` becomes 1001 (max of 501 and snapshot_version+1)
5. **Snapshot is restored**: The snapshot at version 1000 is restored to database state
6. **Frozen subtrees are skipped**: `TransactionRestoreBatchController` receives `first_version = Some(501)` [2](#0-1) 

When `first_version` is `Some(501)`, the critical `confirm_or_save_frozen_subtrees` call is skipped. This function establishes the Merkle accumulator frozen subtrees necessary for the transaction accumulator to function correctly. [3](#0-2) 

Later, when attempting to save transaction at version 1000, the `put_transaction_accumulator` operation requires reading frozen subtree nodes up to position 1000: [4](#0-3) 

The `HashReader` implementation fails when positions don't exist: [5](#0-4) 

This causes the entire restore operation to fail with "position does not exist" error, leaving the database in an inconsistent state (snapshot restored but transaction accumulator incomplete).

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention"

The vulnerability causes:
- **Operational Disruption**: Replay-verify operations fail in specific but realistic scenarios
- **State Inconsistency**: Database left with state snapshot at version 1000 but transaction accumulator frozen subtrees only up to version 500
- **Recovery Complexity**: Manual intervention required to either reset database or manually establish frozen subtrees
- **No Data Corruption**: Due to atomic batch commits, no permanent corruption occurs
- **No Consensus Impact**: Failure happens before any state commitment, preventing consensus splits

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs" by preventing proper Merkle proof verification when the accumulator structure is incomplete.

## Likelihood Explanation

**Medium Likelihood** - Requires specific conditions but realistic scenario:

**Triggering Conditions:**
1. Database with partial transaction history (e.g., from previous partial restore or pruning)
2. State snapshot available at version newer than database transactions
3. Operator runs replay-verify spanning the version range

**Realistic Scenarios:**
- Node operator performing incremental restores across different snapshot versions
- Recovery after partial database corruption
- Testing/validation workflows using different backup sets
- Migration scenarios where old transactions are pruned but newer snapshots exist

The issue is deterministic once conditions are met - it will always fail, not intermittent.

## Recommendation

Move the `save_start_version` assignment to after the `next_txn_version` update, and conditionally set it based on whether a snapshot is being restored:

```rust
let skip_snapshot: bool =
    snapshot_version.is_none() || next_txn_version > snapshot_version.unwrap();

next_txn_version = std::cmp::max(next_txn_version, snapshot_version.map_or(0, |v| v + 1));

// Set save_start_version after next_txn_version is finalized
// Use None when snapshot will be restored to force frozen subtree initialization
let save_start_version = if skip_snapshot && next_txn_version > 0 {
    Some(next_txn_version)
} else {
    None
};
```

Alternatively, always pass `None` when `!skip_snapshot` to ensure frozen subtrees are established:

```rust
let save_start_version = if skip_snapshot {
    (next_txn_version > 0).then_some(next_txn_version)
} else {
    None  // Force frozen subtree establishment when restoring snapshot
};
```

## Proof of Concept

**Setup:**
1. Create AptosDB with transactions 0-500 committed
2. Create state snapshot backup at version 1000
3. Create transaction backups covering versions 1000-2000
4. Run replay-verify with start_version=0, end_version=2000

**Expected Behavior:** Restore completes successfully

**Actual Behavior:** Operation fails with error similar to:
```
Error: transaction restore failed: Position(level: X, pos: Y) does not exist.
```

**Rust Test Skeleton:**
```rust
#[tokio::test]
async fn test_replay_verify_snapshot_frozen_subtree_gap() {
    // 1. Setup DB with transactions 0-500
    let db = setup_test_db_with_transactions(0, 500);
    
    // 2. Create snapshot at version 1000
    let snapshot = create_state_snapshot(1000);
    
    // 3. Create transaction backups from 1000-2000
    let txn_backups = create_transaction_backups(1000, 2000);
    
    // 4. Run replay-verify
    let coordinator = ReplayVerifyCoordinator::new(
        storage,
        metadata_cache_opt,
        trusted_waypoints_opt,
        concurrent_downloads,
        replay_concurrency_level,
        restore_handler,
        0,    // start_version
        2000, // end_version
        false, // validate_modules
        verify_execution_mode,
    ).unwrap();
    
    // This should fail with "position does not exist" error
    let result = coordinator.run().await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));
}
```

## Notes

This vulnerability specifically affects the `replay_verify` coordinator path. The regular `restore` coordinator may have different behavior depending on how it sequences snapshot and transaction restoration. The issue is timing-dependent on when database state is checked versus when restoration parameters are calculated.

### Citations

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L154-157)
```rust
        // Once it begins replay, we want to directly start from the version that failed
        let save_start_version = (next_txn_version > 0).then_some(next_txn_version);

        next_txn_version = std::cmp::max(next_txn_version, snapshot_version.map_or(0, |v| v + 1));
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L306-312)
```rust
        // If first_version is None, we confirm and save frozen substrees to create a baseline
        // When first version is not None, it only happens when we already finish first phase of db restore and
        // we don't need to confirm and save frozen subtrees again.
        let first_version = self.first_version.unwrap_or(
            self.confirm_or_save_frozen_subtrees(&mut loaded_chunk_stream)
                .await?,
        );
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L403-422)
```rust
    async fn confirm_or_save_frozen_subtrees(
        &self,
        loaded_chunk_stream: &mut Peekable<impl Unpin + Stream<Item = Result<LoadedChunk>>>,
    ) -> Result<Version> {
        let first_chunk = Pin::new(loaded_chunk_stream)
            .peek()
            .await
            .ok_or_else(|| anyhow!("LoadedChunk stream is empty."))?
            .as_ref()
            .map_err(|e| anyhow!("Error: {}", e))?;

        if let RestoreRunMode::Restore { restore_handler } = self.global_opt.run_mode.as_ref() {
            restore_handler.confirm_or_save_frozen_subtrees(
                first_chunk.manifest.first_version,
                first_chunk.range_proof.left_siblings(),
            )?;
        }

        Ok(first_chunk.manifest.first_version)
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L108-126)
```rust
    pub fn put_transaction_accumulator(
        &self,
        first_version: Version,
        txn_infos: &[impl Borrow<TransactionInfo>],
        transaction_accumulator_batch: &mut SchemaBatch,
    ) -> Result<HashValue> {
        let txn_hashes: Vec<HashValue> = txn_infos.iter().map(|t| t.borrow().hash()).collect();

        let (root_hash, writes) = Accumulator::append(
            self,
            first_version, /* num_existing_leaves */
            &txn_hashes,
        )?;
        writes.iter().try_for_each(|(pos, hash)| {
            transaction_accumulator_batch.put::<TransactionAccumulatorSchema>(pos, hash)
        })?;

        Ok(root_hash)
    }
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L195-201)
```rust
impl HashReader for TransactionAccumulatorDb {
    fn get(&self, position: Position) -> Result<HashValue, anyhow::Error> {
        self.db
            .get::<TransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| anyhow!("{} does not exist.", position))
    }
}
```
