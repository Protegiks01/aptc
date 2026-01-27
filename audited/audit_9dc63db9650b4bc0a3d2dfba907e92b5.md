# Audit Report

## Title
TOCTOU Race Condition in update_latest_ledger_info() Allows Newer Ledger Info to be Overwritten by Older Epoch

## Summary
The `update_latest_ledger_info()` function in `storage/aptosdb/src/backup/restore_utils.rs` contains a Time-of-Check-Time-of-Use (TOCTOU) race condition. The non-atomic check-then-set pattern between lines 65 and 71 allows concurrent threads to overwrite a newer ledger info (higher epoch) with an older one, potentially causing epoch confusion and consensus inconsistencies across the network. [1](#0-0) 

## Finding Description

The vulnerability exists in the epoch comparison and update logic. The function loads the current latest ledger info via `ArcSwap::load()`, checks if the current epoch is greater than the new epoch, and if not, stores the new ledger info via `ArcSwap::store()`. [2](#0-1) [3](#0-2) 

While `ArcSwap` provides atomic individual operations (`load()` and `store()`), it does not make the entire check-then-set sequence atomic. This creates a race window where:

**Race Scenario:**
1. Current latest ledger info: epoch 9
2. Thread A wants to update to epoch 10
3. Thread B wants to update to epoch 11
4. Thread A loads epoch 9, checks (9 > 10? No), proceeds to update
5. Thread B loads epoch 9, checks (9 > 11? No), proceeds to update
6. Thread B executes `set_latest_ledger_info()` → latest is now epoch 11
7. Thread A executes `set_latest_ledger_info()` → latest is now epoch 10 (overwrites epoch 11!)

**Attack Vectors:**

The race can be triggered through concurrent calls to `update_latest_ledger_info()` from:

1. **State Sync Finalization**: `finalize_state_snapshot()` calls `update_latest_ledger_info()` without acquiring any locks [4](#0-3) [5](#0-4) 

2. **Restore Operations**: `RestoreHandler::save_ledger_infos()` provides public access to trigger updates [6](#0-5) 

Notably, `finalize_state_snapshot()` does NOT acquire the `commit_lock` or `pre_commit_lock` that protect other commit operations: [7](#0-6) 

This allows concurrent state sync operations or restore operations to race when updating the latest ledger info.

## Impact Explanation

**HIGH Severity** - This vulnerability breaks critical invariants:

1. **Consensus Safety Invariant Violation**: The latest ledger info cache is used throughout the system to determine the current epoch and validator set. If an older epoch overwrites a newer one, different nodes may disagree about the current epoch. [8](#0-7) 

2. **Epoch State Confusion**: The system relies on monotonically increasing epochs. Reverting to an older epoch violates this assumption and could cause:
   - Incorrect validator set selection
   - Epoch boundary misidentification  
   - Consensus voting with wrong epoch credentials
   - State sync targeting wrong versions

3. **State Consistency Violation**: The latest ledger info determines what state the node believes is committed. If this is incorrect, the node's view diverges from the network, breaking the deterministic execution guarantee.

While not directly causing fund loss, this creates the conditions for consensus safety violations and potential network partition, qualifying as **High Severity** per the bug bounty criteria: "Significant protocol violations" and potential "Validator node slowdowns" as nodes detect epoch mismatches.

## Likelihood Explanation

**Medium Likelihood** during specific operational scenarios:

1. **State Sync Handoffs**: When consensus hands off to state sync or vice versa, if the handoff is not perfectly serialized, both could attempt to finalize/commit concurrently [9](#0-8) 

2. **Recovery Operations**: During node recovery with concurrent restore operations processing different epoch ranges

3. **Fast Sync**: When multiple state snapshots are being processed in rapid succession

The race window is narrow (nanoseconds to microseconds between the check and set), but in high-throughput recovery scenarios with concurrent operations, the probability increases.

## Recommendation

Replace the check-then-set pattern with an atomic compare-and-swap operation. Since `ArcSwap` doesn't provide CAS, use a mutex to protect the entire check-then-set sequence:

```rust
pub(crate) fn update_latest_ledger_info(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    // Acquire a lock to make check-then-set atomic
    let _lock = ledger_metadata_db.latest_ledger_info_update_lock.lock();
    
    if let Some(li) = ledger_metadata_db.get_latest_ledger_info_option() {
        if li.ledger_info().epoch() > ledger_infos.last().unwrap().ledger_info().epoch() {
            return Ok(());
        }
    }
    ledger_metadata_db.set_latest_ledger_info(ledger_infos.last().unwrap().clone());
    
    Ok(())
}
```

Add a new mutex field to `LedgerMetadataDb`:
```rust
pub(crate) struct LedgerMetadataDb {
    db: Arc<DB>,
    latest_ledger_info: ArcSwap<Option<LedgerInfoWithSignatures>>,
    latest_ledger_info_update_lock: Mutex<()>,  // Add this
}
```

Alternatively, implement proper monotonicity checking with version/epoch tracking to reject out-of-order updates at the storage layer.

## Proof of Concept

```rust
use std::sync::Arc;
use std::thread;
use aptos_types::ledger_info::LedgerInfoWithSignatures;

// Simulate the race condition
fn reproduce_toctou_race() {
    let ledger_db = Arc::new(setup_test_db());
    
    // Set initial state to epoch 9
    ledger_db.metadata_db().set_latest_ledger_info(create_ledger_info(9));
    
    let db1 = Arc::clone(&ledger_db);
    let db2 = Arc::clone(&ledger_db);
    
    // Thread 1: Update to epoch 10
    let t1 = thread::spawn(move || {
        let ledger_infos = vec![create_ledger_info(10)];
        update_latest_ledger_info(db1.metadata_db(), &ledger_infos).unwrap();
    });
    
    // Thread 2: Update to epoch 11  
    let t2 = thread::spawn(move || {
        let ledger_infos = vec![create_ledger_info(11)];
        update_latest_ledger_info(db2.metadata_db(), &ledger_infos).unwrap();
    });
    
    t1.join().unwrap();
    t2.join().unwrap();
    
    // Check final state - could be epoch 10 instead of expected 11!
    let final_epoch = ledger_db.metadata_db()
        .get_latest_ledger_info_option()
        .unwrap()
        .ledger_info()
        .epoch();
    
    // This assertion may fail due to the race:
    // assert_eq!(final_epoch, 11, "Newer epoch should win");
    println!("Final epoch: {} (expected 11)", final_epoch);
    if final_epoch == 10 {
        println!("RACE DETECTED: Older epoch overwrote newer one!");
    }
}
```

The race can be reproduced by running concurrent state sync operations or restore operations with careful timing, demonstrating that newer ledger infos can be overwritten by older ones.

### Citations

**File:** storage/aptosdb/src/backup/restore_utils.rs (L60-74)
```rust
/// Updates the latest ledger info iff a ledger info with a higher epoch is found
pub(crate) fn update_latest_ledger_info(
    ledger_metadata_db: &LedgerMetadataDb,
    ledger_infos: &[LedgerInfoWithSignatures],
) -> Result<()> {
    if let Some(li) = ledger_metadata_db.get_latest_ledger_info_option() {
        if li.ledger_info().epoch() > ledger_infos.last().unwrap().ledger_info().epoch() {
            // No need to update latest ledger info.
            return Ok(());
        }
    }
    ledger_metadata_db.set_latest_ledger_info(ledger_infos.last().unwrap().clone());

    Ok(())
}
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L94-98)
```rust
    pub(crate) fn get_latest_ledger_info_option(&self) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L180-183)
```rust
    pub(crate) fn set_latest_ledger_info(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) {
        self.latest_ledger_info
            .store(Arc::new(Some(ledger_info_with_sigs)));
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L78-93)
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

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L236-236)
```rust
            restore_utils::update_latest_ledger_info(self.ledger_db.metadata_db(), ledger_infos)?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L572-582)
```rust
        let current_epoch = self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            ledger_info_with_sig.ledger_info().epoch() == current_epoch,
            "Gap in epoch history. Trying to put in LedgerInfo in epoch: {}, current epoch: {}",
            ledger_info_with_sig.ledger_info().epoch(),
            current_epoch,
        );
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L61-63)
```rust
    pub fn save_ledger_infos(&self, ledger_infos: &[LedgerInfoWithSignatures]) -> Result<()> {
        restore_utils::save_ledger_infos(self.aptosdb.ledger_db.metadata_db(), ledger_infos, None)
    }
```

**File:** state-sync/state-sync-driver/src/storage_synchronizer.rs (L932-954)
```rust
                            if let Err(error) = finalize_storage_and_send_commit(
                                chunk_executor,
                                &mut commit_notification_sender,
                                metadata_storage,
                                state_snapshot_receiver,
                                storage,
                                &epoch_change_proofs,
                                target_output_with_proof,
                                version,
                                &target_ledger_info,
                                last_committed_state_index,
                            )
                            .await
                            {
                                send_storage_synchronizer_error(
                                    error_notification_sender.clone(),
                                    notification_id,
                                    error,
                                )
                                .await;
                            }
                            decrement_pending_data_chunks(pending_data_chunks.clone());
                            return; // There's nothing left to do!
```
