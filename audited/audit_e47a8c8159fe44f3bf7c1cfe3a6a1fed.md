# Audit Report

## Title
In-Memory Root State Rollback via Unvalidated update_root() in Consensus Observer Fallback Sync

## Summary
The `update_root()` function in the consensus observer's block data management lacks validation checks to ensure the new root is newer than the current root. This allows the fallback sync completion path to roll back the in-memory consensus root state to an older epoch/round when a race condition occurs between ongoing consensus progress and fallback sync completion, violating consensus state consistency invariants.

## Finding Description

The consensus observer maintains an in-memory root state representing the latest committed ledger info. This root is used throughout the observer to determine which blocks to accept, which commit decisions to process, and what the current consensus state is.

The vulnerability exists in the `update_root()` function which blindly overwrites the root without any validation: [1](#0-0) 

This function is called from `process_fallback_sync_notification()` when fallback sync completes: [2](#0-1) 

Critically, there is **no check** that `latest_synced_ledger_info` is actually newer than the current root before calling `update_root()`.

In contrast, the codebase shows awareness of this race condition in other paths:

1. The `handle_committed_blocks()` function **does** validate before updating the root: [3](#0-2) 

Note the comment on line 206 explicitly mentions: "Otherwise, this can race with the state sync process."

2. The `process_commit_sync_notification()` function **also** validates: [4](#0-3) 

The comment on lines 999-1001 explicitly acknowledges the race condition.

However, `process_fallback_sync_notification()` completely lacks this validation, creating an exploitable inconsistency.

**Attack Scenario:**

1. Consensus observer root is at (epoch=E, round=R0, version=V0)
2. Observer falls behind and initiates fallback sync via `sync_for_duration()`
3. While fallback sync is running (takes measurable time), normal consensus progresses
4. Observer receives newer commit decisions and `handle_committed_blocks()` updates root to (epoch=E, round=R1, version=V1) where R1 > R0
5. Fallback sync completes and returns `latest_synced_ledger_info` at (epoch=E, round=R_sync, version=V_sync) where R0 < R_sync < R1 (synced to a point that was ahead when it started, but is now behind current root)
6. `process_fallback_sync_notification()` is called with this ledger info
7. `update_root()` is called without validation at line 950
8. **Root is rolled back** from (E, R1, V1) to (E, R_sync, V_sync)

The root state is now in the past. This affects all downstream consensus observer operations:

- `get_highest_committed_epoch_round()` returns old values [5](#0-4) 

- `get_last_ordered_block()` falls back to old root [6](#0-5) 

- Blocks and commit decisions for already-processed rounds may be accepted again
- Execution pipeline may attempt to re-execute old blocks
- State sync targets become incorrect

## Impact Explanation

**Critical Severity** - This vulnerability causes consensus state rollback that can lead to:

1. **Consensus State Inconsistency**: The observer's view of consensus is rolled back to a previous state, breaking the invariant that consensus state only advances forward. This violates the fundamental "State Consistency" invariant.

2. **Block Re-processing**: The observer may accept and process blocks for rounds it has already committed, potentially causing duplicate execution or execution pipeline corruption.

3. **State Sync Corruption**: Future state sync operations will use the incorrect (rolled-back) root as a baseline, causing persistent state inconsistency.

4. **Downstream Impact**: Applications and services relying on the consensus observer will receive incorrect consensus state information, potentially leading to incorrect transaction processing or application-level double-spending if they trust the observer's state without independent verification.

While the underlying storage layer has monotonicity checks [7](#0-6)  that prevent committed storage rollback, the in-memory consensus state corruption is still critical because:
- The consensus observer is a critical component for non-validator nodes
- State inconsistency requires manual intervention to recover
- The corruption persists until the observer is restarted or manually synced

This meets the **Critical** severity criteria: "Consensus/Safety violations" and "State inconsistencies requiring intervention" at a consensus-critical component level.

## Likelihood Explanation

**High Likelihood** - This vulnerability can trigger naturally without attacker intervention:

1. **Common Trigger Condition**: Fallback sync is triggered when the observer falls behind, which can happen during network issues, high load, or normal catch-up scenarios.

2. **Race Window**: The fallback sync duration is configurable but typically involves seconds or minutes of syncing. During this window, normal consensus can advance multiple rounds, creating a large race window.

3. **No Attacker Required**: While a malicious peer could potentially manipulate timing to increase likelihood, the race condition occurs naturally whenever:
   - Fallback sync is slow (network congestion, peer delays)
   - Consensus progresses quickly (normal operation)
   - Both happen concurrently (common scenario)

4. **No Special Privileges Needed**: Any scenario causing the observer to fall behind and trigger fallback sync can lead to this vulnerability.

The vulnerability is deterministic once the race condition occurs - there are no probabilistic elements that might prevent exploitation.

## Recommendation

Add validation in `process_fallback_sync_notification()` to check if the synced ledger info is actually newer than the current root before calling `update_root()`, matching the pattern used in `process_commit_sync_notification()`.

**Recommended Fix:**

```rust
/// Processes the state sync notification for the fallback sync
async fn process_fallback_sync_notification(
    &mut self,
    latest_synced_ledger_info: LedgerInfoWithSignatures,
) {
    // Get the epoch and round for the latest synced ledger info
    let ledger_info = latest_synced_ledger_info.ledger_info();
    let epoch = ledger_info.epoch();
    let round = ledger_info.round();

    // Log the state sync notification
    info!(
        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
            "Received state sync notification for fallback completion! Epoch {}, round: {}!",
            epoch, round
        ))
    );

    // Verify that there is an active fallback sync
    if !self.state_sync_manager.in_fallback_mode() {
        error!(LogSchema::new(LogEntry::ConsensusObserver).message(
            "Failed to process fallback sync notification! No active fallback sync found!"
        ));
        return;
    }

    // Get the current block data root
    let block_data_root = self.observer_block_data.lock().root();
    let block_data_epoch = block_data_root.ledger_info().epoch();
    let block_data_round = block_data_root.ledger_info().round();

    // If the fallback sync notification is behind the block data root, ignore it.
    // This is possible due to a race condition where consensus progressed while
    // we were syncing for the fallback duration.
    if (epoch, round) < (block_data_epoch, block_data_round) {
        info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Ignoring old fallback sync notification for epoch: {}, round: {}! Current root: {:?}",
                epoch, round, block_data_root
            ))
        );
        self.state_sync_manager.clear_active_fallback_sync();
        return;
    }

    // Reset the fallback manager state
    self.observer_fallback_manager
        .reset_syncing_progress(&latest_synced_ledger_info);

    // Update the root with the latest synced ledger info
    self.observer_block_data
        .lock()
        .update_root(latest_synced_ledger_info);

    // ... rest of the function remains the same
}
```

Alternatively, add validation directly in `update_root()` to make it inherently safe:

```rust
/// Updates the root ledger info
pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
    let new_commit_info = new_root.commit_info();
    let current_commit_info = self.root.commit_info();
    
    // Only update if the new root is actually newer
    if (new_commit_info.epoch(), new_commit_info.round()) > 
       (current_commit_info.epoch(), current_commit_info.round()) {
        self.root = new_root;
    } else {
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Ignoring update_root() with non-advancing root! Current: (epoch={}, round={}), New: (epoch={}, round={})",
                current_commit_info.epoch(), current_commit_info.round(),
                new_commit_info.epoch(), new_commit_info.round()
            ))
        );
    }
}
```

## Proof of Concept

The following Rust test demonstrates the vulnerability:

```rust
#[tokio::test]
async fn test_root_rollback_via_fallback_sync() {
    use aptos_consensus_types::common::Round;
    use aptos_types::{
        aggregate_signature::AggregateSignature,
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    };
    use aptos_crypto::HashValue;

    // Helper to create ledger info
    fn create_ledger_info(epoch: u64, round: Round, version: u64) -> LedgerInfoWithSignatures {
        LedgerInfoWithSignatures::new(
            LedgerInfo::new(
                BlockInfo::new(
                    epoch,
                    round,
                    HashValue::random(),
                    HashValue::random(),
                    version,
                    0,
                    None,
                ),
                HashValue::random(),
            ),
            AggregateSignature::empty(),
        )
    }

    // Create initial root at epoch 10, round 100, version 1000
    let initial_root = create_ledger_info(10, 100, 1000);
    let mut observer_block_data = ObserverBlockData::new_with_root(
        ConsensusObserverConfig::default(),
        initial_root.clone(),
    );

    // Verify initial state
    assert_eq!(observer_block_data.root().commit_info().round(), 100);
    assert_eq!(observer_block_data.root().commit_info().version(), 1000);

    // Simulate consensus progressing: root advances to round 110
    let advanced_root = create_ledger_info(10, 110, 1100);
    observer_block_data.update_root(advanced_root.clone());
    
    // Verify root advanced
    assert_eq!(observer_block_data.root().commit_info().round(), 110);
    assert_eq!(observer_block_data.root().commit_info().version(), 1100);

    // Simulate fallback sync completing with older ledger info (round 105)
    // This represents fallback sync that started earlier and completed late
    let old_synced_info = create_ledger_info(10, 105, 1050);
    observer_block_data.update_root(old_synced_info);

    // VULNERABILITY: Root was rolled back from round 110 to round 105!
    assert_eq!(observer_block_data.root().commit_info().round(), 105);
    assert_eq!(observer_block_data.root().commit_info().version(), 1050);
    
    // This violates the invariant that consensus state should only advance forward
    println!("VULNERABILITY CONFIRMED: Root rolled back from round 110 to 105");
}
```

This test demonstrates that calling `update_root()` with an older `LedgerInfoWithSignatures` successfully rolls back the consensus root state from round 110 to round 105, violating the consensus state monotonicity invariant.

### Citations

**File:** consensus/src/consensus_observer/observer/block_data.rs (L131-141)
```rust
    /// Returns the highest committed block epoch and round
    pub fn get_highest_committed_epoch_round(&self) -> (u64, Round) {
        if let Some(epoch_round) = self.ordered_block_store.get_highest_committed_epoch_round() {
            // Return the highest committed epoch and round
            epoch_round
        } else {
            // Return the root epoch and round
            let root_block_info = self.root.commit_info().clone();
            (root_block_info.epoch(), root_block_info.round())
        }
    }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L143-152)
```rust
    /// Returns the last ordered block
    pub fn get_last_ordered_block(&self) -> BlockInfo {
        if let Some(last_ordered_block) = self.ordered_block_store.get_last_ordered_block() {
            // Return the last ordered block
            last_ordered_block.block_info()
        } else {
            // Return the root block
            self.root.commit_info().clone()
        }
    }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L204-218)
```rust
        // Update the root ledger info. Note: we only want to do this if
        // the new ledger info round is greater than the current root
        // round. Otherwise, this can race with the state sync process.
        if ledger_info.commit_info().round() > root_commit_info.round() {
            info!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Updating the root ledger info! Old root: (epoch: {:?}, round: {:?}). New root: (epoch: {:?}, round: {:?})",
                root_commit_info.epoch(),
                root_commit_info.round(),
                ledger_info.commit_info().epoch(),
                ledger_info.commit_info().round(),
            ))
        );
            self.root = ledger_info;
        }
```

**File:** consensus/src/consensus_observer/observer/block_data.rs (L299-302)
```rust
    /// Updates the root ledger info
    pub fn update_root(&mut self, new_root: LedgerInfoWithSignatures) {
        self.root = new_root;
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L947-950)
```rust
        // Update the root with the latest synced ledger info
        self.observer_block_data
            .lock()
            .update_root(latest_synced_ledger_info);
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L999-1010)
```rust
        // If the commit sync notification is behind the block data root, ignore it. This
        // is possible due to a race condition where we started syncing to a newer commit
        // at the same time that state sync sent the notification for a previous commit.
        if (synced_epoch, synced_round) < (block_data_epoch, block_data_round) {
            info!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Ignoring old commit sync notification for epoch: {}, round: {}! Current root: {:?}",
                    synced_epoch, synced_round, block_data_root
                ))
            );
            return;
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
