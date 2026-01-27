# Audit Report

## Title
Data Race Between State Sync and Consensus Commits Causes Version Skew in LedgerPrunerManager

## Summary
The `LedgerPrunerManager` maintains two version fields with different synchronization mechanisms: `latest_version` (protected by `Mutex`) and `min_readable_version` (atomic). The lack of coordinated updates between these fields allows a race condition where `min_readable_version` can exceed `latest_version`, causing the node to incorrectly reject all historical data as "pruned" and rendering the node unavailable for serving queries.

## Finding Description

The `LedgerPrunerManager` struct contains two critical version tracking fields with different concurrency control: [1](#0-0) 

The invariant that `min_readable_version ≤ latest_version` can be violated through unsynchronized writes from two execution paths:

**Path 1: Normal Consensus Commits** via `maybe_set_pruner_target_db_version()`: [2](#0-1) 

This updates `latest_version` under lock (line 67), then conditionally updates `min_readable_version` through `set_pruner_target_db_version()` (line 76) only if the check at lines 72-74 passes.

**Path 2: State Sync Snapshot Finalization** via `save_min_readable_version()`: [3](#0-2) 

This directly updates `min_readable_version` atomically without any synchronization with `latest_version`.

**The Race Condition:**

When `finalize_state_snapshot()` is called during state sync: [4](#0-3) 

It can race with concurrent consensus commits via `commit_ledger()`: [5](#0-4) 

Critically, `finalize_state_snapshot()` does NOT acquire the `commit_lock`, while `commit_ledger()` does: [6](#0-5) [7](#0-6) 

**Exploitation Timeline:**

1. Node is at version 5,000 from normal consensus operations
2. State sync initiates to apply a snapshot at version 20,000
3. Thread A (State Sync): Calls `finalize_state_snapshot(20000)` → `save_min_readable_version(20000)` → stores `min_readable_version = 20000`
4. Thread B (Consensus): Calls `commit_ledger(5001)` → `maybe_set_pruner_target_db_version(5001)`:
   - Sets `latest_version = 5001`
   - Reads `min_readable_version = 20000` (from step 3)
   - Check at line 73-74: `5001 >= 20000 + batch_size + prune_window` evaluates to FALSE
   - Does NOT call `set_pruner_target_db_version()`, leaving `min_readable_version` unchanged

**Final Invalid State:**
- `latest_version = 5001`
- `min_readable_version = 20000`
- **Invariant violation: `latest_version < min_readable_version`**

**Impact Propagation:**

All database read operations check against `min_readable_version`: [8](#0-7) 

With `min_readable_version = 20000` but actual data only up to version 5001:
- Every query for versions 0-19999 fails with "pruned" error
- The node cannot serve ANY of its actual historical data
- `get_first_txn_version()` incorrectly reports version 20000 as the first available: [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria:

**Validator Node Slowdowns / API Crashes:** The node becomes unable to serve historical queries, effectively causing partial unavailability. While the node can continue processing new transactions, it cannot:
- Serve historical transaction queries to clients
- Participate in state sync as a data source for other nodes
- Respond to archival queries from external systems

**Significant Protocol Violations:** The invariant that `min_readable_version ≤ latest_version` is fundamental to the correctness of the pruner system. Violating this creates an inconsistent view of data availability.

The impact falls short of **Critical** because:
- The node can still process new transactions and participate in consensus
- No loss of funds or consensus safety violation occurs
- The issue doesn't cause permanent data loss (restart may recover)
- It requires coordination failure between state sync and consensus paths

## Likelihood Explanation

**Likelihood: Medium to Low**

The vulnerability requires specific timing conditions:

**Prerequisites:**
1. Node must be undergoing state sync (snapshot finalization) 
2. Consensus must simultaneously attempt to commit new blocks
3. The application-level coordination between state sync and consensus must fail to enforce mutual exclusion

While the code comments indicate these paths "must hand over to each other," there is no storage-level enforcement: [10](#0-9) 

**Trigger Scenarios:**
- Node recovery from crash during active state sync
- Race conditions in state sync driver coordination logic
- Unexpected state transitions during epoch changes
- Fast sync operations concurrent with new block arrivals

The lack of defensive programming at the storage layer (no shared lock between `finalize_state_snapshot` and `commit_ledger`) means that any failure in the higher-level coordination can trigger this race.

## Recommendation

**Immediate Fix: Add Defensive Synchronization**

Ensure `min_readable_version` cannot be set to a value exceeding `latest_version`:

```rust
fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
    // Defensive check: never allow min_readable > latest
    let latest = *self.latest_version.lock();
    let safe_min_readable = std::cmp::min(min_readable_version, latest);
    
    self.min_readable_version
        .store(safe_min_readable, Ordering::SeqCst);

    PRUNER_VERSIONS
        .with_label_values(&["ledger_pruner", "min_readable"])
        .set(safe_min_readable as i64);

    self.ledger_db.write_pruner_progress(safe_min_readable)
}
```

**Alternative Fix: Unified Lock**

Have both fields protected by the same mutex to ensure atomic updates:

```rust
pub(crate) struct LedgerPrunerManager {
    // ... other fields ...
    /// Versions protected by single lock to prevent skew
    versions: Arc<Mutex<PrunerVersions>>,
}

struct PrunerVersions {
    latest: Version,
    min_readable: Version,
}
```

**Long-term Fix: Enforce Mutual Exclusion**

Ensure `finalize_state_snapshot` acquires the same `commit_lock` as `commit_ledger` to enforce the "handover" requirement at the storage level rather than relying on application-level coordination.

## Proof of Concept

```rust
#[test]
fn test_version_skew_race() {
    use std::sync::Arc;
    use std::thread;
    
    // Setup: Create LedgerPrunerManager with initial state
    let ledger_db = Arc::new(create_test_ledger_db());
    let config = LedgerPrunerConfig {
        enable: true,
        prune_window: 10000,
        batch_size: 100,
        user_pruning_window_offset: 0,
    };
    let manager = Arc::new(LedgerPrunerManager::new(
        ledger_db.clone(),
        config,
        None,
    ));
    
    // Simulate normal operation at version 5000
    manager.maybe_set_pruner_target_db_version(5000);
    
    let manager_clone = Arc::clone(&manager);
    
    // Thread 1: State sync finalizes snapshot at version 20000
    let handle1 = thread::spawn(move || {
        manager_clone.save_min_readable_version(20000).unwrap();
    });
    
    // Thread 2: Consensus commits at version 5001
    let handle2 = thread::spawn(move || {
        manager.maybe_set_pruner_target_db_version(5001);
    });
    
    handle1.join().unwrap();
    handle2.join().unwrap();
    
    // Verify invalid state
    let min_readable = manager.get_min_readable_version();
    let latest = *manager.latest_version.lock();
    
    // This assertion may fail, demonstrating the race
    assert!(
        min_readable <= latest,
        "Race condition detected: min_readable={} > latest={}",
        min_readable,
        latest
    );
}
```

## Notes

This vulnerability represents a **defense-in-depth** failure where the storage layer does not protect against misuse from the application layer. While the high-level design assumes mutual exclusion between state sync and consensus commits, the lack of enforcement at the storage level creates a fragile system susceptible to race conditions during crash recovery, coordination bugs, or unexpected state transitions.

The issue is exacerbated by the mixed synchronization primitives (`Mutex` for `latest_version` vs. `AtomicVersion` for `min_readable_version`) without coordinated updates between them.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L29-34)
```rust
    /// latest version
    latest_version: Arc<Mutex<Version>>,
    /// Offset for displaying to users
    user_pruning_window_offset: u64,
    /// The minimal readable version for the ledger data.
    min_readable_version: AtomicVersion,
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L66-78)
```rust
    fn maybe_set_pruner_target_db_version(&self, latest_version: Version) {
        *self.latest_version.lock() = latest_version;

        let min_readable_version = self.get_min_readable_version();
        // Only wake up the ledger pruner if there are `ledger_pruner_pruning_batch_size` pending
        // versions.
        if self.is_pruner_enabled()
            && latest_version
                >= min_readable_version + self.pruning_batch_size as u64 + self.prune_window
        {
            self.set_pruner_target_db_version(latest_version);
        }
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L80-89)
```rust
    fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["ledger_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.ledger_db.write_pruner_progress(min_readable_version)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L45-53)
```rust
        gauged_api("pre_commit_ledger", || {
            // Pre-committing and committing in concurrency is allowed but not pre-committing at the
            // same time from multiple threads, the same for committing.
            // Consensus and state sync must hand over to each other after all pending execution and
            // committing complete.
            let _lock = self
                .pre_commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L89-92)
```rust
            let _lock = self
                .commit_lock
                .try_lock()
                .expect("Concurrent committing detected.");
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L125-132)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
    ) -> Result<()> {
        let (output_with_proof, persisted_aux_info) = output_with_proof.into_parts();
        gauged_api("finalize_state_snapshot", || {
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L225-225)
```rust
            self.ledger_pruner.save_min_readable_version(version)?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L628-629)
```rust
            self.ledger_pruner
                .maybe_set_pruner_target_db_version(version);
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L329-333)
```rust
    fn get_first_txn_version(&self) -> Result<Option<Version>> {
        gauged_api("get_first_txn_version", || {
            Ok(Some(self.ledger_pruner.get_min_readable_version()))
        })
    }
```
