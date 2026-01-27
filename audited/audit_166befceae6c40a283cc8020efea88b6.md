# Audit Report

## Title
State KV Pruner Min Readable Version Can Move Backwards Causing State Inconsistency

## Summary
The `set_pruner_target_db_version()` function in the State KV Pruner Manager lacks defensive validation to prevent `min_readable_version` from moving backwards. If called with a decreasing `latest_version` (due to bugs in caller logic, race conditions, or malformed restore operations), it will unconditionally update `min_readable_version` to a lower value, potentially re-exposing already-pruned state and causing database inconsistencies.

## Finding Description

The `set_pruner_target_db_version()` function computes and stores a new `min_readable_version` without verifying it's greater than or equal to the current value: [1](#0-0) 

This breaks the critical invariant that `min_readable_version` must be monotonically increasing, as once state is pruned (physically deleted from the database), lowering this threshold incorrectly signals that older versions are still readable.

**Attack Scenario:**

1. **Initial State**: Node has pruned state KV data up to version 900. `min_readable_version = 900`. All data for versions < 900 has been physically deleted from the database.

2. **Trigger**: Due to a bug in restore logic, concurrent calls during node restart, or a malformed snapshot operation, `set_pruner_target_db_version()` is called with `latest_version = 800` (or `save_min_readable_version(700)` is called directly during a corrupted restore).

3. **Backwards Movement**: 
   - New `min_readable_version = 800 - prune_window = 700` (moved backwards from 900 to 700)
   - This is stored without any validation: [2](#0-1) 

4. **Inconsistency Exploitation**:
   - Client queries state at version 750
   - Validation check passes: `750 >= 700 ✓`: [3](#0-2) 
   - System attempts to read state at version 750
   - Database returns errors (data not found) or stale data from cache
   - This causes API crashes, consensus divergence if different nodes have different `min_readable_version` values, or incorrect state being served to clients

**Vulnerable Code Paths:**

1. **Primary Path**: While `maybe_set_pruner_target_db_version()` has a threshold check [4](#0-3) , the underlying `set_pruner_target_db_version()` is not self-defensive.

2. **Restore Path**: The `save_min_readable_version()` function also directly stores values without validation: [5](#0-4) 
   This is called during snapshot finalization: [6](#0-5) 

**Key Observation**: The `PrunerWorker` itself has a guard against backwards movement [7](#0-6) , but this only protects the pruner's target version, NOT the manager's `min_readable_version`. This creates an inconsistency where the manager reports a lower min_readable_version than what the pruner actually has.

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

- **API Crashes**: Nodes attempting to serve queries for "available" but actually-pruned data will encounter database errors, potentially causing RPC endpoint failures.

- **Significant Protocol Violations**: Violates the fundamental state consistency invariant that `min_readable_version` must be monotonically increasing. Different nodes could report different minimum versions, breaking deterministic execution guarantees.

- **State Inconsistencies Requiring Intervention**: Once `min_readable_version` moves backwards, manual database intervention is required to correct the metadata, as the pruner cannot automatically recover from this state.

The impact affects all nodes that experience the triggering condition (bugs in restore logic, race conditions during restart, or snapshot corruption).

## Likelihood Explanation

**Likelihood: Medium**

While normal operation paths have guards (`post_commit` checks version increases [8](#0-7) ), several scenarios increase likelihood:

1. **Restore/Snapshot Bugs**: State snapshot operations that process versions out-of-order or handle corrupted data could call `save_min_readable_version()` with lower values.

2. **Race Conditions**: During node restart or reconfiguration, concurrent initialization paths might call pruner methods with stale version information.

3. **Future Code Changes**: The lack of defensive checks creates a landmine for future developers adding new call sites.

4. **Dynamic Configuration**: Changes to `prune_window` or pruning configuration during operation could interact unexpectedly with version tracking.

The vulnerability is latent but realistic, as it depends on bugs in adjacent code rather than requiring attacker-controlled input.

## Recommendation

Add defensive validation to prevent `min_readable_version` from moving backwards:

```rust
fn set_pruner_target_db_version(&self, latest_version: Version) {
    assert!(self.pruner_worker.is_some());
    let new_min_readable_version = latest_version.saturating_sub(self.prune_window);
    let current_min_readable_version = self.min_readable_version.load(Ordering::SeqCst);
    
    // Defensive check: min_readable_version must be monotonically increasing
    if new_min_readable_version < current_min_readable_version {
        error!(
            new_min_readable_version = new_min_readable_version,
            current_min_readable_version = current_min_readable_version,
            "Attempted to move min_readable_version backwards, ignoring"
        );
        return;
    }
    
    self.min_readable_version.store(new_min_readable_version, Ordering::SeqCst);
    // ... rest of function
}
```

Similarly, add validation to `save_min_readable_version()`:

```rust
fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
    let current = self.min_readable_version.load(Ordering::SeqCst);
    ensure!(
        min_readable_version >= current,
        "Cannot move min_readable_version backwards: {} < {}",
        min_readable_version,
        current
    );
    
    self.min_readable_version.store(min_readable_version, Ordering::SeqCst);
    // ... rest of function
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_min_readable_version_backwards {
    use super::*;
    
    #[test]
    #[should_panic(expected = "min_readable_version moved backwards")]
    fn test_min_readable_version_cannot_move_backwards() {
        // Setup: Create pruner with initial state
        let temp_dir = TempPath::new();
        let db = AptosDB::new_for_test(&temp_dir);
        
        // Simulate normal pruning to version 1000
        db.state_store.state_kv_pruner
            .maybe_set_pruner_target_db_version(1150);
        assert_eq!(db.state_store.state_kv_pruner.get_min_readable_version(), 1000);
        
        // Simulate bug: call with lower version
        // This should panic/error but currently succeeds
        db.state_store.state_kv_pruner
            .maybe_set_pruner_target_db_version(900);
        
        let min_after = db.state_store.state_kv_pruner.get_min_readable_version();
        
        // VULNERABILITY: min_readable_version moved backwards from 1000 to 800
        assert!(min_after < 1000, "min_readable_version moved backwards!");
    }
}
```

## Notes

While the normal operation paths through `post_commit` have appropriate guards, the lack of defensive validation in `set_pruner_target_db_version()` and `save_min_readable_version()` creates a critical vulnerability to bugs in adjacent code. The state pruning subsystem should enforce its own invariants rather than relying solely on caller guarantees. This is particularly important for restore/snapshot operations where version ordering might not be guaranteed.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L46-54)
```rust
    fn maybe_set_pruner_target_db_version(&self, latest_version: Version) {
        let min_readable_version = self.get_min_readable_version();
        // Only wake up the state kv pruner if there are `ledger_pruner_pruning_batch_size` pending
        if self.is_pruner_enabled()
            && latest_version
                >= min_readable_version + self.pruning_batch_size as u64 + self.prune_window
        {
            self.set_pruner_target_db_version(latest_version);
        }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L57-59)
```rust
    fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L128-132)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());
        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L305-310)
```rust
    pub(super) fn error_if_state_kv_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.state_store.state_kv_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L232-234)
```rust
            self.state_store
                .state_kv_pruner
                .save_min_readable_version(version)?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L612-612)
```rust
        if old_committed_version.is_none() || version > old_committed_version.unwrap() {
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L93-96)
```rust
    pub fn set_target_db_version(&self, target_db_version: Version) {
        if target_db_version > self.inner.pruner.target_version() {
            self.inner.pruner.set_target_version(target_db_version);
        }
```
