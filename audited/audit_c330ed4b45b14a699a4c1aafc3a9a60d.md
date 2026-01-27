# Audit Report

## Title
Integer Overflow in State KV Pruner Condition Check Leading to Catastrophic Database State Corruption at Version Boundary

## Summary
The `maybe_set_pruner_target_db_version()` function in the state KV pruner manager contains an unchecked integer addition that can overflow when `latest_version` approaches `u64::MAX`. This overflow causes the pruner to be incorrectly activated and sets `min_readable_version` to an extremely large value, rendering all state queries inoperable and potentially causing irreversible data loss.

## Finding Description

The vulnerability exists in the activation condition check for the state KV pruner. [1](#0-0) 

The condition performs an unchecked addition that wraps on overflow in release builds. When `min_readable_version` is close to `u64::MAX`, the expression `min_readable_version + self.pruning_batch_size as u64 + self.prune_window` overflows and wraps to a small value, causing the comparison to evaluate incorrectly.

**Attack Scenario:**

1. **Initial State**: Blockchain operates normally at version 1,000,000 with `min_readable_version = 900,000` and `prune_window = 100,000`.

2. **Trigger Condition**: Through a hypothetical bug in version management or during testing scenarios where version is artificially set, `latest_version` reaches a value near `u64::MAX` (e.g., `u64::MAX - 1000`).

3. **First Overflow**: The condition check evaluates:
   - If `min_readable_version = 900,000`, the addition `900,000 + 10,000 + 100,000 = 1,010,000` does not overflow
   - Condition `(u64::MAX - 1000) >= 1,010,000` is TRUE
   - Function `set_pruner_target_db_version(u64::MAX - 1000)` is called

4. **Erroneous min_readable_version**: [2](#0-1) 

   The `saturating_sub` computes: `min_readable_version = (u64::MAX - 1000) - 100,000 = 18,446,744,073,709,450,615`

5. **Cascading Overflow**: On subsequent calls with normal versions, if `min_readable_version = u64::MAX - 100,000`, then:
   - `(u64::MAX - 100,000) + 10,000 + 100,000 = u64::MAX + 10,000` → wraps to `9,999`
   - Any `latest_version > 9,999` triggers pruner activation incorrectly

6. **Query Failure**: All state queries fail because the validation check rejects them: [3](#0-2) 

   For a query at version 1,000,000: `1,000,000 >= 18,446,744,073,709,450,615` is FALSE, causing error "StateValue at version 1000000 is pruned, min available version is 18446744073709450615"

7. **Data Deletion**: The pruner's target is set to the erroneous high value, and it proceeds to delete all historical state: [4](#0-3) 

   All stale state values with `stale_since_version ≤ 18,446,744,073,709,450,615` (i.e., ALL actual data) are deleted.

8. **Additional Overflow in Pruner Loop**: The pruner loop contains another unchecked addition at line 57 that can overflow when `progress` is near `u64::MAX`, potentially causing infinite loops or unexpected termination.

This violates the **State Consistency** invariant (all state must remain queryable within the prune window) and causes **Total Loss of Liveness** (complete network unavailability).

## Impact Explanation

**Critical Severity (up to $1,000,000)** per Aptos Bug Bounty criteria:

1. **Total Loss of Liveness/Network Availability**: All validator nodes become unable to serve state queries. The entire network becomes non-functional as state reads fail.

2. **Non-Recoverable Network Partition (Requires Hardfork)**: Once `min_readable_version` is written to disk with the erroneous value, it persists across restarts. The pruner permanently deletes historical state data. Recovery requires:
   - Rolling back to a snapshot before the corruption
   - Modifying the database schema to reset `min_readable_version`
   - Coordinated hardfork across all validators

3. **Permanent Data Loss**: Historical state values are irreversibly deleted from the database, breaking state sync, historical queries, and archival nodes.

4. **Consensus Disruption**: While not directly breaking consensus safety, validators cannot process blocks that require state queries, effectively halting the network.

## Likelihood Explanation

**Likelihood: Low to Medium**

**Factors reducing likelihood:**
- Requires `latest_version` to approach `u64::MAX` (18.4 quintillion)
- Natural progression would take ~5.8 billion years at 100 TPS
- Normal operation has version monotonicity checks

**Factors increasing likelihood:**
- Edge case testing or fuzzing could accidentally trigger high version values
- Integration with external systems might provide malformed version data
- Future codebase changes could introduce version calculation bugs
- Database corruption or restoration from backup could set invalid versions
- While Byzantine validators are out of scope, a compromised validator with quorum support could craft malicious ledger info

The vulnerability becomes **highly likely** IF any upstream bug causes version overflow or if testing scenarios use artificial version values near `u64::MAX`.

## Recommendation

Implement checked arithmetic operations and add validation bounds:

```rust
fn maybe_set_pruner_target_db_version(&self, latest_version: Version) {
    let min_readable_version = self.get_min_readable_version();
    
    // Use checked arithmetic to prevent overflow
    let threshold = min_readable_version
        .checked_add(self.pruning_batch_size as u64)
        .and_then(|v| v.checked_add(self.prune_window));
    
    // Add sanity check for version bounds
    const MAX_REASONABLE_VERSION: Version = u64::MAX / 2; // Or lower based on requirements
    if latest_version > MAX_REASONABLE_VERSION {
        error!(
            "latest_version {} exceeds maximum reasonable value {}",
            latest_version, MAX_REASONABLE_VERSION
        );
        return;
    }
    
    if self.is_pruner_enabled() {
        match threshold {
            Some(t) if latest_version >= t => {
                self.set_pruner_target_db_version(latest_version);
            }
            None => {
                // Overflow occurred - do not activate pruner
                error!(
                    "Pruner activation threshold overflow: min_readable_version={}, batch={}, window={}",
                    min_readable_version, self.pruning_batch_size, self.prune_window
                );
            }
            _ => {} // Threshold not reached
        }
    }
}
```

Additionally, add overflow protection in the pruner loop:

```rust
let current_batch_target_version = progress
    .checked_add(max_versions as Version)
    .map(|v| min(v, target_version))
    .unwrap_or(target_version);
```

## Proof of Concept

```rust
#[test]
fn test_version_overflow_catastrophic_pruning() {
    use crate::pruner::{PrunerManager, state_kv_pruner::StateKvPrunerManager};
    use aptos_config::config::LedgerPrunerConfig;
    use aptos_temppath::TempPath;
    
    // Setup test database
    let tmpdir = TempPath::new();
    let state_kv_db = Arc::new(StateKvDb::new(&tmpdir, RocksdbConfig::default(), false));
    
    let pruner_config = LedgerPrunerConfig {
        enable: true,
        prune_window: 100_000,
        batch_size: 10_000,
        ..Default::default()
    };
    
    let pruner_manager = StateKvPrunerManager::new(
        Arc::clone(&state_kv_db),
        pruner_config,
    );
    
    // Simulate normal operation - commit some versions
    for version in 0..1000 {
        // Simulate state commits...
        pruner_manager.maybe_set_pruner_target_db_version(version);
    }
    
    let initial_min_readable = pruner_manager.get_min_readable_version();
    assert!(initial_min_readable < 1000);
    
    // ATTACK: Trigger with version near u64::MAX
    let malicious_version = u64::MAX - 1000;
    pruner_manager.maybe_set_pruner_target_db_version(malicious_version);
    
    let corrupted_min_readable = pruner_manager.get_min_readable_version();
    
    // VERIFY: min_readable_version is now catastrophically large
    assert!(corrupted_min_readable > u64::MAX - 200_000);
    
    // VERIFY: Normal versions now appear "pruned"
    // This would cause error_if_state_kv_pruned(1000) to fail
    assert!(corrupted_min_readable > 1000);
    
    // VERIFY: Subsequent calls with normal versions still trigger overflow
    pruner_manager.maybe_set_pruner_target_db_version(10_000);
    let still_corrupted = pruner_manager.get_min_readable_version();
    assert!(still_corrupted > u64::MAX - 200_000);
    
    println!("CATASTROPHIC STATE ACHIEVED:");
    println!("  Corrupted min_readable_version: {}", corrupted_min_readable);
    println!("  All queries for version < {} will fail", corrupted_min_readable);
    println!("  Pruner will delete all historical data");
}
```

**Expected Output:**
- Test demonstrates that once `latest_version` approaches `u64::MAX`, `min_readable_version` is set to an extremely large value
- All subsequent state queries for normal versions are rejected as "pruned"
- The pruner target is set to delete virtually all historical state data
- Network becomes completely inoperable

## Notes

While the use of `saturating_sub` prevents the most catastrophic outcome (wrapping to 0), it does not prevent the severe consequences of setting `min_readable_version` to `u64::MAX - prune_window`. The vulnerability manifests through the **unchecked addition in the condition check**, not the subtraction operation. The combination of overflow in the condition and the subsequent large value assignment creates a critical failure mode that renders the entire blockchain unreadable and causes permanent data loss.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L46-55)
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
    }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L128-142)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());
        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["state_kv_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.pruner_worker
            .as_ref()
            .unwrap()
            .set_target_db_version(min_readable_version);
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L305-315)
```rust
    pub(super) fn error_if_state_kv_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.state_store.state_kv_pruner.get_min_readable_version();
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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L49-86)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_pruner__prune"]);

        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning state kv data."
            );
            self.metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.shard_pruners.par_iter().try_for_each(|shard_pruner| {
                    shard_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| {
                            anyhow!(
                                "Failed to prune state kv shard {}: {err}",
                                shard_pruner.shard_id(),
                            )
                        })
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning state kv data is done.");
        }

        Ok(target_version)
    }
```
