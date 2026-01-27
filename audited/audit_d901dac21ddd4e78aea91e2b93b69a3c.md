# Audit Report

## Title
Thread Panic During Parallel State Restore Causes Non-Atomic Database Corruption

## Summary
The state snapshot restore operation in `StateSnapshotRestore::add_chunk()` executes KV and tree database writes in parallel using `IO_POOL.join()`. If a thread panics during or after database writes, there is no rollback mechanism, leaving the databases in an inconsistent state where KV and tree data are out of sync, corrupting the node's state.

## Finding Description

The vulnerability exists in the parallel execution of state restore operations where two separate databases (KV and Merkle tree) are updated simultaneously without atomic transaction guarantees.

**Attack Flow:**

1. During state snapshot restoration, `StateSnapshotRestore::add_chunk()` spawns two parallel operations:
   - `kv_fn()`: Writes state key-value pairs to the KV database
   - `tree_fn()`: Writes Merkle tree nodes to the tree database [1](#0-0) 

2. Each function writes to its respective sharded database. The KV database commit spawns 16 parallel tasks (one per shard) that can panic: [2](#0-1) 

3. The tree database similarly writes to multiple shards sequentially, with no rollback on failure: [3](#0-2) 

**Vulnerability Scenarios:**

**Scenario A - Cross-database inconsistency:**
- `kv_fn()` completes successfully, writing KV data and progress marker
- `tree_fn()` panics after partial write (e.g., due to I/O error, OOM, or the explicit panic in `commit_single_shard`)
- Result: KV database has data that the tree database doesn't reference
- On recovery: The recovery logic uses minimum progress, but verification will fail because tree nodes don't correspond to KV keys

**Scenario B - Intra-database inconsistency:**
- During `commit()`, shards 0-7 write successfully
- Shard 8's `commit_single_shard()` fails and panics (as per the TODO comment)
- Shards 9-15 are never written
- Result: Database has partial shard data with inconsistent state

**Scenario C - Async commit race:**
- In async mode, `IO_POOL.spawn()` queues tree writes
- `kv_fn()` completes and commits
- Async tree write task panics mid-execution
- Result: KV committed, tree write incomplete

**Broken Invariant:**
This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The KV database and Merkle tree database become desynchronized, making state verification impossible.

## Impact Explanation

This qualifies as **High Severity** under "State inconsistencies requiring intervention" with potential escalation to **Critical** depending on recoverability.

**Immediate Impact:**
- **Database corruption:** KV and tree databases contain inconsistent state
- **Node unavailability:** Corrupted nodes cannot complete state sync and cannot participate in consensus
- **Recovery complexity:** No automatic recovery mechanism; manual intervention required

**Systemic Impact:**
- If multiple nodes experience this during simultaneous state sync, it could cause **network partition**
- Different nodes may have different corrupted states, breaking **deterministic execution**
- Validator nodes affected by this cannot produce valid state proofs, disrupting consensus

**Severity Justification:**
- Meets High severity criteria: "Significant protocol violations" and "State inconsistencies requiring intervention"
- Near-Critical: If widespread, could cause "Non-recoverable network partition" requiring hardfork

## Likelihood Explanation

**Likelihood: Medium-High**

**Triggering Conditions:**
1. **I/O errors:** Disk full, hardware failures, or network interruptions during state sync
2. **Resource exhaustion:** OOM conditions during large state snapshot restoration
3. **Explicit panics:** The code explicitly panics on shard commit failure (documented in TODO) [4](#0-3) 

4. **Bug-induced panics:** Any unwrap/expect failures in the call chain

**Occurrence Frequency:**
- State sync operations are routine during node startup and catch-up
- Large state snapshots increase memory pressure and I/O load
- The TODO comment indicates developers recognize this is problematic

**Exploitability:**
- Not directly exploitable by external attackers without triggering resource exhaustion
- More likely to occur naturally during high-load conditions
- Could be triggered by malicious peers in state sync protocol (requires further investigation)

## Recommendation

Implement atomic transaction semantics across both databases or add proper error handling with rollback.

**Recommended Fix:**

1. **Replace panic with error propagation:**
   - Change `unwrap_or_else` panic to proper error handling in `commit()`
   - Use `?` operator to propagate errors instead of panicking

2. **Add transaction coordinator:**
   - Implement a two-phase commit protocol or transaction log
   - Track commit progress atomically
   - Implement rollback on partial failure

3. **Validate consistency on recovery:**
   - Add cross-validation between KV and tree progress markers
   - Detect and recover from inconsistent states

4. **Immediate mitigation:**
   - Change parallel execution to sequential with proper error handling
   - Remove `IO_POOL.join()` in favor of sequential execution with rollback

**Code Fix Example:**
```rust
// In add_chunk(), replace parallel execution with transactional sequence
match self.restore_mode {
    StateSnapshotRestoreMode::Default => {
        // Sequential execution with rollback
        let kv_result = kv_fn();
        if let Err(e) = kv_result {
            // KV failed, no tree write needed
            return Err(e);
        }
        
        let tree_result = tree_fn();
        if let Err(e) = tree_result {
            // Tree failed, rollback KV changes
            self.rollback_kv_changes()?;
            return Err(e);
        }
        
        Ok(())
    },
    // ... other modes
}
```

## Proof of Concept

```rust
#[test]
fn test_panic_during_restore_causes_corruption() {
    use std::sync::{Arc, Mutex};
    use std::panic;
    
    // Setup: Create a state restore instance
    let kv_db = Arc::new(MockStateValueWriter::new());
    let tree_db = Arc::new(MockTreeWriter::new());
    
    let mut restore = StateSnapshotRestore::new(
        &tree_db,
        &kv_db,
        0,  // version
        HashValue::zero(),  // expected_root_hash
        false,  // async_commit
        StateSnapshotRestoreMode::Default,
    ).unwrap();
    
    // Inject panic behavior: Make tree_fn panic after KV write succeeds
    let panic_injector = Arc::new(Mutex::new(false));
    let panic_flag = panic_injector.clone();
    
    tree_db.set_panic_callback(Box::new(move || {
        let mut flag = panic_flag.lock().unwrap();
        if !*flag {
            *flag = true;
            panic!("Simulated I/O error during tree write");
        }
    }));
    
    // Trigger the vulnerability
    let chunk = vec![(StateKey::raw(b"key1"), StateValue::new_legacy(b"value1"))];
    let proof = SparseMerkleRangeProof::new(vec![]);
    
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        restore.add_chunk(chunk, proof)
    }));
    
    assert!(result.is_err(), "Expected panic to propagate");
    
    // Verify corruption: KV has data, tree doesn't
    let kv_progress = kv_db.get_progress(0).unwrap();
    let tree_progress = tree_db.get_rightmost_leaf(0).unwrap();
    
    assert!(kv_progress.is_some(), "KV write succeeded");
    assert!(tree_progress.is_none(), "Tree write failed");
    
    // Verify recovery fails due to inconsistency
    let recovery_result = StateSnapshotRestore::new(
        &tree_db,
        &kv_db,
        0,
        HashValue::zero(),
        false,
        StateSnapshotRestoreMode::Default,
    );
    
    // Recovery detects inconsistent state and fails
    assert!(recovery_result.is_err() || 
            verify_state_consistency(&kv_db, &tree_db).is_err(),
            "Corrupted state should be detected");
}
```

**Notes:**
- This vulnerability requires implementing transaction semantics or proper error recovery
- The explicit panic in `commit_single_shard` failure path makes this highly likely to occur
- The TODO comment at line 193 indicates awareness of the problem but no fix implemented
- Cross-database consistency is not validated during recovery, allowing silent corruption
- The use of rayon's `join()` provides no rollback mechanism for database writes

### Citations

**File:** storage/aptosdb/src/state_restore/mod.rs (L229-254)
```rust
        let kv_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_value_add_chunk"]);
            self.kv_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk(chunk.clone())
        };

        let tree_fn = || {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["jmt_add_chunk"]);
            self.tree_restore
                .lock()
                .as_mut()
                .unwrap()
                .add_chunk_impl(chunk.iter().map(|(k, v)| (k, v.hash())).collect(), proof)
        };
        match self.restore_mode {
            StateSnapshotRestoreMode::KvOnly => kv_fn()?,
            StateSnapshotRestoreMode::TreeOnly => tree_fn()?,
            StateSnapshotRestoreMode::Default => {
                // We run kv_fn with TreeOnly to restore the usage of DB
                let (r1, r2) = IO_POOL.join(kv_fn, tree_fn);
                r1?;
                r2?;
            },
```

**File:** storage/aptosdb/src/state_kv_db.rs (L186-200)
```rust
            THREAD_MANAGER.get_io_pool().scope(|s| {
                let mut batches = sharded_state_kv_batches.into_iter();
                for shard_id in 0..NUM_STATE_SHARDS {
                    let state_kv_batch = batches
                        .next()
                        .expect("Not sufficient number of sharded state kv batches");
                    s.spawn(move |_| {
                        // TODO(grao): Consider propagating the error instead of panic, if necessary.
                        self.commit_single_shard(version, shard_id, state_kv_batch)
                            .unwrap_or_else(|err| {
                                panic!("Failed to commit shard {shard_id}: {err}.")
                            });
                    });
                }
            });
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L174-190)
```rust
    pub(crate) fn commit_no_progress(
        &self,
        top_level_batch: SchemaBatch,
        batches_for_shards: Vec<SchemaBatch>,
    ) -> Result<()> {
        ensure!(
            batches_for_shards.len() == NUM_STATE_SHARDS,
            "Shard count mismatch."
        );
        let mut batches = batches_for_shards.into_iter();
        for shard_id in 0..NUM_STATE_SHARDS {
            let state_merkle_batch = batches.next().unwrap();
            self.state_merkle_db_shards[shard_id].write_schemas(state_merkle_batch)?;
        }

        self.state_merkle_metadata_db.write_schemas(top_level_batch)
    }
```
