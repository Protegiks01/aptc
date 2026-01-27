# Audit Report

## Title
Non-Atomic State Proof Verification and Value Retrieval in DbStateView

## Summary
The `DbStateView::get()` method performs two separate, non-atomic database reads when proof verification is enabled: one to retrieve and verify the Merkle proof, and another to fetch the actual state value. This creates a theoretical time-of-check-time-of-use (TOCTOU) race condition where the verified proof and returned value could correspond to different database states.

## Finding Description

In `DbStateView::get()`, when `maybe_verify_against_state_root_hash` is configured (verified mode), the implementation performs proof verification and value retrieval as two distinct operations: [1](#0-0) 

The flow is:
1. **First database call** (line 34-38): Invokes `get_state_value_with_proof_by_version(key, version)` which internally:
   - Reads from the Jellyfish Merkle tree [2](#0-1) 
   - Fetches the state value from the KV store
   - Returns both value and cryptographic proof
   - Verifies the proof against `root_hash`

2. **Second database call** (line 40-42): Invokes `get_state_value_with_version_by_version(key, version)` which:
   - Independently queries the state KV database [3](#0-2) 
   - Returns this value to the caller

**The Critical Issue**: The value returned from the second call may differ from the value whose proof was verified in the first call. Between these two operations:

- Background pruning threads could delete historical state versions [4](#0-3) 
- RocksDB compaction or other database operations could modify the physical data layout
- Without explicit snapshot isolation, each database read sees an independent view of the database

This violates the fundamental security invariant: **"State transitions must be atomic and verifiable via Merkle proofs"** (Invariant #4).

## Impact Explanation

After thorough analysis, this issue qualifies as **MEDIUM severity** under the Aptos Bug Bounty program criteria: "State inconsistencies requiring intervention."

However, the practical impact is significantly limited by several mitigating factors:

1. **Narrow Race Window**: The two database calls occur microseconds apart, making the race window extremely small
2. **Pruning Characteristics**: The background pruner operates on old versions in batches and moves slowly based on configured prune windows (typically 100,000+ versions)
3. **Usage Context**: `verified_state_view_at_version` is primarily used for serving API queries and historical state access, not for consensus-critical transaction execution
4. **Versioned Immutability**: In the versioned database model, historical versions are immutable; only pruning can delete them, and concurrent commits don't affect old version reads

The vulnerability does NOT directly enable:
- Consensus safety violations (validators execute at current version with buffered state, not through this path)
- Fund theft or loss
- Network partition or liveness failures

The most realistic impact is potential API inconsistencies or errors when querying historical state near prune boundaries.

## Likelihood Explanation

**Low likelihood** of triggering in production:
- Requires querying historical state at a version very close to the prune boundary
- Requires precise timing where pruning occurs between the two database calls (microsecond window)
- Modern RocksDB implementations provide significant buffering that reduces the likelihood of observable differences

**Not exploitable** by external attackers:
- Attackers cannot directly control pruning timing
- Attackers cannot force specific race conditions through API calls
- The issue manifests randomly due to system timing, not attacker manipulation

## Recommendation

Implement atomic proof+value retrieval using RocksDB snapshots:

```rust
fn get(&self, key: &StateKey) -> StateViewResult<Option<(Version, StateValue)>> {
    if let Some(version) = self.version {
        if let Some(root_hash) = self.maybe_verify_against_state_root_hash {
            // Create a RocksDB snapshot for atomic read
            let snapshot = self.db.get_snapshot();
            
            // Perform BOTH operations using the same snapshot
            let (value_with_proof, proof) = 
                self.db.get_state_value_with_proof_by_version_snapshot(&snapshot, key, version)?;
            proof.verify(root_hash, *key.crypto_hash_ref(), value_with_proof.as_ref())?;
            
            // Return the SAME value that was verified, not a separate query
            Ok(value_with_proof.map(|v| (version, v)))
        } else {
            Ok(self.db.get_state_value_with_version_by_version(key, version)?)
        }
    } else {
        Ok(None)
    }
}
```

Alternatively, refactor to return the verified value from the first call rather than making a redundant second call.

## Proof of Concept

Due to the timing-dependent nature and low likelihood, a reliable PoC is challenging to construct. However, the race can be demonstrated conceptually:

```rust
// Theoretical PoC (pseudocode - actual implementation would require
// precise timing control and pruner manipulation)

#[test]
fn test_dbstateview_race_condition() {
    // Setup: Database with historical state at version 100
    let (db, state_view) = setup_db_at_version(100);
    
    // Configure pruning to be very aggressive (keep only last 10 versions)
    db.set_prune_window(10);
    
    // Simulate concurrent operations:
    thread::spawn(|| {
        // Thread 1: Query historical state
        let result = state_view.get(&state_key_at_version_95);
        // First call succeeds, proof verified for value V
        // Second call MAY fail if pruning happened in between
        assert!(result.is_ok()); // May fail if race occurs
    });
    
    thread::spawn(|| {
        // Thread 2: Aggressive pruning
        pruner.prune_up_to_version(99); // Deletes version 95
    });
}
```

**Notes**

After rigorous analysis against the validation checklist, this finding does not meet the stringent criteria for a HIGH severity exploitable vulnerability:

- ❌ Not exploitable by unprivileged attackers (no attack vector for timing manipulation)
- ❌ Attack path is not realistic under normal operation
- ⚠️ Impact is limited to potential API inconsistencies, not consensus or fund safety

While the code does exhibit non-atomic behavior that theoretically violates the state consistency invariant, the practical security impact is minimal due to:
1. Extremely small race window (microseconds)
2. Slow-moving pruner operating on old versions
3. Usage context limited to non-consensus-critical API queries
4. Graceful error handling in the system

This is more appropriately classified as a **code quality issue** rather than a critical security vulnerability. The recommendation to use RocksDB snapshots would eliminate even the theoretical race condition and improve code correctness, but the current implementation does not pose an imminent security threat to the Aptos network.

### Citations

**File:** storage/storage-interface/src/state_store/state_view/db_state_view.rs (L27-46)
```rust
    fn get(&self, key: &StateKey) -> StateViewResult<Option<(Version, StateValue)>> {
        if let Some(version) = self.version {
            if let Some(root_hash) = self.maybe_verify_against_state_root_hash {
                // TODO(aldenhu): sample-verify proof inside DB
                // DB doesn't support returning proofs for buffered state, so only optionally
                // verify proof.
                // TODO: support returning state proof for buffered state.
                if let Ok((value, proof)) =
                    self.db.get_state_value_with_proof_by_version(key, version)
                {
                    proof.verify(root_hash, *key.crypto_hash_ref(), value.as_ref())?;
                }
            }
            Ok(self
                .db
                .get_state_value_with_version_by_version(key, version)?)
        } else {
            Ok(None)
        }
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L209-236)
```rust
    fn get_state_value_with_proof_by_version_ext(
        &self,
        key_hash: &HashValue,
        version: Version,
        root_depth: usize,
        use_hot_state: bool,
    ) -> Result<(Option<StateValue>, SparseMerkleProofExt)> {
        let db = if use_hot_state {
            if self.state_merkle_db.sharding_enabled() {
                self.hot_state_merkle_db
                    .as_ref()
                    .ok_or(AptosDbError::HotStateError)?
            } else {
                // Unsharded unit tests still rely on this.
                &self.state_merkle_db
            }
        } else {
            &self.state_merkle_db
        };
        let (leaf_data, proof) = db.get_with_proof_ext(key_hash, version, root_depth)?;
        Ok((
            match leaf_data {
                Some((_val_hash, (key, ver))) => Some(self.expect_value_by_version(&key, ver)?),
                None => None,
            },
            proof,
        ))
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L374-402)
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
    }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L47-72)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
    ) -> Result<()> {
        let mut batch = SchemaBatch::new();

        let mut iter = self
            .db_shard
            .iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&current_progress)?;
        for item in iter {
            let (index, _) = item?;
            if index.stale_since_version > target_version {
                break;
            }
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
        }
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
            &DbMetadataValue::Version(target_version),
        )?;

        self.db_shard.write_schemas(batch)
    }
```
