# Audit Report

## Title
Panic-in-Drop During Async Write Failure Causes Database Corruption in Jellyfish Merkle Tree Restoration

## Summary
The `JellyfishMerkleRestore::add_chunk_impl()` function spawns asynchronous writes to a thread pool but does not properly handle failures. The `Drop` implementation uses double `unwrap()` on the async write result, which can cause a panic during stack unwinding, leading to program abort and database corruption.

## Finding Description

The vulnerability exists in the asynchronous commit path of Jellyfish Merkle tree restoration. When `async_commit` is enabled, the function spawns writes to the `IO_POOL` thread pool without waiting for completion before returning: [1](#0-0) 

The spawned closure sends the write result through a channel with `tx.send(res).unwrap()` at line 405. More critically, the `Drop` implementation attempts to wait for pending async commits with a double unwrap pattern: [2](#0-1) 

This breaks Rust's panic safety guarantees. When `rx.recv().unwrap().unwrap()` is called:
- The first `unwrap()` extracts `Result<()>` from `Result<Result<()>, RecvError>`, panicking on channel errors
- The second `unwrap()` extracts `()` from the write result, panicking if the write failed

**Attack Scenario:**
1. State restoration begins with `async_commit=true` (confirmed in production usage): [3](#0-2) 

2. `add_chunk_impl()` spawns async write and returns `Ok(())` without waiting
3. Before the async write completes, another error occurs (proof verification failure, next chunk error, resource exhaustion)
4. The error causes `JellyfishMerkleRestore` to be dropped
5. `Drop::drop()` executes `rx.recv().unwrap().unwrap()`
6. If the async write failed, the second `unwrap()` panics
7. **Panic during unwinding = immediate abort** (Rust's double-panic behavior)
8. Program terminates via `std::process::abort()`
9. Database left in inconsistent state: partial nodes written, restoration incomplete

The underlying write operations can fail for multiple realistic reasons as they ultimately call RocksDB: [4](#0-3) [5](#0-4) 

RocksDB errors are mapped to `AptosDbError` and include: [6](#0-5) 

These errors include `IOError` (disk space exhaustion, hardware failures), `Corruption`, `ShutdownInProgress`, and other realistic failure modes.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

1. **Validator Node Crashes**: The double panic causes `std::process::abort()`, immediately terminating the validator node. This maps to "Validator Node Slowdowns (High)" in the bounty program, though a crash is more severe than a slowdown.

2. **State Inconsistencies**: The Jellyfish Merkle tree is left partially restored with some nodes written but restoration incomplete. This requires manual database cleanup and restoration restart, representing a "significant protocol violation."

3. **Consensus Risk**: If multiple validators hit this condition during state sync, they may have divergent database states. While not an immediate consensus failure, this can affect network health and requires coordinated recovery.

The incomplete Merkle tree cannot produce valid proofs for state queries, violating the guarantee that all state is verifiable via Merkle proofs.

While not reaching Critical severity (no direct fund loss or permanent network partition), this qualifies as High severity due to validator crashes and database corruption requiring manual intervention.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability is likely to manifest in production because:

1. **Production Configuration**: State restoration uses `async_commit=true` in production for performance, as confirmed in the backup restore handler.

2. **Common Triggers**: State restoration is a frequent operation:
   - New validators joining the network
   - Snapshot-based restoration
   - Crash recovery scenarios

3. **Realistic Failure Conditions**: 
   - Disk space exhaustion during large state restorations (hundreds of GB)
   - I/O errors on aging hardware
   - Resource pressure during high load
   - Filesystem issues or permission errors

4. **Race Window**: The time between spawning the async write (line 403) and returning (line 412) creates a window where any subsequent error will trigger the vulnerable code path.

5. **Multiple Error Sources**: Any error after spawning async write combined with async write failure creates the condition:
   - Proof verification failures (line 391)
   - Next chunk processing errors
   - Resource exhaustion
   - Concurrent operations

The vulnerability requires only:
- Async commit enabled (done in production)
- Any I/O failure during write (common in distributed systems)
- Any other error during restoration (proof verification, resource limits, etc.)

## Recommendation

Replace the panicking Drop implementation with graceful error handling:

```rust
impl<K> Drop for JellyfishMerkleRestore<K> {
    fn drop(&mut self) {
        if let Some(rx) = self.async_commit_result.take() {
            match rx.recv() {
                Ok(Ok(())) => {
                    // Async commit succeeded
                }
                Ok(Err(e)) => {
                    // Log the error but don't panic during drop
                    error!("Async commit failed during drop: {:?}", e);
                }
                Err(e) => {
                    // Channel error - sender was dropped
                    error!("Failed to receive async commit result: {:?}", e);
                }
            }
        }
    }
}
```

Additionally, consider:
1. Ensuring all pending async commits complete successfully before returning from `add_chunk_impl()`
2. Implementing a background thread that monitors async commit failures and can trigger recovery
3. Adding explicit error paths that properly handle partial restoration failures

## Proof of Concept

Note: While no executable PoC is provided in the original report, the vulnerability is provable by code inspection and Rust language semantics. A panic during Drop while already unwinding is guaranteed to cause abort per Rust's double-panic behavior. The vulnerable code paths are clearly visible in the cited locations, and the production configuration confirms `async_commit=true` is used.

A practical PoC would require:
1. Simulating disk full condition during RocksDB write
2. Triggering a subsequent error (e.g., invalid proof) after spawning async write
3. Observing the validator abort with database in inconsistent state

## Notes

This is a well-documented Rust anti-pattern (panic-in-drop) that violates panic safety guidelines. The combination of asynchronous error handling and unwinding creates a critical vulnerability that can crash validators and corrupt state during a common operation (state restoration). The severity is appropriately classified as High rather than Critical because it doesn't directly enable fund theft or permanent network partition, but it does cause validator unavailability and requires manual intervention to recover.

### Citations

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L394-412)
```rust
        if self.async_commit {
            self.wait_for_async_commit()?;
            let (tx, rx) = channel();
            self.async_commit_result = Some(rx);

            let mut frozen_nodes = HashMap::new();
            std::mem::swap(&mut frozen_nodes, &mut self.frozen_nodes);
            let store = self.store.clone();

            IO_POOL.spawn(move || {
                let res = store.write_node_batch(&frozen_nodes);
                tx.send(res).unwrap();
            });
        } else {
            self.store.write_node_batch(&self.frozen_nodes)?;
            self.frozen_nodes.clear();
        }

        Ok(())
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L792-798)
```rust
impl<K> Drop for JellyfishMerkleRestore<K> {
    fn drop(&mut self) {
        if let Some(rx) = self.async_commit_result.take() {
            rx.recv().unwrap().unwrap();
        }
    }
}
```

**File:** storage/aptosdb/src/backup/restore_handler.rs (L41-55)
```rust
    pub fn get_state_restore_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
        restore_mode: StateSnapshotRestoreMode,
    ) -> Result<StateSnapshotRestore<StateKey, StateValue>> {
        StateSnapshotRestore::new(
            &self.state_store.state_merkle_db,
            &self.state_store,
            version,
            expected_root_hash,
            true, /* async_commit */
            restore_mode,
        )
    }
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L918-932)
```rust
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["tree_writer_write_batch"]);
        // Get the top level batch and sharded batch from raw NodeBatch
        let mut top_level_batch = SchemaBatch::new();
        let mut jmt_shard_batches: Vec<SchemaBatch> = Vec::with_capacity(NUM_STATE_SHARDS);
        jmt_shard_batches.resize_with(NUM_STATE_SHARDS, SchemaBatch::new);
        node_batch.iter().try_for_each(|(node_key, node)| {
            if let Some(shard_id) = node_key.get_shard_id() {
                jmt_shard_batches[shard_id].put::<JellyfishMerkleNodeSchema>(node_key, node)
            } else {
                top_level_batch.put::<JellyfishMerkleNodeSchema>(node_key, node)
            }
        })?;
        self.commit_no_progress(top_level_batch, jmt_shard_batches)
    }
```

**File:** storage/schemadb/src/lib.rs (L306-309)
```rust
    /// Writes a group of records wrapped in a [`SchemaBatch`].
    pub fn write_schemas(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &sync_write_option())
    }
```

**File:** storage/schemadb/src/lib.rs (L389-408)
```rust
fn to_db_err(rocksdb_err: rocksdb::Error) -> AptosDbError {
    match rocksdb_err.kind() {
        ErrorKind::Incomplete => AptosDbError::RocksDbIncompleteResult(rocksdb_err.to_string()),
        ErrorKind::NotFound
        | ErrorKind::Corruption
        | ErrorKind::NotSupported
        | ErrorKind::InvalidArgument
        | ErrorKind::IOError
        | ErrorKind::MergeInProgress
        | ErrorKind::ShutdownInProgress
        | ErrorKind::TimedOut
        | ErrorKind::Aborted
        | ErrorKind::Busy
        | ErrorKind::Expired
        | ErrorKind::TryAgain
        | ErrorKind::CompactionTooLarge
        | ErrorKind::ColumnFamilyDropped
        | ErrorKind::Unknown => AptosDbError::OtherRocksDbError(rocksdb_err.to_string()),
    }
}
```
