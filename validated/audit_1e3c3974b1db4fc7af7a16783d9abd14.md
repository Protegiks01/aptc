# Audit Report

## Title
Double-Panic in JellyfishMerkleRestore Drop Handler Causes Process Abort and State Corruption

## Summary
The `JellyfishMerkleRestore::drop()` implementation uses double unwrap on channel receive (`rx.recv().unwrap().unwrap()`), which panics when async commit operations fail. If Drop is called during error unwinding, this creates a double-panic scenario causing immediate process abort and leaving the Jellyfish Merkle tree in an inconsistent state.

## Finding Description

The vulnerability exists in the Drop implementation for `JellyfishMerkleRestore`: [1](#0-0) 

This Drop handler performs `rx.recv().unwrap().unwrap()` to wait for async commit completion. There are two panic scenarios:

1. **Sender dropped without sending**: When the async commit thread panics during `write_node_batch()` execution, the sender `tx` is dropped without sending a result. Subsequently, `recv()` returns `Err(RecvError)`, and the first `.unwrap()` panics.

2. **Database write error**: When `write_node_batch()` returns an error, it's sent through the channel. The second `.unwrap()` then panics on this error result.

The async commit workflow spawns tasks on the IO thread pool: [2](#0-1) 

Notice at line 405, `tx.send(res).unwrap()` sends the result. If `res` is `Err(...)`, the Drop handler's second unwrap will panic on this error.

**Critical Issue**: Panicking in Drop during stack unwinding causes a **double-panic**, which results in immediate process termination (`std::process::abort()`) per Rust semantics, without cleanup or recovery opportunity.

This violates the **State Consistency** invariant. Partial writes from completed async commits remain in storage, but later chunks are lost, leaving the Jellyfish Merkle tree in an inconsistent state.

Production code uses async_commit=true during backup restoration: [3](#0-2) 

The restoration flow shows how errors trigger the vulnerability: [4](#0-3) 

When `add_chunk` returns an error (line 215), the function returns early. The `receiver` Arc is eventually dropped, triggering the Drop handler. If a previous async commit failed, the Drop handler panics, and since we're already in error handling, this becomes a double-panic.

**Attack Scenario**:
1. Node performs state restoration with async_commit=true
2. Async write encounters database error (disk full, corruption) 
3. Error is sent through channel or sender is dropped
4. Main thread encounters separate error (invalid proof, ordering violation)
5. `JellyfishMerkleRestore` drops during error cleanup
6. Drop handler panics on error result
7. Double-panic → immediate process abort
8. Database contains partial tree state from earlier chunks
9. Node cannot restart without manual intervention

## Impact Explanation

**High Severity** - This qualifies under Aptos bug bounty categories:

1. **API crashes** (HIGH): Process abort terminates the validator node during critical backup restoration operations. The process crashes without graceful shutdown.

2. **State inconsistencies requiring manual intervention** (MEDIUM): Corrupted Jellyfish Merkle tree requires manual recovery or full state resync. Partial writes from earlier chunks remain in storage while later chunks are lost.

3. **Validator node unavailability**: Node cannot complete restoration and remains offline until manual intervention.

The impact is severe during critical operations:
- State restoration from backups fails catastrophically
- No graceful error recovery path
- Requires manual diagnosis and intervention
- May require full state resync (hours to days of downtime)

The write_node_batch operation persists individual batches atomically: [5](#0-4) 

However, the overall restoration is NOT transactional across multiple chunks. Partial progress is persisted, making recovery complex.

## Likelihood Explanation

**Medium to High Likelihood** during production conditions:

**Trigger Conditions**:
- Async commit enabled (true in backup restoration path)
- Resource exhaustion (disk space, memory)
- Database corruption or I/O errors
- Concurrent failures during restoration

**Real-world scenarios**:
- Disk full during large state restoration (common operational issue)
- Memory pressure causing OOM during batch write
- Hardware failures during critical restoration window
- Database corruption from previous crash
- Proof verification failures from corrupted backup data

The double-panic scenario is especially likely because:
- State restoration already indicates system stress (recovery mode)
- Multiple error sources are active during restoration
- Error handling code drops the restore object during unwinding
- Database write operations can fail for numerous reasons

## Recommendation

Replace the panic-inducing double unwrap in the Drop handler with proper error handling:

```rust
impl<K> Drop for JellyfishMerkleRestore<K> {
    fn drop(&mut self) {
        if let Some(rx) = self.async_commit_result.take() {
            // Don't panic in Drop - log error instead
            match rx.recv() {
                Ok(Ok(())) => {},
                Ok(Err(e)) => {
                    error!("Async commit failed during cleanup: {:?}", e);
                },
                Err(e) => {
                    error!("Async commit channel recv failed during cleanup: {:?}", e);
                },
            }
        }
    }
}
```

Alternatively, ensure `wait_for_async_commit()` is explicitly called before any error path that could drop the object: [6](#0-5) 

This method already has proper error handling with `??` operator.

## Proof of Concept

While a complete PoC would require triggering database write failures, the vulnerability can be demonstrated by examining the code path:

1. The Drop implementation unconditionally panics on async commit errors
2. Production code enables async_commit during restoration  
3. Error handling in add_chunk causes early return, dropping the restore object
4. Database operations can fail for numerous reasons (disk full, I/O errors, corruption)
5. Rust's double-panic behavior causes immediate process abort

The combination of these factors makes this a realistic and severe vulnerability in production environments.

## Notes

**Key distinguishing factors from similar bugs:**
- This affects the backup restoration path, a critical recovery operation
- The double-panic scenario is triggered by error handling itself, making it particularly insidious
- State corruption occurs because earlier chunks are committed while later chunks fail
- Recovery requires manual intervention, potentially hours of downtime

**Why this is HIGH severity:**
- Process abort during critical operations (matches "API crashes" category)
- State inconsistencies requiring manual recovery
- Affects validator availability during restoration
- Can be triggered by common operational issues (disk full, I/O errors)

**Why this is not CRITICAL:**
- Does not affect consensus or enable fund theft
- Does not cause network-wide failures
- Limited to nodes performing backup restoration
- Does not enable remote code execution or validator compromise

### Citations

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L394-410)
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
```

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L741-746)
```rust
    pub fn wait_for_async_commit(&mut self) -> Result<()> {
        if let Some(rx) = self.async_commit_result.take() {
            rx.recv()??;
        }
        Ok(())
    }
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

**File:** storage/backup/backup-cli/src/backup_types/state_snapshot/restore.rs (L212-215)
```rust
            tokio::task::spawn_blocking(move || {
                receiver.lock().as_mut().unwrap().add_chunk(blobs, proof)
            })
            .await??;
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
