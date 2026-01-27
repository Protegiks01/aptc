# Audit Report

## Title
Double-Panic in JellyfishMerkleRestore Drop Handler Causes Process Abort and State Corruption

## Summary
The `JellyfishMerkleRestore::drop()` implementation uses double unwrap on channel receive (`rx.recv().unwrap().unwrap()`), which panics when the async commit sender is dropped unexpectedly. If Drop is called during error unwinding, this creates a double-panic scenario causing immediate process abort and leaving the Jellyfish Merkle tree in an inconsistent state.

## Finding Description

The vulnerability exists in the Drop implementation for `JellyfishMerkleRestore`: [1](#0-0) 

This Drop handler calls `rx.recv().unwrap().unwrap()` to wait for async commit completion. When the async commit sender is dropped without sending (due to thread panic, OOM, or database errors), `recv()` returns `Err(RecvError)`, and the first `.unwrap()` panics.

The async commit workflow spawns a task on the IO thread pool: [2](#0-1) 

If the thread panics during `write_node_batch()` execution, the sender `tx` is dropped without sending a result. Subsequently, when `JellyfishMerkleRestore` is dropped (e.g., during error cleanup), the Drop handler panics.

**Critical Issue**: Panicking in Drop during stack unwinding causes a **double-panic**, which results in immediate process termination (`std::process::abort()`) without cleanup or recovery opportunity.

This violates the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs". Partial writes from completed async commits remain in storage, but later chunks are lost, leaving the Jellyfish Merkle tree in an inconsistent state.

Production code uses async_commit=true during backup restoration: [3](#0-2) 

**Attack Scenario**:
1. Node performs state restoration with async_commit=true
2. Async write encounters database error (disk full, corruption) causing thread panic
3. Sender is dropped without sending
4. Main thread encounters separate error (network timeout, invalid proof)
5. `JellyfishMerkleRestore` drops during error cleanup
6. Drop handler panics on `rx.recv().unwrap()`
7. Double-panic → immediate process abort
8. Database contains partial tree state from earlier chunks
9. Node cannot restart without manual intervention

## Impact Explanation

**High Severity** - This qualifies under multiple bug bounty categories:

1. **API crashes**: Process abort terminates the validator node
2. **State inconsistencies requiring intervention**: Corrupted Jellyfish Merkle tree requires manual recovery or full state resync
3. **Validator node unavailability**: Node cannot complete restoration and remains offline

The impact is severe during critical operations:
- State restoration from backups fails catastrophically
- No graceful error recovery path
- Requires manual diagnosis and intervention
- May require full state resync (hours to days of downtime)

While individual batch writes are atomic [4](#0-3) , the overall restoration is NOT transactional across multiple chunks. Partial progress is persisted, making recovery complex.

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

The double-panic scenario is especially likely because:
- State restoration already indicates system stress (recovery mode)
- Multiple error sources are active during restoration
- Error handling code drops the restore object

## Recommendation

**Fix 1 - Remove panic from Drop** (Recommended):

```rust
impl<K> Drop for JellyfishMerkleRestore<K> {
    fn drop(&mut self) {
        if let Some(rx) = self.async_commit_result.take() {
            // Log error but don't panic - Drop must not panic
            if let Err(e) = rx.recv() {
                error!("Async commit failed to complete: {:?}", e);
            } else if let Ok(Err(e)) = rx.recv() {
                error!("Async commit returned error: {:?}", e);
            }
        }
    }
}
```

**Fix 2 - Use timeout with proper error handling**:

```rust
pub fn wait_for_async_commit(&mut self) -> Result<()> {
    if let Some(rx) = self.async_commit_result.take() {
        use std::time::Duration;
        match rx.recv_timeout(Duration::from_secs(300)) {
            Ok(result) => result?,
            Err(RecvTimeoutError::Timeout) => {
                bail!("Async commit timeout after 5 minutes");
            }
            Err(RecvTimeoutError::Disconnected) => {
                bail!("Async commit sender dropped unexpectedly");
            }
        }
    }
    Ok(())
}
```

**Fix 3 - Ensure proper cleanup** in `wait_for_async_commit()`:

The existing implementation at [5](#0-4)  correctly handles errors, but Drop should follow the same pattern instead of unwrapping.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    
    #[test]
    #[should_panic(expected = "RecvError")]
    fn test_drop_panic_on_sender_dropped() {
        // Simulate the scenario where sender is dropped without sending
        let (tx, rx) = channel::<Result<()>>();
        
        // Create a mock JellyfishMerkleRestore state
        struct MockRestore {
            async_commit_result: Option<Receiver<Result<()>>>,
        }
        
        impl Drop for MockRestore {
            fn drop(&mut self) {
                if let Some(rx) = self.async_commit_result.take() {
                    // This will panic - mimics actual code
                    rx.recv().unwrap().unwrap();
                }
            }
        }
        
        let restore = MockRestore {
            async_commit_result: Some(rx),
        };
        
        // Drop sender without sending - simulates thread panic
        drop(tx);
        
        // When restore is dropped, Drop will panic on recv()
        drop(restore);
        // Test panics here, demonstrating the vulnerability
    }
    
    #[test]
    fn test_double_panic_scenario() {
        use std::panic;
        
        // Simulate double-panic: outer panic + Drop panic = abort
        let result = panic::catch_unwind(|| {
            let (tx, rx) = channel::<Result<()>>();
            
            struct MockRestore {
                async_commit_result: Option<Receiver<Result<()>>>,
            }
            
            impl Drop for MockRestore {
                fn drop(&mut self) {
                    if let Some(rx) = self.async_commit_result.take() {
                        rx.recv().unwrap().unwrap();
                    }
                }
            }
            
            let _restore = MockRestore {
                async_commit_result: Some(rx),
            };
            
            drop(tx);
            
            // First panic
            panic!("Simulating error during restoration");
            // When unwinding, _restore drops and panics again
            // In real execution, this causes process abort
        });
        
        // This test demonstrates the panic, but in production,
        // double-panic would call std::process::abort()
        assert!(result.is_err());
    }
}
```

**To demonstrate in production context**:
1. Modify `write_node_batch` to inject failure after partial write
2. Trigger restoration with async_commit=true
3. Induce concurrent error (invalid proof, network failure)
4. Observe process abort and check database state
5. Verify Jellyfish Merkle tree is incomplete/corrupted

### Citations

**File:** storage/jellyfish-merkle/src/restore/mod.rs (L403-406)
```rust
            IO_POOL.spawn(move || {
                let res = store.write_node_batch(&frozen_nodes);
                tx.send(res).unwrap();
            });
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

**File:** storage/aptosdb/src/backup/restore_handler.rs (L47-54)
```rust
        StateSnapshotRestore::new(
            &self.state_store.state_merkle_db,
            &self.state_store,
            version,
            expected_root_hash,
            true, /* async_commit */
            restore_mode,
        )
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L920-932)
```rust
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
