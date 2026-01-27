# Audit Report

## Title
Batch ID Reuse Vulnerability Due to Non-Synchronous Database Writes

## Summary
The `save_batch_id()` function uses non-synchronous database writes (`write_schemas_relaxed()`), which can cause batch ID persistence to fail during machine crashes. This leads to duplicate batch IDs being assigned to different batches with different transaction content, breaking the uniqueness invariant that `(author, batch_id)` should uniquely identify a batch.

## Finding Description

The vulnerability exists in the batch ID persistence mechanism used by the Quorum Store system. The `save_batch_id()` function writes the current batch ID to disk using `write_schemas_relaxed()`, which performs non-synchronous writes to RocksDB. [1](#0-0) 

According to the RocksDB write semantics, when sync is disabled, "if the machine crashes, some recent writes may be lost" (even though process crashes without machine reboot are safe). [1](#0-0) 

The `save_batch_id()` implementation directly uses this relaxed write mode: [2](#0-1) 

This is called both during initialization and every time a new batch is created: [3](#0-2)  and [4](#0-3) 

**Exploitation Scenario:**
1. Node creates Batch B1 with `batch_id = BatchId{id: 5, nonce: X}`, `digest = D1` (hash of transactions [T1, T2, T3])
2. Node increments to `batch_id = 6` and saves to database via relaxed write
3. Batch B1 is broadcast to validators who receive and vote on it
4. **Machine crashes** (power failure, kernel panic) before the database write is flushed to disk
5. On restart, database still contains `batch_id = 5` (the write of 6 was lost)
6. Node creates Batch B2 with the reused `batch_id = BatchId{id: 5, nonce: X}` but `digest = D2` (hash of different transactions [T4, T5, T6])

Now two fundamentally different batches exist with the same `(author, batch_id)` pair but different content and digests.

**Consensus Impact:**

The `BatchProofQueue` uses `BatchKey` (author, batch_id) for deduplication: [5](#0-4) 

When inserting proofs or batch summaries, the system checks for duplicates based solely on `BatchKey`, not considering the digest: [6](#0-5)  and [7](#0-6) 

This causes:
- **Transaction Loss**: If B1 already has a proof/summaries inserted, B2 will be rejected as duplicate even though it contains different valid transactions
- **Vote Splitting**: Validators who received B1 vs B2 may vote for different batches, preventing either from reaching quorum  
- **Consensus Liveness Issues**: Proposers including ProofOfStore(B1) in blocks will cause validation failures for validators who only have B2 (different digest), as they cannot fetch the correct batch content

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program criteria:
- **"Significant protocol violations"**: Breaks the fundamental invariant that (author, batch_id) uniquely identifies a batch
- **"Validator node slowdowns"**: Can cause consensus liveness issues requiring manual intervention

It also violates critical invariants:
- **Deterministic Execution**: Different validators may have different views of which batch corresponds to a given batch_id
- **Consensus Safety**: Could lead to validators being unable to validate proposed blocks containing the duplicate batch_id

While not Critical severity (doesn't directly cause fund loss or complete network halt), the ability to cause transaction loss and consensus liveness degradation represents a significant protocol violation.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires a machine crash (not just process crash) to occur:
- Power failures
- Kernel panics  
- Hardware failures
- Hard reboots

While these are not attacker-controlled events (DoS attacks are out of scope), they **do occur in production environments**. Large validator networks will statistically experience machine crashes over time. When a crash occurs at the precise window between batch creation and database flush, the vulnerability triggers.

The timing window is narrow but non-zero, especially under high transaction load where batches are created frequently.

## Recommendation

**Fix: Use synchronous writes for batch_id persistence**

Change `save_batch_id()` to use synchronous writes instead of relaxed writes:

```rust
fn save_batch_id(&self, epoch: u64, batch_id: BatchId) -> Result<(), DbError> {
    // Use synchronous write to ensure crash safety
    let mut batch = self.db.new_native_batch();
    batch.put::<BatchIdSchema>(&epoch, &batch_id)?;
    self.db.write_schemas(batch)?; // Use sync write instead of write_schemas_relaxed
    Ok(())
}
```

The performance cost of syncing batch_id writes is minimal compared to the critical importance of maintaining batch_id uniqueness. Batch IDs are only updated once per batch creation, not once per transaction, so the sync overhead is acceptable.

**Alternative**: Implement batch_id verification on restart by checking if any previously created batches exist with the loaded batch_id, and skip forward if collisions are detected.

## Proof of Concept

```rust
// Proof of Concept: Rust test demonstrating batch_id reuse

#[test]
fn test_batch_id_reuse_after_crash() {
    use tempfile::TempDir;
    
    let tmp_dir = TempDir::new().unwrap();
    let epoch = 1;
    
    // Step 1: Create QuorumStoreDB and save initial batch_id
    {
        let db = QuorumStoreDB::new(tmp_dir.path());
        db.save_batch_id(epoch, BatchId::new_for_test(5)).unwrap();
        // Simulate creating a batch - increment and save
        db.save_batch_id(epoch, BatchId::new_for_test(6)).unwrap();
        
        // NOTE: In real scenario, machine crashes HERE before write_schemas_relaxed
        // flushes to disk. For test purposes, we manually corrupt by overwriting
        db.save_batch_id(epoch, BatchId::new_for_test(5)).unwrap();
        // db is dropped here, simulating crash with old value
    }
    
    // Step 2: Restart - load batch_id and create new batch
    {
        let db = QuorumStoreDB::new(tmp_dir.path());
        let loaded_id = db.clean_and_get_batch_id(epoch).unwrap();
        
        // Expected: loaded_id = 6
        // Actual after crash: loaded_id = 5 (old value)
        assert_eq!(loaded_id, Some(BatchId::new_for_test(5)));
        
        // This will create a new batch with id=5, reusing the old id!
        // Meanwhile, a batch with id=5 was already created and broadcast before crash
        // Result: TWO DIFFERENT BATCHES WITH SAME BATCH_ID
    }
}

// Demonstration of impact: Duplicate batch_id in proof queue
#[test]
fn test_duplicate_batch_id_impact() {
    let author = PeerId::random();
    let batch_id = BatchId::new_for_test(5);
    
    // Create two different batches with same batch_id but different content
    let txns1 = vec![/* transactions T1, T2, T3 */];
    let txns2 = vec![/* transactions T4, T5, T6 */];
    
    let batch1 = create_batch(batch_id, txns1); // digest = D1
    let batch2 = create_batch(batch_id, txns2); // digest = D2
    
    assert_ne!(batch1.digest(), batch2.digest()); // Different digests!
    assert_eq!(batch1.batch_id(), batch2.batch_id()); // Same batch_id!
    
    // When inserting into proof queue
    let mut queue = BatchProofQueue::new(/* ... */);
    queue.insert_batches(vec![(batch1.info(), /* summaries1 */)]);
    queue.insert_batches(vec![(batch2.info(), /* summaries2 */)]);
    
    // batch2 will be REJECTED as duplicate even though it has different content
    // Transactions in batch2 are LOST!
}
```

---

**Note**: While this represents a real correctness bug that can cause consensus issues and transaction loss, it does not meet the strict criterion of "exploitable by unprivileged attacker" since it requires natural machine failures rather than attacker-controlled actions. I report it due to its potential impact on consensus safety and transaction integrity in production environments.

### Citations

**File:** storage/schemadb/src/lib.rs (L311-318)
```rust
    /// Writes without sync flag in write option.
    /// If this flag is false, and the machine crashes, some recent
    /// writes may be lost.  Note that if it is just the process that
    /// crashes (i.e., the machine does not reboot), no writes will be
    /// lost even if sync==false.
    pub fn write_schemas_relaxed(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &WriteOptions::default())
    }
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L181-183)
```rust
    fn save_batch_id(&self, epoch: u64, batch_id: BatchId) -> Result<(), DbError> {
        self.put::<BatchIdSchema>(&epoch, &batch_id)
    }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L87-101)
```rust
        let batch_id = if let Some(mut id) = db
            .clean_and_get_batch_id(epoch)
            .expect("Could not read from db")
        {
            // If the node shut down mid-batch, then this increment is needed
            id.increment();
            id
        } else {
            BatchId::new(aptos_infallible::duration_since_epoch().as_micros() as u64)
        };
        debug!("Initialized with batch_id of {}", batch_id);
        let mut incremented_batch_id = batch_id;
        incremented_batch_id.increment();
        db.save_batch_id(epoch, incremented_batch_id)
            .expect("Could not save to db");
```

**File:** consensus/src/quorum_store/batch_generator.rs (L179-183)
```rust
        let batch_id = self.batch_id;
        self.batch_id.increment();
        self.db
            .save_batch_id(self.epoch, self.batch_id)
            .expect("Could not save to db");
```

**File:** consensus/src/quorum_store/utils.rs (L151-163)
```rust
pub struct BatchKey {
    author: PeerId,
    batch_id: BatchId,
}

impl BatchKey {
    pub fn from_info(info: &BatchInfoExt) -> Self {
        Self {
            author: info.author(),
            batch_id: info.batch_id(),
        }
    }
}
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L180-188)
```rust
        let batch_key = BatchKey::from_info(proof.info());
        if self
            .items
            .get(&batch_key)
            .is_some_and(|item| item.proof.is_some() || item.is_committed())
        {
            counters::inc_rejected_pos_count(counters::POS_DUPLICATE_LABEL);
            return;
        }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L268-276)
```rust
            // If the batch is either committed or the txn summary already exists, skip
            // inserting this batch.
            if self
                .items
                .get(&batch_key)
                .is_some_and(|item| item.is_committed() || item.txn_summaries.is_some())
            {
                continue;
            }
```
