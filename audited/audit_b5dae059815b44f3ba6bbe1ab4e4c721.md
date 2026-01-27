# Audit Report

## Title
BatchId Silent Data Loss Due to Non-Durable Persistence in Quorum Store

## Summary
BatchId mappings in the quorum store are persisted using relaxed writes without synchronous disk flushing, creating a crash window where batch ID increments can be lost. This causes silent data loss when a validator machine crashes after creating a batch but before the OS flushes the persisted batch ID to disk.

## Finding Description

The quorum store's BatchId persistence mechanism uses non-durable writes, violating WAL (Write-Ahead Log) durability guarantees. When a validator creates a batch and increments its batch ID, this increment is persisted using `write_schemas_relaxed()` which does not force an fsync. [1](#0-0) 

The `write_schemas_relaxed` method explicitly documents the data loss risk: [2](#0-1) 

This creates a vulnerability in the batch generation flow: [3](#0-2) 

**Attack Scenario:**

1. Validator creates batch with `BatchId(N, nonce)` and broadcasts it to the network
2. Validator increments batch_id to `(N+1, nonce)` in memory
3. Validator calls `save_batch_id()` which uses relaxed write (no disk sync)
4. **Machine crashes** before OS flushes the write buffer
5. On restart, database still contains `BatchId(N-1, nonce)`
6. Validator loads old ID, increments to `BatchId(N, nonce)` and reuses it
7. New batch with same ID but different transactions is created
8. Other validators already have the old `BatchId(N, nonce)` in their proof queues
9. They reject the new batch as a duplicate: [4](#0-3) 

10. Original batch's transactions are silently lost (not in mempool, not in any block)
11. Validator cannot gather quorum on the new batch due to duplicate rejections

The `BatchId` is part of the cryptographically signed `BatchInfo` structure: [5](#0-4) 

This means two batches with the same `BatchId` but different transaction digests will have incompatible signatures, preventing proof aggregation.

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: Lost batch ID mappings cause state divergence between the validator's internal state and the network's view
- **Limited transaction loss**: Transactions from the lost batch are silently dropped unless users manually resubmit them
- **Temporary liveness degradation**: The affected validator cannot progress batch creation until expired batches are cleaned from peer proof queues

This does NOT constitute:
- **Critical severity**: No consensus safety violation, no permanent funds loss, no chain fork
- **High severity**: Not a protocol-wide issue, limited to single validator

The comment in the code acknowledges the shutdown issue but the solution is insufficient: [6](#0-5) 

The increment on line 92 only helps with clean shutdowns, not machine crashes where relaxed writes are lost.

## Likelihood Explanation

**Likelihood: Medium**

- Requires validator machine crash (power failure, kernel panic, hardware fault)
- Must occur during specific timing window between batch creation and disk flush
- RocksDB's WAL typically flushes every few seconds, creating exploitable windows
- No attacker capability required - natural system failures trigger this
- Each validator is independently vulnerable
- Occurs more frequently under:
  - High batch creation rate (shorter time between saves)
  - Unreliable hardware
  - Power instability

## Recommendation

Use synchronous writes for BatchId persistence to ensure durability:

```rust
// In QuorumStoreDB::put method
pub fn put<S: Schema>(&self, key: &S::Key, value: &S::Value) -> Result<(), DbError> {
    let mut batch = self.db.new_native_batch();
    batch.put::<S>(key, value)?;
    // CHANGE: Use write_schemas with sync instead of write_schemas_relaxed
    self.db.write_schemas(batch)?;
    Ok(())
}
```

This uses the sync write option: [7](#0-6) 

**Alternative approach**: Implement proper WAL semantics by saving batch ID BEFORE creating the batch, not after:

```rust
// In create_new_batch, save BEFORE using the ID
pub fn create_new_batch(...) -> Batch<BatchInfoExt> {
    let mut next_batch_id = self.batch_id;
    next_batch_id.increment();
    
    // Persist next ID before using current ID
    self.db.save_batch_id(self.epoch, next_batch_id)
        .expect("Could not save to db");
    
    let batch_id = self.batch_id;
    self.batch_id = next_batch_id;
    
    // Now create batch with guaranteed-unique ID
    self.insert_batch(self.my_peer_id, batch_id, txns.clone(), expiry_time);
    // ... rest of batch creation
}
```

## Proof of Concept

This vulnerability requires integration testing with crash injection, which cannot be demonstrated in a simple unit test. However, the reproduction steps are:

1. Start a validator node with batch generation enabled
2. Monitor batch creation and `save_batch_id()` calls
3. Inject a machine crash (SIGKILL + immediate power loss simulation) during the window between `create_new_batch()` line 179 and the disk flush of line 182
4. Restart the node
5. Observe that the node reloads an old BatchId value
6. Node creates a new batch with a previously-used BatchId
7. Network validators reject the proof with `POS_DUPLICATE_LABEL` counter increment
8. Original batch transactions are lost

**Test validation approach:**
- Add counter for `save_batch_id` calls
- Add counter for batch creations
- If counter mismatch after crash-recovery, vulnerability confirmed
- Check peer rejection logs for `POS_DUPLICATE_LABEL` 

**Notes**
This vulnerability specifically addresses the security question about WAL durability. The BatchIdSchema uses relaxed writes rather than write-ahead logging with proper fsync guarantees, creating a data loss window that violates durability assumptions critical for distributed consensus systems. While not exploitable by external attackers, it represents a genuine reliability and data integrity issue that can cause transaction loss and network inconsistencies.

### Citations

**File:** consensus/src/quorum_store/quorum_store_db.rs (L82-89)
```rust
    /// Relaxed writes instead of sync writes.
    pub fn put<S: Schema>(&self, key: &S::Key, value: &S::Value) -> Result<(), DbError> {
        // Not necessary to use a batch, but we'd like a central place to bump counters.
        let mut batch = self.db.new_native_batch();
        batch.put::<S>(key, value)?;
        self.db.write_schemas_relaxed(batch)?;
        Ok(())
    }
```

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

**File:** storage/schemadb/src/lib.rs (L374-378)
```rust
fn sync_write_option() -> rocksdb::WriteOptions {
    let mut opts = rocksdb::WriteOptions::default();
    opts.set_sync(true);
    opts
}
```

**File:** consensus/src/quorum_store/batch_generator.rs (L87-96)
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
```

**File:** consensus/src/quorum_store/batch_generator.rs (L173-183)
```rust
    fn create_new_batch(
        &mut self,
        txns: Vec<SignedTransaction>,
        expiry_time: u64,
        bucket_start: u64,
    ) -> Batch<BatchInfoExt> {
        let batch_id = self.batch_id;
        self.batch_id.increment();
        self.db
            .save_batch_id(self.epoch, self.batch_id)
            .expect("Could not save to db");
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

**File:** consensus/consensus-types/src/proof_of_store.rs (L46-58)
```rust
#[derive(
    Clone, Debug, Deserialize, Serialize, CryptoHasher, BCSCryptoHash, PartialEq, Eq, Hash,
)]
pub struct BatchInfo {
    author: PeerId,
    batch_id: BatchId,
    epoch: u64,
    expiration: u64,
    digest: HashValue,
    num_txns: u64,
    num_bytes: u64,
    gas_bucket_start: u64,
}
```
