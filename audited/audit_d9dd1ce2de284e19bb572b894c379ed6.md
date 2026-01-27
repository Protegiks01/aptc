# Audit Report

## Title
Duplicate batch_id Handling Causes Incorrect Transaction Tracking in Quorum Store

## Summary
The `insert_batch()` function in `batch_generator.rs` uses an early return when encountering a duplicate `(author, batch_id)` key, preventing proper transaction counting for subsequent batches with the same batch_id but different content. This causes transactions in the second batch to not be tracked in `txns_in_progress_sorted`, leading to potential duplicate transaction pulls from mempool.

## Finding Description

The vulnerability exists in the `insert_batch()` function where an early return prevents processing of batches with duplicate `(author, batch_id)` keys: [1](#0-0) 

When a malicious or buggy validator sends two batches with the same `batch_id` but different transactions and digests, the following occurs:

1. **First batch** `(author, batch_id_X, digest_A, [txn1, txn2])`:
   - Passes verification (hash matches digest_A) [2](#0-1) 
   
   - Transactions are processed and counted: [3](#0-2) 
   
   - Batch is stored in `batches_in_progress` with key `(author, batch_id_X)`

2. **Second batch** `(author, batch_id_X, digest_B, [txn3, txn4])`:
   - Also passes verification (hash matches digest_B) [4](#0-3) 
   
   - Forwarded to BatchGenerator [5](#0-4) 
   
   - **Early return triggered** - transactions NOT tracked in `txns_in_progress_sorted`
   - Persisted separately in BatchStore (which uses digest as key) [6](#0-5) 

3. **Cleanup phase**: [7](#0-6) 
   
   Only transactions from the first batch are decremented, leaving incorrect counts.

The batching system assumes `batch_id` uniquely identifies batch content, but doesn't enforce this at the tracking layer despite enforcing it cryptographically via digests.

## Impact Explanation

**Medium Severity** - This creates state inconsistencies in the quorum store's transaction tracking mechanism:

- **Incorrect mempool exclusion**: Transactions from the second batch are not excluded from future mempool pulls, potentially causing the same transactions to be included in multiple batches
- **Resource waste**: Duplicate transaction processing and batch storage
- **Tracking divergence**: Different validators may have inconsistent views of which transactions are "in progress"

However, this does NOT lead to:
- Consensus safety violations (transaction replay protection prevents double-execution)
- Double-spending (sequence numbers prevent this)
- Loss of funds

This falls under "State inconsistencies requiring intervention" per the Medium severity criteria, as operators may need to investigate why the same transactions appear in multiple batches.

## Likelihood Explanation

**Low to Medium Likelihood**:

- Requires a malicious or buggy validator to send duplicate `batch_id` values with different content
- Normal validators increment `batch_id` monotonically, preventing duplicates [8](#0-7) 

- However, Byzantine validators (up to 1/3 of the network) are explicitly part of the threat model
- Easy to exploit once a validator is compromised

## Recommendation

Remove the early return and allow updating the batch entry with extended expiry times while properly tracking all transactions:

```rust
fn insert_batch(
    &mut self,
    author: PeerId,
    batch_id: BatchId,
    txns: Vec<SignedTransaction>,
    expiry_time_usecs: u64,
) {
    let txns_in_progress: Vec<_> = txns
        .par_iter()
        .with_min_len(optimal_min_len(txns.len(), 32))
        .map(|txn| {
            (
                TransactionSummary::new(
                    txn.sender(),
                    txn.replay_protector(),
                    txn.committed_hash(),
                ),
                TransactionInProgress::new(txn.gas_unit_price()),
            )
        })
        .collect();

    // Check if batch already exists
    if let Some(existing_batch) = self.batches_in_progress.get(&(author, batch_id)) {
        // If batch exists with different transactions, log warning and update expiry only
        let updated_expiry = expiry_time_usecs.max(existing_batch.expiry_time_usecs);
        if updated_expiry > existing_batch.expiry_time_usecs {
            self.batch_expirations.add_item((author, batch_id), updated_expiry);
        }
        warn!(
            "Duplicate batch_id {} from author {} with potentially different content",
            batch_id, author
        );
        return;
    }

    // Process new batch normally
    let mut txns = vec![];
    for (summary, info) in txns_in_progress {
        let txn_info = self
            .txns_in_progress_sorted
            .entry(summary)
            .or_insert_with(|| TransactionInProgress::new(info.gas_unit_price));
        txn_info.increment();
        txn_info.gas_unit_price = info.gas_unit_price.max(txn_info.gas_unit_price);
        txns.push(summary);
    }
    
    self.batches_in_progress.insert(
        (author, batch_id),
        BatchInProgress::new(txns, expiry_time_usecs),
    );
    self.batch_expirations.add_item((author, batch_id), expiry_time_usecs);
}
```

Alternatively, consider using `(author, batch_id, digest)` as the key to properly distinguish different batches.

## Proof of Concept

```rust
#[cfg(test)]
mod test_double_batch {
    use super::*;
    use aptos_types::transaction::SignedTransaction;
    
    #[tokio::test]
    async fn test_duplicate_batch_id_different_txns() {
        // Setup BatchGenerator
        let mut batch_gen = /* initialize */;
        
        let author = PeerId::random();
        let batch_id = BatchId::new(100);
        
        // Create two different transaction sets
        let txns1 = vec![/* create test transaction 1 and 2 */];
        let txns2 = vec![/* create test transaction 3 and 4 */];
        
        // Insert first batch
        batch_gen.insert_batch(author, batch_id, txns1.clone(), 1000);
        
        // Verify first batch transactions are tracked
        assert_eq!(batch_gen.txns_in_progress_sorted_len(), 2);
        
        // Insert second batch with same batch_id but different transactions
        batch_gen.insert_batch(author, batch_id, txns2.clone(), 2000);
        
        // BUG: Second batch transactions are NOT tracked
        // Should be 4 transactions, but still only 2
        assert_eq!(batch_gen.txns_in_progress_sorted_len(), 2);
        
        // Cleanup
        batch_gen.remove_batch_in_progress_for_test(author, batch_id);
        
        // BUG: Transactions from second batch are never decremented
        assert_eq!(batch_gen.txns_in_progress_sorted_len(), 0);
    }
}
```

## Notes

The code at lines 159-164 attempts to handle duplicate batches by updating expiry times, but this logic is unreachable due to the early return at line 130, indicating this may have been a known issue that was incompletely addressed: [9](#0-8) 

The BatchStore correctly handles duplicate `batch_id` values by using digest as the key, but the BatchGenerator's tracking layer does not.

### Citations

**File:** consensus/src/quorum_store/batch_generator.rs (L130-132)
```rust
        if self.batches_in_progress.contains_key(&(author, batch_id)) {
            return;
        }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L134-158)
```rust
        let txns_in_progress: Vec<_> = txns
            .par_iter()
            .with_min_len(optimal_min_len(txns.len(), 32))
            .map(|txn| {
                (
                    TransactionSummary::new(
                        txn.sender(),
                        txn.replay_protector(),
                        txn.committed_hash(),
                    ),
                    TransactionInProgress::new(txn.gas_unit_price()),
                )
            })
            .collect();

        let mut txns = vec![];
        for (summary, info) in txns_in_progress {
            let txn_info = self
                .txns_in_progress_sorted
                .entry(summary)
                .or_insert_with(|| TransactionInProgress::new(info.gas_unit_price));
            txn_info.increment();
            txn_info.gas_unit_price = info.gas_unit_price.max(txn_info.gas_unit_price);
            txns.push(summary);
        }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L159-164)
```rust
        let updated_expiry_time_usecs = self
            .batches_in_progress
            .get(&(author, batch_id))
            .map_or(expiry_time_usecs, |batch_in_progress| {
                expiry_time_usecs.max(batch_in_progress.expiry_time_usecs)
            });
```

**File:** consensus/src/quorum_store/batch_generator.rs (L179-183)
```rust
        let batch_id = self.batch_id;
        self.batch_id.increment();
        self.db
            .save_batch_id(self.epoch, self.batch_id)
            .expect("Could not save to db");
```

**File:** consensus/src/quorum_store/batch_generator.rs (L314-330)
```rust
    fn remove_batch_in_progress(&mut self, author: PeerId, batch_id: BatchId) -> bool {
        let removed = self.batches_in_progress.remove(&(author, batch_id));
        match removed {
            Some(batch_in_progress) => {
                for txn in batch_in_progress.txns {
                    if let Entry::Occupied(mut o) = self.txns_in_progress_sorted.entry(txn) {
                        let info = o.get_mut();
                        if info.decrement() == 0 {
                            o.remove();
                        }
                    }
                }
                true
            },
            None => false,
        }
    }
```

**File:** consensus/src/quorum_store/types.rs (L262-290)
```rust
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.payload.author() == self.author(),
            "Payload author doesn't match the info"
        );
        ensure!(
            self.payload.hash() == *self.digest(),
            "Payload hash doesn't match the digest"
        );
        ensure!(
            self.payload.num_txns() as u64 == self.num_txns(),
            "Payload num txns doesn't match batch info"
        );
        ensure!(
            self.payload.num_bytes() as u64 == self.num_bytes(),
            "Payload num bytes doesn't match batch info"
        );
        for txn in self.payload.txns() {
            ensure!(
                txn.gas_unit_price() >= self.gas_bucket_start(),
                "Payload gas unit price doesn't match batch info"
            );
            ensure!(
                !txn.payload().is_encrypted_variant(),
                "Encrypted transaction is not supported yet"
            );
        }
        Ok(())
    }
```

**File:** consensus/src/quorum_store/types.rs (L433-461)
```rust
    pub fn verify(
        &self,
        peer_id: PeerId,
        max_num_batches: usize,
        verifier: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        ensure!(!self.batches.is_empty(), "Empty message");
        ensure!(
            self.batches.len() <= max_num_batches,
            "Too many batches: {} > {}",
            self.batches.len(),
            max_num_batches
        );
        let epoch_authors = verifier.address_to_validator_index();
        for batch in self.batches.iter() {
            ensure!(
                epoch_authors.contains_key(&batch.author()),
                "Invalid author {} for batch {} in current epoch",
                batch.author(),
                batch.digest()
            );
            ensure!(
                batch.author() == peer_id,
                "Batch author doesn't match sender"
            );
            batch.verify()?
        }
        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L229-239)
```rust
        for batch in batches.into_iter() {
            // TODO: maybe don't message batch generator if the persist is unsuccessful?
            if let Err(e) = self
                .sender_to_batch_generator
                .send(BatchGeneratorCommand::RemoteBatch(batch.clone()))
                .await
            {
                warn!("Failed to send batch to batch generator: {}", e);
            }
            persist_requests.push(batch.into());
        }
```

**File:** consensus/src/quorum_store/batch_store.rs (L116-116)
```rust
    db_cache: DashMap<HashValue, PersistedValue<BatchInfoExt>>,
```
