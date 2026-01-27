# Audit Report

## Title
Quorum Store Batch Expiration Bypass Allows Storage Exhaustion DoS

## Summary
A Byzantine validator can create batches with expiration set to `u64::MAX`, causing them to never expire and permanently consume storage quota, eventually leading to denial of service as honest nodes cannot accept new batches.

## Finding Description

The `Batch::verify()` method in the quorum store does not validate the expiration field of received batches. [1](#0-0) 

When a Byzantine validator creates a batch with `expiration = u64::MAX` and broadcasts it via `BatchMsg`, honest validators perform verification that checks payload integrity, transaction counts, and gas prices, but critically **does not validate the expiration value**. [2](#0-1) 

The malicious batch passes verification and gets persisted to storage. The `BatchStore::save()` method only checks if expiration is greater than the current certified time (which is always true for `u64::MAX`), allowing the batch to be stored. [3](#0-2) 

Once stored, the batch is tracked in the expiration system. However, the garbage collection mechanism in `clear_expired_payload()` checks if `entry.get().expiration() <= expiration_time`. Since `u64::MAX` exceeds any reasonable expiration timestamp, this condition is never satisfied, and the batch **never expires**. [4](#0-3) 

The batch permanently consumes quota from the `QuotaManager`, which tracks per-validator limits on batch count, memory usage, and database storage. The quota is only freed when batches expire, which never happens for these malicious batches. [5](#0-4) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables a Byzantine validator to perform a targeted denial-of-service attack:

1. **Storage Exhaustion**: Malicious batches fill up the configured storage quota (default: 300MB database, 120MB memory, 300K batches). [6](#0-5) 

2. **Quota Starvation**: Once quota is exhausted, the `update_quota()` function rejects all new batches with "Batch quota exceeded" or "Storage quota exceeded" errors. [5](#0-4) 

3. **Liveness Degradation**: Honest validators cannot create or store new batches, severely impacting the quorum store's ability to batch transactions for consensus, causing validator slowdowns and potential liveness issues.

4. **Persistence Across Restarts**: The malicious batches are persisted to disk, so the attack survives node restarts within the same epoch.

This falls under **High Severity** per the Aptos bug bounty criteria: "Validator node slowdowns" and "Significant protocol violations."

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

- **Attacker Requirements**: Requires a Byzantine validator (allowed under <1/3 Byzantine assumption in BFT systems)
- **Attack Complexity**: Low - simply create batches with modified expiration values
- **Detection Difficulty**: The attack is subtle as batches appear valid during normal verification
- **Mitigation Window**: Batches are cleaned up at epoch boundaries, but can cause significant disruption during an epoch

## Recommendation

Add expiration validation to `Batch::verify()` to mirror the validation present in `SignedBatchInfo::verify()`:

```rust
// In consensus/src/quorum_store/types.rs, add to Batch::verify():

pub fn verify(&self) -> anyhow::Result<()> {
    // ... existing checks ...
    
    // Add expiration validation
    let max_expiry_gap_usecs = /* get from config */;
    let current_time = aptos_infallible::duration_since_epoch().as_micros() as u64;
    ensure!(
        self.expiration() <= current_time + max_expiry_gap_usecs,
        "Batch expiration too far in future: {} > {}",
        self.expiration(),
        current_time + max_expiry_gap_usecs
    );
    
    Ok(())
}
```

Additionally, consider adding a minimum expiration check to prevent batches with unreasonably short expirations.

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_malicious_batch_with_max_expiration() {
    use consensus::quorum_store::types::Batch;
    use aptos_types::transaction::SignedTransaction;
    use aptos_types::quorum_store::BatchId;
    use aptos_types::PeerId;
    
    // Create a batch with u64::MAX expiration
    let malicious_expiration = u64::MAX;
    let batch_id = BatchId::new(1);
    let txns: Vec<SignedTransaction> = vec![]; // empty for simplicity
    let epoch = 1;
    let batch_author = PeerId::random();
    let gas_bucket_start = 0;
    
    let malicious_batch = Batch::new_v1(
        batch_id,
        txns,
        epoch,
        malicious_expiration,
        batch_author,
        gas_bucket_start,
    );
    
    // Verify the batch - this should pass (demonstrating the vulnerability)
    assert!(malicious_batch.verify().is_ok());
    
    // The batch would be persisted and never expire
    // In clear_expired_payload(), the check `expiration <= expiration_time`
    // will never be true when expiration = u64::MAX
}
```

## Notes

While `SignedBatchInfo::verify()` correctly validates expiration against `max_batch_expiry_gap_usecs`, the earlier `Batch::verify()` method lacks this check. This creates an asymmetry where batches can be stored with invalid expirations before the signing phase, allowing the storage exhaustion attack to succeed even though proof creation would eventually fail.

Epoch-based cleanup mechanisms exist but only trigger at epoch transitions, leaving a window for the attack to cause significant disruption during the current epoch.

### Citations

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

**File:** consensus/src/quorum_store/batch_store.rs (L64-84)
```rust
    pub(crate) fn update_quota(&mut self, num_bytes: usize) -> anyhow::Result<StorageMode> {
        if self.batch_balance == 0 {
            counters::EXCEEDED_BATCH_QUOTA_COUNT.inc();
            bail!("Batch quota exceeded ");
        }

        if self.db_balance >= num_bytes {
            self.batch_balance -= 1;
            self.db_balance -= num_bytes;

            if self.memory_balance >= num_bytes {
                self.memory_balance -= num_bytes;
                Ok(StorageMode::MemoryAndPersisted)
            } else {
                Ok(StorageMode::PersistedOnly)
            }
        } else {
            counters::EXCEEDED_STORAGE_QUOTA_COUNT.inc();
            bail!("Storage quota exceeded ");
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L419-439)
```rust
    pub(crate) fn save(&self, value: &PersistedValue<BatchInfoExt>) -> anyhow::Result<bool> {
        let last_certified_time = self.last_certified_time();
        if value.expiration() > last_certified_time {
            fail_point!("quorum_store::save", |_| {
                // Skip caching and storing value to the db
                Ok(false)
            });
            counters::GAP_BETWEEN_BATCH_EXPIRATION_AND_CURRENT_TIME_WHEN_SAVE.observe(
                Duration::from_micros(value.expiration() - last_certified_time).as_secs_f64(),
            );

            return self.insert_to_cache(value);
        }
        counters::NUM_BATCH_EXPIRED_WHEN_SAVE.inc();
        bail!(
            "Incorrect expiration {} in epoch {}, last committed timestamp {}",
            value.expiration(),
            self.epoch(),
            last_certified_time,
        );
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L443-472)
```rust
    pub(crate) fn clear_expired_payload(&self, certified_time: u64) -> Vec<HashValue> {
        // To help slow nodes catch up via execution without going to state sync we keep the blocks for 60 extra seconds
        // after the expiration time. This will help remote peers fetch batches that just expired but are within their
        // execution window.
        let expiration_time = certified_time.saturating_sub(self.expiration_buffer_usecs);
        let expired_digests = self.expirations.lock().expire(expiration_time);
        let mut ret = Vec::new();
        for h in expired_digests {
            let removed_value = match self.db_cache.entry(h) {
                Occupied(entry) => {
                    // We need to check up-to-date expiration again because receiving the same
                    // digest with a higher expiration would update the persisted value and
                    // effectively extend the expiration.
                    if entry.get().expiration() <= expiration_time {
                        self.persist_subscribers.remove(entry.get().digest());
                        Some(entry.remove())
                    } else {
                        None
                    }
                },
                Vacant(_) => unreachable!("Expired entry not in cache"),
            };
            // No longer holding the lock on db_cache entry.
            if let Some(value) = removed_value {
                self.free_quota(value);
                ret.push(h);
            }
        }
        ret
    }
```

**File:** config/src/config/quorum_store_config.rs (L131-135)
```rust
            batch_expiry_gap_when_init_usecs: Duration::from_secs(60).as_micros() as u64,
            remote_batch_expiry_gap_when_init_usecs: Duration::from_millis(500).as_micros() as u64,
            memory_quota: 120_000_000,
            db_quota: 300_000_000,
            batch_quota: 300_000,
```
