# Audit Report

## Title
BatchId Collision Vulnerability in Batch Transaction Filtering

## Summary
A malicious validator can craft multiple batches with identical BatchIds but different transaction content to bypass batch-specific filtering rules. The filtering system assumes BatchId uniquely identifies batch content, but no uniqueness validation is enforced when batches are received over the network.

## Finding Description

The batch transaction filter system uses BatchId as a matching criterion to allow or deny batches. However, BatchId is documented as "A unique identifier for a batch of transactions in quorum store" [1](#0-0)  but this uniqueness is not enforced in the network protocol.

When a batch is received from a remote validator, the verification process checks the batch author, payload consistency, and size limits [2](#0-1) , but never validates that the BatchId is unique or hasn't been used before with different content.

The `matches_batch_id()` function performs simple equality comparison [3](#0-2)  without considering that multiple batches with different content could share the same BatchId.

The batch storage system performs deduplication based on digest (content hash), not BatchId [4](#0-3) . This means two batches with the same BatchId but different transaction content (different digests) will both be stored and processed.

During batch filtering, the system applies rules based on BatchId matching [5](#0-4) . A malicious validator can exploit this by:

1. Creating a batch with BatchId X containing malicious transactions (digest D1)
2. Creating another batch with the same BatchId X but benign transactions (digest D2)
3. Both batches pass validation since they have valid signatures and correct payload hashes
4. Filter rules targeting BatchId X will apply to both batches, even though they contain completely different transactions

This breaks the assumption that BatchId uniquely identifies batch content for filtering purposes.

## Impact Explanation

This is a **Medium Severity** issue (up to $10,000) because it causes state inconsistencies requiring intervention. The vulnerability allows:

- **Filter Rule Bypass**: ALLOW rules targeting specific BatchIds can be exploited to inject malicious transactions
- **Filter Rule Confusion**: DENY rules targeting malicious batches can incorrectly block legitimate batches with the same BatchId
- **State Inconsistency**: Different nodes may process batches differently based on arrival order of colliding BatchIds

However, the impact is limited because:
- It requires a compromised validator to exploit
- The malicious batch still requires valid signatures and passes consensus
- No direct fund loss or consensus safety violation occurs
- The issue can be detected and mitigated by monitoring BatchId reuse

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
- A malicious or compromised validator (high barrier)
- Knowledge of filter rules targeting specific BatchIds (medium barrier)
- Ability to craft batches with arbitrary BatchIds (low barrier - fully deserializable)

While validators are expected to increment BatchIds sequentially, the protocol does not enforce this constraint. A compromised validator could easily craft colliding BatchIds since the BatchId structure is fully under their control [6](#0-5) .

## Recommendation

Add BatchId uniqueness validation in the batch verification and storage layers:

1. **Network Validation**: Track received BatchIds per author and reject batches that reuse a BatchId with different content:

```rust
// In BatchCoordinator
fn validate_batch_id_uniqueness(
    &self,
    author: PeerId,
    batch_id: BatchId,
    digest: &HashValue,
) -> anyhow::Result<()> {
    if let Some(prev_digest) = self.batch_id_to_digest.get(&(author, batch_id)) {
        ensure!(
            prev_digest == digest,
            "BatchId collision detected: same BatchId with different content"
        );
    }
    Ok(())
}
```

2. **Filter Enhancement**: Make filters match on (BatchId, Digest) pairs instead of BatchId alone, or add digest validation to batch matchers.

3. **Storage Layer**: Add a BatchId uniqueness check that rejects batches attempting to reuse a BatchId from the same author with different content.

## Proof of Concept

```rust
// Demonstration of BatchId collision exploitation
// This would be run by a malicious validator

use aptos_types::quorum_store::BatchId;
use aptos_crypto::HashValue;

#[test]
fn test_batch_id_collision_bypass() {
    // Setup: Filter configured to ALLOW BatchId(100, 1000)
    let target_batch_id = BatchId { id: 100, nonce: 1000 };
    
    // Legitimate batch with allowed BatchId
    let legitimate_batch = create_batch(
        target_batch_id,
        vec![legitimate_transaction()],
    );
    let legitimate_digest = legitimate_batch.digest();
    
    // Malicious batch with SAME BatchId but different content
    let malicious_batch = create_batch(
        target_batch_id,  // Same BatchId!
        vec![malicious_transaction()],
    );
    let malicious_digest = malicious_batch.digest();
    
    // Both batches pass verification
    assert!(legitimate_batch.verify().is_ok());
    assert!(malicious_batch.verify().is_ok());
    
    // Both have same BatchId but different digests
    assert_eq!(legitimate_batch.batch_id(), malicious_batch.batch_id());
    assert_ne!(legitimate_digest, malicious_digest);
    
    // Filter matches both based on BatchId alone
    let filter = BatchTransactionFilter::empty()
        .add_batch_id_filter(true, target_batch_id);
    
    assert!(filter.allows_transaction(
        target_batch_id,
        author,
        legitimate_digest,
        &legitimate_transaction(),
    ));
    
    // Malicious batch also matches the ALLOW rule!
    assert!(filter.allows_transaction(
        target_batch_id,  // Same BatchId triggers match
        author,
        malicious_digest,  // Different content ignored
        &malicious_transaction(),
    ));
}
```

## Notes

This vulnerability demonstrates a mismatch between the documented invariant (BatchId is a unique identifier) and the actual enforcement in the network protocol. While the system was designed assuming validators would honestly increment BatchIds sequentially, a malicious validator can violate this assumption without detection.

The issue requires validator compromise to exploit, which significantly limits its practical impact but still represents a protocol weakness that should be addressed to strengthen the filtering system's security guarantees.

### Citations

**File:** types/src/quorum_store/mod.rs (L11-11)
```rust
/// A unique identifier for a batch of transactions in quorum store
```

**File:** types/src/quorum_store/mod.rs (L15-21)
```rust
pub struct BatchId {
    pub id: u64,
    /// A number that is stored in the DB and updated only if the value does not exist in
    /// the DB: (a) at the start of an epoch, or (b) the DB was wiped. When the nonce is updated,
    /// id starts again at 0. Using the current system time allows the nonce to be ordering.
    pub nonce: u64,
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

**File:** crates/aptos-transaction-filters/src/batch_transaction_filter.rs (L221-223)
```rust
fn matches_batch_id(batch_id: BatchId, target_batch_id: &BatchId) -> bool {
    batch_id == *target_batch_id
}
```

**File:** consensus/src/quorum_store/batch_store.rs (L358-417)
```rust
    pub(crate) fn insert_to_cache(
        &self,
        value: &PersistedValue<BatchInfoExt>,
    ) -> anyhow::Result<bool> {
        let digest = *value.digest();
        let author = value.author();
        let expiration_time = value.expiration();

        {
            // Acquire dashmap internal lock on the entry corresponding to the digest.
            let cache_entry = self.db_cache.entry(digest);

            if let Occupied(entry) = &cache_entry {
                match entry.get().expiration().cmp(&expiration_time) {
                    std::cmp::Ordering::Equal => return Ok(false),
                    std::cmp::Ordering::Greater => {
                        debug!(
                            "QS: already have the digest with higher expiration {}",
                            digest
                        );
                        return Ok(false);
                    },
                    std::cmp::Ordering::Less => {},
                }
            };
            let value_to_be_stored = if self
                .peer_quota
                .entry(author)
                .or_insert(QuotaManager::new(
                    self.db_quota,
                    self.memory_quota,
                    self.batch_quota,
                ))
                .update_quota(value.num_bytes() as usize)?
                == StorageMode::PersistedOnly
            {
                PersistedValue::new(value.batch_info().clone(), None)
            } else {
                value.clone()
            };

            match cache_entry {
                Occupied(entry) => {
                    let (k, prev_value) = entry.replace_entry(value_to_be_stored);
                    debug_assert!(k == digest);
                    self.free_quota(prev_value);
                },
                Vacant(slot) => {
                    slot.insert(value_to_be_stored);
                },
            }
        }

        // Add expiration for the inserted entry, no need to be atomic w. insertion.
        #[allow(clippy::unwrap_used)]
        {
            self.expirations.lock().add_item(digest, expiration_time);
        }
        Ok(true)
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L191-213)
```rust
        if self.transaction_filter_config.is_enabled() {
            let transaction_filter = &self.transaction_filter_config.batch_transaction_filter();
            for batch in batches.iter() {
                for transaction in batch.txns() {
                    if !transaction_filter.allows_transaction(
                        batch.batch_info().batch_id(),
                        batch.author(),
                        batch.digest(),
                        transaction,
                    ) {
                        error!(
                            "Transaction {}, in batch {}, from {}, was rejected by the filter. Dropping {} batches!",
                            transaction.committed_hash(),
                            batch.batch_info().batch_id(),
                            author.short_str().as_str(),
                            batches.len()
                        );
                        counters::RECEIVED_BATCH_REJECTED_BY_FILTER.inc();
                        return;
                    }
                }
            }
        }
```
