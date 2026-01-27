# Audit Report

## Title
BatchId Filtering Bypass via Arbitrary BatchId Manipulation by Malicious Validators

## Summary
Malicious validators can bypass BatchId-based transaction filters in the quorum store by arbitrarily setting BatchId values for their batches. There is no validation that BatchId values are legitimate or follow any expected pattern, allowing validators to evade BatchId-based filtering rules configured by node operators.

## Finding Description

The `BatchTransactionFilter` system allows node operators to filter transactions based on batch characteristics including `BatchId`. [1](#0-0) 

However, validators have complete control over the `BatchId` values they assign to their batches. When a validator creates a new batch, the `BatchId` is generated locally with a nonce derived from system time and an auto-incrementing id counter: [2](#0-1) 

The `BatchId` structure simply contains two u64 fields that are fully controlled by the batch creator: [3](#0-2) 

When remote batches are received and verified, there is NO validation that the `BatchId` values are legitimate or expected for that validator: [4](#0-3) 

The filter is applied in `BatchCoordinator.handle_batches_msg()` based on the `BatchId` value provided by the sending validator: [5](#0-4) 

**Attack Scenario:**
1. Operator detects harmful batch from malicious validator with `BatchId {id: 100, nonce: 12345}`
2. Operator adds deny rule: `BatchId: {id: 100, nonce: 12345}`
3. Malicious validator broadcasts new batch with identical or similar content but different `BatchId: {id: 101, nonce: 12345}` or `{id: 100, nonce: 54321}`
4. Filter comparison fails to match the new BatchId: [6](#0-5) 
5. Harmful batch bypasses filter and is accepted

The BatchId is part of the signed `BatchInfo` structure, so signatures cannot be reused across different BatchIds. However, a malicious validator can simply broadcast new batches with arbitrary BatchId values, obtaining fresh signatures from other validators who don't have the specific BatchId filter configured. [7](#0-6) 

## Impact Explanation

This is a **Medium severity** issue per Aptos bug bounty criteria for the following reasons:

1. **Filter Bypass**: Operators cannot reliably block specific batches using BatchId-based filtering, creating a false sense of security
2. **Operational Impact**: Security incidents may require manual intervention when operators discover their filters are ineffective
3. **Limited Scope**: While the bypass exists, secure alternatives are available (`BatchAuthor` filtering for validator-based blocking, `BatchDigest` filtering for content-based blocking)
4. **No Direct Consensus Impact**: This does not break consensus safety, cause fund loss, or create state inconsistencies directly
5. **Byzantine Threat Model**: The vulnerability is exploitable within the expected Byzantine fault tolerance model (< 1/3 malicious validators)

The impact is confined to operational security controls rather than core protocol safety guarantees, justifying Medium rather than High or Critical severity.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited for the following reasons:

1. **Trivial to Execute**: A malicious validator only needs to modify two u64 values (id and nonce) when creating batches
2. **No Prerequisites**: No special conditions, timing windows, or complex state manipulation required
3. **Undetectable**: The bypass leaves no obvious traces since different BatchIds appear as legitimate batches
4. **Operational Usage**: Node operators may naturally configure BatchId filters thinking they provide security guarantees, especially during incident response
5. **Byzantine Reality**: With potentially up to 1/3 of validators being Byzantine in the threat model, at least some validators are expected to attempt filter evasion

## Recommendation

**Short-term Fix:**
Add clear documentation warnings that BatchId filtering should NOT be used for security purposes, only for operational/debugging purposes. Security-critical filtering should use `BatchAuthor` (validator-based) or `BatchDigest` (content-based) filters.

**Long-term Fix:**
Implement BatchId validation to enforce legitimate patterns. Options include:

1. **Sequence Validation**: Verify that BatchId.id values from a validator are monotonically increasing within an epoch
2. **Nonce Validation**: Verify that BatchId.nonce values are reasonably close to the current time and consistent within a time window
3. **Persistence Checking**: Track seen BatchId values per validator in a persistent store and reject duplicates or out-of-sequence values

Example validation addition:

```rust
// In BatchMsg::verify() or similar validation point
fn validate_batch_id_legitimacy(
    &self,
    author: PeerId,
    batch_id: BatchId,
    validator_state: &ValidatorBatchIdState,
) -> anyhow::Result<()> {
    // Check if nonce is within reasonable time bounds
    let current_time = aptos_infallible::duration_since_epoch().as_micros() as u64;
    let max_nonce_drift = 300_000_000; // 5 minutes in microseconds
    ensure!(
        batch_id.nonce <= current_time + max_nonce_drift,
        "Batch nonce too far in future"
    );
    
    // Verify id is greater than last seen id for this author+nonce
    if let Some(last_id) = validator_state.get_last_batch_id(author, batch_id.nonce) {
        ensure!(
            batch_id.id > last_id,
            "Batch id must be monotonically increasing"
        );
    }
    
    Ok(())
}
```

## Proof of Concept

```rust
// Test demonstrating BatchId filter bypass
#[test]
fn test_batch_id_filter_bypass() {
    use aptos_crypto::HashValue;
    use aptos_types::{quorum_store::BatchId, transaction::SignedTransaction, PeerId};
    use crate::batch_transaction_filter::BatchTransactionFilter;
    
    // Create test transactions
    let transactions = create_test_transactions();
    let batch_author = PeerId::random();
    let batch_digest = HashValue::random();
    
    // Operator creates filter to deny BatchId {id: 100, nonce: 12345}
    let blocked_batch_id = BatchId { id: 100, nonce: 12345 };
    let filter = BatchTransactionFilter::empty()
        .add_batch_id_filter(false, blocked_batch_id);
    
    // Verify filter blocks the intended batch
    assert!(!filter.allows_transaction(
        blocked_batch_id,
        batch_author,
        &batch_digest,
        &transactions[0]
    ));
    
    // BYPASS: Malicious validator uses different BatchId with same content
    let bypass_batch_id_1 = BatchId { id: 101, nonce: 12345 }; // Changed id
    let bypass_batch_id_2 = BatchId { id: 100, nonce: 54321 }; // Changed nonce
    
    // Filter is bypassed - same transactions pass through with different BatchId
    assert!(filter.allows_transaction(
        bypass_batch_id_1,
        batch_author,
        &batch_digest,
        &transactions[0]
    ));
    
    assert!(filter.allows_transaction(
        bypass_batch_id_2,
        batch_author,
        &batch_digest,
        &transactions[0]
    ));
    
    println!("✓ Demonstrated: Malicious validator can bypass BatchId filtering by using arbitrary BatchId values");
}
```

## Notes

- The vulnerability exists because BatchId values are not cryptographically bound to validator identity or enforced by consensus
- Secure filtering alternatives exist: `BatchAuthor` for validator-based filtering and `BatchDigest` for content-based filtering
- The issue is rooted in the trust assumption that validators will use legitimate BatchId values, which doesn't hold in a Byzantine fault-tolerant system
- This represents a gap between operational tooling expectations and actual security guarantees provided by the filtering mechanism

### Citations

**File:** crates/aptos-transaction-filters/src/batch_transaction_filter.rs (L195-218)
```rust
/// A matcher that defines the criteria for matching batches
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BatchMatcher {
    All,                    // Matches any batch
    BatchId(BatchId),       // Matches batches with the specified ID
    BatchAuthor(PeerId),    // Matches batches authored by the specified peer
    BatchDigest(HashValue), // Matches batches with the specified digest
}

impl BatchMatcher {
    /// Returns true iff the matcher matches the given batch information
    fn matches(&self, batch_id: BatchId, batch_author: PeerId, batch_digest: &HashValue) -> bool {
        match self {
            BatchMatcher::All => true,
            BatchMatcher::BatchId(target_batch_id) => matches_batch_id(batch_id, target_batch_id),
            BatchMatcher::BatchAuthor(target_author) => {
                matches_batch_author(batch_author, target_author)
            },
            BatchMatcher::BatchDigest(target_digest) => {
                matches_batch_digest(batch_digest, target_digest)
            },
        }
    }
}
```

**File:** crates/aptos-transaction-filters/src/batch_transaction_filter.rs (L220-223)
```rust
/// Returns true iff the batch ID matches the target batch ID
fn matches_batch_id(batch_id: BatchId, target_batch_id: &BatchId) -> bool {
    batch_id == *target_batch_id
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

**File:** types/src/quorum_store/mod.rs (L11-35)
```rust
/// A unique identifier for a batch of transactions in quorum store
#[derive(
    Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash, CryptoHasher, BCSCryptoHash,
)]
pub struct BatchId {
    pub id: u64,
    /// A number that is stored in the DB and updated only if the value does not exist in
    /// the DB: (a) at the start of an epoch, or (b) the DB was wiped. When the nonce is updated,
    /// id starts again at 0. Using the current system time allows the nonce to be ordering.
    pub nonce: u64,
}

impl BatchId {
    pub fn new(nonce: u64) -> Self {
        Self { id: 0, nonce }
    }

    pub fn new_for_test(id: u64) -> Self {
        Self { id, nonce: 0 }
    }

    pub fn increment(&mut self) {
        self.id += 1;
    }
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

**File:** consensus/src/quorum_store/batch_coordinator.rs (L189-213)
```rust
        // Filter the transactions in the batches. If any transaction is rejected,
        // the message will be dropped, and all batches will be rejected.
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

**File:** consensus/consensus-types/src/proof_of_store.rs (L46-82)
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

impl BatchInfo {
    pub fn new(
        author: PeerId,
        batch_id: BatchId,
        epoch: u64,
        expiration: u64,
        digest: HashValue,
        num_txns: u64,
        num_bytes: u64,
        gas_bucket_start: u64,
    ) -> Self {
        Self {
            author,
            batch_id,
            epoch,
            expiration,
            digest,
            num_txns,
            num_bytes,
            gas_bucket_start,
        }
    }

```
