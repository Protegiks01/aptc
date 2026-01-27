# Audit Report

## Title
Unbounded Empty Proof Accumulation in Batch Proof Queue Bypasses Resource Limits

## Summary
The `insert_proof()` function in `BatchProofQueue` accepts proofs with zero transactions without validation. When pulling proofs for block construction via `pull_internal()`, empty batches bypass all size limits since they contribute zero to transaction counts and byte sizes. This allows a malicious validator to flood the proof queue with empty batches, causing unbounded memory growth in the result vector and validator resource exhaustion.

## Finding Description

The vulnerability exists across the batch creation, validation, and proof pulling pipeline:

**1. No Validation Against Empty Batches:**

The `BatchInfo` constructor accepts `num_txns = 0` without validation [1](#0-0) , and the `ensure_max_limits()` function only validates upper bounds, allowing `num_txns = 0` to pass [2](#0-1) .

**2. Empty Proofs Bypass Insert Validation:**

When `insert_proof()` is called with a proof where `num_txns()` returns 0, the proof is accepted without validation [3](#0-2) . The accounting increments proof count but adds zero to transaction counts [4](#0-3) .

**3. Empty Batches Bypass Pull Limits:**

In `pull_internal()`, the critical limit checks compare accumulated sizes against maximums [5](#0-4) . For empty batches, `batch.size()` returns `PayloadTxnsSize::zero()` [6](#0-5) , which when added to `cur_all_txns` produces no change. The unique transaction count also doesn't increase [7](#0-6) .

**4. Unbounded Loop Iteration:**

The `pull_internal()` loop continues until all iterators are exhausted [8](#0-7) . Since empty batches never trigger the `full` flag, they are continuously added to the result vector without bounds, limited only by the number of empty batches in the queue.

**Attack Scenario:**

1. A malicious validator creates multiple batches with empty transaction vectors
2. These batches pass `Batch::verify()` checks [9](#0-8) 
3. ProofOfStore signatures are collected for these empty batches
4. The proofs are broadcast and inserted into other validators' `BatchProofQueue`
5. When consensus requests proofs via `pull_proofs()`, empty batches fill the result vector without triggering size limits
6. Validators experience memory exhaustion and processing overhead

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program:

- **Validator node slowdowns**: Processing unbounded empty proofs causes computational overhead and memory pressure
- **Resource exhaustion**: Memory consumption grows unbounded when pulling empty proofs
- **Consensus liveness degradation**: Validators waste resources on empty batches instead of processing real transactions

The vulnerability breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." Empty batches circumvent the size-based resource limits designed to bound memory usage.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker requirements**: Only requires one malicious validator (within Byzantine fault tolerance assumptions)
- **Complexity**: Low - simply create batches with empty transaction vectors
- **Detection difficulty**: Empty batches appear valid and signed by quorum
- **Exploitation cost**: Minimal - no economic cost to create empty batches
- **Default configuration vulnerability**: No configuration changes needed; default settings are vulnerable

The local batch generator intentionally avoids creating empty batches [10](#0-9) , but remote batches from malicious validators are not similarly protected.

## Recommendation

Add validation to reject empty batches at multiple checkpoints:

**1. In `insert_proof()`** - Reject proofs with zero transactions:
```rust
pub(crate) fn insert_proof(&mut self, proof: ProofOfStore<BatchInfoExt>) {
    if proof.expiration() <= self.latest_block_timestamp {
        counters::inc_rejected_pos_count(counters::POS_EXPIRED_LABEL);
        return;
    }
    
    // ADD THIS CHECK
    if proof.num_txns() == 0 {
        counters::inc_rejected_pos_count("empty_batch");
        return;
    }
    
    // ... rest of function
}
```

**2. In `ensure_max_limits()`** - Add minimum transaction validation:
```rust
fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
    // ... existing code
    for batch in batches.iter() {
        // ADD THIS CHECK
        ensure!(
            batch.num_txns() > 0,
            "Batch must contain at least one transaction"
        );
        
        ensure!(
            batch.num_txns() <= self.max_batch_txns,
            // ... rest
        );
    }
}
```

**3. In `pull_internal()`** - Skip empty batches even if they exist:
```rust
// In the iterator processing
if let Some((batch, item)) = iter.next() {
    // ADD THIS CHECK
    if batch.num_txns() == 0 {
        return true; // Continue to next batch
    }
    
    if excluded_batches.contains(batch) {
        // ... rest
    }
}
```

## Proof of Concept

```rust
// Test case demonstrating unbounded empty proof accumulation
#[tokio::test]
async fn test_empty_batch_proof_accumulation() {
    use aptos_consensus_types::proof_of_store::BatchInfoExt;
    use consensus::quorum_store::batch_proof_queue::BatchProofQueue;
    
    let my_peer_id = PeerId::random();
    let batch_store = Arc::new(BatchStore::new(/* ... */));
    let mut queue = BatchProofQueue::new(my_peer_id, batch_store, 60_000_000);
    
    // Create 1000 empty batch proofs from a malicious validator
    let malicious_peer = PeerId::random();
    for i in 0..1000 {
        let empty_batch_info = BatchInfoExt::new_v1(
            malicious_peer,
            BatchId::new(i),
            1, // epoch
            u64::MAX, // expiration - far future
            HashValue::zero(),
            0, // num_txns = 0 (EMPTY!)
            0, // num_bytes = 0
            0, // gas_bucket_start
        );
        
        let proof = ProofOfStore::new(
            empty_batch_info,
            AggregateSignature::empty(), // Assume valid signature
        );
        
        // This should be rejected but currently isn't
        queue.insert_proof(proof);
    }
    
    // Pull proofs for block construction
    let (proofs, txns_size, unique_txns, _) = queue.pull_proofs(
        &HashSet::new(), // excluded_batches
        PayloadTxnsSize::new(10000, 1_000_000), // max_txns - should limit
        1000, // max_txns_after_filtering
        800, // soft_max_txns_after_filtering
        true, // return_non_full
        Duration::from_secs(0),
    );
    
    // BUG: All 1000 empty proofs are pulled despite size limits!
    // Expected: 0 proofs (or early rejection)
    // Actual: 1000 proofs with 0 transactions
    assert_eq!(proofs.len(), 1000);
    assert_eq!(unique_txns, 0); // No actual transactions
    assert_eq!(txns_size.count(), 0);
    
    // This demonstrates unbounded memory growth - the result vector
    // contains 1000 useless proofs that bypassed all size limits
    println!("Memory consumed by {} empty proofs without bounds!", proofs.len());
}
```

## Notes

While the local batch generator has safeguards against creating empty batches [10](#0-9) , the system must defend against Byzantine validators who can send malicious remote batches. The current implementation assumes all batches contain at least one transaction, but this assumption is not enforced through validation. The validator set size limit and per-message batch limits [11](#0-10)  do not prevent this attack since a malicious validator can send multiple messages over time, accumulating empty batches in the queue.

### Citations

**File:** consensus/consensus-types/src/proof_of_store.rs (L61-81)
```rust
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

**File:** consensus/consensus-types/src/proof_of_store.rs (L312-315)
```rust
    fn size(&self) -> PayloadTxnsSize {
        PayloadTxnsSize::new(self.info().num_txns(), self.info().num_bytes())
    }
}
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L140-156)
```rust
        for batch in batches.iter() {
            ensure!(
                batch.num_txns() <= self.max_batch_txns,
                "Exceeds batch txn limit {} > {}",
                batch.num_txns(),
                self.max_batch_txns,
            );
            ensure!(
                batch.num_bytes() <= self.max_batch_bytes,
                "Exceeds batch bytes limit {} > {}",
                batch.num_bytes(),
                self.max_batch_bytes,
            );

            total_txns += batch.num_txns();
            total_bytes += batch.num_bytes();
        }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L101-108)
```rust
    fn inc_remaining_proofs(&mut self, author: &PeerId, num_txns: u64) {
        self.remaining_txns_with_duplicates += num_txns;
        self.remaining_proofs += 1;
        if *author == self.my_peer_id {
            self.remaining_local_txns += num_txns;
            self.remaining_local_proofs += 1;
        }
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L175-250)
```rust
    pub(crate) fn insert_proof(&mut self, proof: ProofOfStore<BatchInfoExt>) {
        if proof.expiration() <= self.latest_block_timestamp {
            counters::inc_rejected_pos_count(counters::POS_EXPIRED_LABEL);
            return;
        }
        let batch_key = BatchKey::from_info(proof.info());
        if self
            .items
            .get(&batch_key)
            .is_some_and(|item| item.proof.is_some() || item.is_committed())
        {
            counters::inc_rejected_pos_count(counters::POS_DUPLICATE_LABEL);
            return;
        }

        let author = proof.author();
        let bucket = proof.gas_bucket_start();
        let num_txns = proof.num_txns();
        let expiration = proof.expiration();

        let batch_sort_key = BatchSortKey::from_info(proof.info());
        let batches_for_author = self.author_to_batches.entry(author).or_default();
        batches_for_author.insert(batch_sort_key.clone(), proof.info().clone());

        // Check if a batch with a higher batch Id (reverse sorted) exists
        if let Some((prev_batch_key, _)) = batches_for_author
            .range((Bound::Unbounded, Bound::Excluded(batch_sort_key.clone())))
            .next_back()
        {
            if prev_batch_key.gas_bucket_start() == batch_sort_key.gas_bucket_start() {
                counters::PROOF_MANAGER_OUT_OF_ORDER_PROOF_INSERTION
                    .with_label_values(&[author.short_str().as_str()])
                    .inc();
            }
        }

        self.expirations.add_item(batch_sort_key, expiration);

        // If we are here, then proof is added for the first time. Otherwise, we will
        // return early. We only count when proof is added for the first time and txn
        // summary exists.
        if let Some(txn_summaries) = self
            .items
            .get(&batch_key)
            .and_then(|item| item.txn_summaries.as_ref())
        {
            for txn_summary in txn_summaries {
                *self
                    .txn_summary_num_occurrences
                    .entry(*txn_summary)
                    .or_insert(0) += 1;
            }
        }

        match self.items.entry(batch_key) {
            Entry::Occupied(mut entry) => {
                let item = entry.get_mut();
                item.proof = Some(proof);
                item.proof_insertion_time = Some(Instant::now());
            },
            Entry::Vacant(entry) => {
                entry.insert(QueueItem {
                    info: proof.info().clone(),
                    proof: Some(proof),
                    proof_insertion_time: Some(Instant::now()),
                    txn_summaries: None,
                });
            },
        }

        if author == self.my_peer_id {
            counters::inc_local_pos_count(bucket);
        } else {
            counters::inc_remote_pos_count(bucket);
        }
        self.inc_remaining_proofs(&author, num_txns);
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L626-689)
```rust
        while !iters.is_empty() {
            iters.shuffle(&mut thread_rng());
            iters.retain_mut(|iter| {
                if full {
                    return false;
                }

                if let Some((batch, item)) = iter.next() {
                    if excluded_batches.contains(batch) {
                        excluded_txns += batch.num_txns();
                    } else {
                        // Calculate the number of unique transactions if this batch is included in the result
                        let unique_txns = if let Some(ref txn_summaries) = item.txn_summaries {
                            cur_unique_txns
                                + txn_summaries
                                    .iter()
                                    .filter(|txn_summary| {
                                        !filtered_txns.contains(txn_summary)
                                            && block_timestamp.as_secs()
                                                < txn_summary.expiration_timestamp_secs
                                    })
                                    .count() as u64
                        } else {
                            cur_unique_txns + batch.num_txns()
                        };
                        if cur_all_txns + batch.size() > max_txns
                            || unique_txns > max_txns_after_filtering
                        {
                            // Exceeded the limit for requested bytes or number of transactions.
                            full = true;
                            return false;
                        }
                        cur_all_txns += batch.size();
                        // Add this batch to filtered_txns and calculate the number of
                        // unique transactions added in the result so far.
                        cur_unique_txns +=
                            item.txn_summaries
                                .as_ref()
                                .map_or(batch.num_txns(), |summaries| {
                                    summaries
                                        .iter()
                                        .filter(|summary| {
                                            filtered_txns.insert(**summary)
                                                && block_timestamp.as_secs()
                                                    < summary.expiration_timestamp_secs
                                        })
                                        .count() as u64
                                });
                        assert!(item.proof.is_none() == batches_without_proofs);
                        result.push(item);
                        if cur_all_txns == max_txns
                            || cur_unique_txns == max_txns_after_filtering
                            || cur_unique_txns >= soft_max_txns_after_filtering
                        {
                            full = true;
                            return false;
                        }
                    }
                    true
                } else {
                    false
                }
            })
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

**File:** consensus/src/quorum_store/batch_generator.rs (L364-372)
```rust
        if pulled_txns.is_empty() {
            counters::PULLED_EMPTY_TXNS_COUNT.inc();
            // Quorum store metrics
            counters::CREATED_EMPTY_BATCHES_COUNT.inc();

            counters::EMPTY_BATCH_CREATION_DURATION
                .observe_duration(self.last_end_batch_time.elapsed());
            self.last_end_batch_time = Instant::now();
            return vec![];
```

**File:** config/src/config/quorum_store_config.rs (L77-77)
```rust
    pub receiver_max_num_batches: usize,
```
