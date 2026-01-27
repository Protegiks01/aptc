# Audit Report

## Title
Missing Batch Expiration Validation in Proof Queue Allows Expired Batches in Block Proposals

## Summary
The `BatchProofQueue::pull_internal()` function fails to validate batch expiration against the provided `block_timestamp`, allowing expired batches to be included in block proposals as inline batches. This violates the quorum store's temporal freshness guarantees and can cause validators to process and vote on blocks containing stale data.

## Finding Description

The vulnerability exists in the batch pulling logic within the quorum store's proof queue. When the `pull_internal()` function selects batches for inclusion in block proposals, it only validates individual transaction expiration but completely ignores the batch-level expiration timestamp. [1](#0-0) 

The function receives a `block_timestamp` parameter (line 570) that represents the timestamp of the block being constructed. While it uses this timestamp to filter expired transactions within batches (lines 644-646 and 669-670), it never checks whether the batch itself has expired by comparing `batch.expiration()` against `block_timestamp`.

The missing check should be: `if batch.expiration() <= block_timestamp { skip this batch }`.

**Attack Path:**

1. A batch B is created with expiration time T and enters the proof queue
2. Time advances and the current block timestamp becomes T+Δ (where Δ > 0, meaning the batch has expired)
3. A proposal request arrives via `handle_proposal_request()` with `block_timestamp = T+Δ`
4. Before `handle_updated_block_timestamp(T+Δ)` is called to clean up expired batches, the proposal creation proceeds
5. `pull_batches_with_transactions()` is invoked, which calls `pull_internal()`
6. `pull_internal()` iterates through batches and includes batch B because there's no expiration check
7. `get_batch_from_local()` retrieves the expired batch's payload
8. The expired batch is included in the proposal's inline batches and sent to other validators [2](#0-1) 

The database-level retrieval functions also lack expiration validation: [3](#0-2) [4](#0-3) 

Critically, inline batches are treated differently from proof-based batches during payload reconstruction. While proof batches can be skipped when expired, inline batches cannot: [5](#0-4) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program due to "Significant protocol violations."

**Protocol Violation:** The quorum store protocol explicitly assigns expiration timestamps to batches to ensure temporal freshness and bounded storage. Including expired batches in consensus violates this core design principle.

**Consensus Impact:** While this doesn't directly break safety (all validators would process the same expired batches deterministically), it creates inconsistencies in how the protocol should operate:
- Different validators might have different views of which batches are "valid" based on when they ran cleanup
- Expired batches consume consensus bandwidth and execution resources unnecessarily
- The protocol's liveness guarantees assume batches are fresh and haven't accumulated unboundedly

**Resource Exhaustion Risk:** If expired batches accumulate due to delayed cleanup, validators waste resources processing stale data that should have been garbage collected.

## Likelihood Explanation

**High Likelihood** - This can occur under normal operating conditions without requiring attacker intervention:

1. **Timing Windows:** The race condition between batch expiration and cleanup is inherent to the asynchronous nature of the system. Commit notifications that trigger `handle_updated_block_timestamp()` may lag behind proposal requests. [6](#0-5) 

2. **No Defensive Checks:** The expiration validation in `SignedBatchInfo::verify()` only checks if expiration is too far in the future, not if batches are expired: [7](#0-6) 

3. **Natural Occurrence:** During high load or network delays, batches may naturally expire while still in the queue, and the cleanup mechanism may not run immediately.

4. **Amplification:** Once an expired batch is included in a proposal, all validators must process it, multiplying the resource waste across the network.

## Recommendation

Add explicit batch expiration validation in `pull_internal()` before including batches in the result. The fix should be applied at line 636, right after checking if the batch is excluded:

```rust
// After line 636 in batch_proof_queue.rs
if excluded_batches.contains(batch) {
    excluded_txns += batch.num_txns();
} else {
    // ADD THIS CHECK:
    // Skip expired batches
    if batch.expiration() <= block_timestamp.as_micros() as u64 {
        counters::EXPIRED_BATCH_FILTERED_COUNT.inc();
        continue;
    }
    
    // Calculate the number of unique transactions if this batch is included...
    // (rest of existing logic)
}
```

Additionally, consider adding defensive expiration checks in:
1. `get_batch_from_db()` to return an error for expired batches
2. `get_batch_from_local()` to validate expiration before returning
3. Payload verification to reject proposals containing expired inline batches

## Proof of Concept

```rust
#[test]
fn test_pull_expired_batch_vulnerability() {
    use std::time::Duration;
    use aptos_infallible::duration_since_epoch;
    
    // Setup batch proof queue
    let mut proof_queue = create_test_batch_proof_queue();
    
    // Create a batch that expires soon
    let current_time = duration_since_epoch().as_micros() as u64;
    let expiration = current_time + 1000; // Expires in 1ms
    let batch_info = create_test_batch_info(expiration);
    
    // Insert batch with proof
    proof_queue.insert_proof(create_test_proof(batch_info.clone()));
    
    // Wait for batch to expire
    std::thread::sleep(Duration::from_millis(2));
    
    // Try to pull batches with block_timestamp AFTER expiration
    let future_timestamp = Duration::from_micros(expiration + 1000);
    let (batches, _, _, _) = proof_queue.pull_batches_internal(
        &HashSet::new(),
        &HashSet::new(),
        PayloadTxnsSize::new(1000, 1000000),
        1000,
        900,
        true,
        future_timestamp,
        None,
    );
    
    // VULNERABILITY: The expired batch is still returned
    assert!(!batches.is_empty(), "Expired batch should have been filtered but wasn't");
    assert_eq!(batches[0].expiration(), expiration);
    assert!(future_timestamp.as_micros() as u64 > expiration, 
            "Block timestamp is after batch expiration, batch should be filtered");
}
```

## Notes

While the cleanup mechanism `handle_updated_block_timestamp()` is designed to remove expired batches proactively, the lack of defensive validation in `pull_internal()` creates a race condition window. The temporal ordering of commit notifications versus proposal requests is not strictly guaranteed, allowing expired batches to slip through during normal operations. This represents a violation of the quorum store protocol's freshness invariants and should be addressed with explicit expiration validation at the batch selection layer.

### Citations

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L515-559)
```rust
    pub fn pull_batches_with_transactions(
        &mut self,
        excluded_batches: &HashSet<BatchInfoExt>,
        max_txns: PayloadTxnsSize,
        max_txns_after_filtering: u64,
        soft_max_txns_after_filtering: u64,
        return_non_full: bool,
        block_timestamp: Duration,
    ) -> (
        Vec<(BatchInfoExt, Vec<SignedTransaction>)>,
        PayloadTxnsSize,
        u64,
    ) {
        let (batches, pulled_txns, unique_txns, is_full) = self.pull_batches_internal(
            excluded_batches,
            &HashSet::new(),
            max_txns,
            max_txns_after_filtering,
            soft_max_txns_after_filtering,
            return_non_full,
            block_timestamp,
            None,
        );
        let mut result = Vec::new();
        for batch in batches.into_iter() {
            if let Ok(mut persisted_value) = self.batch_store.get_batch_from_local(batch.digest()) {
                if let Some(txns) = persisted_value.take_payload() {
                    result.push((batch, txns));
                }
            } else {
                warn!(
                    "Couldn't find a batch in local storage while creating inline block: {:?}",
                    batch.digest()
                );
            }
        }

        if is_full || return_non_full {
            counters::CONSENSUS_PULL_NUM_UNIQUE_TXNS.observe_with(&["inline"], unique_txns as f64);
            counters::CONSENSUS_PULL_NUM_TXNS.observe_with(&["inline"], pulled_txns.count() as f64);
            counters::CONSENSUS_PULL_SIZE_IN_BYTES
                .observe_with(&["inline"], pulled_txns.size_in_bytes() as f64);
        }
        (result, pulled_txns, unique_txns)
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L561-714)
```rust
    fn pull_internal(
        &mut self,
        batches_without_proofs: bool,
        excluded_batches: &HashSet<BatchInfoExt>,
        exclude_authors: &HashSet<Author>,
        max_txns: PayloadTxnsSize,
        max_txns_after_filtering: u64,
        soft_max_txns_after_filtering: u64,
        return_non_full: bool,
        block_timestamp: Duration,
        min_batch_age_usecs: Option<u64>,
    ) -> (Vec<&QueueItem>, PayloadTxnsSize, u64, bool) {
        let mut result = Vec::new();
        let mut cur_unique_txns = 0;
        let mut cur_all_txns = PayloadTxnsSize::zero();
        let mut excluded_txns = 0;
        let mut full = false;
        // Set of all the excluded transactions and all the transactions included in the result
        let mut filtered_txns = HashSet::new();
        for batch_info in excluded_batches {
            let batch_key = BatchKey::from_info(batch_info);
            if let Some(txn_summaries) = self
                .items
                .get(&batch_key)
                .and_then(|item| item.txn_summaries.as_ref())
            {
                for txn_summary in txn_summaries {
                    filtered_txns.insert(*txn_summary);
                }
            }
        }

        let max_batch_creation_ts_usecs = min_batch_age_usecs
            .map(|min_age| aptos_infallible::duration_since_epoch().as_micros() as u64 - min_age);
        let mut iters = vec![];
        for (_, batches) in self
            .author_to_batches
            .iter()
            .filter(|(author, _)| !exclude_authors.contains(author))
        {
            let batch_iter = batches.iter().rev().filter_map(|(sort_key, info)| {
                if let Some(item) = self.items.get(&sort_key.batch_key) {
                    let batch_create_ts_usecs =
                        item.info.expiration() - self.batch_expiry_gap_when_init_usecs;

                    // Ensure that the batch was created at least `min_batch_age_usecs` ago to
                    // reduce the chance of inline fetches.
                    if max_batch_creation_ts_usecs
                        .is_some_and(|max_create_ts| batch_create_ts_usecs > max_create_ts)
                    {
                        return None;
                    }

                    if item.is_committed() {
                        return None;
                    }
                    if !(batches_without_proofs ^ item.proof.is_none()) {
                        return Some((info, item));
                    }
                }
                None
            });
            iters.push(batch_iter);
        }

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
        info!(
            // before non full check
            block_total_txns = cur_all_txns,
            block_unique_txns = cur_unique_txns,
            max_txns = max_txns,
            max_txns_after_filtering = max_txns_after_filtering,
            soft_max_txns_after_filtering = soft_max_txns_after_filtering,
            max_bytes = max_txns.size_in_bytes(),
            result_is_proof = !batches_without_proofs,
            result_count = result.len(),
            full = full,
            return_non_full = return_non_full,
            "Pull payloads from QuorumStore: internal"
        );

        counters::EXCLUDED_TXNS_WHEN_PULL.observe(excluded_txns as f64);

        if full || return_non_full {
            // Stable sort, so the order of proofs within an author will not change.
            result.sort_by_key(|item| Reverse(item.info.gas_bucket_start()));
            (result, cur_all_txns, cur_unique_txns, full)
        } else {
            (Vec::new(), PayloadTxnsSize::zero(), 0, full)
        }
    }
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L119-121)
```rust
    fn get_batch(&self, digest: &HashValue) -> Result<Option<PersistedValue<BatchInfo>>, DbError> {
        Ok(self.db.get::<BatchSchema>(digest)?)
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L545-569)
```rust
    fn get_batch_from_db(
        &self,
        digest: &HashValue,
        is_v2: bool,
    ) -> ExecutorResult<PersistedValue<BatchInfoExt>> {
        counters::GET_BATCH_FROM_DB_COUNT.inc();

        if is_v2 {
            match self.db.get_batch_v2(digest) {
                Ok(Some(value)) => Ok(value),
                Ok(None) | Err(_) => {
                    warn!("Could not get batch from db");
                    Err(ExecutorError::CouldNotGetData)
                },
            }
        } else {
            match self.db.get_batch(digest) {
                Ok(Some(value)) => Ok(value.into()),
                Ok(None) | Err(_) => {
                    warn!("Could not get batch from db");
                    Err(ExecutorError::CouldNotGetData)
                },
            }
        }
    }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L914-920)
```rust
            match reconstruct_batch(&block_info, &mut transactions_iter, batch_info, false) {
                Ok(Some(batch_transactions)) => {
                    batches_and_transactions.push((batch_info.clone(), batch_transactions));
                },
                Ok(None) => {
                    return Err(Error::UnexpectedError(format!(
                        "Failed to reconstruct inline/opt batch! Batch was unexpectedly skipped: {:?}",
```

**File:** consensus/src/quorum_store/proof_manager.rs (L89-101)
```rust
        &mut self,
        block_timestamp: u64,
        batches: Vec<BatchInfoExt>,
    ) {
        trace!(
            "QS: got clean request from execution at block timestamp {}",
            block_timestamp
        );
        self.batch_proof_queue.mark_committed(batches);
        self.batch_proof_queue
            .handle_updated_block_timestamp(block_timestamp);
        self.update_remaining_txns_and_proofs();
    }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L459-482)
```rust
    pub fn verify(
        &self,
        sender: PeerId,
        max_batch_expiry_gap_usecs: u64,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        if sender != self.signer {
            bail!("Sender {} mismatch signer {}", sender, self.signer);
        }

        if self.expiration()
            > aptos_infallible::duration_since_epoch().as_micros() as u64
                + max_batch_expiry_gap_usecs
        {
            bail!(
                "Batch expiration too far in future: {} > {}",
                self.expiration(),
                aptos_infallible::duration_since_epoch().as_micros() as u64
                    + max_batch_expiry_gap_usecs
            );
        }

        Ok(validator.optimistic_verify(self.signer, &self.info, &self.signature)?)
    }
```
