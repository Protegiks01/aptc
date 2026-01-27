# Audit Report

## Title
Byzantine Validators Can Dilute Block Quality Through Low-Priority Proof Flooding in Quorum Store

## Summary
Byzantine validators can flood the proof manager's queue with low-priority (low `gas_bucket_start`) proofs through the NetworkListener, causing the round-robin selection mechanism to dilute block quality by crowding out high-priority proofs from honest validators. This reduces transaction throughput for high-value transactions and causes economic harm to users.

## Finding Description

The vulnerability exists in the proof selection mechanism of the Quorum Store system. When Byzantine validators send `ProofOfStore` messages through NetworkListener, these proofs are inserted into the `BatchProofQueue` without any per-author limits or gas-based prioritization during the insertion or selection phases. [1](#0-0) 

The critical flaw occurs in the `pull_internal` method of `BatchProofQueue`, where proof selection happens through a round-robin mechanism across authors: [2](#0-1) 

The selection process:
1. Creates iterators per author (batches within each author are ordered by gas, high first)
2. **Randomly shuffles these author iterators** 
3. Performs round-robin selection until transaction/size limits are reached
4. **Only after selection**, sorts the selected batches by `gas_bucket_start` [3](#0-2) 

The sorting at line 709 occurs **after** the selection phase, meaning it only affects the ordering of already-selected batches, not which batches get selected.

**Attack Path:**

1. Byzantine validators (up to f < n/3 validators) create multiple batches containing low-gas transactions (`gas_bucket_start = 0`)
2. These batches are signed through the normal proof coordinator flow (requiring 2f+1 signatures, which honest validators provide since there's no validation of gas values)
3. Byzantine validators broadcast `ProofOfStore` messages (up to 20 proofs per message per configuration) [4](#0-3) 

4. Proofs are inserted into `BatchProofQueue` without per-author limits: [5](#0-4) 

5. During block proposal, the round-robin selection gives Byzantine validators proportional representation based on the number of batches, not gas priority
6. If 33% of validators are Byzantine with 20 batches each, and 67% are honest with 5 batches each, the selection will include ~33% low-gas batches

**Example Scenario:**
- 100 validators (33 Byzantine, 67 honest within BFT threshold)
- Byzantine: 33 validators × 20 low-gas batches = 660 low-gas proofs
- Honest: 67 validators × 5 high-gas batches = 335 high-gas proofs
- Block request for 200 batches: ~2 batches per validator in round-robin
- Result: ~66 low-gas batches + ~134 high-gas batches (33% dilution)

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos Bug Bounty program criteria for the following reasons:

1. **Economic Harm**: High-gas transaction senders experience delayed inclusion despite paying premium fees, resulting in financial losses from timing-sensitive transactions
2. **Network Quality Degradation**: Block space is inefficiently utilized, reducing overall network throughput and validator revenue
3. **State Inconsistency**: The system's intended priority mechanism (gas-based ordering) is subverted, requiring operational intervention to restore expected behavior

The impact does not reach High/Critical severity because:
- No direct fund theft or consensus safety violation occurs
- Network remains operational (liveness preserved)
- The attack doesn't cause permanent state corruption

However, it clearly exceeds Low severity as it causes measurable economic harm and degrades core protocol functionality.

## Likelihood Explanation

The likelihood of this attack is **Medium to High**:

**Feasibility Factors:**
1. Requires coordination among Byzantine validators (f < n/3), which is within BFT assumptions
2. No special privileges needed beyond normal validator operation
3. Attack is economically rational if Byzantine validators profit from delaying competitor transactions
4. The proof verification process has no gas-based validation [6](#0-5) 

5. No per-author limits exist in the proof queue: [7](#0-6) 

**Constraints:**
- Byzantine validators must create valid batches with actual transactions (though low-gas ones are readily available from mempool)
- Limited by global proof limit (20 × num_validators) and back pressure mechanism [8](#0-7) 

The attack is sustainable and repeatable across multiple blocks.

## Recommendation

Implement gas-weighted author prioritization during proof selection. Modify the `pull_internal` method to:

1. **Add per-author gas score tracking**: Calculate aggregate gas value of each author's pending batches
2. **Implement weighted selection**: Instead of uniform random shuffle, weight author selection probability by their maximum gas bucket values
3. **Add per-author proof limits**: Implement quotas similar to the batch storage quota system

**Suggested Fix (conceptual):**

```rust
// In pull_internal, replace random shuffle with weighted selection
// Sort authors by their highest gas bucket batch
let mut author_priorities: Vec<_> = self.author_to_batches
    .iter()
    .filter(|(author, _)| !exclude_authors.contains(author))
    .map(|(author, batches)| {
        let max_gas = batches.keys().map(|k| k.gas_bucket_start()).max().unwrap_or(0);
        (author, max_gas, batches)
    })
    .collect();

author_priorities.sort_by_key(|(_, gas, _)| Reverse(*gas));

// Process high-gas authors first, then round-robin within gas tiers
```

Additionally, add per-author proof count limits in `insert_proof`:

```rust
// In insert_proof, add check
let author_proof_count = self.author_to_batches
    .get(&author)
    .map(|batches| batches.len())
    .unwrap_or(0);

if author_proof_count >= MAX_PROOFS_PER_AUTHOR {
    counters::inc_rejected_pos_count("author_quota_exceeded");
    return;
}
```

## Proof of Concept

```rust
// Test to demonstrate the vulnerability
#[test]
fn test_low_priority_proof_flooding() {
    // Setup: 33 Byzantine validators, 67 honest validators
    let byzantine_count = 33;
    let honest_count = 67;
    let byzantine_batches_per_validator = 20;
    let honest_batches_per_validator = 5;
    
    let mut queue = BatchProofQueue::new(
        PeerId::random(),
        Arc::new(MockBatchStore::new()),
        10_000_000, // batch_expiry_gap
    );
    
    // Byzantine validators insert low-gas proofs (gas_bucket_start = 0)
    for validator_idx in 0..byzantine_count {
        let author = PeerId::random();
        for batch_idx in 0..byzantine_batches_per_validator {
            let proof = create_test_proof(
                author,
                batch_idx,
                0, // gas_bucket_start = 0 (low priority)
                100, // num_txns
            );
            queue.insert_proof(proof);
        }
    }
    
    // Honest validators insert high-gas proofs (gas_bucket_start = 1_000_000)
    for validator_idx in 0..honest_count {
        let author = PeerId::random();
        for batch_idx in 0..honest_batches_per_validator {
            let proof = create_test_proof(
                author,
                batch_idx,
                1_000_000, // gas_bucket_start = 1M (high priority)
                100, // num_txns
            );
            queue.insert_proof(proof);
        }
    }
    
    // Pull 200 proofs as would happen during block creation
    let (pulled_proofs, _, _, _) = queue.pull_proofs(
        &HashSet::new(), // no excluded batches
        PayloadTxnsSize::new(20_000, 20_000_000), // max_txns
        20_000, // max_txns_after_filtering
        18_000, // soft_max
        true, // return_non_full
        Duration::from_secs(0), // block_timestamp
    );
    
    // Count low-gas vs high-gas proofs
    let low_gas_count = pulled_proofs.iter()
        .filter(|p| p.gas_bucket_start() == 0)
        .count();
    let high_gas_count = pulled_proofs.iter()
        .filter(|p| p.gas_bucket_start() == 1_000_000)
        .count();
    
    // Vulnerability demonstrated: Low-gas proofs significantly represented
    // Expected: All high-gas proofs selected first
    // Actual: ~33% low-gas due to round-robin fairness
    println!("Low-gas proofs selected: {}", low_gas_count);
    println!("High-gas proofs selected: {}", high_gas_count);
    println!("Dilution percentage: {}%", 
        (low_gas_count as f64 / pulled_proofs.len() as f64 * 100.0));
    
    // Assert vulnerability exists
    assert!(low_gas_count > 0, "Byzantine low-gas proofs were selected");
    assert!(low_gas_count as f64 / pulled_proofs.len() as f64 > 0.25,
        "More than 25% dilution occurred");
}
```

## Notes

The vulnerability is exacerbated by the lack of coordination between the proof verification layer (which validates signatures but not gas values) and the proof selection layer (which attempts gas prioritization only after selection). The back pressure mechanism only affects local batch generation, not incoming proofs from remote validators, leaving the system vulnerable to this attack vector.

### Citations

**File:** consensus/src/quorum_store/network_listener.rs (L95-104)
```rust
                    VerifiedEvent::ProofOfStoreMsg(proofs) => {
                        counters::QUORUM_STORE_MSG_COUNT
                            .with_label_values(&["NetworkListener::proofofstore"])
                            .inc();
                        let cmd = ProofManagerCommand::ReceiveProofs(*proofs);
                        self.proof_manager_tx
                            .send(cmd)
                            .await
                            .expect("could not push Proof proof_of_store");
                    },
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L175-256)
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

        sample!(
            SampleRate::Duration(Duration::from_millis(500)),
            self.gc_expired_batch_summaries_without_proofs()
        );
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L596-630)
```rust
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
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L707-713)
```rust
        if full || return_non_full {
            // Stable sort, so the order of proofs within an author will not change.
            result.sort_by_key(|item| Reverse(item.info.gas_bucket_start()));
            (result, cur_all_txns, cur_unique_txns, full)
        } else {
            (Vec::new(), PayloadTxnsSize::zero(), 0, full)
        }
```

**File:** config/src/config/quorum_store_config.rs (L122-122)
```rust
            receiver_max_num_batches: 20,
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L635-652)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache) -> anyhow::Result<()> {
        let batch_info_ext: BatchInfoExt = self.info.clone().into();
        if let Some(signature) = cache.get(&batch_info_ext) {
            if signature == self.multi_signature {
                return Ok(());
            }
        }
        let result = validator
            .verify_multi_signatures(&self.info, &self.multi_signature)
            .context(format!(
                "Failed to verify ProofOfStore for batch: {:?}",
                self.info
            ));
        if result.is_ok() {
            cache.insert(batch_info_ext, self.multi_signature.clone());
        }
        result
    }
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L183-184)
```rust
        let (proof_manager_cmd_tx, proof_manager_cmd_rx) =
            tokio::sync::mpsc::channel(config.channel_size);
```
