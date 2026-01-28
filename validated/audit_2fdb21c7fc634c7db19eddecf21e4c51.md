# Audit Report

## Title
Unbounded Batch Accumulation via Far-Future Expiration Time Manipulation in Quorum Store

## Summary
A malicious validator can send `BatchMsg` messages with expiration times set to `u64::MAX`, bypassing all expiration cleanup mechanisms. This causes unbounded memory accumulation in honest validators, leading to performance degradation and potential node crashes.

## Finding Description

The vulnerability exists in the asymmetric validation of batch expiration times between `BatchMsg` and `SignedBatchInfo` message types in the Quorum Store protocol.

**Attack Flow:**

1. **Malicious Batch Creation**: A Byzantine validator creates batches with `expiration = u64::MAX` and broadcasts them via `BatchMsg` to honest validators.

2. **Verification Bypass**: When `UnverifiedEvent::verify()` processes the incoming `BatchMsg`, it calls `BatchMsg::verify()` with only three parameters: `peer_id`, `max_num_batches`, and `validator` - notably missing the `max_batch_expiry_gap_usecs` parameter that would enable upper-bound expiration validation. [1](#0-0) 

The `BatchMsg::verify()` method validates batch count limits, author validity, and payload integrity, but performs no expiration upper bound check. [2](#0-1) 

The `Batch::verify()` method validates payload hash, transaction counts, and gas prices but does not check expiration bounds. [3](#0-2) 

3. **Storage Without Upper Bound Validation**: The batch flows to `BatchStore::persist()` which calls `persist_inner()`, which then calls `save()`. The `save()` method only verifies `value.expiration() > last_certified_time`. [4](#0-3) 

Since `u64::MAX > last_certified_time`, the batch is accepted and cached.

4. **Propagation to ProofManager**: After persistence, the batch info is forwarded to `ProofManager` via `ProofManagerCommand::ReceiveBatches`. [5](#0-4) 

5. **Insertion into BatchProofQueue**: The `ProofManager` calls `insert_batches()` which adds the batch with its malicious expiration to multiple data structures. [6](#0-5) 

6. **Expiration Cleanup Bypass**: When blocks commit, `handle_updated_block_timestamp()` calls `self.expirations.expire(block_timestamp)` to remove expired batches. [7](#0-6) 

Since `u64::MAX >> block_timestamp`, these batches are never expired and remain in memory indefinitely.

7. **Garbage Collection Bypass**: The periodic GC in `gc_expired_batch_summaries_without_proofs()` checks `item.info.expiration() > timestamp`. [8](#0-7) 

For batches with `u64::MAX` expiration, this condition is always true, preventing garbage collection.

**Contrast with SignedBatchInfo Protection**: 

`SignedBatchInfo` messages have upper-bound validation that rejects far-future expirations by checking `self.expiration() <= current_time + max_batch_expiry_gap_usecs`. [9](#0-8) 

This validation is invoked for `SignedBatchInfo` messages with the `max_batch_expiry_gap_usecs` parameter but NOT for `BatchMsg` messages. [10](#0-9) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables resource exhaustion attacks against honest validators, qualifying as **High Severity** ($50,000 tier) under the Aptos Bug Bounty program's "Validator node slowdowns" category.

**Concrete Impacts:**

1. **Unbounded Memory Growth**: Each malicious batch permanently consumes memory in multiple data structures:
   - `BatchStore::db_cache` (DashMap) - caches batch metadata
   - `BatchProofQueue::items` (HashMap) - tracks batch items
   - `BatchProofQueue::author_to_batches` (HashMap of BTrees) - indexes by author
   - `BatchProofQueue::expirations` (TimeExpirations) - expiration tracking index

2. **Validator Performance Degradation**: Growing data structures degrade lookup performance in O(n) or O(log n) operations, increase memory access latency, and cause cache thrashing. This directly impacts consensus participation and block production timing.

3. **Potential Node Crashes**: Continued accumulation can exhaust system memory, triggering OOM kills and causing validator nodes to crash, reducing network decentralization and potentially affecting consensus liveness if enough validators are impacted.

4. **No Economic Deterrent**: The attacker incurs no stake slashing or penalties. Batches with invalid expiration times are not detected as Byzantine behavior by the consensus protocol, allowing repeated attacks without consequence.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Low Attack Complexity**: Constructing a `BatchMsg` with `expiration = u64::MAX` requires minimal effort. A malicious validator can modify their node to create batches with arbitrary expiration times and broadcast them using the standard `broadcast_batch_msg()` network function.

2. **Single Validator Attack**: Only one malicious or compromised validator is needed (< 1/3 Byzantine validators, well within the BFT threat model). The attack does not require coordination or majority stake.

3. **Immediate and Cumulative Impact**: Each malicious batch permanently increases memory usage. An attacker can send multiple batches per epoch, causing rapid accumulation until manual operator intervention.

4. **Detection Difficulty**: Memory growth is gradual and may not trigger immediate alarms. Operators may not notice until performance degradation becomes severe or memory exhaustion causes crashes.

## Recommendation

Add expiration upper-bound validation to `BatchMsg::verify()` to match the protection provided for `SignedBatchInfo` messages:

1. **Modify BatchMsg::verify() signature** to accept `max_batch_expiry_gap_usecs` parameter
2. **Add expiration validation** that checks each batch's expiration against current time + gap
3. **Update UnverifiedEvent::verify()** to pass the parameter when calling `BatchMsg::verify()`

Specifically, in `consensus/src/quorum_store/types.rs`, modify `BatchMsg::verify()`:

```rust
pub fn verify(
    &self,
    peer_id: PeerId,
    max_num_batches: usize,
    max_batch_expiry_gap_usecs: u64,  // Add parameter
    verifier: &ValidatorVerifier,
) -> anyhow::Result<()> {
    // ... existing checks ...
    
    let current_time = aptos_infallible::duration_since_epoch().as_micros() as u64;
    for batch in self.batches.iter() {
        // Add expiration upper bound check
        ensure!(
            batch.expiration() <= current_time + max_batch_expiry_gap_usecs,
            "Batch expiration too far in future: {} > {}",
            batch.expiration(),
            current_time + max_batch_expiry_gap_usecs
        );
        // ... existing validation ...
    }
    Ok(())
}
```

And update the call site in `consensus/src/round_manager.rs`:

```rust
UnverifiedEvent::BatchMsg(b) => {
    if !self_message {
        b.verify(peer_id, max_num_batches, max_batch_expiry_gap_usecs, validator)?;  // Add parameter
        // ...
    }
    // ...
}
```

## Proof of Concept

This PoC demonstrates that a malicious validator can create and send batches with u64::MAX expiration that bypass validation:

```rust
#[test]
fn test_batch_msg_accepts_far_future_expiration() {
    use consensus::quorum_store::types::{Batch, BatchMsg};
    use aptos_types::validator_verifier::ValidatorVerifier;
    
    // Create a batch with u64::MAX expiration
    let malicious_batch = create_test_batch_with_expiration(u64::MAX);
    let batch_msg = BatchMsg::new(vec![malicious_batch]);
    
    // Verify that BatchMsg::verify() accepts it (no max_batch_expiry_gap_usecs check)
    let result = batch_msg.verify(
        test_peer_id(),
        10, // max_num_batches
        &test_validator_verifier(),
    );
    
    // The batch is accepted despite having unrealistic expiration
    assert!(result.is_ok(), "BatchMsg with u64::MAX expiration should be rejected but was accepted");
}
```

The test would pass, demonstrating that `BatchMsg::verify()` accepts batches with far-future expirations, while an equivalent test with `SignedBatchInfo::verify()` would correctly reject such batches.

## Notes

This vulnerability represents a critical asymmetry in the Quorum Store protocol's validation logic. While `SignedBatchInfo` messages correctly enforce expiration bounds, `BatchMsg` messages lack this protection, creating an exploitable attack vector for resource exhaustion. The fix is straightforward: apply consistent validation across all batch message types to prevent unbounded accumulation of expired batch data.

### Citations

**File:** consensus/src/round_manager.rs (L166-210)
```rust
            UnverifiedEvent::BatchMsg(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(Box::new((*b).into()))
            },
            UnverifiedEvent::BatchMsgV2(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(b)
            },
            UnverifiedEvent::SignedBatchInfo(sd) => {
                if !self_message {
                    sd.verify(
                        peer_id,
                        max_num_batches,
                        max_batch_expiry_gap_usecs,
                        validator,
                    )?;
                    counters::VERIFY_MSG
                        .with_label_values(&["signed_batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::SignedBatchInfo(Box::new((*sd).into()))
            },
            UnverifiedEvent::SignedBatchInfoMsgV2(sd) => {
                if !self_message {
                    sd.verify(
                        peer_id,
                        max_num_batches,
                        max_batch_expiry_gap_usecs,
                        validator,
                    )?;
                    counters::VERIFY_MSG
                        .with_label_values(&["signed_batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::SignedBatchInfo(sd)
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

**File:** consensus/src/quorum_store/batch_coordinator.rs (L131-133)
```rust
            let _ = sender_to_proof_manager
                .send(ProofManagerCommand::ReceiveBatches(batches))
                .await;
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L258-280)
```rust
    pub fn insert_batches(
        &mut self,
        batches_with_txn_summaries: Vec<(BatchInfoExt, Vec<TxnSummaryWithExpiration>)>,
    ) {
        let start = Instant::now();

        for (batch_info, txn_summaries) in batches_with_txn_summaries.into_iter() {
            let batch_sort_key = BatchSortKey::from_info(&batch_info);
            let batch_key = BatchKey::from_info(&batch_info);

            // If the batch is either committed or the txn summary already exists, skip
            // inserting this batch.
            if self
                .items
                .get(&batch_key)
                .is_some_and(|item| item.is_committed() || item.txn_summaries.is_some())
            {
                continue;
            }

            self.author_to_batches
                .entry(batch_info.author())
                .or_default()
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L324-338)
```rust
    fn gc_expired_batch_summaries_without_proofs(&mut self) {
        let timestamp = aptos_infallible::duration_since_epoch().as_micros() as u64;
        self.items.retain(|_, item| {
            if item.is_committed() || item.proof.is_some() || item.info.expiration() > timestamp {
                true
            } else {
                self.author_to_batches
                    .get_mut(&item.info.author())
                    .map(|queue| queue.remove(&BatchSortKey::from_info(&item.info)));
                counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                    .with_label_values(&["expired_batch_without_proof"])
                    .inc();
                false
            }
        });
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L716-729)
```rust
    pub(crate) fn handle_updated_block_timestamp(&mut self, block_timestamp: u64) {
        // tolerate asynchronous notification
        if self.latest_block_timestamp > block_timestamp {
            return;
        }
        let start = Instant::now();
        self.latest_block_timestamp = block_timestamp;
        if let Some(time_lag) = aptos_infallible::duration_since_epoch()
            .checked_sub(Duration::from_micros(block_timestamp))
        {
            counters::TIME_LAG_IN_BATCH_PROOF_QUEUE.observe_duration(time_lag);
        }

        let expired = self.expirations.expire(block_timestamp);
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
